//! LAN Wendy server
//!
//! A smoltcp TCP server on the embassy-net stack that speaks the Wendy
//! framing the USB link already uses, so the host tool `litemsg` can push a
//! message to the device over the LAN and have it displayed on screen.
//!
//! ## How it fits
//!
//! This is the pure-Rust, `no_std` half of the Wendy link. It reuses the exact same
//! pipeline the USB `console_task` already runs:
//!
//! ```text
//! TCP bytes → [TLS Session] → [frame::FrameReader] → proto::decode →
//!           dispatch::dispatch → write reply frame + route stdin into ring
//! ```
//!
//! The accepted smoltcp [`TcpSocket`] is wrapped in a self-signed MbedTLS
//! **server** session ([`mbedtls_rs`], see [`crate::tls`]) — server-auth-only,
//! no client certificate. The Wendy framing/decode/dispatch/stdin code is
//! transport-agnostic, so the only thing that differs from the USB path is the
//! byte source (the encrypted [`Session`] instead of the USB-Serial/JTAG
//! peripheral) and the sink for replies (the session instead of USB). A pushed
//! line reaches `message_task` and displays on the band just like the USB
//! scenario.
//!
//! ## Transport note — TLS
//!
//! The Wendy LAN link runs over **TLS** (self-signed, server-auth-only,
//! allowed while the device is unenrolled). This port speaks the same: the
//! socket is upgraded to a [`mbedtls_rs::Session`] before the Wendy framing
//! runs. The recommended `mbedtls-rs` crate provides a `no_std` wrapper around
//! MbedTLS; the prebuilt `xtensa-esp32s3` libraries fall back to software
//! crypto when no accelerator is hooked, so no `EspAccel` wiring is needed.
//!
//! ## DLE-ESC
//!
//! Over a raw serial line the body is DLE-ESC escaped; over a reliable byte
//! stream (TLS, and plain TCP) it is **not**. We feed the socket/session bytes
//! straight into [`frame::FrameReader`], matching the TLS path.
//!
//! [`frame::FrameReader`]: wendy::frame::FrameReader
#![allow(clippy::large_stack_frames)]

use embassy_net::{IpListenEndpoint, Stack, tcp::TcpSocket};
use embedded_io_async::Write;
use log::{debug, info, warn};
use mbedtls_rs::{Session, Tls};

use wendy::dispatch::{self, Ctx};
use wendy::frame::{self, FrameReader, WENDY_MSG_MAGIC, WENDY_MSG_VERSION};
use wendy::proto::{self, DeviceIdentity, DeviceInfo, Message};

use crate::tls;
use crate::wendy_console::put_stdin_data;

/// LAN port the Wendy server listens on — matches `litemsg`'s default.
const LAN_PORT: u16 = 5054;

/// Body cap for the frame assembler (matches the USB task's `BODY_CAP`).
///
/// Raised from 1024 to 2200 so a single SensorLink chunk frame (~2048 payload
/// + protobuf framing) fits over the LAN transport too — the old value would
/// have made the frame assembler silently drop any chunk whose body exceeded
/// 1024 bytes, fragmenting the streamed frame.
const BODY_CAP: usize = 2200;

/// smoltcp receive buffer for the accepted connection.
const RX_BUF: usize = 2048;
/// smoltcp transmit buffer for the accepted connection.
const TX_BUF: usize = 1024;

// smoltcp buffers for the accepted connection. `TcpSocket::new` reborrows these
// as `&'static mut` each iteration (its lifetime is tied to the `'static`
// stack), and the socket is fully dropped at the end of every loop iteration,
// so the buffers are free to be borrowed again. `static mut` + an explicit
// re-borrow inside the loop is what lets us accept repeatedly; see the comment
// on the loop in `lan_server_task`.
static mut RX: [u8; RX_BUF] = [0u8; RX_BUF];
static mut TX: [u8; TX_BUF] = [0u8; TX_BUF];

/// Runs the LAN Wendy server for the lifetime of the stack.
///
/// Accepts one client at a time, upgrades it to a TLS session, then services it
/// (handshake → commands/events → reply + stdin), and accepts the next. Each
/// connection starts with a fresh handshake, like the USB link.
#[embassy_executor::task]
pub async fn lan_server_task(tls: &'static Tls<'static>, stack: Stack<'static>) -> ! {
    // Static device description advertised via get_device_info/identity,
    // Device description, matching what the USB task reports.
    let device_info = DeviceInfo {
        os: lit::<64>("WendyOS"),
        os_version: lit::<64>("0.1.0-rust"),
        cpu_architecture: lit::<32>("xtensa-esp32s3"),
        target: lit::<32>("esp32s3"),
        board: lit::<32>("esp32-s3-vocat"),
        wasm_app_support: false,
        native_app_support: true,
    };
    let device_identity = DeviceIdentity {
        id: lit::<64>("00:00:00:00:00:00"),
        name: lit::<64>("esp32-s3-vocat-wendy"),
        display_name: lit::<64>("ESP-VoCat Wendy"),
        enrolled_device_id: lit::<64>(""),
    };

    // Bind to all interfaces on `LAN_PORT`. `addr: None` = unspecified.
    let endpoint = IpListenEndpoint {
        addr: None,
        port: LAN_PORT,
    };

    loop {
        // `TcpSocket::new` reborrows these buffers as `&'static mut` (its
        // lifetime is tied to the `'static` stack), and wrapping the socket in a
        // TLS session consumes it, so we cannot reuse one across the loop. Each
        // socket is fully dropped at the end of the iteration, so the buffers are
        // free to be borrowed again. `addr_of_mut!` produces a raw pointer
        // without itself creating a borrow, and the previous socket's borrow has
        // already ended, so this re-borrow is sound.
        let rx = unsafe { &mut *core::ptr::addr_of_mut!(RX) };
        let tx = unsafe { &mut *core::ptr::addr_of_mut!(TX) };
        let mut socket = TcpSocket::new(stack, rx, tx);
        match socket.accept(endpoint).await {
            Ok(()) => info!("LAN: client connected on :{LAN_PORT}"),
            Err(e) => {
                warn!("LAN: accept failed: {e:?}; retrying in 1 s");
                embassy_time::Timer::after(embassy_time::Duration::from_secs(1)).await;
                continue;
            }
        }

        // Upgrade the accepted socket to a self-signed MbedTLS server session.
        // The handshake is driven lazily on the first read (see
        // `lan_service_loop`), so this only allocates the session state.
        let conf = tls::server_conf();
        let mut session = match Session::new(tls.reference(), socket, &conf) {
            Ok(session) => {
                info!("LAN: TLS session established");
                session
            }
            Err(e) => {
                warn!("LAN: TLS session setup failed: {e:?}; accepting next client");
                continue;
            }
        };

        lan_service_loop(&mut session, &device_info, &device_identity).await;
    }
}

/// Drives a single (already-upgraded) TLS connection: read application bytes,
/// assemble Wendy frames, dispatch them, and stream replies back through the
/// encrypted session. Returns when the peer closes the connection or an error
/// occurs, then sends a close-notify.
async fn lan_service_loop(
    session: &mut Session<'static, TcpSocket<'static>>,
    device_info: &DeviceInfo,
    device_identity: &DeviceIdentity,
) {
    let mut reader = FrameReader::<BODY_CAP>::new();
    let mut handshake_done = false;
    let mut console_attached = false;
    // Summary counters: log one line when the connection closes instead of
    // spamming a per-read line for every TCP segment (an image is dozens of
    // reads and would flood the console).
    let mut total_bytes: usize = 0;
    let mut frame_count: usize = 0;

    let mut buf = [0u8; RX_BUF];
    loop {
        match session.read(&mut buf).await {
            // EOF: the client closed the connection. Accept the next one.
            Ok(0) => {
                info!(
                    "LAN: client closed ({} frame(s), {} byte(s) received)",
                    frame_count, total_bytes
                );
                break;
            }
            Ok(n) => {
                total_bytes += n;
                // No DLE-ESC over a reliable stream: feed bytes straight
                // into the frame assembler. When a full frame is collected
                // `feed` returns it and we decode + dispatch it.
                // Note: intentionally no `{buf:?}` here — formatting the whole
                // receive buffer on every read is expensive and adds little.
                // The message payload is already surfaced via the
                // "routing stdin" / "committing line" logs below.
                for &b in &buf[..n] {
                    if let Some(bound) = reader.feed(b) {
                        frame_count += 1;
                        process_frame(
                            session,
                            &bound,
                            &mut handshake_done,
                            &mut console_attached,
                            device_info,
                            device_identity,
                        )
                        .await;
                    }
                }
            }
            // A reset/error (or a TLS alert during the handshake) ends the
            // connection; accept the next one.
            Err(e) => {
                warn!("LAN: read error: {e:?}");
                break;
            }
        }
    }

    // Politely send close-notify. Safe to call even if the handshake never
    // completed (`Session::close` returns early when not connected); a peer
    // that has already gone away just yields an error we can ignore.
    if let Err(e) = session.close().await {
        warn!("LAN: close-notify failed: {e:?}");
    }
}

/// Decode a collected frame body, dispatch it, and apply the outcome over the
/// session: send the reply as a raw frame and perform any side effect (stdin
/// injection, console attach/detach, reboot).
async fn process_frame<S>(
    session: &mut S,
    bound: &frame::Frame<BODY_CAP>,
    handshake_done: &mut bool,
    console_attached: &mut bool,
    device_info: &DeviceInfo,
    device_identity: &DeviceIdentity,
) where
    S: Write,
{
    // Decode the protobuf body. A malformed body is dropped (the link keeps
    // resyncing for the next frame).
    let Some(msg) = Message::decode(&bound.body) else {
        return;
    };

    let mut ctx = Ctx::new(device_info, device_identity);
    ctx.handshake_done = *handshake_done;
    ctx.console_attached = *console_attached;
    let (outcome, done) = dispatch::dispatch(&msg, &ctx);
    *handshake_done = done;

    // Send the reply as a RAW 8-byte-header + body frame, unescaped — the host
    // reads a fixed header and a body-length-bounded body straight off the
    // reliable (encrypted) stream. The channel echoes the triggering message's
    // channel.
    if let Some(reply) = outcome.reply {
        let body = proto::encode_message(&reply);
        if let Err(e) = write_frame(session, bound.header.channel, body.as_slice()).await {
            warn!("LAN: write reply failed: {e:?}");
        }
    }

    // SensorLink: feed a raw-RGB565 frame chunk into the shared reassembler,
    // the same path the USB task uses. The render loop draws a completed frame.
    if let Some(sensor_data) = outcome.sensor_data {
        crate::script::feed_sensor_data(&sensor_data);
    }

    // Host→device stdin: route into the *same* ring buffer the USB path uses,
    // so a pushed line reaches `message_task` and displays on screen.
    if let Some(stdin) = outcome.stdin {
        // Preview only the leading bytes. A full `put` line can be up to
        // STDIN_MAX (256) bytes, and dumping every byte on every line floods
        // the slow UART console and slows processing. Show the length plus a
        // short prefix, and an ellipsis when it is truncated.
        const PREVIEW: usize = 24;
        let n = stdin.len();
        let preview = &stdin[..n.min(PREVIEW)];
        // Kept at debug: one frame per host line (hundreds for a full image);
        // at info it floods the slow UART console.
        if n > PREVIEW {
            debug!("LAN: routing stdin ({} bytes): {:?}…", n, preview);
        } else {
            debug!("LAN: routing stdin ({} bytes): {:?}", n, preview);
        }
        put_stdin_data(stdin.as_slice());
    }

    if let Some(attach) = outcome.console_attach {
        *console_attached = true;
        info!(
            "LAN: console_attach event_id={} duration_ms={}",
            attach.event_id, attach.duration
        );
    }
    if let Some(detach) = outcome.console_detach {
        *console_attached = false;
        info!("LAN: console_detach event_id={}", detach);
    }
    if let Some(reboot) = outcome.reboot {
        info!(
            "LAN: reboot app_auto_start={} delay_ms={}",
            reboot.app_auto_start, reboot.app_auto_start_delay
        );
        // Reboot is final: `software_reset` never returns.
        esp_hal::system::software_reset();
    }
}

/// Write a raw Wendy frame (8-byte header + body) over the stream. The body
/// is written unescaped, matching the TLS/LAN path.
async fn write_frame<S>(stream: &mut S, channel: u8, body: &[u8]) -> Result<(), S::Error>
where
    S: Write,
{
    let len = body.len();
    let header = [
        WENDY_MSG_MAGIC,   // 0xA5
        WENDY_MSG_VERSION, // 2
        0u8,               // category (reserved)
        channel,           // channel (echo the triggering channel)
        0u8,
        0u8,                // reserved (big-endian u16 = 0)
        (len >> 8) as u8,   // body_size, big-endian hi
        (len & 0xff) as u8, // body_size, big-endian lo
    ];
    // Each write/flush is awaited: an un-awaited `write` future is dropped
    // immediately and the bytes never reach the wire (this is the plain-TCP
    // bug this port fixed when it moved off the synchronous USB driver).
    stream.write(&header).await?;
    stream.write(body).await?;
    stream.flush().await?;
    Ok(())
}

/// Build a `heapless::String` from a literal known to fit its capacity.
fn lit<const N: usize>(s: &str) -> heapless::String<N> {
    heapless::String::<N>::try_from(s).expect("literal exceeds capacity")
}
