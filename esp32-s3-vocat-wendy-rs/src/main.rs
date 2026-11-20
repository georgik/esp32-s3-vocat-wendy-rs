//! ESP-VoCat (ESP32-S3) — Wendy-compatible host→device text display.
//!
//! Pure-Rust `no_std` port of the console half of the Wendy Lite `wendy_core`
//! stack, running on the round 360×360 ST77916 LCD. This is the "wow" demo:
//! `wendy run` (USB) pushes a string → it appears on the screen.
//!
//! Layout:
//! - `console_task` (core 0): polls USB-Serial/JTAG, feeds the 128-byte stdin
//!   ring buffer ([`wendy_console`]).
//! - `message_task` (core 0): drains the ring, commits the latest line and
//!   forwards it over [`MSG_CH`] to the renderer.
//! - `main` render loop (core 1): draws a live demo + the message band and
//!   flushes only the changed rows.
//!
//! See `wiki/esp32-s3-vocat-rust-wendy.md` for the full plan.
#![no_std]
#![no_main]

extern crate alloc;
use alloc::format;

// ESP-IDF App Descriptor required by newer espflash
esp_bootloader_esp_idf::esp_app_desc!();

use embassy_executor::Spawner;
use embassy_time::{Duration, Instant, Timer};
use embedded_graphics::{
    mono_font::{MonoTextStyle, ascii::FONT_8X13},
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{PrimitiveStyle, Rectangle},
    text::Text,
};
use log::{debug, info, warn};

// embassy_sync gives us both the channel used to hand the latest message from
// the message task to the renderer (cross-core safe) and the raw mutex it is
// built on.
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;

use esp_vocat::board;
use esp_vocat::display::{Backlight, FrameBuffer, Lcd};

mod script;
mod wendy_console;

// Wi-Fi station + embassy-net/smoltcp stack.
mod wifi;
// LAN Wendy server (TCP :5054) on the same stack.
mod lan;
// mDNS responder: advertises the board over the LAN so `wendy device list`
// can browse/resolve it (the wireless counterpart to the USB Wendy link).
mod mdns;
// TLS layer: self-signed server cert/key + session config for the
// MbedTLS session wrapping the LAN socket.
mod tls;
// Wendy link: DLE-ESC de-framing → 8-byte frame assembly → protobuf
// decode → command dispatch. All live in the `wendy` crate
// (see `wendy/`), pure-Rust and `no_std`.
use wendy::dispatch::{self, Ctx, io};
use wendy::esc::{ESC_CMD_COM, ESC_CMD_CONSOLE, ESC_CMD_ECHO, ESC_CMD_OFF, EscDecoder, EscItem};
use wendy::frame::{self, FrameReader, WENDY_MSG_MAGIC, WENDY_MSG_VERSION};
use wendy::proto::{self, ConsoleData, DeviceIdentity, DeviceInfo, Event, EventData, Message};
use wendy::stdio::{READ_CHUNK, put_stdout};
use wendy_console::{put_stdin_data, read_stdin};

/// Maximum committed message length (the ring holds 128 bytes; the host
/// truncates, but we bound the committed line independently).
const MSG_MAX_LEN: usize = 96;

/// Queue carrying the latest committed host message from `message_task` to the
/// renderer.
///
/// Depth is deliberately large (not 1): the host pumps a whole image as a burst
/// of hundreds of lines over the LAN, and `message_task` must be able to queue
/// them all up and drain the stdin ring *before* the renderer consumes them one
/// at a time. A depth‑1 queue would make `message_task` block on `send()` at the
/// renderer's per‑line rate, letting the stdin ring overflow and drop the `\n`
/// between command lines — which merges `>put …>put …` and breaks base64.
static MSG_CH: Channel<CriticalSectionRawMutex, heapless::String<MSG_MAX_LEN>, 128> =
    Channel::new();

/// Link body cap: bounds the protobuf body we will buffer. Larger inbound
/// frames are dropped (corrupt-resync) rather than trusted. Handshake,
/// command, response, and console-data messages are small, but a SensorLink
/// frame carries a raw-RGB565 `SensorData` chunk whose payload can be up to
/// `SENSOR_PAYLOAD_CAP` (2048 B) plus protobuf framing, so this is sized to
/// hold one such frame.
const BODY_CAP: usize = 2200;

/// USB-JTAG console/link mode.
enum UsjMode {
    /// Default: each received byte is stdin for the app.
    Console,
    /// Echo every received byte back (host uses this to match its sentinel).
    Echo,
    /// Full Wendy link: esc → frame → proto → dispatch.
    Com,
    /// Link closed.
    Off,
}

/// `#[embassy_executor::task]` functions may carry parameters; they are moved
/// into the spawned task, so the owned USB driver lives there.
#[embassy_executor::task]
async fn console_task(
    mut usb: esp_hal::usb::usb_serial_jtag::UsbSerialJtag<'static, esp_hal::Blocking>,
) {
    // Wendy link state.
    let mut esc = EscDecoder::new();
    let mut reader = FrameReader::<BODY_CAP>::new();
    let mut mode = UsjMode::Console;
    let mut handshake_done = false;

    // Console capture state. When attached, the pump streams the
    // captured-stdout ring back to the host as `WendyEvent` console_data.
    let mut console_attached = false;
    let mut console_event_id: u32 = 0;
    // Absolute expiry for a lease-based attach (`duration_ms != 0`). `None`
    // means "forever" — the host asked for a non-expiring attach.
    let mut console_deadline: Option<Instant> = None;

    // Static device description/identity advertised via get_device_info/identity.
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

    loop {
        // While attached, drain any captured stdout and stream it to the host
        // as `WendyEvent` console_data. Non-blocking: returns immediately
        // when there is nothing to send (or nothing is attached).
        pump_stdout(
            &mut usb,
            &mut console_attached,
            &mut console_event_id,
            &mut console_deadline,
        );

        // `read_byte` is non-blocking: `Err` means "no byte right now"
        // (`nb::Error::WouldBlock`), so we yield and poll again.
        match usb.read_byte() {
            Ok(b) => match esc.feed(b) {
                // A de-ESCaed data byte: its meaning depends on the current
                // link mode.
                Some(EscItem::Data(d)) => match mode {
                    UsjMode::Com => {
                        // Feed the byte into the frame assembler; when a full
                        // frame body is collected, decode + dispatch it.
                        if let Some(bound) = reader.feed(d) {
                            handle_frame(
                                &mut usb,
                                &mut handshake_done,
                                &mut console_attached,
                                &mut console_event_id,
                                &mut console_deadline,
                                &bound,
                                &device_info,
                                &device_identity,
                            );
                        }
                    }
                    UsjMode::Echo => {
                        // Echo the raw byte back so the host can match its
                        // sentinel and switch into com mode.
                        let _ = usb.write(&[d]);
                    }
                    UsjMode::Console => {
                        // Raw console passthrough: the byte is app stdin.
                        put_stdin_data(&[d]);
                    }
                    UsjMode::Off => {}
                },
                // A link command (`c`/`e`/`m`/`o`). Only acted on outside com
                // mode: once the link is up, the ESC stream is owned by the
                // link (keep-alives and the like pass through untouched).
                Some(EscItem::Cmd(c)) => match mode {
                    UsjMode::Com => {}
                    _ => {
                        mode = match c {
                            ESC_CMD_CONSOLE => UsjMode::Console,
                            ESC_CMD_ECHO => UsjMode::Echo,
                            ESC_CMD_COM => UsjMode::Com,
                            ESC_CMD_OFF => UsjMode::Off,
                            _ => mode,
                        };
                        esc.reset_last_cmd();
                    }
                },
                // Keep-alive: no action here (the link stays up over a direct
                // USB connection).
                Some(EscItem::KeepAlive) => {}
                // Just recorded an ESC; nothing to do until the follow-up byte.
                None => {}
            },
            Err(_) => Timer::after(Duration::from_millis(1)).await,
        }
    }
}

/// Decode a collected frame body, dispatch it, and apply the outcome: send the
/// reply as a raw frame and perform any side effect (stdin injection, console
/// attach/detach, reboot).
fn handle_frame(
    usb: &mut esp_hal::usb::usb_serial_jtag::UsbSerialJtag<'static, esp_hal::Blocking>,
    handshake_done: &mut bool,
    console_attached: &mut bool,
    console_event_id: &mut u32,
    console_deadline: &mut Option<Instant>,
    bound: &frame::Frame<BODY_CAP>,
    device_info: &DeviceInfo,
    device_identity: &DeviceIdentity,
) {
    // Decode the protobuf body. A malformed body is dropped (the link keeps
    // resyncing for the next frame).
    let Some(msg) = Message::decode(&bound.body) else {
        return;
    };

    let ctx = Ctx {
        handshake_done: *handshake_done,
        console_attached: false,
        device_info,
        device_identity,
    };
    let (outcome, done) = dispatch::dispatch(&msg, &ctx);
    *handshake_done = done;

    // Send the reply as a RAW 8-byte-header + body frame. The host's reader
    // reads a fixed header and a body-length-bounded body with no de-escape,
    // so the reply must not be DLE-ESC escaped. The channel echoes the
    // triggering message's channel (0 on a direct link).
    if let Some(reply) = outcome.reply {
        let body = proto::encode_message(&reply);
        write_frame(usb, bound.header.channel, body.as_slice());
    }

    // SensorLink: feed a raw-RGB565 frame chunk into the shared reassembler.
    // The render loop draws a completed frame. A dropped chunk (lock
    // contention or an out-of-order/gap chunk) is self-healing — the next
    // `chunk_seq == 0` restarts the frame.
    if let Some(sensor_data) = outcome.sensor_data {
        script::feed_sensor_data(&sensor_data);
    }

    // Side effects.
    if let Some(stdin) = outcome.stdin {
        put_stdin_data(stdin.as_slice());
    }
    if let Some(attach) = outcome.console_attach {
        // Enter console capture for this event id. A `duration` of 0 means the
        // host wants capture to run forever; otherwise it expires after the
        // lease, at which point the pump detaches on its own.
        *console_attached = true;
        *console_event_id = attach.event_id;
        *console_deadline = if attach.duration == 0 {
            None
        } else {
            Some(
                embassy_time::Instant::now()
                    .saturating_add(Duration::from_millis(attach.duration as u64)),
            )
        };
        wcom_console(format!(
            "[wcom] console_attach event_id={} duration_ms={} blocking={} -> console captured",
            attach.event_id, attach.duration, attach.blocking
        ));
    }
    if let Some(detach) = outcome.console_detach {
        *console_attached = false;
        *console_deadline = None;
        wcom_console(format!(
            "[wcom] console_detach event_id={} -> console released",
            detach
        ));
    }
    if let Some(reboot) = outcome.reboot {
        wcom_console(format!(
            "[wcom] reboot app_auto_start={} delay_ms={}",
            reboot.app_auto_start, reboot.app_auto_start_delay
        ));
        // Reboot is final: `software_reset` never returns.
        esp_hal::system::software_reset();
    }
}

/// Write a raw Wendy frame (8-byte header + body) over USB-JTAG. The body is
/// written unescaped: the host reads a fixed-size header and a body-length
/// bounded body straight from the byte stream.
fn write_frame(
    usb: &mut esp_hal::usb::usb_serial_jtag::UsbSerialJtag<'static, esp_hal::Blocking>,
    channel: u8,
    body: &[u8],
) {
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
    let _ = usb.write(&header);
    let _ = usb.write(body);
}

/// Emit a `[wcom]` line to the captured-stdout ring so the host console
/// streams it while attached. Returns whether the whole line was accepted
/// (false means the ring overflowed and the tail was dropped).
fn wcom_console(line: alloc::string::String) -> bool {
    put_stdout(line.as_bytes()) == line.len()
}

/// While console capture is attached, drain the captured-stdout ring and stream
/// each chunk back to the host as a `WendyEvent` (console_data) on the
/// attached event id, on the default category/channel 0 (which is what the host
/// reads — it discards any frame on a non-zero category or channel).
///
/// Non-blocking: it returns immediately when nothing is attached or the ring is
/// empty. A lease-based attach (`console_deadline` set) detaches itself once the
/// lease has expired, exactly like the C pump's deadline check.
fn pump_stdout(
    usb: &mut esp_hal::usb::usb_serial_jtag::UsbSerialJtag<'static, esp_hal::Blocking>,
    console_attached: &mut bool,
    console_event_id: &mut u32,
    console_deadline: &mut Option<Instant>,
) {
    if !*console_attached {
        return;
    }
    // Lease expired: detach silently. The host stops subscribing on its own.
    if let Some(deadline) = *console_deadline {
        if embassy_time::Instant::now() >= deadline {
            *console_attached = false;
            *console_deadline = None;
            return;
        }
    }

    // Read one chunk from the captured-stdout ring. `gap` is true when output
    // was dropped before this read (non-blocking capture mode).
    let mut chunk = [0u8; READ_CHUNK];
    let mut gap = false;
    let n = wendy::stdio::read_stdout(&mut chunk, &mut gap);
    if n == 0 {
        return;
    }

    // Frame it as WendyEvent { event_id, console_data { io=STANDARD_OUTPUT,
    // gap, data } } and send it on channel 0. The data slice is bounded by
    // READ_CHUNK, which equals ConsoleData's buffer width, so this cannot fail.
    let mut data = heapless::Vec::<u8, 256>::new();
    if data.extend_from_slice(&chunk[..n]).is_err() {
        return;
    }
    let evt = Event {
        event_id: *console_event_id,
        data: EventData::ConsoleData(ConsoleData {
            io: io::STANDARD_OUTPUT,
            gap,
            data,
        }),
    };
    let body = proto::encode_event(&evt);
    let _ = write_frame(usb, 0, body.as_slice());
}

/// Build a `heapless::String` from a literal known to fit its capacity.
fn lit<const N: usize>(s: &str) -> heapless::String<N> {
    heapless::String::<N>::try_from(s).expect("literal exceeds capacity")
}

/// Drains the stdin ring buffer and commits the latest line.
///
/// Reads are non-blocking (return 0 when empty) — matching the C
/// `O_NONBLOCK` stdin requirement. A blocking read here would freeze the chip
/// (the s3box3 `rst:0xc` reset-on-block gotcha).
#[embassy_executor::task]
async fn message_task() {
    let mut line: heapless::String<MSG_MAX_LEN> = heapless::String::new();
    loop {
        let mut buf = [0u8; wendy_console::STDIN_BUF_SIZE];
        let n = read_stdin(&mut buf);
        if n == 0 {
            Timer::after(Duration::from_millis(10)).await;
            continue;
        }
        for &b in &buf[..n] {
            if b == b'\n' || b == b'\r' {
                // Commit on newline/carriage-return: hand the line to the
                // renderer and start buffering the next one.
                let committed = line.clone();
                line.clear();
                // Kept at debug: this fires once per host line (hundreds for a
                // full image) and each `println!` to the slow UART stalls the
                // consumer, which lets the stdin ring overflow and merge the
                // following `>` command lines together.
                debug!("message_task: committing line: {committed:?}");
                MSG_CH.sender().send(committed).await;
            } else if line.len() < MSG_MAX_LEN {
                // Console input is ASCII; push the byte as its char.
                let _ = line.push(b as char);
            }
        }
    }
}

/// What the render loop draws each frame. The display starts in [`View::Demo`]
/// and the host can switch it with the `> image` / `> demo` / `> clear`
/// console commands; a streamed SensorLink frame also auto-enters
/// [`View::Image`] while idle (see the render loop below).
#[derive(Clone, Copy, PartialEq)]
enum View {
    /// The live bouncing-box demo plus the latest centered message. The idle
    /// default when nothing else is showing.
    Demo,
    /// The most recently assembled SensorLink image, held on screen (and
    /// refreshed in place) until the caller switches view.
    Image,
    /// The accumulated DSL script, which fully defines the scene.
    Script,
}

/// Draws a live demo (a bouncing box) so the display has live content.
fn draw_demo(fb: &mut FrameBuffer, frame: u32) {
    const SIZE: u32 = 48;
    const SPEED: u32 = 4;
    let max = 360 - SIZE;
    // Bounce the box along both axes from the frame counter.
    let t = (frame * SPEED) % (2 * max);
    let (x, y) = if t <= max {
        (t, (t * 3 / 4).min(max))
    } else {
        (2 * max - t, ((2 * max - t) * 3 / 4).min(max))
    };
    let style = PrimitiveStyle::with_fill(Rgb565::WHITE);
    Rectangle::new(Point::new(x as i32, y as i32), Size::new(SIZE, SIZE))
        .into_styled(style)
        .draw(fb)
        .ok();
}

/// Draws the latest message centered in the middle of the (round) panel.
///
/// The text sits on a dark panel with a subtle border and white glyphs, so it
/// stays readable no matter what the bouncing demo draws behind it. When no
/// message has been received yet, a default greeting is shown instead.
fn draw_centered(fb: &mut FrameBuffer, msg: &str) {
    const TEXT_PAD: u32 = 18;
    const PANEL: Rgb565 = Rgb565::new(0x0E, 0x12, 0x1C); // dark panel

    // Pick the text to display: a default greeting when nothing arrived yet.
    let text: heapless::String<MSG_MAX_LEN> = if msg.is_empty() {
        let mut s = heapless::String::<MSG_MAX_LEN>::new();
        let _ = s.push_str("Hello ESP32-S3");
        s
    } else {
        let mut s = heapless::String::<MSG_MAX_LEN>::new();
        // FONT_8X13 glyphs are ~5px wide; keep the text inside the panel.
        let max_chars = ((360 - 2 * TEXT_PAD) / 5) as usize;
        let limit = if msg.len() > max_chars {
            max_chars - 1
        } else {
            msg.len()
        };
        for c in msg.chars().take(limit) {
            let _ = s.push(c);
        }
        if msg.len() > max_chars {
            let _ = s.push('…');
        }
        s
    };

    let text_w = text.len() as u32 * 5;
    let text_h: u32 = 13;
    let pw = text_w + 2 * TEXT_PAD;
    let ph = text_h + 2 * TEXT_PAD;
    // Center the panel on the 360x360 panel.
    let origin = Point::new((360 - pw as i32) / 2, (360 - ph as i32) / 2);

    // Dark panel behind the text so white glyphs stay readable.
    Rectangle::new(origin, Size::new(pw, ph))
        .into_styled(PrimitiveStyle::with_fill(PANEL))
        .draw(fb)
        .ok();

    // Center the text inside the panel.
    let tx = origin.x + ((pw as i32 - text_w as i32) / 2);
    let ty = origin.y + ((ph as i32 - text_h as i32) / 2);
    let style = MonoTextStyle::new(&FONT_8X13, Rgb565::WHITE);
    Text::new(text.as_str(), Point::new(tx, ty), style)
        .draw(fb)
        .ok();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    esp_println::println!("Panic: {_info}");
    loop {}
}

#[esp_rtos::main]
async fn main(spawner: Spawner) -> ! {
    let peripherals = board::init();
    esp_println::logger::init_logger_from_env();

    // The Wi-Fi driver (esp-radio) needs internal RAM. esp_alloc's global
    // allocator only serves Internal-capable memory, and the PSRAM heap below
    // is External-only, so without an Internal region every wifi allocation
    // fails with OutOfMemory even though 16 MB of PSRAM is free. This uses a
    // reclaimed-heap allocator plus a small extra internal region.
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: board::RECLAIMED_HEAP);
    esp_alloc::heap_allocator!(size: 96 * 1024);

    // Heap: all of the octal PSRAM, which holds the 253 KiB framebuffer.
    let psram = board::psram(peripherals.PSRAM);
    esp_alloc::psram_allocator!(&psram);

    // Embassy timer for `embassy_time`, started through esp-rtos.
    let timg0 = esp_hal::timer::timg::TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    // The LAN TLS handshake needs an entropy source. `TrngSource::new` enables
    // the chip TRNG; `Trng::try_new()` then succeeds (it errors with
    // `TrngSourceNotEnabled` if the source is not first enabled). The source is
    // dropped at the end of `main`'s scope, and its `drop()` reverts the
    // entropy — so it must stay alive for the whole program. Declaring it here
    // (as a main-local, before the infinite display loop) keeps it enabled for
    // every future handshake.
    let _trng_source = esp_hal::rng::TrngSource::new(peripherals.RNG, peripherals.ADC1);
    static TRNG_CELL: static_cell::StaticCell<esp_hal::rng::Trng> = static_cell::StaticCell::new();
    let trng = TRNG_CELL
        .uninit()
        .write(esp_hal::rng::Trng::try_new().expect("TRNG source not enabled"));
    // The single-active MbedTLS instance, seeded by the static TRNG. Only one
    // TLS context may be active at a time, so this is a shared static.
    static TLS_CELL: static_cell::StaticCell<mbedtls_rs::Tls<'static>> =
        static_cell::StaticCell::new();
    let tls = TLS_CELL
        .uninit()
        .write(mbedtls_rs::Tls::new(trng).expect("Tls::new failed"));

    // Power the LCD (VCC_3V3) and the codec (CODEC_3V3); keep the pins alive.
    let _power = board::peripheral_power_on(peripherals.GPIO9);
    let _codec = board::codec_power_on(peripherals.GPIO48);
    Timer::after(Duration::from_millis(100)).await;

    // Take the USB-Serial/JTAG peripheral out of `peripherals` for the console
    // task (the remaining fields are still used for the LCD below). Construct
    // the `UsbSerialJtag` driver from the raw peripheral; the driver-mode
    // generic (`Blocking`) is inferred from this value.
    let usb = esp_hal::usb::usb_serial_jtag::UsbSerialJtag::new(peripherals.USB_DEVICE);
    spawner.spawn(console_task(usb).expect("spawn console_task"));
    spawner.spawn(message_task().expect("spawn message_task"));

    info!("ESP-VoCat Wendy console starting (USB Wendy link + text display)");

    // Wi-Fi. Best-effort — only when credentials are baked in at build time
    // (`WIFI_SSID`/`WIFI_PASSWORD`). The radio runs over its own SPI and is
    // independent of the USB Wendy link, so the display + console keep
    // running regardless.
    // Report the heap so we can verify the allocator is wired up when the
    // radio requests its packet queues.
    info!("heap: {:#?}", esp_alloc::HEAP.stats());

    if let Some((ssid, password)) = wifi::credentials() {
        match wifi::station_config(ssid, password) {
            Ok(config) => match wifi::init_wifi(peripherals.WIFI, Some(config)) {
                Ok((controller, interface)) => {
                    info!("Wi-Fi station configured for '{ssid}'");
                    let seed = u64::from(esp_hal::rng::Rng::new().random()) << 32
                        | u64::from(esp_hal::rng::Rng::new().random());
                    let stack = wifi::start(&spawner, controller, interface, seed);
                    spawner.spawn(wifi::sntp_probe_task(stack).expect("spawn sntp probe task"));
                    // LAN Wendy server (TLS) on the same
                    // stack, wrapping each accepted socket in the self-signed
                    // MbedTLS server session.
                    spawner.spawn(lan::lan_server_task(tls, stack).expect("spawn lan server task"));
                    // mDNS responder so the board is browsable over the LAN.
                    spawner.spawn(mdns::mdns_task(stack).expect("spawn mdns task"));
                }
                Err(e) => warn!("Wi-Fi init failed: {e:?} (continuing on USB only)"),
            },
            Err(e) => warn!("bad Wi-Fi credentials: {e:?} (continuing on USB only)"),
        }
    } else {
        info!("Wi-Fi credentials not set at build time — running on USB only");
    }

    // LCD: reset line, backlight, then initialise the ST77916.
    let mut reset = board::LcdReset::new(peripherals.GPIO47);
    let mut backlight = Backlight::new(peripherals.LEDC, peripherals.GPIO44);
    backlight.set(100);
    let mut lcd = match Lcd::new(
        peripherals.SPI2,
        peripherals.DMA_CH0,
        esp_vocat::lcd_pins!(peripherals),
        &mut reset,
    )
    .await
    {
        Ok(l) => l,
        Err(e) => {
            warn!("LCD init failed: {e:?}");
            loop {}
        }
    };

    // Holds the latest message received from `message_task`.
    let mut last_msg: heapless::String<MSG_MAX_LEN> = heapless::String::new();
    // Accumulated graphics script. A line prefixed with `>` is a drawing
    // command; sending commands one line at a time animates the panel.
    let mut script = script::Script::new();
    let mut view = View::Demo;
    let mut frame: u32 = 0;
    loop {
        // Drain *all* committed lines that are waiting (non-blocking). With a
        // deep queue this catches up a burst of image lines in one go instead
        // of one per 30 ms frame — otherwise the renderer's per-line pace
        // starves the stdin ring, which merges command lines and breaks decode.
        while let Ok(line) = MSG_CH.receiver().try_receive() {
            let trimmed = line.trim();
            if let Some(body) = trimmed.strip_prefix('>') {
                // A command line (leading `>`) controls what is drawn each
                // frame. The panel starts in the idle demo view.
                match body.trim().to_ascii_lowercase().as_str() {
                    // `>` or `> clear` empties the script and returns to the
                    // idle bouncing-box demo.
                    "" | "clear" | "reset" => {
                        script.reset();
                        view = View::Demo;
                    }
                    // `> image` pins the most recently streamed SensorLink
                    // frame on the screen until the caller switches view.
                    "image" => view = View::Image,
                    // `> help` prints the available commands on the panel
                    // (the demo box still bounces behind them).
                    "help" => {
                        let mut s = heapless::String::<MSG_MAX_LEN>::new();
                        let _ = s.push_str("clear | demo | image | help | img..");
                        last_msg = s;
                    }
                    // Anything else is a drawing command appended to the
                    // running script, which puts the display into script view.
                    // (`demo` animates the bundled scene, `img`/`put`/`place`
                    // assemble a raw image.)
                    _ => match script.push_line(body) {
                        Ok(()) => view = View::Script,
                        Err(err) => info!("script error: {err}"),
                    },
                }
            } else {
                last_msg = line;
            }
        }

        // Drain any just-completed SensorLink frame. When idle (demo view) a
        // fresh frame auto-enters image view so a streamed picture is held on
        // screen instead of flashing for a single frame. While a script or
        // image view is active the assembled pixels stay in the sink and show
        // up on the next `> image`.
        let fresh = script::take_sensor_ready();
        if view == View::Demo && fresh {
            view = View::Image;
        }

        let mut fb = FrameBuffer::new();
        fb.clear(Rgb565::BLACK).ok();

        match view {
            // Hold the streamed image on screen, refreshing it in place as new
            // frames arrive. Fall back to the demo while no frame has landed.
            View::Image => {
                if !script::draw_sensor_image(&mut fb) {
                    draw_demo(&mut fb, frame);
                    draw_centered(&mut fb, last_msg.as_str());
                }
            }
            // The idle demo: a bouncing box with the latest centered message.
            View::Demo => {
                draw_demo(&mut fb, frame);
                draw_centered(&mut fb, last_msg.as_str());
            }
            // A script is active: it fully defines what is on the screen.
            View::Script => {
                script.render(&mut fb);
            }
        }

        // Stream only the changed rows over QSPI.
        lcd.flush(&mut fb).await.unwrap();
        frame = frame.wrapping_add(1);
        Timer::after(Duration::from_millis(30)).await;
    }
}
