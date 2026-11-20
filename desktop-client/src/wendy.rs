//! Wendy host->device stdin framing, over TLS (default) or plain TCP.
//!
//! The firmware's Wendy LAN server (`src/lan.rs` in
//! `esp32-s3-vocat-wendy`) wraps the socket in a self-signed MbedTLS session
//! (server-auth-only, no client certificate) before the Wendy framing runs.
//! The host must therefore complete a TLS handshake with that self-signed
//! server cert — the same "insecure, server-auth-only" mode the reference Go
//! `litemsg` uses (`tls.Dial` + `InsecureSkipVerify: true`). We do that here
//! with rustls and a verifier that accepts the device's self-signed cert.
//!
//! Over a reliable stream (TLS, or plain TCP via `--plain`) there is no
//! DLE-ESC framing — the frame bytes go straight to the device's frame
//! assembler. A Wendy protocol handshake (the `handshake` message built by
//! `build_handshake_frame`) is still required before any command or sensor
//! chunk, or the device rejects them all.
//!
//! ```text
//! frame      = header(8) + body
//! header     = A5 02 00 00 00 00 len_hi len_lo   (big-endian body length)
//! body       = field(5, Event)
//! Event      = field(1, varint event_id=0) + field(3, ConsoleData)
//! ConsoleData= field(1, varint io=0) + field(3, bytes data)
//! ```

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::pki_types::{CertificateDer, ServerName as RustlsServerName, UnixTime};
use rustls::{
    ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned,
};

/// Wendy frame magic + version.
const FRAME_MAGIC: u8 = 0xA5;
const FRAME_VERSION: u8 = 0x02;
const CATEGORY: u8 = 0;
const CHANNEL: u8 = 0;

/// Wendy protocol version this host speaks. It must match the device's
/// `PROTOCOL_VERSION_MAJOR`/`MINOR` (2.0) or the device rejects the opening
/// handshake and never sets `handshake_done`.
const PROTOCOL_VERSION_MAJOR: u32 = 2;
const PROTOCOL_VERSION_MINOR: u32 = 0;

/// Wire types (protobuf).
const WIRE_VARINT: u8 = 0;
const WIRE_LEN_DELIM: u8 = 2;

/// Build a complete Wendy frame for one stdin line (with trailing newline).
pub fn build_stdin_frame(line: &str) -> Vec<u8> {
    // ConsoleData: field(1, io=0) + field(3, bytes data)
    let mut console_data: Vec<u8> = Vec::new();
    console_data.extend(varint_field(1, 0)); // io = STANDARD_INPUT
    console_data.extend(field_bytes(3, line.as_bytes()));
    // Event: field(1, event_id=0) + field(3, ConsoleData)
    let mut event = Vec::new();
    event.extend(varint_field(1, 0)); // event_id = 0
    event.extend(field_bytes(3, &console_data));
    // Message: field(5, Event)
    let mut message = Vec::new();
    message.extend(field_bytes(5, &event));

    let mut frame = Vec::with_capacity(8 + message.len());
    frame.extend_from_slice(&[
        FRAME_MAGIC, FRAME_VERSION, CATEGORY, CHANNEL, 0, 0,
    ]);
    frame.extend_from_slice(&((message.len() as u32).to_be_bytes()[2..])); // len_hi, len_lo
    frame.extend_from_slice(&message);
    frame
}

/// SensorLink channel the device advertises in its manifest (see the firmware's
/// `device_sensor_manifest`): a single raw-RGB565 "wendy-display" sensor.
pub const SENSOR_CHANNEL: u32 = 1;

/// Build a Wendy frame carrying a `sensor_link_subscribe` command.
///
/// Message field 3 (Command) carries `Command { request_id, params }` where the
/// params field 17 holds a `SensorLinkSubscribe` whose field 1 repeats the
/// requested `channel_id`s. This is sent once before the sensor_data stream so
/// the device knows the host wants channel 1.
pub fn build_subscribe_frame(request_id: u32, channel_id: u32) -> Vec<u8> {
    // SensorLinkSubscribe: field 1 = channel_id (repeated varint).
    let mut params: Vec<u8> = Vec::new();
    params.extend(varint_field(1, channel_id as u64));
    // Command: field 1 = request_id, field 17 = params.
    let mut body: Vec<u8> = Vec::new();
    body.extend(varint_field(1, request_id as u64));
    body.extend(field_bytes(17, &params));
    // Message: field 3 = Command.
    build_message_frame(3, &body)
}

/// Build a Wendy frame carrying the opening `handshake` message.
///
/// Message field 1 (Handshake) carries field 1 = `handshake_id` (an arbitrary
/// u32 the device echoes back) and field 2 = the `ProtocolVersion` { major,
/// minor }. The device accepts it when `major` matches its own
/// `PROTOCOL_VERSION_MAJOR`, then sets its `handshake_done` flag — which is
/// what lets the subscribe command through and, crucially, stops it from
/// gating out every subsequent `sensor_data` chunk.
///
/// This frame MUST be sent before any command or sensor chunk, exactly as the
/// reference `WendyLiteClient.handshake()` does. Without it the subscribe is
/// rejected with `BAD_STATE` and the whole image stream is dropped.
pub fn build_handshake_frame(handshake_id: u32) -> Vec<u8> {
    // ProtocolVersion: field(1, major) + field(2, minor).
    let mut version: Vec<u8> = Vec::new();
    version.extend(varint_field(1, PROTOCOL_VERSION_MAJOR as u64));
    version.extend(varint_field(2, PROTOCOL_VERSION_MINOR as u64));
    // Handshake: field(1, handshake_id) + field(2, version).
    let mut handshake: Vec<u8> = Vec::new();
    handshake.extend(varint_field(1, handshake_id as u64));
    handshake.extend(field_bytes(2, &version));
    // Message: field(1) = Handshake.
    build_message_frame(1, &handshake)
}

/// Build a Wendy frame carrying one `sensor_data` chunk.
///
/// Message field 6 (SensorData) carries field 1 channel_id, 2 frame_seq, 3
/// chunk_seq, 4 ts_us, 5 flags, 6 payload. The payload of the first chunk
/// (sent by the caller) begins with the 8-byte width/height header.
pub fn build_sensor_data_frame(
    channel_id: u32,
    frame_seq: u32,
    chunk_seq: u32,
    flags: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.extend(varint_field(1, channel_id as u64));
    body.extend(varint_field(2, frame_seq as u64));
    body.extend(varint_field(3, chunk_seq as u64));
    body.extend(varint_field(4, 0)); // ts_us
    body.extend(varint_field(5, flags as u64));
    body.extend(field_bytes(6, payload));
    build_message_frame(6, &body)
}

/// Build a Wendy frame (8-byte header + body) around a `Message` body that
/// occupies top-level field `msg_field` (3 = Command, 6 = SensorData, 5 =
/// Event, …). Shared by every frame builder so the header is byte-identical.
fn build_message_frame(msg_field: u32, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend(field_bytes(msg_field, body));

    let mut frame = Vec::with_capacity(8 + message.len());
    frame.extend_from_slice(&[
        FRAME_MAGIC, FRAME_VERSION, CATEGORY, CHANNEL, 0, 0,
    ]);
    frame.extend_from_slice(&((message.len() as u32).to_be_bytes()[2..])); // len_hi, len_lo
    frame.extend_from_slice(&message);
    frame
}

fn varint(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut v = value;
    loop {
        let mut byte = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
    out
}

fn varint_field(field: u32, value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(((field << 3) | WIRE_VARINT as u32).to_varint());
    out.extend(varint(value));
    out
}

fn field_bytes(field: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(((field << 3) | WIRE_LEN_DELIM as u32).to_varint());
    out.extend(varint(payload.len() as u64));
    out.extend_from_slice(payload);
    out
}

/// Encode a small integer as a protobuf varint (used for field tags).
trait ToVarint {
    fn to_varint(self) -> Vec<u8>;
}

impl ToVarint for u32 {
    fn to_varint(self) -> Vec<u8> {
        varint(self as u64)
    }
}

/// Send every line as a Wendy stdin frame.
///
/// `tls` selects the transport: `true` (default) speaks TLS to the device's
/// self-signed Wendy LAN server; `false` (`--plain`) uses a bare TCP socket,
/// which is handy for local testing against a non-TLS listener.
///
/// Before handing each line to the transport, the lines are framed for the
/// device's console channel (see `esp32-s3-vocat-wendy` `message_task` + the
/// render loop): the device splits the incoming byte stream on newlines and
/// treats any line beginning with `>` as a **drawing command** — anything else
/// is treated as a chat message. So every DSL line is `>`-prefixed and
/// newline-terminated; otherwise the whole payload would arrive as one
/// message and never become a script.
pub fn send_lines(host: &str, port: u16, lines: &[String], tls: bool) -> Result<(), io::Error> {
    // Each DSL line is `>`-prefixed and newline-terminated (see the module
    // doc), then framed for the device's console channel.
    let framed: Vec<Vec<u8>> = lines
        .iter()
        .map(|l| build_stdin_frame(&format!(">{l}\n")))
        .collect();
    send_raw_frames(host, port, &framed, tls)
}

/// Send raw Wendy frames (e.g. a `sensor_link_subscribe` command followed by
/// its `sensor_data` stream) over the LAN.
///
/// `tls` selects the transport: `true` (default) speaks TLS to the device's
/// self-signed Wendy LAN server; `false` (`--plain`) uses a bare TCP socket.
pub fn send_raw_frames(
    host: &str,
    port: u16,
    frames: &[Vec<u8>],
    tls: bool,
) -> Result<(), io::Error> {
    if tls {
        send_raw_frames_tls(host, port, frames)
    } else {
        send_raw_frames_plain(host, port, frames)
    }
}

fn send_raw_frames_plain(
    host: &str,
    port: u16,
    frames: &[Vec<u8>],
) -> Result<(), io::Error> {
    let mut stream = TcpStream::connect((host, port))?;
    stream.set_nodelay(true).ok();
    for frame in frames {
        stream.write_all(frame)?;
    }
    stream.flush()?;

    // Drain any bytes the peer still has buffered before closing, so the
    // kernel doesn't emit a RST (which the device logs as
    // `read error: Io(ConnectionReset)`) when we shut the socket down.
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut scratch = [0u8; 256];
    loop {
        match stream.read(&mut scratch) {
            Ok(0) => break, // peer closed first: clean
            Ok(_) => continue, // drained more: keep going
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break, // timed out
            Err(_) => break,
        }
    }

    // Clean half-close so the peer observes EOF rather than a RST.
    let _ = stream.shutdown(std::net::Shutdown::Both);
    Ok(())
}

/// rustls verifier that accepts the device's self-signed server certificate.
///
/// The device presents a self-signed cert and does not require a client
/// certificate, so it accepts the cert and any signature the server produces.
#[derive(Debug)]
struct InsecureServerVerifier;

impl ServerCertVerifier for InsecureServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &RustlsServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Support every scheme the firmware's mbedtls might use so the
        // handshake can pick one that both sides agree on.
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

fn tls_client_config() -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_safe_default_protocol_versions()
        .expect("rustls: unsupported protocol version")
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(InsecureServerVerifier))
        .with_no_client_auth()
}

/// Connect over TCP, complete a TLS handshake with the self-signed server, then
/// stream the raw Wendy frames through the encrypted session.
pub fn send_raw_frames_tls(
    host: &str,
    port: u16,
    frames: &[Vec<u8>],
) -> Result<(), io::Error> {
    let tcp = TcpStream::connect((host, port))?;
    tcp.set_nodelay(true).ok();

    let server_name = RustlsServerName::try_from(host.to_string())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid host name"))?;

    let config = std::sync::Arc::new(tls_client_config());
    let conn = ClientConnection::new(config, server_name)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tls handshake: {e}")))?;

    let mut tls = StreamOwned::new(conn, tcp);
    for frame in frames {
        tls.write_all(frame)?;
    }
    tls.flush()?;

    // Drain any device->host bytes still buffered (the handshake reply or any
    // status frame) before closing. A socket that is closed while it still has
    // unread receive data makes the kernel emit a TCP RST, which the device
    // logs as `read error: Io(ConnectionReset)` even though every frame was
    // already delivered. Read until EOF, the device closes first, or the read
    // timeout elapses.
    let _ = tls.sock.set_read_timeout(Some(Duration::from_millis(200)));
    let mut scratch = [0u8; 256];
    loop {
        match tls.read(&mut scratch) {
            Ok(0) => break, // device closed first: clean
            Ok(_) => continue, // drained more: keep going
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break, // timed out
            Err(_) => break,
        }
    }

    // Best-effort graceful TLS close (close_notify) followed by a clean TCP
    // half-close, so the peer observes a clean EOF (`Ok(0)`) rather than a RST.
    let _ = tls.conn.send_close_notify();
    let _ = tls.flush();
    let (_conn, sock) = tls.into_parts();
    let _ = sock.shutdown(std::net::Shutdown::Both);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_has_magic_header_and_length() {
        let frame = build_stdin_frame("hi");
        assert_eq!(&frame[..4], &[0xA5, 0x02, 0x00, 0x00]);
        let body_len = u16::from_be_bytes([frame[6], frame[7]]) as usize;
        assert_eq!(body_len, frame.len() - 8);
    }

    #[test]
    fn frame_round_trips_through_a_decoder() {
        // Decode the protobuf body back to the original line.
        let frame = build_stdin_frame("place 10 20");
        let body = &frame[8..];
        let extracted = extract_console_data(body);
        assert_eq!(extracted, "place 10 20");
    }

    /// The opening handshake must be a `Message` (field 1) carrying a
    /// `Handshake` whose version is `2.0`, so the device accepts it and sets
    /// `handshake_done` (which lets the subscribe + sensor stream through).
    #[test]
    fn handshake_frame_carries_version_2_0() {
        let frame = build_handshake_frame(0x1122_3344);
        // Message: field 1 is the length-delimited Handshake body.
        let handshake = read_field(&frame[8..], 1);
        if handshake.is_empty() {
            panic!("Message field 1 (Handshake) missing");
        }
        // Handshake: field 1 = handshake_id (varint), field 2 = version (bytes).
        let mut id: Option<u32> = None;
        let mut version: Option<Vec<u8>> = None;
        for (field, wire, val) in decode_fields(&handshake) {
            match field {
                1 if wire == WIRE_VARINT => id = Some(read_u32(&val)),
                2 if wire == WIRE_LEN_DELIM => version = Some(val),
                _ => {}
            }
        }
        assert_eq!(id, Some(0x1122_3344));
        let version = match version.take() {
            Some(v) => v,
            _ => panic!("Handshake field 2 (version) missing"),
        };
        // Version: field 1 = major, field 2 = minor (both varint).
        let mut major: u32 = 0;
        let mut minor: u32 = 0;
        for (field, wire, val) in decode_fields(&version) {
            if wire != WIRE_VARINT {
                continue;
            }
            let v = read_u32(&val);
            match field {
                1 => major = v,
                2 => minor = v,
                _ => {}
            }
        }
        assert_eq!(major, 2);
        assert_eq!(minor, 0);
    }

    /// Minimal probe: walk the Message->Event->ConsoleData chain and return the
    /// ConsoleData bytes (field 3 of the ConsoleData message).
    fn extract_console_data(body: &[u8]) -> String {
        let event = read_field(body, 5);
        let console_data = read_field(&event, 3);
        // ConsoleData field 3 is the data string.
        let data = read_field(&console_data, 3);
        String::from_utf8(data).expect("valid utf-8")
    }

    /// Read the payload of the first length-delimited field with `field`.
    fn read_field(msg: &[u8], field: u32) -> Vec<u8> {
        let mut i = 0;
        loop {
            // read a varint tag
            let mut t = 0u64;
            loop {
                let b = msg[i];
                i += 1;
                t = (t << 7) | (b & 0x7F) as u64;
                if b & 0x80 == 0 {
                    break;
                }
            }
            let f = (t >> 3) as u32;
            let wire = (t & 0x7) as u8;
            if wire != WIRE_LEN_DELIM {
                continue;
            }
            // length
            let mut len = 0u64;
            loop {
                let b = msg[i];
                i += 1;
                len = (len << 7) | (b & 0x7F) as u64;
                if b & 0x80 == 0 {
                    break;
                }
            }
            let payload = msg[i..i + len as usize].to_vec();
            i += len as usize;
            if f == field {
                return payload;
            }
        }
    }

    /// Decode a protobuf body into (field, wire_type, raw_value_bytes) tuples.
    /// `wire_type` is one of the `WIRE_*` constants; varint values come through
    /// as their raw varint bytes so callers can read them with `read_u32`.
    fn decode_fields(body: &[u8]) -> Vec<(u32, u8, Vec<u8>)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < body.len() {
            // tag
            let mut tag = 0u64;
            let mut shift = 0;
            loop {
                let b = body[i];
                i += 1;
                tag |= ((b & 0x7F) as u64) << shift;
                if b & 0x80 == 0 {
                    break;
                }
                shift += 7;
            }
            let field = (tag >> 3) as u32;
            let wire = (tag & 7) as u8;
            if wire == WIRE_LEN_DELIM {
                let mut len = 0u64;
                let mut lshift = 0;
                loop {
                    let b = body[i];
                    i += 1;
                    len |= ((b & 0x7F) as u64) << lshift;
                    if b & 0x80 == 0 {
                        break;
                    }
                    lshift += 7;
                }
                let end = i + len as usize;
                out.push((field, wire, body[i..end].to_vec()));
                i = end;
            } else if wire == WIRE_VARINT {
                let start = i;
                loop {
                    let b = body[i];
                    i += 1;
                    if b & 0x80 == 0 {
                        break;
                    }
                }
                out.push((field, wire, body[start..i].to_vec()));
            }
            // other wire types are ignored
        }
        out
    }

    /// Read a small varint value (used for handshake_id / version numbers).
    fn read_u32(bytes: &[u8]) -> u32 {
        let mut v = 0u32;
        let mut shift = 0;
        for &b in bytes {
            v |= ((b & 0x7F) as u32) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        v
    }
}
