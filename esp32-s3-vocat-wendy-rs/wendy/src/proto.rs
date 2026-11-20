//! Minimal no_std protobuf wire-format decoder + limited encoder.
//!
//! Implements the little-endian-varint, length-delimited wire format used by
//! the Wendy message envelope, closely enough that a message encoded here
//! round-trips through the host tool and vice-versa:
//!
//! * field tag = `(field_number << 3) | wire_type`
//! * wire types: 0 = varint, 1 = 64-bit, 2 = length-delimited, 5 = 32-bit
//! * oneofs: at most one member is present; unknown members are skipped
//! * presence markers (e.g. `WendyPingParams {}`) decode as an empty
//!   length-delimited field, which is how we detect their presence
//!
//! The decoder never panics: any truncation or malformed input makes the
//! relevant decode return `None` so the caller can simply drop the frame.

use heapless::{String, Vec};

/// A single decoded protobuf field value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field<'a> {
    /// wire type 0 (also covers int32/int64/uint32/uint64/bool/enum)
    Varint(u64),
    /// wire type 1 (fixed64)
    Bits64(u64),
    /// wire type 2 (bytes / embedded message / packed repeated)
    Bytes(&'a [u8]),
    /// wire type 5 (fixed32)
    Bits32(u32),
}

/// Errors while walking a wire buffer. Every decode maps these to `None`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Ran off the end of the buffer mid-value.
    Truncated,
    /// A length-delimited field declared a length past the buffer end.
    LengthOutOfRange,
    /// A wire type we do not support.
    UnknownWireType(u8),
}

/// Iterates the fields of one protobuf-encoded message.
pub struct FieldIter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> FieldIter<'a> {
    /// Start iterating over a raw message buffer.
    pub fn new(buf: &'a [u8]) -> Self {
        FieldIter { buf, pos: 0 }
    }

    /// Read the next `(field_number, value)` pair.
    ///
    /// Returns `None` when the buffer is exhausted, `Some(Err(_))` on a
    /// malformed field, and `Some(Ok(_))` for a well-formed field.
    pub fn next(&mut self) -> Option<Result<(u32, Field<'a>), ParseError>> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let tag = self.read_varint().ok()?;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x7) as u8;
        let value = match wire_type {
            0 => match self.read_varint() {
                Ok(v) => Field::Varint(v),
                Err(e) => return Some(Err(e)),
            },
            1 => match self.read_raw64() {
                Ok(v) => Field::Bits64(v),
                Err(e) => return Some(Err(e)),
            },
            2 => match self.read_bytes() {
                Ok(v) => Field::Bytes(v),
                Err(e) => return Some(Err(e)),
            },
            5 => match self.read_raw32() {
                Ok(v) => Field::Bits32(v),
                Err(e) => return Some(Err(e)),
            },
            other => return Some(Err(ParseError::UnknownWireType(other))),
        };
        Some(Ok((field_number, value)))
    }

    fn read_varint(&mut self) -> Result<u64, ParseError> {
        let mut result: u64 = 0;
        let mut shift = 0usize;
        loop {
            if self.pos >= self.buf.len() {
                return Err(ParseError::Truncated);
            }
            let byte = self.buf[self.pos];
            self.pos += 1;
            result |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift >= 64 {
                // A varint longer than ten bytes cannot represent a u64.
                return Err(ParseError::Truncated);
            }
        }
    }

    fn read_bytes(&mut self) -> Result<&'a [u8], ParseError> {
        let len = self.read_varint()? as usize;
        if self.pos + len > self.buf.len() {
            return Err(ParseError::LengthOutOfRange);
        }
        let out = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(out)
    }

    fn read_raw64(&mut self) -> Result<u64, ParseError> {
        if self.pos + 8 > self.buf.len() {
            return Err(ParseError::Truncated);
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_le_bytes(b))
    }

    fn read_raw32(&mut self) -> Result<u32, ParseError> {
        if self.pos + 4 > self.buf.len() {
            return Err(ParseError::Truncated);
        }
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_le_bytes(b))
    }
}

/// Decode a slice as a full message, returning `None` if it is malformed.
pub fn decode_fields<'a>(buf: &'a [u8], mut on_field: impl FnMut(u32, Field<'a>) -> bool) -> bool {
    // Returns true if the whole buffer was consumed cleanly.
    let mut it = FieldIter::new(buf);
    while let Some(res) = it.next() {
        match res {
            Ok((num, field)) => {
                if !on_field(num, field) {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// Protocol version exchanged during handshake (major must match).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ProtocolVersion {
    pub major: u32,
    pub minor: u32,
}

impl ProtocolVersion {
    fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut out = ProtocolVersion::default();
        let mut it = FieldIter::new(bytes);
        while let Some(res) = it.next() {
            let (num, field) = res.ok()?;
            match (num, field) {
                (1, Field::Varint(v)) => out.major = v as u32,
                (2, Field::Varint(v)) => out.minor = v as u32,
                _ => {}
            }
        }
        Some(out)
    }
}

/// First message in each direction after connect.
#[derive(Clone, Copy, Debug, Default)]
pub struct Handshake {
    pub handshake_id: u32,
    pub version: Option<ProtocolVersion>,
}

impl Handshake {
    /// Decode from the `WendyMessage.handshake` length-delimited field.
    pub fn from_wire(bytes: &[u8]) -> Option<Self> {
        let mut out = Handshake::default();
        let mut it = FieldIter::new(bytes);
        while let Some(res) = it.next() {
            let (num, field) = res.ok()?;
            match (num, field) {
                (1, Field::Varint(v)) => out.handshake_id = v as u32,
                (2, Field::Bytes(b)) => out.version = ProtocolVersion::from_slice(b),
                _ => {}
            }
        }
        Some(out)
    }
}

/// Params for WENDY_CMD_REBOOT.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct RebootParams {
    pub app_auto_start: bool,
    pub app_auto_start_delay: u32,
}

impl RebootParams {
    fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut out = RebootParams::default();
        let mut it = FieldIter::new(bytes);
        while let Some(res) = it.next() {
            let (num, field) = res.ok()?;
            match (num, field) {
                (1, Field::Varint(v)) => out.app_auto_start = v != 0,
                (2, Field::Varint(v)) => out.app_auto_start_delay = v as u32,
                _ => {}
            }
        }
        Some(out)
    }
}

/// Params for WENDY_CMD_CONSOLE_ATTACH.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ConsoleAttachParams {
    pub event_id: u32,
    pub duration: u32,
    pub blocking: bool,
}

impl ConsoleAttachParams {
    fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut out = ConsoleAttachParams::default();
        let mut it = FieldIter::new(bytes);
        while let Some(res) = it.next() {
            let (num, field) = res.ok()?;
            match (num, field) {
                (1, Field::Varint(v)) => out.event_id = v as u32,
                (2, Field::Varint(v)) => out.duration = v as u32,
                (3, Field::Varint(v)) => out.blocking = v != 0,
                _ => {}
            }
        }
        Some(out)
    }
}

/// Params for WENDY_CMD_CONSOLE_DETACH.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ConsoleDetachParams {
    pub event_id: u32,
}

impl ConsoleDetachParams {
    fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut out = ConsoleDetachParams::default();
        let mut it = FieldIter::new(bytes);
        while let Some(res) = it.next() {
            let (num, field) = res.ok()?;
            match (num, field) {
                (1, Field::Varint(v)) => out.event_id = v as u32,
                _ => {}
            }
        }
        Some(out)
    }
}

/// Host -> device command. The `params` variant identifies the command.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Command {
    pub request_id: u32,
    pub params: CommandParams,
}

/// The oneof `params` of a `WendyCommand`. Presence markers (empty nested
/// messages) decode as `Presence`.
///
/// Not `Copy`: the `SensorLinkSubscribe(SensorLinkSubscribe)` variant owns a
/// heapless `Vec`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum CommandParams {
    /// No command field present.
    #[default]
    None,
    Presence,
    Ping,
    Reboot(RebootParams),
    AppPushBegin,
    AppPushData,
    AppPushEnd,
    AppStart,
    AppStop,
    GetDeviceIdentity,
    GetDeviceInfo,
    ConsoleAttach(ConsoleAttachParams),
    ConsoleDetach(ConsoleDetachParams),
    /// `sensor_link_get_manifest` (field 16): the host wants the device's
    /// sensor manifest. Presence marker only.
    SensorLinkGetManifest,
    /// `sensor_link_subscribe` (field 17): the channel IDs to stream.
    SensorLinkSubscribe(SensorLinkSubscribe),
    /// `sensor_link_unsubscribe` (field 18): the channel IDs to stop.
    SensorLinkUnsubscribe(SensorLinkSubscribe),
}

impl Command {
    /// Decode from the `WendyCommand` length-delimited field.
    pub fn from_wire(bytes: &[u8]) -> Option<Self> {
        let mut out = Command::default();
        let mut it = FieldIter::new(bytes);
        while let Some(res) = it.next() {
            let (num, field) = res.ok()?;
            match (num, field) {
                (1, Field::Varint(v)) => out.request_id = v as u32,
                (2, Field::Bytes(_)) => out.params = CommandParams::Ping,
                (3, Field::Bytes(b)) => {
                    out.params = CommandParams::Reboot(RebootParams::from_slice(b)?)
                }
                (4, Field::Bytes(_)) => out.params = CommandParams::AppPushBegin,
                (5, Field::Bytes(_)) => out.params = CommandParams::AppPushData,
                (6, Field::Bytes(_)) => out.params = CommandParams::AppPushEnd,
                (7, Field::Bytes(_)) => out.params = CommandParams::AppStart,
                (8, Field::Bytes(_)) => out.params = CommandParams::AppStop,
                (9, Field::Bytes(_)) => out.params = CommandParams::GetDeviceIdentity,
                (10, Field::Bytes(_)) => out.params = CommandParams::GetDeviceInfo,
                (11, Field::Bytes(b)) => {
                    out.params = CommandParams::ConsoleAttach(ConsoleAttachParams::from_slice(b)?)
                }
                (12, Field::Bytes(b)) => {
                    out.params = CommandParams::ConsoleDetach(ConsoleDetachParams::from_slice(b)?)
                }
                (16, Field::Bytes(_)) => out.params = CommandParams::SensorLinkGetManifest,
                (17, Field::Bytes(b)) => {
                    out.params =
                        CommandParams::SensorLinkSubscribe(SensorLinkSubscribe::from_slice(b)?)
                }
                (18, Field::Bytes(b)) => {
                    out.params =
                        CommandParams::SensorLinkUnsubscribe(SensorLinkSubscribe::from_slice(b)?)
                }
                _ => {}
            }
        }
        Some(out)
    }
}

/// Device identity (factory MAC recorded as the asset serial number).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub id: String<64>,
    pub name: String<64>,
    pub display_name: String<64>,
    pub enrolled_device_id: String<64>,
}

impl DeviceIdentity {
    fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut out = DeviceIdentity::default();
        let mut it = FieldIter::new(bytes);
        while let Some(res) = it.next() {
            let (num, field) = res.ok()?;
            match (num, field) {
                (1, Field::Bytes(b)) => out.id = bytes_to_string(b)?,
                (2, Field::Bytes(b)) => out.name = bytes_to_string(b)?,
                (3, Field::Bytes(b)) => out.display_name = bytes_to_string(b)?,
                (4, Field::Bytes(b)) => out.enrolled_device_id = bytes_to_string(b)?,
                _ => {}
            }
        }
        Some(out)
    }
}

/// Static device description.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceInfo {
    pub os: String<64>,
    pub os_version: String<64>,
    pub cpu_architecture: String<32>,
    pub target: String<32>,
    pub board: String<32>,
    pub wasm_app_support: bool,
    pub native_app_support: bool,
}

impl DeviceInfo {
    fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut out = DeviceInfo::default();
        let mut it = FieldIter::new(bytes);
        while let Some(res) = it.next() {
            let (num, field) = res.ok()?;
            match (num, field) {
                (1, Field::Bytes(b)) => out.os = bytes_to_string(b)?,
                (2, Field::Bytes(b)) => out.os_version = bytes_to_string(b)?,
                (3, Field::Bytes(b)) => out.cpu_architecture = bytes_to_string(b)?,
                (4, Field::Bytes(b)) => out.target = bytes_to_string(b)?,
                (5, Field::Varint(v)) => out.wasm_app_support = v != 0,
                (6, Field::Varint(v)) => out.native_app_support = v != 0,
                (7, Field::Bytes(b)) => out.board = bytes_to_string(b)?,
                _ => {}
            }
        }
        Some(out)
    }
}

/// Data carried by a `WendyResponse`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ResponseData {
    #[default]
    None,
    DeviceIdentity(DeviceIdentity),
    DeviceInfo(DeviceInfo),
    /// `sensor_link_manifest`: the device's advertised sensors.
    SensorManifest(Vec<SensorDescriptor, 4>),
}

/// Response to a `WendyCommand`; `request_id` matches the request.
#[derive(Clone, Debug, Default)]
pub struct Response {
    pub request_id: u32,
    pub result: u32,
    pub data: ResponseData,
}

impl Response {
    /// Decode from the `WendyResponse` length-delimited field.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut out = Response::default();
        let mut it = FieldIter::new(bytes);
        while let Some(res) = it.next() {
            let (num, field) = res.ok()?;
            match (num, field) {
                (1, Field::Varint(v)) => out.request_id = v as u32,
                (2, Field::Varint(v)) => out.result = v as u32,
                (3, Field::Bytes(b)) => {
                    out.data = ResponseData::DeviceIdentity(DeviceIdentity::from_slice(b)?)
                }
                (4, Field::Bytes(b)) => {
                    out.data = ResponseData::DeviceInfo(DeviceInfo::from_slice(b)?)
                }
                (5, Field::Bytes(b)) => {
                    out.data = ResponseData::SensorManifest(read_sensor_manifest(b)?)
                }
                _ => {}
            }
        }
        Some(out)
    }
}

/// One chunk of console output, streamed as an event while attached.
#[derive(Clone, Debug, Default)]
pub struct ConsoleData {
    pub io: u32,
    pub gap: bool,
    pub data: Vec<u8, 256>,
}

/// Unsolicited device -> host (or host -> device) message.
#[derive(Clone, Debug, Default)]
pub struct Event {
    pub event_id: u32,
    pub data: EventData,
}

/// The oneof `data` of a `WendyEvent`.
#[derive(Clone, Debug, Default)]
pub enum EventData {
    #[default]
    None,
    ConsoleBegin,
    ConsoleData(ConsoleData),
    ConsoleEnd,
}

impl Event {
    /// Decode from the `WendyEvent` length-delimited field.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut out = Event::default();
        let mut it = FieldIter::new(bytes);
        while let Some(res) = it.next() {
            let (num, field) = res.ok()?;
            match (num, field) {
                (1, Field::Varint(v)) => out.event_id = v as u32,
                (2, Field::Bytes(_)) => out.data = EventData::ConsoleBegin,
                (3, Field::Bytes(b)) => {
                    let mut cd = ConsoleData::default();
                    let mut cit = FieldIter::new(b);
                    while let Some(r) = cit.next() {
                        let (n, f) = r.ok()?;
                        match (n, f) {
                            (1, Field::Varint(v)) => cd.io = v as u32,
                            (2, Field::Varint(v)) => cd.gap = v != 0,
                            (3, Field::Bytes(db)) => {
                                cd.data = Vec::from_slice(db).ok()?;
                            }
                            _ => {}
                        }
                    }
                    out.data = EventData::ConsoleData(cd);
                }
                (4, Field::Bytes(_)) => out.data = EventData::ConsoleEnd,
                _ => {}
            }
        }
        Some(out)
    }
}

/// Per-chunk payload width for a decoded `SensorData`. A chunk is at most this
/// big on the wire; the frame body cap (set to `BODY_CAP` in the firmware) must
/// be large enough to hold a full chunk plus its protobuf framing.
pub const SENSOR_PAYLOAD_CAP: usize = 2048;

/// `SensorData.flags` bits that mark chunk and frame boundaries.
pub mod sensorlink {
    /// First chunk of a frame: the consumer can start (re)building the frame.
    pub const FLAG_KEYFRAME: u32 = 1 << 0;
    /// Last chunk of a frame: the consumer has the whole payload.
    pub const FLAG_LAST_CHUNK: u32 = 1 << 1;
}

/// One chunk of a SensorLink frame (video / raw-pixel payload), transported
/// inside a `WendyMessage.sensor_data` (field 6).
///
/// A frame is a run of these, ordered by `chunk_seq` from 0, each carrying up
/// to [`SENSOR_PAYLOAD_CAP`] payload bytes. The chunk that ends a frame sets
/// [`sensorlink::FLAG_LAST_CHUNK`]; the first chunk sets [`sensorlink::FLAG_KEYFRAME`].
#[derive(Clone, Debug, Default)]
pub struct SensorData {
    pub channel_id: u32,
    pub frame_seq: u32,
    pub chunk_seq: u32,
    pub ts_us: u64,
    pub flags: u32,
    pub payload: Vec<u8, SENSOR_PAYLOAD_CAP>,
}

impl SensorData {
    /// Decode the `sensor_data` length-delimited field.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut out = SensorData::default();
        let mut it = FieldIter::new(bytes);
        while let Some(res) = it.next() {
            let (num, field) = res.ok()?;
            match (num, field) {
                (1, Field::Varint(v)) => out.channel_id = v as u32,
                (2, Field::Varint(v)) => out.frame_seq = v as u32,
                (3, Field::Varint(v)) => out.chunk_seq = v as u32,
                (4, Field::Varint(v)) => out.ts_us = v,
                (5, Field::Varint(v)) => out.flags = v as u32,
                (6, Field::Bytes(b)) => out.payload = Vec::from_slice(b).ok()?,
                _ => {}
            }
        }
        // A SensorData with no payload cannot contribute to a frame, so treat it
        // as malformed and drop the frame (the caller resyncs for the next one).
        if out.payload.is_empty() {
            return None;
        }
        Some(out)
    }
}

/// The `sensor_link_subscribe` command params: the channel IDs the host wants
/// to receive (repeated, encoded as `channel_id = 1`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SensorLinkSubscribe {
    pub channel_ids: Vec<u32, 4>,
}

impl SensorLinkSubscribe {
    fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut out = SensorLinkSubscribe::default();
        let mut it = FieldIter::new(bytes);
        while let Some(res) = it.next() {
            let (num, field) = res.ok()?;
            // `channel_id` is a repeated uint32 (wire type 0).
            if num == 1 {
                if let Field::Varint(v) = field {
                    out.channel_ids.push(v as u32).ok()?;
                } else {
                    return None;
                }
            }
        }
        Some(out)
    }
}

/// A video sensor descriptor, for the `sensor_link_manifest` response.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SensorDescriptor {
    pub channel_id: u32,
    pub input_id: u32,
    pub name: String<32>,
    pub codec: u32,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
}

/// The top-level wrapper: every frame body is exactly one of these.
#[derive(Clone, Debug)]
pub enum Message {
    Handshake(Handshake),
    Command(Command),
    Response(Response),
    Event(Event),
    SensorData(SensorData),
}

impl Message {
    /// Decode a frame body into a `Message`. Returns `None` if the body is
    /// malformed or carries a message type this port does not model.
    pub fn decode(body: &[u8]) -> Option<Self> {
        let mut it = FieldIter::new(body);
        while let Some(res) = it.next() {
            let (num, field) = res.ok()?;
            let msg = match (num, field) {
                (1, Field::Bytes(b)) => Message::Handshake(Handshake::from_wire(b)?),
                (2, Field::Bytes(_)) => return None, // WendyService — out of scope
                (3, Field::Bytes(b)) => Message::Command(Command::from_wire(b)?),
                (4, Field::Bytes(b)) => Message::Response(Response::from_slice(b)?),
                (5, Field::Bytes(b)) => Message::Event(Event::from_slice(b)?),
                (6, Field::Bytes(b)) => Message::SensorData(SensorData::from_slice(b)?),
                _ => continue,
            };
            return Some(msg);
        }
        None
    }
}

fn bytes_to_string<const N: usize>(b: &[u8]) -> Option<String<N>> {
    String::from_utf8(heapless::Vec::from_slice(b).ok()?).ok()
}

// ---------------------------------------------------------------------------
// Encoder (used to build device -> host replies)
// ---------------------------------------------------------------------------

/// A tiny append-only protobuf encoder.
pub struct Encoder {
    buf: Vec<u8, 512>,
}

impl Default for Encoder {
    fn default() -> Self {
        Encoder { buf: Vec::new() }
    }
}

impl Encoder {
    pub fn new() -> Self {
        Encoder::default()
    }

    fn append_tag(&mut self, field_number: u32, wire_type: u8) {
        self.push_varint(((field_number as u64) << 3) | u64::from(wire_type));
    }

    fn push_varint(&mut self, mut value: u64) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            if self.buf.push(byte).is_err() {
                break;
            }
            if value == 0 {
                break;
            }
        }
    }

    fn push_bytes(&mut self, bytes: &[u8]) {
        self.push_varint(bytes.len() as u64);
        if self.buf.extend_from_slice(bytes).is_err() {
            // Truncate to fit rather than panic; the frame layer bounds bodies.
            let overflow = self.buf.len().saturating_sub(512);
            if overflow > 0 {
                self.buf.truncate(512 - overflow);
            }
        }
    }

    /// Write a varint field (covers int32/64, uint, bool, enum).
    pub fn varint_field(&mut self, field_number: u32, value: u64) {
        self.append_tag(field_number, 0);
        self.push_varint(value);
    }

    /// Write a length-delimited field (bytes or embedded message).
    pub fn bytes_field(&mut self, field_number: u32, bytes: &[u8]) {
        self.append_tag(field_number, 2);
        self.push_bytes(bytes);
    }

    /// Encode `msg` as a nested message field.
    pub fn message_field(&mut self, field_number: u32, msg: &[u8]) {
        self.bytes_field(field_number, msg);
    }

    /// The encoded bytes so far.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Consume the encoder, returning the owned buffer.
    pub fn into_vec(self) -> Vec<u8, 512> {
        self.buf
    }
}

/// Encode a bare `WendyMessage` carrying a `WendyResponse` with only
/// `request_id` and `result` (no `data` oneof). This is what the device
/// returns for commands it understands but produces no payload for (ping,
/// reboot, app_start, etc.). The whole thing is a `WendyMessage`, so the
/// response is placed in the `response` oneof (field 4).
pub fn encode_response(request_id: u32, result: u32) -> Vec<u8, 512> {
    let mut resp = Encoder::new();
    resp.varint_field(1, request_id as u64);
    resp.varint_field(2, result as u64);
    let mut enc = Encoder::new();
    enc.message_field(4, resp.as_bytes()); // WendyMessage.response = 4
    enc.into_vec()
}

/// Encode a `WendyMessage` whose `response` carries a nested `DeviceInfo`.
pub fn encode_device_info_response(
    request_id: u32,
    result: u32,
    info: &DeviceInfo,
) -> Vec<u8, 512> {
    let mut sub = Encoder::new();
    write_device_info(&mut sub, info);
    let mut resp = Encoder::new();
    resp.varint_field(1, request_id as u64);
    resp.varint_field(2, result as u64);
    resp.message_field(4, sub.as_bytes()); // WendyResponse.data.device_info = 4
    let mut enc = Encoder::new();
    enc.message_field(4, resp.as_bytes()); // WendyMessage.response = 4
    enc.into_vec()
}

fn write_device_info(enc: &mut Encoder, info: &DeviceInfo) {
    if !info.os.is_empty() {
        enc.bytes_field(1, info.os.as_bytes());
    }
    if !info.os_version.is_empty() {
        enc.bytes_field(2, info.os_version.as_bytes());
    }
    if !info.cpu_architecture.is_empty() {
        enc.bytes_field(3, info.cpu_architecture.as_bytes());
    }
    if !info.target.is_empty() {
        enc.bytes_field(4, info.target.as_bytes());
    }
    enc.varint_field(5, info.wasm_app_support as u64);
    enc.varint_field(6, info.native_app_support as u64);
    if !info.board.is_empty() {
        enc.bytes_field(7, info.board.as_bytes());
    }
}

/// Encode the payload of a `WendyResponse.device_identity`.
fn write_device_identity(enc: &mut Encoder, id: &DeviceIdentity) {
    if !id.id.is_empty() {
        enc.bytes_field(1, id.id.as_bytes());
    }
    if !id.name.is_empty() {
        enc.bytes_field(2, id.name.as_bytes());
    }
    if !id.display_name.is_empty() {
        enc.bytes_field(3, id.display_name.as_bytes());
    }
    if !id.enrolled_device_id.is_empty() {
        enc.bytes_field(4, id.enrolled_device_id.as_bytes());
    }
}

/// Encode one `SensorDescriptor` into `enc` (channel_id, input_id, name, video).
fn write_sensor_descriptor(enc: &mut Encoder, d: &SensorDescriptor) {
    enc.varint_field(1, d.channel_id as u64);
    enc.varint_field(2, d.input_id as u64);
    if !d.name.is_empty() {
        enc.bytes_field(3, d.name.as_bytes());
    }
    // video (field 4): a nested VideoFormat { codec, width, height, fps }.
    let mut vf = Encoder::new();
    vf.varint_field(1, d.codec as u64);
    vf.varint_field(2, d.width as u64);
    vf.varint_field(3, d.height as u64);
    vf.varint_field(4, d.fps as u64);
    enc.message_field(4, vf.as_bytes());
}

/// Encode a `SensorManifest` (repeated `SensorDescriptor`, field 1) into `enc`.
fn write_sensor_manifest(enc: &mut Encoder, descriptors: &Vec<SensorDescriptor, 4>) {
    for d in descriptors {
        let mut member = Encoder::new();
        write_sensor_descriptor(&mut member, d);
        enc.message_field(1, member.as_bytes()); // SensorManifest.sensors[] = 1
    }
}

/// Build the payload of a `WendyResponse.sensor_manifest` (field 5).
pub fn encode_sensor_manifest(descriptors: &Vec<SensorDescriptor, 4>) -> Vec<u8, 512> {
    let mut member = Encoder::new();
    write_sensor_manifest(&mut member, descriptors);
    member.into_vec()
}

/// Read a `SensorManifest` (repeated `SensorDescriptor`, field 1) from a
/// `sensor_link_manifest` response payload.
fn read_sensor_manifest(bytes: &[u8]) -> Option<Vec<SensorDescriptor, 4>> {
    let mut out = Vec::<SensorDescriptor, 4>::new();
    let mut it = FieldIter::new(bytes);
    while let Some(res) = it.next() {
        let (num, field) = res.ok()?;
        if num == 1 {
            if let Field::Bytes(b) = field {
                out.push(SensorDescriptor::from_slice(b)?).ok()?;
            } else {
                return None;
            }
        }
    }
    Some(out)
}

/// Decode a `SensorDescriptor` from its length-delimited bytes.
impl SensorDescriptor {
    fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut out = SensorDescriptor::default();
        let mut it = FieldIter::new(bytes);
        while let Some(res) = it.next() {
            let (num, field) = res.ok()?;
            match (num, field) {
                (1, Field::Varint(v)) => out.channel_id = v as u32,
                (2, Field::Varint(v)) => out.input_id = v as u32,
                (3, Field::Bytes(b)) => {
                    out.name = String::<32>::from_utf8(heapless::Vec::from_slice(b).ok()?).ok()?;
                }
                (4, Field::Bytes(b)) => {
                    // video: { codec = 1, width = 2, height = 3, fps = 4 }
                    let mut vit = FieldIter::new(b);
                    while let Some(r) = vit.next() {
                        let (n, f) = r.ok()?;
                        match (n, f) {
                            (1, Field::Varint(v)) => out.codec = v as u32,
                            (2, Field::Varint(v)) => out.width = v as u32,
                            (3, Field::Varint(v)) => out.height = v as u32,
                            (4, Field::Varint(v)) => out.fps = v as u32,
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        Some(out)
    }
}

/// Encode a `WendyMessage` carrying the host→device handshake echo.
///
/// The echo reuses the host's `handshake_id` and advertises our own protocol
/// version so the host can confirm the link is bound to this device.
pub fn encode_handshake(hs: &Handshake) -> Vec<u8, 512> {
    let mut sub = Encoder::new();
    sub.varint_field(1, hs.handshake_id as u64);
    if let Some(v) = &hs.version {
        let mut vsub = Encoder::new();
        vsub.varint_field(1, v.major as u64);
        vsub.varint_field(2, v.minor as u64);
        sub.message_field(2, vsub.as_bytes());
    }
    let mut enc = Encoder::new();
    enc.message_field(1, sub.as_bytes()); // WendyMessage.handshake = 1
    enc.into_vec()
}

/// Encode a device→host `WendyEvent` (a streamed `console_data` chunk) as a
/// full `WendyMessage` wire body, ready to be framed and sent to the host.
/// This is the inverse of [`Event::from_slice`].
///
/// Layout: `WendyConsoleData { io = 1, gap = 2, data = 3 }` nested in
/// `WendyEvent { event_id = 1, console_data = 3 }`, nested in the
/// `WendyMessage` oneof member `event = 5`.
pub fn encode_event(evt: &Event) -> Vec<u8, 512> {
    let mut cd = Encoder::new();
    if let EventData::ConsoleData(ref data) = evt.data {
        cd.varint_field(1, data.io as u64);
        cd.varint_field(2, u64::from(data.gap));
        cd.bytes_field(3, data.data.as_slice());
    }
    let mut ev = Encoder::new();
    ev.varint_field(1, evt.event_id as u64);
    ev.message_field(3, cd.as_bytes()); // data.console_data = 3
    let mut enc = Encoder::new();
    enc.message_field(5, ev.as_bytes()); // WendyMessage.event = 5
    enc.into_vec()
}

/// Encode a `WendyMessage` carrying a `sensor_link_manifest` response.
///
/// Wraps the [`encode_sensor_manifest`] member in a `WendyResponse`
/// (`request_id` + `result` + `data.sensor_manifest` = field 5), the reply to a
/// `sensor_link_get_manifest` / `sensor_link_subscribe` command.
pub fn encode_sensor_link_manifest(
    request_id: u32,
    descriptors: &Vec<SensorDescriptor, 4>,
) -> Vec<u8, 512> {
    let member = encode_sensor_manifest(descriptors);
    let mut resp = Encoder::new();
    resp.varint_field(1, request_id as u64);
    resp.varint_field(2, 0); // WendyResult.WENDY_RESULT_OK
    resp.message_field(5, &member); // data.sensor_manifest = 5
    let mut enc = Encoder::new();
    enc.message_field(4, resp.as_bytes()); // WendyMessage.response = 4
    enc.into_vec()
}

/// Encode any [`Message`] as a `WendyMessage` wire body, ready to be framed
/// and sent back to the host.
///
/// A `Command` is host→device only, so the device encodes it to an empty body;
/// a device→host `Event` is encoded via [`encode_event`].
pub fn encode_message(msg: &Message) -> Vec<u8, 512> {
    match msg {
        Message::Handshake(hs) => encode_handshake(hs),
        Message::Response(r) => {
            // Build the WendyResponse: request_id (1) + result (2) + the
            // nested `data` oneof member. The member is encoded into its own
            // buffer and written as a length-delimited field so its own field
            // numbers (device_info = 4, device_identity = 3) do not collide
            // with the response's request_id/result.
            let mut resp = Encoder::new();
            resp.varint_field(1, r.request_id as u64);
            resp.varint_field(2, r.result as u64);
            match &r.data {
                ResponseData::DeviceIdentity(id) => {
                    let mut member = Encoder::new();
                    write_device_identity(&mut member, id);
                    resp.message_field(3, member.as_bytes()); // data.device_identity = 3
                }
                ResponseData::DeviceInfo(info) => {
                    let mut member = Encoder::new();
                    write_device_info(&mut member, info);
                    resp.message_field(4, member.as_bytes()); // data.device_info = 4
                }
                ResponseData::SensorManifest(descriptors) => {
                    let member = encode_sensor_manifest(descriptors);
                    resp.message_field(5, &member); // data.sensor_manifest = 5
                }
                ResponseData::None => {}
            }
            let mut enc = Encoder::new();
            enc.message_field(4, resp.as_bytes()); // WendyMessage.response = 4
            enc.into_vec()
        }
        // A `Command` is host→device only, so the device never emits one: its
        // body is empty. A `SensorData` chunk is likewise host→device only
        // (the host produces frames, the device reassembles them), so it too
        // encodes to an empty body. A device→host `Event` (e.g. streamed
        // console data) is encoded for real via [`encode_event`].
        Message::Command(_) => Encoder::new().into_vec(),
        Message::SensorData(_) => Encoder::new().into_vec(),
        Message::Event(e) => encode_event(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s<const N: usize>(v: &str) -> heapless::String<N> {
        heapless::String::<N>::try_from(v).expect("literal fits")
    }

    // A device_info reply must decode back to the same request_id/result and
    // the same nested DeviceInfo, proving the response's own field numbers
    // (request_id=1, result=2) never collide with the nested device_info's
    // fields (os=1 .. board=7).
    #[test]
    fn device_info_response_roundtrips() {
        let info = DeviceInfo {
            os: s::<64>("wendy-lite"),
            os_version: s::<64>("1.2.3"),
            cpu_architecture: s::<32>("xtensa-esp32s3"),
            target: s::<32>("esp32s3"),
            board: s::<32>("esp32-s3-vocat"),
            wasm_app_support: false,
            native_app_support: true,
        };
        let msg = Message::Response(Response {
            request_id: 42,
            result: 0,
            data: ResponseData::DeviceInfo(info.clone()),
        });
        let wire = encode_message(&msg);

        let decoded = Message::decode(&wire).expect("wire decodes");
        let Message::Response(resp) = decoded else {
            panic!("expected Response, got {decoded:?}");
        };
        assert_eq!(resp.request_id, 42);
        assert_eq!(resp.result, 0);
        match resp.data {
            ResponseData::DeviceInfo(got) => assert_eq!(got, info),
            other => panic!("expected DeviceInfo, got {other:?}"),
        }
    }

    // Same check for the device_identity oneof member (field 3).
    #[test]
    fn device_identity_response_roundtrips() {
        let id = DeviceIdentity {
            id: s::<64>("b4:3a:45:16:2f:90"),
            name: s::<64>("esp32-s3-vocat-wendy"),
            display_name: s::<64>("ESP-VoCat Wendy"),
            enrolled_device_id: s::<64>(""),
        };
        let msg = Message::Response(Response {
            request_id: 7,
            result: 0,
            data: ResponseData::DeviceIdentity(id.clone()),
        });
        let wire = encode_message(&msg);
        let decoded = Message::decode(&wire).expect("wire decodes");
        let Message::Response(resp) = decoded else {
            panic!("expected Response, got {decoded:?}");
        };
        assert_eq!(resp.request_id, 7);
        match resp.data {
            ResponseData::DeviceIdentity(got) => assert_eq!(got, id),
            other => panic!("expected DeviceIdentity, got {other:?}"),
        }
    }

    // The raw bytes must place the nested device_info under field 4 of the
    // response (not inline), so the response's first field is request_id.
    #[test]
    fn device_info_response_wire_layout() {
        let info = DeviceInfo {
            os: s::<64>("wendy-lite"),
            os_version: s::<64>("1.2.3"),
            cpu_architecture: s::<32>("xtensa"),
            target: s::<32>("esp32s3"),
            board: s::<32>("esp32-s3-vocat"),
            wasm_app_support: false,
            native_app_support: true,
        };
        let wire = encode_message(&Message::Response(Response {
            request_id: 1,
            result: 0,
            data: ResponseData::DeviceInfo(info),
        }));

        // Walk the top-level WendyMessage: field 4 (response) must be a
        // length-delimited nested message.
        let mut top = FieldIter::new(&wire);
        let (num, field) = top.next().expect("has field").expect("ok field");
        assert_eq!((num, field), (4, Field::Bytes(&wire[2..])));

        // Inside the response: field 1 (request_id) then field 2 (result),
        // then field 4 (nested device_info). The very first field must be
        // request_id = 1, never os.
        let resp_bytes = match field {
            Field::Bytes(b) => b,
            _ => panic!("expected bytes"),
        };
        let mut resp = FieldIter::new(resp_bytes);
        let (n1, f1) = resp.next().expect("resp field 1").expect("ok");
        assert_eq!((n1, f1), (1, Field::Varint(1)));
        let (n2, f2) = resp.next().expect("resp field 2").expect("ok");
        assert_eq!((n2, f2), (2, Field::Varint(0)));
        let (n3, f3) = resp.next().expect("resp field 3").expect("ok");
        assert_eq!(n3, 4);
        assert!(matches!(f3, Field::Bytes(_)));
    }

    // A bare OK response (no data oneof) still round-trips.
    #[test]
    fn bare_response_roundtrips() {
        let wire = encode_message(&Message::Response(Response {
            request_id: 9,
            result: 0,
            data: ResponseData::None,
        }));
        let decoded = Message::decode(&wire).expect("wire decodes");
        let Message::Response(resp) = decoded else {
            panic!("expected Response, got {decoded:?}");
        };
        assert_eq!(resp.request_id, 9);
        assert_eq!(resp.result, 0);
        assert_eq!(resp.data, ResponseData::None);
    }

    // A streamed console_data event must round-trip through encode/decode with
    // its io/gap/data and event_id intact, and must decode as a Message::Event
    // (not collapse into a Response or Command).
    #[test]
    fn console_data_event_roundtrips() {
        let mut data = heapless::Vec::<u8, 256>::new();
        data.extend_from_slice(b"hello from the device\n").unwrap();
        let evt = Event {
            event_id: 11,
            data: EventData::ConsoleData(ConsoleData {
                io: 1, // STANDARD_OUTPUT
                gap: false,
                data,
            }),
        };
        let wire = encode_event(&evt);

        let decoded = Message::decode(&wire).expect("event wire decodes");
        let Message::Event(got) = decoded else {
            panic!("expected Event, got {decoded:?}");
        };
        assert_eq!(got.event_id, 11);
        match got.data {
            EventData::ConsoleData(cd) => {
                assert_eq!(cd.io, 1);
                assert!(!cd.gap);
                assert_eq!(cd.data.as_slice(), b"hello from the device\n");
            }
            other => panic!("expected ConsoleData, got {other:?}"),
        }
    }

    // The top-level body must carry the event under the `event` oneof field 5,
    // and the console_data under field 3 of the event, so decoding the outer
    // message sees field 5 first.
    #[test]
    fn console_data_event_wire_layout() {
        let evt = Event {
            event_id: 3,
            data: EventData::ConsoleData(ConsoleData {
                io: 2, // STANDARD_ERROR
                gap: true,
                data: heapless::Vec::new(),
            }),
        };
        let wire = encode_event(&evt);

        let (n, f) = FieldIter::new(&wire)
            .next()
            .expect("outer field")
            .expect("outer ok");
        // The single outer field is msg.event = 5, length-delimited.
        assert_eq!((n, f), (5, Field::Bytes(&wire[2..])));
    }
}
