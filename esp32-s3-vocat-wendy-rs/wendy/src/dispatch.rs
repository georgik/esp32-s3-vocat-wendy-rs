//! Wendy command dispatch — the pure decision layer of the host→device
//! control path.
//!
//! Given an inbound decoded [`Message`] and a read-only [`Ctx`], decide what
//! the device does: what to send back to the host, and what side effect to
//! perform (inject host→device stdin, attach/detach console capture, reboot).
//!
//! All I/O (USB writes, reboot, console capture) is performed by the caller
//! *after* dispatch returns, which keeps this module free of any `esp-hal`
//! dependency, `no_std`-pure, and host-testable. The firmware consumes the
//! [`dispatch`] result to drive the actual USB writes, reboot, and console
//! capture.

use heapless::Vec;

use crate::proto::*;

/// Protocol major version this firmware advertises during the handshake. The
/// host's major must match or the handshake is refused (see
/// [`handle_handshake`]).
pub const PROTOCOL_VERSION_MAJOR: u32 = 2;
/// Protocol minor version. Informational only; the host is not required to match.
pub const PROTOCOL_VERSION_MINOR: u32 = 0;

/// Result codes returned to the host after a command.
pub mod result {
    pub const OK: u32 = 0;
    pub const UNKNOWN_ERROR: u32 = 1;
    pub const BAD_PROTOCOL_VERSION: u32 = 2;
    pub const BAD_STATE: u32 = 3;
    pub const APPLIED_RESTARTING: u32 = 8;
}

/// Console IO channel selectors. Used to distinguish host→device stdin from
/// device→host console streaming.
pub mod io {
    pub const STANDARD_INPUT: u32 = 0;
    pub const STANDARD_OUTPUT: u32 = 1;
    pub const STANDARD_ERROR: u32 = 2;
}

/// Maximum host→device stdin chunk, matching the [`ConsoleData`] buffer width.
pub const STDIN_MAX: usize = 256;

/// Read-only context dispatch needs about the device.
///
/// The caller owns the mutable session state (notably `handshake_done`) and
/// updates it from the [`dispatch`] return value; `Ctx` only carries the
/// read-only snapshots dispatch must answer from.
pub struct Ctx<'a> {
    /// Whether the host has completed the version handshake. Commands and
    /// events are rejected until this is true.
    pub handshake_done: bool,
    /// Whether console capture is currently attached to the host.
    pub console_attached: bool,
    /// Static device description returned by `get_device_info`.
    pub device_info: &'a DeviceInfo,
    /// Static device identity returned by `get_device_identity`.
    pub device_identity: &'a DeviceIdentity,
}

impl<'a> Ctx<'a> {
    /// Build a context with handshake not yet done and console not attached.
    pub fn new(device_info: &'a DeviceInfo, device_identity: &'a DeviceIdentity) -> Self {
        Ctx {
            handshake_done: false,
            console_attached: false,
            device_info,
            device_identity,
        }
    }

    /// Set the `handshake_done` flag (used by tests to simulate an established
    /// link).
    pub fn with_handshake(mut self, handshake_done: bool) -> Self {
        self.handshake_done = handshake_done;
        self
    }
}

/// What [`dispatch`] decided to do in response to one inbound message.
///
/// Every field is `None` unless the message triggered it, so callers can test
/// for the absence of an effect with a plain comparison.
#[derive(Debug)]
pub struct Outcome {
    /// A message to send back to the host (a `Response`, or the handshake
    /// echo). `None` means "no reply".
    pub reply: Option<Message>,
    /// Host→device stdin bytes to inject into the app, if any.
    pub stdin: Option<Vec<u8, STDIN_MAX>>,
    /// A SensorLink frame chunk to feed into the reassembler, if any.
    pub sensor_data: Option<SensorData>,
    /// Attach console capture for this event id + duration, if any.
    pub console_attach: Option<ConsoleAttachParams>,
    /// Detach console capture for this event id, if any.
    pub console_detach: Option<u32>,
    /// Reboot the device with these params, if any.
    pub reboot: Option<RebootParams>,
}

impl Outcome {
    /// The empty outcome — no reply, no side effect.
    fn none() -> Self {
        Outcome {
            reply: None,
            stdin: None,
            sensor_data: None,
            console_attach: None,
            console_detach: None,
            reboot: None,
        }
    }

    /// An outcome carrying only a reply message.
    fn reply(msg: Message) -> Self {
        Outcome {
            reply: Some(msg),
            ..Outcome::none()
        }
    }

    /// A bare `Response` with `result` and no payload.
    fn resp(request_id: u32, result: u32) -> Message {
        Message::Response(Response {
            request_id,
            result,
            data: ResponseData::None,
        })
    }
}

/// Handle an inbound handshake.
///
/// Returns the reply to send (an echo of the host's `handshake_id` with our
/// version) and the new `handshake_done` flag. If the host's major version
/// does not match, we stay silent and leave `handshake_done` unchanged — the
/// real firmware closes the link in this case; over a direct USB link we simply
/// never proceed, so subsequent commands are rejected.
pub fn handle_handshake(hs: &Handshake, ctx: &Ctx) -> (Option<Message>, bool) {
    let version = match hs.version {
        Some(v) => v,
        None => return (None, ctx.handshake_done),
    };
    if version.major != PROTOCOL_VERSION_MAJOR {
        return (None, ctx.handshake_done);
    }
    let reply = Message::Handshake(Handshake {
        handshake_id: hs.handshake_id,
        version: Some(ProtocolVersion {
            major: PROTOCOL_VERSION_MAJOR,
            minor: PROTOCOL_VERSION_MINOR,
        }),
    });
    (Some(reply), true)
}

/// Handle an inbound command.
///
/// Commands are rejected with `BAD_STATE` until the handshake completes,
/// matching the agent's `command received before handshake` guard.
pub fn handle_command(cmd: &Command, ctx: &Ctx) -> Outcome {
    if !ctx.handshake_done {
        return Outcome::reply(Outcome::resp(cmd.request_id, result::BAD_STATE));
    }

    match &cmd.params {
        CommandParams::Ping => Outcome::reply(Outcome::resp(cmd.request_id, result::OK)),

        CommandParams::Reboot(params) => Outcome {
            reply: Some(Outcome::resp(cmd.request_id, result::APPLIED_RESTARTING)),
            reboot: Some(*params),
            ..Outcome::none()
        },

        CommandParams::GetDeviceInfo => Outcome::reply(Message::Response(Response {
            request_id: cmd.request_id,
            result: result::OK,
            data: ResponseData::DeviceInfo(ctx.device_info.clone()),
        })),

        CommandParams::GetDeviceIdentity => Outcome::reply(Message::Response(Response {
            request_id: cmd.request_id,
            result: result::OK,
            data: ResponseData::DeviceIdentity(ctx.device_identity.clone()),
        })),

        CommandParams::ConsoleAttach(params) => Outcome {
            reply: Some(Outcome::resp(cmd.request_id, result::OK)),
            console_attach: Some(*params),
            ..Outcome::none()
        },

        CommandParams::ConsoleDetach(params) => Outcome {
            reply: Some(Outcome::resp(cmd.request_id, result::OK)),
            console_detach: Some(params.event_id),
            ..Outcome::none()
        },

        // App lifecycle: accepted, no payload.
        CommandParams::AppStart | CommandParams::AppStop | CommandParams::AppPushEnd => {
            Outcome::reply(Outcome::resp(cmd.request_id, result::OK))
        }

        // SensorLink: the host streams raw-RGB565 frames to the display. Both
        // `sensor_link_get_manifest` and `sensor_link_subscribe` are answered
        // with the device's manifest (a single raw "display" sensor); the host
        // then streams `SensorData` chunks (field 6) which surface here as
        // `outcome.sensor_data`.
        CommandParams::SensorLinkGetManifest => Outcome::reply(Message::Response(Response {
            request_id: cmd.request_id,
            result: result::OK,
            data: ResponseData::SensorManifest(device_sensor_manifest()),
        })),

        CommandParams::SensorLinkSubscribe(_) => Outcome::reply(Message::Response(Response {
            request_id: cmd.request_id,
            result: result::OK,
            data: ResponseData::SensorManifest(device_sensor_manifest()),
        })),

        // Unsubscribe is accepted; no payload is returned (streaming just
        // stops — the reassembler drops the frame on the next chunk 0).
        CommandParams::SensorLinkUnsubscribe(_) => {
            Outcome::reply(Outcome::resp(cmd.request_id, result::OK))
        }

        // App push body / begin are not implemented in this port yet.
        CommandParams::AppPushBegin | CommandParams::AppPushData => {
            Outcome::reply(Outcome::resp(cmd.request_id, result::UNKNOWN_ERROR))
        }

        // No command field present, or an unrecognised presence marker.
        CommandParams::None | CommandParams::Presence => {
            Outcome::reply(Outcome::resp(cmd.request_id, result::UNKNOWN_ERROR))
        }
    }
}

/// Handle an inbound event.
///
/// Only a `ConsoleData` event on the `STANDARD_INPUT` channel carries
/// host→device stdin; everything else (including device→host console streaming)
/// is ignored here.
pub fn handle_event(evt: &Event) -> Outcome {
    if let EventData::ConsoleData(data) = &evt.data {
        if data.io == io::STANDARD_INPUT {
            return Outcome {
                stdin: Some(data.data.clone()),
                ..Outcome::none()
            };
        }
    }
    Outcome::none()
}

/// The device's SensorLink manifest: a single raw-RGB565 "display" sensor the
/// host can stream frames to. Returned in reply to both
/// `sensor_link_get_manifest` and `sensor_link_subscribe`.
///
/// The codec is `CODEC_UNSPECIFIED` (0): this port carries *raw* big-endian
/// RGB565 pixels (an 8-byte big-endian `width`+`height` header precedes the
/// payload of the first chunk), not an encoded video stream, so no MJPEG/H264
/// decoder is needed on the device.
fn device_sensor_manifest() -> Vec<SensorDescriptor, 4> {
    let mut m: Vec<SensorDescriptor, 4> = Vec::new();
    let name: heapless::String<32> =
        heapless::String::try_from("wendy-display").expect("name fits");
    m.push(SensorDescriptor {
        channel_id: 1,
        input_id: 0,
        name,
        codec: 0, // CODEC_UNSPECIFIED — raw RGB565 payload
        width: 360,
        height: 360,
        fps: 15,
    })
    .expect("manifest fits");
    m
}

/// Route a decoded inbound message to the right handler.
///
/// Returns the [`Outcome`] plus the *updated* `handshake_done` flag (the caller
/// persists it back into its session state). Handshake state only advances on
/// a successful handshake; every other message type preserves it.
pub fn dispatch(msg: &Message, ctx: &Ctx) -> (Outcome, bool) {
    match msg {
        Message::Handshake(hs) => {
            let (reply, done) = handle_handshake(hs, ctx);
            let mut out = Outcome::none();
            out.reply = reply;
            (out, done)
        }
        Message::Command(cmd) => (handle_command(cmd, ctx), ctx.handshake_done),
        Message::Event(evt) => (handle_event(evt), ctx.handshake_done),
        // A SensorData chunk is a host→device data stream (the host produces an
        // image, the device reassembles + displays it). Gate it on the
        // handshake like commands: a chunk arriving before the link is up is
        // dropped. The caller feeds it into the SensorLink reassembler.
        Message::SensorData(cd) => {
            if !ctx.handshake_done {
                return (Outcome::none(), ctx.handshake_done);
            }
            let mut out = Outcome::none();
            out.sensor_data = Some(cd.clone());
            (out, ctx.handshake_done)
        }
        // A device→host Response arriving at the device is unexpected; ignore it.
        Message::Response(_) => (Outcome::none(), ctx.handshake_done),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heapless::String;

    fn ctx(handshake_done: bool) -> Ctx<'static> {
        // Device identity/info are never read by the SensorLink path; build a
        // minimal context. `device_info`/`device_identity` are `'static`, so we
        // point at the statics below.
        static INFO: DeviceInfo = DeviceInfo {
            os: String::new(),
            os_version: String::new(),
            cpu_architecture: String::new(),
            target: String::new(),
            board: String::new(),
            wasm_app_support: false,
            native_app_support: false,
        };
        static IDENTITY: DeviceIdentity = DeviceIdentity {
            id: String::new(),
            name: String::new(),
            display_name: String::new(),
            enrolled_device_id: String::new(),
        };
        Ctx::new(&INFO, &IDENTITY).with_handshake(handshake_done)
    }

    #[test]
    fn subscribe_replies_with_manifest() {
        let mut sub = SensorLinkSubscribe::default();
        sub.channel_ids.push(1).ok();
        let cmd = Command {
            request_id: 17,
            params: CommandParams::SensorLinkSubscribe(sub),
        };
        let (out, _done) = dispatch(&Message::Command(cmd), &ctx(true));
        let Message::Response(resp) = out.reply.expect("a reply") else {
            panic!("expected a response");
        };
        assert_eq!(resp.request_id, 17);
        assert_eq!(resp.result, result::OK);
        let ResponseData::SensorManifest(m) = resp.data else {
            panic!("expected a sensor manifest");
        };
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].channel_id, 1);
    }

    #[test]
    fn get_manifest_replies_with_manifest() {
        let cmd = Command {
            request_id: 16,
            params: CommandParams::SensorLinkGetManifest,
        };
        let (out, _) = dispatch(&Message::Command(cmd), &ctx(true));
        let Message::Response(resp) = out.reply.expect("a reply") else {
            panic!("expected a response");
        };
        assert_eq!(resp.result, result::OK);
        assert!(matches!(resp.data, ResponseData::SensorManifest(_)));
    }

    #[test]
    fn commands_before_handshake_are_rejected() {
        let cmd = Command {
            request_id: 17,
            params: CommandParams::SensorLinkSubscribe(SensorLinkSubscribe::default()),
        };
        let (out, done) = dispatch(&Message::Command(cmd), &ctx(false));
        assert!(!done);
        let Message::Response(resp) = out.reply.expect("a reply") else {
            panic!("expected a response");
        };
        assert_eq!(resp.result, result::BAD_STATE);
    }

    #[test]
    fn sensor_data_is_routed_out() {
        let mut cd = SensorData::default();
        cd.channel_id = 1;
        cd.chunk_seq = 0;
        cd.flags = sensorlink::FLAG_KEYFRAME;
        cd.payload = Vec::from_slice(b"hello").expect("fits");
        let (out, done) = dispatch(&Message::SensorData(cd), &ctx(true));
        assert!(done);
        let got = out.sensor_data.expect("sensor_data");
        assert_eq!(got.channel_id, 1);
        assert_eq!(&got.payload[..], b"hello");
    }

    #[test]
    fn sensor_data_before_handshake_is_dropped() {
        let mut cd = SensorData::default();
        cd.payload = Vec::from_slice(b"hello").expect("fits");
        let (out, _done) = dispatch(&Message::SensorData(cd), &ctx(false));
        assert!(out.sensor_data.is_none());
    }
}
