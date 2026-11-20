//! mDNS (RFC 6762) responder for LAN discovery.
//!
//! Advertises the board as a `_wendy-lite._tcp` service so the host tool
//! `wendy device list` (and the OS's DNS-SD / mDNSResponder) can browse and
//! resolve it over the network — the wireless counterpart to the USB Wendy
//! link the `console_task` runs over USB-Serial/JTAG.
//!
#![allow(clippy::large_stack_frames)]

use alloc::format;

use embassy_net::{
    IpAddress, IpEndpoint, IpListenEndpoint, Ipv4Address, Stack,
    udp::{PacketMetadata, UdpSocket},
};
use heapless::Vec;
use log::{debug, info, warn};
use static_cell::StaticCell;

use crate::wifi;

/// mDNS runs over UDP on port 5353, both for queries and answers.
const MDNS_PORT: u16 = 5353;
/// Link-local multicast group all mDNS listeners (and responders) use.
const MDNS_MULTICAST: Ipv4Address = Ipv4Address::new(224, 0, 0, 251);

/// Cache lifetime advertised on records: 120 s per RFC 6762.
const TTL: u32 = 120;

/// Record types.
const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_TXT: u16 = 16;
const TYPE_SRV: u16 = 33;
/// DNS class `IN` (used for answers; queries may carry `IN` or `ANY`).
const CLASS_IN: u16 = 1;
/// mDNS "ANY" class (RFC 6762 §7.1.1): a responder answers these too.
const CLASS_ANY: u16 = 0x00FF;

/// Standard response flags: QR=1 (this is a response), AA=1.
const MDNS_FLAGS: u16 = 0b1000_1000_0000_0000;

// --- Identity — kept in sync with the USB DeviceIdentity (main.rs / lan.rs). ---

/// DNS-SD instance name and the Wendy service type.
const INSTANCE: &str = "esp32-s3-vocat-wendy";
/// Hostname the A record resolves; the SRV target points here.
const HOSTNAME: &str = "esp32-s3-vocat-wendy";
/// Human-facing name from TXT "displayname".
const DISPLAY_NAME: &str = "ESP-VoCat Wendy";
/// Board id from TXT "id" / the DeviceIdentity.
const BOARD_ID: &str = "00:00:00:00:00:00";
/// Capability advertised in TXT "caps" (enables the sensorlink cap on the
/// host, mirroring what the USB path advertises).
const CAPS: &str = "sensors";

/// DNS labels for the service type `_wendy-lite._tcp.local.`.
const SERVICE_LABELS: &[&str] = &["_wendy-lite", "_tcp", "local"];

/// Maximum bytes we will parse out of an inbound query name.
const MAX_NAME: usize = 48;
/// Maximum questions we bother to parse from a single query.
const MAX_QUESTIONS: usize = 8;
/// Response buffer: header + echoed questions + the full advertisement.
const TX_BUF: usize = 700;
/// Inbound query buffer.
const RX_BUF: usize = 256;

// --- Full DNS names (encoded once per task run, no compression) -------------

/// Encodes a list of DNS labels into a full, NUL-terminated name.
fn encode_name(labels: &[&str]) -> Vec<u8, 64> {
    let mut out: Vec<u8, 64> = Vec::new();
    for label in labels {
        let bytes = label.as_bytes();
        // A label is at most 63 bytes; our labels are far shorter, but keep
        // the invariant explicit rather than trusting the constants.
        let n = bytes.len().min(63) as u8;
        out.push(n).expect("label too long");
        out.extend_from_slice(bytes).expect("label too long");
    }
    out.push(0).expect("name too long");
    out
}

/// A parsed question from the inbound query.
struct Question {
    /// Byte range within the received buffer holding the full question.
    range: core::ops::Range<usize>,
    qtype: u16,
    qclass: u16,
}

/// A tiny append-only mdns packet builder.
struct Packet {
    buf: Vec<u8, TX_BUF>,
}

impl Packet {
    fn new() -> Self {
        Packet { buf: Vec::new() }
    }

    #[inline]
    fn push_u16(&mut self, v: u16) {
        self.buf
            .extend_from_slice(&v.to_be_bytes())
            .expect("packet overflow");
    }

    #[inline]
    fn push_u32(&mut self, v: u32) {
        self.buf
            .extend_from_slice(&v.to_be_bytes())
            .expect("packet overflow");
    }

    #[inline]
    fn push_bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data).expect("packet overflow");
    }

    /// Writes a full (uncompressed) name — always valid, just longer on the
    /// wire. Keeping it uncompressed avoids pointer-arithmetic bugs.
    fn push_name(&mut self, name: &[u8]) {
        self.push_bytes(name);
    }

    /// Writes a resource-record header (name + type + class + TTL).
    fn rr_header(&mut self, name: &[u8], rtype: u16) {
        self.push_name(name);
        self.push_u16(rtype);
        self.push_u16(CLASS_IN);
        self.push_u32(TTL);
    }

    fn ptr(&mut self, name: &[u8], target: &[u8]) {
        self.rr_header(name, TYPE_PTR);
        self.push_u16(target.len() as u16);
        self.push_bytes(target);
    }

    fn srv(&mut self, name: &[u8], port: u16, target: &[u8]) {
        self.rr_header(name, TYPE_SRV);
        self.push_u16(6 + target.len() as u16); // rdlength
        self.push_u16(0); // priority
        self.push_u16(0); // weight
        self.push_u16(port);
        self.push_bytes(target);
    }

    fn txt(&mut self, name: &[u8], data: &[u8]) {
        self.rr_header(name, TYPE_TXT);
        self.push_u16(data.len() as u16);
        self.push_bytes(data);
    }

    fn a(&mut self, name: &[u8], addr: Ipv4Address) {
        self.rr_header(name, TYPE_A);
        self.push_u16(4);
        self.push_bytes(&addr.octets());
    }
}

/// Builds the TXT record RDATA: a sequence of length-prefixed `key=value`
/// strings, one per identity attribute (RFC 6763 §6.1). Each entry is a single
/// length byte followed by the entry bytes.
///
/// The length prefix is mandatory: the host parser reads the length first and
/// then that many bytes. Omitting it makes the whole record unreadable — the
/// first entry's first byte (`'c'` for `caps=...`) would be read as a length.
fn txt_data() -> Vec<u8, 128> {
    let mut out: Vec<u8, 128> = Vec::new();
    let entries: &[&str] = &[
        &format!("caps={CAPS}"),
        &format!("displayname={DISPLAY_NAME}"),
        &format!("id={BOARD_ID}"),
        "mtls=true",
        &format!("name={INSTANCE}"),
    ];
    for e in entries.iter() {
        let bytes = e.as_bytes();
        // Each TXT string is length-prefixed; our entries are far under 255
        // bytes, but keep the invariant explicit rather than trusting it.
        let n = bytes.len();
        assert!(n <= 255, "txt entry too long");
        out.push(n as u8).expect("txt overflow");
        out.extend_from_slice(bytes).expect("txt overflow");
    }
    out
}

/// Parses the question section of an inbound datagram. Returns the parsed
/// questions (bounded by [`MAX_QUESTIONS`]); a malformed header yields none.
fn parse_questions(rx: &[u8]) -> [Option<Question>; MAX_QUESTIONS] {
    let mut questions: [Option<Question>; MAX_QUESTIONS] = [const { None }; MAX_QUESTIONS];
    if rx.len() < 12 {
        return questions;
    }
    let qdcount = u16::from_be_bytes([rx[4], rx[5]]) as usize;
    let mut pos = 12;
    let mut count = 0usize;
    while count < qdcount.min(MAX_QUESTIONS) {
        // Walk the name to its NUL terminator (questions are never
        // compressed; guard against anything malformed).
        let mut p = pos;
        while p < rx.len() && (p - pos) < MAX_NAME && rx[p] != 0 {
            let len = rx[p] as usize;
            if len & 0xC0 != 0 {
                break; // compression pointer — not expected in a question
            }
            p += 1 + len;
        }
        let name_end = if p < rx.len() { p + 1 } else { rx.len() };
        // Need name + QTYPE + QCLASS.
        if name_end + 4 <= rx.len() {
            let qtype = u16::from_be_bytes([rx[name_end], rx[name_end + 1]]);
            let qclass = u16::from_be_bytes([rx[name_end + 2], rx[name_end + 3]]);
            questions[count] = Some(Question {
                range: pos..name_end + 4,
                qtype,
                qclass,
            });
            count += 1;
            pos = name_end + 4;
        } else {
            break;
        }
    }
    questions
}

/// Runs the mDNS responder for the lifetime of the stack: waits for an address,
/// joins the multicast group, then answers PTR/SRV/TXT/A queries.
#[embassy_executor::task]
pub async fn mdns_task(stack: Stack<'static>) -> ! {
    // Wait for DHCP to hand out an address so the multicast join and the
    // outgoing A record have a real route/interface to use.
    let address = wifi::wait_for_address(&stack).await;
    info!("mDNS: advertising '{INSTANCE}' on {address}");

    if let Err(e) = stack.join_multicast_group(MDNS_MULTICAST) {
        warn!("mDNS: join multicast failed: {e:?}");
    }

    // One persistent socket for the life of the stack.
    static RX_META: StaticCell<[PacketMetadata; 2]> = StaticCell::new();
    static RX_BYTES: StaticCell<[u8; RX_BUF]> = StaticCell::new();
    static TX_META: StaticCell<[PacketMetadata; 2]> = StaticCell::new();
    static TX_BYTES: StaticCell<[u8; TX_BUF]> = StaticCell::new();

    let rx_meta = RX_META.init([PacketMetadata::EMPTY; 2]);
    let rx_buf = RX_BYTES.init([0u8; RX_BUF]);
    let tx_meta = TX_META.init([PacketMetadata::EMPTY; 2]);
    let tx_buf = TX_BYTES.init([0u8; TX_BUF]);

    let mut socket = UdpSocket::new(stack, rx_meta, rx_buf, tx_meta, tx_buf);
    let bind_ep = IpListenEndpoint {
        addr: None,
        port: MDNS_PORT,
    };
    // Bind may fail until the stack has a route; retry until we're up.
    loop {
        match socket.bind(bind_ep) {
            Ok(()) => break,
            Err(e) => {
                warn!("mDNS: bind failed: {e:?}; retrying in 500 ms");
                embassy_time::Timer::after(embassy_time::Duration::from_millis(500)).await;
            }
        }
    }
    info!("mDNS: listening on :{MDNS_PORT}");

    let port = crate::lan::LAN_PORT;

    // Encode each full name exactly once. These are reused for every reply, so
    // keep them in stack bindings rather than re-initialising a StaticCell on
    // each call (which would panic "`StaticCell` is already full").
    let svc_name = encode_name(SERVICE_LABELS);
    let instance_name = encode_name(&[INSTANCE, "_wendy-lite", "_tcp", "local"]);
    let hostname_name = encode_name(&[HOSTNAME, "local"]);

    loop {
        // Copy the datagram into a local buffer. `recv_from_with` hands the
        // closure the socket's *internal* buffer directly, so we never re-borrow
        // `rx_buf` (which the socket already owns for the task's lifetime). Once
        // the closure returns, the socket's borrow ends and we can send the
        // reply with `send_to` before looping to the next `recv_from_with`.
        let mut rx_copy: [u8; RX_BUF] = [0; RX_BUF];
        let (n, meta) = socket
            .recv_from_with(|data: &[u8], meta| {
                let n = data.len().min(rx_copy.len());
                rx_copy[..n].copy_from_slice(&data[..n]);
                (n, meta)
            })
            .await;
        let rx = &rx_copy[..n];
        let questions = parse_questions(rx);

        // Build the response, echoing every question and answering the ones
        // that target our service/instance/hostname.
        let mut pkt = Packet::new();
        let id = u16::from_be_bytes([rx[0], rx[1]]);
        pkt.push_u16(id);
        pkt.push_u16(MDNS_FLAGS);
        let qcount = questions.iter().filter(|q| q.is_some()).count() as u16;
        // Reserve the question-count slot; we know it up front.
        pkt.push_u16(qcount);
        let an_pos = pkt.buf.len();
        pkt.push_u16(0); // answer count (patched later)
        pkt.push_u16(0); // authority count
        pkt.push_u16(0); // additional count

        // Answer each question. Per RFC 6762 §7.1.1, answer only IN- or
        // ANY-class questions; echo (but skip) any other class as a good
        // neighbour on the wire. `answer_for` writes the matching record (if
        // any) for the question's name/type; the A record is skipped when no
        // address is assigned yet, but the service/SRV/TXT records are still
        // answered so the board stays browsable during DHCP.
        let mut ancount = 0u16;
        for q in questions.iter().flatten() {
            pkt.push_bytes(&rx[q.range.clone()]); // echo the question
            if q.qclass != CLASS_IN && q.qclass != CLASS_ANY {
                continue;
            }
            let name = &rx[q.range.clone()];
            let addr = current_ip(&stack).unwrap_or(Ipv4Address::new(0, 0, 0, 0));
            if answer_for(
                name,
                q.qtype,
                addr,
                &mut pkt,
                port,
                &svc_name,
                &instance_name,
                &hostname_name,
            ) {
                ancount += 1;
            }
        }

        // Patch the answer count into the header.
        pkt.buf[an_pos] = (ancount >> 8) as u8;
        pkt.buf[an_pos + 1] = (ancount & 0xFF) as u8;

        debug!(
            "mDNS: answering {} bytes to {:?}",
            pkt.buf.len(),
            meta.endpoint
        );

        // Send to the multicast group so every listening mDNS client (including
        // the host's DNS-SD) receives the reply regardless of how it bound.
        let dest = IpEndpoint::new(IpAddress::Ipv4(MDNS_MULTICAST), MDNS_PORT);
        if let Err(e) = socket.send_to(pkt.buf.as_slice(), dest).await {
            warn!("mDNS: send failed: {e:?}");
        }
    }
}

/// Writes the answer record(s) for a single question whose name matches our
/// advertisement. Returns `true` if at least one record was written.
///
/// `svc_name` / `instance_name` / `hostname_name` are the full (encoded) names
/// computed once at the start of the task.
///
/// `addr` is the board's current IPv4 address (`None`-equivalent represented as
/// `0.0.0.0` when unknown); the A record is skipped in that case.
fn answer_for(
    name: &[u8],
    qtype: u16,
    addr: Ipv4Address,
    pkt: &mut Packet,
    port: u16,
    svc_name: &[u8],
    instance_name: &[u8],
    hostname_name: &[u8],
) -> bool {
    if name == svc_name {
        // Browse: `_wendy-lite._tcp.local.` PTR points at the instance.
        if qtype == TYPE_PTR {
            pkt.ptr(svc_name, instance_name);
            true
        } else {
            false
        }
    } else if name == instance_name {
        // Instance resolve: SRV (target + port) and TXT (identity).
        match qtype {
            TYPE_PTR => {
                pkt.ptr(instance_name, svc_name);
                true
            }
            TYPE_SRV => {
                pkt.srv(instance_name, port, hostname_name);
                true
            }
            TYPE_TXT => {
                pkt.txt(instance_name, &txt_data());
                true
            }
            _ => false,
        }
    } else if name == hostname_name {
        // Hostname resolve: A record.
        if qtype == TYPE_A && addr != Ipv4Address::new(0, 0, 0, 0) {
            pkt.a(hostname_name, addr);
            true
        } else {
            false
        }
    } else {
        false
    }
}

/// The stack's current IPv4 address, if DHCP has assigned one.
fn current_ip(stack: &Stack<'_>) -> Option<Ipv4Address> {
    stack.config_v4().map(|c| c.address.address())
}
