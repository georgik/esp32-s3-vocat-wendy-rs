//! Wendy 8-byte frame header + body assembler.
//!
//! The header is fixed 8 bytes; the body is `body_size` bytes of
//! protobuf-encoded `WendyMessage`. [`FrameReader`] consumes de-ESCaed data
//! bytes (fed from [`super::esc::EscDecoder`]) and yields complete [`Frame`]s.

/// Frame header magic.
pub const WENDY_MSG_MAGIC: u8 = 0xA5;
/// Frame header version.
pub const WENDY_MSG_VERSION: u8 = 2;
/// Fixed frame-header length in bytes.
pub const FRAME_HEADER_SIZE: usize = 8;

/// A decoded frame: its header plus the raw protobuf body bytes.
pub struct Frame<const N: usize> {
    pub header: FrameHeader,
    pub body: heapless::Vec<u8, N>,
}

/// The fixed 8-byte frame header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    /// Header version (currently 2).
    pub version: u8,
    /// Category (reserved; 0 today).
    pub category: u8,
    /// Channel byte (replies echo the triggering message's channel).
    pub channel: u8,
    /// Reserved field.
    pub reserved: u16,
    /// Length of the protobuf body, big-endian.
    pub body_size: u16,
}

impl FrameHeader {
    /// Parse 8 bytes into a header. Returns `None` only if the magic byte is
    /// wrong (the caller pre-checks magic byte-by-byte, so a parsed header is
    /// always valid).
    pub fn parse(bytes: &[u8; FRAME_HEADER_SIZE]) -> Option<FrameHeader> {
        if bytes[0] != WENDY_MSG_MAGIC {
            return None;
        }
        Some(FrameHeader {
            version: bytes[1],
            category: bytes[2],
            channel: bytes[3],
            reserved: u16::from_be_bytes([bytes[4], bytes[5]]),
            body_size: u16::from_be_bytes([bytes[6], bytes[7]]),
        })
    }
}

/// Accumulates de-ESCaed data bytes and emits complete [`Frame`]s.
///
/// `N` bounds the largest body we will buffer; a larger body is dropped
/// (corrupt-resync) rather than trusted.
pub struct FrameReader<const N: usize> {
    header_buf: [u8; FRAME_HEADER_SIZE],
    header_len: usize,
    header: Option<FrameHeader>,
    body: heapless::Vec<u8, N>,
    body_remaining: usize,
    corrupt: bool,
}

impl<const N: usize> Default for FrameReader<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> FrameReader<N> {
    /// Create a fresh reader.
    pub fn new() -> Self {
        Self {
            header_buf: [0; FRAME_HEADER_SIZE],
            header_len: 0,
            header: None,
            body: heapless::Vec::new(),
            body_remaining: 0,
            corrupt: false,
        }
    }

    /// Feed one de-ESCaed data byte.
    ///
    /// Returns `Some(Frame)` when a full frame body has been collected; the
    /// caller should then process the frame and discard the return. Returns
    /// `None` while more bytes are needed, or while draining a corrupt/oversize
    /// body.
    pub fn feed(&mut self, byte: u8) -> Option<Frame<N>> {
        // Draining an oversize body: drop bytes until the declared size
        // elapses. Once the last byte is consumed, resync and reprocess this
        // same byte as the start of the next header. Invariant: `corrupt` is
        // true only while `body_remaining > 0`.
        if self.corrupt {
            self.body_remaining -= 1;
            if self.body_remaining == 0 {
                // Last drain byte consumed: drop to header-resync state and
                // fall through to reprocess this byte as a header byte.
                self.corrupt = false;
                self.header_len = 0;
                self.header = None;
                self.body = heapless::Vec::new();
            } else {
                return None;
            }
        }

        // --- header phase ---
        if self.header_len < FRAME_HEADER_SIZE {
            if self.header_len == 0 && byte != WENDY_MSG_MAGIC {
                // Wait for the magic byte before buffering a header.
                return None;
            }
            self.header_buf[self.header_len] = byte;
            self.header_len += 1;
            if self.header_len < FRAME_HEADER_SIZE {
                return None;
            }
            match FrameHeader::parse(&self.header_buf) {
                Some(h) => {
                    let body_size = h.body_size as usize;
                    if body_size > N {
                        // Too large to buffer: mark corrupt and drain.
                        self.corrupt = true;
                        self.body_remaining = body_size;
                        self.header = None;
                        return None;
                    }
                    self.header = Some(h);
                    self.body_remaining = body_size;
                    if body_size == 0 {
                        // Empty body: emit now and return to the
                        // header-waiting state for the next frame.
                        self.header_len = 0;
                        return Some(Frame {
                            header: h,
                            body: heapless::Vec::new(),
                        });
                    }
                    return None;
                }
                None => unreachable!("header byte pre-checked against magic"),
            }
        }

        // --- body phase ---
        if self.body.push(byte).is_err() {
            // Should not happen (body_size <= N), but stay resync-safe.
            self.corrupt = true;
            self.body_remaining = 0;
            return None;
        }
        self.body_remaining -= 1;
        if self.body_remaining == 0 {
            let h = self.header.take().unwrap();
            let body = core::mem::replace(&mut self.body, heapless::Vec::new());
            // Frame complete: return to the header-waiting state so the next
            // byte is treated as the start of a new header (not a body byte).
            self.header_len = 0;
            return Some(Frame { header: h, body });
        }
        None
    }

    /// Whether the reader is currently draining a corrupt/oversize body.
    pub fn is_corrupt(&self) -> bool {
        self.corrupt
    }
}

/// Builds a framed, DLE-ESC-escaped byte stream for a device→host reply.
///
/// Emits the fixed 8-byte header followed by the protobuf body, escaping every
/// literal `0x10` byte (`0x10 '_'`) so the host's [`crate::esc::EscDecoder`]
/// recovers the original bytes verbatim. Escaping covers the header too, so a
/// `body_size` whose big-endian high byte is `0x10` is still recovered.
pub struct FrameEncoder<const N: usize> {
    out: heapless::Vec<u8, N>,
}

impl<const N: usize> FrameEncoder<N> {
    /// Create a fresh encoder with an empty output buffer.
    pub fn new() -> Self {
        FrameEncoder {
            out: heapless::Vec::new(),
        }
    }

    /// Append a frame carrying `body` on `channel`.
    ///
    /// Returns `false` if the escaped output overflowed the buffer; on overflow
    /// the buffer holds a best-effort prefix and the caller should drop the
    /// reply rather than send a truncated frame.
    pub fn write(&mut self, channel: u8, body: &[u8]) -> bool {
        let body_size = body.len();
        let header = [
            WENDY_MSG_MAGIC,   // magic
            WENDY_MSG_VERSION, // version
            0u8,               // category (reserved)
            channel,           // channel
            0u8,
            0u8,                      // reserved (big-endian u16 = 0)
            (body_size >> 8) as u8,   // body_size (big-endian u16) hi
            (body_size & 0xff) as u8, // body_size lo
        ];
        for &b in &header {
            if !self.esc_push(b) {
                return false;
            }
        }
        for &b in body {
            if !self.esc_push(b) {
                return false;
            }
        }
        true
    }

    /// Append one byte, escaping literal `0x10` as `0x10 '_'`.
    fn esc_push(&mut self, byte: u8) -> bool {
        if byte == crate::esc::WENDY_UART_ESC {
            self.out.push(crate::esc::WENDY_UART_ESC).is_ok() && self.out.push(b'_').is_ok()
        } else {
            self.out.push(byte).is_ok()
        }
    }

    /// The encoded, ready-to-send bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.out
    }
}

impl<const N: usize> Default for FrameEncoder<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn roundtrip(header: FrameHeader, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(WENDY_MSG_MAGIC);
        out.push(header.version);
        out.push(header.category);
        out.push(header.channel);
        out.extend_from_slice(&header.reserved.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn parses_header_fields() {
        let bytes = [WENDY_MSG_MAGIC, 2, 0, 7, 0, 0, 0, 13];
        let h = FrameHeader::parse(&bytes).unwrap();
        assert_eq!(h.version, 2);
        assert_eq!(h.category, 0);
        assert_eq!(h.channel, 7);
        assert_eq!(h.reserved, 0);
        assert_eq!(h.body_size, 13);
    }

    #[test]
    fn rejects_bad_magic() {
        let bytes = [0x00, 2, 0, 7, 0, 0, 0, 13];
        assert_eq!(FrameHeader::parse(&bytes), None);
    }

    #[test]
    fn body_size_is_big_endian() {
        // body_size bytes = 0x01 0x00 = 256
        let bytes = [WENDY_MSG_MAGIC, 2, 0, 0, 0, 0, 0x01, 0x00];
        let h = FrameHeader::parse(&bytes).unwrap();
        assert_eq!(h.body_size, 256);
    }

    #[test]
    fn reassembles_empty_body_frame() {
        let mut r = FrameReader::<64>::new();
        let body: &[u8] = &[];
        let wire = roundtrip(
            FrameHeader {
                version: 2,
                category: 0,
                channel: 3,
                reserved: 0,
                body_size: body.len() as u16,
            },
            body,
        );
        let mut emitted = Vec::new();
        for &b in &wire {
            if let Some(f) = r.feed(b) {
                emitted.push(f);
            }
        }
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].body.len(), 0);
        assert_eq!(emitted[0].header.channel, 3);
    }

    #[test]
    fn reassembles_nonempty_body() {
        let mut r = FrameReader::<64>::new();
        let body: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let wire = roundtrip(
            FrameHeader {
                version: 2,
                category: 0,
                channel: 0,
                reserved: 0,
                body_size: body.len() as u16,
            },
            body,
        );
        let mut emitted = Vec::new();
        for &b in &wire {
            if let Some(f) = r.feed(b) {
                emitted.push(f);
            }
        }
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].body.as_slice(), body);
        assert_eq!(emitted[0].header.body_size, 10);
    }

    #[test]
    fn resyncs_after_garbage_between_frames() {
        let mut r = FrameReader::<64>::new();
        let body: &[u8] = b"hi";
        let frame0 = roundtrip(
            FrameHeader {
                version: 2,
                category: 0,
                channel: 0,
                reserved: 0,
                body_size: body.len() as u16,
            },
            body,
        );
        // Two stray bytes (not magic) then a second valid frame.
        let mut wire = vec![0xAB, 0xCD];
        let frame1 = roundtrip(
            FrameHeader {
                version: 2,
                category: 0,
                channel: 9,
                reserved: 0,
                body_size: body.len() as u16,
            },
            body,
        );
        wire.extend_from_slice(&frame1);

        let mut emitted = Vec::new();
        for &b in frame0.iter().chain(wire.iter()) {
            if let Some(f) = r.feed(b) {
                emitted.push(f);
            }
        }
        assert_eq!(emitted.len(), 2);
        assert_eq!(emitted[0].body.as_slice(), body);
        assert_eq!(emitted[1].header.channel, 9);
        assert_eq!(emitted[1].body.as_slice(), body);
    }

    #[test]
    fn drops_oversize_body_and_resyncs() {
        let mut r = FrameReader::<8>::new(); // body cap of 8
        // Declare a 20-byte body; we only buffer 8, so it must be dropped.
        let wire = roundtrip(
            FrameHeader {
                version: 2,
                category: 0,
                channel: 0,
                reserved: 0,
                body_size: 20,
            },
            &[0u8; 20],
        );
        let mut emitted = Vec::new();
        for &b in &wire {
            if let Some(f) = r.feed(b) {
                emitted.push(f);
            }
        }
        // The oversize body is dropped; no frame emitted for it.
        assert_eq!(emitted.len(), 0);
        assert!(!r.is_corrupt());
    }
}
