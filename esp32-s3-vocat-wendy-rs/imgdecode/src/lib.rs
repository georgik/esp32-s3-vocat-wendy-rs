//! Pure-Rust, `no_std` decoders for the raw-RGB565 image chunks the device
//! receives over the network.
//!
//! A host sends an image as `img w h [hex|b64]` followed by many `put` lines,
//! each carrying a small text-safe chunk of the pixel bytes. Because a chunk
//! may split an encoding group in the middle, [`Decoder`] keeps just enough
//! carry state to bridge the gap to the next chunk.
//!
//! This crate is deliberately free of any display or `esp-hal` dependency so it
//! can be unit-tested on the host. The crate root is `no_std` for every build
//! *except* host tests: under `cfg(test)` it compiles against `std`, which is
//! what lets the `libtest` suite run. The firmware build never sets `cfg(test)`,
//! so it always sees the `no_std` variant.

#![cfg_attr(not(test), no_std)]

// `alloc` is used by the decoder in both the firmware (no_std) and host builds.
extern crate alloc;

use alloc::vec::Vec;

/// Text-safe encoding for a pixel chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// Lower-case / upper-case hex digit pairs (2 chars per byte).
    Hex,
    /// Standard base64 (RFC 4648), `=`-padded (~1.33 chars per byte).
    B64,
}

impl Encoding {
    /// Parse `hex` / `b64` / `base64` (case-insensitive).
    pub fn parse(s: &str) -> Option<Encoding> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("hex") {
            Some(Encoding::Hex)
        } else if s.eq_ignore_ascii_case("b64") || s.eq_ignore_ascii_case("base64") {
            Some(Encoding::B64)
        } else {
            None
        }
    }
}

/// Growable byte sink the decoder appends decoded pixels to.
///
/// Keeping the decoder agnostic of the backing store lets the same `no_std`
/// decoder run on the host (feeding a plain `Vec<u8>`) and on the device
/// (feeding a PSRAM-backed buffer).
pub trait ByteSink {
    /// Append one decoded byte, returning an error if the sink already holds
    /// `max` bytes.
    fn push_byte(&mut self, byte: u8, max: usize) -> Result<(), &'static str>;
}

/// A `Vec<u8>` is a `ByteSink`: it grows, bounded by `max`.
impl ByteSink for Vec<u8> {
    fn push_byte(&mut self, byte: u8, max: usize) -> Result<(), &'static str> {
        if self.len() < max {
            self.push(byte);
            Ok(())
        } else {
            Err("image buffer full")
        }
    }
}

/// Incremental decoder carrying the small state needed to bridge a chunk that
/// ends mid-group.
#[derive(Debug)]
pub struct Decoder {
    kind: Encoding,
    /// Pending high nibble waiting for its low nibble (hex).
    hex_carry: Option<u8>,
    /// Up to four raw base64 chars buffered for the current 4-char group.
    b64_buf: [u8; 4],
    b64_n: usize,
}

impl Decoder {
    /// Create a decoder for the given encoding, ready for the first chunk.
    pub fn new(kind: Encoding) -> Self {
        Self {
            kind,
            hex_carry: None,
            b64_buf: [0; 4],
            b64_n: 0,
        }
    }

    /// Decode one chunk, appending the raw bytes to `out`.
    ///
    /// Returns an error (leaving `out` with whatever decoded so far) if the
    /// running total would exceed `max` bytes. A chunk may split an encoding
    /// group; the leftover state is carried into the next call.
    pub fn feed(
        &mut self,
        out: &mut impl ByteSink,
        chunk: &str,
        max: usize,
    ) -> Result<(), &'static str> {
        match self.kind {
            Encoding::Hex => feed_hex(self, out, chunk, max),
            Encoding::B64 => feed_b64(self, out, chunk, max),
        }
    }
}

fn is_ws(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r')
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn push_byte(out: &mut impl ByteSink, byte: u8, max: usize) -> Result<(), &'static str> {
    out.push_byte(byte, max)
}

fn feed_hex(
    d: &mut Decoder,
    out: &mut impl ByteSink,
    chunk: &str,
    max: usize,
) -> Result<(), &'static str> {
    let mut carry = d.hex_carry;
    for c in chunk.bytes() {
        if is_ws(c) {
            continue;
        }
        let low = hex_val(c).ok_or("invalid hex digit")?;
        match carry {
            Some(high) => {
                push_byte(out, (high << 4) | low, max)?;
                carry = None;
            }
            None => carry = Some(low),
        }
    }
    d.hex_carry = carry;
    Ok(())
}

fn feed_b64(
    d: &mut Decoder,
    out: &mut impl ByteSink,
    chunk: &str,
    max: usize,
) -> Result<(), &'static str> {
    for c in chunk.bytes() {
        if is_ws(c) {
            continue;
        }
        // Complete any buffered group before appending a fresh char.
        if d.b64_n == 4 {
            decode_group(d, out, max)?;
        }
        if c == b'=' {
            d.b64_buf[d.b64_n] = c;
        } else {
            b64_val(c).ok_or("invalid base64 character")?;
            d.b64_buf[d.b64_n] = c;
        }
        d.b64_n += 1;
    }
    if d.b64_n == 4 {
        decode_group(d, out, max)?;
    }
    Ok(())
}

/// Decode one buffered 4-char base64 group (handling `=` padding) and push the
/// resulting 1–3 bytes.
fn decode_group(d: &mut Decoder, out: &mut impl ByteSink, max: usize) -> Result<(), &'static str> {
    let g = d.b64_buf;
    let v0 = b64_val(g[0]).ok_or("malformed base64 group")?;
    let v1 = if g[1] == b'=' {
        None
    } else {
        Some(b64_val(g[1]).ok_or("malformed base64 group")?)
    };
    let v2 = if g[2] == b'=' {
        None
    } else {
        Some(b64_val(g[2]).ok_or("malformed base64 group")?)
    };
    let v3 = if g[3] == b'=' {
        None
    } else {
        Some(b64_val(g[3]).ok_or("malformed base64 group")?)
    };

    // Byte 0 is always present.
    push_byte(out, ((v0 << 2) | (v1.unwrap_or(0) >> 4)) as u8, max)?;
    if g[2] != b'=' {
        // Byte 1 needs v1 and v2.
        push_byte(
            out,
            (((v1.unwrap_or(0) & 0xf) << 4) | (v2.unwrap_or(0) >> 2)) as u8,
            max,
        )?;
        if g[3] != b'=' {
            // Byte 2 needs v2 and v3.
            push_byte(
                out,
                (((v2.unwrap_or(0) & 0x3) << 6) | v3.unwrap_or(0)) as u8,
                max,
            )?;
        }
    }

    d.b64_buf = [0; 4];
    d.b64_n = 0;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(kind: Encoding, chunk: &str) -> Vec<u8> {
        let mut d = Decoder::new(kind);
        let mut out = Vec::new();
        d.feed(&mut out, chunk, usize::MAX).unwrap();
        out
    }

    /// Decode `whole` at every possible split point (feeding the two halves to
    /// one decoder so the carry state bridges the split) and confirm each split
    /// equals feeding the whole chunk in a single call. This exercises the
    /// carry state. Returns the reference decode.
    fn decode_split(kind: Encoding, whole: &str) -> Vec<u8> {
        let mut d = Decoder::new(kind);
        let mut whole_out = Vec::new();
        d.feed(&mut whole_out, whole, usize::MAX).unwrap();

        for start in 1..whole.len() {
            let mut d2 = Decoder::new(kind);
            let mut out = Vec::new();
            d2.feed(&mut out, &whole[..start], usize::MAX).unwrap();
            d2.feed(&mut out, &whole[start..], usize::MAX).unwrap();
            assert_eq!(out, whole_out, "mismatch splitting at byte {}", start);
        }
        whole_out
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(
            decode(Encoding::Hex, "deadbeef"),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn hex_odd_nibbles_carry_across_chunks() {
        // First chunk ends on an odd nibble ('a'); it must pair with the first
        // nibble of the next chunk ("b" -> 0xab), not start a fresh byte.
        let mut d = Decoder::new(Encoding::Hex);
        let mut out = Vec::new();
        d.feed(&mut out, "dca", usize::MAX).unwrap(); // 0xdc, carry 0xa
        d.feed(&mut out, "b", usize::MAX).unwrap(); // 0xab
        assert_eq!(out, vec![0xdc, 0xab]);

        // A lone trailing nibble stays pending until the next chunk completes it.
        let mut d2 = Decoder::new(Encoding::Hex);
        let mut out2 = Vec::new();
        d2.feed(&mut out2, "d", usize::MAX).unwrap();
        assert!(out2.is_empty());
        d2.feed(&mut out2, "c", usize::MAX).unwrap();
        assert_eq!(out2, vec![0xdc]);
    }

    #[test]
    fn hex_skips_whitespace() {
        assert_eq!(
            decode(Encoding::Hex, "de ad\nbe ef"),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn b64_known_vectors() {
        assert_eq!(decode(Encoding::B64, "TUFOVUFM"), b"MANUAL");
        assert_eq!(decode(Encoding::B64, "SGVsbG8="), b"Hello");
        assert_eq!(decode(Encoding::B64, "Zm9vYmFy"), b"foobar");
        assert_eq!(decode(Encoding::B64, "QUJD"), b"ABC");
    }

    #[test]
    fn b64_padding_variants() {
        assert_eq!(decode(Encoding::B64, "TWE="), b"Ma");
        assert_eq!(decode(Encoding::B64, "TWY="), b"Mf");
        assert_eq!(decode(Encoding::B64, "TWFm"), b"Maf");
    }

    #[test]
    fn b64_chunks_are_boundary_invariant() {
        let message = b"The quick brown fox jumps over the lazy dog.";
        let whole = decode_split(Encoding::B64, &base64(message));
        assert_eq!(whole, message);
    }

    #[test]
    fn hex_chunks_are_boundary_invariant() {
        let message = b"pixel data \x00\x01\x02\xff";
        let whole = decode_split(Encoding::Hex, &hex_encode(message));
        assert_eq!(whole, message);
    }

    #[test]
    fn capacity_is_enforced() {
        let mut d = Decoder::new(Encoding::Hex);
        let mut out = Vec::new();
        // 4 bytes allowed; the first four decode, the fifth overflows the cap.
        let r = d.feed(&mut out, "deadbeef00", 4);
        assert_eq!(out, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(r, Err("image buffer full"));
    }

    #[test]
    fn encoding_parse_is_case_insensitive() {
        assert_eq!(Encoding::parse("hex"), Some(Encoding::Hex));
        assert_eq!(Encoding::parse("B64"), Some(Encoding::B64));
        assert_eq!(Encoding::parse("base64"), Some(Encoding::B64));
        assert_eq!(Encoding::parse("raw"), None);
    }

    fn base64(bytes: &[u8]) -> alloc::string::String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = alloc::string::String::new();
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let n = (b0 << 16) | (b1 << 8) | b2;
            s.push(ALPHABET[((n >> 18) & 63) as usize] as char);
            s.push(ALPHABET[((n >> 12) & 63) as usize] as char);
            if chunk.len() > 1 {
                s.push(ALPHABET[((n >> 6) & 63) as usize] as char);
            } else {
                s.push('=');
            }
            if chunk.len() > 2 {
                s.push(ALPHABET[(n & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
        s
    }

    fn hex_encode(bytes: &[u8]) -> alloc::string::String {
        const H: &[u8; 16] = b"0123456789abcdef";
        let mut s = alloc::string::String::new();
        for &b in bytes {
            s.push(H[(b >> 4) as usize] as char);
            s.push(H[(b & 0xf) as usize] as char);
        }
        s
    }
}
