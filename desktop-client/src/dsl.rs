//! Build the device network-graphics DSL from raw RGB565 pixels.
//!
//! The DSL (see the firmware `script.rs`) draws a raw image with three kinds of
//! line:
//!
//! ```text
//! img <w> <h> [hex|b64]   // begin a raw RGB565 image
//! put <chunk>             // append decoded pixel bytes (one per line)
//! place <x> <y>           // commit: draw it, top-left at (x, y)
//! ```
//!
//! Each line is capped at 96 bytes on the device, so the pixel payload is split
//! into many small `put` lines.

/// Text-safe encoding for a pixel chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Hex,
    B64,
}

impl Encoding {
    pub fn as_str(&self) -> &'static str {
        match self {
            Encoding::Hex => "hex",
            Encoding::B64 => "b64",
        }
    }

    pub fn parse(s: &str) -> Option<Encoding> {
        match s.trim().to_ascii_lowercase().as_str() {
            "hex" => Some(Encoding::Hex),
            "b64" | "base64" => Some(Encoding::B64),
            _ => None,
        }
    }
}

/// Build the full script (all lines, including the trailing `place`) for one
/// image. `chunk` is the maximum number of encoded characters per `put` line.
pub fn build_script(
    rgb565: &[u8],
    w: u32,
    h: u32,
    encoding: Encoding,
    chunk: usize,
    x: i32,
    y: i32,
) -> Vec<String> {
    let mut lines = vec![format!("img {w} {h} {}", encoding.as_str())];
    let payload = encode(rgb565, encoding);
    for piece in payload.as_bytes().chunks(chunk) {
        // Payload is hex or base64, always valid ASCII.
        let s = std::str::from_utf8(piece).expect("ascii payload");
        lines.push(format!("put {s}"));
    }
    lines.push(format!("place {x} {y}"));
    lines
}

/// A single SensorLink payload chunk.
///
/// `payload` is the raw bytes placed in the chunk's `SensorData.payload`
/// field (the first chunk of a frame carries the 8-byte width/height header
/// before the pixels); `flags` is `FLAG_KEYFRAME` on the first chunk,
/// `FLAG_LAST_CHUNK` on the last, and `0` otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorChunk {
    pub payload: Vec<u8>,
    pub flags: u32,
}

/// SensorLink flags so the host and device agree on which chunk starts / ends
/// a frame.
pub const FLAG_KEYFRAME: u32 = 1 << 0;
pub const FLAG_LAST_CHUNK: u32 = 1 << 1;

/// Size of the big-endian `width` + `height` header prepended to the first
/// chunk's payload.
pub const FRAME_HEADER_SIZE: usize = 8;

/// Split a big-endian RGB565 buffer into SensorLink chunks for a `width` x
/// `height` frame.
///
/// The first chunk carries an 8-byte big-endian `width`+`height` header before
/// its pixels (the device reads it to size the frame); the first chunk sets
/// [`FLAG_KEYFRAME`], the last sets [`FLAG_LAST_CHUNK`], and every other chunk
/// carries no flags. Each chunk's payload is at most `chunk` bytes (the first
/// is capped at `chunk`, which already includes the header slot).
///
/// `chunk` must be small enough that the first chunk's `header + pixels` and
/// every later chunk's `pixels` both fit inside the device's
/// `SENSOR_PAYLOAD_CAP` (2048) — callers should keep `chunk <= 2040`.
pub fn sensorlink_chunks(rgb565: &[u8], width: u32, height: u32, chunk: usize) -> Vec<SensorChunk> {
    // At least one chunk, even for an empty buffer, so the device always gets
    // a complete (empty) frame rather than nothing.
    let pieces: Vec<&[u8]> = if rgb565.is_empty() {
        vec![&[]]
    } else {
        rgb565.chunks(chunk).collect()
    };

    let mut header = [0u8; FRAME_HEADER_SIZE];
    header[0..4].copy_from_slice(&(width as u32).to_be_bytes());
    header[4..8].copy_from_slice(&(height as u32).to_be_bytes());

    pieces
        .iter()
        .enumerate()
        .map(|(i, piece)| {
            let mut payload = Vec::with_capacity(FRAME_HEADER_SIZE + piece.len());
            let flags = if i == 0 {
                payload.extend_from_slice(&header);
                FLAG_KEYFRAME
            } else {
                0 // only the first chunk starts the frame
            };
            payload.extend_from_slice(piece);
            // The terminating chunk also asks the device to commit the frame.
            let flags = if i + 1 == pieces.len() {
                flags | FLAG_LAST_CHUNK
            } else {
                flags
            };
            SensorChunk { payload, flags }
        })
        .collect()
}

/// Encode raw RGB565 bytes into a text-safe string using `encoding`.
fn encode(rgb565: &[u8], encoding: Encoding) -> String {
    match encoding {
        Encoding::Hex => rgb565.iter().map(|b| format!("{:02x}", b)).collect(),
        Encoding::B64 => base64_encode(rgb565),
    }
}

/// Standard base64 (RFC 4648). Chunk boundaries in the caller are aligned to a
/// multiple of 4, so each group decodes independently.
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks_exact(3) {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | chunk[2] as u32;
        s.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        s.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        s.push(ALPHABET[((n >> 6) & 63) as usize] as char);
        s.push(ALPHABET[(n & 63) as usize] as char);
    }
    let rem = &data[data.len() - (data.len() % 3)..]; // remainder (0, 1 or 2 bytes)
    if rem.len() == 1 {
        let n = (rem[0] as u32) << 16;
        s.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        s.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        s.push('=');
        s.push('=');
    } else if rem.len() == 2 {
        let n = ((rem[0] as u32) << 16) | (rem[1] as u32) << 8;
        s.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        s.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        s.push(ALPHABET[((n >> 6) & 63) as usize] as char);
        s.push('=');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encoding_is_pairwise() {
        let out = build_script(&[0xDE, 0xAD, 0xBE, 0xEF], 2, 2, Encoding::Hex, 88, 0, 0);
        assert_eq!(out[0], "img 2 2 hex");
        assert_eq!(out[1], "put deadbeef");
        assert_eq!(out.last().unwrap(), "place 0 0");
    }

    #[test]
    fn b64_encoding_round_trips() {
        let out = build_script(&[0xDE, 0xAD, 0xBE, 0xEF], 2, 2, Encoding::B64, 88, 10, 20);
        assert_eq!(out[0], "img 2 2 b64");
        assert!(out[1].starts_with("put "));
        assert_eq!(out.last().unwrap(), "place 10 20");
        // Verify the base64 payload decodes back to the original pixels.
        let decoded = base64_decode(&out[1]["put ".len()..]);
        assert_eq!(decoded, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn chunking_splits_payload() {
        let rgb = vec![0u8; 10]; // 10 bytes
        let out = build_script(&rgb, 5, 2, Encoding::Hex, 4, 0, 0);
        // hex of 10 bytes = 20 chars; chunk 4 -> 5 put lines
        let put_lines = out.iter().filter(|l| l.starts_with("put ")).count();
        assert_eq!(put_lines, 5);
    }

    // A multi-chunk frame: the first chunk sets FLAG_KEYFRAME, the last sets
    // FLAG_LAST_CHUNK, and the middle chunks carry no flags at all.
    #[test]
    fn sensorlink_flags_per_chunk() {
        let rgb = vec![0u8; 30]; // 30 bytes
        let chunks = sensorlink_chunks(&rgb, 6, 5, 10); // 3 chunks of 10
        assert_eq!(chunks.len(), 3);
        // First chunk: KEYFRAME + header present.
        assert_eq!(chunks[0].flags, FLAG_KEYFRAME);
        assert_eq!(&chunks[0].payload[0..4], &(6u32).to_be_bytes());
        assert_eq!(&chunks[0].payload[4..8], &(5u32).to_be_bytes());
        // Middle chunk: no flags.
        assert_eq!(chunks[1].flags, 0);
        // Last chunk: LAST_CHUNK, no KEYFRAME.
        assert_eq!(chunks[2].flags, FLAG_LAST_CHUNK);
    }

    fn base64_decode(s: &str) -> Vec<u8> {
        let val = |c: u8| match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => 0,
        };
        let mut out = Vec::new();
        let mut buf = 0u32;
        let mut nbits = 0u32;
        for c in s.bytes() {
            if c == b'=' {
                break;
            }
            buf = (buf << 6) | val(c) as u32;
            nbits += 6;
            if nbits >= 8 {
                nbits -= 8;
                out.push((buf >> nbits) as u8);
            }
        }
        out
    }
}
