//! A small PNG decoder built on the well-tested `png` crate.
//!
//! We request `Transformations::EXPAND | ALPHA | STRIP_16` (the old "STRINGIFY"
//! behaviour) so that paletted, 16-bit and sub-8-bit grayscale images are all
//! normalized to 8-bit RGB(A)/grayscale before we read the buffer -- that is
//! exactly what `main::to_rgb565` expects (1, 3 or 4 channels).

use std::io::Cursor;

/// The raw, unfiltered pixel bytes plus geometry.
pub struct PngImage {
    pub width: u32,
    pub height: u32,
    /// Number of 8-bit channels per pixel (1, 3 or 4).
    pub channels: u8,
    /// Row-major pixel data, one byte per channel.
    pub pixels: Vec<u8>,
}

#[derive(Debug)]
pub enum PngError {
    BadSignature,
    UnsupportedInterlace,
    MissingDimensions,
    Decode(png::DecodingError),
}

impl std::fmt::Display for PngError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PngError::BadSignature => write!(f, "not a PNG (bad signature)"),
            PngError::UnsupportedInterlace => {
                write!(f, "unsupported PNG interlace mode (only non-interlaced)")
            }
            PngError::MissingDimensions => write!(f, "PNG has zero width or height"),
            PngError::Decode(e) => write!(f, "PNG decode error: {e}"),
        }
    }
}

impl std::error::Error for PngError {}

const SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/// Decode a PNG from its bytes into raw 8-bit-per-channel pixels.
pub fn decode(data: &[u8]) -> Result<PngImage, PngError> {
    if data.len() < 8 || data[..8] != SIGNATURE {
        return Err(PngError::BadSignature);
    }

    // Expand paletted/sub-8-bit/16-bit to 8-bit RGB(A)/grayscale, matching the
    // channel counts `main::to_rgb565` understands (1, 3 or 4). This is the old
    // "STRINGIFY" behaviour: EXPAND | STRIP_16 (no ALPHA), so a plain RGB image
    // stays 3-channel while a paletted image keeps an alpha channel only when it
    // actually carries a tRNS chunk.
    let mut decoder = png::Decoder::new(Cursor::new(data.to_vec()));
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);

    let mut reader = decoder.read_info().map_err(PngError::Decode)?;
    if reader.info().interlaced {
        return Err(PngError::UnsupportedInterlace);
    }

    // Read every transformed row and concatenate into one row-major buffer.
    let mut pixels = Vec::new();
    while let Some(row) = reader.next_row().map_err(PngError::Decode)? {
        pixels.extend_from_slice(row.data());
    }
    reader.finish().map_err(PngError::Decode)?;

    let width = reader.info().width;
    let height = reader.info().height;
    let px = (width as usize) * (height as usize);
    if px == 0 {
        return Err(PngError::MissingDimensions);
    }
    let channels = (pixels.len() / px) as u8;

    Ok(PngImage {
        width,
        height,
        channels,
        pixels,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode an embedded base64 PNG (see the `*_BASE64` constants below).
    fn decode_b64(b64: &str) -> PngImage {
        let bytes = base64_decode(b64);
        decode(&bytes).expect("decode embedded PNG")
    }

    #[test]
    fn decodes_rgb() {
        let img = decode_b64(env!("RGB_BASE64"));
        assert_eq!((img.width, img.height), (2, 2));
        assert_eq!(img.channels, 3);
        assert_eq!(
            img.pixels,
            vec![255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 0]
        );
    }

    #[test]
    fn decodes_palette_with_alpha_to_rgba() {
        // Palette image with a tRNS chunk: EXPAND | ALPHA expands it to RGBA, so
        // channels should be 4 with the per-entry alpha preserved.
        let img = decode_b64(env!("PALETTE_BASE64"));
        assert_eq!((img.width, img.height), (2, 2));
        assert_eq!(img.channels, 4);
        assert_eq!(
            img.pixels,
            vec![
                255, 0, 0, 255, // idx 0 -> red, full alpha
                0, 0, 255, 128, // idx 1 -> blue, half alpha
                0, 0, 255, 128,
                255, 0, 0, 255,
            ]
        );
    }

    #[test]
    fn rejects_non_png() {
        assert!(matches!(
            decode(b"this is not a png file"),
            Err(PngError::BadSignature)
        ));
    }

    fn base64_decode(s: &str) -> Vec<u8> {
        const TABLE: [u8; 256] = {
            let mut t = [255u8; 256];
            let digits = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut i = 0;
            while i < 62 {
                t[digits[i] as usize] = i as u8;
                i += 1;
            }
            t[b'+' as usize] = 62;
            t[b'/' as usize] = 63;
            t
        };
        let mut out = Vec::new();
        let mut buf = 0u32;
        let mut nbits = 0u32;
        for c in s.bytes() {
            let v = TABLE[c as usize];
            if v == 255 {
                continue;
            }
            buf = (buf << 6) | v as u32;
            nbits += 6;
            if nbits >= 8 {
                nbits -= 8;
                out.push((buf >> nbits) as u8);
            }
        }
        out
    }
}
