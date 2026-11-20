//! Baseline-JPEG encoding of big-endian RGB565 pixels for SensorLink streaming.
//!
//! The device decodes a baseline JPEG (`libjpeg-turbo-rs`, SOF0) straight to
//! RGB, which it repacks into RGB565. Baseline JPEG is lossy, so the round trip
//! is approximate rather than bit-for-bit -- acceptable on the 360x360 display
//! panel, and far smaller than the raw frame.
//!
//! The device expects the payload (after the SensorLink 8-byte width/height
//! header) to start with a JPEG SOI marker (`0xFF 0xD8`) and end with EOI
//! (`0xFF 0xD9`); the encoder emits exactly that.

use libjpeg_turbo_rs::{compress, PixelFormat, Subsampling};

/// Per-frame settings. Tuned for the 360x360 display panel: high quality with
/// full-resolution chroma (4:4:4) so text and sharp edges stay crisp once the
/// device repacks to RGB565.
const QUALITY: u8 = 90;
const SUBSAMPLING: Subsampling = Subsampling::S444;

/// Encode big-endian RGB565 pixels as a baseline-JPEG byte stream.
///
/// Each 16-bit RGB565 pixel is split into its 5-6-5 channels and expanded to
/// 8-bit per channel (the inverse of the device's 8-bit→5-bit compaction in
/// `script.rs`), then encoded as a baseline JPEG.
pub fn encode_rgb565(jpeg: &[u8], width: u32, height: u32) -> Result<Vec<u8>, String> {
    let need = (width as usize) * (height as usize) * 2;
    if jpeg.len() != need {
        return Err(format!(
            "rgb565 length {} != {}x{}x2",
            jpeg.len(),
            width,
            height
        ));
    }

    // Interleaved 8-bit R, G, B samples (one byte each) -- the 8-bit 3-component
    // image the device's decoder emits before it repacks RGB565.
    let mut rgb: Vec<u8> = Vec::with_capacity(width as usize * height as usize * 3);
    for px in jpeg.chunks_exact(2) {
        let val = ((px[0] as u16) << 8) | px[1] as u16; // big-endian pixel
        let r5 = (val >> 11) & 0x1F;
        let g6 = (val >> 5) & 0x3F;
        let b5 = val & 0x1F;
        // 5/6/5-bit -> 8-bit full-range expansion (inverse of the device side).
        let r = ((r5 << 3) | (r5 >> 2)) as u8;
        let g = ((g6 << 2) | (g6 >> 4)) as u8;
        let b = ((b5 << 3) | (b5 >> 2)) as u8;
        rgb.extend_from_slice(&[r, g, b]);
    }

    compress(
        &rgb,
        width as usize,
        height as usize,
        PixelFormat::Rgb,
        QUALITY,
        SUBSAMPLING,
    )
    .map_err(|e| format!("baseline JPEG encode failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A 2x1 frame: red then blue (big-endian RGB565).
    fn frame() -> Vec<u8> {
        vec![0xF8, 0x00, 0x00, 0x1F]
    }

    #[test]
    fn encodes_and_starts_with_soi() {
        let jpeg = encode_rgb565(&frame(), 2, 1).expect("encode");
        // SOI marker first, EOI marker last (what the device detects).
        assert_eq!(&jpeg[0..2], &[0xFF, 0xD8]);
        assert_eq!(&jpeg[jpeg.len() - 2..], &[0xFF, 0xD9]);
        // The device reads an 8-byte width/height header before the stream, so a
        // JPEG frame must be at least that long plus SOI + EOI.
        assert!(jpeg.len() >= 8 + 2 + 2);
    }

    #[test]
    fn decodes_to_expected_dimensions() {
        let jpeg = encode_rgb565(&frame(), 2, 1).expect("encode");
        let img = libjpeg_turbo_rs::decompress_to(&jpeg, PixelFormat::Rgb).expect("decode");
        assert_eq!((img.width, img.height), (2, 1));
        assert_eq!(img.data.len(), 2 * 1 * 3);
    }

    #[test]
    fn round_trips_approximately() {
        // Baseline JPEG is lossy, so the decoded RGB is close to (not identical
        // to) the expanded source pixels.
        let jpeg = encode_rgb565(&frame(), 2, 1).expect("encode");
        let img = libjpeg_turbo_rs::decompress_to(&jpeg, PixelFormat::Rgb).expect("decode");
        let expand = |val: u16| -> (u8, u8, u8) {
            let r5 = (val >> 11) & 0x1F;
            let g6 = (val >> 5) & 0x3F;
            let b5 = val & 0x1F;
            (
                ((r5 << 3) | (r5 >> 2)) as u8,
                ((g6 << 2) | (g6 >> 4)) as u8,
                ((b5 << 3) | (b5 >> 2)) as u8,
            )
        };
        let (r0, g0, b0) = expand(0xF800);
        let (r1, g1, b1) = expand(0x001F);
        let expected = [(r0, g0, b0), (r1, g1, b1)];
        for (i, (er, eg, eb)) in expected.iter().enumerate() {
            let d = &img.data[i * 3..i * 3 + 3];
            assert!(
                (d[0] as i32 - *er as i32).abs() <= 8,
                "pixel {i} R: decoded {} vs expected {}",
                d[0],
                er
            );
            assert!((d[1] as i32 - *eg as i32).abs() <= 8);
            assert!((d[2] as i32 - *eb as i32).abs() <= 8);
        }
    }

    #[test]
    fn rejects_wrong_length() {
        let err = encode_rgb565(&[0, 0, 0], 2, 1);
        assert!(err.is_err());
    }
}
