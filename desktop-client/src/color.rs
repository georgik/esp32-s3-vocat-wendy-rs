//! Pixel conversion: interleaved RGB(A) into big-endian RGB565, plus a
//! built-in gradient pattern so the tool can be exercised with no image file.

/// Convert interleaved 8-bit RGB (len == w*h*3) to big-endian RGB565
/// (high byte first per pixel, 2 bytes per pixel).
pub fn rgb565_from_rgb(rgb: &[u8], w: usize, h: usize) -> Vec<u8> {
    assert_eq!(rgb.len(), w * h * 3, "RGB buffer size mismatch");
    let mut out = Vec::with_capacity(w * h * 2);
    for chunk in rgb.chunks_exact(3) {
        out.extend_from_slice(&rgb_pixel_to_rgb565(chunk[0], chunk[1], chunk[2]));
    }
    out
}

/// Convert interleaved 8-bit RGBA (len == w*h*4) to big-endian RGB565, dropping
/// the alpha channel.
pub fn rgb565_from_rgba(rgba: &[u8], w: usize, h: usize) -> Vec<u8> {
    assert_eq!(rgba.len(), w * h * 4, "RGBA buffer size mismatch");
    let mut out = Vec::with_capacity(w * h * 2);
    for px in rgba.chunks_exact(4) {
        out.extend_from_slice(&rgb_pixel_to_rgb565(px[0], px[1], px[2]));
    }
    out
}

/// Convert a single 8-bit RGB pixel to 2 big-endian RGB565 bytes.
pub fn rgb_pixel_to_rgb565(r: u8, g: u8, b: u8) -> [u8; 2] {
    let val = ((r & 0xF8) as u16) << 8 | ((g & 0xFC) as u16) << 3 | (b >> 3) as u16;
    [(val >> 8) as u8, val as u8]
}

/// A deterministic diagonal gradient (red rises with x, blue with y, green
/// fixed) -- handy for smoke-testing the pipeline with no image on disk.
pub fn gradient_pattern(w: usize, h: usize) -> Vec<u8> {
    let mut rgb = Vec::with_capacity(w * h * 3);
    for y in 0..h {
        for x in 0..w {
            let r = ((x as u32) * 255 / w.max(1) as u32) as u8;
            let b = ((y as u32) * 255 / h.max(1) as u32) as u8;
            rgb.extend_from_slice(&[r, 0x60, b]);
        }
    }
    rgb565_from_rgb(&rgb, w, h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rgb565_endianness_and_rounding() {
        // Pure red, 8-bit: 0xF800 in RGB565, big-endian = 0xF8, 0x00.
        assert_eq!(rgb_pixel_to_rgb565(255, 0, 0), [0xF8, 0x00]);
        // Pure green: 0x07E0 -> 0x07, 0xE0.
        assert_eq!(rgb_pixel_to_rgb565(0, 255, 0), [0x07, 0xE0]);
        // Pure blue: 0x001F -> 0x00, 0x1F.
        assert_eq!(rgb_pixel_to_rgb565(0, 0, 255), [0x00, 0x1F]);
        // White: 0xFFFF -> 0xFF, 0xFF.
        assert_eq!(rgb_pixel_to_rgb565(255, 255, 255), [0xFF, 0xFF]);
    }

    #[test]
    fn rgb_to_rgb565_preserves_order() {
        let rgb = vec![255, 0, 0, 0, 0, 255]; // red, blue
        let out = rgb565_from_rgb(&rgb, 2, 1);
        assert_eq!(out, vec![0xF8, 0x00, 0x00, 0x1F]);
    }

    #[test]
    fn rgba_drops_alpha() {
        let rgba = vec![255, 0, 0, 128, 0, 255, 0, 0];
        let out = rgb565_from_rgba(&rgba, 2, 1);
        assert_eq!(out, vec![0xF8, 0x00, 0x07, 0xE0]);
    }

    #[test]
    fn gradient_is_correct_size() {
        let g = gradient_pattern(4, 3);
        assert_eq!(g.len(), 4 * 3 * 2);
        // Top-left corner (x=0,y=0): red=0, green=0x60, blue=0 -> greenish.
        assert_eq!(&g[0..2], &[0x03, 0x00]);
        // Top-right corner (x=w-1,y=0): red is max, green=0x60, blue=0.
        // (0x60<<3 == 0x0300, so the 0x03 carries into the high byte.)
        assert_eq!(&g[6..8], &[0xBB, 0x00]);
    }
}
