//! img2script -- turn an image into the ESP-VoCat Wendy network-graphics DSL
//! and optionally send it over the LAN.
//!
//! This is the pure-Rust replacement for the old Python client. It supports
//! PNG files, raw 8-bit RGB, raw big-endian RGB565, and a built-in gradient
//! pattern, then emits the `img` / `put…` / `place` script (printed to stdout)
//! and, with `--host`, pushes it to the device over the LAN. The LAN server on
//! the device speaks a self-signed TLS session (server-auth-only), so by default
//! the tool completes a TLS handshake; pass `--plain` to use a bare TCP socket
//! instead (useful for local testing against a non-TLS listener).

mod color;
mod dsl;
mod jpeg;
mod png;
mod wendy;

use std::fs;
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};

use color::{gradient_pattern, rgb565_from_rgb, rgb565_from_rgba};
use dsl::{build_script, Encoding};

/// Round panel width (the ESP-VoCat is a 360×360 round display).
const PANEL: usize = 360;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opts = match parse_args(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("img2script: {e}");
            exit(2);
        }
    };

    let w = opts.width as usize;
    let h = opts.height as usize;
    if w == 0 || h == 0 {
        eprintln!("img2script: --w and --h must be non-zero");
        exit(2);
    }

    // 1. Load + convert to big-endian RGB565.
    let rgb565 = match load_image(&opts.image, w, h) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("img2script: {e}");
            exit(1);
        }
    };

    // 2. Compute placement (centred unless overridden).
    let x = opts.x.unwrap_or((PANEL as i32 - w as i32) / 2);
    let y = opts.y.unwrap_or((PANEL as i32 - h as i32) / 2);

    // 3. SensorLink streaming mode: build the subscribe command + sensor_data
    //    frames and push them over the LAN (no DSL lines involved).
    if opts.sensorlink {
        run_sensorlink(&opts, &rgb565, w as u32, h as u32);
        return;
    }

    // 3. Build the DSL.
    let lines = build_script(
        &rgb565,
        opts.width,
        opts.height,
        opts.encoding,
        opts.chunk,
        x,
        y,
    );

    // 4. Print (plain lines, so output can be redirected to a file).
    for line in &lines {
        println!("{line}");
    }

    // 5. Optionally send over the LAN.
    if let Some(host) = &opts.host {
        match wendy::send_lines(host, opts.port, &lines, opts.tls) {
            Ok(()) => {
                eprintln!(
                    "img2script: sent {} lines to {}:{} ({}x{})",
                    lines.len(),
                    host,
                    opts.port,
                    opts.width,
                    opts.height
                );
            }
            Err(e) => {
                eprintln!("img2script: send failed: {e}");
                exit(1);
            }
        }
    }
}

/// SensorLink streaming mode: subscribe to the device's sensor channel, then
/// stream the frame as a sequence of `sensor_data` chunks.
///
/// The frame list is one `subscribe` command followed by one `sensor_data`
/// frame per chunk (see `dsl::sensorlink_chunks`); each frame is pushed over the
/// LAN via `wendy::send_raw_frames`. With no `--host` the frames are still
/// built and the summary printed, which is handy for counting/chunking checks.
fn run_sensorlink(opts: &Options, rgb565: &[u8], w: u32, h: u32) {
    let mut frames: Vec<Vec<u8>> = Vec::new();
    // Opening Wendy handshake. The device rejects any command (and gates
    // out every sensor chunk) until `handshake_done` is set, which only this
    // message does — so it must go first, before the subscribe and the stream.
    // The id is arbitrary (the device just echoes it); derive one from the
    // clock so runs don't collide.
    let handshake_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u32)
        .unwrap_or(0)
        .rotate_left(16)
        ^ w
        ^ (h << 8);
    frames.push(wendy::build_handshake_frame(handshake_id));
    // Subscribe with a small request id (echoed back in the manifest).
    frames.push(wendy::build_subscribe_frame(1, wendy::SENSOR_CHANNEL));
    // Optional: encode the frame as a baseline JPEG before chunking. A JPEG
    // frame's payload (after the 8-byte header) starts with a SOI marker, which
    // the device detects and decodes; raw mode passes the RGB565 through as-is.
    let frame_data: Vec<u8> = if opts.jpeg {
        match jpeg::encode_rgb565(rgb565, w, h) {
            Ok(j) => {
                eprintln!(
                    "img2script: sensorlink-jpeg: {} bytes for {}x{} frame",
                    j.len(),
                    w,
                    h
                );
                j
            }
            Err(e) => {
                eprintln!("img2script: {e}");
                exit(1);
            }
        }
    } else {
        rgb565.to_vec()
    };
    let mut chunk_seq: u32 = 0;
    for chunk in dsl::sensorlink_chunks(&frame_data, w, h, opts.chunk) {
        frames.push(wendy::build_sensor_data_frame(
            wendy::SENSOR_CHANNEL,
            1, // frame_seq: a single frame per run
            chunk_seq,
            chunk.flags,
            &chunk.payload,
        ));
        chunk_seq += 1;
    }

    eprintln!(
        "img2script: sensorlink: {} chunks for {}x{} frame",
        frames.len().saturating_sub(1),
        w,
        h
    );

    // Send over the LAN if a host was given.
    if let Some(host) = &opts.host {
        match wendy::send_raw_frames(host, opts.port, &frames, opts.tls) {
            Ok(()) => {
                eprintln!(
                    "img2script: sent {} frames to {}:{} ({}x{})",
                    frames.len(),
                    host,
                    opts.port,
                    w,
                    h
                );
            }
            Err(e) => {
                eprintln!("img2script: send failed: {e}");
                exit(1);
            }
        }
    }
}

/// Parsed command-line options.
struct Options {
    image: String,
    width: u32,
    height: u32,
    x: Option<i32>,
    y: Option<i32>,
    encoding: Encoding,
    chunk: usize,
    host: Option<String>,
    tls: bool,
    sensorlink: bool,
    jpeg: bool,
    port: u16,
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut opts = Options {
        image: String::new(),
        width: 96,
        height: 48,
        x: None,
        y: None,
        encoding: Encoding::B64,
        chunk: 88,
        host: None,
        tls: true,
        sensorlink: false,
        jpeg: false,
        port: 5054,
    };

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" => {
                print_help();
                exit(0);
            }
            "-w" | "--width" => {
                opts.width = parse_u32(iter.next(), "--width")?;
            }
            "-h" | "--height" => {
                opts.height = parse_u32(iter.next(), "--height")?;
            }
            "-x" | "--x" => {
                opts.x = Some(parse_i32(iter.next(), "--x")?);
            }
            "-y" | "--y" => {
                opts.y = Some(parse_i32(iter.next(), "--y")?);
            }
            "--enc" => {
                let s = iter.next().ok_or("--enc needs a value")?;
                opts.encoding = Encoding::parse(s)
                    .ok_or_else(|| format!("--enc must be 'hex' or 'b64' (got '{s}')"))?;
            }
            "--chunk" => {
                opts.chunk = parse_usize(iter.next(), "--chunk")?;
            }
            "--host" => {
                opts.host = Some(parse_value(iter.next(), "--host")?);
            }
            "--port" => {
                opts.port = parse_u16(iter.next(), "--port")?;
            }
            "--plain" => {
                // Override the default TLS transport with a bare TCP socket.
                opts.tls = false;
            }
            "--sensorlink" => {
                // Stream the frame over SensorLink instead of emitting DSL lines.
                opts.sensorlink = true;
            }
            "--jpeg" => {
                // Encode the frame as a lossless JPEG (SOF3) before streaming,
                // so a picture is far smaller than raw RGB565 on the wire. JPEG
                // encoding only applies to the SensorLink chunk path (the DSL
                // path has no JPEG concept), so `--jpeg` implies `--sensorlink`.
                opts.jpeg = true;
                opts.sensorlink = true;
            }
            other => {
                if other.starts_with('-') {
                    return Err(format!("unknown option '{other}' (try --help)"));
                }
                if opts.image.is_empty() {
                    opts.image = other.to_string();
                } else {
                    return Err(format!("unexpected extra argument '{other}'"));
                }
            }
        }
    }

    if opts.image.is_empty() {
        return Err("missing <image> argument (a path, or 'pattern')".into());
    }
    if opts.chunk < 4 {
        return Err("--chunk must be >= 4".into());
    }
    Ok(opts)
}

// --- Image loading ----------------------------------------------------------

/// Load an image and return big-endian RGB565 pixel bytes.
fn load_image(path: &str, w: usize, h: usize) -> Result<Vec<u8>, String> {
    if path == "pattern" {
        return Ok(gradient_pattern(w, h));
    }

    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".png") {
        let data = fs::read(path).map_err(|e| format!("read '{path}': {e}"))?;
        let img = png::decode(&data).map_err(|e| format!("decode '{path}': {e}"))?;
        // The device renders at exactly `w x h`, so scale the decoded image to
        // that size (nearest-neighbour, which keeps pixel-art edges crisp).
        let scaled = resize_pixels(
            &img.pixels,
            img.width as usize,
            img.height as usize,
            w,
            h,
            img.channels as usize,
        );
        Ok(to_rgb565(&scaled, w, h, img.channels))
    } else if lower.ends_with(".rgb") || lower.ends_with(".rgb565") || lower.ends_with(".raw") {
        let data = fs::read(path).map_err(|e| format!("read '{path}': {e}"))?;
        expect_exact(&data, w, h, path)?;
        Ok(data) // already big-endian RGB565
    } else if lower.ends_with(".rgb24") || lower.ends_with(".bgr") {
        let data = fs::read(path).map_err(|e| format!("read '{path}': {e}"))?;
        let rgb = rgb_from_any(&data, w, h, path)?;
        Ok(rgb565_from_rgb(&rgb, w, h))
    } else {
        Err(format!(
            "unsupported file '{path}' (use a .png, raw RGB565, or 'pattern')"
        ))
    }
}

/// Resize `pixels` (row-major, `channels` bytes each) from `src_w x src_h` to
/// `dst_w x dst_h` using nearest-neighbour sampling with the standard "centre"
/// rule (the destination pixel samples the centre of its source footprint),
/// matching common image libraries. Channels are copied per-pixel, so this
/// works for grayscale, RGB and RGBA buffers alike.
fn resize_pixels(
    pixels: &[u8],
    src_w: usize,
    src_h: usize,
    dst_w: usize,
    dst_h: usize,
    channels: usize,
) -> Vec<u8> {
    let sample = |o: usize, dst: usize, src: usize| -> usize {
        let c = (o as f64 + 0.5) * (src as f64) / (dst as f64) - 0.5;
        c.clamp(0.0, src.saturating_sub(1) as f64).floor() as usize
    };
    let mut out = vec![0u8; dst_w * dst_h * channels];
    for oy in 0..dst_h {
        let sy = sample(oy, dst_h, src_h);
        for ox in 0..dst_w {
            let sx = sample(ox, dst_w, src_w);
            let src = (sy * src_w + sx) * channels;
            let dst = (oy * dst_w + ox) * channels;
            out[dst..dst + channels].copy_from_slice(&pixels[src..src + channels]);
        }
    }
    out
}

/// Convert decoded PNG pixels to big-endian RGB565, handling the channel count.
fn to_rgb565(pixels: &[u8], w: usize, h: usize, channels: u8) -> Vec<u8> {
    match channels {
        1 => {
            // Grayscale -> duplicate to RGB, then RGB565.
            let mut rgb = Vec::with_capacity(w * h * 3);
            for &v in pixels {
                rgb.extend_from_slice(&[v, v, v]);
            }
            rgb565_from_rgb(&rgb, w, h)
        }
        3 => rgb565_from_rgb(pixels, w, h),
        4 => rgb565_from_rgba(pixels, w, h),
        _ => format!(
            "unsupported PNG channel count {channels} (expected 1, 3 or 4)"
        )
        .into(),
    }
}

/// For raw RGB (3 bytes/pixel) input of unknown layout, assume 8-bit RGB(A).
fn rgb_from_any(data: &[u8], w: usize, h: usize, path: &str) -> Result<Vec<u8>, String> {
    if data.len() == w * h * 3 {
        return Ok(data.to_vec());
    }
    if data.len() == w * h * 4 {
        let mut rgb = Vec::with_capacity(w * h * 3);
        for px in data.chunks_exact(4) {
            rgb.extend_from_slice(&[px[0], px[1], px[2]]);
        }
        return Ok(rgb);
    }
    Err(format!(
        "{path}: expected {} bytes ({}x{} RGB) or {}, got {}",
        w * h * 3,
        w,
        h,
        w * h * 4,
        data.len()
    ))
}

/// Ensure a raw buffer is exactly w*h*2 bytes (big-endian RGB565).
fn expect_exact(data: &[u8], w: usize, h: usize, path: &str) -> Result<(), String> {
    let need = w * h * 2;
    if data.len() != need {
        return Err(format!(
            "{path}: expected {} bytes for {}x{} RGB565, got {}",
            need, w, h, data.len()
        ));
    }
    Ok(())
}

// --- Small arg helpers ------------------------------------------------------

fn parse_value(next: Option<&String>, name: &str) -> Result<String, String> {
    next.cloned().ok_or_else(|| format!("{name} needs a value"))
}

fn parse_u32(next: Option<&String>, name: &str) -> Result<u32, String> {
    let s = parse_value(next, name)?;
    s.parse::<u32>()
        .map_err(|_| format!("{name}: '{s}' is not a positive integer"))
}

fn parse_u16(next: Option<&String>, name: &str) -> Result<u16, String> {
    let s = parse_value(next, name)?;
    s.parse::<u16>()
        .map_err(|_| format!("{name}: '{s}' is not a port number"))
}

fn parse_usize(next: Option<&String>, name: &str) -> Result<usize, String> {
    let s = parse_value(next, name)?;
    s.parse::<usize>()
        .map_err(|_| format!("{name}: '{s}' is not a size"))
}

fn parse_i32(next: Option<&String>, name: &str) -> Result<i32, String> {
    let s = parse_value(next, name)?;
    s.parse::<i32>()
        .map_err(|_| format!("{name}: '{s}' is not an integer"))
}

fn print_help() {
    println!(
        "img2script -- ESP-VoCat Wendy network-graphics DSL tool\n\
         \n\
         Usage:\n\
           img2script <image> [options]\n\
         \n\
         <image> is a PNG file, a raw big-endian RGB565 file, a raw RGB file,\n\
         or the literal 'pattern' (a built-in gradient for testing).\n\
         \n\
         Options:\n\
           -w, --width <px>     output width  (default 96)\n\
           -h, --height <px>    output height (default 48)\n\
               --x <px>           top-left x   (default: centred)\n\
               --y <px>           top-left y   (default: centred)\n\
               --enc <hex|b64>    encoding     (default b64)\n\
               --chunk <n>        chars per put line (default 88)\n\
               --host <ip>        send over the LAN after printing\n\
               --plain            use plain TCP instead of TLS (local testing)\n\
               --sensorlink       stream as SensorLink chunks (requires --host)\n\
               --jpeg             encode each SensorLink frame as lossless JPEG\n\
               --port <n>         LAN port     (default 5054)\n\
           --help               show this help"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    // 4x4 grayscale, row-major 0..15, downscaled to 2x2 with the centre-based
    // nearest rule: dest (oy,ox) samples source (sample(oy,2,4), sample(ox,2,4)).
    #[test]
    fn resize_down_grayscale() {
        let src: Vec<u8> = (0..16).map(|v| v as u8).collect();
        let out = resize_pixels(&src, 4, 4, 2, 2, 1);
        assert_eq!(out, vec![0, 2, 8, 10]);
    }

    // 2x2 upscaled to 4x4: the last row/column picks up the second source line,
    // everything else clamps to 0.
    #[test]
    fn resize_up_grayscale() {
        let src: Vec<u8> = vec![0, 1, 2, 3];
        let out = resize_pixels(&src, 2, 2, 4, 4, 1);
        assert_eq!(
            out,
            vec![
                0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 2, 2, 2, 3,
            ]
        );
    }

    // A 3-channel buffer must keep channels interleaved (no channel mixing).
    #[test]
    fn resize_preserves_channels() {
        // 2x1 RGB: (10,20,30) (40,50,60) -> 4x1. Centre-based sampling picks
        // source col 0 for the first three outputs and col 1 for the last.
        let src = vec![10, 20, 30, 40, 50, 60];
        let out = resize_pixels(&src, 2, 1, 4, 1, 3);
        assert_eq!(out, vec![10, 20, 30, 10, 20, 30, 10, 20, 30, 40, 50, 60]);
    }
}
