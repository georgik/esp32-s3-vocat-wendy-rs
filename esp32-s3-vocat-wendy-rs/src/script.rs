//! A tiny, embedded-graphics-like DSL for drawing graphics and text on the
//! device over the network — no reflash required.
//!
//! A *script* is a sequence of commands, one per line. Lines are sent over the
//! Wendy stdin channel (prefixed with `>`). Each command appends to the
//! running script, and the whole script is re-rendered on the next frame, so
//! sending commands one line at a time animates naturally.
//!
//! The grammar follows the `embedded_graphics` builder style, so what you
//! write reads like the Rust calls it expands to:
//!
//! ```text
//! clear navy                 // clear the panel to a colour (default black)
//! fill red                   // set the default fill colour
//! stroke white 2             // set the default stroke colour and width
//! rect 16 16 328 44          // filled rectangle: x y width height
//! rect_o 20 20 320 38 2      // outlined rectangle (also sets line width)
//! circ 90 160 58             // filled circle: centre_x centre_y radius
//! circ_o 90 160 42 2         // outlined circle
//! line 20 20 340 340 white   // line: x1 y1 x2 y2 [color]
//! text 30 150 "hi"           // text anchored at x y
//! text_c 180 160 "centered"  // text centred on x y
//!
//! img 48 24 b64              // begin a raw RGB565 image (48x24), base64
//! put <base64 chunk…>        // append decoded pixel bytes (one per line)
//! place 156 168              // finalize: draw the image with top-left at (x,y)
//! ```
//!
//! Image data is 2 bytes/pixel (RGB565). Because each network line is capped at
//! 96 bytes, an image is assembled across many `put` lines and committed with
//! `place`. Pixels are stored on the PSRAM heap, not inline in the command list,
//! so a large image never bloats the fixed-size script buffer.
//!
//! Colour arguments accept named colours (`black`, `white`, `red`, `green`,
//! `blue`, `yellow`, `cyan`, `magenta`, `navy`, `gray`) or `#RRGGBB` /
//! `0xRRGGBB` hex.
//!
//! Sending a line that is exactly `>` (nothing after the `>`) clears the whole
//! script, giving you a fresh canvas.

use alloc::string::String as AllocString;
use esp_vocat::display::FrameBuffer;

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use esp_alloc::{HEAP, MemoryCapability};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;

use embedded_graphics::image::{Image as EgImage, ImageRawBE};
use embedded_graphics::{
    mono_font::{MonoTextStyle, ascii::FONT_8X13},
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{Circle, Line, PrimitiveStyle, Rectangle},
    text::Text,
};

use heapless::String;
use log::{debug, info};

use imgdecode::{ByteSink, Decoder, Encoding};
// Baseline-JPEG decoder for the live sensor stream. `decompress_into` writes
// into a caller-provided PSRAM buffer, so there is no separate pool/MCU/work
// state.
use libjpeg_turbo_rs::{PixelFormat, decompress_into, output_buffer_size, probe};
use wendy::proto::SensorData;
use wendy::sensorlink::{FRAME_HEADER_SIZE, Reassembler, SensorSink};

/// Maximum number of commands a script can accumulate.
pub const MAX_COMMANDS: usize = 48;

/// Maximum bytes of raw RGB565 pixel data a single image may hold (128 KiB,
/// i.e. up to 65 536 pixels, a 256×256 image). The pixel buffer is backed by
/// PSRAM via `PsramBytes` (External capability), so this is a deliberate
/// software cap rather than an Internal-heap limit -- the ~16 MB PSRAM easily
/// holds the 253 KiB framebuffer plus a larger image. Bounding it keeps the
/// per-image decode buffer finite and predictable; raise it to send bigger
/// images.
const IMG_MAX_BYTES: usize = 128 * 1024;

/// Fixed capacity (bytes) for a reassembled JPEG frame on PSRAM.
///
/// A JPEG frame's byte count is unrelated to its pixel count (a real
/// photograph compresses to tens of KiB; a noisy 360×360 frame can approach its
/// raw 253 KiB). We reserve a generous fixed cap so a single allocation covers
/// any frame. As with the raw path, this lives in PSRAM (External capability),
/// never on the stack — see [`draw_jpeg`].
const JPEG_CAP: usize = 256 * 1024;

/// A parsed drawing command. Each variant maps directly onto an
/// `embedded_graphics` primitive, so executing a command is a one-to-one
/// translation of the DSL call into a draw call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Clear the whole panel. `None` means black.
    Clear(Option<Color>),
    /// Set the default fill colour for subsequent shapes.
    Fill(Color),
    /// Set the default stroke colour and width for subsequent outlines.
    Stroke { color: Color, width: u32 },
    /// Filled rectangle at `(x, y)` with the given `width`/`height`.
    Rect {
        x: i32,
        y: i32,
        width: i32,
        height: i32,
    },
    /// Outlined rectangle. `line` is the line thickness.
    RectOutline {
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        line: u32,
        color: Option<Color>,
    },
    /// Filled circle centred at `(x, y)` with the given `radius`.
    Circ { x: i32, y: i32, radius: i32 },
    /// Outlined circle. `line` is the line thickness.
    CircOutline {
        x: i32,
        y: i32,
        radius: i32,
        line: u32,
        color: Option<Color>,
    },
    /// Straight line from `(x1, y1)` to `(x2, y2)`.
    Line {
        x1: i32,
        y1: i32,
        x2: i32,
        y2: i32,
        color: Option<Color>,
    },
    /// Text anchored at its top-left corner `(x, y)`.
    Text { x: i32, y: i32, s: String<96> },
    /// Text centred on the point `(x, y)`.
    TextCentered { x: i32, y: i32, s: String<96> },
    /// Raw RGB565 image, top-left corner at `(x, y)`. `data` is row-major,
    /// big-endian (high byte first per pixel).
    Image(Image),
}

/// A raw image: dimensions, top-left position, and its pixel bytes.
///
/// The pixel buffer is a PSRAM-backed [`PsramBytes`] (see there) so it does not
/// inflate the fixed capacity of the command list in [`Script`], nor compete
/// with Wi-Fi for the small Internal heap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    // Private: exposes the internal `PsramBytes`. Only read within this module
    // (see `Renderer::exec`), so there is no need to leak the type.
    data: PsramBytes,
}

/// A parsed error pointing at the offending 1-based line number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub msg: AllocString,
}

impl ParseError {
    fn new(line: usize, msg: impl Into<AllocString>) -> Self {
        Self {
            line,
            msg: msg.into(),
        }
    }
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "line {}: {}", self.line, self.msg)
    }
}

/// A 24-bit colour wrapped in its 565 representation, ready to hand to
/// `embedded_graphics`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Color(pub Rgb565);

impl Color {
    /// Parse a colour from a named colour or `#RRGGBB` / `0xRRGGBB` literal.
    pub fn parse(s: &str) -> Option<Color> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }

        // Named colours, case-insensitive, without allocating.
        const NAMES: [&str; 10] = [
            "black", "white", "red", "green", "blue", "yellow", "cyan", "magenta", "navy", "gray",
        ];
        for name in NAMES {
            if same_ascii_case(s, name) {
                return named_color(name);
            }
        }

        // Hex: #RRGGBB or 0xRRGGBB.
        let hex = s.strip_prefix('#').or_else(|| s.strip_prefix("0x"));
        if let Some(hex) = hex {
            if hex.len() == 6 {
                let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
                let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
                let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
                return Some(Color(Rgb565::new(r, g, b)));
            }
        }

        None
    }
}

/// Compare two ASCII strings ignoring case, without allocating.
fn same_ascii_case(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .all(|(x, y)| x.eq_ignore_ascii_case(&y))
}

fn named_color(name: &str) -> Option<Color> {
    let rgb = match name {
        "black" => (0x00, 0x00, 0x00),
        "white" => (0xff, 0xff, 0xff),
        "red" => (0xf8, 0x00, 0x00),
        "green" => (0x00, 0xe0, 0x00),
        "blue" => (0x00, 0x00, 0xf8),
        "yellow" => (0xff, 0xe0, 0x00),
        "cyan" => (0x00, 0xe0, 0xf8),
        "magenta" => (0xf8, 0x00, 0xf8),
        "navy" => (0x10, 0x18, 0x30),
        "gray" => (0x84, 0x49, 0x84),
        _ => return None,
    };
    Some(Color(Rgb565::new(rgb.0, rgb.1, rgb.2)))
}

/// A growable byte buffer backed by the PSRAM heap.
///
/// A decoded image can be up to `IMG_MAX_BYTES` (128 KiB). The process-global
/// allocator is `HEAP`, which serves *every* region but prefers Internal, so a
/// small `AllocVec` would land in Internal RAM. The internal heap (~168 KiB,
/// reclaimed + 96 KiB) is shared with Wi-Fi, whose lock-free queues must stay
/// in Internal (atomic ops do not work in PSRAM on the S3). To keep the image
/// pixels out of that contended pool we allocate them explicitly from the
/// External/PSRAM region via `HEAP.alloc_caps(External, …)` — the same region
/// the 253 KiB framebuffer lives in.
///
/// This is a hand-managed buffer (raw pointer + length + capacity); it is *not*
/// `Copy`, and [`PsramBytes::drop`] frees the PSRAM block.
struct PsramBytes {
    ptr: *mut u8,
    len: usize,
    cap: usize,
}

impl PsramBytes {
    /// An unallocated buffer (null pointer, zero length/capacity).
    const fn new() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }

    /// Allocate `cap` bytes from PSRAM. Returns `false` (leaving the buffer
    /// unallocated) if the allocation fails or `cap` is zero.
    fn alloc(&mut self, cap: usize) -> bool {
        if cap == 0 {
            return false;
        }
        unsafe {
            let layout = Layout::from_size_align_unchecked(cap, 1);
            let ptr = HEAP.alloc_caps(MemoryCapability::External.into(), layout) as *mut u8;
            if ptr.is_null() {
                return false;
            }
            self.ptr = ptr;
            self.cap = cap;
            self.len = 0;
            true
        }
    }

    /// Number of valid bytes currently stored.
    fn len(&self) -> usize {
        self.len
    }

    /// A slice over the valid bytes.
    fn as_slice(&self) -> &[u8] {
        if self.cap == 0 || self.ptr.is_null() {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
        }
    }

    /// A mutable slice over the *entire allocated capacity* (not just the valid
    /// bytes). Used to hand the whole block to a decoder that writes into it.
    fn as_mut_slice(&mut self) -> &mut [u8] {
        if self.cap == 0 || self.ptr.is_null() {
            &mut []
        } else {
            unsafe { core::slice::from_raw_parts_mut(self.ptr, self.cap) }
        }
    }

    /// Truncate to `n` valid bytes (no allocation change).
    fn truncate(&mut self, n: usize) {
        if n < self.len {
            self.len = n;
        }
    }

    /// Append bytes up to the buffer's capacity (bytes beyond it are dropped),
    /// the same overflow guard the SensorLink reassembler already applies.
    fn append_bytes(&mut self, data: &[u8]) {
        let cap = self.cap;
        let mut i = 0;
        while i < data.len() && self.len < cap {
            unsafe {
                self.ptr.offset(self.len as isize).write(data[i]);
            }
            self.len += 1;
            i += 1;
        }
    }

    /// Free the current block (if any) and allocate a fresh `cap`-byte block.
    /// Used by the JPEG sink to reset its fixed capacity each frame.
    fn reset(&mut self, cap: usize) -> bool {
        if !self.ptr.is_null() {
            unsafe {
                HEAP.dealloc(self.ptr, Layout::from_size_align_unchecked(self.cap, 1));
            }
            self.ptr = ptr::null_mut();
        }
        self.alloc(cap)
    }
}

impl Default for PsramBytes {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PsramBytes {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                HEAP.dealloc(self.ptr, Layout::from_size_align_unchecked(self.cap, 1));
            }
        }
    }
}

impl core::fmt::Debug for PsramBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PsramBytes")
            .field("ptr", &self.ptr)
            .field("len", &self.len)
            .field("cap", &self.cap)
            .finish()
    }
}

impl Clone for PsramBytes {
    fn clone(&self) -> Self {
        let mut cloned = Self::new();
        if !self.ptr.is_null() && cloned.alloc(self.cap) {
            unsafe {
                core::ptr::copy_nonoverlapping(self.ptr, cloned.ptr, self.len);
            }
            cloned.len = self.len;
        }
        cloned
    }
}

impl PartialEq for PsramBytes {
    fn eq(&self, other: &Self) -> bool {
        if self.cap != other.cap || self.len != other.len {
            return false;
        }
        for i in 0..self.len {
            unsafe {
                if self.ptr.offset(i as isize) != other.ptr.offset(i as isize) {
                    return false;
                }
            }
        }
        true
    }
}

impl Eq for PsramBytes {}

// SAFETY: `PsramBytes` owns a `*mut u8` into PSRAM, but every access to that
// buffer (append/begin in the reassembler, as_slice in the renderer) happens
// while holding the `SENSOR` mutex, so two cores never touch it concurrently.
// Sending/sharing the struct across cores is therefore safe, which the
// `static SENSOR` mutex requires.
unsafe impl Send for PsramBytes {}
unsafe impl Sync for PsramBytes {}

/// The decoded pixels feed straight into the PSRAM buffer.
impl ByteSink for PsramBytes {
    fn push_byte(&mut self, byte: u8, _max: usize) -> Result<(), &'static str> {
        // `cap <= IMG_MAX_BYTES` (the caller's `max`), so bounding on `cap`
        // keeps us inside the allocation and never writes past `ptr`.
        if self.len >= self.cap {
            return Err("image buffer full");
        }
        unsafe {
            self.ptr.offset(self.len as isize).write(byte);
        }
        self.len += 1;
        Ok(())
    }
}

/// SensorLink sink: the reassembler drives this, writing raw RGB565 pixels
/// straight into the PSRAM buffer. `begin` resets + resizes the buffer for a
/// new frame; `append` accumulates the payload bytes.
impl SensorSink for PsramBytes {
    fn begin(&mut self, pixel_count: usize) {
        // Drop any bytes from a previous frame, then reserve for this one. The
        // reassembler calls `begin` once per frame (at chunk 0), so the prior
        // frame's buffer is freed before the new one is sized to
        // `pixel_count * 2` (two bytes per RGB565 pixel).
        if !self.ptr.is_null() {
            unsafe {
                HEAP.dealloc(self.ptr, Layout::from_size_align_unchecked(self.cap, 1));
            }
        }
        self.alloc(pixel_count.saturating_mul(2));
    }

    fn append(&mut self, data: &[u8]) {
        // `push_byte` ignores any byte past the allocation, so an over-long
        // stream (which the reassembler guards against anyway) cannot overflow.
        let cap = self.cap;
        for &b in data {
            let _ = self.push_byte(b, cap);
        }
    }

    fn len(&self) -> usize {
        self.len()
    }

    fn as_slice(&self) -> &[u8] {
        self.as_slice()
    }
}

/// A fixed-capacity PSRAM sink that collects a reassembled JPEG
/// byte stream.
///
/// Unlike [`PsramBytes`]'s [`SensorSink`] impl (which reserves exactly
/// `pixel_count * 2` bytes for raw RGB565), this reserves a fixed [`JPEG_CAP`]
/// regardless of the header's pixel count -- a compressed frame's size is
/// unrelated to its pixel count. The collected bytes are handed straight to the
/// baseline-JPEG `libjpeg_turbo_rs::decompress_into` in [`draw_jpeg`].
struct JpegSink {
    data: PsramBytes,
}

impl JpegSink {
    const fn new() -> Self {
        Self {
            data: PsramBytes::new(),
        }
    }

    /// Whether the collected bytes begin with a JPEG SOI marker (`0xFF 0xD8`).
    /// A partial frame that has not completed yet still starts with SOI, so the
    /// renderer must additionally confirm the frame is complete before decoding.
    fn is_jpeg(&self) -> bool {
        let s = self.data.as_slice();
        s.len() >= 2 && s[0] == 0xFF && s[1] == 0xD8
    }
}

impl SensorSink for JpegSink {
    fn begin(&mut self, _pixel_count: usize) {
        // Free any bytes from a previous frame, then reserve the fixed JPEG
        // capacity. The reassembler calls `begin` once per frame (at chunk 0).
        self.data.reset(JPEG_CAP);
    }

    fn append(&mut self, data: &[u8]) {
        self.data.append_bytes(data);
    }

    fn len(&self) -> usize {
        self.data.len()
    }

    fn as_slice(&self) -> &[u8] {
        self.data.as_slice()
    }
}

// --- SensorLink frame delivery ---------------------------------------------

/// Shared SensorLink frame reassembler.
///
/// The console task (core 0) and the Wi-Fi/LAN task (core 1) feed inbound
/// [`SensorData`] chunks here via [`feed_sensor_data`]; the render loop drains
/// the frame-ready flag via [`take_sensor_ready`] and redraws the assembled
/// pixels via [`draw_sensor_image`]. It is a `const`-initialized
/// `static` (not a `StaticCell`) so every task can reach it directly without
/// moving a non-`Send` reference across a task boundary, and the sink is a
/// PSRAM-backed [`PsramBytes`] so a whole frame's pixels live in the same
/// External-capability region as the framebuffer.
static SENSOR: Mutex<CriticalSectionRawMutex, Reassembler<PsramBytes>> =
    Mutex::new(Reassembler::new(PsramBytes::new()));

/// Lossless-JPEG frame reassembler.
///
/// Parallel to [`SENSOR`]: it collects a reassembled JPEG byte stream
/// into a fixed-capacity [`JpegSink`] (PSRAM) instead of raw RGB565 pixels. The
/// render loop decodes the completed stream in [`draw_jpeg`]. See
/// [`feed_sensor_data`] for how a chunk is routed to one sink or the other.
static JPEG: Mutex<CriticalSectionRawMutex, Reassembler<JpegSink>> =
    Mutex::new(Reassembler::new(JpegSink::new()));

/// Feed one inbound SensorLink chunk into the correct reassembler. Returns
/// `true` if the frame completed and is ready to render.
///
/// A JPEG frame is detected when its chunk 0 payload begins, right after
/// the 8-byte width/height header, with a JPEG SOI marker (`0xFF 0xD8`);
/// otherwise it is **raw RGB565**. A JPEG frame's non-zero chunks are routed to
/// the JPEG reassembler while it is active, and vice versa.
///
/// A lock failure means the renderer holds it this instant, so the chunk is
/// dropped; the next `chunk_seq == 0` restarts the frame.
pub fn feed_sensor_data(cd: &SensorData) -> bool {
    if cd.chunk_seq == 0 {
        // First chunk of a frame: decide the format from its header + marker.
        if jpeg_start(&cd.payload) {
            return feed_into(&JPEG, cd);
        }
        return feed_into(&SENSOR, cd);
    }
    // A JPEG frame is in progress: keep feeding it; otherwise continue the raw
    // frame.
    if JPEG.try_lock().map(|g| g.is_active()).unwrap_or(false) {
        return feed_into(&JPEG, cd);
    }
    feed_into(&SENSOR, cd)
}

/// Route one chunk to a reassembler, returning whether the frame completed.
fn feed_into(
    lock: &Mutex<CriticalSectionRawMutex, Reassembler<impl SensorSink>>,
    cd: &SensorData,
) -> bool {
    match lock.try_lock() {
        Ok(mut guard) => guard.feed(cd).is_some(),
        Err(_) => {
            debug!("sensor: renderer holds reassembler; dropped chunk");
            false
        }
    }
}

/// Does `payload` begin a JPEG frame? The SensorLink header is 8
/// bytes; a JPEG frame's payload continues with the JPEG stream, whose first
/// marker is SOI (`0xFF 0xD8`).
fn jpeg_start(payload: &[u8]) -> bool {
    payload.len() >= FRAME_HEADER_SIZE + 2
        && payload[FRAME_HEADER_SIZE] == 0xFF
        && payload[FRAME_HEADER_SIZE + 1] == 0xD8
}

/// Consume the frame-ready flag, returning whether *either* the JPEG or the raw
/// SensorLink frame completed since the last call.
///
/// The assembled bytes stay in their sink until the next frame begins, so the
/// flag only answers "has a *new* frame arrived"; the bytes can still be
/// redrawn afterwards via [`draw_sensor_image`].
pub fn take_sensor_ready() -> bool {
    let jpeg_ready = JPEG
        .try_lock()
        .map(|mut g| g.take_frame_ready())
        .unwrap_or(false);
    let raw_ready = SENSOR
        .try_lock()
        .map(|mut g| g.take_frame_ready())
        .unwrap_or(false);
    jpeg_ready || raw_ready
}

/// Draw the most recently assembled SensorLink image (if any) into `fb`
/// without consuming the frame-ready flag, so a completed frame can be held
/// on screen until the caller switches view.
///
/// A JPEG frame is decoded on the fly (see [`draw_jpeg`]); a raw
/// RGB565 frame is drawn directly (see [`draw_raw_image`]). Returns `true` if an
/// image was drawn, `false` if none is available yet.
pub fn draw_sensor_image(fb: &mut FrameBuffer) -> bool {
    // Baseline-JPEG first: decode the reassembled stream. `draw_jpeg` returns
    // false on a partial / corrupt stream, in which case we fall through.
    if let Ok(mut g) = JPEG.try_lock() {
        if g.sink().is_jpeg() {
            let len = g.sink().len();
            // Only decode a *complete* frame: a partial stream is not a valid
            // JPEG yet, and decoding it on every chunk would waste a full
            // decode + multi-MB PSRAM alloc per chunk (and render a half-built
            // image). `complete_len` is set when the last chunk lands and held
            // until the next frame begins.
            if g.complete_len() == len && len > 0 {
                // Log only when the held JPEG actually changes -- otherwise a
                // still picture floods the console with one line per 30 ms
                // redraw.
                let log = g.last_drawn() != len;
                if draw_jpeg(g.sink(), fb, log) {
                    if log {
                        g.set_last_drawn(len);
                    }
                    return true;
                }
            }
        }
    }
    // Raw RGB565 fallback.
    draw_raw_image(fb)
}

/// Draw the most recently assembled raw RGB565 SensorLink image (if any).
fn draw_raw_image(fb: &mut FrameBuffer) -> bool {
    let mut guard = match SENSOR.try_lock() {
        Ok(g) => g,
        Err(_) => return false,
    };
    let len = guard.sink().len();
    // Only draw a *complete* frame. A partial stream is not a full image yet,
    // so drawing it would show a half-filled picture, and logging on every
    // chunk would flood the console -- see the JPEG path in `draw_sensor_image`.
    if len == 0 || guard.complete_len() != len {
        return false;
    }
    // The assembled bytes are row-major, big-endian RGB565. `ImageRawBE`
    // derives the height from the length given the width, and `EgImage::new`
    // positions the top-left corner at (0, 0).
    let raw = ImageRawBE::<Rgb565>::new(guard.sink().as_slice(), guard.width());
    EgImage::new(&raw, Point::new(0, 0)).draw(fb).ok();
    // The render loop redraws the held frame every 30 ms, so log only when the
    // held image actually changes -- otherwise a still picture floods the
    // console with one line per frame.
    if guard.last_drawn() != len {
        guard.set_last_drawn(len);
        info!(
            "sensor image held: {}x{} = {} bytes",
            guard.width(),
            guard.height(),
            len
        );
    }
    true
}

/// Decode a reassembled baseline-JPEG frame and draw it into `fb`, top-left at
/// (0, 0). Returns `true` on success so the caller can skip the raw fallback.
///
/// Uses `libjpeg-turbo-rs` (MIT/Apache-2.0) -- a baseline-JPEG decoder that
/// matches the host encoder (`img2script-rs`), so the whole pipeline is now
/// baseline JPEG end-to-end. The old lossless-`ljpeg` path was LGPL and has been
/// removed. `decompress_into` writes into a caller-provided buffer, so the
/// decoded pixels land in a PSRAM-backed RGB buffer; each pixel is then packed
/// into the big-endian RGB565 frame buffer before the `ImageRawBE` blit.
fn draw_jpeg(sink: &JpegSink, fb: &mut FrameBuffer, log: bool) -> bool {
    let bytes = sink.as_slice();

    // Probe the header to learn the dimensions and component count before
    // allocating anything. A partial stream has a valid SOI but an incomplete
    // SOF, so a probe failure means we are not yet at a complete frame.
    let head = match probe(bytes) {
        Ok(i) => i,
        Err(e) => {
            debug!("jpeg: header probe failed ({e:?})");
            return false;
        }
    };
    // Baseline JPEG is YCbCr (3 components); grayscale (1 component) has no
    // 3-channel layout to map to RGB565, so it falls back to the raw path.
    if head.components != 3 {
        debug!("jpeg: unsupported component count {}", head.components);
        return false;
    }
    let w = head.width;
    let h = head.height;

    // Full-frame RGB565 output buffer (PSRAM-backed), same ">32 KiB off the
    // stack" rule as the framebuffer.
    let mut frame = PsramBytes::new();
    if !frame.alloc(w.saturating_mul(h).saturating_mul(2)) {
        debug!("jpeg: out of PSRAM for frame buffer");
        return false;
    }

    // Decode into a byte-order-independent RGB buffer. libjpeg-turbo's `Rgb565`
    // output is *native* endian (little-endian on the S3), which does not match
    // the big-endian `ImageRawBE` the framebuffer expects, so we decode to
    // `Rgb` (3 bytes/pixel) and pack big-endian RGB565 ourselves.
    // `output_buffer_size` is exact for the standard RGB path (w*h*3), and the
    // buffer is reused across frames, so it also lives in PSRAM.
    let rgb_len = match output_buffer_size(bytes, PixelFormat::Rgb) {
        Ok(n) => n,
        Err(e) => {
            debug!("jpeg: output_buffer_size failed ({e:?})");
            return false;
        }
    };
    let mut rgb = PsramBytes::new();
    if !rgb.alloc(rgb_len) {
        debug!("jpeg: out of PSRAM for RGB decode buffer");
        return false;
    }
    let info = match decompress_into(bytes, PixelFormat::Rgb, rgb.as_mut_slice()) {
        Ok(i) => i,
        Err(e) => {
            debug!("jpeg: decompress failed ({e:?})");
            return false;
        }
    };
    // `decompress_into` writes into the full buffer but does not advance the
    // sink's `len`; record the valid byte count so `as_slice()` below covers it.
    rgb.len = info.bytes_written;

    // Pack each RGB pixel into big-endian RGB565 and place it in the frame
    // buffer. `Rgb565` is 2 bytes/pixel, big-endian (high byte first).
    let out = unsafe { core::slice::from_raw_parts_mut(frame.ptr, w * h * 2) };
    let src = rgb.as_slice();
    for (i, pix) in src.chunks_exact(3).enumerate() {
        let r = pix[0];
        let g = pix[1];
        let b = pix[2];
        let hi: u16 = ((r as u16 & 0xF8) << 8) | ((g as u16 & 0xFC) << 3) | (b as u16 >> 3);
        out[i * 2] = (hi >> 8) as u8;
        out[i * 2 + 1] = hi as u8;
    }
    frame.len = w * h * 2;
    let raw = ImageRawBE::<Rgb565>::new(frame.as_slice(), w as u32);
    EgImage::new(&raw, Point::new(0, 0)).draw(fb).ok();

    // The render loop redraws the held frame every 30 ms, so the caller gates
    // this log on a length change (see [`crate::draw_sensor_image`]); without it
    // a still picture would emit one line per frame.
    if log {
        info!("jpeg image held: {}x{} = {} jpeg bytes", w, h, bytes.len());
    }
    true
}

/// A pixel chunk still being assembled. The decoded bytes land in a PSRAM
/// buffer via [`PsramBytes`]; the [`Decoder`] carries the small state that lets
/// a chunk end in the middle of an encoding group.
#[derive(Debug)]
struct PendingImage {
    width: u32,
    height: u32,
    data: PsramBytes,
    decoder: Decoder,
}

impl PendingImage {
    /// Begin a pending image, reserving `width * height * 2` bytes of PSRAM.
    ///
    /// Returns `None` if the PSRAM allocation fails; the caller turns that into
    /// a parse error.
    fn new(width: u32, height: u32, encoding: Encoding) -> Option<Self> {
        let mut data = PsramBytes::new();
        let cap = (width as usize)
            .saturating_mul(height as usize)
            .saturating_mul(2);
        if !data.alloc(cap) {
            return None;
        }
        Some(Self {
            width,
            height,
            data,
            decoder: Decoder::new(encoding),
        })
    }
}

/// The running script: an ordered list of commands rendered top-to-bottom.
///
/// Commands accumulate as more lines arrive; re-rendering the whole list each
/// time is what makes sending commands incrementally animate.
#[derive(Debug, Default)]
pub struct Script {
    commands: heapless::Vec<Command, MAX_COMMANDS>,
    /// An image currently being assembled via `img`/`put`; committed with
    /// `place`. Present between `img` and `place`, which is what keeps the
    /// script "active" (and the live demo hidden) while an image loads.
    pending: Option<PendingImage>,
}

impl Script {
    /// Create an empty script.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a single line of script (the body after the leading `>`).
    ///
    /// A blank line is a no-op; use [`Script::reset`] to clear the canvas. The
    /// keyword `demo` expands to [`DEMO_SCRIPT`], animating the bundled scene.
    pub fn push_line(&mut self, line: &str) -> Result<(), ParseError> {
        let line = line.trim();
        if line.is_empty() {
            return Ok(());
        }
        if line.eq_ignore_ascii_case("demo") {
            return self.push_demo();
        }

        let tokens = split_line(line);
        let keyword = tokens
            .first()
            .copied()
            .ok_or_else(|| ParseError::new(1, "empty command"))?;

        // Image assembly is stateful (it mutates `self.pending`), so it is
        // handled here rather than in the pure [`dispatch`] below.
        if matches!(keyword, "img" | "put" | "place") {
            return self.stateful_image(keyword, &tokens);
        }

        let mut args = Args::new(&tokens);
        let command = dispatch(keyword, &mut args, 1)?;
        self.push_command(command, 1)
    }

    fn push_command(&mut self, command: Command, line_no: usize) -> Result<(), ParseError> {
        self.commands
            .push(command)
            .map_err(|_| ParseError::new(line_no, "script is full (max 48 commands)"))?;
        Ok(())
    }

    /// Handle the stateful image commands (`img`, `put`, `place`).
    fn stateful_image(&mut self, keyword: &str, tokens: &[&str]) -> Result<(), ParseError> {
        let mut args = Args::new(tokens);
        match keyword {
            "img" => self.img_begin(&mut args, 1),
            "put" => {
                let data = args.require(1)?;
                self.put_append(data, 1)
            }
            "place" => {
                let x = parse_i32(args.require(1)?, 1)?;
                let y = parse_i32(args.require(1)?, 1)?;
                self.place(x, y, 1)
            }
            _ => unreachable!(),
        }
    }

    /// `img <w> <h> [hex|b64]` — begin (or reset) a pending image buffer.
    fn img_begin(&mut self, args: &mut Args, line_no: usize) -> Result<(), ParseError> {
        let width = parse_u32(args.require(line_no)?, line_no)?;
        let height = parse_u32(args.require(line_no)?, line_no)?;
        let encoding = match args.next() {
            Some(t) => Encoding::parse(t)
                .ok_or_else(|| ParseError::new(line_no, "unknown encoding (use 'hex' or 'b64')"))?,
            None => Encoding::B64,
        };
        let needed = (width as usize)
            .saturating_mul(height as usize)
            .saturating_mul(2);
        if needed > IMG_MAX_BYTES {
            return Err(ParseError::new(
                line_no,
                "image too large (max 16384 bytes)",
            ));
        }
        // Reserve the PSRAM pixel buffer now; a failure surfaces as a parse
        // error rather than a silent decode failure later on.
        let pending = PendingImage::new(width, height, encoding)
            .ok_or_else(|| ParseError::new(line_no, "out of PSRAM for image"))?;
        self.pending = Some(pending);
        Ok(())
    }

    /// `put <data>` — append one decoded chunk to the pending image.
    fn put_append(&mut self, data: &str, line_no: usize) -> Result<(), ParseError> {
        let pending = self.pending.as_mut().ok_or_else(|| {
            ParseError::new(line_no, "no image in progress (send 'img w h' first)")
        })?;
        // `PsramBytes` is a `ByteSink`, so the decoder writes decoded pixels
        // straight into the PSRAM buffer. If decode fails, log the exact line
        // bytes: a stray `>` (from two command lines merging) or a truncated
        // line is the usual culprit, and it shows up verbatim here.
        if let Err(msg) = pending.decoder.feed(&mut pending.data, data, IMG_MAX_BYTES) {
            info!("put decode failed (line {line_no}): bytes {data:?} ({msg})");
            return Err(ParseError::new(line_no, msg));
        }
        Ok(())
    }

    /// `place <x> <y>` — commit the pending image as a drawn [`Command::Image`].
    fn place(&mut self, x: i32, y: i32, line_no: usize) -> Result<(), ParseError> {
        let pending = self
            .pending
            .take()
            .ok_or_else(|| ParseError::new(line_no, "no image in progress"))?;
        let image = finalize_image(pending, x, y, line_no)?;
        self.push_command(Command::Image(image), line_no)
    }

    /// Expand the bundled [`DEMO_SCRIPT`] into individual commands.
    fn push_demo(&mut self) -> Result<(), ParseError> {
        for (idx, line) in DEMO_SCRIPT.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let command = parse_line(line, idx + 1)?;
            self.push_command(command, idx + 1)?;
        }
        Ok(())
    }

    /// Discard every command, starting a fresh script (and any in-flight image).
    pub fn reset(&mut self) {
        self.commands.clear();
        self.pending = None;
    }

    /// Render the whole script onto `fb`. The framebuffer is assumed to be
    /// already cleared by the caller; scripts may `clear` to set their own
    /// background.
    pub fn render(&self, fb: &mut FrameBuffer) {
        let mut renderer = Renderer::new(fb);
        for command in &self.commands {
            let _ = renderer.exec(command);
        }
    }
}

/// Turn a completed pending image into a drawn command, trimming/padding the
/// pixel buffer to exactly `width * height` pixels.
fn finalize_image(
    mut pending: PendingImage,
    x: i32,
    y: i32,
    line_no: usize,
) -> Result<Image, ParseError> {
    let expected = (pending.width as usize)
        .saturating_mul(pending.height as usize)
        .saturating_mul(2);
    if pending.data.len() > expected {
        pending.data.truncate(expected);
    } else if pending.data.len() < expected {
        info!(
            "image {}: got {} bytes, expected {}",
            line_no,
            pending.data.len(),
            expected
        );
    }
    let image = Image {
        x,
        y,
        width: pending.width,
        height: pending.height,
        data: core::mem::take(&mut pending.data),
    };
    // One concise line per committed image (not per pixel) so a failed/short
    // decode is visible without flooding the console.
    info!(
        "image committed: {}x{} at ({},{}) = {} bytes",
        image.width,
        image.height,
        image.x,
        image.y,
        image.data.len()
    );
    Ok(image)
}

// --- Script parsing --------------------------------------------------------
//
// A command line is `keyword arg arg …`. [`split_line`] tokenizes it (keeping
// a quoted run together even if it contains spaces), [`Args`] walks the
// arguments in order, and [`dispatch`] turns the keyword plus arguments into a
// [`Command`]. Argument access is sequential — each [`Args::require`] simply
// yields the next token — so callers read what they need without hard-coding
// positions.

/// Split a command line into whitespace-separated tokens.
///
/// A quoted run (`"…"`) is preserved as a single token even when it contains
/// spaces; the surrounding quotes stay on the token so [`dispatch`] can strip
/// them for text commands.
fn split_line(line: &str) -> heapless::Vec<&str, 16> {
    let mut tokens: heapless::Vec<&str, 16> = heapless::Vec::new();
    let mut in_quote = false;
    let mut start: Option<usize> = None;
    for (i, c) in line.char_indices() {
        match c {
            '"' => {
                in_quote = !in_quote;
                if start.is_none() {
                    start = Some(i);
                }
            }
            _ if c.is_whitespace() && !in_quote => {
                if let Some(s) = start.take() {
                    let _ = tokens.push(&line[s..i]);
                }
            }
            _ => {
                if start.is_none() {
                    start = Some(i);
                }
            }
        }
    }
    if let Some(s) = start.take() {
        let _ = tokens.push(&line[s..]);
    }
    tokens
}

/// The arguments of a command (the tokens after the keyword), walked in order.
struct Args<'a> {
    tokens: &'a [&'a str],
    pos: usize,
}

impl<'a> Args<'a> {
    /// Build from a full command line's tokens; the keyword sits at index 0.
    fn new(tokens: &'a [&'a str]) -> Self {
        Self { tokens, pos: 1 }
    }

    /// The next unconsumed argument, if any.
    fn next(&mut self) -> Option<&'a str> {
        let t = self.tokens.get(self.pos)?;
        self.pos += 1;
        Some(*t)
    }

    /// The next argument; returns a parse error if the line ran out.
    ///
    /// `index` only labels a missing-argument error — access is sequential, so
    /// repeated calls keep returning successive tokens regardless of the index.
    fn require(&mut self, index: usize) -> Result<&'a str, ParseError> {
        let t = self
            .tokens
            .get(self.pos)
            .copied()
            .ok_or_else(|| ParseError::new(index, "expected another argument"))?;
        self.pos += 1;
        Ok(t)
    }
}

/// Parse a trailing optional named color; its absence is fine.
fn optional_color(args: &mut Args, line_no: usize) -> Result<Option<Color>, ParseError> {
    match args.next() {
        Some(t) => Color::parse(t)
            .map(Some)
            .ok_or_else(|| ParseError::new(line_no, "unknown color")),
        None => Ok(None),
    }
}

/// Parse one argument as an `i32`.
fn parse_i32(s: &str, line_no: usize) -> Result<i32, ParseError> {
    s.parse::<i32>()
        .map_err(|_| ParseError::new(line_no, "expected an integer"))
}

/// Parse one argument as a `u32`.
fn parse_u32(s: &str, line_no: usize) -> Result<u32, ParseError> {
    s.parse::<u32>()
        .map_err(|_| ParseError::new(line_no, "expected a positive integer"))
}

/// Strip the surrounding quotes from a text-command argument.
fn text_body(raw: &str, line_no: usize) -> Result<String<96>, ParseError> {
    let inner = raw.trim_matches('"');
    let mut s = String::<96>::new();
    s.push_str(inner)
        .map_err(|_| ParseError::new(line_no, "text too long"))?;
    Ok(s)
}

/// Parse a full command line into a [`Command`] (used to expand [`DEMO_SCRIPT`]).
fn parse_line(line: &str, line_no: usize) -> Result<Command, ParseError> {
    let tokens = split_line(line);
    let keyword = tokens
        .first()
        .copied()
        .ok_or_else(|| ParseError::new(line_no, "empty command"))?;
    let mut args = Args::new(&tokens);
    dispatch(keyword, &mut args, line_no)
}

/// Turn a keyword + arguments into a [`Command`].
///
/// This is the "pure" half of parsing (it mutates no script state) — [`Script`]
/// routes the stateful image commands (`img`/`put`/`place`) around it.
fn dispatch(keyword: &str, args: &mut Args, line_no: usize) -> Result<Command, ParseError> {
    match keyword {
        "clear" => Ok(Command::Clear(optional_color(args, line_no)?)),
        "fill" => Ok(Command::Fill(
            Color::parse(args.require(1)?)
                .ok_or_else(|| ParseError::new(line_no, "unknown color"))?,
        )),
        "stroke" => {
            let color = Color::parse(args.require(1)?)
                .ok_or_else(|| ParseError::new(line_no, "unknown color"))?;
            let width = parse_u32(args.require(1)?, line_no)?;
            Ok(Command::Stroke { color, width })
        }
        "rect" => {
            let x = parse_i32(args.require(1)?, line_no)?;
            let y = parse_i32(args.require(1)?, line_no)?;
            let width = parse_i32(args.require(1)?, line_no)?;
            let height = parse_i32(args.require(1)?, line_no)?;
            // Accepted and validated, but `Rect` has no color field, so the
            // shape renders with the current fill (see [`Renderer`]).
            optional_color(args, line_no)?;
            Ok(Command::Rect {
                x,
                y,
                width,
                height,
            })
        }
        "rect_o" => {
            let x = parse_i32(args.require(1)?, line_no)?;
            let y = parse_i32(args.require(1)?, line_no)?;
            let width = parse_i32(args.require(1)?, line_no)?;
            let height = parse_i32(args.require(1)?, line_no)?;
            let line = parse_u32(args.require(1)?, line_no)?;
            let color = optional_color(args, line_no)?;
            Ok(Command::RectOutline {
                x,
                y,
                width,
                height,
                line,
                color,
            })
        }
        "circ" => {
            let x = parse_i32(args.require(1)?, line_no)?;
            let y = parse_i32(args.require(1)?, line_no)?;
            let radius = parse_i32(args.require(1)?, line_no)?;
            optional_color(args, line_no)?;
            Ok(Command::Circ { x, y, radius })
        }
        "circ_o" => {
            let x = parse_i32(args.require(1)?, line_no)?;
            let y = parse_i32(args.require(1)?, line_no)?;
            let radius = parse_i32(args.require(1)?, line_no)?;
            let line = parse_u32(args.require(1)?, line_no)?;
            let color = optional_color(args, line_no)?;
            Ok(Command::CircOutline {
                x,
                y,
                radius,
                line,
                color,
            })
        }
        "line" => {
            let x1 = parse_i32(args.require(1)?, line_no)?;
            let y1 = parse_i32(args.require(1)?, line_no)?;
            let x2 = parse_i32(args.require(1)?, line_no)?;
            let y2 = parse_i32(args.require(1)?, line_no)?;
            let color = optional_color(args, line_no)?;
            Ok(Command::Line {
                x1,
                y1,
                x2,
                y2,
                color,
            })
        }
        "text" => {
            let x = parse_i32(args.require(1)?, line_no)?;
            let y = parse_i32(args.require(1)?, line_no)?;
            let s = text_body(args.require(1)?, line_no)?;
            Ok(Command::Text { x, y, s })
        }
        "text_c" => {
            let x = parse_i32(args.require(1)?, line_no)?;
            let y = parse_i32(args.require(1)?, line_no)?;
            let s = text_body(args.require(1)?, line_no)?;
            Ok(Command::TextCentered { x, y, s })
        }
        _ => Err(ParseError::new(line_no, "unknown command")),
    }
}

/// Executes [`Command`]s against a framebuffer, holding the current fill/stroke
/// state between commands — the same idea as picking a `PrimitiveStyle` before
/// each `draw` in regular `embedded_graphics` code.
pub struct Renderer<'a> {
    fb: &'a mut FrameBuffer,
    fill: Color,
    stroke: Color,
    line_width: u32,
}

impl<'a> Renderer<'a> {
    pub fn new(fb: &'a mut FrameBuffer) -> Self {
        Self {
            fb,
            fill: Color(Rgb565::WHITE),
            stroke: Color(Rgb565::WHITE),
            line_width: 1,
        }
    }

    fn exec(&mut self, command: &Command) -> Result<(), core::convert::Infallible> {
        match command {
            Command::Clear(color) => {
                let color: Option<Color> = *color;
                self.fb.clear(color.unwrap_or(Color(Rgb565::BLACK)).0).ok();
            }
            Command::Fill(color) => self.fill = *color,
            Command::Stroke { color, width } => {
                self.stroke = *color;
                self.line_width = *width;
            }
            Command::Rect {
                x,
                y,
                width,
                height,
            } => {
                Rectangle::new(Point::new(*x, *y), Size::new(*width as u32, *height as u32))
                    .into_styled(PrimitiveStyle::with_fill(self.fill.0))
                    .draw(self.fb)
                    .ok();
            }
            Command::RectOutline {
                x,
                y,
                width,
                height,
                line,
                color,
            } => {
                let color: Option<Color> = *color;
                let color = color.unwrap_or(self.stroke);
                Rectangle::new(Point::new(*x, *y), Size::new(*width as u32, *height as u32))
                    .into_styled(PrimitiveStyle::with_stroke(color.0, *line))
                    .draw(self.fb)
                    .ok();
            }
            Command::Circ { x, y, radius } => {
                let diameter = (*radius).max(0).saturating_mul(2).max(1) as u32;
                Circle::with_center(Point::new(*x, *y), diameter)
                    .into_styled(PrimitiveStyle::with_fill(self.fill.0))
                    .draw(self.fb)
                    .ok();
            }
            Command::CircOutline {
                x,
                y,
                radius,
                line,
                color,
            } => {
                let color: Option<Color> = *color;
                let color = color.unwrap_or(self.stroke);
                let diameter = (*radius).max(0).saturating_mul(2).max(1) as u32;
                Circle::with_center(Point::new(*x, *y), diameter)
                    .into_styled(PrimitiveStyle::with_stroke(color.0, *line))
                    .draw(self.fb)
                    .ok();
            }
            Command::Line {
                x1,
                y1,
                x2,
                y2,
                color,
            } => {
                let color: Option<Color> = *color;
                let color = color.unwrap_or(self.stroke);
                Line::new(Point::new(*x1, *y1), Point::new(*x2, *y2))
                    .into_styled(PrimitiveStyle::with_stroke(color.0, self.line_width))
                    .draw(self.fb)
                    .ok();
            }
            Command::Text { x, y, s } => {
                let style = MonoTextStyle::new(&FONT_8X13, self.fill.0);
                Text::new(s.as_str(), Point::new(*x, *y), style)
                    .draw(self.fb)
                    .ok();
            }
            Command::TextCentered { x, y, s } => {
                let style = MonoTextStyle::new(&FONT_8X13, self.fill.0);
                let text = Text::new(s.as_str(), Point::new(*x, *y), style);
                // Measure without drawing, then reposition so the glyphs are
                // centred on (x, y).
                let width = text.bounding_box().size.width;
                Text::new(s.as_str(), Point::new(*x - width as i32 / 2, *y), style)
                    .draw(self.fb)
                    .ok();
            }
            Command::Image(image) => {
                // Row-major, big-endian RGB565. `ImageRawBE` derives the height
                // from the data length given the width, and `EgImage::new`
                // positions the top-left corner at (x, y).
                let raw = ImageRawBE::<Rgb565>::new(image.data.as_slice(), image.width);
                EgImage::new(&raw, Point::new(image.x, image.y))
                    .draw(self.fb)
                    .ok();
            }
        }
        Ok(())
    }
}

/// The bundled vector demo. Send it line-by-line (each line prefixed with `>`)
/// and the panel animates into the full scene.
pub const DEMO_SCRIPT: &str = "\
clear navy
rect 16 16 328 44 white
rect 20 20 320 38 navy
circ 90 160 58 red
circ 90 160 42 white
circ 90 160 8 navy
line 175 160 300 110 white
line 175 160 300 210 white
text 32 150 \"ESP32-S3\"
text_c 180 250 \"wendy-lan demo\"
text_c 180 272 \"graphics over TLS\"
";
