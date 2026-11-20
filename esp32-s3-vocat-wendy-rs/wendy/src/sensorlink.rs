//! SensorLink frame reassembly.
//!
//! A SensorLink *frame* (one video / pixel picture) is carried as a run of
//! [`SensorData`](crate::proto::SensorData) chunks, ordered by `chunk_seq` from
//! 0. The chunk that ends a frame sets
//! [`sensorlink::FLAG_LAST_CHUNK`](crate::proto::sensorlink::FLAG_LAST_CHUNK).
//!
//! [`Reassembler`] consumes those chunks and writes the raw payload — for this
//! device, big-endian RGB565 pixels — into an injected [`SensorSink`]. The
//! payload of the first chunk begins with an 8-byte header, a big-endian
//! `width` (u32) followed by a big-endian `height` (u32), so the reassembler
//! knows how many pixels the frame holds before the payload is complete.
//!
//! The reassembler is generic over the [`SensorSink`] so the logic can be
//! unit-tested on the host (feeding a plain [`Vec`]) while the firmware feeds a
//! PSRAM-backed sink. It holds no large buffer of its own: every byte is written
//! straight into the sink.

use crate::proto::{SensorData, sensorlink};

/// The size of the frame header prepended to the first chunk's payload:
/// big-endian `width` (u32) + big-endian `height` (u32).
pub const FRAME_HEADER_SIZE: usize = 8;

/// Where a completed frame lands. The bytes live in the sink, keyed by
/// [`SensorSink::len`]; this only carries the dimensions and identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completed {
    pub channel_id: u32,
    pub frame_seq: u32,
    pub width: u32,
    pub height: u32,
}

/// Where assembled frame bytes are written.
///
/// The reassembler drives this trait: [`SensorSink::begin`] is called once per
/// frame (telling the sink how many pixels to expect), [`SensorSink::append`]
/// receives each chunk's bytes, and [`SensorSink::as_slice`] hands the finished
/// frame back.
pub trait SensorSink {
    /// Start a new frame of `pixel_count` pixels (`width * height`). The sink
    /// should be reset and sized to hold exactly `pixel_count * 2` bytes.
    fn begin(&mut self, pixel_count: usize);

    /// Append raw pixel bytes. Bytes beyond the frame's capacity are ignored,
    /// so a corrupt over-long stream cannot overflow the sink.
    fn append(&mut self, data: &[u8]);

    /// The assembled bytes so far (up to `width * height * 2`).
    fn len(&self) -> usize;

    /// A slice over the assembled bytes.
    fn as_slice(&self) -> &[u8];
}

/// A reassembler that writes into a single injected sink.
///
/// Only one channel is tracked at a time: a `chunk_seq == 0` on a different
/// channel starts a fresh frame. While a frame is still in progress, further
/// chunks that do not continue it are dropped.
pub struct Reassembler<S: SensorSink> {
    active: bool,
    /// Whether a frame has completed since the last
    /// [`Reassembler::take_frame_ready`] call. Distinct from
    /// [`Reassembler::is_active`]: a frame can be *complete* (its last chunk
    /// arrived) while still awaiting the renderer.
    frame_ready: bool,
    channel_id: u32,
    frame_seq: u32,
    expected_chunk: u32,
    width: u32,
    height: u32,
    sink: S,
    /// Byte-length of the image last handed to the renderer. Lets the caller
    /// log/diff only when the held image *changes*, since the render loop
    /// redraws the same frame every 30 ms while it is held on screen.
    last_drawn: usize,
    /// Byte-length of the frame once its last chunk has arrived, held until the
    /// next frame's `begin` resets it to 0. Lets the renderer tell a *complete*
    /// frame (safe to decode/draw) apart from a *partial* one still being
    /// assembled -- decoding mid-stream wastes a full decode + buffer alloc per
    /// chunk and would render a half-built image.
    complete_len: usize,
}

impl<S: SensorSink> Reassembler<S> {
    /// A reassembler writing into `sink`, with no frame in progress.
    pub const fn new(sink: S) -> Self {
        Self {
            active: false,
            frame_ready: false,
            channel_id: 0,
            frame_seq: 0,
            expected_chunk: 0,
            width: 0,
            height: 0,
            sink,
            last_drawn: 0,
            complete_len: 0,
        }
    }

    /// Whether a frame is currently being assembled.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Whether a frame has completed since the last [`Reassembler::take_frame_ready`]
    /// call. The renderer polls this once per frame and draws the assembled
    /// bytes from [`Reassembler::sink`] when it is `true`.
    pub fn is_frame_ready(&self) -> bool {
        self.frame_ready
    }

    /// Consume the "frame ready" flag, returning its previous value. Call this
    /// after rendering so an in-progress frame is not redrawn.
    pub fn take_frame_ready(&mut self) -> bool {
        let ready = self.frame_ready;
        self.frame_ready = false;
        ready
    }

    /// Byte-length of the image last handed to the renderer. Lets the caller
    /// log only when the held image actually changes.
    pub fn last_drawn(&self) -> usize {
        self.last_drawn
    }

    /// Record the byte-length of the image just handed to the renderer.
    pub fn set_last_drawn(&mut self, n: usize) {
        self.last_drawn = n;
    }

    /// Byte-length of the frame once its last chunk has arrived, or 0 while no
    /// frame has completed (or a fresh frame has begun and is still partial).
    /// The renderer decodes/draws only when the sink length equals this, i.e.
    /// the frame is complete rather than a partial stream still being fed.
    pub fn complete_len(&self) -> usize {
        self.complete_len
    }

    /// The frame's width in pixels (only meaningful once a frame has started).
    pub fn width(&self) -> u32 {
        self.width
    }

    /// The frame's height in pixels (only meaningful once a frame has started).
    pub fn height(&self) -> u32 {
        self.height
    }

    /// The assembled bytes (only meaningful once a frame has completed).
    pub fn sink(&self) -> &S {
        &self.sink
    }

    /// Feed one chunk. Returns the [`Completed`] descriptor once the frame's
    /// last chunk has arrived, or `None` while more chunks are expected (or when
    /// a chunk is dropped as out of order / belonging to another stream).
    pub fn feed(&mut self, cd: &SensorData) -> Option<Completed> {
        // An empty chunk carries no bytes and cannot contribute to a frame, so
        // it is malformed: abort any in-progress frame and report nothing. The
        // next `chunk_seq == 0` then starts a fresh one.
        if cd.payload.is_empty() {
            self.active = false;
            return None;
        }
        if !self.active {
            // Start of a frame: the first chunk must be `chunk_seq == 0`.
            if cd.chunk_seq != 0 {
                return None;
            }
            self.channel_id = cd.channel_id;
            self.frame_seq = cd.frame_seq;
            self.expected_chunk = 0;
            self.active = true;
            // A fresh frame supersedes the previous one. A new frame starts
            // partial, so clear the "complete length" recorded for the old frame.
            self.frame_ready = false;
            self.complete_len = 0;
        } else if cd.channel_id != self.channel_id || cd.frame_seq != self.frame_seq {
            // A different stream: only a fresh `chunk_seq == 0` can start it.
            if cd.chunk_seq != 0 {
                return None;
            }
            self.channel_id = cd.channel_id;
            self.frame_seq = cd.frame_seq;
            self.expected_chunk = 0;
            self.frame_ready = false;
            self.complete_len = 0;
        } else if cd.chunk_seq != self.expected_chunk {
            // Gap or out-of-order chunk: drop it.
            return None;
        }

        let payload = &cd.payload;

        if self.expected_chunk == 0 {
            // First chunk: read the width/height header, then size the sink.
            if payload.len() < FRAME_HEADER_SIZE {
                return None;
            }
            let width = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            let height = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
            if width == 0 || height == 0 {
                return None;
            }
            self.width = width;
            self.height = height;
            self.sink
                .begin((width as usize).saturating_mul(height as usize));
            self.sink.append(&payload[FRAME_HEADER_SIZE..]);
        } else {
            self.sink.append(payload);
        }
        self.expected_chunk = self.expected_chunk.saturating_add(1);

        if cd.flags & sensorlink::FLAG_LAST_CHUNK != 0 {
            let completed = Completed {
                channel_id: self.channel_id,
                frame_seq: self.frame_seq,
                width: self.width,
                height: self.height,
            };
            // The sink keeps its bytes until the caller clones them out and the
            // next frame's `begin` resets it. Mark the frame ready for the
            // renderer before leaving the lock, and record the assembled
            // byte-count so the renderer knows the frame is complete (not a
            // partial stream still being assembled).
            self.complete_len = self.sink.len();
            self.active = false;
            self.frame_ready = true;
            return Some(completed);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::SENSOR_PAYLOAD_CAP;
    use heapless::Vec;

    /// A sink over a growable Vec, sized to exactly `pixel_count * 2` on
    /// `begin` and ignoring any overflow.
    struct VecSink {
        data: Vec<u8, 131072>,
    }

    impl VecSink {
        fn new() -> Self {
            Self { data: Vec::new() }
        }
    }

    impl SensorSink for VecSink {
        fn begin(&mut self, _pixel_count: usize) {
            self.data.clear();
        }
        fn append(&mut self, data: &[u8]) {
            for &b in data {
                if self.data.len() < 131072 {
                    self.data.push(b).ok();
                }
            }
        }
        fn len(&self) -> usize {
            self.data.len()
        }
        fn as_slice(&self) -> &[u8] {
            &self.data
        }
    }

    fn sensor_data(
        channel_id: u32,
        frame_seq: u32,
        chunk_seq: u32,
        flags: u32,
        payload: &[u8],
    ) -> SensorData {
        let mut cd = SensorData::default();
        cd.channel_id = channel_id;
        cd.frame_seq = frame_seq;
        cd.chunk_seq = chunk_seq;
        cd.flags = flags;
        cd.payload = Vec::from_slice(payload).expect("payload fits");
        cd
    }

    /// Build a full 2×2 frame (4 pixels = 8 bytes) split into three chunks:
    /// chunk 0 carries the 8-byte header + first 2 bytes, chunk 1 the next 2,
    /// chunk 2 the last 4 (marked last).
    fn frame_chunks() -> ((SensorData, SensorData, SensorData), Vec<u8, 8>) {
        let pixels: Vec<u8, 8> = Vec::from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
            .expect("8 pixels fit");
        let header = [0u8, 0, 0, 2, 0, 0, 0, 2]; // width=2, height=2
        let c0 = sensor_data(0, 7, 0, sensorlink::FLAG_KEYFRAME, &{
            let mut v: Vec<u8, 32> = Vec::new();
            v.extend_from_slice(&header).ok();
            v.extend_from_slice(&pixels[..2]).ok();
            v
        });
        let c1 = sensor_data(0, 7, 1, 0, &pixels[2..4]);
        let c2 = sensor_data(0, 7, 2, sensorlink::FLAG_LAST_CHUNK, &pixels[4..8]);
        ((c0, c1, c2), pixels)
    }

    #[test]
    fn reassembles_a_multi_chunk_frame() {
        let mut r: Reassembler<VecSink> = Reassembler::new(VecSink::new());
        let (chunks, expected) = frame_chunks();
        assert!(r.feed(&chunks.0).is_none()); // header + 2 bytes
        assert!(r.feed(&chunks.1).is_none());
        let completed = r.feed(&chunks.2).expect("last chunk completes");
        assert_eq!(
            completed,
            Completed {
                channel_id: 0,
                frame_seq: 7,
                width: 2,
                height: 2
            }
        );
        assert_eq!(r.sink().as_slice(), expected.as_slice());
    }

    #[test]
    fn drops_out_of_order_chunks() {
        let mut r: Reassembler<VecSink> = Reassembler::new(VecSink::new());
        let (chunks, _) = frame_chunks();
        // Feed chunk 1 before chunk 0: must be dropped.
        assert!(r.feed(&chunks.1).is_none());
        // Now the real sequence completes cleanly.
        assert!(r.feed(&chunks.0).is_none());
        assert!(r.feed(&chunks.1).is_none());
        assert!(r.feed(&chunks.2).is_some());
    }

    #[test]
    fn starts_a_new_frame_on_a_new_stream() {
        let mut r: Reassembler<VecSink> = Reassembler::new(VecSink::new());
        let (chunks, _) = frame_chunks();
        // Complete the first (channel 0) frame by feeding its chunks in order.
        assert!(r.feed(&chunks.0).is_none()); // header + 2 bytes
        assert!(r.feed(&chunks.1).is_none());
        let completed = r.feed(&chunks.2).expect("first frame completes");
        assert_eq!(
            completed,
            Completed {
                channel_id: 0,
                frame_seq: 7,
                width: 2,
                height: 2
            }
        );

        // A 1×1 frame on channel 1 starts from chunk 0, but its terminating
        // chunk has an empty payload, which is rejected as malformed.
        let header = [0u8, 0, 0, 1, 0, 0, 0, 1]; // width=1, height=1
        let mut c0 = sensor_data(1, 0, 0, sensorlink::FLAG_KEYFRAME, &[]);
        let mut v: Vec<u8, SENSOR_PAYLOAD_CAP> = Vec::new();
        v.extend_from_slice(&header).ok();
        v.extend_from_slice(&[0xAA]).ok();
        c0.payload = v;
        assert!(r.feed(&c0).is_none()); // header + 1 byte
        let c1 = sensor_data(1, 0, 1, sensorlink::FLAG_LAST_CHUNK, &[]);
        assert!(r.feed(&c1).is_none()); // empty payload is malformed
    }
}
