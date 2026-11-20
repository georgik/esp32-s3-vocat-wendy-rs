//! Wendy Lite stdin ring buffer — pure-Rust `no_std` port of the critical half
//! of `wendy-lite`'s `wendy_stdio` component (`components/wendy_stdio/src/wendy_stdio.c`).
//!
//! This is the smallest, highest-value piece of the `wendy_core` port: a 128-byte
//! ring buffer that the host channel feeds and which the app reads like `stdin`.
//!
//! ## Single-producer / single-consumer
//!
//! This buffer has exactly one producer (the USB console task) and one
//! consumer (the message task), so it uses the simple SPSC protocol: the
//! writes into the claimed slots and *publishes* by advancing `in` with a
//! release store; the consumer reads up to the latest `in` and advances `out`.
//! The release/acquire pairing on the counters provides the happens-before that
//! makes the published bytes visible — no per-byte flags needed.
//!
//! `BUF` is a `static mut` accessed only through the two accessor helpers below.
//! That is sound here because there is a single writer and a single reader and
//! the counter ordering serialises access; the `unsafe` is localised to this
//! module. If a second producer is ever added, upgrade this to a
//! multi-producer flag protocol.

use core::cmp::min;
use core::sync::atomic::{AtomicUsize, Ordering};

/// stdin buffer depth. Must be a power of two (index = counter & (N - 1)).
///
/// This must comfortably hold a single `lan.rs` receive (`RX_BUF = 2048`) worth
/// of frames, because the LAN task pumps those frames back-to-back into the
/// ring before `message_task` gets to consume them. A buffer this small that the
/// trailing `\n` of one frame is overwritten by the next frame's bytes before
/// `message_task` sees it would merge consecutive `>` command lines into one
/// over-long line — e.g. `>put …>put …` — whose embedded `>` then fails base64
/// decode. 4 KiB (two full receives) leaves plenty of margin.
pub const STDIN_BUF_SIZE: usize = 4096;

/// The bytes, one per slot. Written by the producer, read by the consumer.
static mut BUF: [u8; STDIN_BUF_SIZE] = [0u8; STDIN_BUF_SIZE];
/// Producers' publish counter.
static IN: AtomicUsize = AtomicUsize::new(0);
/// Consumer counter.
static OUT: AtomicUsize = AtomicUsize::new(0);

/// Inject host bytes into the ring buffer.
///
/// Safe to call from the single producer task. Bytes that do not fit are
/// dropped. Returns the number of bytes actually accepted.
pub fn put_stdin_data(data: &[u8]) -> usize {
    let in_c = IN.load(Ordering::Relaxed);
    let out_c = OUT.load(Ordering::Relaxed);
    // Free slots before the buffer wraps: fill level is `in - out`.
    let free = STDIN_BUF_SIZE - (in_c - out_c);
    let n = min(data.len(), free);
    if n == 0 {
        return 0;
    }
    // Write into the claimed slots, then publish below.
    for i in 0..n {
        unsafe {
            BUF[(in_c + i) & (STDIN_BUF_SIZE - 1)] = data[i];
        }
    }
    // Publish: the release makes the writes above visible to the consumer that
    // subsequently loads a greater `in`.
    IN.store(in_c + n, Ordering::Release);
    n
}

/// Read up to `buf.len()` bytes from the ring buffer.
///
/// Returns 0 when empty (non-blocking, matching the C `O_NONBLOCK` stdin
/// semantics). The consumer only reads slots the producer has already published
/// (`< in`), so it never sees a half-written slot.
pub fn read_stdin(buf: &mut [u8]) -> usize {
    let in_c = IN.load(Ordering::Acquire);
    let out_c = OUT.load(Ordering::Relaxed);
    if in_c == out_c {
        return 0;
    }
    // Read only what has been published, capped at the caller's buffer.
    let available = in_c - out_c;
    let n = min(available, buf.len());
    for i in 0..n {
        buf[i] = unsafe { BUF[(out_c + i) & (STDIN_BUF_SIZE - 1)] };
    }
    // Advance `out` only after the reads above have completed.
    OUT.store(out_c + n, Ordering::Release);
    n
}
