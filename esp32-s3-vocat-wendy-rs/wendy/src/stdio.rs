//! Captured device stdout: a bounded ring buffer that application output
//! writes into and which the console task drains while the host is attached.
//!
//! This is the capture half of the Wendy console stream. Producer and consumer
//! semantics:
//!
//! * [`put_stdout`] is the producer — any task may call it (app logging, the
//!   console task's own messages). It returns the bytes actually accepted;
//!   fewer than requested means the buffer overflowed and data was lost.
//! * [`read_stdout`] is the single consumer — the console task calls it to
//!   obtain the next chunk to stream as a `WendyConsoleData` event. It
//!   reports a `gap` when output was dropped before this read.
//!
//! The buffer is guarded by a critical section, so several producer tasks are
//! safe while one consumer drains it (MPSC). The [`Ring`] type itself is pure
//! and host-tested; the firmware owns the process-wide static that wraps it.

/// Ring capacity in bytes. One slot is held back so `len` can distinguish an
/// empty ring from a full one without a separate count.
pub const STDOUT_CAP: usize = 4096;

/// Maximum bytes [`read_stdout`] returns per call, matching the width of
/// `WendyConsoleData.data`.
pub const READ_CHUNK: usize = 256;

/// A bounded, wrapping ring buffer.
///
/// `head` is where the next byte is written, `tail` where the next is read.
/// Indexing is `pos & ...` is unnecessary here because the capacity is not
/// required to be a power of two; modulo keeps it simple and correct.
pub struct Ring {
    head: usize,
    tail: usize,
    /// Set when [`Ring::write`] could not fit all supplied bytes. Cleared by
    /// [`Ring::read`]; the value it held on the next read is the `gap`.
    overflow: bool,
    buf: [u8; STDOUT_CAP],
}

// A manual `Debug` (rather than `#[derive(Debug)]`) because `[u8; STDOUT_CAP]`
// (4096) is not `Debug`. We only ever want to inspect the bookkeeping fields,
// not dump the whole ring. The firmware never needs `Default` here — the
// process-wide static is built via `Mutex::new(Ring::new())`.
impl core::fmt::Debug for Ring {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ring")
            .field("head", &self.head)
            .field("tail", &self.tail)
            .field("len", &self.len())
            .field("overflow", &self.overflow)
            .finish()
    }
}

impl Ring {
    /// A fresh, empty ring.
    pub const fn new() -> Self {
        Ring {
            head: 0,
            tail: 0,
            overflow: false,
            buf: [0u8; STDOUT_CAP],
        }
    }

    /// Number of bytes currently buffered.
    #[inline]
    pub fn len(&self) -> usize {
        (self.head + STDOUT_CAP - self.tail) % STDOUT_CAP
    }

    /// Whether the ring holds no bytes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Append `data`; return how many bytes were accepted.
    ///
    /// If the ring cannot hold all of `data`, the accepted prefix is stored and
    /// [`overflow`] is set so the next [`Ring::read`] reports a `gap`.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let mut n = 0usize;
        for &b in data {
            if self.len() >= STDOUT_CAP - 1 {
                self.overflow = true;
                break;
            }
            self.buf[self.head] = b;
            self.head = (self.head + 1) % STDOUT_CAP;
            n += 1;
        }
        n
    }

    /// Read up to `buf.len()` buffered bytes into `buf`, return the count.
    ///
    /// Clears the overflow flag; the value it held is the `gap` the caller
    /// should report for this chunk.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        self.overflow = false;
        let mut n = 0usize;
        while n < buf.len() && self.len() > 0 {
            buf[n] = self.buf[self.tail];
            self.tail = (self.tail + 1) % STDOUT_CAP;
            n += 1;
        }
        n
    }

    /// Whether output was dropped since the last successful write.
    #[inline]
    pub fn overflow(&self) -> bool {
        self.overflow
    }
}

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;

/// The process-wide captured stdout buffer. Only ever touched through
/// [`put_stdout`] and [`read_stdout`], so a critical section is enough to
/// serialise its multiple producers and single consumer.
///
/// We use the async [`Mutex`] with its non-blocking [`Mutex::try_lock`] rather
/// than the closure-based blocking mutex: `try_lock` hands back a
/// `MutexGuard` whose `DerefMut` yields a genuine `&mut Ring`, sidestepping the
/// `&T -> &mut T` cast (which is UB) while remaining callable from any task or
/// interrupt context (the lock flag is guarded by the critical section).
static STDOUT: Mutex<CriticalSectionRawMutex, Ring> = Mutex::new(Ring::new());

/// Append device stdout to the process-wide buffer.
///
/// Safe to call from any task. Returns the number of bytes actually accepted;
/// a smaller count means the buffer overflowed and the next [`read_stdout`]
/// reports a `gap`. Returns 0 if the buffer was briefly locked (data dropped).
pub fn put_stdout(data: &[u8]) -> usize {
    match STDOUT.try_lock() {
        Ok(mut guard) => guard.write(data),
        Err(_) => 0,
    }
}

/// Read the next chunk of captured stdout.
///
/// On return `*gap` is true if output was dropped before this read. Returns the
/// number of bytes read (0 when the buffer is empty or briefly locked).
/// Non-blocking.
pub fn read_stdout(buf: &mut [u8], gap: &mut bool) -> usize {
    match STDOUT.try_lock() {
        Ok(mut guard) => {
            *gap = guard.overflow();
            guard.read(buf)
        }
        Err(_) => {
            *gap = false;
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_ring_reads_nothing() {
        let mut r = Ring::new();
        let mut buf = [0u8; 8];
        assert_eq!(r.len(), 0);
        assert_eq!(r.read(&mut buf), 0);
    }

    #[test]
    fn write_then_read_roundtrips() {
        let mut r = Ring::new();
        assert_eq!(r.write(b"hello"), 5);
        let mut buf = [0u8; 8];
        let n = r.read(&mut buf);
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn partial_read_leaves_rest() {
        let mut r = Ring::new();
        r.write(b"abcdef");
        let mut buf = [0u8; 4];
        let n = r.read(&mut buf);
        assert_eq!(n, 4);
        assert_eq!(&buf[..4], b"abcd");
        let mut buf2 = [0u8; 8];
        let n2 = r.read(&mut buf2);
        assert_eq!(n2, 2);
        assert_eq!(&buf2[..2], b"ef");
    }

    #[test]
    fn wrapping_roundtrip() {
        let mut r = Ring::new();
        // Fill well past the capacity so head wraps multiple times.
        let payload = vec![7u8; STDOUT_CAP + 10];
        assert_eq!(r.write(&payload), STDOUT_CAP - 1);
        // Overflow flag is set because not all bytes fit.
        assert!(r.overflow());
        let mut buf = [0u8; READ_CHUNK];
        // Capture the gap before read (read clears the overflow flag).
        let gap = r.overflow();
        let n = r.read(&mut buf);
        // The tail still holds the oldest bytes; a gap is reported.
        assert!(gap);
        assert_eq!(n, READ_CHUNK);
        assert_eq!(buf[..n], vec![7u8; READ_CHUNK][..]);
    }

    #[test]
    fn overflow_sets_gap_only_until_next_read() {
        let mut r = Ring::new();
        // Fill to the brim (leave the one reserved slot): exact fill, no loss.
        let fill = STDOUT_CAP - 1;
        let mut big = vec![0u8; fill];
        for (i, b) in big.iter_mut().enumerate() {
            *b = (i & 0xff) as u8;
        }
        assert_eq!(r.write(&big), fill);
        assert!(!r.overflow());

        // A read right after an exact fill reports no gap.
        let mut buf = [0u8; 10];
        let gap = r.overflow();
        let n = r.read(&mut buf);
        assert_eq!(n, 10);
        assert!(!gap); // filled exactly, no loss

        // Write more than the 10 bytes still free: 10 are accepted, the rest
        // are dropped and overflow is set.
        let accepted = r.write(&[
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        ]);
        assert_eq!(accepted, 10); // 10 fit, 2 dropped
        assert!(r.overflow());

        // The read immediately after the overflow reports the gap, and returns
        // the oldest bytes first (FIFO): the still-buffered tail of `big`.
        let mut buf2 = [0u8; 16];
        let gap2 = r.overflow();
        let n2 = r.read(&mut buf2);
        assert!(gap2);
        assert_eq!(n2, 16);
        assert_eq!(buf2[0], big[10]);
        assert_eq!(buf2[15], big[25]);

        // A second read, with no new overflow, reports no gap: the flag is
        // cleared by the read, so it only ever signals the *previous* loss.
        let mut buf3 = [0u8; 4];
        let gap3 = r.overflow();
        let _n3 = r.read(&mut buf3);
        assert!(!gap3);
    }
}
