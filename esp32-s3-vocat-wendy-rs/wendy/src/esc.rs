//! DLE-ESC (`0x10`) de-framing for the Wendy link.
//!
//! The raw USB-Serial/JTAG byte stream escapes the ESC byte `0x10`. This state
//! machine consumes one byte at a time and returns the next logical item: a
//! de-ESCaed data byte (for the frame parser), a link command, or a
//! keep-alive.
//!
//! Timing/timeout concerns (`last_rx_us`, the 12 s idle close) are a
//! link-layer concern and are handled where the pipeline is wired into the
//! USB task, not here — this module is pure and unit-testable.

/// ESC (Data Link Escape) byte.
pub const WENDY_UART_ESC: u8 = 0x10;

/// `0x10 'c'` — console attach command.
pub const ESC_CMD_CONSOLE: u8 = b'c';
/// `0x10 'e'` — echo command.
pub const ESC_CMD_ECHO: u8 = b'e';
/// `0x10 'k'` — keep-alive.
pub const ESC_CMD_KEEP_ALIVE: u8 = b'k';
/// `0x10 'm'` — com (open the full Wendy link).
pub const ESC_CMD_COM: u8 = b'm';
/// `0x10 'o'` — off (close the link).
pub const ESC_CMD_OFF: u8 = b'o';
/// `0x10 '_'` — literal `0x10` passthrough in the data stream.
pub const ESC_CMD_ESC: u8 = b'_';

/// One logical item produced by [`EscDecoder::feed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EscItem {
    /// A de-ESCaed data byte destined for the frame parser.
    Data(u8),
    /// A link command byte (`c`/`e`/`m`/`o`). `_` is normalised to
    /// [`EscItem::Data`] carrying the literal `0x10` byte.
    Cmd(u8),
    /// A keep-alive (`0x10 'k'`).
    KeepAlive,
}

/// Byte-at-a-time DLE-ESC de-framer.
#[derive(Default)]
pub struct EscDecoder {
    pending_esc: bool,
    keepalive_seen: bool,
    last_esc_cmd: u8,
}

impl EscDecoder {
    /// Create a fresh decoder.
    pub fn new() -> Self {
        Self {
            pending_esc: false,
            keepalive_seen: false,
            last_esc_cmd: 0,
        }
    }

    /// Feed one raw byte.
    ///
    /// Returns `None` while the just-received byte was only recording an ESC
    /// (the follow-up byte produces the [`EscItem`]). Returns the decoded item
    /// otherwise. An unknown escape sequence (`0x10 X` where `X` is not a
    /// recognised command) drops the byte.
    pub fn feed(&mut self, byte: u8) -> Option<EscItem> {
        if byte == WENDY_UART_ESC {
            // A run of `0x10` bytes only re-arms pending_esc and emits
            // nothing (a bare ESC is not a complete item).
            self.pending_esc = true;
            return None;
        }
        if self.pending_esc {
            self.pending_esc = false;
            match byte {
                ESC_CMD_ESC => Some(EscItem::Data(WENDY_UART_ESC)),
                ESC_CMD_KEEP_ALIVE => {
                    self.keepalive_seen = true;
                    Some(EscItem::KeepAlive)
                }
                ESC_CMD_CONSOLE | ESC_CMD_ECHO | ESC_CMD_COM | ESC_CMD_OFF => {
                    self.last_esc_cmd = byte;
                    Some(EscItem::Cmd(byte))
                }
                _ => None,
            }
        } else {
            Some(EscItem::Data(byte))
        }
    }

    /// Whether a keep-alive has been seen on this link.
    pub fn keepalive_seen(&self) -> bool {
        self.keepalive_seen
    }

    /// The most recent link command byte (`0` if none).
    pub fn last_esc_cmd(&self) -> u8 {
        self.last_esc_cmd
    }

    /// Clear the recorded command (call after the link layer has acted on it).
    pub fn reset_last_cmd(&mut self) {
        self.last_esc_cmd = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn decode(bytes: &[u8]) -> Vec<EscItem> {
        let mut d = EscDecoder::new();
        let mut out = Vec::new();
        for &b in bytes {
            if let Some(item) = d.feed(b) {
                out.push(item);
            }
        }
        out
    }

    #[test]
    fn plain_data_passes_through() {
        let items = decode(b"hello");
        assert_eq!(
            items,
            vec![
                EscItem::Data(b'h'),
                EscItem::Data(b'e'),
                EscItem::Data(b'l'),
                EscItem::Data(b'l'),
                EscItem::Data(b'o'),
            ]
        );
    }

    #[test]
    fn esc_underscore_is_literal_esc() {
        // 0x10 '_'  ->  one Data(0x10)
        let items = decode(&[WENDY_UART_ESC, ESC_CMD_ESC]);
        assert_eq!(items, vec![EscItem::Data(WENDY_UART_ESC)]);
    }

    #[test]
    fn esc_commands_are_reported_not_emitted() {
        let mut d = EscDecoder::new();
        assert_eq!(d.feed(WENDY_UART_ESC), None);
        assert_eq!(d.feed(ESC_CMD_CONSOLE), Some(EscItem::Cmd(ESC_CMD_CONSOLE)));
        assert_eq!(d.last_esc_cmd, ESC_CMD_CONSOLE);
        assert_eq!(d.feed(WENDY_UART_ESC), None);
        assert_eq!(d.feed(ESC_CMD_COM), Some(EscItem::Cmd(ESC_CMD_COM)));
        assert_eq!(d.last_esc_cmd, ESC_CMD_COM);
        d.reset_last_cmd();
        assert_eq!(d.last_esc_cmd, 0);
    }

    #[test]
    fn keepalive_sets_flag() {
        let mut d = EscDecoder::new();
        assert!(!d.keepalive_seen());
        assert_eq!(d.feed(WENDY_UART_ESC), None);
        assert_eq!(d.feed(ESC_CMD_KEEP_ALIVE), Some(EscItem::KeepAlive));
        assert!(d.keepalive_seen());
    }

    #[test]
    fn double_esc_just_arms_then_arms_again() {
        // Two 0x10 in a row: both only re-arm pending_esc, nothing emitted.
        let mut d = EscDecoder::new();
        assert_eq!(d.feed(WENDY_UART_ESC), None);
        assert_eq!(d.feed(WENDY_UART_ESC), None);
        // Now a real data byte is consumed as an escape target and dropped
        // (not a recognised command), so still nothing.
        assert_eq!(d.feed(b'x'), None);
        assert_eq!(d.pending_esc, false);
    }

    #[test]
    fn interleaved_data_and_esc() {
        // 'A' 0x10 '_' 'B'  ->  Data(A), Data(0x10), Data(B)
        // `0x10 '_'` is the escape that yields a literal 0x10 byte; the
        // trailing `B` is plain data (not preceded by an ESC). Note that a
        // `0x10 X` where `X` is an unrecognised command is dropped, so the
        // input here must not ESC-escape the final `B`.
        let mut d = EscDecoder::new();
        let mut out = Vec::new();
        for &b in b"A\x10_B" {
            if let Some(i) = d.feed(b) {
                out.push(i);
            }
        }
        assert_eq!(
            out,
            vec![
                EscItem::Data(b'A'),
                EscItem::Data(WENDY_UART_ESC),
                EscItem::Data(b'B'),
            ]
        );
        assert_eq!(out[0], EscItem::Data(b'A'));
        assert_eq!(out[1], EscItem::Data(WENDY_UART_ESC));
        assert_eq!(out[2], EscItem::Data(b'B'));
    }
}
