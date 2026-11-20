//! Pure-Rust, `no_std` implementation of the Wendy **link framing** layer
//! that makes an ESP32 board discoverable and controllable by `wendy run` over
//! USB-Serial/JTAG.
//!
//! This crate is intentionally free of any `esp-hal` dependency so the framing
//! and (later) protobuf logic can be unit-tested on the host. It depends on
//! `heapless` and, for the captured-stdout ring, `embassy-sync`'s critical-section
//! mutex.
//!
//! Pipeline: raw USB bytes → [`esc`] (DLE-ESC de-framing) → [`frame`]
//! (8-byte header + body assembly) → [`proto`] (protobuf decode) →
//! command dispatch.
//!
//! Pure code targets `core`/`alloc` only (via `heapless`), never `std`, so it
//! links into the `no_std` firmware. The crate root is `no_std` for every build
//! *except* host tests: under `cfg(test)` the crate is compiled against `std`,
//! which is what lets its (and dependents') `libtest` suites run on the host.
//! The firmware build never sets `cfg(test)`, so it always sees the `no_std`
//! variant.
//!
//! Because the payload logic is free of `esp-hal`, host unit tests live in the
//! crate's own `#[cfg(test)]` modules (run with `cargo test -p wendy`) as
//! well as against real wire traffic on the target.
#![cfg_attr(not(test), no_std)]

#[cfg(test)]
extern crate alloc;

pub mod dispatch;
pub mod esc;
pub mod frame;
pub mod proto;
pub mod sensorlink;
pub mod stdio;
