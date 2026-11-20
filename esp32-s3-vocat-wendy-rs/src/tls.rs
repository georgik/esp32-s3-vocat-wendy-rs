//! TLS server credentials for the LAN Wendy link.
//!
//! The LAN link uses a **self-signed, server-auth-only** TLS connection
//! (allowed while the device is unenrolled). These are the credentials and
//! session configuration the device presents: a self-signed ECDSA (P-256)
//! certificate and its matching private key, embedded at compile time, plus a
//! [`ServerSessionConfig`] using `AuthMode::None` (no client certificate
//! requested).
//!
//! The transport-agnostic Wendy framing lives in [`crate::lan`]; this module
//! only supplies the material that a [`mbedtls_rs::Session`] needs to negotiate
//! the server half of the handshake.
//!
//! ## Why the prebuilt `mbedtls-rs` libraries
//!
//! [`mbedtls_rs`] is a `no_std` TLS wrapper around MbedTLS 3.x. We reuse its
//! committed prebuilt `xtensa-esp32s3` libraries and bindings (full `tls`
//! bundle, `DEFAULT_HOOKS`). Those hooks fall back to MbedTLS's *software*
//! implementations whenever no hardware accelerator is hooked, so no
//! `esp_hal` accelerator (`EspAccel`) wiring is required — just the entropy
//! source (see [`crate::tls::install_rng`]) and the embedded key/cert.

use mbedtls_rs::{Certificate, Credentials, PrivateKey, ServerSessionConfig, SessionConfig, X509};

/// The self-signed X.509 certificate (DER) embedded from `tls-cert/cert.der`.
const CERT_DER: &[u8] = include_bytes!("tls-cert/cert.der");
/// The matching EC private key (DER) embedded from `tls-cert/key.der`.
const KEY_DER: &[u8] = include_bytes!("tls-cert/key.der");

/// Builds the MbedTLS server session configuration used for every accepted LAN
/// connection.
///
/// The cert/key are parsed (copied) into MbedTLS's own contexts on each call,
/// so the returned configuration is self-contained and `'static`; the source
/// DER bytes are only needed at parse time and live in flash via `include_bytes!`.
///
/// Authentication is `AuthMode::None` (the default of
/// [`ServerSessionConfig::new`]): the server presents its certificate and no
/// client certificate is requested. This server-auth-only policy is what the
/// host tool `litemsg` expects when connecting to an unenrolled device.
pub fn server_conf() -> SessionConfig<'static> {
    let certificate = Certificate::new(X509::DER(CERT_DER))
        .expect("failed to parse the embedded self-signed server certificate");
    let private_key = PrivateKey::new(X509::DER(KEY_DER), None)
        .expect("failed to parse the embedded server private key");

    SessionConfig::Server(ServerSessionConfig::new(Credentials {
        certificate,
        private_key,
    }))
}
