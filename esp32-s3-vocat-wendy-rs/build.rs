use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rustc-link-arg=-Tlinkall.x");

    // The LAN Wendy link presents a self-signed cert over anonymous (unenrolled)
    // TLS. The host does not verify it, so the pair is ephemeral: generate a fresh
    // one on first build if it is missing. Generated files live in
    // `src/tls-cert/`, which is gitignored (see repo `.gitignore`).
    ensure_tls_certs();

    // Check if xtensa-esp32s3-elf-gcc is already in PATH
    if Command::new("xtensa-esp32s3-elf-gcc")
        .arg("--version")
        .output()
        .is_err()
    {
        // Toolchain not found in PATH, try to load from export-esp.sh
        setup_xtensa_environment();
    }
}

fn setup_xtensa_environment() {
    let home_dir = env::var("HOME")
        .unwrap_or_else(|_| env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string()));

    let export_script = PathBuf::from(&home_dir).join("export-esp.sh");

    if !export_script.exists() {
        eprintln!(
            "Warning: {} not found. Please ensure Xtensa toolchain is in PATH.",
            export_script.display()
        );
        return;
    }

    // Parse the export script to extract environment variables
    if let Ok(content) = std::fs::read_to_string(&export_script) {
        for line in content.lines() {
            let line = line.trim();

            // Handle LIBCLANG_PATH
            if line.starts_with("export LIBCLANG_PATH=") {
                if let Some(path) = extract_path_from_export(line, "LIBCLANG_PATH") {
                    println!("cargo:rustc-env=LIBCLANG_PATH={}", path);
                    unsafe {
                        env::set_var("LIBCLANG_PATH", &path);
                    }
                }
            }

            // Handle PATH
            if line.starts_with("export PATH=") {
                if let Some(path_addition) = extract_path_addition(line) {
                    let current_path = env::var("PATH").unwrap_or_default();
                    let new_path = if current_path.is_empty() {
                        path_addition
                    } else {
                        format!("{}:{}", path_addition, current_path)
                    };
                    println!("cargo:rustc-env=PATH={}", new_path);
                    unsafe {
                        env::set_var("PATH", &new_path);
                    }
                }
            }
        }
    }
}

fn extract_path_from_export(line: &str, var_name: &str) -> Option<String> {
    let prefix = format!("export {}=", var_name);
    if let Some(value) = line.strip_prefix(&prefix) {
        let value = value.trim_matches('"').trim_matches('\'');
        let expanded = expand_home(value);
        return Some(expanded);
    }
    None
}

fn extract_path_addition(line: &str) -> Option<String> {
    // Parse: export PATH="new_path:$PATH" or export PATH="new_path"
    if let Some(value) = line.strip_prefix("export PATH=") {
        let value = value.trim_matches('"').trim_matches('\'');

        // Extract just the new path additions (before $PATH)
        let parts: Vec<&str> = value.split('$').collect();
        if let Some(new_paths) = parts.first() {
            let paths = new_paths.trim_end_matches(':');
            let expanded = expand_home(paths);
            return Some(expanded);
        }
    }
    None
}

fn expand_home(path: &str) -> String {
    if path.starts_with("~/") {
        let home_dir = env::var("HOME")
            .unwrap_or_else(|_| env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string()));
        path.replacen("~", &home_dir, 1)
    } else {
        path.to_string()
    }
}

/// Generate a self-signed ECDSA P-256 cert + key in `src/tls-cert/` when the
/// pair is missing, so the firmware always has something to present over the
/// anonymous LAN Wendy link. The pair is intentionally ephemeral and is not
/// committed to version control.
fn ensure_tls_certs() {
    let certs_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("tls-cert");
    let cert_path = certs_dir.join("cert.der");
    let key_path = certs_dir.join("key.der");

    // A complete, matching pair already exists — nothing to do.
    if cert_path.exists() && key_path.exists() {
        watch_certs(&cert_path, &key_path);
        return;
    }

    // `openssl` is only required to *generate* the ephemeral pair; an existing
    // checkout that already has the files never needs it.
    if Command::new("openssl").arg("--version").output().is_err() {
        eprintln!(
            "error: {} and {} are missing, and `openssl` was not found in PATH.\n\
             Install OpenSSL, or place a self-signed X.509 cert at {} and its \
             EC private key at {}.",
            cert_path.display(),
            key_path.display(),
            cert_path.display(),
            key_path.display(),
        );
        return;
    }

    let run = |args: &[&str]| -> std::io::Result<()> {
        let status = Command::new("openssl").args(args).status()?;
        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("openssl {args:?} exited with {status}"),
            ))
        }
    };

    // Generate the key first, then self-sign the cert from it, so the two always
    // match. `genpkey` + `req` with `-keyform DER` is the subset of the openssl
    // CLI available on both OpenSSL and LibreSSL (macOS ships LibreSSL). The key
    // comes out as a DER EC private key (SEC1 on OpenSSL, PKCS#8 on LibreSSL);
    // both parse fine under MbedTLS.
    let generated = run(&[
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-outform",
        "DER",
        "-out",
        key_path.to_str().expect("valid cert path"),
    ])
    .and_then(|()| {
        run(&[
            "req",
            "-batch",
            "-new",
            "-x509",
            "-keyform",
            "DER",
            "-key",
            key_path.to_str().expect("valid cert path"),
            "-sha256",
            "-days",
            "3650",
            "-subj",
            "/CN=wendy-lite-default",
            "-outform",
            "DER",
            "-out",
            cert_path.to_str().expect("valid cert path"),
        ])
    });

    match generated {
        Ok(()) => {
            println!(
                "cargo:warning=generated self-signed LAN Wendy cert/key in {}",
                certs_dir.display()
            );
        }
        Err(e) => eprintln!("error: failed to generate LAN Wendy cert/key: {e}"),
    }

    watch_certs(&cert_path, &key_path);
}

/// Tell cargo to re-run this build script if the cert/key change or are deleted,
/// so a removed pair is regenerated on the next build.
fn watch_certs(cert_path: &Path, key_path: &Path) {
    if cert_path.exists() {
        println!("cargo:rerun-if-changed={}", cert_path.display());
    }
    if key_path.exists() {
        println!("cargo:rerun-if-changed={}", key_path.display());
    }
}
