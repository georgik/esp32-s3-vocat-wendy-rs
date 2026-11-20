# esp32-vocat-wendy

ESP-VoCat (ESP32-S3, round ST77916 display) **Wendy native demo** and its host
tool, in one repository.

- **`esp32-s3-vocat-wendy-rs/`** — the idf/esp native firmware (the round-panel
  demo). Builds for `xtensa-esp32s3-none-elf`, `no_std` +
  `build-std`.
- **`desktop-client/`** — the host tool that turns an image into the ESP-VoCat
  Wendy network-graphics DSL and streams it over the LAN. Builds for the host
  (std).

Both share the same **baseline-JPEG** codec family (`libjpeg-turbo-rs`,
MIT/Apache-2.0): a frame the host encodes is exactly what the device decodes.

## Layout

```
esp32-vocat-wendy/
├── README.md
├── .gitignore
├── .github/workflows/build.yml  # CI: builds both workspaces (no flashing)
├── esp32-s3-vocat-wendy-rs/   # firmware — package: esp32-s3-vocat-wendy-rs (own Cargo workspace)
│   ├── .cargo/config.toml  (+ esp-config.toml)   # target=xtensa, build-std, espflash runner
│   ├── rust-toolchain.toml # channel = "esp"
│   ├── Cargo.toml / Cargo.lock
│   ├── build.rs, partitions.csv
│   ├── src/                # main.rs, script.rs, lan.rs, tls.rs, wifi.rs, …
│   ├── wendy/          # pure-Rust Wendy link (no_std, host-testable)
│   └── imgdecode/          # pure-Rust raw-RGB565 decoder (no_std, host-testable)
├── desktop-client/          # host tool — package: desktop-client (own Cargo workspace/bin)
│   ├── Cargo.toml / Cargo.lock
│   └── src/                # main.rs, color.rs, dsl.rs, jpeg.rs, png.rs, wendy.rs
```

## Why two Cargo workspaces (not one)

The firmware and the host tool **must not share a single Cargo workspace**:

- The firmware's `.cargo/config.toml` sets `target = xtensa-esp32s3-none-elf`,
  `[unstable] build-std = ["alloc","core"]`, and an `espflash` runner — all
  firmware-only. Inherited by the host build, that would force `build-std`
  onto the host tool (rebuilds std from source, slow and fragile).
- `esp32-s3-vocat-wendy-rs/rust-toolchain.toml` pins `channel = "esp"`
  (nightly + Xtensa); at the repo root it would drag the stable host tool onto
  that toolchain.

So each keeps its own `.cargo/config.toml` and `rust-toolchain.toml`, and the
top level is just a plain folder with `README.md` tying them together. A GitHub
Actions workflow (`.github/workflows/build.yml`) builds both workspaces.

## Build

Both workspaces build with plain `cargo` — no wrapper scripts, so the same
commands work on any platform:

```bash
# Firmware (Xtensa ESP32-S3, no_std + build-std). The esp toolchain is selected
# via rust-toolchain.toml; build.rs auto-loads the Xtensa gcc if it is absent.
cd esp32-s3-vocat-wendy-rs
cargo build --release

# Host tool (stable toolchain, normal std).
cd ../desktop-client
cargo build --release
```

The firmware's `.cargo/config.toml` sets an `espflash flash --monitor` runner,
but that only runs under `cargo run` — `cargo build` just compiles and links, so
no board is required.

Continuous integration builds both workspaces on every push / pull request in
[`.github/workflows/build.yml`](.github/workflows/build.yml).

## Deploying to hardware

The Rust firmware flashes and monitors directly through `espflash` — that is the
runner declared in the firmware's `.cargo/config.toml`, so there is no `wendy`
CLI or ESP-IDF toolchain involved.

Build only (no board needed):

```bash
cd esp32-s3-vocat-wendy-rs
cargo build --release
```

Flash + monitor the board:

```bash
cd esp32-s3-vocat-wendy-rs
cargo run --release
```

## Note

**The monitor owns the serial channel.** `cargo run --release` flashes and then
**blocks** in `espflash monitor`, holding the USB-Serial/JTAG port. While it is
running, `wendy device list` cannot open the same port, so the board only ever
shows up over the LAN. To list the board over USB, stop the monitor first
(`Ctrl+C` twice, or `Ctrl+]` then `q` to quit the espflash session), release the
port, and run `wendy device list` in another terminal.

### Wi-Fi credentials

Wi-Fi is best-effort and only activates when credentials are baked into the
build. For now, export them as environment variables before building
(temporary — this will later move to the Wendy security mechanism):

```bash
export WIFI_SSID="your-ssid"
export WIFI_PASSWORD="your-password"
cargo run --release
```

## Sending a picture over the LAN

The `desktop-client/` host tool turns an image into the ESP-VoCat Wendy
network-graphics DSL (or a SensorLink frame stream) and streams it to the board
over the LAN. Build it like any host binary:

```bash
cd desktop-client
cargo build --release
# run it with: cargo run --release -- <image> [options]
```

### Find the board's IP

The board joins your Wi-Fi (see above) and listens on port **5054**. Its IP is
assigned by your router's DHCP — find it in the router's client list, or by
scanning the LAN for the open port 5054.

### Send a small image (DSL path)

```bash
cd desktop-client
cargo run --release -- photo.png \
    --host <board-ip> -w 96 -h 96
```

This prints the DSL to stdout and, because `--host` is given, also pushes it to
the board. The image is scaled to `-w`×`-h` and centred by default (override
with `--x` / `--y`). The DSL path is for **small** images: the reassembled
frame must fit in the device's 128 KiB image buffer, so anything above roughly
256×256 will not render — for the full 360×360 panel use `--jpeg` below.

### Options

| flag | meaning | default |
|------|---------|---------|
| `<image>` | PNG, raw big-endian RGB565, raw RGB, or `pattern` (built-in gradient). JPEG input is not read — convert `.jpg`/`.jpeg` to PNG first | — |
| `-w, --width` | output width in px | 96 |
| `-h, --height` | output height in px | 48 |
| `--x, --y` | top-left position (default: centred) | centred |
| `--enc` | DSL encoding: `hex` or `b64` | `b64` |
| `--chunk` | chars per `put` line | 88 |
| `--host` | push to this LAN IP after printing | (print only) |
| `--port` | LAN port | 5054 |
| `--plain` | bare TCP instead of TLS (local testing only) | TLS |
| `--sensorlink` | stream as SensorLink chunks instead of DSL | off |
| `--jpeg` | encode each SensorLink frame as lossless JPEG (implies `--sensorlink`) | off |

With no `--host` the tool only prints the DSL (handy for piping to a file or
reviewing). The board's Wendy LAN server uses a self-signed, server-auth-only
TLS session, so the default TLS path completes a handshake with that cert; use
`--plain` only when testing against a non-TLS listener.

### Full-frame streaming (SensorLink + JPEG)

For a full picture, the SensorLink path with `--jpeg` compresses the frame to a
lossless JPEG before chunking, so it is far smaller on the wire than raw RGB565:

```bash
cd desktop-client
cargo run --release -- photo.png \
    --host <board-ip> -w 360 -h 360 --jpeg
```

## External dependencies

- **`mbedtls-rs`** — the C TLS backend for the LAN Wendy link, pulled from
  crates.io (`mbedtls-rs` 0.3.0 + its `mbedtls-rs-sys` 0.3.1 bindings, which
  bundle the prebuilt `xtensa-esp32s3-none-elf` libraries). No vendored copy or
  git submodule is kept in this repo.
- **`esp-vocat`** — a git dependency (the BSP/`esp-vocat` crate), fetched from
  crates.io/git at build time.
