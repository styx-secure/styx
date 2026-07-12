#!/usr/bin/env bash
# Build the styx-kdf-wasm artifact reproducibly, via Docker.
# Requires: Docker. No host Rust toolchain needed.
#
# Every input to the build is pinned:
#   - the crate source                    (this directory, committed)
#   - the Rust toolchain                  (RUST_IMAGE, by manifest digest — the
#                                          SAME image pinned by the canonical
#                                          openmls-wasm build)
#   - wasm-pack                           (release binary, sha256-verified)
#   - the whole dependency graph          (./Cargo.lock, built with --locked)
#
# Usage: ./build.sh                       artifacts land in ./pkg/
#        OUT_DIR=/tmp/x ./build.sh        artifacts land in OUT_DIR (used by verify.sh)
#        CARGO_TEST=1 ./build.sh          also run `cargo test --locked` (native) first
set -euo pipefail

# The digest is the real pin (a tag can be re-pushed); the version tag documents intent.
RUST_IMAGE="rust:1.96.1@sha256:1f0dbad1df66647807e6952d1db85d0b2bda7606cb2139d82517e4f009967376"
WASM_PACK_VERSION="0.15.0"
WASM_PACK_SHA256="c09f971ecaed9a2efc80fdcea7a00ef6b53c7fadc8c57d1f61b53a6aa66b668a"

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${OUT_DIR:-$HERE/pkg}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Build from a clean copy of the committed sources only — never from the live
# tree — so stray local files cannot leak into the artifact.
mkdir -p "$WORK/crate/src"
cp "$HERE/Cargo.toml" "$WORK/crate/"
cp "$HERE/src/lib.rs" "$WORK/crate/src/"

# Cargo.lock round-trip. Steady state: build --locked against the vendored
# lockfile. First run (or after a dependency bump): bootstrap one and commit it.
LOCKED="no"
if [[ -f "$HERE/Cargo.lock" ]]; then
  cp "$HERE/Cargo.lock" "$WORK/crate/Cargo.lock"
  LOCKED="yes"
else
  echo "WARNING: no vendored Cargo.lock — bootstrap build, one will be generated." >&2
fi

echo "Building styx-kdf-wasm in $RUST_IMAGE ..."
docker run --rm -v "$WORK:/work" -w /work/crate \
  -e WASM_PACK_VERSION="$WASM_PACK_VERSION" \
  -e WASM_PACK_SHA256="$WASM_PACK_SHA256" \
  -e LOCKED="$LOCKED" \
  -e CARGO_TEST="${CARGO_TEST:-0}" \
  -e HOST_UID="$(id -u)" \
  -e HOST_GID="$(id -g)" \
  "$RUST_IMAGE" bash -c '
    set -euo pipefail
    trap "chown -R ${HOST_UID}:${HOST_GID} /work" EXIT
    rustup target add wasm32-unknown-unknown
    wp="wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl"
    curl -sSfLo /tmp/wp.tar.gz "https://github.com/rustwasm/wasm-pack/releases/download/v${WASM_PACK_VERSION}/${wp}.tar.gz"
    echo "${WASM_PACK_SHA256}  /tmp/wp.tar.gz" | sha256sum -c -
    tar -xzf /tmp/wp.tar.gz -C /tmp
    install "/tmp/${wp}/wasm-pack" /usr/local/bin/wasm-pack
    if [[ "$CARGO_TEST" == "1" ]]; then
      if [[ "$LOCKED" == "yes" ]]; then cargo test --locked; else cargo test; fi
    fi
    if [[ "$LOCKED" == "yes" ]]; then
      wasm-pack build --target web -- --locked
    else
      wasm-pack build --target web
    fi
  '

# Drift guard (steady state) / lockfile export (bootstrap).
if [[ "$LOCKED" == "yes" ]]; then
  cmp -s "$HERE/Cargo.lock" "$WORK/crate/Cargo.lock" || {
    echo "ERROR: Cargo.lock changed despite --locked — pin drift; refusing the artifact." >&2
    exit 1
  }
else
  cp "$WORK/crate/Cargo.lock" "$HERE/Cargo.lock"
  echo "Bootstrapped Cargo.lock into $HERE — commit it alongside the artifact."
fi

echo "Copying artifact into $OUT_DIR ..."
mkdir -p "$OUT_DIR"
cp "$WORK/crate/pkg/styx_kdf_wasm.js" \
   "$WORK/crate/pkg/styx_kdf_wasm.d.ts" \
   "$WORK/crate/pkg/styx_kdf_wasm_bg.wasm" \
   "$WORK/crate/pkg/styx_kdf_wasm_bg.wasm.d.ts" \
   "$OUT_DIR/"

sha256sum "$OUT_DIR/styx_kdf_wasm_bg.wasm" "$OUT_DIR/styx_kdf_wasm.js"
echo "Done. Artifact refreshed in $OUT_DIR"
