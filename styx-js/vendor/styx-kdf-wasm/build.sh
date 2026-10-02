#!/usr/bin/env bash
# Build the styx-kdf-wasm artifact reproducibly, via Docker.
# Requires: Docker. No host Rust toolchain needed.
#
# Pinned build inputs:
#   - the crate source                    (this directory, committed)
#   - the Rust toolchain                  (RUST_IMAGE, by manifest digest — the
#                                          SAME image pinned by the canonical
#                                          openmls-wasm build)
#   - wasm-pack                           (release binary, sha256-verified)
#   - wasm-bindgen-cli                    (release binary, sha256-verified, version
#                                          must equal the Cargo.lock wasm-bindgen)
#   - binaryen / wasm-opt                 (release binary, sha256-verified)
#   - the whole dependency graph          (./Cargo.lock, built with --locked)
# Not pinned by this repository: the wasm32 `rust-std` component that `rustup target
# add` fetches (verified by rustup against its channel manifest) — any drift is caught
# by verify.sh against the committed bytes.
#
# wasm-pack runs with `--mode no-install`: it uses only the hash-verified tools on
# PATH and can neither download a tool nor fall back to `cargo install`.
#
# Usage: ./build.sh                       artifacts land in ./pkg/
#        OUT_DIR=/tmp/x ./build.sh        artifacts land in OUT_DIR (used by verify.sh)
#        CARGO_TEST=1 ./build.sh          also run `cargo test --locked` (native) first
set -euo pipefail

# The digest is the real pin (a tag can be re-pushed); the version tag documents intent.
RUST_IMAGE="rust:1.96.1@sha256:1f0dbad1df66647807e6952d1db85d0b2bda7606cb2139d82517e4f009967376"
WASM_PACK_VERSION="0.15.0"
WASM_PACK_SHA256="c09f971ecaed9a2efc80fdcea7a00ef6b53c7fadc8c57d1f61b53a6aa66b668a"
# The exact release archives wasm-pack 0.15.0 itself downloads for this platform
# (same pins as the canonical openmls-wasm build).
WASM_BINDGEN_VERSION="0.2.126"
WASM_BINDGEN_SHA256="064948d58e2d6c0a745216477a639ba696216d6309aaa902939d1b865b1d869d"
BINARYEN_VERSION="version_117"
BINARYEN_SHA256="3dc677006555b355ea2da5e82602065a161d5e83eaefd3f759afa00b96e83212"

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${OUT_DIR:-$HERE/pkg}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Build from a clean copy of the committed sources only — never from the live
# tree — so stray local files cannot leak into the artifact.
mkdir -p "$WORK/crate/src"
cp "$HERE/Cargo.toml" "$WORK/crate/"
cp "$HERE/src/lib.rs" "$WORK/crate/src/"

# Container runs as root (rustup/cargo own /usr/local/cargo); it chowns the work tree
# back to us on the way out so the cleanup trap never meets root-owned files.
DOCKER_ARGS=(
  --rm -v "$WORK:/work" -w /work/crate
  -e HOST_UID="$(id -u)"
  -e HOST_GID="$(id -g)"
)

# Cargo.lock round-trip. Steady state: build --locked against the vendored lockfile.
# First run (or after a dependency bump): bootstrap — resolve a fresh lockfile, export
# it to this directory, then hold it to the same pins as a committed one.
if [[ -f "$HERE/Cargo.lock" ]]; then
  cp "$HERE/Cargo.lock" "$WORK/crate/Cargo.lock"
else
  echo "WARNING: no vendored Cargo.lock — bootstrap: resolving one with cargo generate-lockfile." >&2
  docker run "${DOCKER_ARGS[@]}" "$RUST_IMAGE" bash -c '
    set -euo pipefail
    trap "chown -R ${HOST_UID}:${HOST_GID} /work" EXIT
    cargo generate-lockfile
  '
  cp "$WORK/crate/Cargo.lock" "$HERE/Cargo.lock"
  echo "Bootstrapped Cargo.lock into $HERE — review and commit it alongside the artifact."
fi
locked_bindgen="$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/version = |"/, ""); print; exit }' "$HERE/Cargo.lock")"
[[ "$locked_bindgen" == "$WASM_BINDGEN_VERSION" ]] || {
  echo "ERROR: Cargo.lock wasm-bindgen is '$locked_bindgen' but the pinned wasm-bindgen-cli is $WASM_BINDGEN_VERSION." >&2
  echo "       Update WASM_BINDGEN_VERSION/WASM_BINDGEN_SHA256 in build.sh to match, then rebuild." >&2
  exit 1
}

echo "Building styx-kdf-wasm in $RUST_IMAGE ..."
docker run "${DOCKER_ARGS[@]}" \
  -e WASM_PACK_VERSION="$WASM_PACK_VERSION" \
  -e WASM_PACK_SHA256="$WASM_PACK_SHA256" \
  -e WASM_BINDGEN_VERSION="$WASM_BINDGEN_VERSION" \
  -e WASM_BINDGEN_SHA256="$WASM_BINDGEN_SHA256" \
  -e BINARYEN_VERSION="$BINARYEN_VERSION" \
  -e BINARYEN_SHA256="$BINARYEN_SHA256" \
  -e CARGO_TEST="${CARGO_TEST:-0}" \
  "$RUST_IMAGE" bash -c '
    set -euo pipefail
    trap "chown -R ${HOST_UID}:${HOST_GID} /work" EXIT
    rustup target add wasm32-unknown-unknown
    wp="wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl"
    curl -sSfLo /tmp/wp.tar.gz "https://github.com/rustwasm/wasm-pack/releases/download/v${WASM_PACK_VERSION}/${wp}.tar.gz"
    echo "${WASM_PACK_SHA256}  /tmp/wp.tar.gz" | sha256sum -c -
    tar -xzf /tmp/wp.tar.gz -C /tmp
    install "/tmp/${wp}/wasm-pack" /usr/local/bin/wasm-pack
    wb="wasm-bindgen-${WASM_BINDGEN_VERSION}-x86_64-unknown-linux-musl"
    curl -sSfLo /tmp/wb.tar.gz "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${WASM_BINDGEN_VERSION}/${wb}.tar.gz"
    echo "${WASM_BINDGEN_SHA256}  /tmp/wb.tar.gz" | sha256sum -c -
    tar -xzf /tmp/wb.tar.gz -C /tmp
    install "/tmp/${wb}/wasm-bindgen" /usr/local/bin/wasm-bindgen
    by="binaryen-${BINARYEN_VERSION}-x86_64-linux"
    curl -sSfLo /tmp/by.tar.gz "https://github.com/WebAssembly/binaryen/releases/download/${BINARYEN_VERSION}/${by}.tar.gz"
    echo "${BINARYEN_SHA256}  /tmp/by.tar.gz" | sha256sum -c -
    tar -xzf /tmp/by.tar.gz -C /tmp
    install "/tmp/binaryen-${BINARYEN_VERSION}/bin/wasm-opt" /usr/local/bin/wasm-opt
    # Required: under --mode no-install wasm-pack would silently SKIP a missing
    # wasm-opt rather than fail, so its presence and version are enforced here.
    [[ "$(wasm-bindgen --version)" == "wasm-bindgen ${WASM_BINDGEN_VERSION}" ]] || {
      echo "ERROR: wasm-bindgen on PATH is not the pinned ${WASM_BINDGEN_VERSION}." >&2; exit 1; }
    [[ "$(wasm-opt --version)" == "wasm-opt version ${BINARYEN_VERSION#version_} (${BINARYEN_VERSION})" ]] || {
      echo "ERROR: wasm-opt on PATH is not the pinned ${BINARYEN_VERSION}." >&2; exit 1; }
    if [[ "$CARGO_TEST" == "1" ]]; then
      cargo test --locked
    fi
    wasm-pack build --mode no-install --target web -- --locked
  '

# Drift guard: the lockfile (committed or freshly bootstrapped) must survive --locked.
cmp -s "$HERE/Cargo.lock" "$WORK/crate/Cargo.lock" || {
  echo "ERROR: Cargo.lock changed despite --locked — pin drift; refusing the artifact." >&2
  exit 1
}

echo "Copying artifact into $OUT_DIR ..."
mkdir -p "$OUT_DIR"
cp "$WORK/crate/pkg/styx_kdf_wasm.js" \
   "$WORK/crate/pkg/styx_kdf_wasm.d.ts" \
   "$WORK/crate/pkg/styx_kdf_wasm_bg.wasm" \
   "$WORK/crate/pkg/styx_kdf_wasm_bg.wasm.d.ts" \
   "$OUT_DIR/"

sha256sum "$OUT_DIR/styx_kdf_wasm_bg.wasm" "$OUT_DIR/styx_kdf_wasm.js"
echo "Done. Artifact refreshed in $OUT_DIR"
