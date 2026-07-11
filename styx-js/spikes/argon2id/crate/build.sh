#!/usr/bin/env bash
# STYX_SPIKE_PROTOTYPE — build candidate A with the SAME pinned toolchain as the
# canonical crate (vendor/openmls-wasm/build.sh): identical image digest and
# wasm-pack release. The canonical artifact and its toolchain are NOT touched.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

RUST_IMAGE="rust:1.96.1@sha256:1f0dbad1df66647807e6952d1db85d0b2bda7606cb2139d82517e4f009967376"
WASM_PACK_VERSION="0.15.0"
WASM_PACK_SHA256="c09f971ecaed9a2efc80fdcea7a00ef6b53c7fadc8c57d1f61b53a6aa66b668a"

docker run --rm -v "$HERE":/work -w /work \
  -e WASM_PACK_VERSION="$WASM_PACK_VERSION" -e WASM_PACK_SHA256="$WASM_PACK_SHA256" \
  "$RUST_IMAGE" bash -ceu '
    curl -sSfLO "https://github.com/rustwasm/wasm-pack/releases/download/v${WASM_PACK_VERSION}/wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl.tar.gz"
    echo "${WASM_PACK_SHA256}  wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl.tar.gz" | sha256sum -c -
    tar xzf "wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl.tar.gz" --strip-components=1 -C /usr/local/bin "wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl/wasm-pack"
    rustup target add wasm32-unknown-unknown
    wasm-pack build --target web --out-dir pkg
  '
sha256sum "$HERE"/pkg/argon2id_spike_bg.wasm
