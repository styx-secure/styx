#!/usr/bin/env bash
# Rebuild the vendored OpenMLS-WASM artifact from source, reproducibly, via Docker.
# Requires: Docker. No host Rust toolchain needed.
#
# Usage: ./build.sh [OPENMLS_COMMIT]
set -euo pipefail

OPENMLS_COMMIT="${1:-09e92777dba0528d3d29e2e5e681b7e91637c7be}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "Cloning openmls @ $OPENMLS_COMMIT ..."
git clone https://github.com/openmls/openmls.git "$WORK/openmls"
git -C "$WORK/openmls" checkout "$OPENMLS_COMMIT"

echo "Building openmls-wasm in rust:latest container ..."
docker run --rm -v "$WORK:/work" -w /work rust:latest bash -c '
  set -e
  rustup target add wasm32-unknown-unknown
  curl -sSfL https://rustwasm.github.io/wasm-pack/installer/init.sh | sh
  cd /work/openmls/openmls-wasm
  wasm-pack build --target web
'

echo "Copying artifact into vendor dir ..."
cp "$WORK/openmls/openmls-wasm/pkg/openmls_wasm.js" \
   "$WORK/openmls/openmls-wasm/pkg/openmls_wasm.d.ts" \
   "$WORK/openmls/openmls-wasm/pkg/openmls_wasm_bg.wasm" \
   "$WORK/openmls/openmls-wasm/pkg/openmls_wasm_bg.wasm.d.ts" \
   "$WORK/openmls/openmls-wasm/pkg/package.json" \
   "$HERE/"

echo "Done. Artifact refreshed in $HERE"
