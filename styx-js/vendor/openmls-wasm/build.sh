#!/usr/bin/env bash
# Rebuild the vendored OpenMLS-WASM artifact from source, reproducibly, via Docker.
# Requires: Docker. No host Rust toolchain needed.
#
# Every input to the build is pinned:
#   - the OpenMLS source commit          (OPENMLS_COMMIT, see PROVENANCE.md)
#   - the Rust toolchain                 (RUST_IMAGE, by manifest digest)
#   - wasm-pack                          (release binary, sha256-verified)
#   - the whole dependency graph         (./Cargo.lock, built with --locked)
#
# Usage: ./build.sh [OPENMLS_COMMIT]     artifacts land in this directory
#        OUT_DIR=/tmp/x ./build.sh       artifacts land in OUT_DIR (used by verify.sh)
set -euo pipefail

# Descendant of tag openmls-v0.8.1; carries the SRLabs audit fixes. Do NOT downgrade
# to the v0.8.1 tag: it would lose 76 commits and change the persisted storage format.
# See PROVENANCE.md.
OPENMLS_COMMIT="${1:-09e92777dba0528d3d29e2e5e681b7e91637c7be}"

# The digest is the real pin (a tag can be re-pushed); the version tag documents intent.
RUST_IMAGE="rust:1.96.1@sha256:1f0dbad1df66647807e6952d1db85d0b2bda7606cb2139d82517e4f009967376"
WASM_PACK_VERSION="0.15.0"
WASM_PACK_SHA256="c09f971ecaed9a2efc80fdcea7a00ef6b53c7fadc8c57d1f61b53a6aa66b668a"

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${OUT_DIR:-$HERE}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "Cloning openmls @ $OPENMLS_COMMIT ..."
git clone --quiet https://github.com/openmls/openmls.git "$WORK/openmls"
git -C "$WORK/openmls" checkout --quiet "$OPENMLS_COMMIT"

# Apply our patch: adds Provider.serialize_state/restore_state, Group.load,
# Identity.public_key/load, Group.member_identities, and returns errors instead of
# panicking on wire input.
echo "Applying Styx patch (patch/lib.rs) ..."
cp "$HERE/patch/lib.rs" "$WORK/openmls/openmls-wasm/src/lib.rs"

# Cargo.lock round-trip. openmls is a cargo workspace, so the lockfile lives at the
# workspace root. Steady state: build --locked against the vendored lockfile. First run
# (or after an OPENMLS_COMMIT bump): bootstrap a fresh one and commit it.
LOCKED="no"
if [[ -f "$HERE/Cargo.lock" ]]; then
  cp "$HERE/Cargo.lock" "$WORK/openmls/Cargo.lock"
  LOCKED="yes"
else
  echo "WARNING: no vendored Cargo.lock — bootstrap build, one will be generated." >&2
fi

echo "Building openmls-wasm in $RUST_IMAGE ..."
# The container builds as root (rustup/cargo own /usr/local/cargo), so it chowns the
# work tree back to us on the way out — otherwise root-owned build output would make
# the cleanup trap fail and leak temp dirs on every run.
docker run --rm -v "$WORK:/work" -w /work \
  -e WASM_PACK_VERSION="$WASM_PACK_VERSION" \
  -e WASM_PACK_SHA256="$WASM_PACK_SHA256" \
  -e LOCKED="$LOCKED" \
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
    cd /work/openmls/openmls-wasm
    if [[ "$LOCKED" == "yes" ]]; then
      wasm-pack build --target web -- --locked
    else
      wasm-pack build --target web
    fi
  '

# Drift guard (steady state) / lockfile export (bootstrap).
if [[ "$LOCKED" == "yes" ]]; then
  cmp -s "$HERE/Cargo.lock" "$WORK/openmls/Cargo.lock" || {
    echo "ERROR: Cargo.lock changed despite --locked — pin drift; refusing the artifact." >&2
    exit 1
  }
else
  cp "$WORK/openmls/Cargo.lock" "$HERE/Cargo.lock"
  echo "Bootstrapped Cargo.lock into $HERE — commit it alongside the artifact."
fi

echo "Copying artifact into $OUT_DIR ..."
mkdir -p "$OUT_DIR"
cp "$WORK/openmls/openmls-wasm/pkg/openmls_wasm.js" \
   "$WORK/openmls/openmls-wasm/pkg/openmls_wasm.d.ts" \
   "$WORK/openmls/openmls-wasm/pkg/openmls_wasm_bg.wasm" \
   "$WORK/openmls/openmls-wasm/pkg/openmls_wasm_bg.wasm.d.ts" \
   "$WORK/openmls/openmls-wasm/pkg/package.json" \
   "$OUT_DIR/"

sha256sum "$OUT_DIR/openmls_wasm_bg.wasm" "$OUT_DIR/openmls_wasm.js"
echo "Done. Artifact refreshed in $OUT_DIR"
