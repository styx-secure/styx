#!/usr/bin/env bash
# Run the Styx OpenMLS wrapper's native tests against the exact source, Rust,
# dependency, patch, and feature pins used for the committed WASM artifact.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OPENMLS_COMMIT="09e92777dba0528d3d29e2e5e681b7e91637c7be"
RUST_IMAGE="rust:1.96.1@sha256:1f0dbad1df66647807e6952d1db85d0b2bda7606cb2139d82517e4f009967376"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

[[ -f "$HERE/Cargo.lock" ]] || {
  echo "ERROR: missing pinned Cargo.lock" >&2
  exit 1
}

git clone --quiet https://github.com/openmls/openmls.git "$WORK/openmls"
git -C "$WORK/openmls" checkout --quiet "$OPENMLS_COMMIT"
cp "$HERE/patch/lib.rs" "$WORK/openmls/openmls-wasm/src/lib.rs"
cp "$HERE/Cargo.lock" "$WORK/openmls/Cargo.lock"

docker run --rm -v "$WORK:/work" -w /work/openmls \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" "$RUST_IMAGE" bash -c '
    set -euo pipefail
    trap "chown -R ${HOST_UID}:${HOST_GID} /work" EXIT
    cargo test -p openmls-wasm --locked --features extensions-draft
  '

cmp -s "$HERE/Cargo.lock" "$WORK/openmls/Cargo.lock" || {
  echo "ERROR: Cargo.lock drifted during native tests" >&2
  exit 1
}
