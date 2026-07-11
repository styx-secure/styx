#!/usr/bin/env bash
# Reproducibility check for the vendored OpenMLS-WASM artifact.
#
# Builds twice from the pins in build.sh and requires that:
#   1. the two builds are byte-identical to each other, and
#   2. they are byte-identical to the artifact committed in this directory.
#
# Exits non-zero on any divergence. Slow (two full container builds).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
[[ -f "$HERE/Cargo.lock" ]] || {
  echo "ERROR: no Cargo.lock in $HERE — bootstrap it with ./build.sh first." >&2
  exit 1
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "=== build 1/2 ==="
OUT_DIR="$TMP/a" "$HERE/build.sh"
echo "=== build 2/2 ==="
OUT_DIR="$TMP/b" "$HERE/build.sh"

echo
echo "=== results ==="
status=0
for f in openmls_wasm_bg.wasm openmls_wasm.js; do
  if cmp -s "$TMP/a/$f" "$TMP/b/$f"; then
    echo "REPRODUCIBLE:  $f  $(sha256sum "$TMP/a/$f" | cut -d' ' -f1)"
  else
    echo "NON-REPRODUCIBLE:  $f differs between two builds from identical pins"
    status=1
  fi
  if ! cmp -s "$TMP/a/$f" "$HERE/$f"; then
    echo "MISMATCH vs committed:  $f — the vendored file was not produced by these pins"
    status=1
  fi
done

exit $status
