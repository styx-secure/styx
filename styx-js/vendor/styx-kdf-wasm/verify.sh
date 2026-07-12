#!/usr/bin/env bash
# Reproducibility check for the styx-kdf-wasm artifact.
#
# Builds twice from the pins in build.sh and requires that:
#   1. the two builds are byte-identical to each other,
#   2. they are byte-identical to the artifact committed under ./pkg/,
#   3. every expected artifact file exists,
#   4. SHA256SUMS matches the committed files,
#   5. the lockfile did not drift (build.sh itself enforces --locked + cmp).
#
# Exits non-zero on any divergence. Slow (two full container builds).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
[[ -f "$HERE/Cargo.lock" ]] || {
  echo "ERROR: no Cargo.lock in $HERE — bootstrap it with ./build.sh first." >&2
  exit 1
}

FILES=(styx_kdf_wasm_bg.wasm styx_kdf_wasm.js styx_kdf_wasm.d.ts styx_kdf_wasm_bg.wasm.d.ts)
for f in "${FILES[@]}"; do
  [[ -s "$HERE/pkg/$f" ]] || { echo "MISSING committed artifact file: pkg/$f" >&2; exit 1; }
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "=== build 1/2 (with cargo test) ==="
OUT_DIR="$TMP/a" CARGO_TEST=1 "$HERE/build.sh"
echo "=== build 2/2 ==="
OUT_DIR="$TMP/b" "$HERE/build.sh"

echo
echo "=== results ==="
status=0
for f in "${FILES[@]}"; do
  if cmp -s "$TMP/a/$f" "$TMP/b/$f"; then
    echo "REPRODUCIBLE:  $f  $(sha256sum "$TMP/a/$f" | cut -d' ' -f1)"
  else
    echo "NON-REPRODUCIBLE:  $f differs between two builds from identical pins"
    status=1
  fi
  if ! cmp -s "$TMP/a/$f" "$HERE/pkg/$f"; then
    echo "MISMATCH vs committed:  pkg/$f — the vendored file was not produced by these pins"
    status=1
  fi
done

( cd "$HERE/pkg" && sha256sum -c SHA256SUMS ) || { echo "SHA256SUMS does not match the committed files"; status=1; }

# The package must contain exactly the expected files (plus checksums/README):
# no build cache, logs or unexpected outputs.
unexpected=$(cd "$HERE/pkg" && ls -A | grep -vxF -e "${FILES[0]}" -e "${FILES[1]}" -e "${FILES[2]}" -e "${FILES[3]}" -e SHA256SUMS -e README.md || true)
if [[ -n "$unexpected" ]]; then
  echo "UNEXPECTED files in pkg/: $unexpected"
  status=1
fi

exit $status
