#!/usr/bin/env bash
# Run the Styx OpenMLS wrapper's native tests against the exact source, Rust,
# dependency, patch, and feature pins used for the committed WASM artifact.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OPENMLS_COMMIT="09e92777dba0528d3d29e2e5e681b7e91637c7be"
RUST_IMAGE="rust:1.96.1@sha256:1f0dbad1df66647807e6952d1db85d0b2bda7606cb2139d82517e4f009967376"
# termion: the same commit-verified GitHub mirror as build.sh; the lockfile's
# gitlab.redox-os.org host is never contacted (see build.sh and PROVENANCE.md).
LOCKED_TERMION_URL="https://gitlab.redox-os.org/Jezza/termion.git"
GITHUB_TERMION_URL="https://github.com/redox-os/termion.git"
TERMION_BRANCH="windows-support"
TERMION_COMMIT="9e35f915e54ead30d02cf67c56eb56709f569ffd"
TERMION_TREE="fa273e9ef3642f0363327e9ad9d0be4c4a4565b4"
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

MIRROR="$WORK/mirrors/termion.git"
git init --quiet --bare "$MIRROR"
git -C "$MIRROR" fetch --quiet --no-tags "$GITHUB_TERMION_URL" "$TERMION_COMMIT"
[[ "$(git -C "$MIRROR" rev-parse --verify "${TERMION_COMMIT}^{commit}")" == "$TERMION_COMMIT" ]]
[[ "$(git -C "$MIRROR" rev-parse --verify "${TERMION_COMMIT}^{tree}")" == "$TERMION_TREE" ]] || {
  echo "ERROR: termion $TERMION_COMMIT does not have the pinned tree $TERMION_TREE." >&2
  exit 1
}
git -C "$MIRROR" update-ref "refs/heads/$TERMION_BRANCH" "$TERMION_COMMIT"
git -C "$MIRROR" symbolic-ref HEAD "refs/heads/$TERMION_BRANCH"

docker run --rm -v "$WORK:/work" -w /work/openmls \
  --add-host "gitlab.redox-os.org:127.0.0.1" \
  -e LOCKED_TERMION_URL="$LOCKED_TERMION_URL" \
  -e CARGO_NET_GIT_FETCH_WITH_CLI=true \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" "$RUST_IMAGE" bash -c '
    set -euo pipefail
    trap "chown -R ${HOST_UID}:${HOST_GID} /work" EXIT
    git config --global --add safe.directory "*"
    git config --global "url.file:///work/mirrors/termion.git.insteadOf" "${LOCKED_TERMION_URL}"
    cargo test -p openmls-wasm --locked --features extensions-draft
  '

cmp -s "$HERE/Cargo.lock" "$WORK/openmls/Cargo.lock" || {
  echo "ERROR: Cargo.lock drifted during native tests" >&2
  exit 1
}
