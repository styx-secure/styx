#!/usr/bin/env bash
# Rebuild the vendored OpenMLS-WASM artifact from source, reproducibly, via Docker.
# Requires: Docker. No host Rust toolchain needed.
#
# Pinned build inputs:
#   - the OpenMLS source commit          (OPENMLS_COMMIT, see PROVENANCE.md)
#   - the Rust toolchain                 (RUST_IMAGE, by manifest digest)
#   - wasm-pack                          (release binary, sha256-verified)
#   - wasm-bindgen-cli                   (release binary, sha256-verified, version
#                                         must equal the Cargo.lock wasm-bindgen)
#   - binaryen / wasm-opt                (release binary, sha256-verified)
#   - the whole dependency graph         (./Cargo.lock, built with --locked)
#   - termion (git dep of the upstream `cli` workspace member), fetched by exact
#     commit from GITHUB_TERMION_URL and served to cargo from a local mirror; the
#     lockfile's gitlab.redox-os.org host is never contacted (see README.md)
# Not pinned by this repository: the wasm32 `rust-std` component that `rustup target
# add` fetches (verified by rustup against its channel manifest) — any drift is caught
# by verify.sh against the committed bytes.
#
# wasm-pack runs with `--mode no-install`: it uses only the hash-verified tools on
# PATH and can neither download a tool nor fall back to `cargo install`.
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
# The exact release archives wasm-pack 0.15.0 itself downloads for this platform.
WASM_BINDGEN_VERSION="0.2.126"
WASM_BINDGEN_SHA256="064948d58e2d6c0a745216477a639ba696216d6309aaa902939d1b865b1d869d"
BINARYEN_VERSION="version_117"
BINARYEN_SHA256="3dc677006555b355ea2da5e82602065a161d5e83eaefd3f759afa00b96e83212"

# termion: Cargo.lock records it as
#   git+https://gitlab.redox-os.org/Jezza/termion.git?branch=windows-support#<TERMION_COMMIT>
# The same commit is published on GitHub (redox-os/termion, ref
# refs/merge-requests/151/head).
LOCKED_TERMION_URL="https://gitlab.redox-os.org/Jezza/termion.git"
GITHUB_TERMION_URL="https://github.com/redox-os/termion.git"
TERMION_BRANCH="windows-support"
TERMION_COMMIT="9e35f915e54ead30d02cf67c56eb56709f569ffd"
TERMION_TREE="fa273e9ef3642f0363327e9ad9d0be4c4a4565b4"

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${OUT_DIR:-$HERE}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Refuse a lockfile whose wasm-bindgen differs from the pinned CLI, or whose termion
# git source differs from the mirrored pin, before any build starts.
check_lockfile() {
  local lock="$1" locked_bindgen termion_sources
  locked_bindgen="$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/version = |"/, ""); print; exit }' "$lock")"
  [[ "$locked_bindgen" == "$WASM_BINDGEN_VERSION" ]] || {
    echo "ERROR: Cargo.lock wasm-bindgen is '$locked_bindgen' but the pinned wasm-bindgen-cli is $WASM_BINDGEN_VERSION." >&2
    echo "       Update WASM_BINDGEN_VERSION/WASM_BINDGEN_SHA256 in build.sh to match, then rebuild." >&2
    exit 1
  }
  termion_sources="$(grep -c '^source = "git+https://gitlab.redox-os.org/' "$lock" || true)"
  if [[ "$termion_sources" != "0" ]]; then
    grep -qxF "source = \"git+${LOCKED_TERMION_URL}?branch=${TERMION_BRANCH}#${TERMION_COMMIT}\"" "$lock" \
      && [[ "$termion_sources" == "1" ]] || {
      echo "ERROR: Cargo.lock gitlab.redox-os.org source is not exactly termion @ $TERMION_COMMIT;" >&2
      echo "       update the TERMION_* pins in build.sh and test.sh to match." >&2
      exit 1
    }
  fi
}

echo "Cloning openmls @ $OPENMLS_COMMIT ..."
git clone --quiet https://github.com/openmls/openmls.git "$WORK/openmls"
git -C "$WORK/openmls" checkout --quiet "$OPENMLS_COMMIT"

# Apply our patch: adds Provider.serialize_state/restore_state, Group.load,
# Identity.public_key/load, Group.member_identities, the isolated Phase B1 probe,
# and returned errors instead of panics on wire input.
echo "Applying Styx patch (patch/lib.rs) ..."
cp "$HERE/patch/lib.rs" "$WORK/openmls/openmls-wasm/src/lib.rs"

# Local, commit-verified termion mirror. Cargo is pointed at it with a git
# url.insteadOf rewrite inside the container; Cargo.lock is not modified.
echo "Mirroring termion @ $TERMION_COMMIT from $GITHUB_TERMION_URL ..."
MIRROR="$WORK/mirrors/termion.git"
git init --quiet --bare "$MIRROR"
git --git-dir="$MIRROR" fetch --quiet --no-tags "$GITHUB_TERMION_URL" "$TERMION_COMMIT"
[[ "$(git --git-dir="$MIRROR" rev-parse --verify "${TERMION_COMMIT}^{commit}")" == "$TERMION_COMMIT" ]] || {
  echo "ERROR: termion commit $TERMION_COMMIT not obtained from $GITHUB_TERMION_URL." >&2
  exit 1
}
[[ "$(git --git-dir="$MIRROR" rev-parse --verify "${TERMION_COMMIT}^{tree}")" == "$TERMION_TREE" ]] || {
  echo "ERROR: termion $TERMION_COMMIT does not have the pinned tree $TERMION_TREE." >&2
  exit 1
}
git --git-dir="$MIRROR" update-ref "refs/heads/$TERMION_BRANCH" "$TERMION_COMMIT"
git --git-dir="$MIRROR" symbolic-ref HEAD "refs/heads/$TERMION_BRANCH"

# Common container setup. gitlab.redox-os.org resolves to a closed local port inside
# the container, so any attempt to reach it fails instead of silently succeeding.
# The container runs as root (rustup/cargo own /usr/local/cargo), so it chowns the
# work tree back to us on the way out — otherwise root-owned build output would make
# the cleanup trap fail and leak temp dirs on every run.
DOCKER_ARGS=(
  --rm -v "$WORK:/work"
  --add-host "gitlab.redox-os.org:127.0.0.1"
  -e LOCKED_TERMION_URL="$LOCKED_TERMION_URL"
  -e CARGO_NET_GIT_FETCH_WITH_CLI=true
  -e HOST_UID="$(id -u)"
  -e HOST_GID="$(id -g)"
)
# shellcheck disable=SC2016  # expanded inside the container
GIT_SETUP='git config --global --add safe.directory /work/mirrors/termion.git
    git config --global "url.file:///work/mirrors/termion.git.insteadOf" "${LOCKED_TERMION_URL}"'

# Cargo.lock round-trip. openmls is a cargo workspace, so the lockfile lives at the
# workspace root. Steady state: build --locked against the vendored lockfile. First run
# (or after an OPENMLS_COMMIT bump): bootstrap — resolve a fresh lockfile, export it to
# this directory, then hold it to the same pins as a committed one.
if [[ -f "$HERE/Cargo.lock" ]]; then
  cp "$HERE/Cargo.lock" "$WORK/openmls/Cargo.lock"
else
  echo "WARNING: no vendored Cargo.lock — bootstrap: resolving one with cargo generate-lockfile." >&2
  docker run "${DOCKER_ARGS[@]}" -w /work/openmls "$RUST_IMAGE" bash -c "
    set -euo pipefail
    trap 'chown -R \${HOST_UID}:\${HOST_GID} /work' EXIT
    $GIT_SETUP
    cargo generate-lockfile
  "
  cp "$WORK/openmls/Cargo.lock" "$HERE/Cargo.lock"
  echo "Bootstrapped Cargo.lock into $HERE — review and commit it alongside the artifact."
fi
check_lockfile "$HERE/Cargo.lock"

echo "Building openmls-wasm in $RUST_IMAGE ..."
docker run "${DOCKER_ARGS[@]}" -w /work \
  -e WASM_PACK_VERSION="$WASM_PACK_VERSION" \
  -e WASM_PACK_SHA256="$WASM_PACK_SHA256" \
  -e WASM_BINDGEN_VERSION="$WASM_BINDGEN_VERSION" \
  -e WASM_BINDGEN_SHA256="$WASM_BINDGEN_SHA256" \
  -e BINARYEN_VERSION="$BINARYEN_VERSION" \
  -e BINARYEN_SHA256="$BINARYEN_SHA256" \
  "$RUST_IMAGE" bash -c "
    set -euo pipefail
    trap 'chown -R \${HOST_UID}:\${HOST_GID} /work' EXIT
    $GIT_SETUP
"'
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
    cd /work/openmls/openmls-wasm
    wasm-pack build --mode no-install --target web -- --locked --features extensions-draft
  '

# Drift guard: the lockfile (committed or freshly bootstrapped) must survive --locked.
cmp -s "$HERE/Cargo.lock" "$WORK/openmls/Cargo.lock" || {
  echo "ERROR: Cargo.lock changed despite --locked — pin drift; refusing the artifact." >&2
  exit 1
}

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
