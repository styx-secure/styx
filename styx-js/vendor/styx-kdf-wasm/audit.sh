#!/usr/bin/env bash
# Supply-chain checks for styx-kdf-wasm: cargo audit (RustSec advisories) and
# cargo deny (licenses, bans, sources, advisories), run inside the SAME pinned
# toolchain image as the build, with sha256-verified release binaries of both
# tools (no reliance on globally installed tooling).
# Requires: Docker, network (crates.io index + RustSec advisory DB).
set -euo pipefail

RUST_IMAGE="rust:1.96.1@sha256:1f0dbad1df66647807e6952d1db85d0b2bda7606cb2139d82517e4f009967376"
CARGO_AUDIT_VERSION="0.22.2"
CARGO_AUDIT_SHA256="7fb9497f8594b389e5fce5ef9b92db08432996895b2e0c5a0167a69ed445c428"
CARGO_DENY_VERSION="0.20.2"
CARGO_DENY_SHA256="9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f"

HERE="$(cd "$(dirname "$0")" && pwd)"

docker run --rm -v "$HERE:/crate:ro" -w /tmp \
  -e AV="$CARGO_AUDIT_VERSION" -e AS="$CARGO_AUDIT_SHA256" \
  -e DV="$CARGO_DENY_VERSION" -e DS="$CARGO_DENY_SHA256" \
  "$RUST_IMAGE" bash -c '
    set -euo pipefail
    an="cargo-audit-x86_64-unknown-linux-musl-v${AV}"
    curl -sSfLo /tmp/audit.tgz "https://github.com/rustsec/rustsec/releases/download/cargo-audit%2Fv${AV}/${an}.tgz"
    echo "${AS}  /tmp/audit.tgz" | sha256sum -c -
    tar -xzf /tmp/audit.tgz -C /tmp
    install "/tmp/${an}/cargo-audit" /usr/local/bin/cargo-audit
    dn="cargo-deny-${DV}-x86_64-unknown-linux-musl"
    curl -sSfLo /tmp/deny.tar.gz "https://github.com/EmbarkStudios/cargo-deny/releases/download/${DV}/${dn}.tar.gz"
    echo "${DS}  /tmp/deny.tar.gz" | sha256sum -c -
    tar -xzf /tmp/deny.tar.gz -C /tmp
    install "/tmp/${dn}/cargo-deny" /usr/local/bin/cargo-deny
    cp -r /crate /tmp/c && cd /tmp/c
    echo "=== cargo audit ==="
    cargo audit
    echo "=== cargo deny check ==="
    cargo deny --locked check
    echo "=== supply-chain checks passed ==="
  '
