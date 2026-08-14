# mls-state-b3-1 writer fixture

This directory freezes one synthetic provider snapshot written by the exact
B3.1 OpenMLS-WASM artifact before the B3.2 wrapper is added. It contains a
fresh MLS signing identity and one non-last-resort B3.1 KeyPackage using fixed
synthetic account-proof inputs. It contains no browser export, real identity,
conversation or user data.

The generated `context.json` records the public KeyPackage, its account and MLS
signature-key binding, its proof, advertised components and exact writer tuple.
The generated `envelope.json` records the provider snapshot that retains the
private KeyPackage bundle required to consume a matching Welcome.

The fixture is generated once with
`spikes/marmot-phase-b3-2/generate-b3-1-fixture.mjs` while the committed writer
WASM still has SHA-256
`26a41d86d7fd2c9ab4184344e4ff00f5eebb5bc7609ba22e98b12ce903d4a4dd`.
OpenMLS uses a CSPRNG, so the exact generated files are immutable and must not
be regenerated in place.

## Bound provenance

- Source head: `019da38921deca8b9bb9a4ca6544c827db8ef3ac`
- OpenMLS revision: `09e92777dba0528d3d29e2e5e681b7e91637c7be`
- Writer WASM: 2,094,818 bytes, SHA-256
  `26a41d86d7fd2c9ab4184344e4ff00f5eebb5bc7609ba22e98b12ce903d4a4dd`
- Generator: 6,246 bytes, SHA-256
  `00fb2f8130ee0e2c3f9637a8062264ba308a2394a8ab079abcadc4ab0a5504e4`
- `context.json`: 1,607 bytes, SHA-256
  `c0b48232b86778955da4e0cfb315e412c6480ca426a6ee03bb2ab292916e5b2d`
- `envelope.json`: 4,683 bytes, SHA-256
  `a7a951f8e1517ed7d457cb65db8b5c0f251cd756ba794e4db1f216a3a9814aaf`
- Provider payload: 3,121 bytes, SHA-256
  `0e9d2f54d92cf7cb2a7403e07449446aa1e64554979ae9749d19bf40bd703cad`
- Framed B3.1 KeyPackage: 435 bytes, SHA-256
  `45c37058e95ad78f8c211d5dfa61e523ed3964969fd78ecc2995ef11c8f8e819`
- Synthetic account private-key input: 31 zero bytes followed by `0x03`.
  It is public test material and must never be reused.
- Account-proof timestamp: `1786707600`.
- Self-check: `restore-identity-and-key-package-round-trip-pass`.

Stage 1 does not admit the writer tuple to a compatibility allowlist. Stage 2
may do so only if the separately approved candidate restores this exact payload
and consumes this exact KeyPackage through the bounded MDK Welcome join.
