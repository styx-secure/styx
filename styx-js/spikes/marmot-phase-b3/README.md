# Phase B3: exact-pin Styx/MDK interoperability probe

`STYX_SPIKE_PROTOTYPE` — isolated synthetic evidence for Issue #165. This
directory is not imported by product code and is not suitable for real data.

## Result

The exact pinned peers reproducibly reach a bounded **NO-GO before group
creation**.

Styx creates and durably restores a non-last-resort, ciphersuite `0x0001`
KeyPackage using the installed B2.7 OpenMLS-WASM artifact. MDK accepts the exact
framed bytes at its public `CreateGroupRequest.members` boundary, parses them,
and rejects their capabilities because the Styx KeyPackage advertises
application components `0x8003`, `0x8009` and `0x800c`, but not the MDK-required
`marmot.group.profile.v1` component `0x8001`.

The MDK outcome is the typed error
`mdk_missing_required_capabilities`; the Styx-side classification is
`STYX_KEY_PACKAGE_MISSING_MDK_REQUIRED_GROUP_PROFILE_COMPONENT`. The harness
does not reinterpret either outcome as compatibility.

This is the first observed incompatibility. The probe therefore does not reach
Welcome processing, application traffic, Commit processing or restart traffic.
Those later operations remain untested, not failed.

That result is historical evidence for Issue #165. Later bounded phases add
new exact profiles and RPC operations without relabelling or weakening this
NO-GO. In particular, B3.3a uses the same pinned MDK adapter only after an exact
B3.2a group has been established; it does not claim that the original B3
KeyPackage became compatible.

Issue #188 additively extends that adapter for the isolated B3.3b-1 sequential
self-update probe. The extension does not change the historical B3 result or
activate any product path. It keeps MDK's `PendingStateRef` process-local,
requires publication outcomes to match the exact transport message id, and
recovers a fresh pending reference only through the pinned public
`drain_auto_publish` API after restart.

## Strict JSON-lines RPC operations

Every request is an exact-field JSON object containing `id` and `op`. Unknown
fields and unknown operations fail closed. Binary inputs and outputs are
lowercase hexadecimal and remain subject to the peer's fixed line/field bounds.

| Operation | Required additional fields | Bounded purpose |
|---|---|---|
| `hello` | none | Report the frozen adapter protocol, MDK revision and direct synthetic envelope. |
| `initialize` | `account_identity_hex`, `database_key_path`, `database_path`, `node_binary`, `signer_script`, `signer_secret_path` | Open the encrypted MDK store and current-profile engine. |
| `create_group` | `key_package_hex` | Create the exact current-profile two-member group and return one Welcome. |
| `confirm_published` | `welcome_message_id_hex` | Acknowledge the independent durable Welcome-delivery obligation. |
| `public_projection` | none | Return MDK's public conformance snapshot for the selected group. |
| `restore_group` | `group_id_hex` | Select and validate an already durable group after a fresh process starts. |
| `send_application` | `payload_hex` | Validate a Marmot inner event and return MDK's durably prepared MLS application ciphertext. |
| `ingest_group_message` | `group_message_hex` | Ingest one direct-envelope MLS message and release plaintext only from the exact authenticated `MessageReceived` event. |
| `self_update` | none | Prepare one exact public self-update through `SendIntent::SelfUpdate`; retain its process-local pending reference until a matching publication outcome. |
| `drain_auto_publish` | none | After restart, recover at most one byte-identical durable group evolution and register only its newly issued process-local pending reference. |
| `confirm_group_published` | `message_id_hex` | Apply the exact registered group evolution through `confirm_published` and require one matching epoch transition. |
| `fail_group_publication` | `message_id_hex` | Roll back the exact registered group evolution through `publish_failed`; this is not valid after ambiguous or successful publication. |
| `ingest_group_evolution` | `group_message_hex` | Ingest an exact peer Commit and accept only one matching epoch transition, or an explicit duplicate/own-echo disposition. |
| `checkpoint_and_exit` | none | Drop the process after all preceding synchronous durable operations complete. |
| `destroy` | none | Drop the in-process engine and group selection; private-file removal remains orchestrator-owned. |

An MDK error after entering an application-message mutation boundary is fatal
to that peer process. It returns `mdk_peer_quarantined` once and exits, so a
possibly queued application event cannot be drained by a later RPC call.

## Frozen inputs

- Styx base: `925554ef89921ee6b6fa8ea1c976ed3a05977a26`, tree
  `48899a558c67e9ec0aad8a6814a1d56078d2f54c`
- OpenMLS source: `09e92777dba0528d3d29e2e5e681b7e91637c7be`
- OpenMLS-WASM SHA-256:
  `ed5e740d9c93aa46aa1afb7b6065e4b5b92be972a8a080ddd0a35091260691bb`
- Marmot specification: `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1`,
  tree `10d941f358de5d9fe4ee1db75581f3e5363f5e92`
- [MDK](https://github.com/marmot-protocol/mdk):
  `9396adb6aa6b95b521a7979facd5ea7040c07288`, tree
  `a1145de604e616634dae9a1ef6bf5033c9c9e879`, upstream `Cargo.lock`
  SHA-256 `edb8c706e12934b8d94239203f73d24a2d480033c3ec6830f19d06c85a247b09`
- MDK license: MIT, copyright 2024–2026 Internet Privacy Foundation

No MDK source, fixture or generated artifact is copied into this repository.
The local AGPL test executable consumes the exact Git dependencies through
Cargo and is `publish = false`.

## Layout

- `verify-pins.mjs` fails closed on repository scope, immutable inputs, clean
  upstream checkouts, license identity and the exact driver manifest.
- `b3-styx-driver.mjs` creates the synthetic Styx account, KeyPackage and
  durable provider state, then reloads it before public exposure.
- `mdk-peer/` is an original strict JSON-lines Rust adapter over MDK public
  production APIs. Its direct `TransportPeeler` is an identity envelope; it
  does not parse, repair or rewrite MLS payloads.
- `b3-mdk-driver.mjs` validates the RPC surface and supplies the synthetic
  BIP-340 account-proof signature through MDK's public signer callback.
- `b3-orchestrator.mjs` runs the peers, hash-links public evidence and deletes
  the exact private-state child even on failure.
- `b3-canonical.mjs` contains strict parsers and report/transcript validators.

## Reproduction

Build and test the peer first:

```bash
cd styx-js/spikes/marmot-phase-b3/mdk-peer
cargo build --locked
cargo test --locked
```

Then run two fresh probes from `styx-js/`:

```bash
node spikes/marmot-phase-b3/b3-orchestrator.mjs \
  --run-dir /home/mverde/.local/share/styx-b3-runs/issue-165/run-a \
  --private-dir /home/mverde/.local/share/styx-b3-private/issue-165/run-a
node spikes/marmot-phase-b3/b3-orchestrator.mjs \
  --run-dir /home/mverde/.local/share/styx-b3-runs/issue-165/run-b \
  --private-dir /home/mverde/.local/share/styx-b3-private/issue-165/run-b
npm test -- --runInBand --testTimeout=20000 -- \
  mls-phase-b3-mdk-interop.test.js
```

Run and private directories must be new strict children of their frozen roots.
The orchestrator refuses an existing directory and never overwrites evidence.

## Evidence boundary

Public run artifacts contain only synthetic public protocol bytes, hashes,
typed outcomes and projections. Private MLS provider state, init keys,
SQLCipher database/key, account signing secrets and decrypted non-synthetic
content are forbidden. Private state is created with owner-only permissions and
removed before the command returns.

## Smallest hypothetical remedy

A later, separately approved increment could extend the Styx current-profile
KeyPackage capability set and validated application-component model with
`marmot.group.profile.v1` (`0x8001`), rebuild the pinned WASM boundary, and
repeat B3 from a new immutable baseline. Issue #165 freezes that interface and
artifact, so it cannot apply or validate this remedy.

## Non-claims

B3 did not establish Styx/MDK interoperability at the tested pins. It does not
establish Marmot conformance, Nostr interoperability, transport security,
metadata privacy, anonymity, production readiness or suitability for
whistleblowing, accounting, legal evidence or any real sensitive data.
