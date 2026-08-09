# Marmot/OpenMLS Phase B2.0 durable-restore feasibility

Status: **GO for the next separately contracted B2 increment**

Date: 2026-08-09

Authority: Issue #145 (`styx-task-contract:v1`)

Issue-body SHA-256: `96909d3cb68e5abe3a57eb89ff6f93a29da1e15ddb122d3d761008b7f6bbba00`

## Decision

The bounded Phase B2.0 feasibility probes pass. The exact pinned OpenMLS engine
can restore the durable state needed to recover locally pending Add and
self-update Commits, can re-stage an inbound PublicMessage Commit from its exact
bytes after a fresh-provider restore, and can represent the current required
Marmot GroupContext and member-leaf structure used by this probe.

This GO applies only to planning the next separately approved B2 increment. It
does not authorize a production API, persisted product format, migration,
policy engine, transport integration, convergence implementation, or B3
interoperability claim.

## Exact inputs

| Input | Exact value |
| --- | --- |
| Styx base | `8db17f6c9351abddf9ce802cf9163b3ce63a1ac9` |
| OpenMLS | `09e92777dba0528d3d29e2e5e681b7e91637c7be` |
| Marmot specification evidence | `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1` |
| MDK comparison source (not executed or copied) | `9396adb6aa6b95b521a7979facd5ea7040c07288` |
| Rust image | `rust:1.96.1@sha256:1f0dbad1df66647807e6952d1db85d0b2bda7606cb2139d82517e4f009967376` |
| Probe ciphersuite | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` |
| B1 WASM SHA-256 | `61cce676c81366fc9c62752a09ea1547a4998ede7f144013ac5ade088e70a863` |
| B1 generated JavaScript SHA-256 | `fab287f525a83fe8e0f2196d38efba7cf20e4b50e9fe91e062e235e78659f151` |

The implementation adds only native Rust test code inside the existing
`#[cfg(test)]` module. It adds no wasm-bindgen export and changes no generated
file, dependency, feature, pin, manifest, lockfile, product module, or persisted
product schema.

## Probe results

### Local pending Commit recovery

Result: **PASS**.

The founding Add matrix starts from epoch 0 with one member and a retained
pending Add Commit. One observed synthetic run produced a complete provider
snapshot of 19,484 bytes with SHA-256
`5f16dc745d33712ebb77bfc494c8ae9210b005cdc985a3591e5737bce06f3404`.
Fresh providers restored independently from that snapshot demonstrated both
recovery choices:

- merge once reached epoch 1 and two members;
- a second merge returned the pinned engine's no-op success and did not change
  epoch or membership;
- the joining peer consumed the retained Welcome and exported ratchet tree;
- both peers exchanged and decrypted fresh application messages in both
  directions;
- clear retained epoch 0 and one member, persisted the absence of pending
  state, survived another fresh-provider restore, and then successfully created
  and merged a new Add of the same test shape with bidirectional application
  liveness.

The same matrix was repeated for a non-founding self-update created at epoch 1
in a stable two-member group. One observed synthetic run produced a complete
provider snapshot of 18,493 bytes with SHA-256
`48486b9b2202ff16e39753d834d813eaab2dfbdf7ae3d7b5632dcbae5198d4c0`.
The merge branch converged both peers at epoch 2, and its second merge was also
a no-op that did not advance state. The clear branch remained at epoch 1,
survived a second restore, created a fresh self-update, converged at epoch 2,
and exchanged application data both ways.

These hashes identify those individual synthetic observations only. Fresh
cryptographic randomness changes the snapshots, and raw provider-map iteration
order is not canonical.

### Inbound re-staging after restore

Result: **PASS**.

The sender created an Add Commit in a stable two-member group under an explicit
test-only plaintext outgoing-wire policy. Exact MLSMessage parsing confirmed
that the Commit body was a PublicMessage. The receiver was snapshotted before
staging, staged without merging, and was snapshotted again.

Observed measurement:

| State | Bytes | SHA-256 |
| --- | ---: | --- |
| pre-stage | 10,486 | `a566d5de41197b50db29f1cff3a817568432fb2444bbae605dca4a1b0380c503` |
| post-stage | 10,486 | `a566d5de41197b50db29f1cff3a817568432fb2444bbae605dca4a1b0380c503` |

The raw blobs were equal and their decoded key/value maps were equal. On this
pin and test shape, staging did not write provider state. After discarding the
receiver's in-memory group and staged object, a fresh provider restored from
the pre-stage snapshot loaded the exact group, re-staged the identical Commit
bytes, merged once to epoch 2 and three members, rejected replay without a
second state advance, and exchanged fresh application messages with the
converged sender in both directions.

### Current profile representation

Result: **PASS**.

The test constructed a new group whose authenticated GroupContext:

- requires app components `0x8003`, `0x8009`, and `0x800c`;
- contains initial admin-policy component `0x8003` with the founder account as
  its one non-empty active administrator;
- contains lifecycle component `0x800c` with the exact one-byte `active` value
  `0x00`; and
- requires MLS proposal capability `app_data_update` (`0x0008`).

The founder leaf and the joined peer leaf advertise support for all three
required components and `app_data_update`. Each contains exactly one `0x8009`
entry at the valid LeafNode location with the required 104-byte structural
shape and a signer key equal to its BasicCredential identity. A second party
joined through the Welcome and exported ratchet tree and observed the same
GroupContext, capability, placement, and proof-shape facts.

The proof bytes are synthetic and the test deliberately checks structure, not
NIP-01/BIP-340 authorization. This is not an account-proof cryptographic
validator.

### Negative decoding evidence

Result: **PASS**.

Separate negative cases prove that:

- the pinned OpenMLS AppDataDictionary exact decoder rejects duplicate
  component entries;
- exact decoding rejects malformed/truncated dictionary bytes;
- exact decoding rejects a valid dictionary followed by trailing bytes; and
- the Styx test-only exact profile decoder rejects a RequiredCapabilities value
  that omits `app_data_update`.

The first three are OpenMLS/exact-codec behavior. The final case and the
admin/lifecycle/location checks are Styx-authored test assertions only. They are
not described as OpenMLS validation, complete Marmot authorization, or a
reusable production policy engine.

## Commands and evidence

| Command | Result |
| --- | --- |
| Issue #145 scope preflight at base=head | PASS; no changed paths |
| `cd styx-js/vendor/openmls-wasm && ./test.sh` | PASS; 6 native tests, 0 failed |
| exact-pin B2 tests with `--nocapture` | PASS; 3 B2 tests; measurements above |
| `cd styx-js/vendor/openmls-wasm && ./verify.sh` | PASS; two reproducible builds, both artifacts match B1 |
| `cd styx-js && npm ci` | PASS |
| `cd styx-js && npm test -- --testTimeout=20000` | PASS; 85 suites, 1,149 tests |
| documented relay infrastructure plus the three relay suites | PASS; 3 suites, 19 tests, no relay skip |
| `cd styx-js && node vendor/openmls-wasm/roundtrip.mjs` | PASS |
| `cd styx-js && node spikes/marmot-phase-b1/probe.mjs` | PASS |
| `cd styx-js/apps/chat && npm ci && npm run build` | PASS |
| docs claims lint | PASS; 47 files, 0 findings before this report |
| agent-enforcement unit tests | PASS; 54 tests |
| `git diff --check` | PASS before report finalization |

The initial all-Jest run reported the repository's expected relay-unavailable
skips because the documented test relay was not running. Those skips were not
accepted as green evidence: the relay was started and all three affected suites
were run again successfully with 19/19 tests.

Final exact-HEAD CI, final scope evidence, and independent implementation
reviews remain PR gates and are not represented as complete by this local
report.

## Artifact and API invariants

Two clean release builds were mutually byte-identical and byte-identical to the
committed B1 artifacts:

- `openmls_wasm_bg.wasm`:
  `61cce676c81366fc9c62752a09ea1547a4998ede7f144013ac5ade088e70a863`;
- `openmls_wasm.js`:
  `fab287f525a83fe8e0f2196d38efba7cf20e4b50e9fe91e062e235e78659f151`.

Therefore this increment changes no release export or generated binding. The
only executable additions are removed by `#[cfg(test)]` in release builds.

## Recovery consequences for later B2 work

Raw `Provider.serialize_state()` SHA-256 is not stable across providers or
restores and must not be used as a B2 durable snapshot identity. The format
serializes a map whose entry order is not canonical. The inbound probe therefore
compared decoded key/value maps independently of raw order as well as recording
raw bytes, lengths, and hashes.

Recovery used native pinned OpenMLS storage APIs and necessarily bypassed
volatile B1 handles. `PhaseB1PendingAdd` and `PhaseB1StagedCommit` cannot survive
a restart. B2 recovery must persist durable facts such as group id, prior epoch,
exact Commit bytes, and a digest; it must never persist or reconstruct a B1
handle as if it were durable authority.

The tested Commit shapes contain inline proposals only. Standalone proposal
store residue is outside B2.0 and must be covered before B2 permits stored or
referenced proposals.

## Provenance

The test design was written specifically for Issue #145 from the public pinned
OpenMLS APIs and the pinned Marmot specification facts recorded above. No
Marmot, MDK, Darkmatter, Least Authority, or other third-party implementation
code, test, fixture, vector, or prose was copied or adapted. MDK was not built or
executed in this increment.

## Limits and residual work

Native in-module tests can access private wrapper state and native OpenMLS APIs;
they do not prove a safe JS/WASM API. Memory-provider restore does not prove
IndexedDB transaction atomicity, browser eviction behavior, crash durability,
multi-tab coordination, or recovery UX. The profile test proves
representability and structural inspection, not full Marmot authorization or
wire interoperability.

B2 still requires separately contracted work for the durable
pending/published/merging/stable lifecycle, exact policy projection and
identity-proof binding, same-epoch convergence, fork detection/recovery,
adversarial lifecycle tests, and browser storage integration. B3 remains
necessary for independent MDK round-trip evidence. Neither upstream audits nor
these probes transfer audit coverage to Styx, and Styx is not yet
Marmot-compatible.

Existing browser-origin, compromised-device or extension, metadata,
malicious-recipient, physical-erasure, and rollback limitations remain.
