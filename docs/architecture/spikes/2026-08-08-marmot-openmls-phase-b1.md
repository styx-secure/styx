# Marmot / OpenMLS Phase B1 capability probe

- **Issue:** [#129](https://github.com/styx-secure/styx/issues/129)
- **Date:** 2026-08-08
- **Result:** **B1 capability demonstrated; B2 and B3 remain required**
- **Scope:** isolated local mechanics and legacy compatibility; no product or interoperability claim

## Executive conclusion

The OpenMLS revision already pinned by Styx can expose a second, isolated MLS
profile with the mechanics needed for a later Marmot compatibility experiment.
Without changing the shipping legacy API, this Phase B1 probe demonstrates:

- creation and strict inspection of a framed, non-last-resort KeyPackage using
  `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`;
- a raw 32-byte x-only Nostr account identity that is distinct from the leaf's
  Ed25519 MLS signing key;
- representation of application component `0x8009`, its capability, and one
  exact 104-byte account-identity-proof v2 value;
- original JavaScript construction and BIP-340 verification of that proof;
- WASM-owned, group/epoch/provider-bound staged inbound Commit handles that do
  not merge implicitly;
- explicit single-use merge/discard and local pending confirm/discard paths;
- exact continued acceptance of the committed pre-B1 legacy state tuple and
  rejection of unknown or mixed compatibility tuples.

This result is deliberately narrower than compatibility. No MDK peer, Marmot
transport event, Welcome delivery, last-resort KeyPackage, convergence rule,
durable publish lifecycle, or product module participates. Styx is **not yet
Marmot-compatible**, and no upstream audit applies to this code.

## Pinned inputs and produced artifacts

| Input | Pin |
|---|---|
| Styx base | `698599a0953f9063818b7ba4f17b00729c4746da` |
| OpenMLS source | `09e92777dba0528d3d29e2e5e681b7e91637c7be` |
| Marmot specification used for comparison | `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1` |
| Rust container | `rust:1.96.1@sha256:1f0dbad1df66647807e6952d1db85d0b2bda7606cb2139d82517e4f009967376` |
| wasm-pack | `0.15.0`, archive SHA-256 `c09f971ecaed9a2efc80fdcea7a00ef6b53c7fadc8c57d1f61b53a6aa66b668a` |
| OpenMLS feature | `extensions-draft` |

The OpenMLS source revision and committed `Cargo.lock` did not change. The
feature is enabled explicitly by the reproducible build command.

| Generated file | SHA-256 |
|---|---|
| `openmls_wasm_bg.wasm` | `61cce676c81366fc9c62752a09ea1547a4998ede7f144013ac5ade088e70a863` |
| `openmls_wasm.js` | `fab287f525a83fe8e0f2196d38efba7cf20e4b50e9fe91e062e235e78659f151` |

`vendor/openmls-wasm/verify.sh` performed two clean builds. Both generated
WASM files and both generated JavaScript bindings were byte-identical to each
other and to the committed artifacts.

## Architecture and isolation

The legacy and probe profiles coexist inside the same generated artifact but
have separate exported types and fixed behavior:

| Property | Legacy shipping API | Isolated `PhaseB1*` probe API |
|---|---|---|
| Ciphersuite | X25519 / ChaCha20-Poly1305 / SHA-256 / Ed25519 | X25519 / AES-128-GCM / SHA-256 / Ed25519 |
| Credential identity | existing UTF-8 hexadecimal Nostr key text | exactly 32 raw account-key bytes |
| KeyPackage encoding | existing bare KeyPackage | framed MLSMessage |
| Commit handling | existing automatic inbound merge | stage, inspect, then explicit merge/discard |
| Local Add | existing immediate legacy behavior | pending until explicit confirm/discard |
| Product imports | existing product path | none |

A repository test scans current `src` and `apps` JavaScript/TypeScript sources
and fails if they import the probe directory or reference a `PhaseB1` export.
The probe cannot be persisted through the current product envelope and no
shipping selector enables it.

## Identity proof boundary

The proof harness constructs the pinned account-identity-proof v2 shape from
synthetic keys. It canonicalizes the NIP-01 event, binds the x-only account key
to the distinct 32-byte Ed25519 leaf public key, encodes the creation time as an
unsigned 64-bit big-endian value, and verifies the 64-byte BIP-340 signature.
Its accepted proof length is exactly 104 bytes.

The JavaScript boundary accepts only direct `Uint8Array` instances with exact
lengths. It rejects buffers, views, subclasses, accessor-backed objects,
missing or trailing bytes, invalid x-only keys, changed account or leaf keys,
changed timestamps, and invalid signatures.

The Rust wrapper validates the MLS representation and the structural binding:
credential bytes, leaf signing key, suite, framing, lifetime, component and
capability lists, dictionary shape, proof length, and the proof's embedded
account bytes. It does not add a secp256k1 dependency and therefore does not
independently verify Schnorr inside WASM. B1 relies on the isolated JavaScript
proof verifier before constructing the probe identity. A future product policy
must make cryptographic proof validation an explicit trusted boundary rather
than treating structural parsing as authorization.

## KeyPackage result

The probe emits an MLSMessage-framed KeyPackage that is parsed back
canonically and checked for:

- ciphersuite `0x0001`;
- exact raw 32-byte `BasicCredential.identity`;
- a distinct 32-byte Ed25519 leaf signature key;
- a bounded seven-day Lifetime;
- no last-resort marker;
- application component capability `0x8009`;
- component support list containing exactly `0x8009`;
- an application-data dictionary containing the required component entries and
  one exact proof value;
- no trailing frame bytes.

Negative tests mutate lengths, identities, signatures, component data,
capabilities, frame bytes, and a real generated component identifier. Duplicate
or unsupported component structure fails closed.

## Explicit Commit lifecycle result

Inbound processing authenticates and stages a Commit but returns no plaintext
and does not advance epoch or membership. JavaScript receives an opaque
WASM-owned handle plus a bounded projection containing only proposal counts,
epoch, added-member credential identities, leaf signature keys, component ids,
and capability ids.

The handle is single-use and bound to:

- the provider instance;
- the provider restore generation;
- the concrete group instance and group id;
- the prior epoch.

Explicit merge advances the group exactly once. Explicit discard leaves the
group unchanged. Reuse, wrong-provider use, wrong-group use, stale-epoch use,
and use after provider restoration fail closed. Local Add returns Commit and
Welcome bytes while OpenMLS retains pending state; explicit confirmation
applies it once, while discard clears it without advancing the epoch.

This is a memory-only capability surface. It does not yet make pending or
staged transitions durable and it does not define which authenticated proposal
combinations an application is authorized to accept.

## Legacy compatibility evidence

The persisted envelope schema, schema version, database layout, product worker
protocol, legacy ciphersuite, credential encoding, and public
`MlsEngine`/`MlsSession` semantics are unchanged.

Compatibility is an allowlist of complete tuples, not independent field
allowlists:

| State identity | OpenMLS revision | Artifact SHA-256 | Ciphersuite |
|---|---|---|---|
| pre-B1 fixture | `09e92777dba0528d3d29e2e5e681b7e91637c7be` | `b56e3ea095c3be3dc9a589e27ad2092bcc6de663cc788db30853e89c02ff386a` | legacy ChaCha20-Poly1305 suite |
| Phase B1 artifact | `09e92777dba0528d3d29e2e5e681b7e91637c7be` | `61cce676c81366fc9c62752a09ea1547a4998ede7f144013ac5ade088e70a863` | legacy ChaCha20-Poly1305 suite |

Tampered hashes, changed revisions or suites, unknown hashes, malformed
metadata, and cross-products fail before provider restoration. The committed
fixture's `envelope.json`, `context.json`, and `generate.js` bytes are
unchanged. The restore test decrypts its committed post-snapshot ciphertext and
creates a reply from restored state. The live legacy round-trip independently
proves peer decryption in both directions under the rebuilt artifact.

## Verification performed

The Phase B1-specific evidence includes:

- native Rust wrapper tests on the exact source, lockfile, feature, and pinned
  container: 3 passed, 0 failed;
- four focused Jest suites covering profile, proof, staging, state restore, and
  envelope compatibility: 51 passed, 0 failed;
- the legacy `roundtrip.mjs` probe: passed;
- the isolated `spikes/marmot-phase-b1/probe.mjs` probe: passed;
- two clean reproducible builds: passed, exact hashes above.

The complete local contract matrix passed:

| Command | Result |
|---|---|
| `cd styx-js && npm ci` | passed; lockfile unchanged |
| `cd styx-js && npm test -- --testTimeout=20000` | 84 suites and 1,109 tests passed |
| legacy and Phase B1 Node probes | both passed |
| pinned native Rust test script | 3 tests passed |
| two-build WASM verification | passed, byte-identical artifacts |
| `cd styx-js/apps/chat && npm ci && npm run build` | passed |
| documentation claims lint | 45 files scanned, 0 findings |
| agent-enforcement unit tests | 44 tests passed |
| diff whitespace and scope checks | passed |

The root Jest run reported the existing environment-conditional skips for its
three local-relay integration suites because no relay was running. The B1
profile, staging, legacy restore, and artifact-integrity tests all executed and
passed. Exact-candidate GitHub CI remains a separate gate; local results are not
reported as CI evidence.

## Licensing and provenance

No Marmot, MDK, Darkmatter, or Least Authority source, test, fixture, vector,
example, or prose was copied or adapted. The probe is an independent Styx
implementation of pinned public protocol facts and constants, using synthetic
keys generated by its own tests.

The existing path classifications remain unchanged: the OpenMLS derivative and
generated material retain their existing classifications, while new Styx
scripts, harness code, tests, and this report remain under the repository's
AGPL-3.0-or-later default. No permissive interoperability surface, licensing
policy change, affiliation, endorsement, certification, or audit inheritance is
created by B1.

## Required B2 work

B1 must not be connected to the product until a separate approved B2 contract
defines and verifies at least:

1. a closed authorization whitelist for every permitted Commit and proposal
   shape, including Add, Update, Remove, PSK, ReInit, group-context extension,
   external Commit/join, and application-data changes;
2. proof and immutable-identity validation for every proposed and resulting
   member leaf before merge;
3. durable publish-before-apply with atomic persistence of pending bytes,
   acknowledgement state, provider state, epoch transition, and recovery data;
4. fail-closed behavior for quota failure, eviction, crash, reload, retry,
   duplicate acknowledgement, and a crash between remote publication and local
   merge;
5. explicit resynchronization for epoch forks that cannot be repaired from
   durable state;
6. deterministic handling of competing valid same-epoch Commits and all
   convergence/fork cases relevant to the selected profile;
7. bounded storage, projection, skipped-key, and hostile-input policies;
8. a decision about where Schnorr proof verification belongs in the trusted
   product architecture.

## Required B3 work

B3 must establish compatibility as an observed fact rather than an inference:

- generate and consume profile KeyPackages with an independent, pinned MDK
  implementation;
- exchange Welcome, Commit, application data, and required external framing in
  both directions;
- compare exact credential, extension, capability, component, lifetime, and
  MLSMessage wire behavior;
- exercise transport-author and account-proof checks across the implementation
  boundary;
- run hostile and concurrency cases derived independently from the selected
  specification and audit findings;
- publish provenance-clean conformance vectors only under a separately approved
  licensing decision;
- document every intentional divergence and avoid any compatibility claim until
  the selected independent peer accepts the complete round trip.

## Residual risks

- `extensions-draft` expands the compiled parser surface for the shared
  artifact even though the product does not select the probe.
- The local OpenMLS patch and all `PhaseB1*` exports are outside upstream and
  Marmot-family audit scope.
- A finite historical fixture cannot prove every past browser state or storage
  failure mode.
- WASM-owned handles reduce accidental JavaScript misuse but do not protect
  against origin-controlled code using the worker or WASM as an oracle.
- B1 has no durable pending-epoch state machine, authorization policy,
  convergence, delivery, metadata protection, or independent peer evidence.
- Reproducibility and passing tests are supply-chain and regression evidence,
  not a security audit or production-readiness proof.
- The documented browser, operating-system, extension, malicious-recipient,
  metadata, screen/key-logging, physical-erasure, and rollback limits remain.

## Decision

Phase B1 answers its bounded capability question with **GO**: the unchanged
OpenMLS pin can support the isolated mechanics without altering the legacy
shipping profile. It does not authorize B2, B3, product integration, migration,
or deployment. Those remain separate human-gated decisions.
