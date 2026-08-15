# Phase B3.3a: durable exact-profile application traffic

`STYX_SPIKE_PROTOTYPE` — isolated synthetic evidence for Issue #185. This
directory is not imported by product code and must never process real data.

## Bounded question

Can the exact B3.2a Styx and pinned-MDK peers exchange MLS application
messages in both directions, commit every sender/receiver ratchet mutation
before ciphertext or plaintext is released, restart from durable state, reject
replays without releasing plaintext twice, and continue exchanging messages?

B3.3a does not exercise Commit processing, epoch changes, fork choice or
convergence. Those belong to B3.3b.

## Trust and durability boundary

- The Rust `PhaseB33a*` surface loads only the sorted B3.2a canonical Provider
  bytes and revalidates the closed two-member profile before every operation.
- Every operation consumes its group handle. Its one-use pending handle binds
  state and message bytes to SHA-256 digests before release.
- The JavaScript adapter independently re-verifies both account identity
  proofs and binds the authenticated MLS sender to the frozen B3.2a roster.
- Outbound state and ciphertext are committed by one authoritative CAS before
  ciphertext is returned. Inbound state, ciphertext, plaintext and sender
  evidence are committed and read back before plaintext is returned.
- Duplicate inbound ciphertext returns only a typed duplicate result. It does
  not read or release the original plaintext.
- Persistence failure and CAS loss fail closed. Best-effort buffer clearing is
  not a physical-erasure claim.

## Components

- `b3-3a-canonical.mjs`: strict codecs, limits and closed report/transcript
  validation.
- `b3-3a-artifact-reader.mjs`: descriptor-bound, no-symlink reads tied to the
  exact candidate tuple before JavaScript or WASM execution.
- `b3-3a-journal.mjs`: isolated in-memory and owner-only file-backed CAS
  journals.
- `b3-3a-engine-adapter.mjs`: trusted write-ahead boundary around the one-use
  WASM operations.
- `b3-3a-styx-driver.mjs`: fresh-process Styx peer that imports a disposable
  candidate tuple without installing it.
- `b3-3a-mdk-driver.mjs`: strict fresh-process JSON-lines boundary around the
  pinned MDK executable.
- `b3-3a-mdk-signer.mjs`: owner-only synthetic proof signer for the pinned MDK
  public signer callback.
- `b3-3a-orchestrator.mjs`: exact two-peer sequence, restart/replay checks,
  hash-linked evidence and private-state deletion.
- `verify-pins.mjs`: frozen source, tree, lockfile and five-file candidate
  verification.

The pinned MDK adapter and its RPC table remain in
`../marmot-phase-b3/mdk-peer/` and `../marmot-phase-b3/README.md`.

## Stage separation

Stage 1 produces and reviews a source candidate plus two byte-identical clean
builds. It does **not** install the candidate into `vendor/openmls-wasm/`.
Installation is forbidden until the owner approves the exact source
commit/tree, Rust patch digest, unchanged Cargo lock digest and full five-file
tuple.

Stage 2 installs only that approved tuple and performs two new, disjoint exact
runs. Development runs are diagnostic evidence, not substitutes for those
post-installation runs.

During Stage 1, the vendored integrity verifier is expected to report a tuple
mismatch only when both isolated builds are byte-identical to each other and
that reviewed candidate intentionally differs from the still-installed B3.2a
tuple. Any other verification failure is blocking. After the approved tuple is
installed in Stage 2, the same verifier must exit successfully. Each Stage 2
run also rebuilds the pinned MDK peer from its locked, clean source checkout and
records the resulting source and executable identity in its evidence.

## Stage 1 commands

From the documented directories:

```bash
cd styx-js/vendor/openmls-wasm && ./test.sh
cd styx-js/spikes/marmot-phase-b3/mdk-peer && cargo test --locked
cd styx-js && npm test -- --runInBand --testTimeout=20000 -- mls-phase-b3-3a
```

Build candidates must be new strict children of
`/home/mverde/.local/share/styx-b3-3a-builds/issue-185/`. Run and private
directories must likewise be new strict children of their frozen roots. The
orchestrator refuses existing directories and always removes the exact private
state child before returning.

## Evidence and non-claims

Public reports contain synthetic public event bytes, hashes, exact artifact
digests and typed outcomes. Account secrets, SQLCipher keys/databases and MLS
Provider state remain private and are deleted after a run.

Even a bounded `GO` proves only application-message interoperability at the
declared pins and sequence. It does not establish general Marmot conformance,
Commit interoperability, convergence, transport security, metadata privacy,
anonymity, production readiness, audit inheritance or suitability for
whistleblowing, accounting, legal evidence or real sensitive data.
