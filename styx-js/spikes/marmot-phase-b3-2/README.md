# Marmot Phase B3.2 — durable embedded-tree Welcome join

This directory contains an isolated, non-product interoperability experiment.
It tests one exact direction at pinned revisions: MDK founds a current-profile
group and emits a Welcome for a Styx B3.1 KeyPackage; Styx admits that Welcome
only when the RatchetTree is embedded in encrypted GroupInfo.

The bounded success condition ends after Styx has:

1. persisted the exact predecessor Provider and non-last-resort KeyPackage
   before public exposure;
2. durably recorded the exact Welcome before passing it to OpenMLS;
3. prepared and fully validated a join using a cloned Provider and no external
   RatchetTree;
4. released a digest-bound candidate exactly once;
5. restored and reprojected that candidate before one atomic `JOINED` head CAS;
6. selected the candidate from a fresh Provider; and
7. repeated the same verification in a new process.

Before the `JOINED` CAS, `activationState()` always returns the predecessor and
the recorded Welcome remains retryable. After it, only the content-addressed
candidate is authoritative. Provider-state hashes bind exact bytes within this
operation; they are not logical group identities across arbitrary restores.

The JavaScript projection validates every account-identity-proof v2 Schnorr
signature before durability, in addition to the structural validation in the
native wrapper. Records are closed and canonical. The file harness stores
immutable content-addressed blobs and replaces its single head atomically under
an owner-PID CAS lock. These are local experimental filesystem guarantees, not
general power-loss guarantees.

## Files

- `b3-2-canonical.mjs` defines bounded values, typed errors, the complete
  canonical projection and transcript chain.
- `b3-2-journal.mjs` implements the three-state private journal and its memory
  and process-persistent CAS stores.
- `b3-2-styx-driver.mjs` owns the isolated WASM Provider, validates two
  independent preparations, releases the candidate once and activates only
  through the journal.
- `b3-2-mdk-driver.mjs` is the bounded JSONL adapter and account-proof signer
  for the existing Styx-authored exact-pin MDK peer.
- `b3-2-orchestrator.mjs` runs the exact flow and records a chained transcript
  plus a bounded GO, NO-GO or BLOCKED report.
- `generate-b3-1-fixture.mjs` reproduces the frozen outgoing-writer fixture.
- `verify-pins.mjs` fails closed on source, artifact or external MDK drift.

## Boundaries

This experiment does **not** establish full Marmot compatibility, production
readiness, application traffic, Commit lifecycle, transport privacy, PWA or
vault integration. B3.3 owns application-message and restart evidence. No
product code imports or selects this directory.

Stage 1 does not install generated WASM. After the exact generated tuple is
approved and installed in Stage 2, the harness is invoked twice with fresh,
empty paths beneath:

```text
/home/mverde/.local/share/styx-b3-2-runs/issue-173
/home/mverde/.local/share/styx-b3-2-private/issue-173
```

The private child is deleted after evidence extraction; the run child retains
only the synthetic transcript and report.
