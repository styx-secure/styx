# Marmot Phase B3.1 — isolated `0x8001` capability closure

This directory contains the bounded interoperability experiment authorized by
Issue #167. It is not a product runtime and does not establish Marmot
interoperability or product readiness.

## What changed

Stage 1 froze a synthetic state fixture written by the outgoing `ed5e740d…`
artifact, implemented a strict independent codec for
`marmot.group.profile.v1`, and prepared an isolated B3.1 KeyPackage profile.
After the exact candidate tuple and generated surface were approved, Stage 2
installed that tuple and ran the exact-pin MDK probe twice.

The B3.1-only KeyPackage advertises exactly:

```text
[0x8001, 0x8003, 0x8009, 0x800c]
```

The frozen `PhaseB2*` component sets, readers, group validation and persisted
state remain unchanged. Product code cannot construct the B3.1 profile.

## Result

Both `run-a` and `run-b` produced the same typed boundary:

- MDK accepted the emitted B3.1 KeyPackage;
- MDK created the founding group;
- MDK's GroupContext contained exactly `[0x0001, 0x8001, 0x8003, 0x800c]`;
- MDK required exactly `[0x8001, 0x8003, 0x8009, 0x800c]`;
- the independent Styx codec decoded MDK's `0x8001` bytes and proved exact byte
  equality with the canonical founding profile;
- the bounded flow then stopped at `styx_join_mdk_welcome`, before Welcome
  parsing, because wasm-bindgen requires the public Styx join wrapper's external
  `PhaseB2RatchetTree` argument while the exact MDK path keeps the tree inside
  encrypted GroupInfo.

The disposition is therefore `NO-GO`, with
`compatibilityEstablished: false`. B3.1 closed the exact missing-`0x8001`
capability gate; it did not establish end-to-end Styx/MDK interoperability.

Stable profile evidence across both runs:

```text
profile state SHA-256: 67b0033c2ec0c46eb9f36b23e54b205ba8a10312b5e32450fab88225b212b720
name SHA-256:          0b36b36e8851b0ea4cee211eeda24d38338397c74b1b059caf5af2cd283b1220
description SHA-256:   16a7183bfcc5b1105caf1c64a673adf7009bb083e16e7469a78ee25c1855b80d
```

GroupContext, projection, KeyPackage, Welcome and transcript digests differ
between runs by design because each run uses fresh cryptographic material.

## Run

The peer must first be built from its locked dependency graph:

```bash
cd styx-js/spikes/marmot-phase-b3/mdk-peer
cargo build --locked
cargo test --locked
```

Then run the probe with new, empty directories:

```bash
node styx-js/spikes/marmot-phase-b3-1/b3-1-orchestrator.mjs \
  --run-dir /home/mverde/.local/share/styx-b3-1-runs/issue-167/run-a \
  --private-dir /home/mverde/.local/share/styx-b3-1-private/issue-167/run-a
```

The orchestrator verifies all pins before creating state, writes only canonical
public evidence under the run directory, and removes the corresponding private
directory in a `finally` block. Existing run directories are rejected.
The public evidence includes measured provider-state and restored-leaf-key
commitments, an independently recomputed Welcome digest, and strict schemas for
each MDK response. The public join ceiling records that Welcome parsing was not
attempted.

## Files and boundaries

- `b3-1-canonical.mjs` defines strict canonical encodings, report schemas,
  transcript chaining, pins and scoped paths.
- `b3-1-styx-driver.mjs` owns the isolated WASM provider, persists before public
  exposure, restarts, and produces the B3.1 KeyPackage.
- `b3-1-mdk-driver.mjs` is the bounded JSONL adapter to the exact Rust peer.
- `b3-1-orchestrator.mjs` executes the fail-closed probe and records the first
  incompatible operation.
- `verify-pins.mjs` verifies source history, trees, artifact tuple, lockfiles,
  external checkouts, licenses, the outgoing B2.7 fixture and the exact base
  identity of the four files admitted only as Git copy-detection operands.
- `generate-b2-7-legacy-fixture.mjs` is one-shot and must never overwrite its
  checked-in synthetic fixture.

The report intentionally excludes Welcome bytes, provider state, database
contents, signer secrets and private key material.
