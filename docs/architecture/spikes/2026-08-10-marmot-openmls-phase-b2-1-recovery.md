# Phase B2.1: restore-safe OpenMLS recovery boundary

Status: experimental capability evidence; not a product or interoperability
claim.

Issue #147 adds the smallest recovery surface needed to evaluate later Marmot
convergence work without activating Marmot or changing the shipping MLS
ciphersuite. The implementation remains pinned to OpenMLS commit
`09e92777dba0528d3d29e2e5e681b7e91637c7be`.

## Result

The isolated Phase B1 wrapper can now reload an identity and group from a fully
serialized provider, inspect pending-Commit state, confirm or clear a pending
Commit with an epoch precondition, and verify the restored group's own public
identity. Group operations are bound to the provider instance and restore
generation that created or loaded the object. They also compare the in-memory
group with a fresh durable load before reporting or mutating pending state.

The generated Phase B2.1 artifact is:

- WASM SHA-256:
  `d0399fddc2ed5f030927f9786d295c394bcdfa133a1c69feeb9514edf2cd6f01`;
- WASM length: `1970752` bytes;
- unchanged OpenMLS revision and legacy product ciphersuite;
- reproducible from the pinned Rust image, wasm-pack binary and Cargo lockfile.

The public typed delta is exactly seven Phase B1 recovery members. Pinned
`wasm-bindgen` additionally emits the reviewed, non-enumerable
`PhaseB1Identity.__wrap` implementation helper; it is absent from TypeScript
declarations and is not a standing wildcard allowance.

## Recovery evidence

The native wrapper suite covers successful restore and the fail-closed cases for
wrong providers, restore-generation confusion, stale duplicate groups, epoch
mismatch and identity mismatch. The JavaScript probe exercises six bounded
recovery branches:

1. founding Add Commit confirmation after restore;
2. founding Add Commit discard after restore;
3. non-founding Add Commit confirmation after restore;
4. non-founding Add Commit discard after restore;
5. exact-byte inbound Commit re-staging and merge after restore;
6. exact-byte inbound Commit re-staging and discard after restore.

The committed recovery tests also restore two historical state-writer fixtures:

- the pre-B1 fixture written by artifact `b56e3ea0…`;
- the Phase B1 fixture written by artifact `61cce676…`.

For both, the current runtime must recover the identity and group, validate the
two-member set, decrypt a post-snapshot application message and produce a
non-empty reply. Compatibility remains an exact tuple of OpenMLS revision, WASM
digest and ciphersuite; fields are never accepted as independent allowlists.

## Security boundary

This work prevents several object-confusion and stale-state paths from becoming
silent success. A wrong provider, provider restore after object acquisition,
missing durable group, stale duplicate group, epoch disagreement, pending-state
disagreement or malformed identity input returns an error before a storage
write. A persistence or product lifecycle layer must still journal Commit bytes
and publication state; provider serialization alone cannot reconstruct those
events.

The capability does not provide:

- a Proposal/Commit policy whitelist or staged inbound policy decision;
- same-epoch convergence, fork selection or automatic resynchronization;
- Marmot/MDK wire compatibility or an independent-peer round trip;
- browser storage durability, multi-tab exclusion or origin compromise defence;
- product activation in the reference chat, PWA, vault or worker.

The wrapper changes and fixtures are Styx-authored and are outside upstream
OpenMLS, Marmot and Least Authority audit scope. Green reproducibility and
recovery tests are evidence for this bounded result, not a production-readiness
or security-certification claim.

## Follow-up

The next lifecycle contract can use this boundary to define durable Commit
journaling and policy-controlled merge. It must retain exact compatibility
tuples for every artifact that may have written live state and must not infer
Marmot conformance from this recovery probe.
