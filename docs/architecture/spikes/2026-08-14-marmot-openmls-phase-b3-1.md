# Phase B3.1: exact `0x8001` capability closure

Date: 2026-08-14

Issue: #167

Disposition: **NO-GO at the next typed boundary**

Compatibility established: **no**

## Question

Can an isolated Styx OpenMLS profile advertise and process the exact Marmot
group-profile component required by pinned MDK, without changing the frozen B2
product profile or weakening persisted-state compatibility?

## Approved change

The approved candidate adds one isolated generated surface,
`PhaseB31KeyPackage`, and one B3.1-only constructor member. It installs the
exact five-file artifact tuple recorded in Issue #167. The current WASM digest
is:

```text
26a41d86d7fd2c9ab4184344e4ff00f5eebb5bc7609ba22e98b12ce903d4a4dd
```

The outgoing B2.7 artifact remains an exact, bounded compatibility reader. No
existing B2 component set, reader, validator or product activation path was
changed.

## Method

The fail-closed harness performed these operations twice with fresh state:

1. verify the approved base, Stage 1 source head/tree, exact artifact tuple,
   generated surface, lockfiles, external repositories and B2.7 fixture;
2. create a synthetic B3.1 identity and KeyPackage;
3. persist the Styx provider and restart before exposing the KeyPackage;
4. decode the emitted KeyPackage and require the exact supported component set
   `[0x8001, 0x8003, 0x8009, 0x800c]`;
5. ask the pinned MDK peer to create the founding group;
6. project MDK's resulting GroupContext through a strict Rust evidence schema;
7. independently decode `marmot.group.profile.v1` in JavaScript and require
   exact byte equality with the expected founding state;
8. acknowledge publication and attempt the bounded Welcome join;
9. stop at the first incompatible operation, write a canonical hash-linked
   report/transcript, and delete private run state.

## Evidence

Both runs established all of the following:

- `mdkAcceptedB31Advertisement: true`;
- `styxDurableRestart: true`;
- exact emitted supported components
  `[0x8001, 0x8003, 0x8009, 0x800c]`;
- exact MDK GroupContext components
  `[0x0001, 0x8001, 0x8003, 0x800c]`;
- exact MDK required components
  `[0x8001, 0x8003, 0x8009, 0x800c]`;
- `styxDecodedMdkProfile: true`;
- `exactProfileByteEquality: true`.

Stable canonical content digests:

| Evidence | SHA-256 |
| --- | --- |
| Group-profile state | `67b0033c2ec0c46eb9f36b23e54b205ba8a10312b5e32450fab88225b212b720` |
| Founding name | `0b36b36e8851b0ea4cee211eeda24d38338397c74b1b059caf5af2cd283b1220` |
| Founding description | `16a7183bfcc5b1105caf1c64a673adf7009bb083e16e7469a78ee25c1855b80d` |

Public evidence locations:

```text
/home/mverde/.local/share/styx-b3-1-runs/issue-167/run-a
/home/mverde/.local/share/styx-b3-1-runs/issue-167/run-b
```

Transcript heads:

```text
run-a  115b3b07d3887c6492c93d2c2351e16d0572d6ed22e3c27343ae9046e07dd4a9
run-b  d14f508bafc8a7db17f4d19afa14352deee118a647a8afd22db2ce793b075ff6
```

Fresh cryptographic material makes GroupContext, projection, KeyPackage,
Welcome and transcript digests intentionally different across runs. The typed
sequence, exact component sets, canonical profile bytes and first incompatible
operation are the reproducible invariants.

## First incompatible operation

Both runs stopped at:

```text
styx_join_mdk_welcome
```

MDK reports that the RatchetTree is embedded in encrypted GroupInfo, while the
bounded public Styx join surface requires a `PhaseB2RatchetTree` argument. The
typed Styx outcome is:

```text
STYX_PUBLIC_JOIN_REQUIRES_EXTERNAL_RATCHET_TREE
```

This boundary is later than the B3 failure: MDK no longer rejects Styx for
missing `0x8001`, and the exact profile is present and byte-compatible.

## Conclusion

B3.1 answers its narrow question positively: the exact `0x8001` capability gap
can be closed in an isolated profile without changing the frozen B2 product
surface, and pinned MDK creates a group whose profile state Styx decodes
exactly.

The overall experiment remains `NO-GO`. No claim is made for Welcome join,
message exchange, commit/update processing, restart after MDK-originated state,
Marmot wire conformance, product activation or production security. A future
contract may investigate an explicit, public RatchetTree delivery mechanism;
this Issue does not authorize that design or implementation.

## Verification

The contract verification includes the exact pin verifier, locked Rust build and
tests, two fresh harness runs, hash-linked evidence tests, vendored WASM
reproducibility/integrity checks, the full JavaScript suite, chat production
build, agent enforcement and documentation lint. Exact final commands and
results are recorded in the Pull Request evidence rather than broadened here.
