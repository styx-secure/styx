# Phase B3.2: durable embedded-tree MDK Welcome join

Date: 2026-08-14

Issue: #173

Disposition: **NO-GO at the first typed exact-pin incompatibility**

Compatibility established: **no**

Durable restarted Welcome join established: **no**

Application traffic tested: **no**

## Question

Can the exact pinned MDK founder create an embedded-RatchetTree Welcome for an
exact Styx B3.1 non-last-resort KeyPackage, and can the isolated Styx B3.2 path
validate and durably activate that candidate across a fresh process restart
without mutating the predecessor Provider?

The approved contract also accepts a reproducible typed NO-GO at the first
earlier incompatibility. It forbids weakening either peer to manufacture a
successful result.

## Installed candidate

Stage 2 installed only the five-file tuple separately approved in Issue #173:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `openmls_wasm.js` | 126900 | `e46684332ea0cb885988a2ff2cf6c6519b46d0f78125bb828b8a1b4b258ad09c` |
| `openmls_wasm.d.ts` | 45179 | `60af6c9ffb9a0d4acb7a5fd16e762adc31626de33ec4e9ff225e7c86a4bec5e2` |
| `openmls_wasm_bg.wasm` | 2139387 | `d281d4a4c3c72999e966c1e70bff68b0ddc5eda23653295adbf620bad723f62c` |
| `openmls_wasm_bg.wasm.d.ts` | 24849 | `e2b96efae4fab9be193ae32b24927d0a34aca4c5d427f3d9563fba8e6c309bbe` |
| `package.json` | 449 | `88f2ec1e2a5c1904b0fc1d147221c32ba6dcbf1cb4441c53b04a1b2a03bd1d85` |

The OpenMLS, Marmot and MDK revisions, dependency lockfiles and ciphersuites did
not change. The generated surface is frozen at 70,501 canonical JSON bytes with
SHA-256 `91b6d584a5612678ff7b9d1fd6551bf299ee4fceb9e74858ddfe3e2ed3ddc860`.

Before admitting the outgoing B3.1 state-writer tuple, the B3.2 artifact restored
the exact synthetic B3.1 Provider fixture, reloaded its identity and parsed and
rebound its exact non-last-resort KeyPackage. The old WASM digest
`26a41d86d7fd2c9ab4184344e4ff00f5eebb5bc7609ba22e98b12ce903d4a4dd`
is therefore retained only as an exact fixture-proven compatibility tuple.

## Method

The fail-closed harness performed the following sequence twice with fresh
cryptographic material and disjoint private state:

1. verify the exact base, OpenMLS/Marmot/MDK pins, MDK tree and lockfile, outgoing
   B3.1 writer and installed B3.2 artifact;
2. create and durably persist a synthetic Styx B3.1 identity, Provider and exact
   non-last-resort KeyPackage before exposure;
3. initialize the exact pinned MDK peer with a separate synthetic account;
4. have MDK create the group and one Welcome containing its RatchetTree only in
   encrypted GroupInfo;
5. validate the returned MDK schema and Welcome digest;
6. persist the exact Welcome and advance the private journal from
   `STABLE_ADVERTISED` to `WELCOME_RECORDED` before invoking OpenMLS;
7. prepare the Welcome on a clone with external RatchetTree argument structurally
   absent and equal to `None` in Rust;
8. stop at the first typed incompatibility, retain only the synthetic public
   report/transcript and delete the private state.

The `JOINED` CAS was never attempted. The predecessor remained authoritative
and the Welcome remained retryable up to private-state disposal.

## Reproducible evidence

Both formal runs produced the same operation sequence, classification and outer
typed error:

```text
verify_pins
styx_advertise_durable_b31_key_package
mdk_hello
mdk_initialize
mdk_create_group_with_embedded_tree_welcome
styx_durable_welcome_recorded_before_engine
first_typed_incompatibility: B32_ENGINE_REJECTED
```

Public evidence locations:

```text
/home/mverde/.local/share/styx-b3-2-runs/issue-173/run-a
/home/mverde/.local/share/styx-b3-2-runs/issue-173/run-b
```

| Evidence | run-a | run-b |
| --- | --- | --- |
| Report SHA-256 | `a94ca64a57383c3d314f49c56703744bfa9a1891ddb96e63839bf20a93ac8f50` | `27613d9f62d8e756dab9a00e20dca24726f64d8adb251232cc16c99f64463c25` |
| Transcript SHA-256 | `8b58df2e61906740560b4f25fa9e506624a0e191ff01fa165f13c76c06067254` | `8981036a00fa363bf81b75114b4742f3414e5d392773023250ffcd568c8fb5d8` |
| Transcript head | `ef0add577b13c50a22037de3608b4f41bccb0b4e04ec6e7ac1269e04bef81ca1` | `23d8d2c126a85a5f4ae1cdf962c263f1206f042dacec8f52a631170023c8a121` |
| Group id | `ff0fc54d4c809fcdb82e648268f95388` | `5431d952e2aca81d253716d95d504cb4` |
| Welcome SHA-256 | `7f73ce5f87d3b66f47cc99422449fb5d43106bf8977e8649952ff55e0ead5a7a` | `852d26b24427e3370a229bb0f980cebfbcfaa7f247f0fac77bf711abced70d0e` |

The differing group ids, Welcome bytes, GroupContexts, identities and transcript
heads prove fresh randomness. The ordered operations, structural MDK projection,
failure class and first rejected boundary are stable.

## First incompatible operation

Both runs reached the same boundary immediately after durable Welcome recording:

```text
PhaseB32PendingWelcome.prepare(...)
B32_ENGINE_REJECTED
```

The isolated wrapper preserved the more specific native detail
`PHASE_B32_WELCOME_AUTHOR_PROFILE_INVALID` in the in-memory error cause. A
non-writing diagnostic replay exposed that existing detail; it did not alter the
candidate, formal runs or repository.

The authenticated Welcome author is MDK's founder leaf. The pinned MDK projection
shows this exact capability advertisement in both runs:

```text
extensions:    [0x0003, 0x0006]
app components:[0x0001, 0x8001, 0x8003, 0x8009, 0x800c]
```

The Styx B3.1 KeyPackage leaf advertises:

```text
extensions:    [0x0006]
app components:[0x8001, 0x8003, 0x8009, 0x800c]
```

The B3.2 wrapper intentionally reused the exact B3.1 leaf validator, whose first
gate requires full equality with the Styx capability object. It therefore rejects
the MDK founder before candidate construction. The account identity, signature
key and proof are not treated as accepted merely because the outer Welcome is
authenticated.

This result does not decide whether a future Styx profile should admit a strictly
validated MDK capability superset or whether the peer profiles should converge
elsewhere. Either choice changes a frozen protocol validation rule and requires
a separate approved security decision. B3.2 does not relax the equality check.

## Conclusion

B3.2 establishes that the exact pinned MDK path accepts Styx's B3.1 advertisement,
creates an embedded-tree Welcome, and reaches Styx only after the Welcome has
been durably recorded. It also establishes a reproducible incompatibility at the
authenticated founder-leaf capability profile.

It does **not** establish a joined candidate, restart after join, application
traffic, full Marmot compatibility, product activation or production security.
No product path changed and no security promise was reduced. A subsequent
contract must decide the capability-profile rule before attempting the B3.3
application-message/restart objective.

## Residual risks and non-claims

- The installed Rust patch and `extensions-draft` surface remain unaudited.
- Provider state compatibility is demonstrated only by committed fixtures and
  exact tuples, not arbitrary migration.
- The journal is an isolated filesystem experiment, not a browser or product
  durability guarantee.
- Commit lifecycle, convergence, transport privacy, metadata protection, PWA,
  vault and hostile-device behavior remain untested here.
- The successful steps and NO-GO use only synthetic data and exact current pins;
  they do not transfer audit or conformance status from any upstream project.

## Verification

The contract verification includes native wrapper tests, two byte-identical
rebuilds compared with the installed tuple, legacy round trip, exact locked MDK
tests, pin verification, both formal runs, the full JavaScript suite, chat
production build, agent enforcement and documentation-claims lint. Exact final
command results are recorded in PR #174 evidence.
