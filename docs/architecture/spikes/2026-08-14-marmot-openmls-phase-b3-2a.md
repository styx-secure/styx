# Phase B3.2a: exact-profile durable-input Welcome preparation

Date: 2026-08-15

Issue: #175

Stage: **Stage 1 candidate evidence; Stage 2 not authorized**

Disposition: **candidate implementation passes the bounded Stage 1 checks run so far**

Installed artifact changed: **no**

Exact-pin MDK round trip established: **not yet; reserved for Stage 2**

Application traffic tested: **no**

## Question

Can Styx repair the B3.2 exact-profile mismatch without weakening historical
profiles, bind Welcome processing exclusively to exact durable predecessor
bytes, and produce one scratch-restorable canonical candidate for a closed
CAS journal?

Stage 1 answers only the source, parser, profile, state-machine and reproducible
candidate-artifact portions of that question. Installing the candidate tuple
and running the exact MDK peer require a separate Issue amendment and human
approval.

## Frozen source and dependencies

| Boundary | Exact value |
| --- | --- |
| Styx base commit | `675aa5e0e5ec9f0fdaae308953cd4c81863d90ea` |
| Styx base tree | `7a71c9eaa7d5713185ac3ee3986cc73c625bd06f` |
| OpenMLS source commit | `09e92777dba0528d3d29e2e5e681b7e91637c7be` |
| OpenMLS source tree | `fde242458abe5594fbebf2556dca0a135367a817` |
| Marmot commit / tree | `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1` / `10d941f358de5d9fe4ee1db75581f3e5363f5e92` |
| MDK commit / tree | `9396adb6aa6b95b521a7979facd5ea7040c07288` / `a1145de604e616634dae9a1ef6bf5033c9c9e879` |
| Vendored Cargo.lock SHA-256 | `33964e33f6a48e8b9982c5894c4a7e9ddc5ee2e5157c763596393a08c607672b` |
| External MDK Cargo.lock SHA-256 | `edb8c706e12934b8d94239203f73d24a2d480033c3ec6830f19d06c85a247b09` |
| Stage 1 Rust patch SHA-256 | `9d2b497f91e3065f6a7226954a421d97173e04ec9064d7e25377253632c4c996` |

No pin, lockfile, ciphersuite, dependency, manifest or historical Provider
serializer changed.

## Candidate artifact tuple

Two clean disposable builds from the exact source pin and the same Stage 1
patch produced byte-identical files. The files remain outside the repository at
`/home/mverde/.local/share/styx-b3-2a-runs/issue-175/stage1-post-review-20260815T023500Z/`.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `openmls_wasm.js` | 153005 | `f73093ae4f2f4a408e94a91512fe4ae45400e1b41cfe4d0384dddb7179430dfc` |
| `openmls_wasm.d.ts` | 55147 | `32aeca75d16efd5fe27e8f640ebea21e2f4f1e4abd27b2e8176af9573195f0f3` |
| `openmls_wasm_bg.wasm` | 2243925 | `31ea1e4dba48cb5a2492a6c65843fe5536f278085fbb12429ec4756c4fd434ff` |
| `openmls_wasm_bg.wasm.d.ts` | 31041 | `c2d0a05d2debf27c8afe2f87974b64f22fc3a0dce7dba933b31cc38cdfc40fd6` |
| `package.json` | 449 | `88f2ec1e2a5c1904b0fc1d147221c32ba6dcbf1cb4441c53b04a1b2a03bd1d85` |

The installed B3.2 tuple is unchanged. These candidate files must not be copied
into the repository unless the exact tuple and evidence are separately approved.

## Additive generated surface

The high-level TypeScript surface delta is additive:

- `PhaseB2Identity.b3_2a_key_package(...)`;
- `PhaseB32aKeyPackage`;
- `PhaseB32aPendingWelcome`, including one-use release, discard, preparation
  classification, second-candidate digest and differing-key evidence;
- `PhaseB32aJoinProjection`, including exact member-profile evidence and the
  `phase-b32a-provider-canonical-v1` format identifier;
- `PhaseB32aGroup`, which loads only canonical candidate bytes and reproduces
  the complete projection.

No historical high-level export was removed or renamed. Mechanical ordering in
the generated low-level WASM import/export declaration is not treated as a new
semantic surface.

## Exact profile result

The new constructor emits only the declared `STYX_B32A` profile. The closed
candidate validator accepts exactly two members:

- the joiner as `STYX_B32A`, with dictionary ids `[0x0001, 0x8009]`, no
  `safe_aad` entry and no default `required_capabilities` self-listing;
- the authenticated founder as `MDK_PIN_9396ADB`, with dictionary ids
  `[0x0001, 0x0002, 0x8009]`, the pinned optional empty `safe_aad` entry and the
  pinned default `required_capabilities` self-listing recorded as evidence.

Both profiles require the exact supported component list, exact proof-v2
binding and all existing GroupContext, administrator and lifecycle checks.
Hybrids, supersets, unknown/GREASE values, reordered or duplicate values and a
third member fail closed. This is an exact-pin experiment, not a general MLS or
Marmot receiver policy.

## Durable-input and candidate boundary

The new preparation entry point accepts only exact predecessor bytes and digest,
identity locators, exact Welcome, exact KeyPackage and expected founder identity.
It uses a private Provider, strict role-specific snapshot parsers and a sorted
candidate serializer. The legacy public Provider serializer and parser remain
unchanged.

Each unmodified candidate is scratch-restored through the canonical-order parser
and reproduces its own full projection. Candidate release owns no live Provider
or identity handle, is one-use, and returns only the already validated bytes.

The isolated JavaScript journal uses a new B3.2a namespace and the state sequence
`STABLE_ADVERTISED -> WELCOME_RECORDED -> JOINED`. It independently rechecks
every durable-input digest, both Schnorr identity proofs and the complete
projection. The `WELCOME_RECORDED -> JOINED` CAS is the sole authoritative join
linearization point. Local predecessor and candidate buffers are cleared on
success, engine rejection, persistence failure and CAS conflict.

## Exact-pin retention timestamp classification

Two independent OpenMLS preparations can differ because the pinned
`MessageSecrets.message_secrets.added_at` value is local wall-clock retention
metadata. Stage 1 therefore does not claim byte-reproducible snapshots.

The native comparator requires identical key sets, exactly one joined-group
`MessageSecrets` entry, and byte identity for every other value. Its strict,
bounded exact-pin JSON recognizer accepts either no difference or differences
confined to the canonical unsigned `secs_since_epoch` and
`nanos_since_epoch` leaves, with nanoseconds below one billion. It rejects
missing, duplicate, extra, renamed, reordered, malformed, wrong-type, negative,
overflowing or out-of-range fields and every difference elsewhere.

No candidate byte is rewritten or excluded from SHA-256. The exact first
candidate is the one released and eligible for the journal CAS. The second
candidate digest and classification are evidence only.

Primary upstream evidence:

- [Pinned OpenMLS past-secrets construction](https://github.com/openmls/openmls/blob/09e92777dba0528d3d29e2e5e681b7e91637c7be/openmls/src/group/mls_group/past_secrets.rs#L67-L81)
- [Pinned OpenMLS MessageSecrets representation](https://github.com/openmls/openmls/blob/09e92777dba0528d3d29e2e5e681b7e91637c7be/openmls/src/schedule/message_secrets.rs)
- [Pinned wasm clock implementation](https://github.com/daxpedda/web-time/blob/v1.1.0/src/time/system_time.rs#L19-L25)

## Stage 1 verification completed so far

- Native wrapper suite: 25 passed, 0 failed.
- Targeted artifact-independent Jest suite plus historical state restore and
  envelope tests: 75 passed, 0 failed.
- Full JavaScript Jest suite: 1,476 passed, 0 failed. Relay-dependent suites
  emitted their existing unavailable-local-relay warnings; no relay evidence is
  claimed by B3.2a.
- Two clean disposable builds: all five candidate files byte-identical.
- Candidate parser stability: exact candidate survives 200 canonical
  restore/serialize cycles in the native hostile suite.
- Historical native B3.2 fixtures: retained and green; an accidental local
  removal of the frozen fixture `group_id` field was detected by compilation and
  restored before the successful run.
- JavaScript hostile evidence includes profile hybrids, wrong proof and roles,
  head/blob corruption, digest rebinding, replay/state conflicts, persistence
  failure, CAS races, content-address collision and transient-buffer clearing.

Final Stage 1 diff checks and agent-enforcement results are recorded in the
Issue amendment after the Stage 1 source is committed. Any subsequent source or
tuple drift invalidates this evidence.

## Bounded conclusion

At the exact declared pins, the Stage 1 candidate can produce a fully
digest-bound Welcome candidate that is deterministic modulo the pinned OpenMLS
local `MessageSecrets.added_at` retention timestamp. The implementation keeps
each candidate unmodified, validates it by exact scratch restore and makes only
one candidate eligible for the authoritative CAS.

This is source and isolated harness evidence. Until Stage 2 is approved and the
exact MDK runs complete, it does not establish an exact-pinned durable restarted
MDK Welcome join.

## Residual risks and non-claims

- The candidate WASM is not installed, reviewed or approved.
- The Styx Rust patch and `extensions-draft` surface remain unaudited.
- The exact MDK pin still lists default `0x0003`; the exception expires on any
  pin or observed-profile drift.
- Neither Styx nor the exact MDK pin implements SafeAAD GroupContext framing.
- The journal is isolated filesystem evidence, not a product storage boundary;
  arbitrary power-loss atomicity and orphan secret-blob cleanup remain future
  requirements.
- File-journal locks fail closed and are never broken automatically. A crashed
  writer therefore requires explicit operator cleanup in this isolated harness;
  product-grade crash recovery remains a future requirement.
- Best-effort buffer clearing is not physical erasure and does not defend
  against a hostile browser origin, extension, operating system or device.
- No application message, Commit lifecycle, convergence, transport, metadata
  privacy, PWA, vault, multi-device or production claim is made.
