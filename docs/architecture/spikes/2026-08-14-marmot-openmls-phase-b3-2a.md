# Phase B3.2a: exact-profile durable-input Welcome preparation

Date: 2026-08-15

Issue: #175

Stage: **post-review tuple installed; fresh Stage 2 verification pending**

Disposition: **pending fresh evidence at the post-review tuple**

Installed artifact changed: **yes; exact human-approved five-file tuple**

Exact-pin MDK round trip established: **yes; two independent runs**

Application traffic tested: **no**

## Question

Can Styx repair the B3.2 exact-profile mismatch without weakening historical
profiles, bind Welcome processing exclusively to exact durable predecessor
bytes, and produce one scratch-restorable canonical candidate for a closed
CAS journal?

Stage 1 answered the source, parser, profile, state-machine and reproducible
candidate-artifact portions of that question. The separately approved Stage 2
installed that exact tuple and exercised it twice against the exact MDK pin.

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
| Post-review Rust patch SHA-256 | `56bfa7e7439f3a5dce260930b0ba19604581177de8092170a1f057592de30a7c` |

No pin, lockfile, ciphersuite, dependency, manifest or historical Provider
serializer changed.

## Installed artifact tuple

Two clean disposable builds from the exact source pin and the approved
post-review patch produced byte-identical files. The build evidence remains at
`/home/mverde/.local/share/styx-b3-2a-runs/issue-175/post-review-c68aac6/`.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `openmls_wasm.js` | 153005 | `f73093ae4f2f4a408e94a91512fe4ae45400e1b41cfe4d0384dddb7179430dfc` |
| `openmls_wasm.d.ts` | 55147 | `32aeca75d16efd5fe27e8f640ebea21e2f4f1e4abd27b2e8176af9573195f0f3` |
| `openmls_wasm_bg.wasm` | 2243916 | `f1596c27c90f71e50998bfae1be212e6b016944e18fe3c3fecee1eb44e64f869` |
| `openmls_wasm_bg.wasm.d.ts` | 31041 | `c2d0a05d2debf27c8afe2f87974b64f22fc3a0dce7dba933b31cc38cdfc40fd6` |
| `package.json` | 449 | `88f2ec1e2a5c1904b0fc1d147221c32ba6dcbf1cb4441c53b04a1b2a03bd1d85` |

The Issue #175 post-review approval bound this exact tuple to source commit
`c68aac60acd4c7c5ec249213c80a38971cc40562`, tree
`efb25a2d810db2dd014f504853c365b8ca1f8116`, the patch digest above and the
unchanged Cargo.lock digest. No different artifact was installed.

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
or identity handle and is one-use. It consumes the pending wrapper before all
caller-controlled validation: success transfers only the already validated
bytes, while every rejection wipes and clears the candidate and makes retry
fail closed.

The isolated JavaScript journal uses a new B3.2a namespace and the state sequence
`STABLE_ADVERTISED -> WELCOME_RECORDED -> JOINED`. It independently rechecks
every durable-input digest, both Schnorr identity proofs and the complete
projection. The `WELCOME_RECORDED -> JOINED` CAS is the sole authoritative join
linearization point. Local predecessor and candidate buffers are cleared on
success, engine rejection, persistence failure and CAS conflict.
File-backed head and blob reads bind the size check and content read to the
same open descriptor, so an atomic path replacement cannot bypass the resource
envelope between a pathname `stat` and a later read.

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

## Verification

- Native wrapper suite: 26 passed, 0 failed.
- Targeted artifact-independent Jest suite plus historical state restore and
  envelope tests: 75 passed, 0 failed.
- Full JavaScript Jest suite: 101 suites and 1,483 tests passed, 0 failed. Relay-dependent suites
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

Stage 2 added the exact-pin MDK/Styx harness and produced two fresh runs. Both
reported `GO`, used member profiles `[MDK_PIN_9396ADB, STYX_B32A]`, classified
the independently prepared candidate difference as
`RETENTION_TIMESTAMP_BOUNDED`, committed the first unmodified candidate through
the sole `JOINED` CAS, scratch-restored it, and restored it again after a fresh
Node process restart. The private run directories were removed after each run.

| Evidence | Run A | Run B |
| --- | --- | --- |
| Report SHA-256 | `6feabcb1dfb2024b0c7a95437c11c1a1a3ebc1edc0cacff17fe8bd882bf3d062` | `5f74edb7808e447ab8d73bb4101f75ec43cca238ad5e80fe3848a9032a433145` |
| Transcript SHA-256 | `8ca36b0cee1646558c58215af3b2b3da4d41965cf8261eafc36205689eafa6f3` | `e2d7bead40c9600ca26ed0f65fa72a99110e5713636de9eb05900c457c83fb20` |
| Transcript head | `3cd931dd2bca539a230aaf484476a22debe52c1a465615e3c44ee8164b5acf9d` | `49e682ab2adbb6e0fc500237b27f4e64ad4e3a3e75c46d86d1c6383e9213dd56` |

The paired evidence proves only the bounded claim below. Random identities,
groups and ciphertexts intentionally make byte-for-byte report equality neither
expected nor required. Any subsequent source, pin or installed-tuple drift
invalidates the evidence.

## Bounded conclusion

At the exact declared pins, MDK accepts the exact Styx B3.2a KeyPackage, creates
an embedded-tree Welcome, and Styx durably records, validates, commits and
restores the joined candidate after a fresh process restart. The implementation
keeps each candidate unmodified and makes only the first validated candidate
eligible for the authoritative CAS. This is a bounded exact-profile Welcome
join result, not a general compatibility or application-traffic claim.

## Residual risks and non-claims

- The installed WASM tuple is reproducible and independently reviewed, but the
  Styx-authored Rust patch and its `extensions-draft` surface remain unaudited.
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
