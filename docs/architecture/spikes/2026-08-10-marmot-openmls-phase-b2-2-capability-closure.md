# Phase B2.2 OpenMLS capability-closure evidence

Status: **NO-GO pending relay-infrastructure amendment**

This report evaluates the source-only Stage 1 authorized by Issue #149. The
OpenMLS capability itself passed its native, generated-JavaScript,
reproducibility and retained-surface checks. Stage 1 is nevertheless not called
GO because the exact moving relay image required by the contract changed and
the mandatory full relay run is not green. That failure is recorded rather
than waived.

Passing results in this report are capability evidence only. They do not
activate Phase B2 in a product, verify the BIP-340 account-identity proof, prove
Marmot interoperability, or establish production readiness.

## Frozen inputs

- Contract: Issue #149, Stage 1, approved body SHA-256
  `10ad40928019b5f9c2793d0c760b25209a96e3fa8bacc1541a5da5d723b64ae3`.
- Base: `0bcd19f114ad1dd9cc419a8c53f0d53d33428ac0` on `main`.
- Stage-1 source head evaluated by this report:
  `571b031d9da6bba2528c5789a4609d86a3749d25`.
- SHA-256 of the binary-safe `base..source-head` diff:
  `b43609f7fb3bb17a3c7cf4ee5b9b44b31efeb40001fc014ae522a0c02593ac0c`.
- OpenMLS: `09e92777dba0528d3d29e2e5e681b7e91637c7be`, with the existing
  `extensions-draft` feature.
- Marmot specification evidence:
  `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1`.
- MDK comparison evidence:
  `9396adb6aa6b95b521a7979facd5ea7040c07288` (not executed or copied).
- Rust build image:
  `rust:1.96.1@sha256:1f0dbad1df66647807e6952d1db85d0b2bda7606cb2139d82517e4f009967376`.

The only source changes at the evaluated head are the authorized wrapper patch
and two new independently written probes. The review corrections add test-only
Rust code after the production module and generated-JavaScript probe assertions.
Two fresh builds prove that those corrections leave all five candidate
artifacts byte-identical to the previously recorded Stage-1 candidate. No
generated binding, binary, manifest, lockfile or product path differs in Stage
1.

## Implemented boundary

Seven parallel classes are added without changing a retained named export:

1. `PhaseB2Identity`
2. `PhaseB2KeyPackage`
3. `PhaseB2RatchetTree`
4. `PhaseB2Group`
5. `PhaseB2PendingCommit`
6. `PhaseB2StagedCommit`
7. `PhaseB2CommitProjection`

The boundary uses ciphersuite `0x0001`, PublicMessage Commits, independent
Ed25519 MLS leaf keys, exact 32-byte account credentials, exact 104-byte
identity-proof components, strict required components, a canonical
administrator policy and active lifecycle state.

Local Add, Remove and self-update operations return single-use pending handles;
inbound Commits return single-use staged handles. No operation implicitly
merges. Handles are bound to the provider instance, group instance, restore
generation and prior epoch. Durable pending state can be inspected, confirmed
or cleared only after strict provider, epoch and own-identity checks.

The projection captures the authenticated OpenMLS sender before consuming the
processed message, every admitted inline proposal, the update-path replacement
leaf, the complete ordered candidate member set, and the complete candidate
GroupContext. Referenced proposals and unresolved AppDataUpdate Commits fail at
the exported staging boundary with their stable errors. The pure policy
predicate also assigns distinct stable errors to inline Update, Custom and
other proposal kinds, but those shapes are rejected or normalized by the
pinned OpenMLS API before they can reach this boundary and are recorded only as
defence-in-depth coverage.

Before confirm or merge, WASM independently recomputes the exact
`STYX-B2-VERIFIED-LEAVES-v1` digest over all candidate leaves. The JavaScript
probe independently reconstructs the bounded preimage and obtains the same
SHA-256. This is a state-binding check, not BIP-340 verification; that remains
B2.4 work.

## Bounds and stable failures

The production checks and native tests cover these exact maxima and errors:

| Bound | Maximum | Error |
| --- | ---: | --- |
| queued proposals | 32 | `PHASE_B2_PROPOSAL_LIMIT` |
| Adds per Commit | 8 | `PHASE_B2_ADD_LIMIT` |
| occupied candidate leaves | 4096 | `PHASE_B2_MEMBER_LIMIT` |
| component ids per leaf | 64 | `PHASE_B2_COMPONENT_LIMIT` |
| GroupContext TLS bytes | 1,048,576 | `PHASE_B2_GROUP_CONTEXT_LIMIT` |

Counts and serialized sizes are checked before capacity allocation or exported
copying. The implementation never truncates a projection.

## Generated surface snapshot

The composition probe compares the committed B2.1 module with the disposable
candidate and records:

- exact named-export additions;
- constructor, static and prototype property descriptors, including function
  arity, for every new runtime class;
- exact generated TypeScript declaration members for every new class;
- the complete raw `InitOutput` member delta;
- the non-enumerable, arity-one `PhaseB2Identity.__wrap` generated helper and
  its single generated call site; and
- exact equality of all 17 retained named exports and their class surfaces.

The complete textual snapshot emitted at source head
`571b031d9da6bba2528c5789a4609d86a3749d25` is 24,183 bytes and has SHA-256
`6090ac29fcc257e54d58251f63853990f65e0fb8cc2bd83156f2ee524b9fc3a8`.
Its final marker is `PASS PHASE_B2_2_COMPOSITION_EXACT`. The generated
declaration digest below is the independent artifact identity that will freeze
the exact public types in a Stage-2 amendment.

## Reproducible disposable artifacts

Builds `issue149-opus-close.9lvBRH` and
`issue149-opus-close-b.trZvYz` were produced independently from the exact final
source patch. `cmp` succeeded for all
five files. Their complete generated-surface snapshots are also byte-identical:
15,839 bytes with SHA-256
`0a49c88bb7e465ec058c08acf6df69b750b35ec90f9e3ea5be101c8777f1de66`.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `openmls_wasm.js` | 101,919 | `50599ddc433619fd617d8071990f1edb94866388028c6875a493c7ac7ec1de7d` |
| `openmls_wasm.d.ts` | 35,074 | `17daa548987cdde22b9704921264ce85ec8ad70411eee255f544de70cd8e5d30` |
| `openmls_wasm_bg.wasm` | 2,074,265 | `60dbbc1127fbfb0e7e479cf7e2f7e6e20183c60d0559268f039d8db58bf60a3a` |
| `openmls_wasm_bg.wasm.d.ts` | 19,195 | `dc6ae4ce69782b70c483caf06f0bc2b8691ed99b4540239352df408609c89473` |
| `package.json` | 449 | `88f2ec1e2a5c1904b0fc1d147221c32ba6dcbf1cb4441c53b04a1b2a03bd1d85` |

Neither disposable directory is inside the repository, and none of these
generated files has entered the Stage-1 branch.

## Test results

### Green capability and regression evidence

- `styx-js/vendor/openmls-wasm/test.sh`: 16 passed, 0 failed. This includes all
  12 pre-existing tests and four B2.2-owned tests.
- The generated-JavaScript capability probe passed against both disposable
  builds. It exercised current-profile creation, KeyPackage inspection,
  Add/join, independent candidate-digest recomputation, wrong-digest rejection,
  self-update, inbound discard and exact re-stage, merge, Remove, bidirectional
  liveness, serialization, fresh-provider restore, durable pending confirm and
  clear, wrong epoch/account/signature-key/length rejection with provider-state
  equality, replay-after-clear rejection, PrivateMessage and non-Commit
  rejection, malformed framing rejection, and rejection of a genuine B1
  KeyPackage at the generated B2 boundary.
- Native hostile-input evidence constructs and authenticates a standalone Add
  proposal, a referenced Commit, a standalone Update proposal, and an
  AppDataUpdate Commit with the pinned OpenMLS API. It observes the real
  `Reference` and `UnresolvedAppDataCommit` shapes and drives both authenticated
  Commit byte strings through the exported `stage_inbound_commit` method. On a
  native non-WASM target, construction of the returned `JsError` deliberately
  traps at the wasm-bindgen boundary; the tests catch that target limitation and
  prove provider-state equality before/after, while the exact stable error is
  asserted from the same authenticated staged proposal or unresolved Commit.
  Generated WASM additionally exercises exact exported-wrapper errors where
  those inputs are constructible (PrivateMessage, non-Commit, B1 KeyPackage and
  durable recovery). Non-constructible inline Update/Custom/Other cases retain
  exact typed unit coverage and are not represented as end-to-end evidence.
- Native negative coverage also exercises the production GroupContext validator
  with an administrator absent from the supplied candidate-member set. The
  eight-byte administrator-policy case is explicitly a non-canonical prefix
  rejection; target-width `usize` overflow remains reasoned rather than claimed
  as an x86_64 test result.
- The same candidate probe repeated the retained B2.1 founding/non-founding
  confirm/clear matrix and exact inbound re-stage merge/discard behavior.
- Each required marker is emitted only after its minimum evidence count passes:
  exported composition 2, public Commit framing 3, policy projection 5,
  verified-leaf binding 5, and exact surface delta 2. The canonical evidence
  manifest SHA-256 is
  `13abc21785fb3d81450fde207bdd1548e98e2182913a9df2c0b8d1612eccb608`.
  `PHASE_B2_POLICY_PROJECTION` attests the five admitted positive projection
  shapes only; fail-closed proposal-policy rejection is separately evidenced by
  the native authenticated-hostile-input test above.
- `node vendor/openmls-wasm/roundtrip.mjs`: passed.
- `node spikes/marmot-phase-b1/probe.mjs`: passed.
- Reference chat `npm ci && npm run build`: passed. Existing npm audit output
  reported six dependency findings; no dependency or lockfile change is in
  scope.
- Agent-enforcement: 54 tests passed.
- Claims-lint: 10 tests passed; repository scan reported zero findings.
- Translation-sync: 20 tests passed; repository check reported zero findings.
- Full Jest with a disposable corrected relay configuration: 85/85 suites and
  1,151/1,151 tests passed with no relay skip. The configuration was external
  evidence only and did not modify a repository path.

### Mandatory relay finding

The contract resolves `ghcr.io/hoytech/strfry:latest` at execution time. It now
resolves to
`ghcr.io/hoytech/strfry@sha256:d6b31e8ab32e159f98d250b90aa6a62b9b47c468efdd311341597f60198861e1`,
reporting `strfry 1.1.1-119-g9acdaeb`.

The repository configuration exposes two independent upstream-default
dependencies:

1. the image runs as uid/gid 1000 while the compose file creates
   `/app/strfry-db` as a root-owned tmpfs, producing
   `mdb_env_open: Permission denied`; and
2. when the repository configuration omits `relay.auth`, this image defaults
   `restrictedReadKinds` to `4, 1059`. The real-time tests publish kind 1059
   but do not negotiate NIP-42 authentication, so writes are logged while reads
   time out.

A disposable external-only experiment set the tmpfs to
`uid=1000,gid=1000,mode=0700` and made the auth policy explicit:
`enabled=true`, empty `serviceUrl`, empty `restrictedReadKinds`, and
`restrictReadToInvolvedPubkey=true`. With the exact image digest above, the
complete relay-backed Jest run passed 85/85 suites and 1,151/1,151 tests without
a relay skip. This isolates the cause as under-specified repository
configuration interacting with changed upstream defaults, not an engine or
transport regression.

The external two-file diagnostic patch is retained outside the repository and
has SHA-256
`437aa384755d32ad92bc1f8c99a5131b9b022e16d5cfe8ddaee7f42321edfb7b`.
It proves the configuration root cause but is not a complete correction: the
three integration suites must also fail closed when a relay is contractually
required. The current Issue forbids the compose, relay-config and
integration-test paths, so this diagnostic success cannot satisfy the exact
repository command or be called Stage-1 GO.

One final disposable build attempt failed during bootstrap with a temporary DNS
error resolving crates.io/GitLab. The attempt was discarded and the complete
build was rerun successfully from the same source. It contributes no artifact
evidence.

## Verdict and required resolution

**NO-GO for the Stage-2 artifact amendment under the currently approved test
contract.** The Phase-B2.2 engine capability, reproducible bytes and retained
surfaces passed. The only unresolved condition is the mandatory moving relay
image and its real-time kind-1059 behavior, but Issue #149 explicitly forbids
treating that condition as a green skip or silently substituting another image.

The safe next action is an independently reviewed Issue amendment that replaces
the moving relay dependency with a reproducible digest/configuration, makes all
three real-relay suites fail closed in required mode, and proves a kind-1059
policy round trip. A compose-only correction is explicitly insufficient. Only
after the amended exact command passes may this report be changed to GO and the
Stage-2 generated-artifact gate be requested.

No product activation, generated artifact installation or security claim is
authorized by this report.
