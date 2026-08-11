# Phase B2.2 OpenMLS capability-closure evidence

Status: **GO for the separately approved Stage-2 amendment gate**

This report evaluates Stage 1 and the separately approved relay-harness
amendment authorized by Issue #149. The OpenMLS capability passed its native,
generated-JavaScript, reproducibility and retained-surface checks. The pinned,
explicitly configured relay harness also passed the mandatory full live run and
all three required-mode negative runs. Stage 1 is therefore GO for drafting and
reviewing the exact Stage-2 amendment; Stage 2 remains blocked until that exact
amendment is independently reviewed and approved by the product owner.

Passing results in this report are capability evidence only. They do not
activate Phase B2 in a product, verify the BIP-340 account-identity proof, prove
Marmot interoperability, or establish production readiness.

## Frozen inputs

- Contract: Issue #149. The original Stage-1 approval at body SHA-256
  `10ad40928019b5f9c2793d0c760b25209a96e3fa8bacc1541a5da5d723b64ae3`
  was superseded by the relay amendment. The operative approved contract body
  has REST SHA-256
  `3bed770030150caed56a6a969f41aa26b52cb4926eec521fee2625af45a9be10`.
- Base: `0bcd19f114ad1dd9cc419a8c53f0d53d33428ac0` on `main`.
- Engine source head evaluated by the capability and composition probes:
  `e08c226aa9bfc7dce7640624e4771f7a3061c1df`.
- SHA-256 of the binary-safe `base..engine-source-head` diff:
  `5d8b40fdae78549897882b4a6c37ca4fcd9288b746fa51a5ee984627e62d0b8f`.
- Final executable Stage-1 source head after the approved relay amendment:
  `d878ed75c11d5459c4361b425c5b48724ca91406`.
- SHA-256 of the complete binary-safe `base..final-executable-head` diff:
  `553943ab3766e86e198e4d9ed8f030c716358d743b25dc7980e044dcea84094a`.
- SHA-256 of the complete binary-safe `patch/lib.rs` diff over that range:
  `798f02e93249ab6b30f6df76828129382631222248390f93f79248252dfd1e77`.
- OpenMLS: `09e92777dba0528d3d29e2e5e681b7e91637c7be`, with the existing
  `extensions-draft` feature.
- Marmot specification evidence:
  `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1`.
- MDK comparison evidence:
  `9396adb6aa6b95b521a7979facd5ea7040c07288` (not executed or copied).
- Rust build image:
  `rust:1.96.1@sha256:1f0dbad1df66647807e6952d1db85d0b2bda7606cb2139d82517e4f009967376`.

The only source changes at the engine source head are the authorized wrapper patch
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
GroupContext. Referenced proposals and unresolved AppDataUpdate Commits fail
closed at the exported staging boundary; the exact stable classification is
asserted from the same authenticated staged object. The pure policy predicate
also assigns distinct stable errors to inline Update, Custom and other proposal
kinds, but those shapes are rejected or normalized by the pinned OpenMLS API
before they can reach this boundary and are recorded only as defence-in-depth
coverage.

Before confirm or merge, WASM independently recomputes the exact
`STYX-B2-VERIFIED-LEAVES-v1` digest over all candidate leaves. The JavaScript
probe independently reconstructs the bounded preimage and obtains the same
SHA-256. This is a state-binding check, not BIP-340 verification; that remains
B2.4 work. It does not bind the group id, epoch or any GroupContext field and
must not be persisted or reused as a standalone authorization token; the Stage
2 lifecycle must bind each policy decision to that complete transition context.

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
`e08c226aa9bfc7dce7640624e4771f7a3061c1df` is 24,183 bytes and has SHA-256
`6090ac29fcc257e54d58251f63853990f65e0fb8cc2bd83156f2ee524b9fc3a8`.
Its final marker is `PASS PHASE_B2_2_COMPOSITION_EXACT`. The generated
declaration digest below is the independent artifact identity that will freeze
the exact public types in a Stage-2 amendment.

## Reproducible disposable artifacts

Builds `issue149-final-a.ZH3XbJ` and
`issue149-final-b.9BMfqe` were produced independently from the exact final
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
  `Reference` and `UnresolvedAppDataCommit` shapes, first proves that an admitted
  inline self-update succeeds at the exported `stage_inbound_commit` method,
  and then drives both authenticated hostile Commit byte strings through that
  same method. On a native non-WASM target, construction of the returned
  `JsError` deliberately traps at the wasm-bindgen boundary; the tests catch
  that target limitation only as the final use of each victim group and prove
  provider-state equality before/after, while the exact stable error is asserted
  from the same authenticated staged proposal or unresolved Commit.
  Generated WASM additionally exercises exact exported-wrapper errors where
  those inputs are constructible (PrivateMessage, non-Commit, B1 KeyPackage and
  durable recovery). Non-constructible inline Update/Custom/Other cases retain
  exact typed unit coverage and are not represented as end-to-end evidence.
- Native negative coverage also exercises the production GroupContext validator
  first with the actual administrator present and then with that administrator
  absent from the supplied candidate-member set. The
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
- Full Jest with the approved repository relay harness and
  `REQUIRE_RELAY=1 NOSTR_RELAY=ws://127.0.0.1:17777`: 85/85 suites and
  1,151/1,151 tests passed with no relay skip. The complete log SHA-256 is
  `577101ff73812d4ffc9eb6954f64f419aab8af9c7b8820a2e8e4519233694f40`.
- With the relay stopped, each of
  `nostr-relay.test.js`, `nostr-chat-transport.test.js` and
  `styx-chat-nostr.test.js` failed nonzero in required mode and emitted the
  stable `required relay unavailable` diagnostic. Their respective log
  SHA-256 values are
  `14e5d0db6999f1e395e78ee89c5cd2d5d94005eb138282bbac201b6478911fde`,
  `9124d540f896e54827566a832713639cba5dcb1785405a4614794a2437fe8285`
  and
  `b3f81d4eb6733c1e472093d5276c1abb2883002d6d1d05b1b6b369c4d8068ac2`.
- With required mode unset and the relay stopped, the same three suites
  retained their developer-friendly behavior: 3/3 suites and 19/19 tests
  passed after the existing skip warning. The log SHA-256 is
  `1835dc52e6b193677e1279f3dda75a103eb43f47a30584dd6b3e20f76edc3ceb`.

### Mandatory relay resolution

The contract resolves `ghcr.io/hoytech/strfry:latest` at execution time. It now
resolves to
`ghcr.io/hoytech/strfry@sha256:d6b31e8ab32e159f98d250b90aa6a62b9b47c468efdd311341597f60198861e1`,
reporting `strfry 1.1.1-119-g9acdaeb`.

The pre-amendment repository configuration exposed two independent
upstream-default dependencies:

1. the image runs as uid/gid 1000 while the compose file creates
   `/app/strfry-db` as a root-owned tmpfs, producing
   `mdb_env_open: Permission denied`; and
2. when the repository configuration omits `relay.auth`, this image defaults
   `restrictedReadKinds` to `4, 1059`. The real-time tests publish kind 1059
   but do not negotiate NIP-42 authentication, so writes are logged while reads
   time out.

The approved amendment resolves both dependencies. Compose now uses the exact
image digest, binds only `127.0.0.1:17777`, and creates a fresh named local
tmpfs volume with exactly `uid=1000,gid=1000,mode=0700`. Runtime inspection
confirmed the relay process is uid/gid 1000 and `/app/strfry-db` is a
1000:1000 mode-0700 directory. The host-port and mount inspection log SHA-256
is `84aa0e58ea7038c8b8194e56bd87164eae05ee08da50b6a90417e4883a1f3536`;
the runtime identity/filesystem log SHA-256 is
`cc664247caf814c9d8a9f34b0c895f57b0622776523272afb29cd16918884f1f`.

`relay.auth` now explicitly sets `enabled=true`, empty `serviceUrl`, empty
`restrictedReadKinds`, and `restrictReadToInvolvedPubkey=true`, so the policy
preflight completes a real kind-1059 publish/read round trip. The three
integration suites additionally fail closed when `REQUIRE_RELAY=1`, while
their prior optional developer behavior remains unchanged when it is unset.
This proves the earlier failure was under-specified test infrastructure
interacting with changed upstream defaults, not an engine or transport
regression.

One final disposable build attempt failed during bootstrap with a temporary DNS
error resolving crates.io/GitLab. The attempt was discarded and the complete
build was rerun successfully from the same source. It contributes no artifact
evidence.

## Verdict and required resolution

**GO to prepare the exact Stage-2 artifact amendment.** The Phase-B2.2 engine
capability, reproducible bytes, retained surfaces, pinned relay configuration,
real kind-1059 policy round trip and required-mode failure behavior all passed.
No relay failure or skip has been waived or relabelled green.

This GO authorizes only preparation, independent review and product-owner
consideration of the exact Stage-2 amendment. It does not authorize any
generated artifact, provenance, runtime tuple, fixture, product path or other
Stage-2 repository change before that separately hashed amendment is approved.

No product activation, generated artifact installation or security claim is
authorized by this report.

## Residual relay-gate limitation

The relay suites fail closed only when `REQUIRE_RELAY=1`. The approved Stage-1
contract invokes that mode explicitly, but the ordinary repository workflow
does not currently set it; routine CI can therefore retain the optional local
developer skip behavior when no relay is available. Wiring the required relay
mode into `.github/**` needs a separate contract and human gate because workflow
files are outside this Issue's scope. Until then, the evidence in this report
proves the mandatory contract run, not an always-on repository CI guarantee.
