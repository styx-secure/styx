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
  `9a4cc801139afca241cdc030b9d9f153929fa254`.
- SHA-256 of the binary-safe `base..source-head` diff:
  `0e0db336cf687d02da7bf5126387334c537b2b65af1700e60b4440a407aa5c03`.
- OpenMLS: `09e92777dba0528d3d29e2e5e681b7e91637c7be`, with the existing
  `extensions-draft` feature.
- Marmot specification evidence:
  `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1`.
- MDK comparison evidence:
  `9396adb6aa6b95b521a7979facd5ea7040c07288` (not executed or copied).
- Rust build image:
  `rust:1.96.1@sha256:1f0dbad1df66647807e6952d1db85d0b2bda7606cb2139d82517e4f009967376`.

The only source changes at the evaluated head are the authorized wrapper patch
and two new independently written probes. No generated binding, binary,
manifest, lockfile or product path differs in Stage 1.

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
GroupContext. Standalone/referenced, Update, AppDataUpdate, Custom and all other
unsupported proposal shapes fail closed with distinct stable errors.

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
`9a4cc801139afca241cdc030b9d9f153929fa254` is 24,183 bytes and has SHA-256
`6090ac29fcc257e54d58251f63853990f65e0fb8cc2bd83156f2ee524b9fc3a8`.
Its final marker is `PASS PHASE_B2_2_COMPOSITION_EXACT`. The generated
declaration digest below is the independent artifact identity that will freeze
the exact public types in a Stage-2 amendment.

## Reproducible disposable artifacts

Builds `issue149-stage1-build-c` and `issue149-stage1-build-d` were produced
independently from the same patch. `cmp` succeeded for all five files.

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

- `styx-js/vendor/openmls-wasm/test.sh`: 15 passed, 0 failed. This includes all
  12 pre-existing tests and three B2.2-owned tests.
- The generated-JavaScript capability probe passed against both disposable
  builds. It exercised current-profile creation, KeyPackage inspection,
  Add/join, independent candidate-digest recomputation, wrong-digest rejection,
  self-update, inbound discard and exact re-stage, merge, Remove, bidirectional
  liveness, serialization, fresh-provider restore, durable pending confirm and
  clear, and malformed framing rejection.
- The same candidate probe repeated the retained B2.1 founding/non-founding
  confirm/clear matrix and exact inbound re-stage merge/discard behavior.
- All five required probe markers were present:
  `PHASE_B2_EXPORTED_COMPOSITION`, `PHASE_B2_PUBLIC_COMMIT_FRAMING`,
  `PHASE_B2_POLICY_PROJECTION`, `PHASE_B2_VERIFIED_LEAF_BINDING` and
  `PHASE_B2_SURFACE_DELTA_EXACT`.
- `node vendor/openmls-wasm/roundtrip.mjs`: passed.
- `node spikes/marmot-phase-b1/probe.mjs`: passed.
- Reference chat `npm ci && npm run build`: passed. Existing npm audit output
  reported six dependency findings; no dependency or lockfile change is in
  scope.
- Agent-enforcement: 54 tests passed.
- Claims-lint: 10 tests passed; repository scan reported zero findings.
- Translation-sync: 20 tests passed; repository check reported zero findings.
- Full Jest without a relay: 85 suites and 1,151 tests passed; the relay suites
  reported their pre-existing environment skip.

### Mandatory relay finding

The contract resolves `ghcr.io/hoytech/strfry:latest` at execution time. It now
resolves to
`ghcr.io/hoytech/strfry@sha256:d6b31e8ab32e159f98d250b90aa6a62b9b47c468efdd311341597f60198861e1`,
reporting `strfry 1.1.1-119-g9acdaeb`.

The exact compose command fails before tests: the new image runs as uid/gid
1000 while the repository compose creates `/app/strfry-db` as a root-owned
tmpfs. The relay exits with `mdb_env_open: Permission denied`.

A disposable external compose override assigning the tmpfs to uid/gid 1000
allowed that exact image to start. This override was outside the repository and
is diagnostic evidence only. With the relay reachable, the full Jest run
executed rather than skipped, but three assertions in two pre-existing suites
failed:

- `test/integration/nostr-chat-transport.test.js`: live addressed delivery and
  reconnect delivery timed out;
- `test/integration/styx-chat-nostr.test.js`: live pairing timed out.

Offline replay scenarios and `test/integration/nostr-relay.test.js` passed.
Relay logs showed the events being inserted. The B2.2 diff does not touch the
relay, transport, tests or product artifact.

For isolation, the locally retained preceding image
`strfry 1.1.0-98-gb80cda3` (local image id
`sha256:c52807349888ef8a9f8720f3e51ee81af7e20114bad105915febb78f9c604cb1`)
was run without a repository change. Both previously failing suites then passed
(5/5 tests), and the complete relay-backed Jest run passed all 85 suites and
1,151 tests with no relay skip. This comparison identifies an upstream relay
image/configuration compatibility regression; it does not satisfy the Issue's
exact moving-image requirement and is not used to claim Stage-1 GO.

One earlier disposable build attempt also failed during bootstrap with a
temporary DNS error resolving `github.com`. The attempt was discarded and the
complete build was rerun successfully. It contributes no artifact evidence.

## Verdict and required resolution

**NO-GO for the Stage-2 artifact amendment under the currently approved test
contract.** The Phase-B2.2 engine capability, reproducible bytes and retained
surfaces passed. The only unresolved condition is the mandatory moving relay
image and its real-time kind-1059 behavior, but Issue #149 explicitly forbids
treating that condition as a green skip or silently substituting another image.

The safe next action is an independently reviewed Issue amendment that replaces
the moving relay dependency with a reproducible digest/configuration and states
how the three real relay suites must run. It may also authorize the minimal
compose correction if that correction belongs in this PR; otherwise the relay
repair must be a closed native dependency. Only after the amended exact command
passes may this report be changed to GO and the Stage-2 generated-artifact gate
be requested.

No product activation, generated artifact installation or security claim is
authorized by this report.
