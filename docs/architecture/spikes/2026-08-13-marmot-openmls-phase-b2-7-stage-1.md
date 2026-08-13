# Phase B2.7 Stage 1 — authenticated MLS sender-attribution source boundary

Status: Stage 1 implementation candidate for Issue #163. This is isolated
source and executable evidence. It does not install a new WASM artifact or
implement the B2.7 durable delivery format.

## Question

Can the pinned OpenMLS-WASM boundary preserve the authenticated current-epoch
MLS member identity that produced application plaintext, without inferring it
from payload bytes, a caller roster or a reused leaf index, and without changing
the committed runtime artifact during this stage?

## Result

The source candidate answers the bounded question affirmatively.

`PhaseB2Group.receive_application_message` exact-decodes only a
`PrivateMessage`, rejects a different group or epoch before engine processing,
processes the message once, rejects own echo and every non-member or
non-application result, then resolves the authenticated member through the
same loaded profile-valid group. The processed BasicCredential identity must
match that member byte-for-byte.

The getter-only `PhaseB2ReceivedApplicationMessage` returns:

- exact group id and epoch;
- authenticated sender leaf index;
- 32-byte account credential identity;
- 32-byte MLS leaf signature key; and
- application plaintext.

The result deliberately does not carry a caller-supplied roster, application
identity claim, mutable last-sender state or cross-epoch interpretation. The
legacy sender-discarding method remains behaviorally unchanged and has only a
generated-documentation warning directing B2.7 callers to the new method.

## Frozen identity

- Contract base: `097fc88f05e8fc740ba67ef13ff07906d6999006`
- Base tree: `b3ab218046641acd9ffa0d4f39446dc5fa7780d1`
- Candidate source commit: `ea6fd5b23b6ba7c9f9f07da7084db53fb1f8f87e`
- Candidate source tree: `1c10eb0f35fb7586602eb5801c98a60f847f1a11`
- OpenMLS revision: `09e92777dba0528d3d29e2e5e681b7e91637c7be`
- Rust image:
  `rust:1.96.1@sha256:1f0dbad1df66647807e6952d1db85d0b2bda7606cb2139d82517e4f009967376`
- wasm-pack: `0.15.0`, release SHA-256
  `c09f971ecaed9a2efc80fdcea7a00ef6b53c7fadc8c57d1f61b53a6aa66b668a`
- Ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
- Committed B2.2 WASM SHA-256:
  `60dbbc1127fbfb0e7e479cf7e2f7e6e20183c60d0559268f039d8db58bf60a3a`
- Marmot specification revision:
  `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1`

The committed generated files and product build tuple remain byte-identical to
the B2.2 base throughout Stage 1.

## External reproducible-build evidence

Two clean `build.sh` invocations used distinct disposable `OUT_DIR`
directories outside the repository. The first invocation encountered a
transient DNS failure while resolving crates.io and GitLab and produced no
candidate. One explicit retry succeeded; the independently executed second
build also succeeded. This network failure is not counted as green evidence.

`cmp` succeeded for all five outputs from the two successful builds:

| External candidate file | Bytes | SHA-256 |
|---|---:|---|
| `openmls_wasm.js` | 105,588 | `3ae01d30c30d2fdb7bcd48d8406d485a875f5c0a8ad25e726cb6ed7b820c6083` |
| `openmls_wasm.d.ts` | 36,771 | `890693bda50ca202181f1988078b43d6dfa81e5468a2b7034f5fedbd71fe37d6` |
| `openmls_wasm_bg.wasm` | 2,081,600 | `ed5e740d9c93aa46aa1afb7b6065e4b5b92be972a8a080ddd0a35091260691bb` |
| `openmls_wasm_bg.wasm.d.ts` | 19,972 | `d9eb6767743ef6436580e16f78bb8c549764fd3cedea8977f73640d720b74b4d` |
| `package.json` | 449 | `88f2ec1e2a5c1904b0fc1d147221c32ba6dcbf1cb4441c53b04a1b2a03bd1d85` |

The automatically discovered generated public surface is 57,363 canonical
JSON bytes with SHA-256
`84fc77b3394fff5d48027dce3fe55c29aa339507bf9bd140f9c9966a60ba4061`.
This is evidence for the future Stage 2 surface re-freeze; the committed B2.2
surface remains 54,941 bytes with SHA-256
`1eb94ae14138918fb4ad0d8b91bb5560fa0898a23d7272542aa4b36fed342cc6`.

No external output was copied into `vendor/openmls-wasm/`.

## Exact current-writer fixture

The fixture under `test/fixtures/mls-state-b2-2/` was generated before the
Rust patch changed, using the exact committed writer. It contains fixed
synthetic account inputs, fresh synthetic MLS material and no user data.

- Generator: 7,551 bytes, SHA-256
  `28b203f136dcac524e44cdb8a05c57823135e9448f18f881ac1100c61cb593dd`
- `context.json`: 1,894 bytes, SHA-256
  `7347133bdfc94ce9d44eb437f13a14cbd243a6db87dfee9f2b22b900ccbcb839`
- `envelope.json`: 19,465 bytes, SHA-256
  `384f51bad7813524554127d145b5fe4c1a10087f5607d44f8eff87a7578c3208`
- Provider payload: 14,209 bytes, SHA-256
  `813a5d5c0fcdc18cb8da016c0f5e0164d90b472a3fa8deb8712a55ba15fa90eb`
- Self-check: `restore-reference-decrypt-and-reply-pass`

The generator refuses a different writer digest and refuses to overwrite the
fixture. The fixture is not a compatibility allowlist entry in Stage 1.

## Adversarial evidence

The native Rust test uses three members and proves interleaved Alice/Charlie
attribution, exact result fields, payload-identity non-authority, own-echo and
PublicMessage refusal, both cross-epoch directions, remove/re-add at the same
leaf, replay, malformed framing and a tampered generation. Every pre-engine
reject has byte-identical serialized Provider state.

The standalone source probe runs against each external build and independently
checks:

- the committed artifact has the exact B2.2 digest and lacks the new method;
- the external artifact differs and exposes exactly the candidate boundary;
- three-member interleaved group/epoch/leaf/identity/signature attribution;
- a payload that falsely claims another account has no authority;
- own echo, public Commit, different group, future epoch and past epoch refusal;
- stable closed errors for malformed, tampered and replay input; and
- no early-reject Provider write.

One inherited behavior is now explicit: after a current-generation ciphertext
is modified, OpenMLS returns an authentication failure but may consume that
receiver-ratchet generation. The original bytes for that generation then fail,
while the next sender generation succeeds. No plaintext or sender result is
released for the altered message. This is a residual targeted liveness/DoS
cost; it is not state-neutral rejection and is not described as one.

## Verification results

The following completed successfully on the source candidate:

- native pinned OpenMLS-WASM tests: 17 passed, 0 failed;
- two external source probes: pass, one per byte-identical build;
- root Jest: 92 suites and 1,329 tests passed;
- committed-artifact legacy round trip: pass in both directions;
- chat PWA production build: pass;
- agent-enforcement: 54 tests passed;
- docs-claims-lint tests: 10 passed;
- docs/spec claims scan: 56 files, 0 findings; and
- JavaScript syntax checks and `git diff --check`: pass.

The root Jest invocation reported its pre-existing documented relay integration
self-skips because no relay was running at `ws://localhost:17777`; no changed
path depends on relay behavior and the required root invocation exited green.
The chat install also reported the existing dependency audit inventory and
bundle-size warnings. Neither warning was changed or treated as security
evidence by this Stage 1.

Exact-HEAD GitHub CI and exact-source independent review remain required before
Stage 1 evidence is complete.

## Independent-review basis

The pre-contract Fable 5 design review returned `GO WITH REQUIRED AMENDMENTS`.
Its report SHA-256 is
`67a170395ca15214a8ece3bda6ce4e9e4cf4cee990824c9111603f497c98b9c2`.
Stage 1 incorporates its required findings as follows:

- F1: explicit current-epoch precheck, both epoch directions and leaf-reuse test;
- F2: closed result binds group, epoch and current member tuple;
- F3/F4/F5: roster digest, durable-record and artifact-transition obligations
  are reserved for the separately approved Stage 2 contract;
- F6: only PrivateMessage reaches application processing, with closed errors;
  and
- F7: the legacy method is unchanged and marked sender-discarding; Stage 2 must
  structurally prevent its use by the durable adapter.

The contract also requires Fable 5 to review the exact Stage 1 source head in a
fresh read-only checkout. That review is pending at the time of this candidate
report and must be appended as evidence; Claude Opus must not review this task.

## Planned Stage 2 amendment

Stage 1 is not independently mergeable as the completed B2.7 increment. If its
source, exact builds, CI and reviews pass, Issue #163 must be amended with:

- the exact source commit and all candidate hashes and lengths above;
- the 57,363-byte generated-surface digest;
- explicit authorization to install the five generated files;
- provenance and build-info transition plus current-writer compatibility
  admission, proven by restoring this fixture under the candidate;
- a new `styx-b2-7-poc-v1-` durable namespace and content-bound ACCEPTED record;
- full binding to transcript-derived instance, group, epoch, GroupContext,
  verified-roster digest, ciphertext, plaintext, sender leaf, account identity,
  MLS signature key and the BIP-340-verified 104-byte proof; and
- exact Jest, browser, reproducible-build, migration and human-review gates.

DEFERRED records will carry no sender. Duplicate delivery will return stored
attribution rather than recomputing it. No Stage 2 work starts without renewed
product-owner approval.

## Assumptions, residual risks and non-claims

The initialized pinned WASM, browser crypto and same-origin runtime remain
trusted. This does not defend against a malicious origin, XSS, extensions, a
compromised browser or OS, coherent IndexedDB rewrite/rollback, storage
eviction, physical erasure failure or device compromise while unlocked.

The new Rust patch is not covered by an upstream OpenMLS, Marmot or MDK audit.
The OpenMLS pin remains unreleased upstream `main` with `extensions-draft`.
Tests pin only the exercised behavior. Attribution binds an MLS leaf/account
tuple, not a human, device, transport endpoint or legal identity; it is not
third-party-verifiable non-repudiation and no deniability claim is made.

This stage provides no product integration, durable B2.7 record, real
transport, delivery proof, metadata privacy, anonymous whistleblowing channel,
Marmot/MDK interoperability, application payload conformance, business-rule
effect, multi-device recovery, global finality or audit claim. Real sensitive
data must not be used.

## Rollback

Before any Stage 2 approval, delete the task branch/worktree and close the Draft
PR to return to the unchanged B2.2 artifact and product tuple. The fixture and
report have no production authority. No migration, compatibility widening or
data repair is required because Stage 1 installs no generated artifact and
creates no product database.
