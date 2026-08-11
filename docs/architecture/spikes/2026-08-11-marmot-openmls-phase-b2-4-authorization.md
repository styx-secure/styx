# Phase B2.4: authenticated account binding and bounded Commit authorization

**Status:** isolated proof candidate for Issue #153 and Draft PR #154

**Base:** `388b6645b1b3589610e6116373e55b2698562c8e`

**OpenMLS revision:** `09e92777dba0528d3d29e2e5e681b7e91637c7be`

**WASM SHA-256:** `60dbbc1127fbfb0e7e479cf7e2f7e6e20183c60d0559268f039d8db58bf60a3a`

**Marmot specification revision:** `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1`

## Bounded claim

Within the isolated B2.4 adapter and frozen B2 profile, every accepted tested
Commit is MLS-authenticated by the pinned OpenMLS WASM, bound to valid Nostr
account/MLS-leaf proof-v2 pairs, authorized against the fresh restored parent,
and cryptographically inseparable from the exact transition evaluated by the
JavaScript policy.

This is deliberately narrower than full Marmot authorization. It proves three
transition shapes and no product integration.

## Trust boundary and algorithm

The pinned WASM remains trusted to stage the exact Commit, reject unsupported
sender/proposal encodings and expose an authenticated complete candidate
projection. JavaScript does not duplicate MLS validation. It evaluates the
projected source classifications again and independently performs the
application-policy work:

1. restore the exact Provider snapshot selected by the B2.3 CAS head;
2. cross-check own identity, group id, epoch and GroupContext digest;
3. project the current parent before preparation or staging can mutate it;
4. verify every parent proof-v2 account/leaf binding;
5. prepare or stage the exact Commit in disposable memory;
6. canonicalize the complete B2.3 candidate projection;
7. verify every candidate proof-v2 account/leaf binding;
8. decode and validate parent authority, then evaluate the strict whitelist;
9. bind the immutable result to the exact transition context;
10. recompute that binding immediately before merge or durable CAS.

Rejected local preparation performs no CAS. Rejected inbound staging is
discarded and performs no merge or CAS. Provider memory is disposable in both
cases.

## Proof-v2 verification

For every relevant leaf, B2.4 calls the Styx-authored pinned proof-v2 verifier
with the exact 104-byte component, 32-byte BasicCredential identity and
32-byte Ed25519 MLS signature key. The verifier:

- parses signer, unsigned big-endian `created_at` and BIP-340 signature;
- requires `created_at` in `1..2^53-1` without consulting local time;
- reconstructs the local-only kind-450 Nostr event with ciphersuite `0x0001`,
  signature scheme `0x0807`, ordered tags and fixed content;
- recomputes the NIP-01 event id; and
- verifies the Schnorr signature and signer/credential equality.

The event reconstruction uses fixed ASCII constants. This proof does not claim
a general-purpose NIP-01 canonicalizer for arbitrary Unicode input.

## Administrator policy

The parent administrator-policy component is decoded as a canonical MLS
variable-length byte vector. The prefix must use the shortest QUIC-varint
width. The payload must be nonempty, a multiple of 32 bytes, bounded to 16
accounts, strictly lexicographically sorted and unique. Every administrator
must be a current authenticated parent member.

Authority is never taken from the candidate. The candidate policy must remain
byte-identical to the parent policy.

## Policy table

| Shape | Parent authority | Required effect | Result |
|---|---|---|---|
| Add | committer is a parent admin | exactly one inline Add, one new account/leaf, `N -> N+1` members | allow |
| Remove | committer is a parent admin | exactly one inline Remove of a non-admin, non-self leaf, `N -> N-1` members | allow |
| Self update | authenticated current member | no proposals; same leaf, account and MLS signature key | allow |
| Anything else | irrelevant | referenced, mixed, batched, external or unsupported shape | reject |

Every allowed shape requires exactly one epoch advance, an update path matching
the candidate committer, active lifecycle, the frozen required-component set,
unchanged administrator bytes, no duplicate account identities and unchanged
unrelated member tuples. A refreshed valid proof may accompany the committer,
but account and MLS signature-key rotation are not accepted.

## Canonical authorization domains

Policy version 1 uses:

- context domain `STYX-B2.4-AUTHORIZATION-CONTEXT-v1`;
- result domain `STYX-B2.4-AUTHORIZATION-RESULT-v1`; and
- database prefix `styx-b2-4-poc-v1-`.

The context digest is SHA-256 over UTF-8 `JSON.stringify` of one fixed-order
array containing domain/version, group id, parent epoch and GroupContext
SHA-256, exact Commit SHA-256, canonical candidate-projection SHA-256,
candidate epoch and GroupContext SHA-256, verified-leaf digest, normalized
operation and authenticated committer tuple. The result digest adds the exact
`ALLOW`/`REJECT` verdict and stable reason.

The projection digest commits to the complete candidate leaf set and proposal
shape. Neither the verified-leaf digest nor any result is independently usable
as an authorization token.

## Durable lifecycle and recovery

B2.4 reuses byte-identical B2.3 head, transition, evidence and snapshot records
behind its distinct v1 namespace. It adds no decision field and no migration.

- Local: parent -> prepare -> candidate -> authorize -> `CAS PREPARED`.
- Inbound: parent -> stage -> candidate -> authorize -> merge in RAM ->
  `CAS STABLE(N+1)`.
- Recovery: restore exact `PREPARED` parent/pending state -> recover candidate
  -> rerun proof and policy v1 over the durable Commit -> confirm ->
  `CAS STABLE(N+1)` only after the result is again `ALLOW`.

If persistence fails after in-memory preparation, merge or confirmation, the
Provider is discarded and the durable predecessor remains authoritative. A
retry starts from that predecessor.

The B2.3 factory and permissive adapter require an actual `B23Journal` backed
by a database whose name has the frozen B2.3 prefix. The B2.4 factory requires
the distinct frozen B2.4 prefix and is the only holder of its wrapper
construction token. Neither the wrapper nor its underlying B2.4 database can
be passed through the permissive B2.3 adapter. Extra caller booleans passed to
B2.4 `acceptInbound(groupId, commitBytes)` are ignored by the JavaScript call
signature and never consulted.

## B2.3 byte-preserving hardening

The prerequisite hardening changes no B2.3 field, schema, domain or canonical
encoding:

- adapter transition/head bags have exact fields and cannot shadow journal
  identity fields;
- missing raw builder inputs and counter exhaustion use typed closed errors;
- every CAS checks epoch relationships with parsed `BigInt`: prepare/discard/
  publication stay at N, confirm/inbound advance exactly to N+1.

Frozen fixture digests remain:

- head: `246eedf94299e6d4d67499795788946dc49fc51b151bf72264213ad852944733`;
- projection: `bebcd2346a3365863368e08c1b582de79acc2d519160c2818faa1c09960f6a13`;
- transition: `6e43d2c51c21589d88ec5685eeae2ce2e58ee03e5fcbbc9dc3db0ba43a9fddd8`.

## Hostile evidence matrix

The Styx-authored tests cover:

- valid, forged, zero-time, old-valid, wrong-binding and structurally invalid
  proof envelopes;
- malformed, empty, non-minimal, duplicate, unsorted and non-member admin
  policies;
- authorized Add, non-admin Remove and self update with bidirectional MLS
  liveness;
- non-admin mutation, self-removal preflight, admin removal, duplicate account,
  signing-key rotation, credential swap, ghost member and changed unrelated
  member;
- referenced, mixed, batched, Update, PSK, ReInit, ExternalInit,
  GroupContextExtensions, SelfRemove, AppDataUpdate, AppEphemeral, Custom and
  unknown proposals;
- external/non-member senders, lifecycle/component/policy mutation and epoch
  mismatch;
- result replay across Commit, group, parent context, candidate context and
  verified-leaf digest;
- a hostile split-view `Proxy`, proving authorization and decision binding use
  the same normalized, closed candidate snapshot;
- local and inbound CAS loss after authorization, zero-write rejection,
  duplicate suppression and recovered pending confirmation;
- attempted caller booleans, cross-prefix journal factories, direct wrapper
  construction and attempted use of a raw B2.3 journal/adapter over a B2.4
  database; and
- B2.3 shadow fields, getters, missing values, counter overflow, stale CAS and
  epoch regression.

## Evidence

The exact candidate evidence is:

- focused B2.3+B2.4 Jest evidence: 47 passed, zero skipped;
- complete root Jest evidence: 88 suites and 1,202 tests passed, zero Jest-marked
  skips;
- B2.2 capability probe: passed with evidence-manifest SHA-256
  `13abc21785fb3d81450fde207bdd1548e98e2182913a9df2c0b8d1612eccb608`;
- B2.2 composition probe: `PASS PHASE_B2_2_COMPOSITION_EXACT`, comparing the
  pre-B2.2 vendor at `0bcd19f` with the installed candidate through
  `B2_COMMITTED_WASM_DIR` and `B2_WASM_DIR`;
- B2.3 Playwright evidence: 6/6 passed across Chromium and Firefox, with zero
  skip, including 100 two-connection CAS races on each browser;
- chat PWA: clean `npm ci` followed by a successful Vite/PWA production build;
- agent-enforcement: 54/54 Python tests passed; and
- `git diff --check`: passed.

The exact implementation hashes before the evidence-only report commit are:

- `b2-3-record.mjs`:
  `67ca92f4b71e6cef4db47a768379a173eb2aaf7175a94d3dc42024b3650ef3ae`;
- `b2-4-canonical.mjs`:
  `128155f57ad492cb9f85d04bddd07057e5d47c9d4bc88a801b8999de66f63c06`;
- `b2-4-policy.mjs`:
  `b9af577cbc30af997c9af79cee9ee47400819d08f013790e0847f4074ef3a880`;
- `b2-4-journal.mjs`:
  `d30ceb89dc57e683c7035cab9303b8235e988f54bf62b50c6e7be6d5e2ffa90c`;
- `b2-4-engine-adapter.mjs`:
  `cb2fb9be6788bff98c24dc46fb813dbab8cb099236bcff9fc4d2ae91fe256f77`;
- `mls-phase-b2-4-policy.test.js`:
  `fa8b22deacf22f60582116ce38dd54fbdc880f2f3e517bb367ca9398a344186c`.

The PR evidence comment binds these outputs and the two independent reviews to
the exact final Git HEAD; embedding a commit's own hash in this tracked file
would be self-referential.

The full Jest run reports pre-existing relay-unavailable warnings for optional
local Docker integration tests and the pre-existing forced-exit/open-handle
diagnostic. No Jest test is marked skipped, but those warnings are not evidence
of relay interoperability and are not hidden by this report.

## Rejected alternatives

- Duplicating BIP-340 inside WASM would enlarge the trusted change and require a
  vendored artifact/pin update; proof verification remains above the frozen
  WASM boundary.
- Persisting an `allowed` boolean or authorization token would create replay
  and migration semantics; recovery instead recomputes frozen policy v1.
- Accepting batched operations, admin succession or signing-key rotation would
  exceed the evidence available in this increment.
- Reusing the B2.3 namespace would permit policy reinterpretation of pending
  records; v1 has a distinct namespace and no migration.

## Inherited assumptions and residual risks

The exact installed WASM artifact is trusted to report the staged candidate
faithfully. B2.3 record digests detect accidental corruption but do not
authenticate IndexedDB against a malicious same-origin script. A complete
origin-profile attacker can coherently rewrite or replay storage. The browser
origin, XSS, extensions, compromised OS, keylogging, screen capture, code
substitution, storage eviction and secure erasure remain outside this proof.

The result also does not establish full Marmot interoperability, retained
history, same-epoch branch selection, peer fork convergence, rejoin, transport,
delivery, Nostr metadata anonymity, application-protocol authorization,
Safari/native persistence, audit, certification, beta readiness or fitness for
real whistleblowing data. Phase B2.5 must address convergence before a broader
protocol claim can be made.
