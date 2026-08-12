# Phase B2.6 — crash-safe OpenMLS application-message persistence

Status: implementation candidate for Issue #161. This is isolated executable
evidence, not a product, audit or Marmot-conformance claim.

## Question

Can Styx persist the OpenMLS sender and receiver ratchets across multiple
messages, crashes, restarts and competing browser contexts without releasing a
ciphertext or plaintext whose corresponding ratchet transition is not already
durable?

## Result

The bounded proof supports the required write-ahead order without changing the
pinned OpenMLS WASM artifact:

1. Restore an exact durable epoch-instance provider snapshot into a disposable
   provider.
2. Encrypt or decrypt once in that provider.
3. Serialize the post-operation provider.
4. Atomically CAS the prior message position to the post-state together with
   the exact immutable outbox or accepted-inbound record.
5. Discard all computed values on error or CAS loss.
6. Expose data only by reading the committed durable record.

The encrypting method returns an instance key and ordinal only. Publication
reads exact ciphertext bytes from the outbox, so restart and retry cannot
silently re-encrypt a committed request. Inbound ciphertext digest
deduplication happens before OpenMLS and accepted plaintext is returned only
after its receiver-state transaction commits.

## Identity and sender-attribution boundary

The epoch-instance identity is derived from group id, canonical tip Commit,
epoch, GroupContext digest and authenticated local account member. Re-adopting
the same retained instance therefore addresses the same durable ratchet rather
than its original post-Commit snapshot.

Settlement may later advance the canonical anchor and compact the original
producing edge. B2.6 therefore adds `anchorTipCommitDigestHex` to its isolated,
content-bound head record. The advance transaction accepts the new binding only
with the exact replay-authorized edge from the prior anchor to the successor
anchor that is bound by the transaction's prior edge, normalized input or
local-generation replay evidence; an unchanged anchor must preserve the old binding. Readers combine this head
authority with any still-available edge, transition and local-generation
evidence, and fail closed on contradiction. This is an identity-preservation
rule inside the disposable B2.6 schema, not a substitution of storage ids or
snapshot digests for the transcript-derived tuple.

Inspection of the pinned wrapper established a narrower inbound claim.
PhaseB2Group.process_application_message authenticates and processes MLS but
returns plaintext only; the ProcessedMessage sender and credential are not
exported. The inbound record therefore contains exact ciphertext, plaintext
and membership-level engine acceptance, but no per-member sender identity.

The following are explicitly forbidden substitutes:

- an identity claimed inside application plaintext;
- inference from a two-member group;
- provider-state differences.

Exact ciphertext remains retained inside the bounded history so a later
human-gated wrapper export can add attribution. No identity-sensitive payload
policy may consume this PoC output before that export exists.

## Durable model

The isolated styx-b2-6-poc-v2 namespace adds:

- message-state: monotonic sent/received position and current provider digest;
- message-snapshot: exact current provider bytes and epoch binding;
- app-outbox: opaque request id, payload digest, immutable recipient scope and
  exact ciphertext;
- app-inbound: exact ciphertext disposition, immutable retained-base binding
  and accepted bounded plaintext;
- app-publication-evidence: bounded attempts, acknowledgements and failures;
- message-release: content-bound logical release evidence; and
- inbound-truncation: a digest-linked marker for terminal oldest-first removal.

All records use strict exact-field version-2 codecs and domain-separated
digests. Unknown fields, malformed bindings, unsafe counters and oversized
values fail before journal mutation.

## Concurrency and settlement

WASM execution never occurs inside IndexedDB transactions. Multiple contexts
may compute from the same predecessor, but only one CAS successor commits.
Web Locks and BroadcastChannel are not safety inputs.

Settlement and message operations share an IndexedDB transaction scope.
Message records are deliberately excluded from the convergence selection read
digest, so continuous messaging cannot invalidate a decision snapshot. The
settlement transaction may suspend outbox release on a displaced retained
instance, reactivate it after re-adoption, or terminally invalidate and
tombstone it when its base state leaves the retained horizon. Release first
uses the `instanceKeyHex` and retained-base binding already frozen in every
durable message-state, after cross-checking it against the unique pre-settlement
transcript evidence. Deferred-only sibling input is invalidated directly by its
immutable inbound retained-base binding; release never derives a new instance
identity from post-settlement state. The same path
applies atomically to local-generation replacement and eviction. Every message
commit revalidates its exact retained base inside the same transaction;
canonical-head equality alone is therefore not treated as release authority
for local pending generations.

Publication evidence is attested liveness metadata. It can close an obligation
but never advances or rolls back the MLS ratchet.

The inherited one-use liveness probe reserves its transcript-derived instance
before encryption and then uses the same durable outbound and inbound message
ratchet as ordinary application traffic. The reservation ledger remains
selection-inert evidence; it is not sender or receiver state. The internal
probe request namespace is unavailable to application callers, and a probe
racing an ordinary send has exactly one message-position CAS winner.

## Bounds

- message states: at most 17 retained epoch instances, enforced before the
  first state mutation;
- live outbox obligations: 16 per instance, never evicted;
- total outbox history: 128 records per instance, fail-closed without eviction;
- inbound history: 64 per instance;
- evidence: 64 records per outbox;
- request id: 128 UTF-8 bytes;
- plaintext: 4 KiB;
- ciphertext: 8 KiB;
- provider snapshot: 8 MiB.

The six-message restart scenario observed a current four-member provider
snapshot of 17,989 bytes after the sixth outbound message. Because every send
or receive persists a whole replacement snapshot, the present write
amplification is approximately one full provider snapshot per accepted
application message, plus one small state record and one outbox or inbound
record. This is accepted only for the bounded PoC; delta persistence and
compaction are non-goals.

## Evidence

The real-WASM Jest suite proves:

- three sends, restart, and three more sends in one epoch;
- exactly-once durable receive and duplicate pre-engine recovery;
- pre-commit outbound and inbound crash refusal, plus exact rollback when each
  logical message store fails immediately before or after its write;
- one CAS winner for competing outbound ciphertexts and for competing inbound
  plaintext computations at one prior message position;
- opaque request-id recovery and conflict refusal;
- exact-byte publication retry, idempotent evidence, immutable terminal states,
  bounded late acknowledgements and failure-driven discard;
- out-of-order receive at generations 2, 0 and 1, rejection of generation 1001
  from an unadvanced receiver, replay rejection and invalid-ciphertext refusal
  without durable mutation;
- oldest-first inbound truncation with a digest-linked marker and bounded
  outbox refusal before mutation;
- displaced-instance suspension, exact-byte re-adoption and atomic retained
  horizon release/invalidation, including deferred-only siblings and local
  generation replacement/eviction, plus a release-versus-deferred-commit race
  in which release wins without relying on canonical-head movement;
- preservation of the original transcript-derived instance key after anchor
  advancement compacts its producing edge, including branch-changing adoption
  where the new anchor was never head and re-adoption after it was previously
  head, plus replay refusal in the already-consumed namespace;
- non-destructive upgrade of an existing deferred ciphertext when its bounded
  inbound history is already at the cap;
- refusal of an eighteenth message state before disposable-provider or journal
  mutation;
- unchanged B2.5c convergence and local-generation behavior; and
- durable continuation from bidirectional liveness probes into ordinary
  traffic, plus a probe-versus-message same-predecessor CAS race.

The focused suite currently contains 59 passing tests against the pinned real
WASM artifact.

The Playwright suite uses two real IndexedDB connections and no Web Locks. In
both Chromium and Firefox it proves:

- one complete settlement successor;
- one branch-changing settlement CAS winner with convergence on the exact
  producing-Commit anchor binding;
- one durable one-use probe reservation;
- 100 adversarial same-predecessor application-message races, each with exactly
  one durable winner and one typed CAS loser; and
- a concurrent message commit and settlement that serialize without adding
  message traffic to branch selection.

This is 100 races in Chromium and 100 in Firefox (200 total), with ten browser
tests passing and zero skips.

## Assumptions and non-claims

The initialized pinned WASM, browser crypto and same-origin runtime are trusted
inside this proof. This does not defend against a malicious origin, XSS,
extensions, compromised browser/OS, coherent IndexedDB rewrite or rollback,
storage eviction, physical erasure failure or device compromise while
unlocked.

The proof does not provide real transport, proof of recipient delivery,
anonymity, metadata privacy, Welcome processing, kind-445 conformance,
application payload conformance, business-rule effects, multi-device state,
global finality, unbounded offline delivery or full Marmot interoperability.
Accepted plaintext is stored unencrypted in the disposable PoC namespace; real
sensitive data must never be used.

The pinned engine's out-of-order window is inherited rather than reconfigured.
No sender generation or per-message authenticated sender is exposed by the
wrapper, so those properties are behavioral or unavailable rather than
directly introspected.

Per-instance operational bounds do not impose a global lifetime-history cap.
Released instance records therefore remain durable audit evidence and may grow
with repeated branch churn; compaction and retention policy are later work and
must not silently erase this proof history.

## Rejected alternatives

- Persist after publication: rejected because a crash can expose ciphertext
  without the corresponding durable sender-ratchet transition.
- Reserve a caller-selected generation: rejected because the pinned engine
  exposes neither safe generation selection nor skipping.
- Re-encrypt on retry: rejected because it advances the ratchet and changes
  bytes for one logical request.
- Make acknowledgements ratchet authority: rejected because they are
  caller-attested and do not prove delivery.
- Add sender attribution in JavaScript: rejected because the authenticated
  sender data is encrypted on wire and discarded by the current wrapper.
- Modify vendored WASM in B2.6: rejected because it changes the pinned security
  boundary, reproducible artifact and required provenance; it needs a separate
  contract and human gate.

## Rollback

Before merge, delete the task branch/worktree and close Issue #161 and its Draft
PR. After merge, revert the single squash commit. Only new isolated files and a
disposable database namespace are introduced; no prior database requires a
migration.
