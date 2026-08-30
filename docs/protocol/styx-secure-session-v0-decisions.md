# Styx bounded secure-session evidence profile — v0 decision registry

- **Status:** conditional SS-0 normative source under Issue #285: candidate
  before a valid Gate A and byte-frozen authority afterward; never a supported
  adapter or product profile.
- **Authority:** the exact Issue #285 contract and its immutable Gate-A comment.
- **Evidence base:** the five repository-resident Phase-B reports pinned by
  Issue #285.
- **Scope:** one two-member direct-session evidence profile at exact upstream
  pins; no generally supported dependency or interoperability claim.
- **Language:** English is canonical.

The words **MUST**, **MUST NOT**, **SHALL**, **SHALL NOT**, **REJECT** and
**UNSUPPORTED** below constrain only the bounded evidence profile. They do not
claim that a Styx adapter, SDK or product currently implements the rule.

## 1. Interpretation and authority boundary

`SS` owns secure-session authentication, confidentiality, membership and
session-state transitions. It does not own application identity or authority
(`AP`), application transcript admission or causality (`K`), durable state
(`RS`), transport delivery (`TR`) or product/legal meaning (`PV`). Evidence
from one owner is never a substitute for a decision owned by another.

The positive profile is closed. A missing pin, unsupported operation or input
outside the selected topology produces no smaller fallback profile. Model-local
dispositions are review evidence, not stable O-10 codes.

## 2. Selected decisions

### SSD-01 — Exact evidence-profile identity

- **Owner:** `SS`.
- **Inputs:** OpenMLS, Marmot and MDK revisions; IANA MLS ciphersuite; member
  profiles; recorded application-history depth.
- **Preconditions:** OpenMLS
  `09e92777dba0528d3d29e2e5e681b7e91637c7be`, Marmot
  `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1`, MDK
  `9396adb6aa6b95b521a7979facd5ea7040c07288`, IANA MLS ciphersuite `0x0001`
  (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`), member profiles
  `STYX_B32A` and `MDK_PIN_9396ADB`, and five past epochs of recorded
  application-history evidence all match exactly.
- **Transition/disposition:** the exact tuple is eligible for the remaining
  SS-0 checks. Any drift is `UNSUPPORTED` and invalidates the positive report.
- **Forbidden substitutions:** fallback revisions, negotiation, downgrade,
  feature inference, extension inference or treating Styx signature suite
  `0x0001` as the IANA MLS registry value.
- **Residual risks:** exact pins can retain upstream defects and have not been
  audited as integrated by Styx.
- **Non-claims:** no generally supported dependency, ciphersuite, retention
  policy, negotiation mechanism or general Marmot compatibility is selected.

### SSD-02 — Layer and identity separation

- **Owner:** `SS`; `AP` remains owner of role/authorization and `K` of
  application binding/admission.
- **Inputs:** opaque bounded application bytes and an abstract selected
  session/context binding.
- **Preconditions:** the exact SS-0 profile has passed SSD-01.
- **Transition/disposition:** successful processing may emit authenticated
  plaintext bytes, member/session attribution, the exact session profile, a
  model-local observed-epoch diagnostic and one model-local typed disposition.
- **Forbidden substitutions:** membership, decryption, key possession or
  session attribution MUST NOT prove application author identity, role,
  authorization, causality, freshness or business truth. An observed epoch
  MUST NOT become a K-interface value.
- **Residual risks:** future K-to-SS binding bytes remain unspecified.
- **Non-claims:** this decision selects no application schema or K-to-SS wire,
  API or persisted representation.

### SSD-03 — Bounded opaque-payload path

- **Owner:** `SS` for the protected session payload; `AP`, `TR` and `PV` retain
  their own semantics.
- **Inputs:** opaque bounded application bytes and the exact two-member direct
  session.
- **Preconditions:** SSD-01 and SSD-02 hold.
- **Transition/disposition:** the bounded positive path protects and recovers
  exactly the opaque application bytes under the selected session profile.
- **Forbidden substitutions:** session success MUST NOT infer an application
  schema, transport envelope, metadata protection, attachment semantics,
  delivery or human receipt.
- **Residual risks:** size, timing, routing and endpoint exposure remain profile
  concerns outside SS-0.
- **Non-claims:** no transport, notification, attachment or product behavior is
  selected.

### SSD-04 — Staged authoritative session mutation

- **Owner:** `SS` stages and applies the session mutation; `RS` owns the
  abstract commit result.
- **Inputs:** an authenticated candidate membership or self-update mutation and
  exactly one RS result in `{COMMITTED, NOT_COMMITTED, INDETERMINATE}`.
- **Preconditions:** only proposal-free self-updates recorded by the Phase-B
  evidence are in the positive set.
- **Transition/disposition:** authentication stages the mutation without making
  it authoritative. Only `COMMITTED` permits authoritative application.
  `NOT_COMMITTED` leaves it unapplied. Missing or `INDETERMINATE` evidence
  halts, emits no success, advances no authoritative state and authorizes no
  automatic retry.
- **Forbidden substitutions:** ciphertext release, memory mutation, a journal
  entry, relay acknowledgement, time or local optimism MUST NOT replace the RS
  result.
- **Residual risks:** the authenticity, durability and recovery of an RS result
  are outside SS-0.
- **Non-claims:** no API, backend, transaction, journal, wire, storage ordering
  or persisted format is selected; the application-message write ordering of
  the pinned implementation is not characterized.

### SSD-05 — Epoch retention and duplicate replay

- **Owner:** `SS`.
- **Inputs:** message epoch, current group epoch and the applicable
  sender-ratchet/message-secret replay identity.
- **Preconditions:** the exact profile and the pinned Phase-B witnesses at
  distances zero, one, five and six are available.
- **Transition/disposition:** compare message epoch at receipt. The evidence
  profile records `{current-1 ... current-5}`; traffic at distances four and
  five is accepted and distance six is rejected. Traffic beyond the
  evidence-profile depth is rejected; distance zero is the current epoch and is
  accepted within the same bounded window. Separately, an exact duplicate replay
  is idempotent and emits neither duplicate plaintext nor a second state
  transition.
- **Forbidden substitutions:** retention MUST NOT be inferred from duplicate
  replay behavior or vice versa; checkpoint, wall time, relay order or storage
  presence MUST NOT replace the epoch or replay identity.
- **Residual risks:** logical availability does not prove secure physical
  retention or disposal.
- **Non-claims:** no storage quota, compaction, physical deletion, arbitrary
  replay window or general retention policy is selected.

### SSD-06 — Bounded concurrent-Commit convergence

- **Owner:** `SS`.
- **Inputs:** exactly two authenticated, proposal-free, depth-one, same-parent
  self-update candidates and their authenticated 32-byte committer account
  identities.
- **Preconditions:** there are no application witnesses; observed Phase-B
  values are `effective_commit_depth=1`, `witness_quorum_met=false`,
  `app_witness_score=0` and `tip_priority=ordinary`, with a validated
  `tip_digest`.
- **Transition/disposition:** unsigned lexicographic comparison of the raw
  authenticated committer identities selects the lower identity. The losing
  valid candidate remains non-authoritative/deferred evidence.
- **Forbidden substitutions:** application data, witness score, priority,
  arrival order, time, relay order or digest value MUST NOT select the branch.
  A proposal, third candidate, deeper branch, nonzero witness score,
  nonordinary priority or other out-of-profile input is `UNSUPPORTED` before
  selection.
- **Residual risks:** the retained losing candidate prolongs sensitive-state
  lifetime and the rule says nothing about general group convergence.
- **Non-claims:** no arbitrary convergence, pruning, compaction, finality or
  N-member behavior is selected.

### SSD-07 — Onboarding and one-shot logical consumption

- **Owner:** `SS`; rollback-stable custody remains `RS`.
- **Inputs:** framed non-last-resort KeyPackage, embedded-tree Welcome and exact
  profile/member binding.
- **Preconditions:** the input belongs to the exact positive evidence profile.
- **Transition/disposition:** consumption is a monotone logical transition in
  the SS-0 model. A modeled restart, replayed Welcome or asserted rollback does
  not re-enable the consumed KeyPackage.
- **Forbidden substitutions:** LastResort, external Commit, PSK, ReInit,
  rejoin, account rotation and multi-device onboarding are `UNSUPPORTED`.
  Opaque lifetime data MUST NOT be interpreted as physical time.
- **Residual risks:** a real rolled-back store can reuse material unless a
  future `OB-RS09`/O-16 design prevents it.
- **Non-claims:** no physical-time expiry, freshness, rollback resistance,
  production deletion or general onboarding policy is selected; O-12 remains
  `OPEN`. One-shot deletion is an upstream MLS requirement observed by the
  pinned profile, not an SS-0 protocol selection.

### SSD-08 — Bounded secret-lifecycle claim

- **Owner:** `SS` for logical session-secret use; `RS` owns physical custody.
- **Inputs:** the state logically required by SSD-05 and the losing candidate
  retained by SSD-06.
- **Preconditions:** the state belongs to the exact evidence-profile run.
- **Transition/disposition:** the model exposes only whether the required
  logical state is available for the bounded operation.
- **Forbidden substitutions:** logical absence or retention MUST NOT prove
  zeroization, secure deletion, rollback detection or physical custody.
- **Residual risks:** retained state can remain recoverable from memory,
  storage, backups or a compromised endpoint.
- **Non-claims:** no stronger forward-secrecy, post-compromise-recovery,
  zeroization, deletion or custody property is claimed beyond exact upstream
  and Phase-B evidence.

### SSD-09 — Persistence and restored-state boundary

- **Owner:** `SS` defines the indivisible logical mutation; `RS` owns durable
  commit, restore and rollback behavior.
- **Inputs:** the complete logical session mutation set and SSD-04 RS result.
- **Preconditions:** no partial member of the logical set is authoritative.
- **Transition/disposition:** authoritative application is conditional on
  SSD-04. Restored SS state is unvalidated until its owning layer revalidates
  it under the active profile.
- **Forbidden substitutions:** the Phase-B proof journal, a deserialized object
  or restored bytes MUST NOT be treated as authenticated durable product state.
- **Residual risks:** a coherent rollback may be invisible without an external
  anchor.
- **Non-claims:** no restore, recovery, rollback detection, result
  authentication, product storage or crash-atomicity mechanism is selected.

### SSD-10 — Closed diagnostic surface

- **Owner:** `SS` for model-local observations; O-10 remains owner of stable
  protocol outcome classes.
- **Inputs:** a bounded SS-0 validation or transition result.
- **Preconditions:** the observation is necessary to falsify SSD-01 through
  SSD-11.
- **Transition/disposition:** emit only a closed model-local disposition and
  redacted observation.
- **Forbidden substitutions:** a model disposition MUST NOT become a stable
  O-10 outcome, API or wire string. Output MUST NOT contain secret/plaintext
  bytes, stable group identifiers, absolute paths, host/user identity, runtime
  timing or evidence-package identity.
- **Residual risks:** multiple internal failures can intentionally collapse to
  one redacted observation.
- **Non-claims:** no product diagnostic, recovery promise or transport delivery
  taxonomy is selected.

### SSD-11 — Evidence provenance and invalidation

- **Owner:** `SS` for its evidence-profile identity; repository governance owns
  external provenance records.
- **Inputs:** exact Phase-B source/report identities, Gate-A-frozen normative
  digests, topology and operation identity.
- **Preconditions:** raw external evidence binds every identity; canonical
  reports use only closed artifact labels and content observations.
- **Transition/disposition:** matching inputs permit evaluation. Drift, missing
  identity, unsupported topology or an unrepresented operation invalidates the
  report and produces no narrower positive claim.
- **Forbidden substitutions:** canonical reports MUST NOT contain repository,
  commit, tree, diff, bundle, worktree or environment-derived provenance; a
  label or aggregate suite result MUST NOT replace a bound source identity.
- **Residual risks:** exact provenance does not establish correctness of the
  pinned code or evidence interpretation.
- **Non-claims:** no audit, product conformance, supported adapter, deployment
  safety or transferable upstream assurance follows.

## 3. Cross-decision invariants

1. SSD-01 failure prevents every positive disposition.
2. SSD-02 separation applies before and after every other SS decision.
3. SSD-04 persistence evidence gates authoritative mutation but never payload
   release, transport publication or human receipt claims.
4. SSD-05 retention and replay are independent mechanisms with independent
   witnesses and mutants.
5. SSD-06 has one selector and no application-derived selector input.
6. SSD-07 logical one-shot state is not rollback-resistant storage.
7. SSD-10 observations never enlarge SSD-01 through SSD-09.
8. SSD-11 drift invalidates evidence rather than negotiating a fallback.

## 4. Gate and reopening rule

These decisions become the frozen SS-0 normative source only when Gate A binds
this file's exact SHA-256 together with the other Phase-A files and verifier.
Any later byte change voids Gate A and all derived evidence. Reopening one
decision requires a new approved contract and human gate; an executor may not
reinterpret an unsupported input into an extension.
