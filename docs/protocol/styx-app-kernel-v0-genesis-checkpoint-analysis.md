# O-07 genesis and checkpoint analysis

## 1. Scope and authority

This document explains the bounded O-07 selection ratified in Issue #248. The
normative rules live in the O-07 decision record and section 6 of the transcript
encoding profile. This analysis neither defines product storage nor supplies an
alternative protocol authority.

O-07 instantiates existing inputs: the O-03 context tuple, O-06b-1 transcript
domains and full-width SHA-256 references, and O-14 signature suite `0x0001`.
It creates no domain, suite, wire object, storage object or checkpoint role.

## 2. Single-root genesis

V0 selects one context-local root. The genesis body contains exactly the
protocol version, AP identifier and version, fresh context identifier, derived
signature-suite identifier, canonical 32-octet root verification key and the
complete non-empty initial AP authority/policy block. The root credential
identifier is exactly the derived `genesis_reference`.

This selection avoids a second credential-identity construction. Threshold and
precommitted root sets are not selectable in v0 because they would require new
domain roles, participant-set semantics and an authority rule that O-02 does
not currently define.

The AP block names the root only by its fixed positional role. It cannot contain
the reference that is derived only after the transcript is complete. This is
what keeps the construction non-circular.

## 3. Trust establishment and the five gates

An acceptor presents a ceremony assertion `R` to its own locally configured
`CeremonyBoundary` through a channel independent of candidate delivery. `R`
has exactly three semantic bindings: the O-03 tuple, expected genesis reference
and explicit authorization decision. Authenticated provenance is not a fourth
caller-supplied field. Successful independent verification causes the local
Boundary to issue an opaque, non-exportable `VerifiedCeremonyCapability` bound
to that Boundary, acceptance domain and immutable tuple/reference pair. It
supplies no separate suite, key or policy block.

| Gate | Owner | Input | Success means | Does not mean |
| --- | --- | --- | --- | --- |
| Possession | AP bootstrap | Local Boundary verification and capability issuance | The acceptor independently authenticated the intended ceremony statement | Candidate validity or authority |
| Cryptographic validity | K | Parsed transcript, root key, O-14 signature | The root key authenticated these exact bytes | AP authorization |
| Structural binding | K | Recomputed reference and capability-bound O-03 tuple | Candidate bytes match the locally verified ceremony and context | Real-world legitimacy |
| Initial authority | AP | Validated AP block plus capability-bound affirmative decision | The selected AP authorizes the root | Durability or availability |
| Local acceptance | RS abstract transition | All prior gates | The immutable accepted pair is fixed locally | Crash atomicity or rollback resistance |

PV discloses the trust decision and residual limits; it authorizes nothing.
Session membership, relay acceptance, signature validity, possession, storage
presence and UI state cannot substitute for AP authority.

Creator initialization returns separate `CreatorLocalGenesisState`; it never
creates an acceptor capability. That self-certifying local action is not
evidence for another replica. Every later participant may receive the same
semantic ceremony assertion, but its own Boundary must authenticate it and
issue a fresh local capability. A capability, alias, copy, reconstruction,
lookalike or foreign-domain/foreign-Boundary handle is never transferable.

## 4. Acceptance state

The abstract acceptance transition consumes one valid local capability and
atomically fixes the accepted O-03 tuple and `genesis_reference`. K receives
the tuple/reference pair as immutable
configuration and never queries live AP or RS state while validating later
objects.

- an exact duplicate is idempotent;
- a distinct genesis for the same context is rejected;
- every descendant bound to the rejected genesis is rejected;
- the accepted projection is unchanged by either rejection;
- without a matching capability issued by the local Boundary, no candidate is accepted;
- arrival, relay, storage, lexical and wall-clock order never select a root.

The first genesis-authored application event uses the genesis reference in both
common field 11 (credential identity) and common field 16 (context genesis
binding). Equality follows from their independent positional meanings and never
creates authority. Any K-valid `GRANT` whose derived event reference equals the
genesis credential is rejected before binding. Adversarial evidence exercises
that post-derivation boundary through an injected equality oracle; it does not
claim a practical SHA-256 collision.

## 5. Checkpoint boundary

Checkpoint use is split by effect.

Grant-side use would let a producer or signer create authority, replace AP
replay, reconstruct content/openings, claim freshness/finality or define a
horizon. Every such use is `UNSUPPORTED` in v0. There is no checkpoint object,
domain, producer, signer, threshold, compaction operation or possession signal.

Suppress-side use retains the O-02/O-04 rule that a dependency available only
as checkpoint evidence makes the whole projection stale. Its trigger is
structurally unreachable in v0: `checkpoint_evidence_refs` is always empty,
while `replay_dependency_refs` contains every live authority transcript and
`REQUIRED` opening needed by replay. Checkpoint-like material from a peer,
relay, runtime, fixture, flag, file or retention summary is rejected before
projection. The evidence deliberately uses a non-empty dependency set so the
unreachability proof is not vacuous.

## 6. Failure and residual risk

Single-root v0 deliberately prefers one explicit trust decision over implicit
selection. The availability cost is severe: reduction or equivocation of the
root can terminate the complete authority lineage. The context may remain
permanently authority-unavailable. No automatic recovery, finality or
availability is promised.

The ceremony Boundary is an abstract trust premise, not proof that an
organization or person is legitimate. Its production transport, credential,
trusted path and issuer-held witness remain unselected. A compromised Boundary,
issuer configuration, product operator, runtime or acceptance store can install
an attacker root and voids the root-of-trust guarantee. Exact persistence, trusted-path UX,
rollback-resistant custody and onboarding delivery remain later AP/PV/RS/O-11
work. A coherent whole-profile rollback can remain undetectable.

No-substitution v0 can require full history retention and can fail closed when
necessary evidence is withheld. O-08 still owns enforceable resource bounds and
O-10 owns stable outcome codes. Any future checkpoint capability must reopen
the affected O-01/O-02/O-04/O-07 and threat-model decisions before activation.
