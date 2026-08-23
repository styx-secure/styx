# Styx application-protocol hardening plan

> **Status:** active planning and ratification phase, 23 August 2026.
>
> This document governs the order of protocol work. It is not a protocol
> specification, security proof, implementation authorization or readiness
> claim. C0.3 remains `NO-GO`.

## 1. Purpose

Styx will not build product behavior on application-protocol semantics that are
still disputed, incomplete or supported only by one implementation. The active
priority is therefore to make the language-neutral application protocol
coherent, falsifiable and reviewable before resuming feature, runtime or product
integration work.

The phase deliberately trades short-term feature velocity for a smaller chance
of freezing unsafe authority, causality, retention or recovery behavior into
multiple implementations. Progress is measured by closed security obligations
and reproducible evidence, not by source lines, test counts or Issue counts.

## 2. Freeze boundary

While this phase is active, permitted work is limited to separately approved
increments that produce or reconcile:

- normative protocol decisions and exact language-neutral encodings;
- the application-protocol threat model and responsibility boundaries;
- machine-readable review-model records derived from normative sources;
- executable adversarial traces, mutation tests and deterministic reports;
- language-neutral conformance vectors after the corresponding semantics and
  bytes have been ratified;
- review evidence, finding disposition and explicit residual risks.

The following work is paused:

- product, SDK, adapter, PWA/UI and Themis/Flegias feature development;
- new wire, storage, vault or migration implementation;
- product activation of the secure-session proof;
- cleanup or refactoring that could obscure protocol provenance;
- demo, production, anonymity, compliance or sensitive-use claims.

An emergency security fix may proceed only under its own approved contract and
must not select new protocol semantics. Work proven to be disjoint from the
application protocol may proceed only when its Issue names the disjoint paths,
dependencies and integration owner. Neither exception silently lifts this
freeze.

Issue #233 and PR #234 remain isolated experimental work. Their local model and
simulator changes are preserved as candidate evidence, but are not normative,
ratified or eligible to support a security claim until their own contract and
human gates complete.

Only an explicit human-ratified exit verdict may end the freeze.

## 3. Authority and artifact classes

When artifacts disagree, fail closed and use this order:

1. an approved GitHub task contract and its native dependencies;
2. repository `AGENTS.md`;
3. the English decision registry, encoding profiles, responsibility matrix and
   threat model identified by the review model;
4. the derived machine-readable review model;
5. executable scenarios, mutants, generated reports and conformance vectors;
6. independent review reports and local notes.

The classes have different meanings:

| Class | Function | May select semantics? |
|---|---|---|
| Normative source | Defines accepted rules, bytes, ownership and non-claims | Yes, only through its approved process |
| Derived review model | Indexes and cross-checks normative claims | No |
| Executable evidence | Attempts to falsify a selected rule under bounded conditions | No |
| Conformance vector | Tests exact ratified semantics or bytes | No |
| Review report | Records independent findings and challenges | No |

A validator pass proves only that the checked artifact satisfies the validator's
closed rules. Agreement among implementations or reviewers does not repair a
shared omission. A finding changes protocol meaning only after the normative
source is amended and human-ratified.

## 4. Hardening sequence

Protocol increments proceed in dependency order:

1. **Close authority and succession semantics.** Complete C0.2j or retain an
   explicit `NO-GO`; cover credential identity, binding, grant, revocation,
   rotation, recovery, provenance, forks and bounded evaluation.
2. **Bind the commitment context.** Execute C0.2k only after C0.2j selects exact
   credential and sequence semantics.
3. **Falsify the combined construction.** Execute O-06c against the exact
   C0.2j/C0.2k bytes and rules, not an approximation.
4. **Resolve remaining C0.3 blockers.** Close or precisely scope O-07 genesis
   and checkpoint evidence, O-08 resource bounds, O-10 stable errors and O-14
   signature-suite binding. Resolve O-12 wherever a selected profile carries
   time.
5. **Reconcile the threat model.** Re-run hostile cases against the complete
   selected boundary, including cross-layer assumptions and newly introduced
   trust actors.
6. **Synchronize the derived model.** Update it only after normative changes;
   pin provenance and add negative fixtures for each new invariant or failure
   class.
7. **Produce C0.3.** Generate a specification-derived adversarial corpus and
   language-neutral vectors only for fully defined semantics and bytes.
8. **Obtain the phase verdict.** Independent exact-final review and human
   ratification produce `GO`, bounded `GO`, or `NO-GO` with residual risks.

No later step may be used to fill an unresolved input of an earlier one.

## 5. Mandatory threat coverage

Every applicable increment states which of these surfaces it changes and how it
is challenged:

- authentication versus application authorization;
- context, credential and author binding;
- causality, deterministic order, forks and duplicate evidence;
- grant, revocation, rotation, recovery and compromised provenance;
- concurrency, late evidence, rollback and incremental-versus-full replay;
- pending content, retention, removal and no-substitution behavior;
- genesis and checkpoint freshness, including substitution and stale evidence;
- resource exhaustion, cardinality, depth, work and storage bounds;
- cryptographic suite and downgrade binding;
- observer, metadata, transport, storage and runtime boundaries;
- availability loss caused by fail-closed safety rules.

The threat model must distinguish a malicious peer, compromised credential,
relay, storage backend, runtime/origin, operator and recipient. A proof against
one actor must not be presented as protection against another.

## 6. Bounded reviewer bundle

A reviewer starts with a small manifest rather than the whole repository. The
minimum bundle for a protocol increment contains:

1. the exact Issue body and base/final SHAs;
2. `AGENTS.md`;
3. this plan;
4. the changed normative sources and their directly referenced normative
   dependencies;
5. the relevant slice of the derived review model and its source/digest map;
6. the changed executable scenarios, mutants and deterministic reports;
7. the exact diff, required-command results and artifact digests;
8. prior unresolved findings that affect the increment.

The reviewer may inspect the entire repository and public standards when useful.
The bundle limits mandatory context; it does not forbid investigation. Omitting a
material dependency to reduce tokens invalidates the review.

## 7. Per-increment gate

Every protocol increment requires:

- an approved bounded contract with non-goals, allowed paths, frozen interfaces,
  exact tests, rollback and residual risks;
- named hostile witnesses and a mapping from obligations to assertions;
- relevant mutants, including intra-rule and cross-rule failures rather than
  only happy-path or block-local tests;
- deterministic reports generated twice and compared byte for byte;
- normative-source changes before derived-model changes;
- explicit disposition and re-verification of every material finding;
- exact-final independent review for substantial security increments;
- human review and ratification through the approved gates.

Silence, timeout, truncation, non-determinism, an unexpected skip or an absent
artifact is failure, not evidence of success. Review frequency may be reduced by
grouping coherent work, but review depth and independence are not reduced.

## 8. Exit gates

The phase may end only when all applicable conditions are true:

1. every C0.3 blocker is closed, or the final contract excludes it from a
   precisely defined corpus without making the excluded claim;
2. no unresolved `BLOCKING` or `HIGH` finding remains in the phase scope;
3. normative sources, the derived model, scenarios, vectors and threat model are
   mutually consistent at the exact final SHA;
4. required adversarial traces and mutants pass deterministically, with no
   unexplained survivor or cascading failure that hides the intended assertion;
5. cross-implementation or independent-oracle evidence exists for every claimed
   language-neutral behavior;
6. resource and availability costs of fail-closed behavior are measured and
   stated, not assumed away;
7. security claims and non-claims name their actors, scope and residual risks;
8. an independent exact-final review reports no unresolved blocking finding;
9. the authorized humans ratify an explicit `GO`, bounded `GO`, or `NO-GO`.

A bounded `GO` authorizes only the named corpus or next contract. It does not
authorize product code, deployment or sensitive use.

## 9. Work after the freeze

After a passing exit verdict, work resumes through separate contracts in this
order:

1. C0.3 specification-derived corpus and conformance evidence, if not already
   included in the exit verdict;
2. minimum language-neutral application-core interface;
3. independently testable implementation(s) against the conformance corpus;
4. supported secure-session adapter and authenticated persistence boundaries;
5. reliable delivery and runtime profiles;
6. synthetic Themis/Flegias scenarios, then separately gated field readiness.

The current browser PWA remains one runtime profile, not the protocol authority.
No post-freeze item is automatically approved by this document.

## 10. Progress reporting

Status reports use this table and cite evidence:

| Measure | Meaning |
|---|---|
| Obligations closed | Ratified security obligations with reproduced evidence |
| Blockers open | Decisions or findings that still prevent the next gate |
| Evidence complete | Required traces, mutants, vectors and deterministic reports present |
| Review complete | Exact-final independent findings disposed and re-verified |
| Human verdict | Explicit `GO`, bounded `GO` or `NO-GO` |

Percentages, when used, must be derived from the declared obligation set and must
not be interpreted as a probability of security.

## 11. Current state

At adoption of this plan:

- the review model exists and is useful for bounded inspection;
- C0.2j is active experimental work under Issue #233 / PR #234;
- C0.2k and O-06c depend on C0.2j;
- O-07, O-08, O-10 and O-14 remain open;
- C0.3 remains `NO-GO`;
- demo, product and sensitive-use claims remain blocked.

This state is intentionally conservative. The freeze ends only through section
8, not through elapsed time, reviewer consensus or pressure to demonstrate a
feature.
