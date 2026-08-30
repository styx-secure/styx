# Styx application-protocol hardening plan

> **Status:** active protocol-hardening and ratification phase, 30 August 2026.
>
> This document governs the order of protocol work. It is not a protocol
> specification, security proof, implementation authorization or readiness
> claim. Issue #266 / merged PR #267 records a bounded evidence GO for the
> exact D4 transcript/K corpus and evidence package only. C0.3 remains `NO-GO`
> for implementation alignment, demo, product and sensitive use.

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
  bytes have been ratified and the K-11 Apache-2.0 path inventory has been
  separately approved in Issue #253 before the first corpus file is created;
- extraction of reference cases and independent oracles from existing
  implementations into the language-neutral corpus, provided this adds no
  behavior to those implementations and selects no protocol semantics;
- review evidence, finding disposition and explicit residual risks.

The following work is paused:

- product, SDK, adapter, PWA/UI and Flegias or successor-vertical feature
  development;
- new wire, storage, vault or migration implementation;
- product activation of the secure-session proof;
- cleanup or refactoring that could obscure protocol provenance;
- demo, production, anonymity, compliance or sensitive-use claims.

This freeze binds both execution lanes defined in `AGENTS.md`: Styx contract
tasks on `task/<issue>-<slug>` and MUCC stories on `task/US-<id>`. A story in
`specs/05-sprint-plan.md` is not executable during this phase merely because it
satisfies the ordinary MUCC lane condition; US-001 through US-008 are paused.
The scope-evidence check does not inspect `task/US-*`, so review must enforce
this constraint explicitly.

Any human-approved security remediation, emergency or otherwise, may proceed
under its own approved contract only when it selects no new protocol semantics.
Routine dependency, CI, licensing or governance maintenance may proceed under
an approved contract only when an authorized human ratifies before execution
that it changes no protocol artifact. Work claimed to be disjoint from the
application protocol may proceed only when its Issue names the disjoint paths,
dependencies and integration owner and an authorized human ratifies that
determination before execution. Every exception is recorded for the exit audit
in section 8. Neither exception silently lifts this freeze.

Issue #233 and PR #234 remain isolated experimental work. Their local model and
simulator changes are preserved as candidate evidence, but are not normative,
ratified or eligible to support a security claim until their own contract and
human gates complete.

Only an explicit human-ratified exit verdict may end the freeze.

## 3. Authority and artifact classes

When artifacts disagree, fail closed and use this order:

1. an approved GitHub task contract, or an executable MUCC story, and its
   native dependencies, subject to this phase boundary;
2. repository `AGENTS.md`;
3. this plan for the order and gating of work during this phase;
4. the ratified English normative sources enumerated below;
5. tool adapters such as `CLAUDE.md`;
6. the derived machine-readable review model;
7. executable scenarios, mutants, generated reports and conformance vectors;
8. independent review reports, chat and local notes.

An item at rank 1 governs its approved scope but cannot silently supersede a
native dependency, this freeze or a human gate. An approved amendment may
change how the freeze operates; it cannot end it. Ending the freeze requires
the exit verdict in section 8.
Where another active plan conflicts with this plan, this plan governs the order
of application-protocol work; the other plan continues to govern its disjoint
domain.

### 3.1 Normative source index

The current application-protocol normative set is enumerated here, independently
of the derived review model:

- decision registry:
  `docs/protocol/styx-app-kernel-v0-decisions.md`;
- transcript encoding profile:
  `docs/protocol/styx-app-kernel-v0-transcript-encoding-profile.md`;
- commitment encoding profile:
  `docs/protocol/styx-app-kernel-v0-commitment-encoding-profile.md`;
- responsibility matrix:
  `docs/protocol/styx-app-kernel-v0-responsibility-matrix.md`;
- application-protocol threat model:
  `docs/security/STYX-THREAT-MODEL.md`.

The derived review model at
`docs/protocol/review/styx-app-kernel-v0-review-model.json` is verified against
this enumeration; it does not define it. A normative source omitted from the
model's `sources` map remains normative and makes validation fail. A model entry
with no ratified normative source is an error, not an addition to the normative
set. The model schema and operating guide are respectively
`docs/protocol/review/styx-app-kernel-v0-review-model.schema.json` and
`docs/protocol/review/README.md`.

The source index and the validator's pinned source tuples are independent
copies whose equality is review-enforced until a separately approved validator
can check the plan directly. Any mismatch blocks validation and phase exit.

Frozen sections use one extraction rule: hash the raw contiguous bytes
beginning at the first octet of the selected `## N.` heading and ending
immediately before the first octet of the next `## ` heading. Every stored octet
in that slice, including all trailing LF octets before the next heading, is
retained without normalization, insertion, removal or line-ending conversion.
The rule is defined only where a following `## ` heading exists and fails
closed otherwise. A selected section containing a line that begins `## ` inside
a fenced block, with the first `#` at column zero, is not hashable by this rule
and requires a separately ratified extractor/version before it may be pinned.

The O-06c handoff pins these independently reproduced base-SHA inputs:

- O-06b-1 section 4, seven-role registry:
  `5b6bc4041b028ead4821cd7d33bb102255d7df728309e2e8bef232f16c9e3fb3`;
- O-06b-2 section 6, logical-removal tail:
  `14bcde53d5534584e3cd1ba2503a3bb755df112ed0d42485cf9f1bef61b1f7f8`;
- O-06b-2 section 2, current 84-octet commitment context:
  `9efff974cbc69ae58a2c2c883347c90129587cf9a7355f046c5b0f437e1234b1`;
- O-06b-1 section 5, frozen application-event field inventory and role/tail
  grammar:
  `f3f074befc0d258345b2e067f97a0eabbb08069591fb30b7c508f2ff56d5d8c1`;
- O-06b-2 section 3, frozen exact commitment preimages and widths:
  `4ec776a1bbb8bb044de235ec0a8e34a61158d7d30e33bf1146d1787b6765abf0`;
- O-06b-2 section 4, frozen inverse/parsing and tree-layout rules:
  `ce6172a9843a43628fff2f36c70336b5df49e8713b5ea3822f9b6e8e5f57037e`.

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
2. **Bind the commitment context.** Preserve the C0.2k 84-octet context selected
   only after C0.2j fixed exact credential and sequence semantics; require its
   exact-final evidence and human gates before treating it as complete.
3. **Falsify the combined construction.** Execute O-06c against the exact
   C0.2j/C0.2k bytes and rules, not an approximation. The current gate reruns
   v1, v2, v3 and C0.2k baseline and mutation evidence and binds each historical
   digest to its expected verdict and exit status; two byte-identical failures
   are failure, not determinism evidence. The identifier-derivation analysis's
   rerun list is historical and non-exhaustive and is not the current gate.
   O-06c must repair or independently compensate for two known evidence
   limitations: the v2 mutation harness is not reproducible from a read-only
   checkout because its copy preserves unwritable modes, a failed report can
   contain a random absolute path and its deterministic flag is not trustworthy
   after abort; and the C0.2k harness has a weaker kill predicate than v3, some
   claimed context-witness families do not execute the supplied mutant, and the
   current baseline relies on the M08/M09 mutation helpers rather than
   independently supplying all promised context witnesses. These limitations
   do not silently invalidate the selected 84-octet grammar and prose cannot
   convert them into passing evidence.
   **Completed by Issue #243:** the new isolated package compensates for those
   historical limits, independently encodes the selected bytes in Python and
   JavaScript, kills the closed 16-class source-mutant registry, challenges all
   selected complete-object octets and explicit scalars, and reproduces the
   frozen six-section and seven-entry historical registries. Its positive
   verdict is bounded evidence with explicit placeholder-triggered reruns, not
   proof, conformance, implementation or readiness authority.
4. **Resolve remaining C0.3 blockers.** O-07 fixes single-root genesis and
   rejects checkpoint substitution in v0; O-08 is bounded `DECIDED` after
   replacement human selection of the transcript-only `balanced` resource
   envelope, two-clean-checkout evidence and exact-HEAD gates. O-10 closes the
   bounded trusted-local taxonomy and opaque remote collapse without selecting
   wire/API codes. O-14 is condition-bearing `DECIDED`; Issue #260 replaces its
   O-06c placeholder with the selected signature semantics and reruns the
   complete combined evidence. Its exact-final technical reproducibility gate
   passes, and independent review and human gates completed in merged PR #261
   at `490689f0d81980cf942d448c76a54192913b7cde`. Resolve O-12 wherever a
   selected profile carries time.
   Issue #255 is a bounded procedural predecessor to O-10 only: it pins the
   historical evidence guards to their exact candidate identities and supplies
   the reusable AST allowlist and O-14-removal rejection required by O-08's
   recorded exception. It selects no protocol semantics and does not add a C0.3
   dependency.
5. **Reconcile the threat model.** Re-run hostile cases against the complete
   selected boundary, including cross-layer assumptions and newly introduced
   trust actors.
6. **Synchronize the derived model.** Update it only after normative changes;
   pin provenance and add negative fixtures for each new invariant or failure
   class.
7. **Authorize the corpus licensing boundary — complete in Issue #253.** The
   exact twelve-path Apache-2.0 inventory now includes six absent future C0.3
   data paths. This licensing gate creates no corpus byte and does not authorize
   C0.3.
8. **Produce and reconcile C0.3 — bounded evidence completed by Issue #266 /
   merged PR #267.** Issue #264 constructed the six-file,
   synthetic-only specification-derived corpus preserves 17 historical valid
   transcript byte sequences, contains 36 local-negative records, 128
   state/flow/counterexample/vector/invariant/history/dependency scenarios and
   522 adversarial mutations. Its v2 connected surface adds three positive and
   17 hostile authority graphs with 84 candidate observations. Every vector is
   executed; every counterexample has a
   distinct three-step program and observation; every executable invariant has
   a one-to-one semantic witness and hostile substitution. The vectors include
   distinct contexts, authors and dependency cardinalities, selected-bound
   witnesses, over-limit inputs, profile substitution, parent reordering and an
   overlong fixed-width integer. Coverage and manifest mutants are materialized
   and rejected by the same production corpus validators, but are classified as
   evidence-integrity checks rather than semantic invariant witnesses.
   Independent Python and JavaScript replay and relation validation agree byte
   for byte, and a fresh oracle-free reader independently derived the same
   public transcript/K observations. The reviewed candidate and merged `main`
   have the same exact tree. The resulting bounded evidence GO remains corpus
   and conformance evidence only; it does not authorize implementation
   alignment, demo, product or sensitive use.
9. **Obtain the phase verdict.** Independent exact-final review and human
   ratification produce `GO`, bounded `GO`, or `NO-GO` with residual risks.

No later step may be used to fill an unresolved input of an earlier one.

The dependency basis is explicit:

| Step | Required closed inputs | Deferred or repeated work |
|---|---|---|
| C0.2j | ratified O-01/O-02/O-03/O-04/O-05/O-09 baseline | none |
| C0.2k | exact C0.2j credential and sequence semantics | selected 84-octet context plus bounded model/mutation evidence; exact-final review and human gates complete the increment |
| O-06c | exact C0.2j/C0.2k bytes and existing O-06b profiles | completed as bounded evidence by Issue #243; obligations affected by later O-07/O-08/O-10/O-14 decisions are rerun or reopened after those decisions |
| remaining blockers | O-06c results plus each decision's own recorded inputs | Issue #260 / merged PR #261 reruns the integrated O-14/O-06c hostile cases; exact-final technical evidence, independent review and human gates pass |
| K-11 corpus boundary | `DECIDED` by the exact Issue #253 six-path amendment; twelve Apache paths total | Issue #264 populates only the approved synthetic paths; no third-party corpus byte is authorized |
| C0.3 | all seven frozen Issue #251 entry items satisfied by Issue #262; corpus construction completed by Issue #264; exact D4 transcript/K reconciliation, blind corroboration and bounded evidence GO completed by Issue #266 / merged PR #267 | implementation alignment and the full phase-exit verdict remain separate gated work; C0.3 remains `NO-GO` for demo, product and sensitive use |

For visibility, every O-series objective in the current registry is accounted
for below. Absence from this table is an error in this plan, not evidence that
an objective is closed. Where the table and the decision registry disagree, the
registry governs and this plan must be corrected.

| Objectives | Registry status | Effect on this phase |
|---|---|---|
| O-01 through O-05 | `DECIDED` | preserved inputs; reopen only through their recorded conditions |
| O-06 | condition-bearing `DECIDED` | Issue #243 completed bounded O-06c evidence; recorded placeholder decisions and later counterexamples trigger rerun/reopen |
| O-07 | bounded `DECIDED` | retains its satisfied C0.3 dependency edge; Issue #264 exercises it only through the exact transcript-only corpus |
| O-08 | bounded `DECIDED` | replacement `balanced` selection, two-clean-checkout evidence, exact-HEAD reviews and technical human approval complete; Issue #255 carries the separately gated procedural AST-guard remediation; retained C0.3 edge; no product/runtime claim |
| O-10 | bounded `DECIDED` | 25 trusted-local primaries plus opaque untrusted-remote collapse; final Issue #252 evidence and merged PR #257 human gates completed; no wire/API selection |
| O-14 | condition-bearing `DECIDED` | closed suite; Issue #260 / merged PR #261 completed the separately ratified combined rerun, exact-final evidence, independent review and human gates |
| O-09 | `DECIDED` | preserved responsibility split |
| O-11 | `OPEN` | intentionally deferred; does not block a strictly transcript-only C0.3 corpus |
| O-12 | `OPEN`, profile-conditional | blocks every profile retaining physical-time claims; inapplicable only when time is omitted |
| O-13, O-15, O-16 | `OPEN` | do not block a strictly pinned transcript-only C0.3 corpus; block applicable destruction, profile-upgrade, finality and product-readiness claims |

## 5. Mandatory threat coverage

Every applicable increment states which of these surfaces it changes, which it
does not change and why, and how each changed surface is challenged:

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
relay, network observer, push provider, storage backend, runtime/origin, client
publisher, operator and recipient, following the actor taxonomy in
`docs/platform/application-capability-model.md` section 3. A proof against one
actor must not be presented as protection against another.

## 6. Bounded reviewer bundle

A reviewer starts with a small manifest rather than the whole repository. The
minimum bundle for a protocol increment contains:

1. the exact Issue body and base/final SHAs;
2. `AGENTS.md`;
3. this plan;
4. the normative source index in section 3.1, the changed normative sources and
   their directly referenced normative dependencies;
5. `docs/security/STYX-THREAT-MODEL.md`,
   `docs/protocol/styx-app-kernel-v0-responsibility-matrix.md`, and the relevant
   slice of `docs/protocol/review/styx-app-kernel-v0-review-model.json` with its
   source/digest map;
6. the changed executable scenarios, mutants and deterministic reports;
7. the exact diff, required-command results and artifact digests;
8. final-SHA provider status for every required check, including scope-evidence
   status and report; absent, cancelled or unexpectedly skipped is failure;
9. prior unresolved findings that affect the increment.

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
- exact-final independent review for every increment that changes a normative
  source, ratified byte encoding, authority or revocation rule, or threat model;
  any other exemption must be justified in its contract and re-verified at the
  phase exit;
- human review and ratification through the approved gates.

Silence, timeout, truncation, non-determinism, an unexpected skip or an absent
artifact is failure, not evidence of success. Review frequency may be reduced by
grouping coherent work, but review depth and independence are not reduced.

## 8. Exit gates

The phase may end only when all applicable conditions are true:

1. every unconditional C0.3 blocker is closed; a conditional blocker may be
   excluded from a precisely defined corpus only where the decision registry
   explicitly records that non-blocking condition and the excluded claim is
   not made; C0.2j, C0.2k and O-06c cannot be excluded;
2. no unresolved `BLOCKING` or `HIGH` finding remains in the phase scope;
3. the enumerated normative sources, derived-model source map, scenarios,
   vectors and threat model are mutually consistent at the exact final SHA; an
   omitted normative source remains a failure rather than shrinking the set;
4. required adversarial traces and mutants pass deterministically, with no
   unexplained survivor or cascading failure that hides the intended assertion;
5. cross-implementation or independent-oracle evidence exists for every claimed
   language-neutral behavior;
6. resource and availability costs of fail-closed behavior are measured and
   stated, not assumed away;
7. security claims and non-claims name their actors, scope and residual risks;
8. an independent exact-final review reports no unresolved blocking finding,
   with distinct reviewer identity and execution context evidenced as required
   by `AGENTS.md`;
9. the authorized humans ratify an explicit `GO`, bounded `GO`, or `NO-GO`.
10. every exception invoked under section 2 is enumerated with its Issue,
    ratifying human, touched paths and finding that it selected no protocol
    semantics; any unreconciled exception is blocking.
11. K-11's exact Apache-2.0 corpus-path inventory and required licensing
    amendments were approved in Issue #253 before the first C0.3 corpus file
    was created.

A bounded `GO` authorizes only the named corpus or next contract. It does not
authorize product code, deployment or sensitive use.

While the freeze remains active, a separately contracted SS-0 increment may
proceed only if it is limited to the Section 2 artifact classes: normative
decisions, threat-model/responsibility reconciliation, synchronized derived-
model records and bounded executable adversarial evidence. It may not create or
change conformance-corpus bytes, adapters, product code, wire or storage
formats, persistence behavior, transport selection or deployment behavior.

### 8.10 Closed first-parent exception audit

This audit covers the literal first-parent range from the freeze merge through
the Issue #283 Base. `CONFORMING` means that immutable provider evidence places
the increment inside the named plan lane or a previously recorded exception;
it is not a security verdict. A row that needs a new historical determination
remains `UNRECONCILED/BLOCKING` until an authorized human makes that decision
explicitly. The later determination is never backdated to execution time.

The exact path set for each pull request is the provider `files` response linked
in the path column. The associated-pulls response is checked independently for
every commit; the one empty association below is evidence, not an inference
from its subject.

<!-- styx-section8-exception-audit:v1:start -->
| Commit | Subject | Issue / PR association | Touched paths / path set | Closed class | Ratifying-human evidence | Integration owner | Provider evidence | Semantic finding | Reconciliation outcome |
|---|---|---|---|---|---|---|---|---|---|
| `8f30f1940e4417fcb47b156b08c2242f405dc09b` | Establish the protocol-hardening freeze | Issue [#235](https://github.com/styx-secure/styx/issues/235) / PR [#236](https://github.com/styx-secure/styx/pull/236) | [5 exact paths](https://api.github.com/repos/styx-secure/styx/pulls/236/files) | `FREEZE_BASELINE` | [contract ratification 5385215554](https://github.com/styx-secure/styx/issues/235#issuecomment-5385215554); [final ratification 5385459344](https://github.com/styx-secure/styx/pull/236#issuecomment-5385459344) | `maverde73` via PR #236 | [commit](https://api.github.com/repos/styx-secure/styx/commits/8f30f1940e4417fcb47b156b08c2242f405dc09b); [association](https://api.github.com/repos/styx-secure/styx/commits/8f30f1940e4417fcb47b156b08c2242f405dc09b/pulls) | Establishes the freeze; selects no protocol semantic. | `CONFORMING` |
| `d28deb4ac8fe00718201c7384a4b7e18fda1b296` | Select and falsify credential succession | Issue [#233](https://github.com/styx-secure/styx/issues/233) / PR [#234](https://github.com/styx-secure/styx/pull/234) | [21 exact paths](https://api.github.com/repos/styx-secure/styx/pulls/234/files) | `PLAN_INCREMENT` | [contract ratification 5386313008](https://github.com/styx-secure/styx/issues/233#issuecomment-5386313008); [final ratification 5388510070](https://github.com/styx-secure/styx/pull/234#issuecomment-5388510070) | `maverde73` via PR #234 | [commit](https://api.github.com/repos/styx-secure/styx/commits/d28deb4ac8fe00718201c7384a4b7e18fda1b296); [association](https://api.github.com/repos/styx-secure/styx/commits/d28deb4ac8fe00718201c7384a4b7e18fda1b296/pulls) | Ratified C0.2j credential/succession semantics and bounded evidence within the ordered plan. | `CONFORMING` |
| `745de6d8954a39ad3a39e9ccc5303ba08fa8508c` | Harden review-model validation | Issue [#232](https://github.com/styx-secure/styx/issues/232) / PR [#238](https://github.com/styx-secure/styx/pull/238) | [4 exact paths](https://api.github.com/repos/styx-secure/styx/pulls/238/files) | `EXCEPTION_ROUTINE_MAINTENANCE` | [contract ratification 5390630845](https://github.com/styx-secure/styx/issues/232#issuecomment-5390630845); [final ratification 5391111223](https://github.com/styx-secure/styx/pull/238#issuecomment-5391111223); [present determination 5468111470](https://github.com/styx-secure/styx/pull/284#issuecomment-5468111470) | `maverde73` via PR #238 | [commit](https://api.github.com/repos/styx-secure/styx/commits/745de6d8954a39ad3a39e9ccc5303ba08fa8508c); [association](https://api.github.com/repos/styx-secure/styx/commits/745de6d8954a39ad3a39e9ccc5303ba08fa8508c/pulls) | Non-normative validator hardening; frozen model and normative sources were reported byte-identical. The present determination confirms the exception without backdating it. | `RETROACTIVE_HUMAN_DETERMINATION(5468111470)` |
| `6676be641a4b3edc250fcb59ce9c7dd39c4ad8cc` | Bind commitments to credential and sequence | Issue [#239](https://github.com/styx-secure/styx/issues/239) / PR [#240](https://github.com/styx-secure/styx/pull/240) | [19 exact paths](https://api.github.com/repos/styx-secure/styx/pulls/240/files) | `PLAN_INCREMENT` | [contract ratification 5391758126](https://github.com/styx-secure/styx/issues/239#issuecomment-5391758126); [completion 5393446984](https://github.com/styx-secure/styx/issues/239#issuecomment-5393446984) | `maverde73` via PR #240 | [commit](https://api.github.com/repos/styx-secure/styx/commits/6676be641a4b3edc250fcb59ce9c7dd39c4ad8cc); [association](https://api.github.com/repos/styx-secure/styx/commits/6676be641a4b3edc250fcb59ce9c7dd39c4ad8cc/pulls) | Ratified C0.2k commitment-context semantics and bounded evidence within the ordered plan. | `CONFORMING` |
| `3f439189e0cbe4071f642c693dbb196b477a48ea` | Reconcile the O-06c handoff | Issue [#241](https://github.com/styx-secure/styx/issues/241) / PR [#242](https://github.com/styx-secure/styx/pull/242) | [7 exact paths](https://api.github.com/repos/styx-secure/styx/pulls/242/files) | `SECTION_7_EXEMPTED_INCREMENT` | [final contract ratification 5396241901](https://github.com/styx-secure/styx/issues/241#issuecomment-5396241901); [completion 5396477958](https://github.com/styx-secure/styx/issues/241#issuecomment-5396477958) | `maverde73` via PR #242 | [commit](https://api.github.com/repos/styx-secure/styx/commits/3f439189e0cbe4071f642c693dbb196b477a48ea); [association](https://api.github.com/repos/styx-secure/styx/commits/3f439189e0cbe4071f642c693dbb196b477a48ea/pulls) | Reconciles contradictory prose/provenance only; no wire, persisted, runtime or new protocol semantic; the Section 7 evidence exemption remains a residual exit risk. | `CONFORMING` |
| `94f0a9b2781d45324199e6588629d23babedf746` | Execute the O-06c falsification gate | Issue [#243](https://github.com/styx-secure/styx/issues/243) / PR [#244](https://github.com/styx-secure/styx/pull/244) | [36 exact paths](https://api.github.com/repos/styx-secure/styx/pulls/244/files) | `PLAN_INCREMENT` | [contract ratification 5398321811](https://github.com/styx-secure/styx/issues/243#issuecomment-5398321811); [completion 5401803354](https://github.com/styx-secure/styx/issues/243#issuecomment-5401803354) | `maverde73` via PR #244 | [commit](https://api.github.com/repos/styx-secure/styx/commits/94f0a9b2781d45324199e6588629d23babedf746); [association](https://api.github.com/repos/styx-secure/styx/commits/94f0a9b2781d45324199e6588629d23babedf746/pulls) | Supplies bounded O-06c executable evidence without implementation or readiness authority. | `CONFORMING` |
| `86c3f2dbd630e445d737a25c09889de2777ee185` | Close O-14 with a guarded signature suite | Issue [#246](https://github.com/styx-secure/styx/issues/246) / PR [#247](https://github.com/styx-secure/styx/pull/247) | [30 exact paths](https://api.github.com/repos/styx-secure/styx/pulls/247/files) | `PLAN_INCREMENT` | [contract ratification 5402987067](https://github.com/styx-secure/styx/issues/246#issuecomment-5402987067); [suite selection 5403171142](https://github.com/styx-secure/styx/issues/246#issuecomment-5403171142) | `maverde73` via PR #247 | [commit](https://api.github.com/repos/styx-secure/styx/commits/86c3f2dbd630e445d737a25c09889de2777ee185); [association](https://api.github.com/repos/styx-secure/styx/commits/86c3f2dbd630e445d737a25c09889de2777ee185/pulls) | Ratifies the bounded internal signature-suite language and evidence; no product/runtime conformance. | `CONFORMING` |
| `ba0525da1dd78c76c5cc60bc2041e2d3bed44bb3` | Decide O-07 genesis and checkpoint evidence | Issue [#248](https://github.com/styx-secure/styx/issues/248) / PR [#249](https://github.com/styx-secure/styx/pull/249) | [41 exact paths](https://api.github.com/repos/styx-secure/styx/pulls/249/files) | `PLAN_INCREMENT` | [consolidated contract ratification 5411849432](https://github.com/styx-secure/styx/issues/248#issuecomment-5411849432); [human review 5028648088](https://github.com/styx-secure/styx/pull/249#pullrequestreview-5028648088) | `maverde73` via PR #249 | [commit](https://api.github.com/repos/styx-secure/styx/commits/ba0525da1dd78c76c5cc60bc2041e2d3bed44bb3); [association](https://api.github.com/repos/styx-secure/styx/commits/ba0525da1dd78c76c5cc60bc2041e2d3bed44bb3/pulls) | Ratifies bounded single-root genesis and checkpoint non-substitution evidence; production ceremony and recovery remain non-claims. | `CONFORMING` |
| `c9a0420e8cf26606c4c87d7fe7b610beb31133ef` | Bound the O-08 C0.3 resource envelope | Issue [#250](https://github.com/styx-secure/styx/issues/250) / PR [#254](https://github.com/styx-secure/styx/pull/254) | [41 exact paths](https://api.github.com/repos/styx-secure/styx/pulls/254/files) | `PLAN_INCREMENT` | [provider-bound selection 5431393925](https://github.com/styx-secure/styx/issues/250#issuecomment-5431393925); [closing ratification 5432143151](https://github.com/styx-secure/styx/issues/250#issuecomment-5432143151) | `maverde73` via PR #254 | [commit](https://api.github.com/repos/styx-secure/styx/commits/c9a0420e8cf26606c4c87d7fe7b610beb31133ef); [association](https://api.github.com/repos/styx-secure/styx/commits/c9a0420e8cf26606c4c87d7fe7b610beb31133ef/pulls) | Selects the bounded transcript-only resource envelope; no product/runtime availability claim. | `CONFORMING` |
| `d35052dfbf0631c726f250933bc401f424602f31` | Rebase historical evidence guards | Issue [#255](https://github.com/styx-secure/styx/issues/255) / PR [#256](https://github.com/styx-secure/styx/pull/256) | [8 exact paths](https://api.github.com/repos/styx-secure/styx/pulls/256/files) | `EXCEPTION_SECURITY_REMEDIATION` | [exact-final human review 5036984300](https://github.com/styx-secure/styx/pull/256#pullrequestreview-5036984300); [completion 5434008409](https://github.com/styx-secure/styx/issues/255#issuecomment-5434008409) | `maverde73` via PR #256 | [commit](https://api.github.com/repos/styx-secure/styx/commits/d35052dfbf0631c726f250933bc401f424602f31); [association](https://api.github.com/repos/styx-secure/styx/commits/d35052dfbf0631c726f250933bc401f424602f31/pulls) | Repairs historical identity pins and AST scope guards; the plan records it as procedural remediation selecting no protocol semantic. | `CONFORMING` |
| `4a4ebc4b8fc91e500ecd8002801896dc73d5073f` | Close O-10 stable outcome taxonomy | Issue [#252](https://github.com/styx-secure/styx/issues/252) / PR [#257](https://github.com/styx-secure/styx/pull/257) | [41 exact paths](https://api.github.com/repos/styx-secure/styx/pulls/257/files) | `PLAN_INCREMENT` | [human review 5038130839](https://github.com/styx-secure/styx/pull/257#pullrequestreview-5038130839); merged by `maverde73` | `maverde73` via PR #257 | [commit](https://api.github.com/repos/styx-secure/styx/commits/4a4ebc4b8fc91e500ecd8002801896dc73d5073f); [association](https://api.github.com/repos/styx-secure/styx/commits/4a4ebc4b8fc91e500ecd8002801896dc73d5073f/pulls) | Ratifies the bounded trusted-local taxonomy and opaque remote collapse without wire/API selection. | `CONFORMING` |
| `25be9abc0d8c1bce8821a750616e13d245abc356` | Approve exact C0.3 corpus paths | Issue [#253](https://github.com/styx-secure/styx/issues/253) / PR [#258](https://github.com/styx-secure/styx/pull/258) | [12 exact paths](https://api.github.com/repos/styx-secure/styx/pulls/258/files) | `PLAN_INCREMENT` | [copyright-holder contract ratification 5436056363](https://github.com/styx-secure/styx/issues/253#issuecomment-5436056363); [final approval 5436628091](https://github.com/styx-secure/styx/pull/258#issuecomment-5436628091) | `maverde73` via PR #258 | [commit](https://api.github.com/repos/styx-secure/styx/commits/25be9abc0d8c1bce8821a750616e13d245abc356); [association](https://api.github.com/repos/styx-secure/styx/commits/25be9abc0d8c1bce8821a750616e13d245abc356/pulls) | Ratifies the exact synthetic-only Apache-2.0 corpus-path inventory; creates no corpus byte. | `CONFORMING` |
| `490689f0d81980cf942d448c76a54192913b7cde` | Integrate O-14 verification into O-06c | Issue [#260](https://github.com/styx-secure/styx/issues/260) / PR [#261](https://github.com/styx-secure/styx/pull/261) | [23 exact paths](https://api.github.com/repos/styx-secure/styx/pulls/261/files) | `PLAN_INCREMENT` | [contract ratification 5437409919](https://github.com/styx-secure/styx/issues/260#issuecomment-5437409919); [human review 5045824217](https://github.com/styx-secure/styx/pull/261#pullrequestreview-5045824217) | `maverde73` via PR #261 | [commit](https://api.github.com/repos/styx-secure/styx/commits/490689f0d81980cf942d448c76a54192913b7cde); [association](https://api.github.com/repos/styx-secure/styx/commits/490689f0d81980cf942d448c76a54192913b7cde/pulls) | Discharges the recorded O-14 placeholder rerun within bounded O-06c evidence; no runtime/product claim. | `CONFORMING` |
| `7768c32d3ddba230bd60f8b5db1b34d4bcb8ec3b` | Synchronize C0.3 entry authority | Issue [#262](https://github.com/styx-secure/styx/issues/262) / PR [#263](https://github.com/styx-secure/styx/pull/263) | [20 exact paths](https://api.github.com/repos/styx-secure/styx/pulls/263/files) | `PLAN_INCREMENT` | [human review 5046400672](https://github.com/styx-secure/styx/pull/263#pullrequestreview-5046400672); merged by `maverde73` | `maverde73` via PR #263 | [commit](https://api.github.com/repos/styx-secure/styx/commits/7768c32d3ddba230bd60f8b5db1b34d4bcb8ec3b); [association](https://api.github.com/repos/styx-secure/styx/commits/7768c32d3ddba230bd60f8b5db1b34d4bcb8ec3b/pulls) | Synchronizes the exact corpus-entry authority set; keeps implementation, demo, product and sensitive use blocked. | `CONFORMING` |
| `0fbba871130e4e100558030837e03dd609128976` | Construct transcript-only C0.3 conformance corpus | Issue [#264](https://github.com/styx-secure/styx/issues/264) / PR [#265](https://github.com/styx-secure/styx/pull/265) | [34 exact paths](https://api.github.com/repos/styx-secure/styx/pulls/265/files) | `PLAN_INCREMENT` | [contract ratification 5446445472](https://github.com/styx-secure/styx/issues/264#issuecomment-5446445472); [amendment ratification 5446789373](https://github.com/styx-secure/styx/issues/264#issuecomment-5446789373) | `maverde73` via PR #265 | [commit](https://api.github.com/repos/styx-secure/styx/commits/0fbba871130e4e100558030837e03dd609128976); [association](https://api.github.com/repos/styx-secure/styx/commits/0fbba871130e4e100558030837e03dd609128976/pulls) | Constructs only the licensed synthetic corpus and bounded conformance/mutation evidence. | `CONFORMING` |
| `0912c49e4b40e0c8aa4e35fa3e8d500152e60e71` | Align GitHub storefront with merged C0.3 corpus state | Issue [#268](https://github.com/styx-secure/styx/issues/268) / PR [#269](https://github.com/styx-secure/styx/pull/269) | [3 exact paths](https://api.github.com/repos/styx-secure/styx/pulls/269/files) | `EXCEPTION_ROUTINE_MAINTENANCE` | [final contract ratification 5462438153](https://github.com/styx-secure/styx/issues/268#issuecomment-5462438153); [human review 5058119165](https://github.com/styx-secure/styx/pull/269#pullrequestreview-5058119165); [present determination 5468111470](https://github.com/styx-secure/styx/pull/284#issuecomment-5468111470) | `maverde73` via PR #269 | [commit](https://api.github.com/repos/styx-secure/styx/commits/0912c49e4b40e0c8aa4e35fa3e8d500152e60e71); [association](https://api.github.com/repos/styx-secure/styx/commits/0912c49e4b40e0c8aa4e35fa3e8d500152e60e71/pulls) | Public documentation claims only; no protocol byte or semantic intended. The present determination records the exception and original timing without backdating it. | `RETROACTIVE_HUMAN_DETERMINATION(5468111470)` |
| `a51d1cdb378678a8997cf131f8d2df63fa2a3937` | Align landing page with C0.3 evidence | Issue [#271](https://github.com/styx-secure/styx/issues/271) / PR [#272](https://github.com/styx-secure/styx/pull/272) | [4 exact paths](https://api.github.com/repos/styx-secure/styx/pulls/272/files) | `EXCEPTION_DISJOINT_WORK` | [final contract ratification 5462652352](https://github.com/styx-secure/styx/issues/271#issuecomment-5462652352); [human review 5058236423](https://github.com/styx-secure/styx/pull/272#pullrequestreview-5058236423); [present determination 5468111470](https://github.com/styx-secure/styx/pull/284#issuecomment-5468111470) | `maverde73` via PR #272 | [commit](https://api.github.com/repos/styx-secure/styx/commits/a51d1cdb378678a8997cf131f8d2df63fa2a3937); [association](https://api.github.com/repos/styx-secure/styx/commits/a51d1cdb378678a8997cf131f8d2df63fa2a3937/pulls) | Static website copy/style alignment only; no protocol byte or semantic intended. The present determination records the exception and original timing without backdating it. | `RETROACTIVE_HUMAN_DETERMINATION(5468111470)` |
| `ebd7ff60523e9658055fb2904246917716678aac` | Add a bounded C0.3 evidence explorer | Issue [#273](https://github.com/styx-secure/styx/issues/273) / PR [#275](https://github.com/styx-secure/styx/pull/275) | [11 exact paths](https://api.github.com/repos/styx-secure/styx/pulls/275/files) | `EXCEPTION_DISJOINT_WORK` | [final contract ratification 5463003161](https://github.com/styx-secure/styx/issues/273#issuecomment-5463003161); [final maintainer record 5463417097](https://github.com/styx-secure/styx/pull/275#issuecomment-5463417097); [present determination 5468111470](https://github.com/styx-secure/styx/pull/284#issuecomment-5468111470) | `maverde73` via PR #275 | [commit](https://api.github.com/repos/styx-secure/styx/commits/ebd7ff60523e9658055fb2904246917716678aac); [association](https://api.github.com/repos/styx-secure/styx/commits/ebd7ff60523e9658055fb2904246917716678aac/pulls) | Dependency-free synthetic read-only evidence explorer; it does not execute product protocol, transport or persistence and is not a deployable product demo. The present determination confirms the disjoint-work exception without backdating it. | `RETROACTIVE_HUMAN_DETERMINATION(5468111470)` |
| `578b3241d6e7d0231da0d2e00b9d04c69530d24e` | Bind historical MLS fixture replay to proof time | No associated PR: [empty provider response](https://api.github.com/repos/styx-secure/styx/commits/578b3241d6e7d0231da0d2e00b9d04c69530d24e/pulls). PR [#279](https://github.com/styx-secure/styx/pull/279) remains open on a different HEAD and is not this commit's association. | [1 exact path in commit response](https://api.github.com/repos/styx-secure/styx/commits/578b3241d6e7d0231da0d2e00b9d04c69530d24e) | `NON_PR_COMMIT` | No immutable pre-integration PR association or exact-commit human gate found; [present determination 5468111470](https://github.com/styx-secure/styx/pull/284#issuecomment-5468111470) | `maverde73` direct commit via GitHub `web-flow` | [commit](https://api.github.com/repos/styx-secure/styx/commits/578b3241d6e7d0231da0d2e00b9d04c69530d24e); [empty association](https://api.github.com/repos/styx-secure/styx/commits/578b3241d6e7d0231da0d2e00b9d04c69530d24e/pulls); [different open PR #279](https://api.github.com/repos/styx-secure/styx/pulls/279) | Changes one historical MLS fixture-replay test, not protocol semantics. The present determination accepts its bounded semantic placement but preserves the non-PR process-provenance violation and does not associate it with PR #279. | `RETROACTIVE_HUMAN_DETERMINATION(5468111470)` |
| `a4fa1286b57b2ee79b3c580fdce0d1fb3bf9cd40` | Rename the planned Themis vertical to Flegias | Issue [#274](https://github.com/styx-secure/styx/issues/274) / PR [#276](https://github.com/styx-secure/styx/pull/276) | [47 exact paths](https://api.github.com/repos/styx-secure/styx/pulls/276/files) | `EXCEPTION_ROUTINE_MAINTENANCE` | [final contract ratification 5463780077](https://github.com/styx-secure/styx/issues/274#issuecomment-5463780077); [human review 5058733881](https://github.com/styx-secure/styx/pull/276#pullrequestreview-5058733881); [present determination 5468111470](https://github.com/styx-secure/styx/pull/284#issuecomment-5468111470) | `maverde73` via PR #276 | [commit](https://api.github.com/repos/styx-secure/styx/commits/a4fa1286b57b2ee79b3c580fdce0d1fb3bf9cd40); [association](https://api.github.com/repos/styx-secure/styx/commits/a4fa1286b57b2ee79b3c580fdce0d1fb3bf9cd40/pulls) | Mechanical brand/package rename with no intended protocol semantic. The present determination confirms the exception without backdating it. | `RETROACTIVE_HUMAN_DETERMINATION(5468111470)` |
| `289418257268d88d7d546c78fef662fd0579365d` | Reconcile C0.3 K evidence with O-08/O-10 | Issue [#266](https://github.com/styx-secure/styx/issues/266) / PR [#267](https://github.com/styx-secure/styx/pull/267) | [38 exact paths](https://api.github.com/repos/styx-secure/styx/pulls/267/files) | `PLAN_INCREMENT` | [exact D4 kit ratification 5466903799](https://github.com/styx-secure/styx/issues/266#issuecomment-5466903799); [final bounded GO 5467276541](https://github.com/styx-secure/styx/issues/266#issuecomment-5467276541); [merged-byte record 5467311216](https://github.com/styx-secure/styx/issues/266#issuecomment-5467311216) | `maverde73` via PR #267 | [commit](https://api.github.com/repos/styx-secure/styx/commits/289418257268d88d7d546c78fef662fd0579365d); [association](https://api.github.com/repos/styx-secure/styx/commits/289418257268d88d7d546c78fef662fd0579365d/pulls) | Completes bounded D4 transcript/K evidence and blind corroboration; AP execution, implementation alignment, demo, product and sensitive use remain `NO-GO`. | `CONFORMING` |
<!-- styx-section8-exception-audit:v1:end -->

## 9. Work after the freeze

After a passing exit verdict, work resumes through separate contracts in this
order:

1. C0.3 specification-derived corpus and conformance evidence, if not already
   included in the exit verdict and only under Issue #253's separately approved
   Apache-2.0 path inventory and synthetic-only licensing boundary;
2. minimum language-neutral application-core interface;
3. independently testable implementation(s) against the conformance corpus;
4. supported secure-session adapter and authenticated persistence boundaries;
5. reliable delivery and runtime profiles;
6. synthetic Flegias or successor-vertical scenarios, then separately gated
   field readiness.

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

A dated status record is produced after each completed increment and carried
into the section 8 verdict.

The 2026-08-24 O-06c reconciliation increment under Issue #241 uses the bounded
section-7 exemption from new hostile witnesses, mutants and executable protocol
evidence because it changes only contradictory normative prose and derived
provenance before O-06c can be specified. It changes no wire, persisted or
runtime behavior and selects no protocol semantic. The exemption remains
subject to exact-final review, human gates and section-8 re-verification.
Originating findings are dispositioned as follows:

- **F01:** current whole-context fork wording is replaced by an exact reference
  to the ratified C0.2j lineage-scoped rule;
- **F02:** role `0x01` directive content is fixed to `NONE`, while ambient
  `NONE`/`DETACHABLE`/`REQUIRED` coverage and target-equality scope are stated
  without impossible directive variants;
- **F03:** O-06 closure is limited to O-06-owned fields, with unresolved owners,
  placeholders, non-claims and rerun/reopen triggers retained; and
- **F09:** the frozen section-6 digest is relabelled as the logical-removal tail,
  the extraction rule is corrected and the current section-2 84-octet context
  is pinned separately.

## 11. Current state

After Issue #266 / merged PR #267 completed the exact D4 reconciliation and
bounded evidence verdict:

- the review model exists and is useful for bounded inspection;
- C0.2j and C0.2k are ratified historical inputs; the selected 84-octet
  commitment context and its bounded evidence remain frozen inputs rather than
  O-06c proof authority;
- `specs/05-sprint-plan.md` still marks US-001 through US-008 `todo`, but this
  plan pauses their execution and requires that conflict to be audited at exit;
- O-06 and O-06c are condition-bearing `DECIDED` over the exact combined
  C0.2j/C0.2k construction and the declared bounded envelope. Issue #241
  reconciles the handoff; Issue #243 supplies the isolated executable evidence,
  compensates the recorded v2/C0.2k limitations and preserves every rerun/
  reopen trigger;
- O-07 and O-08 are bounded `DECIDED`; O-08 has a replacement provider-bound
  `balanced` selection after correcting its final-gate evidence defect and
  completing two-clean-checkout evidence, exact-HEAD reviews and technical
  human approval; Issue #255 supplies the separately scoped historical-guard and
  AST-allowlist maintenance required for O-10's exact validator assignment;
  O-10 is bounded `DECIDED` after its final evidence and human gates.
  O-14 is condition-bearing `DECIDED`, with
  Dart/browser support claims and the separately ratified O-06c
  placeholder-substitution rerun still gated. O-12 remains conditional as
  described in section 4; O-11, O-13, O-15 and O-16 retain their explicitly
  bounded non-blocking or downstream-blocking roles;
- the exact D4 transcript/K corpus and evidence package have a bounded evidence
  GO, while the C0.3 capability gate remains `NO-GO` for implementation
  alignment, demo, product and sensitive use;
- `C0.3_CORPUS_PATH_APPROVAL` is bounded `DECIDED` by Issue #253; Issue #264
  populates exactly its six synthetic-only paths and completes their executable
  conformance and mutation evidence;
- Issue #262 completed the final authority-set synchronization, Issue #264
  completed corpus construction and Issue #266 completed the exact D4
  transcript/K reconciliation with independent-reader agreement. Independent
  implementation alignment, the full Section 8 exit review and an explicit
  human phase verdict remain separate work.

The human ratification gate is currently discipline-enforced rather than fully
server-enforced: the repository governance record at
`docs/governance/mucc-migration/ruleset-proposal.md` records no required
approving review and no last-push approval. Until an authorized human verifies
and applies stronger ruleset controls, every human gate must be evidenced
explicitly in the relevant Issue and pull request.

`AGENTS.md` and `CLAUDE.md` now link directly to this plan. Tracking Issue #237
is satisfied when the reconciliation increment that added those pointers is
merged. Issue #230 retains historical wording outside that bounded change.
Issue #270 remains idle and unratified on a stale base; it may not execute
without a refreshed non-overlapping contract or a new explicit ratification.

This state is intentionally conservative. The freeze ends only through section
8, not through elapsed time, reviewer consensus or pressure to demonstrate a
feature.
