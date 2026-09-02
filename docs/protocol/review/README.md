# Styx application-protocol review model

This directory contains a compact, machine-readable view of the currently
ratified Styx application-protocol baseline. It exists to make security review
faster and more systematic. It is not the protocol specification, a security
proof or implementation evidence. Issue #264 completes the separately
contracted, synthetic-only C0.3 corpus; this derived model still does not
authorize implementation alignment, demo, product or sensitive use.

## Authority

When sources disagree, use this order and fail closed:

1. the accepted GitHub task contract and its native dependencies;
2. repository `AGENTS.md`;
3. the protocol-hardening plan for the order and gating of work during the
   active phase;
4. the English decision registry, encoding profiles, responsibility matrix and
   threat model enumerated by the plan's normative source index;
5. tool adapters such as `CLAUDE.md`;
6. the derived JSON review model;
7. generated validation reports, review reports and local notes.

The JSON model must never be used to define the normative set, override,
complete or silently select an unresolved normative decision. Its source paths,
exact byte digests and citations make drift visible; they do not prove that a
modeled claim is true or complete. A normative source omitted from `sources`
remains normative and makes the model incomplete; an unratified model entry
cannot add a normative source.

## Files

- `styx-app-kernel-v0-review-model.json` is the derived
  `styx.review-model.v1` snapshot.
- `styx-app-kernel-v0-review-model.schema.json` is its closed JSON Schema
  interface, pinned to JSON Schema Draft 2020-12.
- `../../../tools/protocol-review-model/validate.py` is the repository-owned,
  standard-library-only fail-closed validator.
- `../../../tools/protocol-review-model/tests/` contains positive and hostile
  mutation tests.

The model separates actors, responsibility layers, objects and fields, wire
presence, integrity, confidentiality, observers, mutators, flows, outcomes,
state transitions, invariants, counterexamples, non-claims, residual risks and
blocker edges. Decision and obligation identifiers are closed registries rather
than free text, and each security-relevant record names its responsible layer.
An explicit `UNRESOLVED`, `SYMBOLIC`, `PROFILE_DEPENDENT` or `EVIDENCE_ONLY`
state is deliberate; it must not be promoted merely to make a review simpler.

Source authority is explicit per `sources[].authority`. The decision registry,
the two encoding profiles, the responsibility matrix and the threat model are
normative. Analysis and falsification reports are evidence: they may support a
claim but cannot select protocol semantics. Some evidence documents retain
pre-merge wording because their proposals were ratified by an exact final merge;
the model records the resulting decision only where a current normative source
also does so. Any apparent conflict is investigated as drift and never resolved
by promoting the evidence report.

The C0.2k snapshot adds the bounded commitment-context falsification report as
evidence for the selected 84-octet context. The positive binding invariant and
the retained `NC_COMMITMENT_COPY` record must be read together: unchanged
commitment/opening copy across credential or sequence contexts is rejected,
while knowledgeable recomputation, same-slot siblings and all authority,
originality and truth claims remain outside that result.

The O-06c snapshot adds
`styx-app-kernel-v0-identifier-commitment-falsification-report.md` as evidence
for the exact combined O-06b-1/O-06b-2/C0.2j/C0.2k construction. O-06/O-06c are
condition-bearing `DECIDED`; the evidence is bounded, carries explicit
placeholder-triggered reruns and opens no capability. Exact candidate identity
is immutable PR evidence rather than a tracked generated-report input, avoiding
self-referential digests.

The O-14 snapshot adds `styx-app-kernel-v0-signature-suite-analysis.md` and
`styx-app-kernel-v0-signature-suite-falsification-report.md` as bounded evidence
for internal suite `0x0001` and its exact guarded accepted language. O-14 is
condition-bearing `DECIDED`; this does not establish product/runtime
conformance, discharge the O-06c placeholder-substitution rerun, authorize C0.3
or add a security, interoperability, availability or readiness claim.

The Issue #260 snapshot integrates that frozen O-14 language into the complete
O-06c construction while preserving the frozen O-07 provenance, O-08 envelope
and O-10 outcome taxonomy. Exact-final evidence exercises 115 fixed/transcript/candidate-envelope
witnesses and seven integration-order mutants, and the two-clean-checkout
technical gate passes. Independent review and human approvals completed in
merged PR #261 at `490689f0d81980cf942d448c76a54192913b7cde`; no
product/runtime conformance follows.

The SS-0 snapshot adds the Gate-A-frozen
`styx-secure-session-v0-decisions.md` source and represents `SSD-01` through
`SSD-11` as a separate bounded secure-session evidence-profile decision group.
The top-level `modeled_scope` record keeps those decisions distinct from the
application-kernel `O-*` group, while `decision_sources` attributes every
decision to exactly one pinned normative source. The `SS` layer and its actor
record reference all nine `OB-SS*` obligations and the closed forbidden-
inference boundary. This is evidence-model coverage only: it selects no
supported adapter, implementation, SDK, wire, persistence or product behavior,
and `C0.3` remains `NO_GO`.

The historical filenames in this directory remain application-kernel-oriented
even though the derived graph now includes the bounded SS-0 slice. Renaming or
splitting the graph would create a second source-of-truth and is outside Issue
#285. The closed modeled scope and per-decision attribution make that mismatch
explicit, but do not eliminate its review cost.

The historical C0.3 corpus and public kernel review model retain their exact
eight-token Base precedence and do not project the APP-core
`POST_REVOCATION`, `AUTHENTIC_BUT_UNAUTHORIZED` or
`NO_OPERATIONAL_AUTHORITY` semantics. Their relative position of
`LINEAGE_QUARANTINED` differs from the O-10 event precedence implemented by
APP-core v0; APP-core record-outcome precedence is defined only by O-10 and
ACV-076. The APP-core v0 interface document and executable candidate remain
separate non-authoritative projections with respect to this public model. This
separation is an explicit non-claim, not an alias, an implicit corpus extension
or evidence that the public model validates APP-core precedence.

The validator pins the exact source-ID, repository-path and authority tuple for
every source in this snapshot. Changing an evidence source to `normative`,
retargeting an ID to a different file, adding or removing a modeled record, or
changing a selected status therefore fails closed rather than silently changing
the review boundary.

The validator also pins the raw schema SHA-256 and the exact selected security
structure of this snapshot. The latter covers every field protection tuple,
transition status and edge, state list and precedence list, invariant reference
pair, blocker edge pair, outcome transition flag and counterexample blocker list.
Pins are keyed by the already pinned record identifiers and are independent of
candidate input. Missing or additional identifiers remain inventory failures;
changes to known values use the stable protection, status, blocker-edge or
`PINNED_VALUE_DRIFT` finding assigned to that class.

Validation is additive but ordered. The complete schema-definition walk runs
first and must have no finding before that schema is trusted for instance
traversal. Instance findings do not suppress domain, provenance, canonical-byte,
status or blocker checks: malformed subtrees are converted to deterministic
typed neutral values only for those continuing checks. At the CLI boundary,
malformed JSON, duplicate keys, non-standard constants, excessive nesting and
an output path resolving inside the repository are `INPUT_INVALID`; raw schema
byte drift is `SCHEMA_SNAPSHOT_DRIFT`; and an unexpected caught exception is
`INTERNAL_ERROR`. A PASS report is written atomically outside the repository,
and a failed run neither creates nor replaces it.

## Bounded review bundle

The active [protocol-hardening plan](../protocol-hardening-plan.md) defines the
review process. For one protocol increment, mandatory reviewer context is
bounded to the accepted Issue and SHAs, `AGENTS.md`, the hardening plan and its
normative source index, the threat model and responsibility matrix, changed
normative sources and direct dependencies, the relevant model slice, changed
adversarial evidence, exact diff and test artifacts, final required-check and
scope-evidence status, and prior unresolved findings that affect the increment.

This bundle reduces repeated context loading; it is not a restriction on
investigation. Reviewers may inspect the whole repository and public standards.
Omitting a material dependency invalidates the review. A validator pass, model
query or reviewer consensus remains an aid to falsification, never a security
verdict or permission to implement unresolved semantics.

## Closed registry semantics

The arrays in `registries` are exhaustive and sorted. `modeled_scope` and
`decision_sources` additionally close the distinction between application-
kernel decisions and bounded secure-session evidence decisions. Their meanings
are:

- `statuses`: `DECIDED` is normatively selected; `DERIVED` follows mechanically
  from normative data; `EVIDENCE_ONLY` is an observation, not authority;
  `NO_GO` is an active prohibition; `OPEN` has no selected answer;
  `PROFILE_DEPENDENT` requires a future concrete profile; `SYMBOLIC` is a named
  model input without selected construction; `UNRESOLVED` is deliberately
  unspecified.
- `wire_presence`: `SIGNED_TRANSCRIPT`, `OUT_OF_BAND`, `DERIVED` and
  `NOT_CARRIED` describe current carriage; `PROFILE_DEPENDENT` and
  `SYMBOLIC_INPUT` forbid inventing bytes.
- `integrity`: authentication (`SIGNED_TRANSCRIPT` or
  `SESSION_AUTHENTICATED`), commitment (`COMMITMENT`) and derivation
  (`DIGEST_DERIVED`) are independent facts. `NONE`, `PROFILE_DEPENDENT` and
  `UNRESOLVED` do not imply protection.
- `confidentiality`: `LOCAL_RUNTIME_PROFILE` concerns local custody only;
  `SECURE_SESSION_PROFILE` may be used only after a supported adapter is
  selected; `PROFILE_DEPENDENT`, `UNRESOLVED` and `NONE` are not encryption
  claims.
- `layers`, `trust_classes`, `decisions`, `obligations` and
  `gated_capabilities` are closed reference namespaces. A blocker `blocks`
  target must resolve either to another blocker or to one of the explicitly
  named non-record capabilities. Unknown members fail validation. Every gated
  capability must also retain at least one blocker whose status is not
  `DECIDED`; otherwise validation fails with `GATED_CAPABILITY_UNBLOCKED`
  instead of silently promoting the capability when its last gate closes.

`visible_to` means an actor may learn the field value at the named semantic
boundary; it does not mean every transport observer sees it. `mutable_by` means
an actor can propose or supply that value before validation, not that it may
alter an admitted record. Every mutator must therefore also be a possible
observer. A secure-session adapter handles the application plaintext presented
at its boundary, while a relay observer sees only the separately declared
transport envelope and metadata.

## Review-first workflow

1. Validate the unmodified model and schema against the repository root.
2. Use `review_queries` to select the relevant actors, fields, flows,
   transitions, invariants, witnesses and blockers.
3. Treat the model as an index. For every material conclusion, open the cited
   source and verify the claim against its raw normative context.
4. Exercise relevant counterexamples and attempt to falsify the claimed
   invariant. Successful JSON validation is not a security verdict.
5. Report any disagreement as source/model drift. Fix or decide the normative
   source first, then update the derived model in the same reviewed increment.
6. Re-run the hostile tests and compare two clean canonical reports byte for
   byte.

Reviewers must preserve the model's central separations: signature validity is
not application authorization; successful secure-session delivery is not an
authorized AP transition; relay acknowledgement is not receipt or truth;
commitment, confidentiality, observability and retention are distinct; and an
open blocker is never converted into a selected fact.

## Updating the model

Update this snapshot only under an approved task contract that names every
normative and derived path. Make the normative decision first. Then:

1. update affected normative documents and preserve explicit residual risks;
2. recompute lowercase SHA-256 values over the exact raw source bytes;
3. update the minimum affected model records and citations;
4. keep all registries closed, IDs unique and set-like arrays sorted;
5. add a negative fixture for each new validator invariant or failure class;
6. run the exact commands below twice from a clean checkout;
7. obtain an exact-final independent review that samples model claims against
   raw sources and mutates both provenance and blocker gates.

Do not put timestamps, absolute paths, host names, random values or
environment-dependent ordering in the model or report.

The commands below are currently a mandatory **manual repository gate**. Issue
#227 deliberately forbids workflow changes, so no claim is made that GitHub CI
already invokes this validator. Wiring the same commands into path-aware CI and
reconciling stale wording in evidence-only source documents require separate,
approved task contracts. Until that happens, an exact-final run is recorded in
the PR evidence and absence of that evidence fails closed.

## Required commands

Run from the repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s tools/protocol-review-model/tests -p 'test_*.py'

PYTHONDONTWRITEBYTECODE=1 python3 tools/protocol-review-model/validate.py \
  --repo-root . \
  --schema docs/protocol/review/styx-app-kernel-v0-review-model.schema.json \
  --model docs/protocol/review/styx-app-kernel-v0-review-model.json \
  --output "${TMPDIR:-/tmp}/styx-review-model-1.json"

PYTHONDONTWRITEBYTECODE=1 python3 tools/protocol-review-model/validate.py \
  --repo-root . \
  --schema docs/protocol/review/styx-app-kernel-v0-review-model.schema.json \
  --model docs/protocol/review/styx-app-kernel-v0-review-model.json \
  --output "${TMPDIR:-/tmp}/styx-review-model-2.json"

cmp "${TMPDIR:-/tmp}/styx-review-model-1.json" \
  "${TMPDIR:-/tmp}/styx-review-model-2.json"
sha256sum "${TMPDIR:-/tmp}/styx-review-model-1.json"

python3 tools/docs-claims-lint/claims_lint.py \
  --scan docs specs \
  --exclude docs/superpowers docs/security docs/archive docs/piano-utente.md

python3 tools/docs-translation-sync/check.py \
  --manifest docs/platform/translation-pairs.json

reuse lint
```

## Phase-exit merged-scope review coverage

<!-- styx-phase-exit-merged-review:v1:start -->
- Exact merged-scope Base: `fd6f652af1666c6c9dca8356c2aed615773f5208`.
- SS-0 PR #286 exact-final review `5062107437`: `APPROVED`, with no unresolved
  `BLOCKER` or `HIGH` finding on reviewed head
  `ddc62ac3d2f3b06aacf244cca924b1ef97433c62`.
- SS-0 post-squash remediation PR #290 exact-final review `5065807842`:
  `APPROVED`, with no unresolved `BLOCKER` or `HIGH` finding on reviewed head
  `b9926a70c3a6feae78851852bcd1aa2159428b07`.
- Merged phase scope through the exact Base has no recorded unresolved
  `BLOCKER` or `HIGH` finding. The current phase-exit candidate is deliberately
  excluded from this statement and is resolved only by `EXIT-08` at its exact
  final HEAD.
<!-- styx-phase-exit-merged-review:v1:end -->

## Limits

The model does not prove protocol security, cryptographic soundness,
implementation conformance, interoperability, anonymity, erasure, finality,
availability, audit readiness or production fitness. It cannot detect a
normative omission shared by all sources. C0.2j is ratified historical input;
C0.2k selects only its bounded commitment-context amendment and O-06c adds
bounded combined-construction evidence. O-14 selects only its bounded guarded
signature language; Issue #260 / merged PR #261 completed its separately
ratified exact-final combined rerun. O-07 and O-08 are bounded `DECIDED`;
O-08 has a replacement provider-bound `balanced` selection after correction of
its final-gate response shape and completion of two-clean-checkout evidence,
exact-HEAD reviews and technical human approval; O-10 is bounded `DECIDED` for
trusted-local outcomes and one opaque untrusted-remote collapse, with no
numeric/wire/API representation selected. `C0.3_CORPUS_PATH_APPROVAL` is
bounded `DECIDED` by Issue #253's exact six-path synthetic-only amendment. Issue
#264 populated exactly those paths. Issue #266 / merged PR #267 reconciled the
resulting corpus with an explicit transcript/local-negative/connected-K
evidence split, derived connected authority only from accepted genesis and
admitted `GRANT` history, and obtained agreement from Python, JavaScript and a
fresh oracle-free reader on the bounded public transcript/K surface. That exact
D4 package has a bounded evidence GO only. The C0.3 capability gate remains
`NO_GO` and continues to block implementation alignment, demo, product and
sensitive-use claims.

Issue #291 separately ratified six exact, synthetic-only SS-0 corpus paths
under Apache-2.0; Issue #293 populates exactly those paths with Styx-generated
data and bounded replay/mutation evidence. `K11-SS` and SS-CORPUS-0 authorize no
adapter, persistence, SDK, transport, product, demo, deployment or sensitive
use.

`counterexamples[].steps` is the one intentionally order-sensitive sequence in
the model: entries describe the procedural order of an adversarial trace and
must not be alphabetically sorted. Other arrays documented as registries,
references or sets remain sorted and duplicate-free.

<!-- styx-protocol-phase-exit-status:v1:start -->
Protocol-hardening phase-exit status: `BOUNDED_GO`. The broad protocol freeze has ended
only for work separately authorized under Section 9 of the hardening plan. Issue #287
itself authorizes no adapter, authenticated persistence, SDK, transport/delivery, product,
demo, deployment or sensitive-use work; US-001 through US-008 remain paused.
<!-- styx-protocol-phase-exit-status:v1:end -->
