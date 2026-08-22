# Styx application protocol v0: pending-subtree falsification report

Status: C0.2i executable evidence; bounded, non-production, non-proof

Base: `468e822d7c7113ccceeea339eede27ec56f12ab3`

Model: `styx.pending-subtree-falsification/v2`

Report schema: `styx.pending-subtree-report/v2`

Machine report SHA-256:
`d30638f3ce4d737ecb0c0e4346691d7c8af1997526c66551aa3776dcf37ec302`

Mutation report SHA-256:
`9af6b6c1b0f86d0e838314aae645afe6926e920f45660ee6e6acba7c6b3376c9`

Historical v1 machine report SHA-256:
`8bee78b7bde503597d331bea63bca1548bb3d8f006ea4505854b7973b3a5a3f7`

The exact final candidate HEAD is recorded in immutable PR evidence and in the
independent exact-HEAD review reports. A tracked file cannot self-identify the
SHA of the commit that contains that same text.

Issue: [#225](https://github.com/styx-secure/styx/issues/225)

## 1. Outcome and claim boundary

The isolated dependency-free C0.2i model found no counterexample within its
declared small-state envelope to the selected pending-subtree construction. The
required run performed 109 directed invariant evaluations over all 22
re-encoded C0.2d causal families, all 16 C0.2f obligations and all 41 C0.2i
hostile families. It explored 1,268 explicitly recorded bounded delivery traces,
opening/event combinations and typed-axis cases. Delivery permutations are
coverage of one semantic construction, not independent semantic shapes.
The closed-registry checks fail if any required family or obligation is absent or
has no directed assertion. A separate deterministic mutation gate kills all
thirteen required source mutants, including named assertions weakened to
tautologies.

This result is candidate evidence for returning O-01, O-02 and O-04 to
`DECIDED` only after the exact-final review and human gates. It
does not authorize C0.3, a protocol demo, a production kernel, product work or a
sensitive pilot. It is not a formal proof, conformance corpus, cryptographic
argument, interoperability result, audit, anonymity claim, deletion guarantee or
readiness verdict. Any future counterexample reopens O-04.

## 2. Model boundary

The v2 model is fresh and independent from the immutable v1 simulator. It uses a
distinct module tree, model identifier and report schema and imports no v1
simulator module. It models:

- signed transcripts, symbolic references and one authenticated context;
- direct author predecessors, causal frontiers, duplicate observations, forks,
  missing dependencies and canonical topological order;
- symbolic monotone K-level credential bindings and reversible AP-level grants,
  all applied revocations, policy, closure and logical removal; rotation and
  recovery are authenticated no-op evidence because C0.2j still owns exact
  credential succession;
- closed `NONE`, `REQUIRED` and `DETACHABLE` content classes;
- the full 54-case product of content class, local availability and binding
  observation, with every unlisted combination rejected and every accepted
  combination assigned a typed presentation;
- per-replica opening observations and deterministic pending-subtree replay;
- permanent whole-context AP quarantine whenever the K graph contains a
  same-author fork, while preserving graph and pending diagnostics;
- symbolic checkpoint evidence whose references are checkpoint-only only when
  absent from the live admitted graph, plus an unvalidated replay-dependency
  oracle whose matching intersection produces whole-projection stale evidence;
- unsupported credential-identifier collisions as negative witnesses excluded
  from every positive claim; and
- symbolic current-profile commitment and geometry checks without selecting new
  bytes.

The model additionally supplies symbolic K-readable control kinds, grant
subjects, binding references and verification keys that the current O-06b-1
transcript does not yet carry. Those fields make the candidate construction
falsifiable but are not runtime-carriage, encoding or cryptographic evidence;
C0.2j owns their exact authenticated representation.

The only static authority input is the O-07 genesis-authority abstraction.
Opening availability is replica-local. AP authorization, revocation and removal
effects are derived from modelled events; no ordinary static authorization input
exists.

## 3. Selected construction

For one K-derived admitted graph `G = (E, ->)`, canonical order `T(E)`, content
class `class(e)` and replica-local monotone set `V` of events with verified
openings, the model computes:

```text
R(V) = { e in E | class(e) = REQUIRED and e not in V }
P(V) = R(V) union { x in E | exists r in R(V): r ->+ x }
A(V) = [ e in T(E) | e not in P(V) ]
```

`R(V)` contains the pending roots, `P(V)` contains each root and all of its causal
descendants, and `A(V)` preserves the canonical relative order of everything
outside the pending set. A pending root is observed as `PENDING_OPENING`; an
event pending only through ancestry is `PENDING_ANCESTOR`. Missing, wrong-length
and commitment-mismatching openings remain distinct binding observations even
though none permits replay.

Opening observations never change K-validity, graph membership, graph edges,
duplicate identity, fork classification or canonical order. Adding a verified
opening cannot add pending events. Incremental replay after monotone opening
acquisition equals fresh full replay for the same transcript and verified-opening
sets. An opening observed before or without its event has no graph or AP effect.

For an opening-set update over an identical transcript, incremental replay
starts at the earliest canonical position in:

```text
(prior_pending - updated_pending)
union
(prior_pending_roots - updated_pending_roots)
```

This includes the nested-root case where membership in the pending set is
unchanged but an event changes from `PENDING_OPENING` to `PENDING_ANCESTOR`.

Checkpoint staleness is the symbolic intersection:

```text
(checkpoint_evidence - graph.admitted) intersection replay_dependencies
```

A retained admitted transcript is therefore live even when checkpoint evidence
also names it. These inputs model neither checkpoint authentication nor
acceptance; `replay_dependencies` remains an unvalidated oracle. Matching absent
evidence makes the whole projection `STALE_EVIDENCE`, whose AP order, authority
and removal state are empty. Checkpoints never substitute for retained
authenticated history.

Any K-admitted same-author fork instead activates permanent whole-context AP
quarantine. Non-stale siblings are `FORK_EVIDENCE`; every other admitted event
is `FORK_QUARANTINED`. The graph, order, fork set, pending roots and pending
closure remain observable, but applied order, authority, removals and producer
eligibility are empty. No later opening, checkpoint, event or replay can lift
quarantine for the v0-pinned context. `STALE_EVIDENCE` has higher precedence.

## 4. Authentication and authority boundary

K binding is historical and monotone; AP authority is reversible and evaluated
by the deterministic fold. A K-valid grant from an AP-unauthorized actor remains
authentication evidence but grants no AP authority. A later action may therefore
be graph-admitted and still be `AUTHENTIC_BUT_UNAUTHORIZED`. A causally prior,
AP-authorized revocation produces `POST_REVOCATION` without deleting the event or
making it unusable as graph evidence.

Grant, revoke, rotate, recover, policy, closure and removal events are modelled as
control events. Every control event must have `content_class == NONE`; a
content-bearing control is structurally rejected before opening or AP evaluation.
The exact K-readable control-event carriage remains C0.2j work. `ROTATE` and
`RECOVER` deliberately do not mint, rebind or re-authorize an identifier in this
model, so this report makes no executable credential-succession claim.

The v2 positive envelope permits exactly one authenticated binding for each
credential identifier. A full validated set containing two K-valid binding grant
events for one identifier, including reuse of a genesis identifier, fails closed
with `CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED` before positive exploration.
Ten hostile witnesses cover reverse delivery, grants by a distinct credential,
pre-chain and post-chain publication, attacker descendants, genesis collision
and a grant by a causally revoked credential. This is an explicit denial-of-
service non-claim, not a collision solution.

Fork quarantine prevents the prior fork-descendant authority takeover but does
not make v0 authority safe. In a fork-free transcript, a compromised credential
can issue a concurrent successor `GRANT` while another authority revokes it.
When the grindable reference order places the grant first, the successor remains
operational because revocation is non-transitive; the opposite order rejects it.
The suite preserves both outcomes as an executable counterexample. C0.2j must
replace the credential/grant provenance, revocation and two-sided authority
contract before any safe-compromise or product claim.

## 5. Hostile cases exercised

The directed suite includes:

- delivery permutations, duplicates, reference collision, child-before-parent,
  missing parent, author gap, cross-context input, cycles, stale/redundant
  parents, the direct-predecessor/maximal-parent-frontier distinction, late
  prefix growth, late forks, late lower references, malicious omission and
  rollback limits;
- missing, wrong-length, mismatching and later-correct openings; opening before,
  after or without its event; selective opening distribution and convergence;
- every one of the 54 content-class, availability and binding-observation
  combinations from C0.2f-05, including typed unavailable, unverifiable and
  substituted `DETACHABLE` presentations and fail-closed illegal inputs;
- root/descendant/independent-event separation, overlapping-root diamonds,
  partially opened fork siblings, fork descendants, prior-prefix-cache replay
  and incremental/full equivalence over bounded verified-opening and
  delivery-order combinations;
- revoked-key, retired-genesis, ordinary-member and dual-equivocation forks;
  whole-context quarantine of independent control work; fork-plus-pending late
  reveal; fork-plus-stale precedence with both conditions observable; empty
  authority/removal/application views and false producer eligibility under
  quarantine;
- the fork-free concurrent grant/revoke authority-laundering counterexample in
  both grindable reference orders;
- same-credential and cross-credential nested `REQUIRED` roots whose pending
  membership is unchanged while the root set and typed outcome change;
- revocation and removal state reconstructed from a reused replay prefix;
- delayed reveal, relay withholding, late low-reference siblings and bounded
  multi-hole flooding;
- authentic-but-unauthorized events, terminal invalid binding ancestry,
  direct non-ancestral grant binding, false `CONTROL` role on an ordinary action,
  duplicate genesis binding, unauthorized holes and removals, revoked old keys,
  multiple retained
  revocations, both concurrent-revocation reference orders, revocation behind or
  concurrent with a hole, late authority replay, symbolic rotation/recovery,
  sole-authority self-lockout and grant-behind-hole cases;
- removal behind a hole, reversible removal authority, `DETACHABLE` removal
  inside a pending subtree, rejection of attempted `REQUIRED` removal, and
  deterministic `NONE`, independent symbolic `CLOSURE`, non-ancestral late and
  already-removed targets;
- pending checkpoint producers, matching and unrelated symbolic checkpoint
  evidence, retained admitted checkpoint references, custody frontiers and
  retained target-prefix abandonment as a negative design witness;
  and
- current-profile descriptor-copy/self-copy non-protection and unchanged
  symbolic geometry boundaries.

The suite separately preserves all sixteen C0.2f obligations under the amended
fold, including post-removal presentation distinctions and resource checks before
symbolic expansion. A closed assertion registry pins one discriminating assertion
for every retained obligation plus the critical fork, stale, ancestry,
genesis-collision and role-separation claims. The machine report maps each
obligation to its executable witness identifiers and separately labels properties
that are true only because the symbolic vocabulary or search bounds construct
them. Repeated family labels and delivery permutations are coverage, not
independent semantic shapes; construction-only facts are not counted as
executable witnesses.

## 6. Reproducible result

The required environment was Python `3.14.4`. Two v2 required-suite invocations
were byte-identical and each produced:

```text
PENDING SUBTREE FALSIFICATION verdict=NO_COUNTEREXAMPLE_WITHIN_BOUNDS invariants=109 traces=1268
```

The report records these explicit bounds:

| Bound | Value |
|---|---:|
| Events | 10 |
| Parents per event | 4 |
| Genesis authorities | 4 |
| UTF-8 bytes per symbolic field | 96 |
| Delivery permutations | 720 |

Observed instrumentation within the suite was:

| Metric | Maximum/earliest value |
|---|---:|
| Pending roots | 10 |
| Pending descendants | 2 |
| Earliest replay boundary | 0 |
| Replayed-event work | 3 |

These are observations inside the falsification envelope, not production limits.
O-08 owns production resource bounds.

The historical v1 required suite also ran twice and remained byte-identical at
its frozen digest. The v1 source, tests, schema and report remain evidence of the
superseded whole-suffix construction and were not modified.

The repository-owned mutation harness ran twice with byte-identical canonical
JSON and reported:

```text
C0.2i MUTATION GATE verdict=ALL_REQUIRED_MUTANTS_KILLED killed=13/13
```

It source-mutates the v2 kernel/scenario tree and kills: non-sibling application
under fork quarantine, stale-authority copying, pending-only replay-boundary
selection, retained-evidence misclassification as checkpoint-only, identity
inputs added to the current commitment profile, removal of the grant-ancestry
check, stale state hiding terminal fork quarantine, weakened `expect_error`,
retired-genesis and laundering assertions, a disabled duplicate-genesis guard,
and false control-role acceptance. Named security assertions are pinned by an
independent AST assertion-contract registry rather than trusting the weakened
test itself. Every mutant is executed twice and non-determinism fails the gate.

## 7. Residual risks and non-claims

- An author or relay can keep that author's causal subtree pending indefinitely
  by withholding an opening, and permanent opening loss can make it unrecoverable.
- Selective opening distribution can create temporary per-replica projection
  divergence until verified-opening sets converge.
- Delayed openings and late transcript admission can force expensive reversible
  replay. No finality or irreversible-effect permission follows.
- A coherent older transcript set can remain locally valid. The model does not
  provide rollback detection.
- AP-preserving compaction is unsolved. Checkpoint evidence cannot replace
  retained replay history.
- A hostile peer or relay can withhold checkpoint-named transcript material and
  force whole-projection `STALE_EVIDENCE`. The model detects the fail-closed
  condition but supplies neither freshness nor availability.
- Credential-identifier collision remains a cheap retroactive authority-freeze
  attack. C0.2j must solve it before C0.3, demo or product work.
- Any holder of valid signing-key material, including a revoked credential, can
  permanently quarantine the entire v0 AP context. This prevents authority
  expansion but creates an intentional fail-closed availability denial. A
  self-fork is an absolute context lockout, never a self-lockout escape.
- Fork arrival can be asymmetric between replicas. A replica that has not yet
  received the second sibling can expose only reversible provisional AP state;
  once the sibling arrives, terminal quarantine replaces that view. No finality
  claim follows from the earlier prefix.
- Fork-free concurrent grant/revoke can leave an attacker-granted successor
  operational in one grindable reference order. V0 revocation is non-transitive
  and does not bound credential compromise. C0.2j must replace the authority
  model, not merely rename outcomes.
- `ROTATE` and `RECOVER` are symbolic authenticated no-ops in this bounded
  model. They cannot resurrect an identifier, but the model also does not prove
  the fresh-credential succession required by O-02.
- Symbolic K-readable control kinds, grant subjects, binding references and
  verification keys are model inputs, not current O-06b-1 wire fields. C0.2j
  must define their authenticated carriage before implementation or C0.3.
- The current 44-octet commitment context accepts cross-credential descriptor
  copy and same-credential cross-sequence self-copy. C0.2k must bind the exact
  C0.2j credential and author sequence while preserving same-sequence fork
  evidence.
- Successful commitment verification does not prove possession at commit time,
  knowledge, truthful authorship, originality, first submission or semantic
  truth.
- Content lengths, types, geometry and commitment values can remain correlatable
  metadata.
- No optional disposition, profile-succession mechanism or stability/finality
  construction is selected. O-15 and O-16 remain open owners.

## 8. Required next gates

C0.2i changes replay semantics only. It leaves the following mandatory order:

1. **C0.2j:** decide collision-resistant credential identity, binding resolution,
   fork namespace and exact K-readable grant evidence;
2. **C0.2k:** amend the commitment context using the exact C0.2j credential and
   author sequence, rederive lengths and geometry, and flip the declared copy
   cases;
3. **O-06c:** produce real SHA-256 byte vectors, a second-language encoder,
   transcript/length mutations and the amended hostile suite; then
4. **C0.3:** only after all named protocol blockers close.

O-06, O-07, O-08, O-10, O-14, O-15, O-16 and K-11 remain open as documented.
C0.3, demo, product implementation and sensitive pilot work remain `NO-GO`.

## 9. Reproduction

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s tools/causal-flow-simulator/v2/tests -p 'test_*.py'

PYTHONDONTWRITEBYTECODE=1 python3 \
  tools/causal-flow-simulator/v2/causal_flow_simulator_v2.py \
  --suite required --output /tmp/styx-c02i-v2-1.json

PYTHONDONTWRITEBYTECODE=1 python3 \
  tools/causal-flow-simulator/v2/causal_flow_simulator_v2.py \
  --suite required --output /tmp/styx-c02i-v2-2.json

cmp /tmp/styx-c02i-v2-1.json /tmp/styx-c02i-v2-2.json
sha256sum /tmp/styx-c02i-v2-1.json /tmp/styx-c02i-v2-2.json

PYTHONDONTWRITEBYTECODE=1 python3 \
  tools/causal-flow-simulator/v2/mutation_harness_v2.py \
  --suite required --output /tmp/styx-c02i-v2-mutations-1.json

PYTHONDONTWRITEBYTECODE=1 python3 \
  tools/causal-flow-simulator/v2/mutation_harness_v2.py \
  --suite required --output /tmp/styx-c02i-v2-mutations-2.json

cmp /tmp/styx-c02i-v2-mutations-1.json \
  /tmp/styx-c02i-v2-mutations-2.json
sha256sum /tmp/styx-c02i-v2-mutations-1.json \
  /tmp/styx-c02i-v2-mutations-2.json
```

The positive verdict is valid only when the closed registries are complete and
non-empty, every invariant passes, both machine reports are byte-identical and
the exact final HEAD passes the independent and human gates in Issue #225.
