# M1 final-review follow-ups

This file records the MEDIUM/LOW findings from the final six-chunk cross-vendor
review that are not part of the bounded H1/H2/H3 remediation. They do not alter
public schema meaning in this change.

## Fixed in the M1 remediation

- H1: strict scope classification includes the disposition document and nested
  ACV-049 fixture, with a real-tree strict-guard regression.
- H2: reserved O-04 rows are excluded from derivation and rejected at release.
- H3: all semantic targets resolve; ACV-038/065/075 are retargeted, while
  ACV-064 and ACV-084 are removed because no semantically faithful public field
  exists. The family/instance counts and digests are repinned.
- The structural-isolation digest is bound and corrected.
- ACV-043/044 relation-row counts are bound to the 16/17-row relations.
- The stale semantic/combined family counts in the atom derivation are corrected.

## Protocol or owner decision required

- Define the authority-fold tie rule for equal minimum-sequence siblings.
- Decide whether nested evidence references must equal their outer reference;
  this would require a new semantic family and mutants.
- Define the byte/delta meaning of
  `SEEDED_EXTENSION_ONLY_PRESERVE_BASE_SEMANTICS` before strengthening its pin.
- Decide whether `PresentationIdV0` is u64 or a wider opaque decimal identifier.
- Confirm the ACV-010 `RECORDS + 1` credential-binding bound.
- Confirm whether replay pending counts use all deferred records or minimized
  pending roots and whether `PENDING_DESCENDANTS` needs an independent check.
- Confirm candidate-domain bounds used by the ACV-049 scalar-pair derivation.
- Confirm F13 fallback/profile mapping and signature/envelope failure ordering.
- Bound final-gate metadata visibility if visibility above evidence/tool roots is
  not intended.
- Define complete logical-K admission preconditions in the separately scoped
  C0.3 model (signature/opening/reference observations).

## Implementation hardening

- Bound authority down-set construction before enumeration and normalize
  projection errors instead of leaking `KeyError`/`TypeError`.
- Convert canonical-JSON recursion failures to `CanonicalJsonError`; separately
  define the Python/JavaScript integer-domain invariant.
- Improve canonical-report forbidden-token matching without short-token false
  positives.
- Tighten `RelativeRegularFile` against `.` and trailing slash.
- Make provider overlap checks ancestor-aware and paginate all open items.
- Pin the contract validator default to the ratified Base SHA.
- Harden final-gate pagination, completion-decision validation, process tracing,
  Python/Node runtime monitors, isolated environment, decimal-ID parsing and
  stale-count diagnostics.
- Derive decoded-octet maxima independently of JSON maxima and fold every
  non-neutral `allOf` sibling.
- Bind probe request/response rows to all 19 response cases.
- Key the pinned C0.3 module cache by verified path/digest.
- Give the Node adapter a closed schema-keyword vocabulary and pin the manifest
  before trusting artifact rows.
- Reject dynamic JavaScript loading in static isolation checks.
- Anchor inventory-validator success parsing to the exact total.
- Strengthen ACV-049 ownership/route bindings, monitor channel preflight,
  alternative deduplication, trace reset, CLI map identity and exception
  normalization; remove claims of independent readers when sources are shared.
- Resolve evidence-root symlinks before normalization and generate seed outputs
  atomically.
- Freeze Phase-A evidence bytes once for both Phase-B derivations.
- Replace hard-coded `/usr/bin/git` with a discovered, recorded executable while
  retaining the intentional Python 3.14.4 evidence pin.

## Documentation and test cleanup

- Clarify README scope wording and replace stale command literals with variables.
- Add the fourth evidence-update result arm to the prose.
- Correct remaining validator/witness runbook row literals and document the
  interpreter patch prerequisite.
- Remove the unused unmonitored JavaScript reader and the vacuous byte-identity
  claim, or relabel them honestly.
- Correct the mutation-runner printed killed count.
- Add equality assertions across all derived-maxima consumers and uniqueness for
  nested maxima use-site keys.

## Deferred because no present defect was demonstrated

- Python Unicode regex classes: current public patterns use explicit ASCII.
- Concurrent evidence-file mutation: use descriptor-bound hashing if that threat
  model becomes supported.
- `generate_structural_witnesses.py` exception-class placement is readability
  only.
