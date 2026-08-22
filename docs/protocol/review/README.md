# Styx application-protocol review model

This directory contains a compact, machine-readable view of the currently
ratified Styx application-protocol baseline. It exists to make security review
faster and more systematic. It is not the protocol specification, a security
proof, implementation evidence or permission to build C0.3.

## Authority

When sources disagree, use this order and fail closed:

1. the accepted GitHub task contract and its native dependencies;
2. repository `AGENTS.md`;
3. the English decision registry, encoding profiles, responsibility matrix and
   threat model identified in the model's `sources` array;
4. the derived JSON review model;
5. generated validation reports, review reports and local notes.

The JSON model must never be used to override, complete or silently select an
unresolved normative decision. Its source paths, exact byte digests and
citations make drift visible; they do not prove that a modeled claim is true or
complete.

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
state transitions, invariants, counterexamples, non-claims and blocker edges.
An explicit `UNRESOLVED`, `SYMBOLIC`, `PROFILE_DEPENDENT` or `EVIDENCE_ONLY`
state is deliberate; it must not be promoted merely to make a review simpler.

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

## Limits

The model does not prove protocol security, cryptographic soundness,
implementation conformance, interoperability, anonymity, erasure, finality,
availability, audit readiness or production fitness. It cannot detect a
normative omission shared by all sources. C0.2j, C0.2k, O-06c, O-07, O-08,
O-10 and O-14 remain blockers for C0.3; demo, product and sensitive-use claims
remain fail closed.
