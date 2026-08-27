# O-10 outcome-taxonomy falsification report

Status: bounded implementation evidence for Issue #252.

The isolated O-10 package challenges, but does not prove, the taxonomy selected
in `styx-app-kernel-v0-outcome-taxonomy.md`.

## Evidence boundary

- literal source inventory: 36 Base review-model citations plus all 66 frozen
  O-08 handoff rows, for 102 rows total;
- partition: 99 positive mappings and three forbidden alias/profile-marker
  registrations;
- closed taxonomy: 25 primaries, one alias, two post-C0.3 markers and one
  remote collapse;
- hostile corpus: 85 successful cases covering every primary, every adjacent precedence
  edge in both presentation orders, the distinct S6 `DEPENDENCY_DEFERRED`
  branch, S4/S6 overlaps and privacy perturbations;
- independent evaluators: Python reference and JavaScript adapter with no
  shared semantic oracle, plus one cross-runtime fail-closed case where mutation
  disposition cannot be proven;
- mutants: 64 killed, zero survivors, spanning every primary row, every
  intra-stage and inter-stage precedence boundary, the S6 resource split in
  both evaluators, one Base-source anchor, recovery and independent JavaScript
  behavior;
- repository integration: exact three-coordinate validator delta, frozen
  predecessor packages and a two-clean-checkout regeneration gate.

Canonical generated reports contain no repository/commit identity, absolute
path, host/user/process provenance, timestamp or elapsed measurement. The
scope report separately binds Base and final blob digests for every modified
allowed path.

## What the evidence can falsify

The probes fail closed on unknown fields/identifiers, duplicate or missing
inventory rows, stale Base anchors, handoff drift, competing primaries,
presentation-order dependence, unsafe same-byte recovery, remote diagnostic
leakage, surviving mutants, cross-runtime disagreement and validator changes
outside the ratified coordinates.

## What it cannot establish

Passing evidence is not proof of completeness or security and is not product
implementation or conformance. The package does not select wire/storage codes,
transport or session behavior, product ceremony, persistence, recovery,
freshness, finality, rollback detection or availability. A shared omission in
the contract and both implementations can remain undetected.

O-10 may be marked bounded `DECIDED` only after the exact-final package,
independent reviews and human gates pass. C0.3 remains `NO_GO` because its
other retained dependencies and the corpus licensing/path gate still apply.
