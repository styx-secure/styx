# Styx O-14/O-06c integration falsification report

## 1. Status and authority

- **Task:** Issue #260.
- **Ratified Base:**
  `25be9abc0d8c1bce8821a750616e13d245abc356`.
- **Candidate status:** the exact-final two-clean-checkout technical gate passes;
  independent review and human gates remain pending.
- **Verdict:** `NO_COUNTEREXAMPLE_WITHIN_CANDIDATE_BOUNDS`.
- **C0.3:** `NO_GO` until the Issue #260 review/human gates and the remaining
  authority-set synchronization required by Issue #251 are complete.

This report records bounded falsification evidence. It is not proof, an audit,
product conformance, a production verifier or authorization to create a C0.3
corpus.

## 2. Frozen inputs and integration boundary

The rerun does not amend O-06b, O-07, O-08, O-10 or O-14. It consumes their
frozen outputs in this observable order:

1. O-08 rejects an envelope violation before proportional work.
2. O-06b regenerates the complete canonical application transcript and event
   reference.
3. K resolves one authenticated O-07 genesis or C0.2j `GRANT` credential
   binding. Candidate bytes cannot supply the binding provenance, suite or key.
4. O-14 admits only suite `0x0001`, canonical 32-octet prime-order key material
   and canonical 64-octet `R || S` with `S < L`, then invokes exactly one
   selected verifier over the regenerated transcript.
5. Only a K-verified object reaches AP authorization.
6. O-06c projects the frozen commitment, causality and replay result.
7. O-10 classifies the trusted-local result and collapses every non-applied
   untrusted-remote projection to its frozen opaque shape.

The model treats provenance as a local trusted-resolver result rather than a
serialized field. Its `O07_GENESIS` and `C02J_GRANT` labels distinguish the two
already-ratified sources; they are evidence-model labels, not production wire or
storage values.

## 3. Candidate evidence

The integrated candidate evidence currently exercises:

| Evidence family | Candidate result |
| --- | ---: |
| fixed, transcript and candidate-envelope hostile witnesses | 115 passed |
| O-08 dispositions consumed | 69 of 69 |
| C0.3-entry dimensions exercised | 53 of 53 |
| O-08-to-O-10 handoff rows exercised | 66 of 66 |
| boundary observations | 154 |
| integration-order mutants | 7 killed, 0 survivors |
| integrated Python unit tests | 41 passed |
| Python/JavaScript runtime traces | 9 events, byte-identical where jointly claimed |

The 115-witness set covers content-free, `REQUIRED` and `DETACHABLE` content;
single and tree commitments; genesis and grant provenance; rotation/recovery
successors; fresh replay; sequence rollback and gaps; same-key distinct
credentials; unknown, reserved and maximum suites; key and signature length
boundaries; scalar boundaries; non-canonical, small-order, mixed-order and
off-curve `A`/`R` families; signature and transcript bit flips; event-reference
substitution; and explicit Nostr/MLS substitution attempts.

The seven integrated mutants challenge the integration order and ownership
boundary. They do not replace the frozen O-14 mutation registry or claim its 26
mutants as integration-owned evidence. The exact-final gate reruns the frozen
O-07, O-08, O-10 and O-14 suites separately and fails closed if any inherited
source, report, command, runtime or second execution is missing.

The O-08 disposition, handoff and boundary rows are integration coverage, not
an independent oracle for the frozen O-08 policy. Their expected values are
derived from that frozen policy and are defended independently by the frozen
O-08 suite. Work counters are ordering observations rather than standalone
security verdicts; mutant survival and the named expected outcome remain the
primary discriminators. The four preflight dimensions not encoded by the O-06b
grammar are conservative caller observations: an observation may increase a
derived value, but cannot understate it.

## 4. Properties challenged

No counterexample was found within the candidate envelope to these properties:

- suite/key hints from an event, transport, Nostr, MLS or session layer cannot
  replace the authenticated credential binding;
- malformed suite, key, signature or transcript input cannot reach AP;
- a failed O-14 verification cannot retry, fall back, select another backend,
  batch or invoke a second verifier;
- signature success proves possession for the exact transcript but cannot
  substitute for O-07 provenance, C0.2j binding or AP authority;
- all limits precede proportional work and AP exposure;
- trusted-local O-10 precedence is unchanged, including for inactive but
  cryptographically verifiable credentials;
- untrusted-remote failure does not reveal the local diagnostic class; and
- JavaScript interchange remains explicitly `TEST_ONLY_NOT_O11`.

## 5. Exact-final reproducibility

The four canonical report families are deterministic. Their exact digests are
emitted into the immutable external PR evidence package rather than copied into
this tracked report, avoiding stale or self-referential identity claims. The
Issue #260 final gate regenerated all reports twice from
distinct clean clones, verified the complete bundle and raw provider evidence,
reran every frozen suite with Python 3.14.4, Node 24.18.0 and Dart 3.10.8, and
produced byte-identical package evidence. It passed with 21 regenerated reports
and 80 package artifacts; a post-final strict scope rerun also passed. Bundle,
diff, report and manifest identities remain immutable PR evidence rather than
tracked inputs.

## 6. Non-claims and residual risk

This evidence selects no production ceremony, wire format, signature carriage,
storage encoding, durable custody, recovery, freshness, rollback detection,
finality, delivery, availability, anonymity, erasure or product behavior. It
does not claim Dart/browser adapter conformance, constant-time behavior,
hardware-backed keys or secure key storage. O-11 retains wire and persisted
representation ownership.

K-first verification of an inactive credential can consume bounded verifier
work before O-10 reports the later authority outcome. This is the existing
`O14-GUARD-COST-O08` residual and neither a new authorization rule nor a change
to O-10.

The candidate-owned final gate is itself executable evidence, not an
independent proof of its correctness. Exact-final Opus 5 read-only review,
`manexada` approval and the `maverde73` merge decision remain mandatory.
