# O-07 genesis and checkpoint falsification report

## 1. Claim boundary

This report records bounded specification evidence for Issue #248. It does not
test a product adapter, persistence implementation, ceremony UI, transport or
wire format. A passing result is not a production-readiness, audit, anonymity,
availability, recovery or rollback-resistance claim.

## 2. Evidence package

The isolated package is `tools/causal-flow-simulator/o07/`. Its Python model
regenerates the exact transcript, uses real SHA-256 derivation and invokes the
selected O-14 Ed25519 verifier. An independent Node.js adapter parses, hashes
and verifies the same candidate bytes without receiving an oracle verdict.

The deterministic probe currently covers 19 named semantic cases. The
cross-runtime gate covers six positive and negative vectors. The source
mutation gate performs eleven exact single-site changes and requires a named
detector to kill every one.

## 3. Hostile classes exercised

- exact framing, truncation, trailing input, wrong domain and allocation bound;
- unauthenticated or denied ceremony, wrong reference and wrong O-03 tuple;
- malformed signature and signature-to-authority substitution;
- exact duplicate, distinct same-context genesis and rejected descendants;
- semantic equality between a grant reference and genesis credential identity;
- non-empty live replay dependencies, checkpoint smuggling and vacuous oracle;
- alternate delivery order without a root-selection effect.

The grant/reference equality case injects equality only after both reference
constructions have crossed their structural boundary. Production SHA-256 and
its domain separators are never replaced. The case tests mandatory behavior if
the post-derivation values are equal and preserves the collision and
second-preimage assumptions recorded by O-06.

## 4. Mutation relation

The source registry removes or changes one of these selected rules at a time:
reference-domain separation, authenticated provenance, explicit authorization,
reference matching, tuple matching, signature verification, one-genesis
fixation, descendant binding, grant/genesis collision rejection, checkpoint
unreachability and the non-vacuous replay-dependency witness. Every mutation is
required to execute and to fail its named detector.

## 5. Current bounded result

The development run at branch commit `b9ed187` produced:

- unit suite: 10 tests passed;
- semantic probe: `PASS`, 19/19 cases, deterministic report SHA-256
  `59b629cd6b6acdaceb3273c3a7f5e52655ea6dc5c5a2532514210ae9247b85f4`;
- Python/Node cross-runtime gate: `PASS`, 6/6 vectors, deterministic report
  SHA-256 `f2c4c4f2c773abbc6ff01b825f295a83d3ffbde974cfc18c950c23bd0091909e`;
- source mutation gate: all 11 required mutants killed.

These are development identities, not final-HEAD evidence. The PR must replace
or supplement them with two complete fresh-worktree runs and publish every
final report and diff digest before O-07 can become effective.

## 6. Residual falsification limits

Two independent implementations can share a conceptual error. The AP block's
interior grammar is profile-owned and not tested here. Fresh-key non-reuse is a
creator obligation that an acceptor cannot prove globally. The model fixes an
abstract atomic acceptance transition but does not prove crash durability or
rollback resistance. The unchanged O-06c run remains historical-placeholder
evidence and does not discharge the separate O-14-to-O-06c substitution rerun.
