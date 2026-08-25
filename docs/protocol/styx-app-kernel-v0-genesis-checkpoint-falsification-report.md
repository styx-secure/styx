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

The versioned inventory has exactly 287 normative atom/scenario relations:
229 semantic hostile instances and 58 distinct repository, reproducibility,
external-review or human gates. The deterministic probe executes all 229
semantic instances. The cross-runtime gate executes the same exact 229
relations independently in Python and JavaScript. The source mutation gate
anchors seven real source mutants, one per semantic family, and maps every one
of the 229 semantic rules to a unique named mutant/detector relation; every
registered mutant must be killed.

## 3. Hostile classes exercised

- exact framing, truncation, trailing input, wrong domain and allocation bound;
- caller-fabricated, denied or malformed ceremony input; fake, copied,
  reconstructed, foreign-domain and foreign-Boundary capabilities; wrong
  reference and wrong O-03 tuple;
- malformed signature and signature-to-authority substitution;
- exact duplicate, distinct same-context genesis and rejected descendants;
- semantic equality between a grant reference and genesis credential identity;
- non-empty live replay dependencies, checkpoint smuggling and vacuous oracle;
- every contract-required candidate/ceremony delivery order and deterministic
  ambient arrival/relay/storage/wall-clock permutation without root selection.

The grant/reference equality case injects equality only after both reference
constructions have crossed their structural boundary. Production SHA-256 and
its domain separators are never replaced. The case tests mandatory behavior if
the post-derivation values are equal and preserves the collision and
second-preimage assumptions recorded by O-06.

## 4. Mutation relation

The source registry changes one selected rule in each closed semantic family:
framing/profile closure, reference-domain separation, local capability-domain
binding, cross-gate substitution, terminated-lineage admission, checkpoint
smuggling and hostile-candidate delivery. The 229 inventory relations remain
distinct even where a family shares one anchored source mutant. Every actual
registered mutant executes and must fail its named detector; a prose-only or
cosmetic mutant cannot satisfy the gate.

## 5. Current bounded result

The bounded development run produces:

- O-07 unit suite: 39 tests passed;
- semantic probe: `PASS`, 229/229 semantic instances, with all 58 separate
  gates explicitly retained rather than reported as semantic passes;
- Python/Node cross-runtime gate: `PASS`, 229/229 exact relations with no skip
  or oracle input;
- source mutation gate: all seven registered mutants killed and all 229 unique
  mutation relations covered.

Every canonical-report producer derives one mandatory hygiene context from the
exact Base, candidate, both trees, the binary/full-index diff, repository path,
hostname and user before serialization. The API has no empty default context.
The final evidence gate then reads the actual bundle bytes, adds their SHA-256
to that same identity set and requires exactly two canonical, byte-identical
reports for each of the probe, cross-runtime, mutation and scope schemas.

Canonical reports deliberately contain no Base, candidate, tree, diff or bundle
identity. Final identities and SHA-256 values belong only to the immutable
external evidence package. Two complete fresh-worktree runs, the final bundle
hygiene gate and every separate gate remain mandatory before O-07 can become
effective.

## 6. Residual falsification limits

Two independent implementations can share a conceptual error. The test
Boundary is deterministic evidence only, not a production authenticator. The AP block's
interior grammar is profile-owned and not tested here. Fresh-key non-reuse is a
creator obligation that an acceptor cannot prove globally. The model fixes an
abstract atomic acceptance transition but does not prove crash durability or
rollback resistance. The unchanged O-06c run remains historical-placeholder
evidence and does not discharge the separate O-14-to-O-06c substitution rerun.
