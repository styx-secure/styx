# SS-CORPUS-0 falsification report

## Scope and authority

Issue #293 authorizes construction and falsification of a six-file, fully
synthetic SS-0 conformance corpus at Base
`28a5e78e80a014a27b94683479d4e82206abac2f`. Its normalized contract body has
SHA-256 `2c7b4eadb90a1435ba9772b48e84ce6d1a0e727959272d78f02d189e3f992e11`
and was ratified by provider comment `5485961310`. The K11-SS path inventory was
separately ratified by Issue #291 comment `5484188019`; its ordered six-path
digest is `61bea8adc1e36af3bc011df2553f634f0eeeae2c2dba01611a426628341b1861`.

This report evaluates corpus construction, deterministic transport through the
already-frozen readers, mutation detection and evidence integrity. It does not
reopen or independently prove the SS-0 semantics, MLS/OpenMLS/MDK correctness,
cryptography or general interoperability.

## Constructed evidence

The canonical manifest binds the generator, six normative inputs, sixteen
reproduction inputs, all generated-file digests, `synthetic: true` and
`upstreamBytes: "none"`. The closed corpus contains:

| Evidence class | Exact count |
| --- | ---: |
| owners | 20 |
| atoms | 60 |
| source witnesses | 56 |
| atom/witness relations | 104 |
| valid session vectors | 14 |
| invalid session vectors | 18 |
| state-machine scenarios | 24 |
| expected traces | 56 |
| source mutation records | 44 (`41` corpus / `3` supplemental) |
| corpus-data mutants | 28 |

Every source witness occurs exactly once in one input partition and once in the
expected traces. The generator reads only pinned normative/reproduction data;
it does not execute either reader and cannot consume reader output.

## Falsification method and observations

1. Canonical regeneration and validation reject missing, extra, reordered,
   duplicate, non-canonical, non-synthetic, unbound or symlinked corpus data.
2. The Python and JavaScript children receive only the bare candidate input:
   source file, partition, witness ID, detector and expected result are absent.
3. Both raw observation streams are written atomically before the expected
   trace file is opened. All 56 Python observations equal the 56 independent
   JavaScript observations and the 56 frozen traces.
4. The frozen source runner kills all 44 source mutants. All 44 mutate the
   Python reference reader; this increment makes no JavaScript mutation-
   sensitivity claim. The corpus mutation registry maps exactly 41 of them to
   corpus witnesses and preserves three frozen supplemental detectors.
5. All 28 literal corpus-data mutants are killed by their named detector owner;
   the reader-stream and report-provenance negative controls cannot pass.
6. The scope guard re-fetches Issue #293, its ratification and the K11-SS
   authority from the provider, imports the repository's official task-contract
   parser/path matcher, verifies pinned inputs/history and rejects any changed
   path or object outside the ratified relation.
7. The final gate requires two distinct, pairwise-disjoint clean exact-HEAD
   checkouts with distinct Git metadata and no alternates, plus pairwise-
   disjoint external evidence roots. It
   reruns the corpus suite, compares all six corpus files and four canonical
   report families byte-for-byte, and checks cleanliness again after execution.

The final evidence roots contain the replay, mutation, scope and review-model
reports from each checkout. The canonical manifest binds its generator,
normative inputs and reproduction inputs to exact closed lists. Report input is
recursively rejected if it exposes source-file, partition, witness, case or
other provenance keys to a child reader.

The reader agreement is transport-fidelity and regression evidence relative to
the already-frozen Base agreement. It is not presented as a fresh independent
semantic implementation because both readers were frozen before this corpus.

## Reproduction qualifications

The scope and final gates preserve two historical commits from PR #286 that are
not ancestors of the default `main` clone. A reproducer must fetch that provider
reference before running either gate:

```bash
git fetch --no-tags origin refs/pull/286/head
git cat-file -e bd9a06c7f7299a798105a71894934c25643ba78e^{commit}
git cat-file -e c8430b4b57ff69a070ae4bc3a60b1a232c25df24^{commit}
```

The repository-wide `tools/protocol-phase-exit` suite is outside Issue #293's
allowed paths and was already stale at Base: three of its 24 tests failed there.
The candidate has four failures because that excluded suite also expects new
audit-table rows for this increment. This is recorded as inherited/out-of-scope
evidence, not converted into a green skip or silently repaired here.

## Mechanical result and remaining gates

The constructed corpus, replay and mutation suites produce `PASS` under the
pinned Python `3.14.4` and Node `v24.18.0` capabilities. The exact-final
candidate remains subject to the full Issue #293 command block, two-checkout
final gate, required live CI, independent exact-final review and distinct human
technical, integration, Ready and merge gates. Missing, skipped, timed-out or
unverifiable evidence is a failure, not a green skip.

No adapter, authenticated persistence, SDK, transport/delivery, product,
Flegias workflow, demo, deployment or sensitive-use authority follows from
this bounded corpus result.

Residual falsification limits include the asymmetric source-mutation evidence
(Python only), the historical PR-reference fetch requirement and the excluded
stale phase-exit suite. The exact-final review must assess these limitations; a
passing corpus run does not erase them.
