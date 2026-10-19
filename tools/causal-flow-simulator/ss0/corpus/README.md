# Synthetic SS-0 conformance corpus tooling

This directory constructs and validates the six synthetic-only SS-0 corpus
files under `conformance/secure-session/ss0/`. The data files contain no
OpenMLS, MDK, Marmot or other upstream bytes. They encode the already-ratified
Styx SS-0 witness inventory and remain bounded evidence, not a supported
adapter, persistence format, SDK, transport or product capability.

Generate once from the exact pinned inputs:

```bash
python3 tools/causal-flow-simulator/ss0/corpus/generate_corpus.py \
  --repo-root . --output-dir conformance/secure-session/ss0 --write
```

Subsequent verification is read-only:

```bash
python3 tools/causal-flow-simulator/ss0/corpus/generate_corpus.py \
  --repo-root . --output-dir conformance/secure-session/ss0 --check
python3 tools/causal-flow-simulator/ss0/corpus/validate_corpus.py \
  --repo-root . --corpus-dir conformance/secure-session/ss0
python3 -m unittest discover -v \
  -s tools/causal-flow-simulator/ss0/corpus/tests -p 'test_*.py'
```

Corpus JSON uses literal UTF-8, sorted object keys, compact separators, no
floating-point values and exactly one final LF. The manifest binds all five
non-manifest files and its own field-omitted projection. The generator consumes
only pinned source documents and inventories; it never executes either SS-0
reader and never consumes reader output.
