# C0.1 application-semantics characterization

Status: non-normative characterization at Styx base
`f0f7c35fa030477f56ea3b29efa1381f0d2dc972`.

This directory records how the current Dart reference ledger and JavaScript
browser ledger respond to one ordered synthetic corpus. It does not select a
protocol rule, certify either implementation, or establish interoperability,
security, audit coverage, anonymity, compliance, readiness or suitability for
sensitive use.

The JavaScript ledger is a port of the Dart ledger and was previously aligned
to Dart-generated vectors. A `MATCH` is therefore evidence of port fidelity,
not independent corroboration and never proof that the observed construction
should become normative.

## Evidence order

`cases.json`, `schema.json`, this README and
`expected-classifications.json` are preregistered before the first commit that
contains runtime observations or `report.json`. A later change to an expected
classification requires a separate commit with written justification.

Neither runtime may generate corpus input for the other. `EVENT-002` consumes
the RFC 8032 test-vector-1 seed and public key as literal synthetic input; the
runtime-created genesis signature is not compared.

### Independently derived signed-chain fixture

`CHAIN-006` is a one-event, non-empty valid-chain hypothesis. Its fixture was
derived before either adapter or the generated report was changed:

- `previousHash` is null, `eventType` is `transaction`, and the payload is the
  single byte `01`;
- the HLC canonical string is
  `2026-02-24T12:00:00.123Z-0042-a1b2c3d4`;
- the signed preimage is `utf8("transaction") || 0x01 ||
  ascii(hlcCanonical)`, whose lowercase hex is
  `7472616e73616374696f6e01323032362d30322d32345431323a30303a30302e3132335a2d303034322d6131623263336434`;
- SHA-256 of that preimage, and therefore the literal signed-message bytes and
  stored event hash, is
  `6a203102c491dbdf209441e5d8edcc3aabc883f7ddb9bc2231dadade0de4878e`;
- the RFC 8032 test-vector-1 public key is
  `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`;
- the Ed25519 signature over those 32 hash bytes is
  `a6427faee44642ef6170be5c4c23ee814f83e7a4429824c7b5d38b9abeaa1e17306d7180963cfbd619015515187e6e5e9d266f83e8267309446a9d5618063f0f`.

Each adapter must fail closed unless `signedMessageHex == eventHashHex`, build
the event only from these literal fields, and invoke its production full-chain
validator. Neither adapter may repair or regenerate the fixture.

## Files

- `cases.json`: single ordered, versioned synthetic input corpus;
- `schema.json`: strict adapter-envelope schema;
- `expected-classifications.json`: preregistered hypotheses, never runtime
  output;
- `compare.mjs`: fail-closed orchestrator and canonical comparator;
- `report.json`: deterministic generated evidence, added only after the
  preregistration commit.

The adapters live in their runtime test areas. They import production code as
is and may not duplicate, repair or substitute its algorithms.

## Classification

- `MATCH`: both runtimes support the case and canonical semantic values are
  byte-identical;
- `DIVERGENCE`: both support it and the values differ;
- `UNSUPPORTED`: at least one named runtime cannot express the case without a
  production change.

An implementation exception, sentinel, wrap or truncation on an expressible
input is an observation, not `UNSUPPORTED`. Harness/infrastructure failure
aborts the entire run.

## Canonical envelope rules

| Rule | Why it cannot erase semantic content |
| --- | --- |
| Object keys sorted by UTF-16 code unit | Establishes one byte representation without changing keys or values. |
| UTF-8 without BOM, no insignificant whitespace, LF and one trailing LF | Fixes transport bytes only. |
| Every integral value represented as an exact decimal string | Preserves values outside the JavaScript safe-integer range and avoids numeric-format drift. |
| Raw bytes encoded directly as lowercase hex | Is bijective and does not decode or transcode implementation bytes. |
| Stable harness-owned reason codes | Compares error categories without locale-dependent exception text. |

Forbidden normalization includes numeric coercion or reformatting, case
folding, locale/collation comparison, Unicode normalization, string
trimming/padding/re-encoding, byte re-encoding and comparison of human-readable
error text. `observedToken` preserves a deterministic implementation-shape
witness but is reported separately and is not part of semantic equality.

Cases marked `unspecifiedBehaviour` may detect drift, but their `MATCH` values
must not be reported as shared semantics.

## Runtime and CI boundary

Both adapters take the corpus path explicitly. The Dart test runs only Dart;
the Jest test runs only JavaScript on Node 20. Each test regenerates and
byte-checks its own committed observation section. Only `compare.mjs` invokes
both adapters, using fixed executable and argument arrays without a shell.
For every adapter process the comparator overrides `LANG=C`, `LC_ALL=C` and
`TZ=UTC`, irrespective of its caller environment. This controls the locale and
timezone inputs without removing unrelated environment values needed to locate
the pinned toolchains. Collation-dependent ordering cases remain explicitly
unspecified because this process setting cannot turn an implementation's
default collation into a protocol guarantee.

At this base the cross-runtime classification step has no required CI job. It
is mandatory local and independent-review evidence. Adding a required job, and
extending the CI claims-lint root to `conformance/`, require separate workflow
contracts.

`staleMetadataFindings` assesses only the legacy `hlcCounter` entry. Every
other legacy incompatibility entry remains outside C0.1 and is neither confirmed
nor disproved by this report.

## Deliberate boundary

The implementation-specific event-object JSON projections are not
characterized here because Dart exposes no equivalent public JSON contract.
C0.2 must first decide whether such a projection belongs in the language-neutral
protocol. This prevents a browser convenience representation from becoming a
durable format by accident.

All material in this increment remains under the repository's
AGPL-3.0-or-later default. It contains no source excerpts. Any future
permissive exact-path corpus license requires a fresh inventory and explicit
human amendment.
