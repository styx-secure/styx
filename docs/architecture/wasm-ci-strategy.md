# WASM integrity in CI — strategy

Status: active · 2026-07-12 · implemented by `.github/workflows/wasm-integrity.yml`

## Why

The vendored `styx-js/vendor/openmls-wasm/` crate (OpenMLS → WebAssembly) is the
cryptographic critical path of Styx Chat. It ships as a **pre-built, committed** artifact
because OpenMLS publishes no npm package. Two properties must therefore be enforced by CI,
not by trust:

1. the committed artifact is exactly what the pinned source + toolchain produce
   (reproducibility), and
2. the artifact's wire-facing parsers reject hostile input without poisoning the shared
   WASM instance (robustness).

A full reproducible build is expensive (two hermetic OpenMLS builds under Docker), so
running it on every PR would be wasteful. But a change to the crate, its patch, or its pin
must **never** merge without a rebuild. The answer is a two-tier gate.

## Tiers

### Light tier — every relevant PR

Runs when a PR touches the artifact, its provenance, or its MLS/chat consumers
(`styx-js/vendor/openmls-wasm/**`, `styx-js/src/crypto/mls/**`, `styx-js/src/chat/**`).
Fast; no rebuild:

- **Artifact presence** — the `.wasm`, glue `.js` and `.d.ts` exist and are non-trivial.
- **Checksum vs provenance** — `sha256(openmls_wasm_bg.wasm)` must be the value recorded in
  `PROVENANCE.md`. Catches an artifact that was swapped without updating its provenance.
- **Pin coherence** — the `OPENMLS_COMMIT` in `build.sh` is the commit documented in
  `PROVENANCE.md`. Catches a silent pin bump.
- **Adversarial + MLS tests** — the jest suites that feed corrupt Welcome / ratchet-tree /
  KeyPackage bytes and assert a catchable `Error` (never a `WebAssembly.RuntimeError`
  trap), plus the MLS round-trip and member-identity binding tests. This is the negative
  and positive coverage of the parsers and the persistence/identity API.

### Hermetic tier — crate changes and releases

Runs when a PR changes the crate source, patch, pin, toolchain, `Cargo.lock`, provenance,
or the artifact itself — and on manual `workflow_dispatch` (releases):

- **Reproducible double build** — `verify.sh` builds twice from the pins and requires the
  two builds to be byte-identical to each other **and** to the committed artifact, with
  `--locked` + a `Cargo.lock` drift guard. Uses the digest-pinned `rust:1.96.1` image and
  the sha256-verified `wasm-pack`.
- **Hashes published** — the verify output (artifact sha256s + toolchain) is uploaded as a
  build artifact for the release record.

Because the hermetic job is required whenever crate-level paths change, **a change to the
crate, patch, or pin cannot be integrated without a matching reproducible rebuild.**

## Stable required check

The workflow always runs (no top-level `paths:` filter). A `changes` job classifies the
diff; the light/hermetic jobs run only when their tier applies; a final `gate` job
(`if: always()`) reports one definite status — an explicit green skip when no relevant path
changed. That single `WASM integrity / Gate` check is therefore present on every PR and is
suitable as a required check, and it cannot be bypassed by editing path filters (the
classification is inside the always-run job, not a workflow-level `paths:` trigger).

## Coverage boundaries and residual risks

- **CodeQL does not cover Rust or WebAssembly.** This workflow is the security gate for the
  crate; CodeQL covers only JavaScript/TypeScript (see the GitHub security baseline report).
- **`wasm-bindgen-cli` is pinned transitively by `Cargo.lock`, not hash-verified.** Recorded
  as an accepted residual in `PROVENANCE.md`.
- **The light tier trusts the committed artifact.** Its defence is the checksum-vs-provenance
  gate plus the fact that any crate-level change escalates to the hermetic rebuild. A
  consistent artifact+provenance swap that is *also* reproducible from the pins is, by
  definition, the legitimate artifact.
- **The OpenMLS pin is intentionally fixed** (a descendant of `openmls-v0.8.1` carrying the
  SRLabs audit fixes). CI must not bump it; Dependabot is configured not to touch the crate.

## Change procedure for the crate

1. Update source/patch/pin and rebuild locally with `./build.sh`.
2. Run `./verify.sh` until it is byte-identical and update `PROVENANCE.md` hashes.
3. Open a PR — the hermetic tier reproduces the build in CI and gates the merge.
