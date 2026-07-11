# Argon2id spike (STYX_SPIKE_PROTOTYPE)

Candidate comparison + parameter benchmarks for the Blocco 3 Root-Key KDF, run in
a dedicated module worker (the context the crypto-worker spike selected). **Not
production code**; nothing here ships (bundle verified clean of both the spike
marker and hash-wasm). Results, parameter profiles and the recommendation:
`docs/superpowers/spikes/2026-07-12-argon2id.md`.

Candidates:

- **A** — `crate/`: RustCrypto `argon2` compiled to WASM (36.5 KB) with the SAME
  pinned toolchain as the canonical vendored crate (`crate/build.sh`, identical
  image digest + wasm-pack release; the canonical artifact is untouched).
- **B** — `hash-wasm@4.12.0`, exact-pinned devDependency (npm integrity recorded
  in the spike doc). Never a production dependency.

Run (from `styx-js/`):

```bash
npx playwright test -c spikes/argon2id/playwright.spike.config.js
# rebuild candidate A (needs Docker):
spikes/argon2id/crate/build.sh
```

Probes A1–A8: init cost/artifact size, byte-for-byte cross-candidate agreement on
three parameter sets (cross test vectors, stable across browsers), profile
benchmarks (desktop / mobile-balanced / mobile-low-memory, median of 3),
main-thread paint starvation vs worker execution, 10-run stability, absurd
memory cost (3 GiB) failing typed with clean recovery, mid-derivation
termination, and 4× CPU throttling (chromium; note: the throttle does not reach
dedicated workers — recorded in the doc).
