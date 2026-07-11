# argon2id-spike — built artifact (STYX_SPIKE_PROTOTYPE)

Minimal artifact set needed to run the spike probes without Docker. **Strictly
experimental**: this is candidate A of the Argon2id spike, not a production
artifact, and it never ships (the web gate verifies the bundle is free of the
spike marker).

## Provenance

| Field | Value |
|---|---|
| Source | `../src/lib.rs` + `../Cargo.toml` (RustCrypto `argon2` 0.5.3, `wasm-bindgen` 0.2.126) |
| Dependency graph | `../Cargo.lock` (committed; build runs `--locked`) |
| Toolchain image | `rust:1.96.1@sha256:1f0dbad1df66647807e6952d1db85d0b2bda7606cb2139d82517e4f009967376` |
| wasm-pack | `0.15.0` (release tarball, sha256 `c09f971ecaed9a2efc80fdcea7a00ef6b53c7fadc8c57d1f61b53a6aa66b668a`, verified by the build script) |
| Artifact digest | `argon2id_spike_bg.wasm` sha256 `59e11b90b01a7085500b780f07dddd2255554ac4c30cec4c741eafe87ce6cac6` (all files: `SHA256SUMS`) |

## Regeneration

```bash
# from styx-js/spikes/argon2id/crate/ (needs Docker):
./build.sh
sha256sum -c pkg/SHA256SUMS
```

`build.sh` pins the image by digest, sha-verifies the wasm-pack tarball, and
builds with the committed `Cargo.lock`. Build cache (`target/`) and the
downloaded tarball are ignored and must not be committed.
