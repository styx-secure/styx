# Blocco 1 — Emergenza WASM — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (or superpowers:subagent-driven-development) to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Execute tasks **in order** — the ordering is load-bearing (one WASM rebuild only).

**Goal:** Close all seven Blocco 1 requirements from the feasibility document (`docs/security/2026-07-11-fattibilita-piano-utente.md` §5): remove panics reachable from network input, pin OpenMLS to a post-audit release, pin the build toolchain, vendor `Cargo.lock`, make the build reproducible, fix the ciphersuite documentation, and cover the untrusted parsers with negative tests and fuzzing. Along the way, land the MLS↔transport identity binding (N2) that the same crate work unblocks.

**Why this block first:** the feasibility assessment identifies the vendored Rust/WASM crate as the project's critical path — `StorageProvider`, ACK-gated commits, fork detection and multi-device all depend on APIs the crate does not expose today. Nothing else in the roadmap can be built on a crate whose parsers trap on hostile input and whose artifact is not reproducible.

**Architecture:** The JS layer of Fase A (signature verification, nonce/HMAC pairing proof, no-overwrite guards, explicit roster confirmation, safety number) is **already implemented, committed and tested** — do not re-implement it. What remains lives under `styx-js/vendor/openmls-wasm/`: `build.sh` clones OpenMLS at a pinned commit, overwrites `openmls-wasm/src/lib.rs` with `patch/lib.rs`, and compiles to WASM with `wasm-pack` inside Docker. We harden that Rust, pin every input to the build, rebuild the artifact **once**, verify it is byte-reproducible, and expose `member_identities()` through the `Group` → `MlsSession` → `MlsEngine` chain so `StyxChat` can reject a group whose peer credential does not equal the transport `from` pubkey.

**Tech Stack:** Rust + `wasm-bindgen` + `wasm-pack` (Docker); JavaScript ES modules; Jest (`testMatch: **/test/**/*.test.js`, `transform: {}` — native ESM, no Babel); `@noble/curves`, `@noble/hashes`.

## Global Constraints

- **Everything is under `styx-js/`** (JavaScript + vendored Rust). Do not touch the Dart packages.
- **Reproducible WASM build only.** The `.wasm` artifact MUST be regenerated via `vendor/openmls-wasm/build.sh` (Docker, **digest-pinned** rust image + **sha256-pinned** wasm-pack + `--locked` against the vendored `Cargo.lock` — see Task 2), never hand-edited. Docker is required (verified available: 29.1.3).
- **One rebuild.** Tasks 1–3 prepare the inputs; Task 4 performs the single `build.sh` run; Task 5 verifies reproducibility (which builds twice more, into temp dirs, without touching the vendored artifact).
- **Coverage gates (jest.config.js):** global lines ≥ 85, functions ≥ 80, branches ≥ 70; `./src/crypto/` lines ≥ 90, functions ≥ 90, branches ≥ 80.
- **Ciphersuite is fixed** in `patch/lib.rs:29`: `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`. Do not change it — Task 10 fixes the *documentation* to match it.
- **MLS BasicCredential == Nostr pubkey hex.** Identities are created as `new Identity(provider, name)` with `name` = the lowercase hex secp256k1 pubkey (`mls-engine.js`). The binding check compares the member credential bytes, decoded as UTF-8, against that exact string.
- **Run tests from `styx-js/`:** `npm test` (jest). A single file: `npx jest test/path/to/file.test.js`.
- **Commit messages:** Conventional Commits, English, ending with the `Co-Authored-By` trailer.
- **Do not weaken existing Fase A code.** `_verifyEvent`, the nonce/HMAC pairing proof, `joinSession`'s no-overwrite throw, `confirmPairing`, and `safetyNumber` are done and tested — this plan only adds to them.

---

## Status snapshot (already done — do NOT re-implement)

| Fase A item | State | Where |
|---|---|---|
| A1 verify Nostr signatures on receive | **done** | `transport/nostr-chat-transport.js` `_verifyEvent`, before dedup |
| A2 welcome proves QR scan (nonce + HMAC, single-use) | **done** | `chat/styx-chat.js` `createQrInvite`/`_welcomeMac`/`_onWire` |
| A3 no session overwrite | **done** | `_onWire` guard + `MlsEngine.joinSession` throws if `_sessions.has(contactId)` |
| A4 explicit roster add + alias sanitize | **done** | `_pending`/`confirmPairing`/`onPairing`; `sanitizeAlias` |
| A5 safety number + verified flag | **done** | `safetyNumber` via `MlsSession.exportSecret` |
| A6 forbid unauthenticated transport | **done** | `BroadcastChannelTransport` `allowInsecure` |

## Panic-surface audit (grounds Task 3 and Task 7 — verified in-repo)

| Entry point | Line | Attacker-controlled? | Panics? |
|---|---|---|---|
| `Group::process_message` | 314–363 | yes (wire) | **YES** — `tls_deserialize(..).unwrap()` :319; `todo!()` arms :329–333 → **Task 3** |
| `Group::join` | 244–261 | yes (welcome via QR) | No — already `Result<_, JsError>` |
| `KeyPackage::from_bytes` | 455–466 | yes (QR invite) | No — `Result` + `validate()` with `map_err` |
| `RatchetTree::from_bytes` | 482–487 | yes (welcome flow) | No — `Result` with `map_err` |
| `create_new` :240, `key_package` :172, `to_bytes` :450/:477, serialize :494, RwLock :58/:96 | — | no (locally-built material) | acceptable — enumerate in PROVENANCE.md |
| `Provider::restore_state` | 71–98 | local persisted state only | `Result`, but `u64 as usize` length arithmetic can wrap on wasm32 → residual note, out of scope |

**Consequence:** the extended adversarial tests (Task 7) are **pure JS** — no Rust changes are needed beyond Task 3's `process_message` fix.

---

## File Structure

- `vendor/openmls-wasm/build.sh` — **rewrite** (Task 2): pinned rust image digest, sha256-verified wasm-pack, `Cargo.lock` round-trip with `--locked` + drift guard, `OUT_DIR` override. Bump `OPENMLS_COMMIT` (Task 1).
- `vendor/openmls-wasm/verify.sh` — **create** (Task 2): double build → byte-identical `.wasm`, compared against the committed artifact.
- `vendor/openmls-wasm/Cargo.lock` — **create** (Task 4, bootstrapped by the build): the pinned workspace dependency graph.
- `vendor/openmls-wasm/PROVENANCE.md` — **create** (Task 1), completed with hashes in Task 5.
- `vendor/openmls-wasm/patch/lib.rs` — **modify**: errors instead of panics in `process_message` (Task 3); add `Group::member_identities()` (Task 4).
- `vendor/openmls-wasm/{openmls_wasm.js,openmls_wasm_bg.wasm,openmls_wasm.d.ts,openmls_wasm_bg.wasm.d.ts,package.json}` — **regenerated** by `build.sh` (Task 4). Never hand-edited.
- `vendor/openmls-wasm/README.md` — **modify** (Task 10): ciphersuite, commit, toolchain, size, API list.
- `src/crypto/mls/mls-session.js` — **modify** (Task 8): `memberIdentities()`.
- `src/crypto/mls/mls-engine.js` — **modify** (Task 8/9): `peerIdentity(contactId)`, `dropSession(contactId)`.
- `src/chat/styx-chat.js` — **modify** (Task 9): identity binding in `_onWire`'s welcome branch and in `acceptQrInvite`.
- `test/crypto/mls-panic.test.js` — **create** (Task 6).
- `test/crypto/mls-adversarial.test.js` — **create** (Task 7).
- `test/crypto/mls-member-identity.test.js` — **create** (Task 8).
- `test/chat/styx-chat-identity-binding.test.js` — **create** (Task 9).
- `docs/security/2026-07-10-styx-chat-security-report.md` — **modify** (Task 11).

---

## Task 1: Verify and document the OpenMLS pin (R1) — ✅ DONE

> **Premise correction (2026-07-11).** This task originally said "bump the pin to a post-audit
> release", on the assumption that `09e9277` predated the SRLabs fixes. **That assumption was
> false and is now disproven.** No bump is performed. The task is a *verification and
> documentation* task instead. The feasibility document has been corrected accordingly.

**Files:** create `vendor/openmls-wasm/PROVENANCE.md`. `build.sh:8` is **unchanged**.

**Evidence gathered:**

- The pin `09e92777dba0528d3d29e2e5e681b7e91637c7be` (2026-07-08) is a **descendant of tag
  `openmls-v0.8.1`** (2026-02-13): **76 commits ahead, 0 behind** (GitHub compare API).
- **S3-7 (High, CWE-354) is fixed at the pin**, verified in the source, not inferred:
  - `openmls-v0.7.0`, `openmls/src/ciphersuite/mod.rs` → `equal_ct` zips without a length
    check, so a truncated/empty MAC compares equal.
  - At the pin, same file → `if a.len() != b.len() { return false }` precedes the
    constant-time loop.
- Release 0.8.1 (fully contained in the pin) updated `libcrux`/`rust_crypto` for
  GHSA-435g-fcv3-8j26 and GHSA-g433-pq76-6cmf.

**Decision: keep the pin.** Moving to the `openmls-v0.8.1` tag would be a five-month
downgrade (−76 commits) **and** would change the persisted storage format — PR #2034 (present
at the pin, absent in 0.8.1) restores serde storage-tag compatibility with v0.7.1 by default.
Downgrading would break MLS state already written to disk.

**Residual risk, recorded not hidden:** the pin is an **unreleased `main` commit**. Those 76
commits are in no crates.io release and were not the subject of the SRLabs audit. Follow-up:
move the pin to the first upstream tag that descends from this commit, once one exists.

- [x] **Step 1: Establish the pin's position** — `git ls-remote --tags` + GitHub compare API.
- [x] **Step 2: Verify the audit fix at source level** — `equal_ct` length check, pin vs v0.7.0.
- [x] **Step 3: Write `PROVENANCE.md`** with the evidence, the do-not-downgrade rationale, and the residual risks.
- [x] **Step 4: Commit.**

---

## Task 2: Pin the build toolchain and vendor the dependency graph

**Files:** rewrite `vendor/openmls-wasm/build.sh`; create `vendor/openmls-wasm/verify.sh`.

**Interfaces:** produces a build whose every input is pinned (OpenMLS commit, rust image digest, wasm-pack sha256, `Cargo.lock`) and a `verify.sh` that proves the artifact is reproducible. Consumed by Tasks 4 and 5.

**Design rationale:**
- *Docker image:* pin by **manifest-list digest** (`rust:<X.Y.Z>@sha256:<digest>`) — the digest is the real pin (immune to tag re-push); the tag documents intent. Full image, not `slim` (the container script needs `curl`).
- *wasm-pack:* install the **release binary with a verified sha256**, not `cargo install`. `cargo install` recompiles wasm-pack inside every ephemeral container (~5–10 min, ×2 in `verify.sh`) and pins only a version, not a hash.
- *`Cargo.lock`:* openmls is a cargo **workspace**, so the lockfile is at `$WORK/openmls/Cargo.lock`, not inside `openmls-wasm/`. Steady state: copy the vendored lockfile in **before** the build, compile with `-- --locked`, then `cmp` as a drift guard. Bootstrap (no vendored lockfile yet, or right after a commit bump): build unlocked, export the generated lockfile, commit it.

- [ ] **Step 1: Resolve the three pins** (needs network + Docker; if unavailable, **STOP** and surface — do not guess)

```bash
docker run --rm rust:latest rustc --version                 # → X.Y.Z
docker pull rust:<X.Y.Z>
docker image inspect rust:<X.Y.Z> --format '{{index .RepoDigests 0}}'   # → rust@sha256:<digest>
gh api repos/rustwasm/wasm-pack/releases/latest --jq .tag_name          # → v<V>
curl -sSfLO https://github.com/rustwasm/wasm-pack/releases/download/v<V>/wasm-pack-v<V>-x86_64-unknown-linux-musl.tar.gz
sha256sum wasm-pack-v<V>-x86_64-unknown-linux-musl.tar.gz              # → <WASM_PACK_SHA256>
```

- [ ] **Step 2: Rewrite `build.sh`**

```bash
#!/usr/bin/env bash
# Rebuild the vendored OpenMLS-WASM artifact from source, reproducibly, via Docker.
# Every build input is pinned: OpenMLS commit, rust image (digest), wasm-pack (sha256),
# and the full dependency graph (Cargo.lock).
#
# Usage: ./build.sh [OPENMLS_COMMIT]     artifacts land in this directory
#        OUT_DIR=/tmp/x ./build.sh       artifacts land in OUT_DIR (used by verify.sh)
set -euo pipefail

OPENMLS_COMMIT="${1:-09e92777dba0528d3d29e2e5e681b7e91637c7be}"   # unchanged — see PROVENANCE.md
RUST_IMAGE="rust:<X.Y.Z>@sha256:<digest>"
WASM_PACK_VERSION="<V>"
WASM_PACK_SHA256="<WASM_PACK_SHA256>"

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${OUT_DIR:-$HERE}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "Cloning openmls @ $OPENMLS_COMMIT ..."
git clone https://github.com/openmls/openmls.git "$WORK/openmls"
git -C "$WORK/openmls" checkout "$OPENMLS_COMMIT"

# Our patch: Provider.serialize_state/restore_state, Group.load, Identity.public_key/load,
# Group.member_identities, and Results instead of panics on wire input.
echo "Applying Styx patch (patch/lib.rs) ..."
cp "$HERE/patch/lib.rs" "$WORK/openmls/openmls-wasm/src/lib.rs"

# Cargo.lock round-trip: steady state builds --locked against the vendored lockfile;
# the first run after a commit bump bootstraps a fresh one.
LOCKED="no"
if [[ -f "$HERE/Cargo.lock" ]]; then
  cp "$HERE/Cargo.lock" "$WORK/openmls/Cargo.lock"
  LOCKED="yes"
else
  echo "WARNING: no vendored Cargo.lock — bootstrap build, one will be generated." >&2
fi

echo "Building openmls-wasm in $RUST_IMAGE ..."
docker run --rm -v "$WORK:/work" -w /work \
  -e WASM_PACK_VERSION="$WASM_PACK_VERSION" \
  -e WASM_PACK_SHA256="$WASM_PACK_SHA256" \
  -e LOCKED="$LOCKED" \
  "$RUST_IMAGE" bash -c '
    set -euo pipefail
    rustup target add wasm32-unknown-unknown
    curl -sSfLo /tmp/wp.tar.gz "https://github.com/rustwasm/wasm-pack/releases/download/v${WASM_PACK_VERSION}/wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl.tar.gz"
    echo "${WASM_PACK_SHA256}  /tmp/wp.tar.gz" | sha256sum -c -
    tar -xzf /tmp/wp.tar.gz -C /tmp
    install "/tmp/wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl/wasm-pack" /usr/local/bin/wasm-pack
    cd /work/openmls/openmls-wasm
    if [[ "$LOCKED" == "yes" ]]; then
      wasm-pack build --target web -- --locked
    else
      wasm-pack build --target web
    fi
  '

# Drift guard (steady state) / lockfile export (bootstrap). Workspace root, NOT openmls-wasm/.
if [[ "$LOCKED" == "yes" ]]; then
  cmp -s "$HERE/Cargo.lock" "$WORK/openmls/Cargo.lock" || {
    echo "ERROR: Cargo.lock changed despite --locked — pin drift; refusing the artifact." >&2
    exit 1
  }
else
  cp "$WORK/openmls/Cargo.lock" "$HERE/Cargo.lock"
  echo "Bootstrapped Cargo.lock into $HERE — commit it alongside the artifact."
fi

echo "Copying artifact into $OUT_DIR ..."
mkdir -p "$OUT_DIR"
cp "$WORK/openmls/openmls-wasm/pkg/openmls_wasm.js" \
   "$WORK/openmls/openmls-wasm/pkg/openmls_wasm.d.ts" \
   "$WORK/openmls/openmls-wasm/pkg/openmls_wasm_bg.wasm" \
   "$WORK/openmls/openmls-wasm/pkg/openmls_wasm_bg.wasm.d.ts" \
   "$WORK/openmls/openmls-wasm/pkg/package.json" \
   "$OUT_DIR/"

sha256sum "$OUT_DIR/openmls_wasm_bg.wasm" "$OUT_DIR/openmls_wasm.js"
echo "Done. Artifact refreshed in $OUT_DIR"
```

- [ ] **Step 3: Create `verify.sh`** (`chmod +x`)

```bash
#!/usr/bin/env bash
# Reproducibility check: build twice from the pins, require byte-identical artifacts,
# and require that they match the committed vendored artifact.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
[[ -f "$HERE/Cargo.lock" ]] || { echo "ERROR: no Cargo.lock — bootstrap with ./build.sh first." >&2; exit 1; }
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

OUT_DIR="$TMP/a" "$HERE/build.sh"
OUT_DIR="$TMP/b" "$HERE/build.sh"

status=0
for f in openmls_wasm_bg.wasm openmls_wasm.js; do
  if cmp -s "$TMP/a/$f" "$TMP/b/$f"; then
    echo "REPRODUCIBLE: $f $(sha256sum "$TMP/a/$f" | cut -d' ' -f1)"
  else
    echo "NON-REPRODUCIBLE: $f differs between two pinned builds"; status=1
  fi
  if ! cmp -s "$TMP/a/$f" "$HERE/$f"; then
    echo "MISMATCH vs committed artifact: $f (the vendored file was not produced by these pins)"; status=1
  fi
done
exit $status
```

- [ ] **Step 4: Syntax check** (no rebuild here — the rebuild is Task 4)

Run: `bash -n styx-js/vendor/openmls-wasm/build.sh styx-js/vendor/openmls-wasm/verify.sh`
Expected: no output, exit 0.

- [ ] **Step 5: Commit**

```bash
git add styx-js/vendor/openmls-wasm/build.sh styx-js/vendor/openmls-wasm/verify.sh
git commit -m "chore(openmls-wasm): pin build toolchain and add Cargo.lock round-trip + verify.sh"
```

---

## Task 3: Remove remote-triggerable panics in the WASM (N1)

**Files:** modify `vendor/openmls-wasm/patch/lib.rs` (`process_message`, ~lines 314–363).

**Interfaces:** `Group.process_message` returns a JS error instead of trapping the WASM instance on malformed or unexpected-type input. `MlsSession.decrypt` already wraps this in `try/catch`; the point is that **the instance stays usable afterwards**.

- [ ] **Step 1: Read the current `process_message`**

Run: `sed -n '314,363p' styx-js/vendor/openmls-wasm/patch/lib.rs`
Expected: `let msg = MlsMessageIn::tls_deserialize(&mut msg).unwrap();` plus `todo!()` arms for `Welcome(_)`, `GroupInfo(_)`, `KeyPackage(_)` (and a feature-gated `TargetedMessage(_)`).

- [ ] **Step 2: Replace the deserialization `unwrap()` and the `todo!()` arms with errors**

```rust
    pub fn process_message(
        &mut self,
        provider: &mut Provider,
        mut msg: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let msg = MlsMessageIn::tls_deserialize(&mut msg)
            .map_err(|e| JsError::new(&format!("process_message: malformed MLS message: {e:?}")))?;

        let msg = match msg.extract() {
            openmls::framing::MlsMessageBodyIn::PublicMessage(msg) => {
                self.mls_group.process_message(provider.as_ref(), msg)?
            }
            openmls::framing::MlsMessageBodyIn::PrivateMessage(msg) => {
                self.mls_group.process_message(provider.as_ref(), msg)?
            }
            other => {
                return Err(JsError::new(&format!(
                    "process_message: unsupported message body over the wire: {other:?}"
                )));
            }
        };

        // ... unchanged below: match msg.into_content() { ApplicationMessage, ... }
```

The single `other =>` arm replaces every `todo!()` arm at once, so no `todo!()` remains on the input path. Keep the `match msg.into_content() { ... }` block unchanged.

- [ ] **Step 3: Scan for remaining panics on the network path**

Run: `grep -n 'unwrap()\|todo!\|expect(\|panic!' styx-js/vendor/openmls-wasm/patch/lib.rs`
Expected: no `unwrap()`/`todo!()` on the `process_message` path. Remaining `unwrap()`s on internal, non-network data (storage `RwLock`, locally-built KeyPackage material) are acceptable — list them in the commit body; they are not reachable from untrusted input.

- [ ] **Step 4: Commit** (rebuild happens in Task 4)

```bash
git add styx-js/vendor/openmls-wasm/patch/lib.rs
git commit -m "fix(openmls-wasm): return errors instead of panicking on wire input (N1)"
```

---

## Task 4: Add `member_identities()`, rebuild once, vendor the lockfile (N2 part 1)

**Files:** modify `vendor/openmls-wasm/patch/lib.rs`; regenerate the five artifact files; create `vendor/openmls-wasm/Cargo.lock` (bootstrapped by the build).

**Interfaces:**
- Consumes `self.mls_group.members()`, yielding `Member { credential, .. }` whose `BasicCredential` identity bytes are the pubkey hex string.
- Produces `Group.member_identities(): string[]` in the WASM API. Consumed by `MlsSession.memberIdentities()` in Task 8.

- [ ] **Step 1: Add the Rust method inside `#[wasm_bindgen] impl Group`**

```rust
    /// The identity string of every current group member (the BasicCredential
    /// serialized identity, which Styx sets to the member's Nostr pubkey hex).
    /// Lets the app bind an MLS member to a transport identity.
    pub fn member_identities(&self) -> Vec<String> {
        self.mls_group
            .members()
            .map(|m| String::from_utf8_lossy(m.credential.serialized_content()).into_owned())
            .collect()
    }
```

> **Credential API drift:** `Member.credential` is a `Credential`; the accessor for its identity bytes varies across OpenMLS versions. If `serialized_content()` is not the accessor in the pinned version, use the `BasicCredential` conversion (`BasicCredential::try_from(m.credential.clone())` then `.identity()`). Confirm against the pinned crate's `credentials` module — do not guess from memory.

- [ ] **Step 2: Rebuild the WASM artifact (the ONE rebuild)**

Run: `cd styx-js/vendor/openmls-wasm && ./build.sh`
Expected: the pinned image is pulled, openmls is cloned at `<AUDITED_SHA>`, `patch/lib.rs` is applied, wasm-pack's sha256 checks out, `WARNING: no vendored Cargo.lock — bootstrap build` appears, the build succeeds, `Bootstrapped Cargo.lock into ...` appears, the five artifacts are copied back, and two sha256 lines are printed.

> If the build fails on the `member_identities` credential accessor, fix per Step 1's note and re-run. Do not proceed until `build.sh` succeeds.

- [ ] **Step 3: Confirm the new API is in the generated typings**

Run: `grep -n 'member_identities' styx-js/vendor/openmls-wasm/openmls_wasm.d.ts`
Expected: `member_identities(): string[];` inside `export class Group`.

- [ ] **Step 4: Confirm the rebuilt WASM does not break the existing surface**

Run: `cd styx-js && npx jest test/crypto/mls-session.test.js test/chat/`
Expected: PASS. **In particular the reload/persistence test must still pass** — if a test that restores persisted MLS state now fails, this is a `serialize_state` format incompatibility introduced by the version bump, **not** a build problem. Stop and surface it (see Rollback).

- [ ] **Step 5: Commit**

```bash
git add styx-js/vendor/openmls-wasm/patch/lib.rs styx-js/vendor/openmls-wasm/Cargo.lock \
        styx-js/vendor/openmls-wasm/openmls_wasm.js styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm \
        styx-js/vendor/openmls-wasm/openmls_wasm.d.ts styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm.d.ts \
        styx-js/vendor/openmls-wasm/package.json
git commit -m "feat(openmls-wasm): expose Group.member_identities and rebuild against pinned toolchain (N2)"
```

---

## Task 5: Verify the build is reproducible; record the hashes

**Files:** modify `vendor/openmls-wasm/PROVENANCE.md`.

**Interfaces:** produces the evidence for the feasibility doc's "build riproducibile" requirement.

- [ ] **Step 1: Run the double build**

Run: `cd styx-js/vendor/openmls-wasm && ./verify.sh`
Expected: two `REPRODUCIBLE:` lines with identical hashes, no `MISMATCH`, exit 0. This proves three things at once: the double build is byte-identical; the committed artifact was produced by these pins; `-- --locked` and the drift guard work in steady state.

> If it reports `NON-REPRODUCIBLE`: **STOP**. Do not write a hash into PROVENANCE.md. Localize the divergence (`wasm-objdump -h`, `strings`, `cmp -l | head`) and surface it — this is exactly risk §7.3(6) of the feasibility document and is allowed to become a spike. Keep the pinning commits (they still narrow variance) and record the failure mode in PROVENANCE.md instead of the hash.

- [ ] **Step 2: Record the pins and hashes in `PROVENANCE.md`**

```markdown
## Toolchain pins & artifact hashes

- Rust image: rust:<X.Y.Z>@sha256:<digest>
- wasm-pack: v<V> (release binary, sha256 <WASM_PACK_SHA256>)
- Dependency graph: ./Cargo.lock (workspace lockfile; builds run with `-- --locked`)
- openmls_wasm_bg.wasm sha256: <hash>
- openmls_wasm.js sha256: <hash>
- Reproducibility: verified <date> via ./verify.sh (double build byte-identical,
  matches the committed artifact)

### Residual risks (accepted, not fixed here)

- wasm-bindgen-cli is fetched by wasm-pack at the version pinned by the lockfile,
  but the download is not hash-verified.
- binaryen/wasm-opt is pinned by the wasm-pack version, not by hash.
- `Provider::restore_state` does `u64 as usize` length arithmetic that can wrap on
  wasm32; reachable only from locally persisted state, never from the wire.
- `unwrap()`s remain on locally-built material (KeyPackage builder, storage RwLock,
  to_bytes/serialize) — not reachable from untrusted input.
```

Also fix the Task 1 template's `Rebuild:` line so it names the pinned image, not `rust:latest`.

- [ ] **Step 3: Commit**

```bash
git add styx-js/vendor/openmls-wasm/PROVENANCE.md
git commit -m "chore(openmls-wasm): verify reproducible build; record artifact sha256 and toolchain pins"
```

---

## Task 6: Prove the WASM no longer poisons itself on malformed ciphertext (N1 test)

**Files:** create `styx-js/test/crypto/mls-panic.test.js`.

Follow the wasm-loading pattern already used by `test/crypto/mls-session.test.js` (`readFileSync(wasmPath)` + `await MlsEngine.initWasm({ wasmBytes })` in `beforeAll`).

- [ ] **Step 1: Write the test**

```javascript
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import { utf8Encode, utf8Decode } from '../../src/utils.js';

/** Two engines already joined into one 1:1 group (a = inviter, b = joiner). */
async function pairedSessions() {
  const a = await MlsEngine.create({ name: 'a'.repeat(64) });
  const b = await MlsEngine.create({ name: 'b'.repeat(64) });
  const { welcome, ratchetTree } = a.startSession('b', b.keyPackageBytes());
  b.joinSession('a', welcome, ratchetTree);
  return { a, b };
}

test('malformed ciphertext does not brick the engine for other messages', async () => {
  const { a, b } = await pairedSessions();

  // Garbage down the decrypt path must throw, not trap the WASM instance.
  expect(() => b.session('a').decrypt(new Uint8Array([1, 2, 3, 4, 5]))).toThrow();

  // The instance must still work afterwards: a real message round-trips.
  const ct = a.session('b').encrypt(utf8Encode('still alive'));
  const out = b.session('a').decrypt(ct);
  expect(out.kind).toBe('application');
  expect(utf8Decode(out.plaintext)).toBe('still alive');
});
```

- [ ] **Step 2: Run it**

Run: `cd styx-js && npx jest test/crypto/mls-panic.test.js`
Expected: PASS against the rebuilt WASM (against the *old* artifact it would have errored — the instance was poisoned).

- [ ] **Step 3: Commit**

```bash
git add styx-js/test/crypto/mls-panic.test.js
git commit -m "test(mls): malformed ciphertext throws without poisoning the engine (N1)"
```

---

## Task 7: Adversarial tests for every untrusted parser + fuzz-lite

**Files:** create `styx-js/test/crypto/mls-adversarial.test.js`. **No Rust changes** — see the panic-surface audit: `join`, `KeyPackage::from_bytes` and `RatchetTree::from_bytes` already return `Result`.

**Interfaces:** produces the evidence for the P0 criterion *"nessun panic noto raggiungibile da input non fidato; parser coperti da test negativi, fuzzing e gestione esplicita degli errori"*.

- [ ] **Step 1: Write the tests**

Every corruption case must be followed by proof the engine is still alive (a pristine join and/or a real message round-trip). Cases:

```javascript
test('garbage welcome bytes: joinSession throws, a pristine join still works afterwards')
test('truncated welcome: joinSession throws a catchable error')            // welcome.slice(0, welcome.length >> 1)
test('bit-flipped welcome: joinSession fails cleanly')                     // copy, xor one mid-buffer byte with 0xff
test('garbage ratchet tree: joinSession throws')                           // valid welcome + Uint8Array([9,9,9])
test('truncated ratchet tree: joinSession throws, engine stays usable')    // ratchetTree.slice(0, 10)
test('garbage KeyPackage: startSession throws, no phantom session, retry succeeds')
  // expect(() => a.startSession('c', new Uint8Array([1,2,3]))).toThrow();
  // expect(a.session('c')).toBeUndefined();          // the group is built before the KP parse
  // then a.startSession('c', c.keyPackageBytes()) must succeed  (mls-engine.js:124-125)
test('fuzz-lite: 100 seeded random buffers through joinSession/startSession never trap')
  // mulberry32(42) → deterministic buffers, length 0..512.
  // Every call must throw; assert the error is NOT a trap:
  //   expect(e).not.toBeInstanceOf(WebAssembly.RuntimeError)
  // After the loop, a real pairing + message round-trip must still succeed.
```

- [ ] **Step 2: Run them**

Run: `cd styx-js && npx jest test/crypto/mls-adversarial.test.js`
Expected: PASS.

> **Contingency:** if any case traps (a panic *inside* openmls, past the `Result` boundary — e.g. tree validation in `StagedWelcome::new_from_welcome`), **STOP**: that is a genuine upstream finding. Record the reproducer, surface it, and evaluate pre-validating the input in `patch/lib.rs` before the openmls call. **Do not** delete the test to make the suite green.

- [ ] **Step 3: Commit**

```bash
git add styx-js/test/crypto/mls-adversarial.test.js
git commit -m "test(mls): adversarial welcome/ratchet-tree/KeyPackage inputs throw without poisoning the engine"
```

---

## Task 8: Surface member identities through MlsSession and MlsEngine (N2 part 2)

**Files:** modify `src/crypto/mls/mls-session.js`, `src/crypto/mls/mls-engine.js`; create `test/crypto/mls-member-identity.test.js`.

**Interfaces:**
- `MlsSession.memberIdentities(): string[]` — every member credential string.
- `MlsEngine.peerIdentity(contactId): string | null` — the one member identity that is not ours, or `null` if the session is unknown or the membership is not exactly `{us, one peer}`.

- [ ] **Step 1: Write the failing test**

```javascript
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';

const A = 'a'.repeat(64);
const B = 'b'.repeat(64);

async function paired() {
  const a = await MlsEngine.create({ name: A });
  const b = await MlsEngine.create({ name: B });
  const { welcome, ratchetTree } = a.startSession('b', b.keyPackageBytes());
  b.joinSession('a', welcome, ratchetTree);
  return { a, b };
}

test('memberIdentities lists both members by their credential (pubkey hex)', async () => {
  const { a } = await paired();
  expect(a.session('b').memberIdentities().sort()).toEqual([A, B].sort());
});

test('peerIdentity returns the other member, not ourselves', async () => {
  const { a, b } = await paired();
  expect(a.peerIdentity('b')).toBe(B);
  expect(b.peerIdentity('a')).toBe(A);
});

test('peerIdentity is null for an unknown contact', async () => {
  const { a } = await paired();
  expect(a.peerIdentity('nope')).toBeNull();
});
```

Run it: `cd styx-js && npx jest test/crypto/mls-member-identity.test.js` → FAIL (methods undefined).

- [ ] **Step 2: Add `memberIdentities()` to `MlsSession`**

```javascript
  /**
   * The identity string of every current group member (the MLS credential,
   * which Styx sets to the member's Nostr pubkey hex).
   * @returns {string[]}
   */
  memberIdentities() {
    return this._group.member_identities();
  }
```

- [ ] **Step 3: Add `peerIdentity()` to `MlsEngine`**

The engine must remember its own credential name (the pubkey hex passed to `MlsEngine.create({ name })`). If it is not already retained, store it in the constructor as `this._name`. Do **not** derive it from `identityPublicKey()` — that is the MLS signature key, not the credential string.

```javascript
  /**
   * The single member of `contactId`'s session that is not us, matched by MLS
   * credential (== pubkey hex). Null if the session is unknown or the membership
   * is not exactly {us, one peer}.
   * @param {string} contactId
   * @returns {string|null}
   */
  peerIdentity(contactId) {
    const session = this._sessions.get(contactId);
    if (!session) return null;
    const others = session.memberIdentities().filter((id) => id !== this._name);
    return others.length === 1 ? others[0] : null;
  }
```

- [ ] **Step 4: Run the test** → PASS.

- [ ] **Step 5: Commit**

```bash
git add styx-js/src/crypto/mls/mls-session.js styx-js/src/crypto/mls/mls-engine.js styx-js/test/crypto/mls-member-identity.test.js
git commit -m "feat(mls): expose peerIdentity for transport-identity binding (N2)"
```

---

## Task 9: Bind the MLS peer credential to the transport pubkey at join (N2 part 3)

**Files:** modify `src/chat/styx-chat.js` (`_onWire` welcome branch, `acceptQrInvite`), `src/crypto/mls/mls-engine.js` (`dropSession`); create `test/chat/styx-chat-identity-binding.test.js`.

**Interfaces:** produces the invariant `engine.peerIdentity(from) === from` for every retained session. On mismatch the session is discarded and no pending pairing is created.

- [ ] **Step 1: Write the failing test**

Follow the DI construction used by `test/chat/styx-chat-no-overwrite.test.js` (copy its in-memory transport/backend pattern rather than inventing a helper). Two cases, both with concrete bodies — **do not commit `// Arrange…` placeholders**:

1. *A welcome whose MLS peer credential ≠ the sender pubkey is rejected*: craft the joining side so the group carries a credential for pubkey X while the welcome is delivered claiming `from = Y` (X ≠ Y). Assert: no pending pairing for Y, no session for Y.
2. *A genuine welcome (credential == sender pubkey) is accepted and offered*: the normal path → `onPairing` fires.

Run it → FAIL (the mismatched welcome is currently accepted).

- [ ] **Step 2: Add `dropSession()` to `MlsEngine`**

```javascript
  /** Forget a session (used to roll back a join that failed identity binding). */
  dropSession(contactId) {
    this._sessions.delete(contactId);
  }
```

- [ ] **Step 3: Add the binding check to `_onWire`'s welcome branch**

Immediately after `this._engine.joinSession(from, welcomeBytes, treeBytes);`, before persisting or emitting:

```javascript
      // Bind the MLS credential to the transport identity: the group we just joined
      // must have `from` as its peer, or we are being spliced into a group built for
      // someone else. On mismatch, discard the session.
      if (this._engine.peerIdentity(from) !== from) {
        this._engine.dropSession(from);
        return;
      }
```

- [ ] **Step 4: Add the same check to `acceptQrInvite`**

After `startSession`, assert the resulting group binds `inv.pubkey`:

```javascript
    if (this._engine.peerIdentity(inv.pubkey) !== inv.pubkey) {
      this._engine.dropSession(inv.pubkey);
      throw new Error('acceptQrInvite: KeyPackage credential does not match invite pubkey');
    }
```

- [ ] **Step 5: Run the new test** → PASS.

- [ ] **Step 6: Run the full suite**

Run: `cd styx-js && npm test`
Expected: PASS — every pre-existing test (`styx-chat-no-overwrite`, `styx-chat-invite-nonce`, `styx-chat-safety-number`, `styx-chat-explicit-pairing`, …) plus the four new files, with the coverage gates met.

- [ ] **Step 7: Commit**

```bash
git add styx-js/src/chat/styx-chat.js styx-js/src/crypto/mls/mls-engine.js styx-js/test/chat/styx-chat-identity-binding.test.js
git commit -m "feat(chat): bind MLS peer credential to transport pubkey at join (N2)"
```

---

## Task 10: Reconcile the vendor README with reality

**Files:** modify `vendor/openmls-wasm/README.md` (documentation only).

The README currently makes three false claims. Fix all three plus the API list:

- [ ] **Step 1: Fix the claims**
  - line 11 — commit: keep `09e92777…`, but add its date (2026-07-08) and its position (76 commits after tag `openmls-v0.8.1`); point to `PROVENANCE.md` for the audit status.
  - line 13 — ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` → **`MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`** (what `patch/lib.rs:29` actually compiles). Drop the "(MTI di OpenMLS)" note.
  - line 14 — toolchain: `rust:latest` → the pinned `rust:<X.Y.Z>@sha256:…` + `wasm-pack v<V>` + "`Cargo.lock` vendorizzato, build `--locked`". Point to `PROVENANCE.md` and `verify.sh`.
  - line 15 — re-measure the artifact size: `ls -l openmls_wasm_bg.wasm`; `gzip -c openmls_wasm_bg.wasm | wc -c`.
  - API paragraph (~lines 28–31) — add `Group.member_identities()`.

- [ ] **Step 2: Commit**

```bash
git add styx-js/vendor/openmls-wasm/README.md
git commit -m "docs(openmls-wasm): fix ciphersuite claim and record pinned toolchain in README"
```

---

## Task 11: Update the security report

**Files:** modify `docs/security/2026-07-10-styx-chat-security-report.md`.

- [ ] **Step 1: Annotate the closed items**

Mark A1–A6, M1, M2, M3 as **implemented** (JS layer, already committed) and R1, N1, N2 as **implemented** (this plan). Add a short "Stato di attuazione — Blocco 1" note mapping the feasibility document's seven Blocco 1 requirements (§5) to the tasks that closed them:

| Requisito (§5) | Chiuso da |
|---|---|
| 1. eliminazione panic da input | Task 3 + test Task 6/7 |
| 2. aggiornamento OpenMLS | Task 1 |
| 3. pin toolchain | Task 2 |
| 4. `Cargo.lock` | Task 2 + Task 4 |
| 5. build riproducibile | Task 2 + Task 5 |
| 6. correzione doc ciphersuite | Task 10 |
| 7. test con input malevoli | Task 6 + Task 7 |

Leave N3/N4, R2 (FS/PCS), and Fasi B/C/D **open**. Point to this plan file. Keep the edit small — a status note, not a rewrite of the analysis.

- [ ] **Step 2: Commit**

```bash
git add docs/security/2026-07-10-styx-chat-security-report.md
git commit -m "docs(security): mark Fase A and Blocco 1 (R1/N1/N2) as implemented"
```

---

## Acceptance criteria — Blocco 1 (feasibility doc §7.5, P0/WASM)

1. `PROVENANCE.md` documents the pin's position (descendant of `openmls-v0.8.1`, 76 ahead / 0 behind), the source-level verification of the S3-7 fix (`equal_ct` length check), the do-not-downgrade rationale (PR #2034 storage format), and the unreleased-`main` residual risk.
2. `grep -n 'unwrap()\|todo!\|expect(\|panic!' patch/lib.rs` shows no hits on the `process_message` / `join` / `from_bytes` paths; the remaining ones (local material) are enumerated in `PROVENANCE.md`.
3. `test/crypto/mls-panic.test.js` + `test/crypto/mls-adversarial.test.js` are green: all four untrusted parsers covered plus the seeded fuzz loop; every failure is a catchable `Error`, never a `WebAssembly.RuntimeError`; the engine round-trips a real message afterwards.
4. `vendor/openmls-wasm/Cargo.lock` is committed; `build.sh` fails on lockfile drift; `verify.sh` exits 0.
5. Image digest + wasm-pack sha256 are hardcoded in `build.sh`; the double build is byte-identical and matches the committed artifact; both hashes are in `PROVENANCE.md`.
6. The README's ciphersuite, commit and toolchain match `patch/lib.rs:29` and `build.sh`.
7. `cd styx-js && npm test` is green with the coverage gates (global lines ≥ 85; `./src/crypto/` ≥ 90).

## Rollback

Every task is a separate conventional commit.

- The artifact-bearing commit (Task 4) contains **only** regenerated files + `Cargo.lock`, so `git revert <task4-sha>` restores the previous known-good `.wasm` **byte for byte, with no rebuild** — this is the core rollback property of vendoring the artifact.
- If the OpenMLS bump breaks the JS surface or the persisted-state format (`Provider::serialize_state` blobs written by the old crate may fail `restore_state`/`Group.load` — **unverifiable before the rebuild**; the reload/persistence test in `test/chat/` is the detector): revert Tasks 1 + 4 together, keep Task 2 (the toolchain pinning is version-agnostic), and regenerate `Cargo.lock` with one bootstrap build against the old commit.
- If reproducibility (Task 5) fails: keep the pinning commits, do **not** publish a hash claim, record the failure mode in `PROVENANCE.md`, and open the §7.3(6) spike.
- Tests (Tasks 6, 7) and docs (Tasks 10, 11) are additive and revert independently.

## Open questions the executor must resolve (do not guess)

1. ~~Post-audit OpenMLS tag/SHA~~ — **resolved in Task 1:** the pin already carries the fixes; no bump. See `PROVENANCE.md`.
2. **Current stable Rust version + image digest; latest wasm-pack version + tarball sha256** — need network/Docker (Task 2 Step 1 gates on them).
3. **`wasm-pack build --target web -- --locked` forwarding** — documented wasm-pack behaviour (args after `--` go to `cargo build`) but not provable from this repo. Failure is loud and immediate in Task 4; the post-build `cmp` drift guard also covers the case where wasm-pack's internal `cargo metadata` rewrites the lockfile before the locked build runs.
4. **Whether openmls at the new pin ships its own workspace `Cargo.lock`** — if it does, the bootstrap simply inherits it; the flow is unchanged.
5. **`serialize_state` blob compatibility across the version bump** — see Rollback.
6. **Whether openmls internals can panic on TLS-valid but semantically hostile ratchet trees** — statically unverifiable; Task 7 is the detector, with a stop-and-surface contingency.

## Self-review notes for the implementer

- **The JS Fase A is done.** If a step seems to ask you to add something that already exists (e.g. a no-overwrite guard), STOP — you are reading stale intent; verify against the file and skip.
- **The hard dependency is the single rebuild (Task 4).** Tasks 6–9 cannot pass without `Group.member_identities` in the rebuilt artifact, and Tasks 1–3 must land before it so the rebuild picks up all three input changes at once.
- **Credential API drift is the most likely build failure** (Task 4 Step 1's note). Confirm against the pinned crate, not from memory.
- **No new secrets, no new storage.** This plan adds no key material and no persisted fields.
- After Task 11, **stop**: the feasibility document (§6) requires an architectural review at the end of each block before starting the next one.
