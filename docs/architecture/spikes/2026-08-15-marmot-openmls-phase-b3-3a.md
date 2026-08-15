# Phase B3.3a: exact-profile durable application traffic

Date: 2026-08-16

Issue: #185

Stage: **Stage 2 approved tuple installed; final paired execution pending**

Disposition: **Stage 1 reached bounded GO and the owner approved the exact
source/tree/patch/lock/tuple; no final Stage 2 conclusion yet**

## Question and scope

B3.3a asks whether the exact B3.2a Styx member and the pinned MDK founder can
exchange synthetic MLS application events in both directions while preserving
write-ahead ratchet durability across a real process restart. It deliberately
excludes every Commit and epoch-transition operation reserved for B3.3b.

The candidate is isolated from product code. It does not change the PWA,
vault, transport, Nostr, push, media, dependencies, ciphersuite, frozen member
profiles or historical persisted formats.

## Frozen inputs

| Boundary | Exact value |
| --- | --- |
| Styx base commit | `1404d05ed2604195e3b697caeccad9133a6cdc34` |
| Styx base tree | `7d0ee0078385f3f7a85e1f8f23e11adc347cddf8` |
| OpenMLS source commit / tree | `09e92777dba0528d3d29e2e5e681b7e91637c7be` / `fde242458abe5594fbebf2556dca0a135367a817` |
| Marmot commit / tree | `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1` / `10d941f358de5d9fe4ee1db75581f3e5363f5e92` |
| MDK commit / tree | `9396adb6aa6b95b521a7979facd5ea7040c07288` / `a1145de604e616634dae9a1ef6bf5033c9c9e879` |
| Vendored Cargo lock SHA-256 | `33964e33f6a48e8b9982c5894c4a7e9ddc5ee2e5157c763596393a08c607672b` |
| External MDK Cargo lock SHA-256 | `edb8c706e12934b8d94239203f73d24a2d480033c3ec6830f19d06c85a247b09` |
| Ciphersuite | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (`0x0001`) |

The installed Stage 2 tuple is exactly:

| File | SHA-256 |
| --- | --- |
| `openmls_wasm.js` | `044a7cce67730ea45964f1bfc3e54ee79f3ff6ee277029efb87d9abd57a9aa6f` |
| `openmls_wasm.d.ts` | `c64a515a55591d8c84bfe0386b2db984d83e39f3ace7a14553d2cd7f11dc8048` |
| `openmls_wasm_bg.wasm` | `7087b53f8f0597f0107802d5b629cd211d138d4f916b2ddd5831862088551624` |
| `openmls_wasm_bg.wasm.d.ts` | `eb26390ba4b96299df0105ed72c1bf2a292217a8635f816488a64d65b7deb6dc` |
| `package.json` | `88f2ec1e2a5c1904b0fc1d147221c32ba6dcbf1cb4441c53b04a1b2a03bd1d85` |

## Candidate architecture

The Rust boundary consumes the loaded group and private Provider at operation
start. It validates the exact ciphersuite, active state, two-member roster,
GroupContext, member profile and local identity binding before and after each
operation. Only private application messages at the current group id and epoch
can reach plaintext extraction. Authenticated sender identity and signature key
are projected from the processed message and exact roster.

The JavaScript adapter treats the resulting bytes as uncommitted until its
authoritative journal CAS succeeds. The outbound CAS covers the post-send state
and ciphertext record; the inbound CAS additionally covers plaintext and
authenticated sender evidence. Both paths read the committed bytes back before
returning a copy to the orchestrator. All local scratch copies are cleared on
success and failure.

The artifact loader binds each fresh Styx process to the tuple measured by the
orchestrator. It opens candidate files with `O_NOFOLLOW`, validates the regular
file inode before and after the descriptor-bound read, checks the exact SHA-256
digest, and imports the generated JavaScript from those verified bytes. It does
not execute a path after a separate check, so a path replacement cannot change
the code or WASM bytes exercised by the recorded tuple.

The file journal uses immutable content-addressed blobs, an exclusive
fail-closed lock, atomic head replacement and directory synchronization. A
stale lock is never broken automatically. This is isolated evidence, not a
claim of product-grade crash recovery or physical erasure.

## Closed Stage 1 evidence

- Native wrapper tests cover durable bidirectional traffic and restart,
  malformed input, wrong group and epoch, replay, own echo, public proposal and
  Commit rejection, wrong identity locators, profile hybrids/supersets, a third
  member, canonical serialization stability and one-use releases.
- JavaScript tests cover one-time activation, write-ahead ordering, memory and
  file restart, duplicate request/ciphertext, inbound/outbound persistence
  failure, CAS races, non-release, inner-event sender/id validation and strict
  cross-format readers.
- The pinned MDK adapter uses only its public send, ingest, durable-store and
  event-drain APIs. A mutation-boundary failure quarantines the process.
- One development execution completed 24 hash-linked operations, committed two
  events in each direction, restarted both peers in fresh processes, rejected
  both first-message replays without a second plaintext/event, continued in
  both directions and deleted private state.

The reviewed Stage 1 source commit is
`2d37bbc66828dbd30c1f5058989441e276704502`, tree
`ca7ea7fb3a6f4c3f22c058c7c1bc689ba577bf12`; the Rust patch digest is
`3647f49d787285bc5f810cc4529245b7a978f1d111cc5fc0f00c0e9b9e65b745`.
Two locked builds produced the byte-identical five-file tuple above. Fable 5
and DeepSeek V4 Flash independently reviewed the exact candidate, their
findings were incorporated, and the owner approved the binding before
installation.

## Stage 2 execution boundary

`verify-pins.mjs` now hard-codes the approved tuple and fails unless both the
installed runtime and any supplied candidate directory match all five digests.
For each final run, the orchestrator builds the pinned MDK peer with
`cargo build --locked` in a different new target directory. The public
`verify_exact_inputs` and `build_locked_mdk_peer` transcript entries record the
clean MDK source revision/tree/lock, the local peer lock, Cargo version and the
descriptor-bound SHA-256 of the exact executable used by both fresh MDK
processes in that run.

## Remaining gates

1. Commit the approved tuple and Stage 2 verifier/build-evidence boundary.
2. Run the complete locked native, vendored, JavaScript and chat-build matrix.
3. Execute and validate two fresh disjoint Stage 2 interop runs, each with its
   own locked MDK target directory and executable identity.
4. Obtain independent exact-HEAD agent review, then human security and final
   owner gates. The pull request remains Draft until all gates are green.

## Residual risks and non-claims

- The Styx-authored Rust/JavaScript boundary remains unaudited.
- `extensions-draft` remains a pinned experimental upstream surface.
- Application traffic does not establish Commit lifecycle or convergence.
- Direct synthetic transport establishes no Nostr, anonymity or metadata
  privacy property.
- File-backed evidence is not the browser vault or a production persistence
  profile.
- Transient clearing is best effort: the operation-scoped Provider is wiped on
  drop, but wasm-bindgen copies returned across the boundary cannot be proven
  physically zeroized after the JavaScript copy is made.
- Non-roster senders are rejected by OpenMLS membership authentication and then
  rebound to the exact roster in both WASM and JavaScript; the candidate has
  layered hostile coverage rather than a separately constructible valid-group
  native fixture for an authenticated non-member.
- No real user data, security certification, general Marmot compatibility,
  legal-evidence or production-suitability claim is made.
