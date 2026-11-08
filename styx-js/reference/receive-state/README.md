# Reference receive-state adapter (experimental, Node)

This directory is the experimental Node reference implementation of the caller side of the M3 durable
receive path: the receive-state port (`ports.receiveState`, C-SDK §8.5) and a session port with the receive
methods `openCandidate` and `isKnownSender` (C-SDK §8.2), over the unchanged `MlsEngine` and the immutable
vendored OpenMLS WASM. It is the mitigation that C-SDK §8.2 names for caller semantics the SDK cannot verify.
It is **not** imported by the SDK lane, is not a product storage layer and makes no claim beyond what this
file and the tests under `styx-js/test/sdk-receive/` show.

```js
import { createReferenceReceiver } from './index.js';

const receiver = createReferenceReceiver({
  directory,          // archive directory owned by this one identity
  atRestKey,          // exactly 32 random bytes, kept apart from the archive
  identity,           // own public key, 64 lowercase hex (also the MLS credential)
  mode: 'create',     // 'create' the first time (fails if an archive exists), then 'open'
});
// ports: { storage, identity, session: receiver.session, receiveState: receiver.receiveState }
```

One receiver instance serves one client at a time; a second writer on the same directory is unsupported
(there is no inter-process lock). After `shutdown()`, a new client may reuse the instance: its `start()`
calls `load`, which reads the archive again.

## Behaviour

- **One exclusive coordinator per provider.** A provider lock serialises everything that reads or mutates MLS
  state (`openCandidate`, `commit`, `seal`, `createKeyPackage`, `startSession`, `joinSession`, `load`); a file
  lock serialises every snapshot rewrite and `resolve`. The provider lock is always taken first. A slow
  candidate never delays a plain receive-state write.
- **Candidate copy.** `openCandidate` opens the ciphertext on a copy of the authoritative engine restored from
  its serialized state; the authoritative engine and the archive never change in `openCandidate`. Only the
  latest candidate can be committed, its ticket once. `commit` makes the copy's MLS state, the entry's new
  state, the receipt obligation, the seen mark and any binding completion durable in one atomic rewrite, then
  re-applies the same open to the authoritative engine and compares the two provider states as sets of
  entries; if they differ, the committed state replaces the authoritative engine. If a provider mutation
  happened after the candidate was made, `commit` opens the message again on the current state first, so the
  mutation is never lost (C-SDK §8.2 rollback rule).
- **Classification.** `reject` only for: a ciphertext that is not an MLS application `PrivateMessage` or whose
  header `group_id` is not strict canonical UTF-8; a header group other than the bound group of an
  established binding; for an invitee binding, a header group that the provider does not hold, or whose
  exporter value is computed and differs from the stored one; and an application message that yields no
  peer plaintext; and a well-formed group id longer than the 255 bytes this adapter stores when the binding is
  established (the bound id is at most 255 bytes, so a longer one names a different group). Every other
  failure — an unknown sender, any engine exception, a `MlsBindingError`, a fault, timeout or malformed result
  in the verification, and a well-formed group id longer than 255 bytes for an invitee binding not yet
  completed (a bound of this adapter, not a property of the message) — is `retry`.
- **Checkpoints.** `seal`, `createKeyPackage`, `startSession` and `joinSession` make the provider state
  durable before returning. `startSession` checks the KeyPackage on a throwaway engine first and
  `joinSession` checks the Welcome on a copy first, so a refused peer leaves no group in the authoritative
  provider. An existing binding for the peer refuses both.
- **Peer bindings (D7, C-SDK §8.2 and the M3-RECEIVE contract §12).** The inviter's binding records the group
  id `startSession` returns. The invitee's binding records no group id and a 32-byte value
  `exportSecret('styx/m3-receive/invitee-binding/v1', UTF-8(peer), 32)` computed right after
  `joinSession`. The group id is learned from the cleartext header of the first message from that peer and
  accepted only if `Group.load` finds that group in the provider and its `export_key` under the same label
  and context equals the stored value (constant-time comparison); it is written with that message's commit.
  The 1:1 epoch does not change after setup, so the value is stable on that path only.
- **Fail-stop.** A rewrite that fails before the rename leaves the archive unchanged and returns
  `E_SDK_RECEIVE_STATE_FAILED`. Any failure from the rename on (the rename, the directory fsync or a fault
  after it) makes the outcome unknown: the call throws (an uncertain result for the SDK) and every later call
  fails until a new `load`. The same holds for a commit that is durable but whose state cannot be installed in
  the authoritative engine.
- **`resolve`** is read-only and repeatable and waits for a commit still being installed. It answers
  `committed` for the last durable message commit, from a resolution record in the snapshot that holds the
  exact closed result (payload included) and survives `ack`, `receiptDone` and `commitCursor`; the record
  is retained until the next `load`, and the first write after that load drops it. Any other operation id is
  answered `aborted` and from then on can no longer take effect in this process (the refused ids are kept
  for the whole run).

## Archive format (owner technical gate G1, G2)

One authoritative file `receive-state.snapshot` in the archive directory; no journal, no older copies.

- **Atomic rewrite.** Every change writes the whole encrypted snapshot to a fresh temporary file in the same
  directory (exclusive create, mode 0600, no symbolic link followed), fsyncs and closes it, renames it over the
  authoritative name and fsyncs the directory; only then does the call return. A new archive also makes the
  directory entry durable first. Temporary files are never read as state; they are removed when the archive
  is opened. An unreadable, unauthentic or inconsistent snapshot is `E_SDK_RECEIVE_STATE_INCOMPATIBLE`; there
  is no reset and no fallback.
- **Encryption at rest.** `atRestKey` is mandatory (exactly 32 bytes; there is no plaintext mode). For each
  rewrite a fresh random 32-byte salt and 12-byte nonce are drawn; the subkey is
  HKDF-SHA256(`atRestKey`, salt, `styx/m3-receive/reference-snapshot-key/v1`, 32) and the body is encrypted
  with AES-256-GCM and a 128-bit tag. Because each subkey encrypts exactly one body, nonce reuse under a key
  needs a salt collision (probability about n²/2²⁵⁷ after n rewrites). The additional data is
  `lp(label) ‖ lp(header) ‖ lp(identity) ‖ lp(scope)` with 32-bit big-endian length prefixes; the header is
  `"STYXRCV1" ‖ version (u16) ‖ salt ‖ nonce ‖ body length (u64)`. The tag is verified before the body is
  parsed. A wrong key and a modified byte are indistinguishable (both INCOMPATIBLE).
- **Body.** A canonical binary encoding with a version, every length checked against the remaining bytes and
  its own bound before any allocation, strict canonical UTF-8, and no trailing bytes: identity, scope,
  revision, the MLS identity key and serialized provider state, the peer bindings, the cursors, the seen ids,
  the `PENDING` entries in stage order, the `READY` entries in commit order, the acknowledged ids, the receipt
  obligations and the last message commit (for `resolve`).
- **`storedBytes`** is a fixed formula, not the file size: the MLS state length, 65 + ciphertext length per
  `PENDING` entry, 65 + payload length per `READY` entry, 32 per seen and per acknowledged id, 64 per receipt
  obligation, relay length + 8 per cursor, 96 + group id length per binding, and 65 + payload length for
  the resolution record of the last application commit while it is kept. The adapter refuses a stage
  over its own `maxStoredBytes` (default 512 MiB) with `E_SDK_RECEIVE_STATE_FAILED` and a commit over it with
  `E_SDK_RECEIVE_STATE_CAPACITY`; set it above the SDK's `receive.maxStoredBytes` plus one inbound event and
  one MLS checkpoint, so that the SDK's own quota stops admission first. The file read at `load` is bounded by
  twice that value plus 1 MiB. At most 256 cursors are kept; the least recently committed is dropped beyond
  that (a missing cursor only means a full catch-up).

## Cost

Every write rewrites and fsyncs the whole state, so its cost grows with the state. Measured on the test host
(AES-256-GCM, write, fsync, rename and directory fsync; medians of five): 1 MiB about 4 ms, 16 MiB about
62 ms, 64 MiB about 215 ms, 256 MiB about 770 ms. A candidate copy restores the whole provider: about 5 ms for
500 two-member groups (5.5 MB of MLS state). With the SDK defaults (256 MiB, 6 000 ms port-call timeout) a
write stays well inside the timeout, but sustained reception slows as the unacknowledged state grows.

## Limits (declared)

- **No rollback protection.** Replacing the archive with an older copy of itself (backup restore, file-system
  snapshot, tampering) is not detected: acknowledged payloads may reappear, and `seen`, the cursors and the MLS
  checkpoint may regress (reopening a regressed MLS state may fail or reuse key material).
- **No secure erase.** An acknowledged payload leaves the active state and every later `load`; older bytes may
  remain on the medium. The payload of the last committed application message also stays, encrypted, in the
  snapshot's resolution record after its `ack`, until the next message commit or the first write after the
  next `load`. Plaintext buffers are zeroed on a best-effort basis only: JavaScript gives no erasure
  guarantee.
- **No key rotation** in this release.
- **Invitee binding.** An invitee whose process restarts before the first message from the inviter cannot seal
  to that peer until that message completes the binding. If the authoritative engine ever has to be replaced
  by the committed state (provider states differ after re-applying an open), invitee sessions joined in that
  run and not yet completed are lost from memory in the same way. Group ids that are not valid UTF-8 cannot be
  completed.
- **Single writer, single process, Node only.** No multi-device or multi-process state.
- **Memory.** Copies of the provider are released by the WASM finaliser when garbage-collected, not
  explicitly.
