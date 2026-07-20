# Storage operational limits — localStorage vs the 16 MiB parser cap

Scope: persistence of the MLS chat state (`mls:state` envelope v1) on the
current `LocalStorageBackend`. This is the operational-limit record requested
at the Fase D gate of PR #23 (Story US-004, Issue #27). Normative behaviour
(format, migration, fail-closed policy) lives in
[`docs/architecture/mls-state-migration-policy.md`](../../docs/architecture/mls-state-migration-policy.md);
this page only states the operational limits and keeps them tied to the code.

## 1. `MAX_PAYLOAD_BYTES` is a defensive parser cap, not backend capacity

`MAX_PAYLOAD_BYTES = 16 * 1024 * 1024` (16 MiB of **decoded** payload,
[`src/storage/mls-state-envelope.js:26`](../src/storage/mls-state-envelope.js))
is the defensive upper bound of the envelope codec: it exists to keep a
hostile or corrupted `mls:state` value from materializing an arbitrarily
large payload, not to promise that the current backend can store anything
near that size. It is enforced on encode
(`encodeMlsStateEnvelope`, size check before building the envelope) and on
parse (`parseMlsStateEnvelope`, a size gate on the base64 string **before**
decoding, then again on the decoded bytes), and pinned by a test
(`test/storage/mls-state-envelope.test.js:155`). Real two-peer MLS state is
orders of magnitude smaller.

## 2. Base64 and JSON overhead: 16 MiB binary becomes >21 MiB stored

The envelope stores the payload as base64 inside a JSON object, and the
backend serializes the whole value to JSON again. 16 MiB of binary state
expand to about 21.3 MiB of base64 (4/3 ratio) plus the envelope's metadata
and JSON quoting — well beyond what localStorage typically accepts for a
single origin. A payload at the cap therefore cannot be persisted by the
current backend even in the most generous browsers.

In addition, the current base64 encoder (`bytesToBase64` in
[`src/utils.js:34`](../src/utils.js), spread-based `String.fromCharCode`)
throws a `RangeError` for inputs far below the cap, so the effective write
ceiling of `_persistMls` today is the encoder, not the parser cap. This is a
recorded, accepted residual of the Fase D security review
(`docs/security/2026-07-12-review-mls-state-envelope.md`, residual 2) and
goes away with the Blocco 3 vault, where base64 encoding disappears.

## 3. Browser quotas differ: the practical ceiling is much lower

Browsers apply different localStorage quotas — commonly around 5–10 MB per
origin, with per-browser variations. The practical ceiling for persisted MLS
state is therefore browser-dependent and much lower than the 16 MiB cap.
Nothing in the code can raise this limit; code must treat any write as
allowed to fail with `QuotaExceededError` at any time.

## 4. The Blocco 3 IndexedDB vault replaces this operational limit

The Blocco 3 vault (design:
[`docs/superpowers/specs/2026-07-12-styx-vault-design.md`](../../docs/superpowers/specs/2026-07-12-styx-vault-design.md);
spike: [`spikes/indexeddb-vault/`](../spikes/indexeddb-vault/)) moves
persistence to IndexedDB: binary values (no base64 expansion), much larger
origin quotas, and `navigator.storage.estimate()` for capacity awareness.
Once the vault is the storage backend, the localStorage ceiling described
here no longer applies; `MAX_PAYLOAD_BYTES` remains as the codec's defensive
cap.

## 5. Quota errors are fail-closed and non-destructive — keep it that way

A `QuotaExceededError` (or any other write failure) must never destroy or
overwrite saved MLS state. Today this holds for the legacy→envelope
migration (`src/storage/mls-state-migration.js`): a failure at any step
leaves the legacy `mls:state` value and its backup intact and raises a
structured `MLS_STATE_MIGRATION_FAILED` error — no partial state, no deleted
session, no silent fresh start. This property is tested with simulated quota
exhaustion on both the backup write and the main write
(`test/storage/mls-state-migration.test.js:90` and `:107`). Any future write
path (including the Blocco 3 vault) must preserve the same fail-closed,
non-destructive behaviour on quota errors, and this document must stay true
when it does.
