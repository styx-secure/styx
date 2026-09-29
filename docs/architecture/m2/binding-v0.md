# M2 opaque local binding v0 and KeyPackage bootstrap contract

Status: normative candidate for the exact M2 profile. C-FMT, O-SCEN and dependent implementation remain blocked until the owner ratifies the SHA-256 of this exact file.

## 1. Authority, scope and precedence

This document defines only the canonical non-secret adapter-local binding `m2-opaque-binding/v0` and logical local KeyPackage issuance at the SS bootstrap boundary. Its exact base is `e1538ef9c070e463a8256872a3fd0882c424e2ef`. Its read-only normative API input is `docs/architecture/m2/adapter-contract.md` from `00ae21802396b85f36acea703060f140f40f6407`, SHA-256 `b77d39fbb412b0eba3a579ebf6053408186a4c11f0de07b8727b4e1147305ad9`.

The machine-readable record in section 12 is normative and closed. Prose explains it but cannot add a field, value, transition or exception. Unknown values, missing or duplicate keys and duplicate JSON member names reject. C-API precedence remains authoritative: request shape and exact profile precede `CAPI-E006` at P03; onboarding/reference cases occur at P09; commit and reconciliation outcomes occur at P10.

`AP` carries opaque requests and originates `bindingRef` from its opaque application context exactly as C-API requires: its outer context controller generates a random token, never a semantic label. `SS` validates and registers that token, and owns authentication and session logic. `RS` owns authenticated durable state and reconciliation evidence. `TR` is absent. No byte defined here is an application identity or authority.

## 2. Closed canonical binding grammar

The complete binding is exactly:

```text
magic[8] = 53 54 59 58 4d 42 4e 44              # ASCII STYXMBND
encodingVersion:u16be = 00 00
field(tag=01, length=0020, value=localContextId[32])
field(tag=02, length=0020, value=secureSessionIdentity[32])
field(tag=03, length=0132, value=productProfile[306])
field = tag:u8 || length:u16be || value[length]
```

The outer fields occur once, in the shown order, with no optional field. Both 32-byte identifiers must be nonzero. Unknown versions/tags, missing, duplicate or reordered fields, wrong widths or endian order, zero identifiers, length mismatch, truncation and trailing bytes reject as malformed before comparison or mutation. Canonical decoding must re-encode byte-identically. The complete accepted length is exactly 389 bytes.

The product-profile value is the concatenation of the following 13 ordered inner fields using the same `tag:u8 || length:u16be || value` framing. ASCII means the exact listed ASCII bytes without NUL or normalization. `hex20` and `hex32` mean decoded raw bytes, not hexadecimal text.

| Tag | Field | Wire type | Length | Exact value |
|---|---|---:|---:|---|
| `0x01` | `adapterApi` | `ascii` | 26 | `styx-m2-session-adapter/v1` |
| `0x02` | `bindingVersion` | `ascii` | 20 | `m2-opaque-binding/v0` |
| `0x03` | `logicalAdapter` | `ascii` | 7 | `session` |
| `0x04` | `physicalStore` | `ascii` | 3 | `mls` |
| `0x05` | `stage` | `ascii` | 12 | `test-profile` |
| `0x06` | `topology` | `ascii` | 17 | `two-member-direct` |
| `0x07` | `openMlsRevision` | `hex20` | 20 | `09e92777dba0528d3d29e2e5e681b7e91637c7be` |
| `0x08` | `wasmArtifactPath` | `ascii` | 48 | `styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm` |
| `0x09` | `wasmArtifactSha256` | `hex32` | 32 | `fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e` |
| `0x0a` | `ciphersuiteIanaId` | `u16be` | 2 | `0x0001` |
| `0x0b` | `ciphersuiteName` | `ascii` | 44 | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` |
| `0x0c` | `ss0DecisionsSha256` | `hex32` | 32 | `235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07` |
| `0x0d` | `pastEpochWindow` | `u32be` | 4 | `5` |

Any change to one field produces different candidate bytes but is rejected as `UNSUPPORTED_PROFILE`; it does not define another accepted profile.

## 3. Components, ownership and generation

`localContextId` is the exact `bindingRef`: a fresh 32-byte nonzero value generated before the first request by the AP outer context controller's cryptographic generator. This is the precise meaning of C-API's “AP originates”; it is random opaque context, not application-semantic input. SS validates length, nonzero value and local uniqueness, then registers it as the slot key within the first complete C-API mutation. A failed or indeterminate first mutation follows the same RS outcome and reconciliation rules; there is no separate result or operation. It never derives from snapshots, labels, accounts, contacts, devices, Nostr or transport identifiers.

`secureSessionIdentity` is the exact raw 32-byte MLS Group ID. Founder SS generates it freshly and rejects local duplication. A joiner obtains the founder-chosen value only from the authenticated embedded-tree Welcome; peer-chosen bytes outside that authenticated object never enter it. Restore accepts it only after complete-record authentication and exact-profile revalidation. `productProfile` is the exact fixed encoding in section 2 and is built and checked by SS, never selected by AP.

Before a session, a slot has authoritative context and profile but no session identity and therefore no complete binding. `CREATE` or `JOIN_WELCOME` may hold a candidate complete binding in one mutation. It becomes authoritative only after `COMMITTED`. During reconciliation from `EMPTY`, the candidate remains held and unusable; from `ACTIVE`, the original complete binding remains authoritative until proof. `RESTORE` never trusts decoded bytes before authentication.

Equality is byte equality of the entire canonical binding. Changing context, session identity, outer encoding version or any one profile field changes the candidate bytes. A partial match never authorizes a session.

## 4. C-API `bindingRef` and mismatch

`bindingRef` denotes exactly the 32 `localContextId` bytes. AP originates the random opaque token and supplies it in the mandatory C-API field; SS validates and registers it. It is a lookup reference to a local binding slot, not the complete binding, a semantic AP value or authority. No channel from SS to AP is needed or defined.

In `EMPTY`, P03 compares `bindingRef` with the token being registered or the authoritative empty slot. In `ACTIVE`, P03 compares only the context token; SS separately reconstructs and compares authenticated complete binding bytes before mutation, with mismatch `FAIL_CLOSED_INTERNAL`. In `RECONCILIATION_REQUIRED`, P03 resolves the original slot; held candidate bytes remain unusable until RS proof. At `RESTORE`, P03 uses the pre-existing slot, never untrusted restored bytes; after authentication, complete-binding mismatch follows existing `CAPI-S004` / `AUTHENTICATED_STATE_INCONSISTENT`. A session swap is therefore not E006: it is rejected by this later authenticated complete-binding comparison.

Wrong length, unknown reference, byte mismatch or cross-context use yields `CAPI-E006` / `BINDING_MISMATCH`, `REJECTED`, unchanged and no persistence. This applies in `EMPTY`, `ACTIVE` and `RECONCILIATION_REQUIRED`. It does not turn the reference into authority and does not replace profile, authentication, replay, lifecycle or commit checks.

## 5. Exact local KeyPackage content

C-BIND defines an internal SS bootstrap primitive, not a ninth C-API operation. Each logical KeyPackage has:

- MLS version `MLS 1.0` and ciphersuite `0x0001`, `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`;
- one Basic credential whose identity is a fresh nonzero 32-byte SS-generated opaque member identity;
- a fresh Ed25519 signature key pair, fresh exact-suite HPKE init key pair and fresh distinct leaf-node HPKE encryption key pair, generated and owned by SS for this package only;
- leaf-node source `key_package`; `not_before = issuanceUnixSeconds - 300`, `not_after = issuanceUnixSeconds + 604800`; the normative maximum total lifetime is the full `not_after - not_before` span, exactly 605100 seconds. MLS clock validation is operational validity only and makes no remote, session or application freshness claim;
- capabilities exactly: version `[MLS 1.0]`, ciphersuite `[0x0001]`, extensions `[]`, proposals `[]`, credentials `[Basic]`; GREASE is excluded;
- no KeyPackage extension and specifically no `last_resort` extension; and
- canonical TLS framing as an MLSMessage carrying the KeyPackage.

The credential identity is never an application, contact, account, device, Nostr, transport or user-label identity. Public wire bytes carry no binding-v0 bytes, `bindingRef`, context id, product profile or AP value. Context/profile association is SS/RS local metadata only. This document does not claim the frozen WASM artifact can produce these bytes; F-WASM owns that determination.

## 6. Issuance, durability and aliasing

One issuance accepts only `bindingRef` and atomically creates a fresh public package, signature/init/leaf-encryption private material, opaque local KeyPackage reference, context association and exact-profile association as one non-aliasable logical identity. The local reference is a fresh nonzero 32-byte SS random value, distinct from the canonical MLS KeyPackageRef; RS maps them one-to-one. No public bytes, private component or reference may appear in another identity. Duplicate public bytes, signature key, init key, leaf encryption key, private bundle or reference; cross-context/profile aliasing; and application-supplied local references fail closed. In `UNCONSUMED` they enter `INVALID`; in `RESERVED` they set durable `invalidPending`; `CONSUMED` remains terminal.

RS must prove the complete logical record `COMMITTED` before SS releases the only bootstrap output: opaque framed public KeyPackage bytes. `NOT_COMMITTED` discards the candidate and releases nothing. `INDETERMINATE` retains a held identity, releases nothing, blocks another issuance and survives restart until reconciliation; reconciled `COMMITTED` releases at most once and reconciled `NOT_COMMITTED` discards. Private material, local reference and binding metadata never cross this boundary. The transaction mechanism and physical layout remain C-MUT/C-FMT work.

At most one package per binding slot may be issuance-held, `UNCONSUMED` or `RESERVED`. `RESERVED` and issuance-held uncertainty block issuance. A package cannot be replaced until a proven `NOT_COMMITTED` permits a fresh issuance or makes an uncorrupted reserved package retryable, a proven `COMMITTED` consumes it, or fail-closed invalidation reaches `INVALID`.

## 7. Closed one-shot lifecycle

Reservation precedes `JOIN_WELCOME`. `COMMITTED` or reconciled `COMMITTED` makes the reference `CONSUMED`. `NOT_COMMITTED` restores `UNCONSUMED`. `INDETERMINATE` remains `RESERVED`, unusable and not retryable. `CONSUMED` and `INVALID` are terminal.

If invalidation, drift or corruption is detected while `RESERVED` and the commit outcome is unresolved, SS latches `invalidPending` but cannot discard or reuse the reference. Reconciled `COMMITTED` wins to `CONSUMED`; reconciled `NOT_COMMITTED` with the latch goes to `INVALID`; continued uncertainty remains `RESERVED`. Detection in `UNCONSUMED` goes directly to `INVALID`. A consumed package cannot be resurrected or reclassified; corruption in its associated session record is rejected by the owning session/restore contract while the package remains terminal `CONSUMED`.

Every valid `(state, invalidPending, event)` key is listed exactly once below. `invalidPending=true` is valid only with `RESERVED`; it is part of durable state, not hidden metadata. Rows with local disposition `NO_EFFECT_REJECTED` preserve state and emit no output.

| State | Pending before | Event | Next | Pending after | C-API scenario | C-API disposition | Local disposition |
|---|---:|---|---|---:|---|---|---|
| `UNCONSUMED` | `false` | `RESTART` | `UNCONSUMED` | `false` | `-` | `-` | `RESTORED_EXACT_STATE` |
| `UNCONSUMED` | `false` | `RESERVE_MATCHING_WELCOME` | `RESERVED` | `false` | `-` | `-` | `RESERVATION_STAGED` |
| `UNCONSUMED` | `false` | `RESERVE_CONCURRENT_OR_REPEATED` | `UNCONSUMED` | `false` | `-` | `-` | `NO_EFFECT_REJECTED` |
| `UNCONSUMED` | `false` | `JOIN_COMMITTED` | `UNCONSUMED` | `false` | `-` | `-` | `NO_EFFECT_REJECTED` |
| `UNCONSUMED` | `false` | `JOIN_NOT_COMMITTED` | `UNCONSUMED` | `false` | `-` | `-` | `NO_EFFECT_REJECTED` |
| `UNCONSUMED` | `false` | `JOIN_INDETERMINATE` | `UNCONSUMED` | `false` | `-` | `-` | `NO_EFFECT_REJECTED` |
| `UNCONSUMED` | `false` | `RECONCILE_COMMITTED` | `UNCONSUMED` | `false` | `-` | `-` | `NO_EFFECT_REJECTED` |
| `UNCONSUMED` | `false` | `RECONCILE_NOT_COMMITTED` | `UNCONSUMED` | `false` | `-` | `-` | `NO_EFFECT_REJECTED` |
| `UNCONSUMED` | `false` | `RECONCILE_INDETERMINATE` | `UNCONSUMED` | `false` | `-` | `-` | `NO_EFFECT_REJECTED` |
| `UNCONSUMED` | `false` | `EXPLICIT_INVALIDATE` | `INVALID` | `false` | `-` | `-` | `INVALIDATED` |
| `UNCONSUMED` | `false` | `PROFILE_DRIFT_DETECTED` | `INVALID` | `false` | `-` | `-` | `INVALIDATED` |
| `UNCONSUMED` | `false` | `CORRUPTION_DETECTED` | `INVALID` | `false` | `-` | `-` | `INVALIDATED` |
| `RESERVED` | `false` | `RESTART` | `RESERVED` | `false` | `-` | `-` | `RESTORED_EXACT_STATE` |
| `RESERVED` | `false` | `RESERVE_MATCHING_WELCOME` | `RESERVED` | `false` | `-` | `-` | `NO_EFFECT_REJECTED` |
| `RESERVED` | `false` | `RESERVE_CONCURRENT_OR_REPEATED` | `RESERVED` | `false` | `-` | `-` | `NO_EFFECT_REJECTED` |
| `RESERVED` | `false` | `JOIN_COMMITTED` | `CONSUMED` | `false` | `CAPI-S006` | `JOINED` | `JOIN_COMMITTED` |
| `RESERVED` | `false` | `JOIN_NOT_COMMITTED` | `UNCONSUMED` | `false` | `CAPI-S006` | `NOT_COMMITTED` | `JOIN_NOT_COMMITTED_RETRYABLE` |
| `RESERVED` | `false` | `JOIN_INDETERMINATE` | `RESERVED` | `false` | `CAPI-S006` | `INDETERMINATE` | `JOIN_INDETERMINATE_BLOCKED` |
| `RESERVED` | `false` | `RECONCILE_COMMITTED` | `CONSUMED` | `false` | `CAPI-S020` | `RECONCILED_COMMITTED` | `RECONCILED_COMMITTED` |
| `RESERVED` | `false` | `RECONCILE_NOT_COMMITTED` | `UNCONSUMED` | `false` | `CAPI-S021` | `NOT_COMMITTED` | `RECONCILED_NOT_COMMITTED_RETRYABLE` |
| `RESERVED` | `false` | `RECONCILE_INDETERMINATE` | `RESERVED` | `false` | `CAPI-S024` | `INDETERMINATE` | `RECONCILIATION_STILL_INDETERMINATE` |
| `RESERVED` | `false` | `EXPLICIT_INVALIDATE` | `RESERVED` | `true` | `-` | `-` | `INVALIDATION_LATCHED` |
| `RESERVED` | `false` | `PROFILE_DRIFT_DETECTED` | `RESERVED` | `true` | `-` | `-` | `INVALIDATION_LATCHED` |
| `RESERVED` | `false` | `CORRUPTION_DETECTED` | `RESERVED` | `true` | `-` | `-` | `INVALIDATION_LATCHED` |
| `RESERVED` | `true` | `RESTART` | `RESERVED` | `true` | `-` | `-` | `RESTORED_EXACT_STATE` |
| `RESERVED` | `true` | `RESERVE_MATCHING_WELCOME` | `RESERVED` | `true` | `-` | `-` | `NO_EFFECT_REJECTED` |
| `RESERVED` | `true` | `RESERVE_CONCURRENT_OR_REPEATED` | `RESERVED` | `true` | `-` | `-` | `NO_EFFECT_REJECTED` |
| `RESERVED` | `true` | `JOIN_COMMITTED` | `CONSUMED` | `false` | `CAPI-S006` | `JOINED` | `JOIN_COMMITTED` |
| `RESERVED` | `true` | `JOIN_NOT_COMMITTED` | `INVALID` | `false` | `CAPI-S006` | `NOT_COMMITTED` | `RECONCILED_NOT_COMMITTED_INVALID` |
| `RESERVED` | `true` | `JOIN_INDETERMINATE` | `RESERVED` | `true` | `CAPI-S006` | `INDETERMINATE` | `JOIN_INDETERMINATE_BLOCKED` |
| `RESERVED` | `true` | `RECONCILE_COMMITTED` | `CONSUMED` | `false` | `CAPI-S020` | `RECONCILED_COMMITTED` | `RECONCILED_COMMITTED` |
| `RESERVED` | `true` | `RECONCILE_NOT_COMMITTED` | `INVALID` | `false` | `CAPI-S021` | `NOT_COMMITTED` | `RECONCILED_NOT_COMMITTED_INVALID` |
| `RESERVED` | `true` | `RECONCILE_INDETERMINATE` | `RESERVED` | `true` | `CAPI-S024` | `INDETERMINATE` | `RECONCILIATION_STILL_INDETERMINATE` |
| `RESERVED` | `true` | `EXPLICIT_INVALIDATE` | `RESERVED` | `true` | `-` | `-` | `INVALIDATION_LATCHED` |
| `RESERVED` | `true` | `PROFILE_DRIFT_DETECTED` | `RESERVED` | `true` | `-` | `-` | `INVALIDATION_LATCHED` |
| `RESERVED` | `true` | `CORRUPTION_DETECTED` | `RESERVED` | `true` | `-` | `-` | `INVALIDATION_LATCHED` |
| `CONSUMED` | `false` | `RESTART` | `CONSUMED` | `false` | `-` | `-` | `TERMINAL_CONSUMED` |
| `CONSUMED` | `false` | `RESERVE_MATCHING_WELCOME` | `CONSUMED` | `false` | `CAPI-S007` | `KEY_PACKAGE_ALREADY_CONSUMED` | `TERMINAL_CONSUMED` |
| `CONSUMED` | `false` | `RESERVE_CONCURRENT_OR_REPEATED` | `CONSUMED` | `false` | `CAPI-S007` | `KEY_PACKAGE_ALREADY_CONSUMED` | `TERMINAL_CONSUMED` |
| `CONSUMED` | `false` | `JOIN_COMMITTED` | `CONSUMED` | `false` | `-` | `-` | `TERMINAL_CONSUMED` |
| `CONSUMED` | `false` | `JOIN_NOT_COMMITTED` | `CONSUMED` | `false` | `-` | `-` | `TERMINAL_CONSUMED` |
| `CONSUMED` | `false` | `JOIN_INDETERMINATE` | `CONSUMED` | `false` | `-` | `-` | `TERMINAL_CONSUMED` |
| `CONSUMED` | `false` | `RECONCILE_COMMITTED` | `CONSUMED` | `false` | `-` | `-` | `TERMINAL_CONSUMED` |
| `CONSUMED` | `false` | `RECONCILE_NOT_COMMITTED` | `CONSUMED` | `false` | `-` | `-` | `TERMINAL_CONSUMED` |
| `CONSUMED` | `false` | `RECONCILE_INDETERMINATE` | `CONSUMED` | `false` | `-` | `-` | `TERMINAL_CONSUMED` |
| `CONSUMED` | `false` | `EXPLICIT_INVALIDATE` | `CONSUMED` | `false` | `-` | `-` | `TERMINAL_CONSUMED` |
| `CONSUMED` | `false` | `PROFILE_DRIFT_DETECTED` | `CONSUMED` | `false` | `-` | `-` | `TERMINAL_CONSUMED` |
| `CONSUMED` | `false` | `CORRUPTION_DETECTED` | `CONSUMED` | `false` | `-` | `-` | `TERMINAL_CONSUMED` |
| `INVALID` | `false` | `RESTART` | `INVALID` | `false` | `-` | `-` | `TERMINAL_INVALID` |
| `INVALID` | `false` | `RESERVE_MATCHING_WELCOME` | `INVALID` | `false` | `CAPI-S027` | `WELCOME_NO_MATCHING_KEY_PACKAGE` | `TERMINAL_INVALID` |
| `INVALID` | `false` | `RESERVE_CONCURRENT_OR_REPEATED` | `INVALID` | `false` | `CAPI-S027` | `WELCOME_NO_MATCHING_KEY_PACKAGE` | `TERMINAL_INVALID` |
| `INVALID` | `false` | `JOIN_COMMITTED` | `INVALID` | `false` | `-` | `-` | `TERMINAL_INVALID` |
| `INVALID` | `false` | `JOIN_NOT_COMMITTED` | `INVALID` | `false` | `-` | `-` | `TERMINAL_INVALID` |
| `INVALID` | `false` | `JOIN_INDETERMINATE` | `INVALID` | `false` | `-` | `-` | `TERMINAL_INVALID` |
| `INVALID` | `false` | `RECONCILE_COMMITTED` | `INVALID` | `false` | `-` | `-` | `TERMINAL_INVALID` |
| `INVALID` | `false` | `RECONCILE_NOT_COMMITTED` | `INVALID` | `false` | `-` | `-` | `TERMINAL_INVALID` |
| `INVALID` | `false` | `RECONCILE_INDETERMINATE` | `INVALID` | `false` | `-` | `-` | `TERMINAL_INVALID` |
| `INVALID` | `false` | `EXPLICIT_INVALIDATE` | `INVALID` | `false` | `-` | `-` | `TERMINAL_INVALID` |
| `INVALID` | `false` | `PROFILE_DRIFT_DETECTED` | `INVALID` | `false` | `-` | `-` | `TERMINAL_INVALID` |
| `INVALID` | `false` | `CORRUPTION_DETECTED` | `INVALID` | `false` | `-` | `-` | `TERMINAL_INVALID` |

Reservation is a local precondition, not itself CAPI-S006. CAPI-S006 governs the ensuing JOIN_WELCOME tri-state. New joins while adapter state is `RECONCILIATION_REQUIRED` fail at CAPI-G019/P05. CAPI-S007 covers consumed reuse; CAPI-S027's exact disposition `WELCOME_NO_MATCHING_KEY_PACKAGE` covers unknown, forged, drifted, invalid, cross-slot or ambiguous material. Join-specific CAPI-S020/S021/S024 apply only when the held original operation was `JOIN_WELCOME`.

## 8. Restart, reference validation and release rules

Restart restores each lifecycle state and flag exactly; it never converts uncertainty into retryability. SS first resolves the `bindingRef` slot, then a Welcome must authenticate to exactly one local `UNCONSUMED` package in that slot through its canonical MLS KeyPackageRef/private-init-key mapping. Concurrent, repeated or cross-slot reservation rejects. An AP-added semantic local-reference field is an unknown request field at P01; AP supplies only opaque Welcome bytes through C-API.

No public bootstrap output is released before issuance durability. No join output is released on `NOT_COMMITTED`, `INDETERMINATE`, rejection or before reconciliation. Private material is usable only internally for the one reserved join and never for a second candidate while reserved; after clean `NOT_COMMITTED`, the same unconsumed identity may be retried.

## 9. Vectors

The vectors publish all literal input and canonical output bytes in the normative record. Digests are integrity evidence only; they are never identifiers or references.

| Vector | Producer | Bytes | SHA-256 |
|---|---|---:|---|
| `BIND-KAT-001` | `reference-encoder-a` | 389 | `b0960b281efff7e2fbc8a4c0aa406d9a32048d585d881d5bf5b93eeda480aba0` |
| `BIND-KAT-002` | `reference-encoder-a` | 389 | `94fda7db9ebb262d72a4e43f679feab6421bd40ac3ce03067f69b2ca5ac111ad` |
| `BIND-KAT-003` | `independent-encoder-b` | 389 | `12668f36719fa39bb132886e5b94165697a491ebb8608f1a6441a95114319205` |

`BIND-KAT-003` must be reproduced by a second encoder written only from sections 2 and 12 and sharing no encoding code with the reference encoder. Repeated runs must be byte-identical. Pairwise bindings are unequal. The validator must recompute every digest from literal bytes.

## 10. Required conformance coverage

Every `negativeCases` entry names a base and deterministic mutation or event sequence. The extracted standard-library validator must execute each fixture and emit one PASS record per id; reject every malformed-encoding class; mutate context and session independently; mutate outer version; mutate each of the 13 profile fields independently; verify repeated equality and pairwise inequality; and check decode/re-encode identity.

It must prove all 60 lifecycle keys are unique and exactly equal to the five valid state/flag configurations × twelve-event Cartesian product, terminal-state invariants, restart/flag preservation, reservation exclusivity, aliasing rejection, outstanding bound, and each CAPI-E006/G019/S004/S006/S007/S020/S021/S024/S027 mapping. It must sabotage missing, duplicate and overlapping rows and execute every issuance/reference model negative. Unexpected skips fail. The external evidence bundle contains validator source, exact command, per-case output and digests; it is not part of this repository diff.

## 11. Boundaries and non-claims

C-BIND supplies canonical bytes and local domain identities. C-FMT owns persisted layout, AAD construction, keyed-root coverage, HKDF labels and key versions. C-MUT owns transaction mechanics and physical atomicity. No value here claims application identity, role, authorization, account/device/contact meaning, transport/delivery, freshness, coherent whole-profile rollback prevention, legacy import, downgrade, public SDK, production activation or general topology. The binding has no fallback version. No legacy or transport identifier may be reused.

Removal of this file is complete rollback because this card implements no bytes, storage, migration or issuance. Entropy quality, private-key handling, durable atomicity, restore safety, deletion/zeroization and constant-time behavior remain implementation risks.

## 12. Normative machine-readable record

<!-- styx-m2-binding-v0-json:start -->
```json
{
  "schema": "styx-m2-opaque-binding/v0",
  "status": "owner-ratification-required-before-dependent-implementation",
  "closed": true,
  "authority": {
    "base": "e1538ef9c070e463a8256872a3fd0882c424e2ef",
    "cApiCommit": "00ae21802396b85f36acea703060f140f40f6407",
    "cApiSha256": "b77d39fbb412b0eba3a579ebf6053408186a4c11f0de07b8727b4e1147305ad9"
  },
  "profile": {
    "adapterApi": "styx-m2-session-adapter/v1",
    "bindingVersion": "m2-opaque-binding/v0",
    "logicalAdapter": "session",
    "physicalStore": "mls",
    "stage": "test-profile",
    "topology": "two-member-direct",
    "openMlsRevision": "09e92777dba0528d3d29e2e5e681b7e91637c7be",
    "wasmArtifactPath": "styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm",
    "wasmArtifactSha256": "fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e",
    "ciphersuiteIanaId": "0x0001",
    "ciphersuiteName": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
    "ss0DecisionsSha256": "235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07",
    "pastEpochWindow": 5
  },
  "byteGrammar": {
    "magicHex": "535459584d424e44",
    "encodingVersion": 0,
    "integerEndian": "big",
    "outerFields": [
      {
        "order": 1,
        "tag": 1,
        "name": "localContextId",
        "length": 32
      },
      {
        "order": 2,
        "tag": 2,
        "name": "secureSessionIdentity",
        "length": 32
      },
      {
        "order": 3,
        "tag": 3,
        "name": "productProfile",
        "length": 306
      }
    ],
    "fieldHeader": "tag:u8 || length:u16be",
    "canonicalBindingLength": 389,
    "rejectUnknownMissingDuplicateReorderedTruncatedTrailing": true,
    "identifiersAllZeroRejected": true
  },
  "profileFields": [
    {
      "tag": 1,
      "name": "adapterApi",
      "wireType": "ascii",
      "exactSourceValue": "styx-m2-session-adapter/v1",
      "valueLength": 26,
      "valueHex": "737479782d6d322d73657373696f6e2d616461707465722f7631",
      "mutationId": "NEG-PROFILE-01"
    },
    {
      "tag": 2,
      "name": "bindingVersion",
      "wireType": "ascii",
      "exactSourceValue": "m2-opaque-binding/v0",
      "valueLength": 20,
      "valueHex": "6d322d6f70617175652d62696e64696e672f7630",
      "mutationId": "NEG-PROFILE-02"
    },
    {
      "tag": 3,
      "name": "logicalAdapter",
      "wireType": "ascii",
      "exactSourceValue": "session",
      "valueLength": 7,
      "valueHex": "73657373696f6e",
      "mutationId": "NEG-PROFILE-03"
    },
    {
      "tag": 4,
      "name": "physicalStore",
      "wireType": "ascii",
      "exactSourceValue": "mls",
      "valueLength": 3,
      "valueHex": "6d6c73",
      "mutationId": "NEG-PROFILE-04"
    },
    {
      "tag": 5,
      "name": "stage",
      "wireType": "ascii",
      "exactSourceValue": "test-profile",
      "valueLength": 12,
      "valueHex": "746573742d70726f66696c65",
      "mutationId": "NEG-PROFILE-05"
    },
    {
      "tag": 6,
      "name": "topology",
      "wireType": "ascii",
      "exactSourceValue": "two-member-direct",
      "valueLength": 17,
      "valueHex": "74776f2d6d656d6265722d646972656374",
      "mutationId": "NEG-PROFILE-06"
    },
    {
      "tag": 7,
      "name": "openMlsRevision",
      "wireType": "hex20",
      "exactSourceValue": "09e92777dba0528d3d29e2e5e681b7e91637c7be",
      "valueLength": 20,
      "valueHex": "09e92777dba0528d3d29e2e5e681b7e91637c7be",
      "mutationId": "NEG-PROFILE-07"
    },
    {
      "tag": 8,
      "name": "wasmArtifactPath",
      "wireType": "ascii",
      "exactSourceValue": "styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm",
      "valueLength": 48,
      "valueHex": "737479782d6a732f76656e646f722f6f70656e6d6c732d7761736d2f6f70656e6d6c735f7761736d5f62672e7761736d",
      "mutationId": "NEG-PROFILE-08"
    },
    {
      "tag": 9,
      "name": "wasmArtifactSha256",
      "wireType": "hex32",
      "exactSourceValue": "fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e",
      "valueLength": 32,
      "valueHex": "fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e",
      "mutationId": "NEG-PROFILE-09"
    },
    {
      "tag": 10,
      "name": "ciphersuiteIanaId",
      "wireType": "u16be",
      "exactSourceValue": "0x0001",
      "valueLength": 2,
      "valueHex": "0001",
      "mutationId": "NEG-PROFILE-10"
    },
    {
      "tag": 11,
      "name": "ciphersuiteName",
      "wireType": "ascii",
      "exactSourceValue": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      "valueLength": 44,
      "valueHex": "4d4c535f3132385f44484b454d5832353531395f41455331323847434d5f5348413235365f45643235353139",
      "mutationId": "NEG-PROFILE-11"
    },
    {
      "tag": 12,
      "name": "ss0DecisionsSha256",
      "wireType": "hex32",
      "exactSourceValue": "235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07",
      "valueLength": 32,
      "valueHex": "235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07",
      "mutationId": "NEG-PROFILE-12"
    },
    {
      "tag": 13,
      "name": "pastEpochWindow",
      "wireType": "u32be",
      "exactSourceValue": 5,
      "valueLength": 4,
      "valueHex": "00000005",
      "mutationId": "NEG-PROFILE-13"
    }
  ],
  "ownership": {
    "AP": "originates a fresh opaque random context token outside operation semantics and carries opaque peer inputs; never supplies a semantic label as binding bytes",
    "SS": "validates and registers the AP-originated opaque context token, generates founder session identity, authenticates joiner identity and validates exact binding bytes",
    "RS": "durably records and restores authenticated binding and KeyPackage lifecycle metadata",
    "TR": "ABSENT"
  },
  "generationRules": {
    "localContextId": "AP outer context controller generates 32 nonzero bytes from its cryptographic RNG before the first adapter request; the value has no application semantics; SS validates length, nonzero value and local uniqueness before registering it as the slot key",
    "founderSecureSessionIdentity": "SS generates a fresh nonzero 32-byte MLS Group ID and rejects local duplication",
    "joinerSecureSessionIdentity": "SS accepts only the exact 32-byte nonzero Group ID authenticated by the Welcome and rejects local duplication or any out-of-Welcome peer bytes",
    "restoreSecureSessionIdentity": "SS accepts only after complete-record authentication and exact-profile revalidation"
  },
  "bindingRef": {
    "wireBytes": "exactly localContextId (32 bytes)",
    "originator": "AP outer context controller",
    "registration": "SS validates and durably registers the first use as an opaque binding slot before session mutation; registration is part of the complete C-API mutation and has no separate output",
    "carrier": "AP supplies its own previously generated opaque context token on every request",
    "semantics": "opaque random application-context token with no semantic content; it is a local binding-slot reference only, not the complete binding and not authority",
    "capiMismatch": "CAPI-E006 BINDING_MISMATCH at P03 before mutation"
  },
  "bindingSlotStates": [
    {
      "state": "EMPTY",
      "context": "authoritative",
      "session": "absent",
      "profile": "authoritative",
      "completeBinding": "absent"
    },
    {
      "state": "STAGED_FROM_EMPTY",
      "context": "authoritative",
      "session": "held",
      "profile": "authoritative",
      "completeBinding": "held-not-authoritative"
    },
    {
      "state": "ACTIVE",
      "context": "authoritative",
      "session": "authoritative",
      "profile": "authoritative",
      "completeBinding": "authoritative"
    },
    {
      "state": "RECONCILIATION_FROM_EMPTY",
      "context": "authoritative",
      "session": "held",
      "profile": "authoritative",
      "completeBinding": "held-not-authoritative"
    },
    {
      "state": "RECONCILIATION_FROM_ACTIVE",
      "context": "authoritative",
      "session": "original-authoritative",
      "profile": "authoritative",
      "completeBinding": "original-authoritative; held mutation does not change Group ID"
    }
  ],
  "comparisonRules": {
    "equality": "byte equality of the complete canonical binding",
    "partialMatchNeverAuthorizes": true,
    "empty": "P03 compares request bindingRef with the AP-originated context token being registered or the authoritative empty slot; session identity does not yet exist",
    "active": "P03 compares only request bindingRef to the authoritative slot context; SS then compares the reconstructed authenticated complete binding to the authoritative complete binding before mutation, and failure is FAIL_CLOSED_INTERNAL",
    "reconciliationRequired": "P03 compares bindingRef with the original slot; held candidate remains unusable until RS proof; mismatch is CAPI-E006",
    "restore": "P03 resolves the pre-existing local slot without trusting restored bytes; after record authentication, complete-binding mismatch is AUTHENTICATED_STATE_INCONSISTENT through the existing CAPI-S004 path",
    "sessionSwap": "never CAPI-E006 because bindingRef contains no session bytes; it is rejected by authenticated complete-binding comparison"
  },
  "keyPackageProfile": {
    "mlsVersion": "MLS 1.0",
    "ciphersuiteIanaId": "0x0001",
    "ciphersuiteName": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
    "credentialType": "Basic",
    "credentialIdentity": "fresh 32-byte nonzero SS CSPRNG member identity with no application semantics; issuance accepts no identity input",
    "signatureKey": "fresh Ed25519 key pair per logical package, generated and owned by SS",
    "initKey": "fresh exact-suite HPKE init key pair per logical package, generated and owned by SS",
    "leafEncryptionKey": "fresh exact-suite HPKE leaf-node encryption key pair, distinct from initKey and generated and owned by SS",
    "leafNodeSource": "key_package",
    "leafNodeLifetime": {
      "notBeforeFormula": "issuanceUnixSeconds - 300",
      "notAfterFormula": "issuanceUnixSeconds + 604800",
      "maxTotalLifetimeSeconds": 605100,
      "interpretation": "The normative maximum is the full not_after minus not_before span: 605100 seconds. MLS operational validity only; local clock validation does not establish remote, session or application freshness"
    },
    "capabilities": {
      "versions": [
        "MLS 1.0"
      ],
      "ciphersuites": [
        "0x0001"
      ],
      "extensions": [],
      "proposals": [],
      "credentials": [
        "Basic"
      ],
      "greaseAllowed": false
    },
    "keyPackageExtensions": [],
    "lastResort": false,
    "framing": "TLS serialized framed MLSMessage carrying a KeyPackage",
    "wireExcludes": [
      "binding-v0",
      "bindingRef",
      "localContextId",
      "product profile",
      "AP value"
    ]
  },
  "issuanceRules": {
    "boundary": "internal SS bootstrap primitive; not a C-API operation",
    "inputs": [
      "bindingRef only"
    ],
    "freshness": "public bytes, signature private key, init private key, leaf encryption private key and opaque reference are fresh and non-aliasable",
    "localReference": "fresh nonzero 32-byte SS CSPRNG value, distinct from the MLS KeyPackageRef; RS maps it one-to-one to the canonical MLS KeyPackageRef and complete private record; it never crosses the bootstrap boundary",
    "welcomeMatching": "SS resolves the bindingRef slot first, then authenticates the Welcome against exactly one UNCONSUMED package in that slot using the canonical MLS KeyPackageRef/private init key mapping",
    "durability": "RS proves the complete private-material/reference/context/profile record COMMITTED before SS releases public framed bytes",
    "commitOutcomes": {
      "COMMITTED": "release public bytes once and enter UNCONSUMED",
      "NOT_COMMITTED": "discard the candidate identity and release nothing; a fresh issuance may retry",
      "INDETERMINATE": "retain held identity, release nothing, block issuance and reconcile on restart; reconciled COMMITTED releases at most once, reconciled NOT_COMMITTED discards"
    },
    "output": "only opaque framed public KeyPackage bytes",
    "neverOutput": [
      "private material",
      "local KeyPackage reference",
      "binding metadata"
    ],
    "maxOutstandingUnconsumedOrReservedOrIssuanceHeldPerBindingSlot": 1,
    "reservedBlocksIssuance": true,
    "wasmFeasibilityClaim": false
  },
  "lifecycle": {
    "states": [
      "UNCONSUMED",
      "RESERVED",
      "CONSUMED",
      "INVALID"
    ],
    "events": [
      "RESTART",
      "RESERVE_MATCHING_WELCOME",
      "RESERVE_CONCURRENT_OR_REPEATED",
      "JOIN_COMMITTED",
      "JOIN_NOT_COMMITTED",
      "JOIN_INDETERMINATE",
      "RECONCILE_COMMITTED",
      "RECONCILE_NOT_COMMITTED",
      "RECONCILE_INDETERMINATE",
      "EXPLICIT_INVALIDATE",
      "PROFILE_DRIFT_DETECTED",
      "CORRUPTION_DETECTED"
    ],
    "validConfigurations": [
      {
        "state": "UNCONSUMED",
        "invalidPending": false
      },
      {
        "state": "RESERVED",
        "invalidPending": false
      },
      {
        "state": "RESERVED",
        "invalidPending": true
      },
      {
        "state": "CONSUMED",
        "invalidPending": false
      },
      {
        "state": "INVALID",
        "invalidPending": false
      }
    ],
    "rowKey": [
      "state",
      "invalidPendingBefore",
      "event"
    ],
    "expectedRowCount": 60,
    "localDispositionEnum": [
      "NO_EFFECT_REJECTED",
      "RESTORED_EXACT_STATE",
      "RESERVATION_STAGED",
      "JOIN_COMMITTED",
      "JOIN_NOT_COMMITTED_RETRYABLE",
      "JOIN_INDETERMINATE_BLOCKED",
      "RECONCILED_COMMITTED",
      "RECONCILED_NOT_COMMITTED_RETRYABLE",
      "RECONCILED_NOT_COMMITTED_INVALID",
      "RECONCILIATION_STILL_INDETERMINATE",
      "INVALIDATION_LATCHED",
      "INVALIDATED",
      "TERMINAL_CONSUMED",
      "TERMINAL_INVALID"
    ],
    "terminalStates": [
      "CONSUMED",
      "INVALID"
    ],
    "rows": [
      {
        "state": "UNCONSUMED",
        "invalidPendingBefore": false,
        "event": "RESTART",
        "nextState": "UNCONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "RESTORED_EXACT_STATE"
      },
      {
        "state": "UNCONSUMED",
        "invalidPendingBefore": false,
        "event": "RESERVE_MATCHING_WELCOME",
        "nextState": "RESERVED",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "RESERVATION_STAGED"
      },
      {
        "state": "UNCONSUMED",
        "invalidPendingBefore": false,
        "event": "RESERVE_CONCURRENT_OR_REPEATED",
        "nextState": "UNCONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "NO_EFFECT_REJECTED"
      },
      {
        "state": "UNCONSUMED",
        "invalidPendingBefore": false,
        "event": "JOIN_COMMITTED",
        "nextState": "UNCONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "NO_EFFECT_REJECTED"
      },
      {
        "state": "UNCONSUMED",
        "invalidPendingBefore": false,
        "event": "JOIN_NOT_COMMITTED",
        "nextState": "UNCONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "NO_EFFECT_REJECTED"
      },
      {
        "state": "UNCONSUMED",
        "invalidPendingBefore": false,
        "event": "JOIN_INDETERMINATE",
        "nextState": "UNCONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "NO_EFFECT_REJECTED"
      },
      {
        "state": "UNCONSUMED",
        "invalidPendingBefore": false,
        "event": "RECONCILE_COMMITTED",
        "nextState": "UNCONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "NO_EFFECT_REJECTED"
      },
      {
        "state": "UNCONSUMED",
        "invalidPendingBefore": false,
        "event": "RECONCILE_NOT_COMMITTED",
        "nextState": "UNCONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "NO_EFFECT_REJECTED"
      },
      {
        "state": "UNCONSUMED",
        "invalidPendingBefore": false,
        "event": "RECONCILE_INDETERMINATE",
        "nextState": "UNCONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "NO_EFFECT_REJECTED"
      },
      {
        "state": "UNCONSUMED",
        "invalidPendingBefore": false,
        "event": "EXPLICIT_INVALIDATE",
        "nextState": "INVALID",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "INVALIDATED"
      },
      {
        "state": "UNCONSUMED",
        "invalidPendingBefore": false,
        "event": "PROFILE_DRIFT_DETECTED",
        "nextState": "INVALID",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "INVALIDATED"
      },
      {
        "state": "UNCONSUMED",
        "invalidPendingBefore": false,
        "event": "CORRUPTION_DETECTED",
        "nextState": "INVALID",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "INVALIDATED"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": false,
        "event": "RESTART",
        "nextState": "RESERVED",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "RESTORED_EXACT_STATE"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": false,
        "event": "RESERVE_MATCHING_WELCOME",
        "nextState": "RESERVED",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "NO_EFFECT_REJECTED"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": false,
        "event": "RESERVE_CONCURRENT_OR_REPEATED",
        "nextState": "RESERVED",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "NO_EFFECT_REJECTED"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": false,
        "event": "JOIN_COMMITTED",
        "nextState": "CONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": "CAPI-S006",
        "capiDisposition": "JOINED",
        "localDisposition": "JOIN_COMMITTED"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": false,
        "event": "JOIN_NOT_COMMITTED",
        "nextState": "UNCONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": "CAPI-S006",
        "capiDisposition": "NOT_COMMITTED",
        "localDisposition": "JOIN_NOT_COMMITTED_RETRYABLE"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": false,
        "event": "JOIN_INDETERMINATE",
        "nextState": "RESERVED",
        "invalidPendingAfter": false,
        "capiScenario": "CAPI-S006",
        "capiDisposition": "INDETERMINATE",
        "localDisposition": "JOIN_INDETERMINATE_BLOCKED"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": false,
        "event": "RECONCILE_COMMITTED",
        "nextState": "CONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": "CAPI-S020",
        "capiDisposition": "RECONCILED_COMMITTED",
        "localDisposition": "RECONCILED_COMMITTED"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": false,
        "event": "RECONCILE_NOT_COMMITTED",
        "nextState": "UNCONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": "CAPI-S021",
        "capiDisposition": "NOT_COMMITTED",
        "localDisposition": "RECONCILED_NOT_COMMITTED_RETRYABLE"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": false,
        "event": "RECONCILE_INDETERMINATE",
        "nextState": "RESERVED",
        "invalidPendingAfter": false,
        "capiScenario": "CAPI-S024",
        "capiDisposition": "INDETERMINATE",
        "localDisposition": "RECONCILIATION_STILL_INDETERMINATE"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": false,
        "event": "EXPLICIT_INVALIDATE",
        "nextState": "RESERVED",
        "invalidPendingAfter": true,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "INVALIDATION_LATCHED"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": false,
        "event": "PROFILE_DRIFT_DETECTED",
        "nextState": "RESERVED",
        "invalidPendingAfter": true,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "INVALIDATION_LATCHED"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": false,
        "event": "CORRUPTION_DETECTED",
        "nextState": "RESERVED",
        "invalidPendingAfter": true,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "INVALIDATION_LATCHED"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": true,
        "event": "RESTART",
        "nextState": "RESERVED",
        "invalidPendingAfter": true,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "RESTORED_EXACT_STATE"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": true,
        "event": "RESERVE_MATCHING_WELCOME",
        "nextState": "RESERVED",
        "invalidPendingAfter": true,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "NO_EFFECT_REJECTED"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": true,
        "event": "RESERVE_CONCURRENT_OR_REPEATED",
        "nextState": "RESERVED",
        "invalidPendingAfter": true,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "NO_EFFECT_REJECTED"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": true,
        "event": "JOIN_COMMITTED",
        "nextState": "CONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": "CAPI-S006",
        "capiDisposition": "JOINED",
        "localDisposition": "JOIN_COMMITTED"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": true,
        "event": "JOIN_NOT_COMMITTED",
        "nextState": "INVALID",
        "invalidPendingAfter": false,
        "capiScenario": "CAPI-S006",
        "capiDisposition": "NOT_COMMITTED",
        "localDisposition": "RECONCILED_NOT_COMMITTED_INVALID"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": true,
        "event": "JOIN_INDETERMINATE",
        "nextState": "RESERVED",
        "invalidPendingAfter": true,
        "capiScenario": "CAPI-S006",
        "capiDisposition": "INDETERMINATE",
        "localDisposition": "JOIN_INDETERMINATE_BLOCKED"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": true,
        "event": "RECONCILE_COMMITTED",
        "nextState": "CONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": "CAPI-S020",
        "capiDisposition": "RECONCILED_COMMITTED",
        "localDisposition": "RECONCILED_COMMITTED"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": true,
        "event": "RECONCILE_NOT_COMMITTED",
        "nextState": "INVALID",
        "invalidPendingAfter": false,
        "capiScenario": "CAPI-S021",
        "capiDisposition": "NOT_COMMITTED",
        "localDisposition": "RECONCILED_NOT_COMMITTED_INVALID"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": true,
        "event": "RECONCILE_INDETERMINATE",
        "nextState": "RESERVED",
        "invalidPendingAfter": true,
        "capiScenario": "CAPI-S024",
        "capiDisposition": "INDETERMINATE",
        "localDisposition": "RECONCILIATION_STILL_INDETERMINATE"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": true,
        "event": "EXPLICIT_INVALIDATE",
        "nextState": "RESERVED",
        "invalidPendingAfter": true,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "INVALIDATION_LATCHED"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": true,
        "event": "PROFILE_DRIFT_DETECTED",
        "nextState": "RESERVED",
        "invalidPendingAfter": true,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "INVALIDATION_LATCHED"
      },
      {
        "state": "RESERVED",
        "invalidPendingBefore": true,
        "event": "CORRUPTION_DETECTED",
        "nextState": "RESERVED",
        "invalidPendingAfter": true,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "INVALIDATION_LATCHED"
      },
      {
        "state": "CONSUMED",
        "invalidPendingBefore": false,
        "event": "RESTART",
        "nextState": "CONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "TERMINAL_CONSUMED"
      },
      {
        "state": "CONSUMED",
        "invalidPendingBefore": false,
        "event": "RESERVE_MATCHING_WELCOME",
        "nextState": "CONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": "CAPI-S007",
        "capiDisposition": "KEY_PACKAGE_ALREADY_CONSUMED",
        "localDisposition": "TERMINAL_CONSUMED"
      },
      {
        "state": "CONSUMED",
        "invalidPendingBefore": false,
        "event": "RESERVE_CONCURRENT_OR_REPEATED",
        "nextState": "CONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": "CAPI-S007",
        "capiDisposition": "KEY_PACKAGE_ALREADY_CONSUMED",
        "localDisposition": "TERMINAL_CONSUMED"
      },
      {
        "state": "CONSUMED",
        "invalidPendingBefore": false,
        "event": "JOIN_COMMITTED",
        "nextState": "CONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "TERMINAL_CONSUMED"
      },
      {
        "state": "CONSUMED",
        "invalidPendingBefore": false,
        "event": "JOIN_NOT_COMMITTED",
        "nextState": "CONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "TERMINAL_CONSUMED"
      },
      {
        "state": "CONSUMED",
        "invalidPendingBefore": false,
        "event": "JOIN_INDETERMINATE",
        "nextState": "CONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "TERMINAL_CONSUMED"
      },
      {
        "state": "CONSUMED",
        "invalidPendingBefore": false,
        "event": "RECONCILE_COMMITTED",
        "nextState": "CONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "TERMINAL_CONSUMED"
      },
      {
        "state": "CONSUMED",
        "invalidPendingBefore": false,
        "event": "RECONCILE_NOT_COMMITTED",
        "nextState": "CONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "TERMINAL_CONSUMED"
      },
      {
        "state": "CONSUMED",
        "invalidPendingBefore": false,
        "event": "RECONCILE_INDETERMINATE",
        "nextState": "CONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "TERMINAL_CONSUMED"
      },
      {
        "state": "CONSUMED",
        "invalidPendingBefore": false,
        "event": "EXPLICIT_INVALIDATE",
        "nextState": "CONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "TERMINAL_CONSUMED"
      },
      {
        "state": "CONSUMED",
        "invalidPendingBefore": false,
        "event": "PROFILE_DRIFT_DETECTED",
        "nextState": "CONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "TERMINAL_CONSUMED"
      },
      {
        "state": "CONSUMED",
        "invalidPendingBefore": false,
        "event": "CORRUPTION_DETECTED",
        "nextState": "CONSUMED",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "TERMINAL_CONSUMED"
      },
      {
        "state": "INVALID",
        "invalidPendingBefore": false,
        "event": "RESTART",
        "nextState": "INVALID",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "TERMINAL_INVALID"
      },
      {
        "state": "INVALID",
        "invalidPendingBefore": false,
        "event": "RESERVE_MATCHING_WELCOME",
        "nextState": "INVALID",
        "invalidPendingAfter": false,
        "capiScenario": "CAPI-S027",
        "capiDisposition": "WELCOME_NO_MATCHING_KEY_PACKAGE",
        "localDisposition": "TERMINAL_INVALID"
      },
      {
        "state": "INVALID",
        "invalidPendingBefore": false,
        "event": "RESERVE_CONCURRENT_OR_REPEATED",
        "nextState": "INVALID",
        "invalidPendingAfter": false,
        "capiScenario": "CAPI-S027",
        "capiDisposition": "WELCOME_NO_MATCHING_KEY_PACKAGE",
        "localDisposition": "TERMINAL_INVALID"
      },
      {
        "state": "INVALID",
        "invalidPendingBefore": false,
        "event": "JOIN_COMMITTED",
        "nextState": "INVALID",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "TERMINAL_INVALID"
      },
      {
        "state": "INVALID",
        "invalidPendingBefore": false,
        "event": "JOIN_NOT_COMMITTED",
        "nextState": "INVALID",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "TERMINAL_INVALID"
      },
      {
        "state": "INVALID",
        "invalidPendingBefore": false,
        "event": "JOIN_INDETERMINATE",
        "nextState": "INVALID",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "TERMINAL_INVALID"
      },
      {
        "state": "INVALID",
        "invalidPendingBefore": false,
        "event": "RECONCILE_COMMITTED",
        "nextState": "INVALID",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "TERMINAL_INVALID"
      },
      {
        "state": "INVALID",
        "invalidPendingBefore": false,
        "event": "RECONCILE_NOT_COMMITTED",
        "nextState": "INVALID",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "TERMINAL_INVALID"
      },
      {
        "state": "INVALID",
        "invalidPendingBefore": false,
        "event": "RECONCILE_INDETERMINATE",
        "nextState": "INVALID",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "TERMINAL_INVALID"
      },
      {
        "state": "INVALID",
        "invalidPendingBefore": false,
        "event": "EXPLICIT_INVALIDATE",
        "nextState": "INVALID",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "TERMINAL_INVALID"
      },
      {
        "state": "INVALID",
        "invalidPendingBefore": false,
        "event": "PROFILE_DRIFT_DETECTED",
        "nextState": "INVALID",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "TERMINAL_INVALID"
      },
      {
        "state": "INVALID",
        "invalidPendingBefore": false,
        "event": "CORRUPTION_DETECTED",
        "nextState": "INVALID",
        "invalidPendingAfter": false,
        "capiScenario": null,
        "capiDisposition": null,
        "localDisposition": "TERMINAL_INVALID"
      }
    ],
    "invalidPending": "Only RESERVED may set invalidPending. The flag is part of the row key and durable state: RESTART and INDETERMINATE preserve it; COMMITTED wins to CONSUMED; NOT_COMMITTED with the flag goes INVALID; NOT_COMMITTED without it returns UNCONSUMED."
  },
  "referenceValidation": [
    {
      "case": "single exact UNCONSUMED match in the bindingRef-resolved slot",
      "result": "reserve locally, then CAPI-S006 governs the join outcome"
    },
    {
      "case": "exact RESERVED match while adapter is RECONCILIATION_REQUIRED",
      "result": "CAPI-G019 RECONCILIATION_REQUIRED at P05"
    },
    {
      "case": "exact CONSUMED match",
      "result": "CAPI-S007 KEY_PACKAGE_ALREADY_CONSUMED"
    },
    {
      "case": "INVALID, unknown, forged, drifted, unmatched, cross-slot or ambiguous",
      "result": "CAPI-S027 WELCOME_NO_MATCHING_KEY_PACKAGE"
    },
    {
      "case": "AP adds local-reference semantic field",
      "result": "UNKNOWN_FIELD at P01"
    }
  ],
  "capiMappings": {
    "CAPI-E006": "bindingRef mismatch at P03; unchanged",
    "CAPI-G019": "new JOIN_WELCOME while reconciliation is required",
    "CAPI-S004": "authenticated restored complete-binding inconsistency",
    "CAPI-S006": "JOIN_WELCOME after local reservation; COMMITTED is JOINED, NOT_COMMITTED restores or invalidates according to durable invalidPending, INDETERMINATE remains RESERVED",
    "CAPI-S007": "consumed reuse",
    "CAPI-S020": "reconciled COMMITTED consumes exactly once",
    "CAPI-S021": "reconciled NOT_COMMITTED restores UNCONSUMED or applies durable invalidPending",
    "CAPI-S024": "reconciliation remains INDETERMINATE",
    "CAPI-S027": "no single eligible UNCONSUMED package in the resolved slot"
  },
  "vectors": [
    {
      "id": "BIND-KAT-001",
      "producer": "reference-encoder-a",
      "contextIdHex": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
      "secureSessionIdentityHex": "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
      "profileBytesHex": "01001a737479782d6d322d73657373696f6e2d616461707465722f76310200146d322d6f70617175652d62696e64696e672f763003000773657373696f6e0400036d6c7305000c746573742d70726f66696c6506001174776f2d6d656d6265722d64697265637407001409e92777dba0528d3d29e2e5e681b7e91637c7be080030737479782d6a732f76656e646f722f6f70656e6d6c732d7761736d2f6f70656e6d6c735f7761736d5f62672e7761736d090020fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e0a000200010b002c4d4c535f3132385f44484b454d5832353531395f41455331323847434d5f5348413235365f456432353531390c0020235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba070d000400000005",
      "canonicalBindingHex": "535459584d424e4400000100200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200200202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4003013201001a737479782d6d322d73657373696f6e2d616461707465722f76310200146d322d6f70617175652d62696e64696e672f763003000773657373696f6e0400036d6c7305000c746573742d70726f66696c6506001174776f2d6d656d6265722d64697265637407001409e92777dba0528d3d29e2e5e681b7e91637c7be080030737479782d6a732f76656e646f722f6f70656e6d6c732d7761736d2f6f70656e6d6c735f7761736d5f62672e7761736d090020fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e0a000200010b002c4d4c535f3132385f44484b454d5832353531395f41455331323847434d5f5348413235365f456432353531390c0020235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba070d000400000005",
      "canonicalBindingLength": 389,
      "canonicalBindingSha256": "b0960b281efff7e2fbc8a4c0aa406d9a32048d585d881d5bf5b93eeda480aba0",
      "expectedProfile": {
        "adapterApi": "styx-m2-session-adapter/v1",
        "bindingVersion": "m2-opaque-binding/v0",
        "logicalAdapter": "session",
        "physicalStore": "mls",
        "stage": "test-profile",
        "topology": "two-member-direct",
        "openMlsRevision": "09e92777dba0528d3d29e2e5e681b7e91637c7be",
        "wasmArtifactPath": "styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm",
        "wasmArtifactSha256": "fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e",
        "ciphersuiteIanaId": "0x0001",
        "ciphersuiteName": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "ss0DecisionsSha256": "235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07",
        "pastEpochWindow": 5
      }
    },
    {
      "id": "BIND-KAT-002",
      "producer": "reference-encoder-a",
      "contextIdHex": "4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60",
      "secureSessionIdentityHex": "6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80",
      "profileBytesHex": "01001a737479782d6d322d73657373696f6e2d616461707465722f76310200146d322d6f70617175652d62696e64696e672f763003000773657373696f6e0400036d6c7305000c746573742d70726f66696c6506001174776f2d6d656d6265722d64697265637407001409e92777dba0528d3d29e2e5e681b7e91637c7be080030737479782d6a732f76656e646f722f6f70656e6d6c732d7761736d2f6f70656e6d6c735f7761736d5f62672e7761736d090020fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e0a000200010b002c4d4c535f3132385f44484b454d5832353531395f41455331323847434d5f5348413235365f456432353531390c0020235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba070d000400000005",
      "canonicalBindingHex": "535459584d424e4400000100204142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f600200206162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8003013201001a737479782d6d322d73657373696f6e2d616461707465722f76310200146d322d6f70617175652d62696e64696e672f763003000773657373696f6e0400036d6c7305000c746573742d70726f66696c6506001174776f2d6d656d6265722d64697265637407001409e92777dba0528d3d29e2e5e681b7e91637c7be080030737479782d6a732f76656e646f722f6f70656e6d6c732d7761736d2f6f70656e6d6c735f7761736d5f62672e7761736d090020fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e0a000200010b002c4d4c535f3132385f44484b454d5832353531395f41455331323847434d5f5348413235365f456432353531390c0020235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba070d000400000005",
      "canonicalBindingLength": 389,
      "canonicalBindingSha256": "94fda7db9ebb262d72a4e43f679feab6421bd40ac3ce03067f69b2ca5ac111ad",
      "expectedProfile": {
        "adapterApi": "styx-m2-session-adapter/v1",
        "bindingVersion": "m2-opaque-binding/v0",
        "logicalAdapter": "session",
        "physicalStore": "mls",
        "stage": "test-profile",
        "topology": "two-member-direct",
        "openMlsRevision": "09e92777dba0528d3d29e2e5e681b7e91637c7be",
        "wasmArtifactPath": "styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm",
        "wasmArtifactSha256": "fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e",
        "ciphersuiteIanaId": "0x0001",
        "ciphersuiteName": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "ss0DecisionsSha256": "235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07",
        "pastEpochWindow": 5
      }
    },
    {
      "id": "BIND-KAT-003",
      "producer": "independent-encoder-b",
      "contextIdHex": "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f00f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
      "secureSessionIdentityHex": "aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55",
      "profileBytesHex": "01001a737479782d6d322d73657373696f6e2d616461707465722f76310200146d322d6f70617175652d62696e64696e672f763003000773657373696f6e0400036d6c7305000c746573742d70726f66696c6506001174776f2d6d656d6265722d64697265637407001409e92777dba0528d3d29e2e5e681b7e91637c7be080030737479782d6a732f76656e646f722f6f70656e6d6c732d7761736d2f6f70656e6d6c735f7761736d5f62672e7761736d090020fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e0a000200010b002c4d4c535f3132385f44484b454d5832353531395f41455331323847434d5f5348413235365f456432353531390c0020235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba070d000400000005",
      "canonicalBindingHex": "535459584d424e440000010020f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f00f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f020020aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa5503013201001a737479782d6d322d73657373696f6e2d616461707465722f76310200146d322d6f70617175652d62696e64696e672f763003000773657373696f6e0400036d6c7305000c746573742d70726f66696c6506001174776f2d6d656d6265722d64697265637407001409e92777dba0528d3d29e2e5e681b7e91637c7be080030737479782d6a732f76656e646f722f6f70656e6d6c732d7761736d2f6f70656e6d6c735f7761736d5f62672e7761736d090020fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e0a000200010b002c4d4c535f3132385f44484b454d5832353531395f41455331323847434d5f5348413235365f456432353531390c0020235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba070d000400000005",
      "canonicalBindingLength": 389,
      "canonicalBindingSha256": "12668f36719fa39bb132886e5b94165697a491ebb8608f1a6441a95114319205",
      "expectedProfile": {
        "adapterApi": "styx-m2-session-adapter/v1",
        "bindingVersion": "m2-opaque-binding/v0",
        "logicalAdapter": "session",
        "physicalStore": "mls",
        "stage": "test-profile",
        "topology": "two-member-direct",
        "openMlsRevision": "09e92777dba0528d3d29e2e5e681b7e91637c7be",
        "wasmArtifactPath": "styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm",
        "wasmArtifactSha256": "fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e",
        "ciphersuiteIanaId": "0x0001",
        "ciphersuiteName": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "ss0DecisionsSha256": "235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07",
        "pastEpochWindow": 5
      }
    }
  ],
  "negativeCases": [
    {
      "id": "NEG-GRAMMAR-WRONG-MAGIC",
      "class": "encoding",
      "expected": "MALFORMED_BINDING",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "replace-byte",
          "offset": 0,
          "valueHex": "00"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-GRAMMAR-UNKNOWN-VERSION",
      "class": "encoding",
      "expected": "MALFORMED_BINDING",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "replace-range",
          "offset": 8,
          "length": 2,
          "valueHex": "0001"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-GRAMMAR-UNKNOWN-TAG",
      "class": "encoding",
      "expected": "MALFORMED_BINDING",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "replace-byte",
          "offset": 10,
          "valueHex": "04"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-GRAMMAR-MISSING-FIELD",
      "class": "encoding",
      "expected": "MALFORMED_BINDING",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "remove-outer-field",
          "tag": 2
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-GRAMMAR-DUPLICATE-FIELD",
      "class": "encoding",
      "expected": "MALFORMED_BINDING",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "duplicate-outer-field",
          "tag": 1,
          "insertBeforeTag": 2
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-GRAMMAR-REORDERED-FIELD",
      "class": "encoding",
      "expected": "MALFORMED_BINDING",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "swap-outer-fields",
          "firstTag": 1,
          "secondTag": 2
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-GRAMMAR-TRUNCATED",
      "class": "encoding",
      "expected": "MALFORMED_BINDING",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "truncate",
          "length": 388
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-GRAMMAR-TRAILING",
      "class": "encoding",
      "expected": "MALFORMED_BINDING",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "append",
          "valueHex": "00"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-GRAMMAR-LENGTH-UNDERFLOW",
      "class": "encoding",
      "expected": "MALFORMED_BINDING",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "replace-range",
          "offset": 11,
          "length": 2,
          "valueHex": "001f"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-GRAMMAR-LENGTH-OVERFLOW",
      "class": "encoding",
      "expected": "MALFORMED_BINDING",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "replace-range",
          "offset": 11,
          "length": 2,
          "valueHex": "0021"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-GRAMMAR-WRONG-ENDIAN",
      "class": "encoding",
      "expected": "MALFORMED_BINDING",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "replace-range",
          "offset": 11,
          "length": 2,
          "valueHex": "2000"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-GRAMMAR-NONASCII",
      "class": "encoding",
      "expected": "MALFORMED_BINDING",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "replace-profile-value-byte",
          "profileTag": 1,
          "valueOffset": 0,
          "valueHex": "ff"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-GRAMMAR-NUL-SUFFIX",
      "class": "encoding",
      "expected": "MALFORMED_BINDING",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "append-profile-value-byte",
          "profileTag": 1,
          "valueHex": "00"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-GRAMMAR-ZERO-CONTEXT",
      "class": "encoding",
      "expected": "MALFORMED_BINDING",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "zero-outer-value",
          "tag": 1
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-GRAMMAR-ZERO-SESSION",
      "class": "encoding",
      "expected": "MALFORMED_BINDING",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "zero-outer-value",
          "tag": 2
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-CONTEXT-SWAP",
      "class": "inequality",
      "expected": "BINDING_MISMATCH",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "replace-outer-value",
          "tag": 1,
          "sourceVector": "BIND-KAT-002",
          "sourceComponent": "contextIdHex"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-SESSION-SWAP",
      "class": "inequality",
      "expected": "AUTHENTICATED_STATE_INCONSISTENT",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "replace-outer-value",
          "tag": 2,
          "sourceVector": "BIND-KAT-002",
          "sourceComponent": "secureSessionIdentityHex"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-PROFILE-01",
      "class": "profile-inequality",
      "expected": "UNSUPPORTED_PROFILE",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "flip-profile-value-bit",
          "profileTag": 1,
          "valueOffset": 0,
          "bitMaskHex": "01"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-PROFILE-02",
      "class": "profile-inequality",
      "expected": "UNSUPPORTED_PROFILE",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "flip-profile-value-bit",
          "profileTag": 2,
          "valueOffset": 0,
          "bitMaskHex": "01"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-PROFILE-03",
      "class": "profile-inequality",
      "expected": "UNSUPPORTED_PROFILE",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "flip-profile-value-bit",
          "profileTag": 3,
          "valueOffset": 0,
          "bitMaskHex": "01"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-PROFILE-04",
      "class": "profile-inequality",
      "expected": "UNSUPPORTED_PROFILE",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "flip-profile-value-bit",
          "profileTag": 4,
          "valueOffset": 0,
          "bitMaskHex": "01"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-PROFILE-05",
      "class": "profile-inequality",
      "expected": "UNSUPPORTED_PROFILE",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "flip-profile-value-bit",
          "profileTag": 5,
          "valueOffset": 0,
          "bitMaskHex": "01"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-PROFILE-06",
      "class": "profile-inequality",
      "expected": "UNSUPPORTED_PROFILE",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "flip-profile-value-bit",
          "profileTag": 6,
          "valueOffset": 0,
          "bitMaskHex": "01"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-PROFILE-07",
      "class": "profile-inequality",
      "expected": "UNSUPPORTED_PROFILE",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "flip-profile-value-bit",
          "profileTag": 7,
          "valueOffset": 0,
          "bitMaskHex": "01"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-PROFILE-08",
      "class": "profile-inequality",
      "expected": "UNSUPPORTED_PROFILE",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "flip-profile-value-bit",
          "profileTag": 8,
          "valueOffset": 0,
          "bitMaskHex": "01"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-PROFILE-09",
      "class": "profile-inequality",
      "expected": "UNSUPPORTED_PROFILE",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "flip-profile-value-bit",
          "profileTag": 9,
          "valueOffset": 0,
          "bitMaskHex": "01"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-PROFILE-10",
      "class": "profile-inequality",
      "expected": "UNSUPPORTED_PROFILE",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "flip-profile-value-bit",
          "profileTag": 10,
          "valueOffset": 0,
          "bitMaskHex": "01"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-PROFILE-11",
      "class": "profile-inequality",
      "expected": "UNSUPPORTED_PROFILE",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "flip-profile-value-bit",
          "profileTag": 11,
          "valueOffset": 0,
          "bitMaskHex": "01"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-PROFILE-12",
      "class": "profile-inequality",
      "expected": "UNSUPPORTED_PROFILE",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "flip-profile-value-bit",
          "profileTag": 12,
          "valueOffset": 0,
          "bitMaskHex": "01"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-PROFILE-13",
      "class": "profile-inequality",
      "expected": "UNSUPPORTED_PROFILE",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "flip-profile-value-bit",
          "profileTag": 13,
          "valueOffset": 0,
          "bitMaskHex": "01"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-KP-DUPLICATE-PUBLIC",
      "class": "key-package-alias",
      "expected": "INVALID",
      "fixture": {
        "base": "closed-key-package-model/v0",
        "operation": {
          "kind": "construct-second-record",
          "baselineState": "UNCONSUMED",
          "reuseField": "publicBytes"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-KP-DUPLICATE-PRIVATE",
      "class": "key-package-alias",
      "expected": "INVALID",
      "fixture": {
        "base": "closed-key-package-model/v0",
        "operation": {
          "kind": "construct-second-record",
          "baselineState": "UNCONSUMED",
          "reuseField": "privateBundle"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-KP-DUPLICATE-SIGNATURE-KEY",
      "class": "key-package-alias",
      "expected": "INVALID",
      "fixture": {
        "base": "closed-key-package-model/v0",
        "operation": {
          "kind": "construct-second-record",
          "baselineState": "UNCONSUMED",
          "reuseField": "signatureKey"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-KP-DUPLICATE-INIT-KEY",
      "class": "key-package-alias",
      "expected": "INVALID",
      "fixture": {
        "base": "closed-key-package-model/v0",
        "operation": {
          "kind": "construct-second-record",
          "baselineState": "UNCONSUMED",
          "reuseField": "initKey"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-KP-DUPLICATE-REFERENCE",
      "class": "key-package-alias",
      "expected": "INVALID",
      "fixture": {
        "base": "closed-key-package-model/v0",
        "operation": {
          "kind": "construct-second-record",
          "baselineState": "UNCONSUMED",
          "reuseField": "localReference"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-KP-CROSS-CONTEXT",
      "class": "key-package-alias",
      "expected": "INVALID",
      "fixture": {
        "base": "closed-key-package-model/v0",
        "operation": {
          "kind": "construct-second-record",
          "baselineState": "UNCONSUMED",
          "reuseField": "logicalIdentity",
          "changeField": "contextId"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-KP-CROSS-PROFILE",
      "class": "key-package-alias",
      "expected": "INVALID",
      "fixture": {
        "base": "closed-key-package-model/v0",
        "operation": {
          "kind": "construct-second-record",
          "baselineState": "UNCONSUMED",
          "reuseField": "logicalIdentity",
          "changeField": "profile"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-KP-CONCURRENT-RESERVATION",
      "class": "lifecycle",
      "expected": "WELCOME_NO_MATCHING_KEY_PACKAGE",
      "fixture": {
        "base": "closed-key-package-model/v0",
        "operation": {
          "kind": "reserve",
          "initialState": "RESERVED",
          "reference": "reference-a"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-KP-REUSED-CONSUMED",
      "class": "lifecycle",
      "expected": "KEY_PACKAGE_ALREADY_CONSUMED",
      "fixture": {
        "base": "closed-key-package-model/v0",
        "operation": {
          "kind": "reserve",
          "initialState": "CONSUMED",
          "reference": "reference-a"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-KP-FORGED-REFERENCE",
      "class": "reference",
      "expected": "WELCOME_NO_MATCHING_KEY_PACKAGE",
      "fixture": {
        "base": "closed-key-package-model/v0",
        "operation": {
          "kind": "welcome-match",
          "slot": "slot-a",
          "reference": "forged-reference",
          "records": [
            {
              "slot": "slot-a",
              "reference": "reference-a",
              "state": "UNCONSUMED"
            }
          ]
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-KP-UNMATCHED-REFERENCE",
      "class": "reference",
      "expected": "WELCOME_NO_MATCHING_KEY_PACKAGE",
      "fixture": {
        "base": "closed-key-package-model/v0",
        "operation": {
          "kind": "welcome-match",
          "slot": "slot-a",
          "reference": "reference-b",
          "records": [
            {
              "slot": "slot-a",
              "reference": "reference-a",
              "state": "UNCONSUMED"
            }
          ]
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-KP-DRIFTED-REFERENCE",
      "class": "reference",
      "expected": "WELCOME_NO_MATCHING_KEY_PACKAGE",
      "fixture": {
        "base": "closed-key-package-model/v0",
        "operation": {
          "kind": "welcome-match",
          "slot": "slot-a",
          "reference": "reference-a-drifted",
          "records": [
            {
              "slot": "slot-a",
              "reference": "reference-a",
              "state": "UNCONSUMED"
            }
          ]
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-KP-APPLICATION-REFERENCE-FIELD",
      "class": "reference",
      "expected": "UNKNOWN_FIELD",
      "fixture": {
        "base": "closed-key-package-model/v0",
        "operation": {
          "kind": "validate-request-fields",
          "fields": [
            "operation",
            "bindingRef",
            "requestId",
            "keyPackageReference"
          ]
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-KP-RELEASE-BEFORE-DURABLE",
      "class": "issuance",
      "expected": "NO_OUTPUT",
      "fixture": {
        "base": "closed-key-package-model/v0",
        "operation": {
          "kind": "issuance-release",
          "commitOutcome": "INDETERMINATE"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-KP-BOUND-EXCEEDED",
      "class": "issuance",
      "expected": "NO_OUTPUT",
      "fixture": {
        "base": "closed-key-package-model/v0",
        "operation": {
          "kind": "issuance-start",
          "existingStates": [
            "UNCONSUMED"
          ]
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-KP-LAST-RESORT",
      "class": "content",
      "expected": "REJECTED",
      "fixture": {
        "base": "closed-key-package-model/v0",
        "operation": {
          "kind": "validate-key-package-content",
          "lastResort": true,
          "ciphersuite": "0x0001",
          "credentialIdentitySource": "ss-random"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-KP-FOREIGN-SUITE",
      "class": "content",
      "expected": "UNSUPPORTED_ONBOARDING",
      "fixture": {
        "base": "closed-key-package-model/v0",
        "operation": {
          "kind": "validate-key-package-content",
          "lastResort": false,
          "ciphersuite": "0x0002",
          "credentialIdentitySource": "ss-random"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-KP-APPLICATION-IDENTITY",
      "class": "content",
      "expected": "REJECTED",
      "fixture": {
        "base": "closed-key-package-model/v0",
        "operation": {
          "kind": "validate-key-package-content",
          "lastResort": false,
          "ciphersuite": "0x0001",
          "credentialIdentitySource": "application"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-LIFECYCLE-MISSING-ROW",
      "class": "lifecycle-schema",
      "expected": "MODEL_REJECTED",
      "fixture": {
        "base": "lifecycle.rows",
        "operation": {
          "kind": "remove-row",
          "rowKey": {
            "state": "UNCONSUMED",
            "invalidPendingBefore": false,
            "event": "RESTART"
          }
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-LIFECYCLE-DUPLICATE-ROW",
      "class": "lifecycle-schema",
      "expected": "MODEL_REJECTED",
      "fixture": {
        "base": "lifecycle.rows",
        "operation": {
          "kind": "duplicate-row",
          "rowKey": {
            "state": "UNCONSUMED",
            "invalidPendingBefore": false,
            "event": "RESTART"
          }
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-LIFECYCLE-OVERLAPPING-ROW",
      "class": "lifecycle-schema",
      "expected": "MODEL_REJECTED",
      "fixture": {
        "base": "lifecycle.rows",
        "operation": {
          "kind": "append-conflicting-row",
          "rowKey": {
            "state": "UNCONSUMED",
            "invalidPendingBefore": false,
            "event": "RESTART"
          },
          "replacementDisposition": "INVALIDATED"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-BINDINGREF-WRONG-LENGTH-EMPTY",
      "class": "binding-reference",
      "expected": "CAPI-E006",
      "fixture": {
        "base": "closed-key-package-model/v0",
        "operation": {
          "kind": "validate-binding-ref",
          "slotState": "EMPTY",
          "registeredHex": "0101010101010101010101010101010101010101010101010101010101010101",
          "suppliedHex": "01010101010101010101010101010101010101010101010101010101010101"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-BINDINGREF-UNKNOWN-ACTIVE",
      "class": "binding-reference",
      "expected": "CAPI-E006",
      "fixture": {
        "base": "closed-key-package-model/v0",
        "operation": {
          "kind": "validate-binding-ref",
          "slotState": "ACTIVE",
          "registeredHex": "0101010101010101010101010101010101010101010101010101010101010101",
          "suppliedHex": "0202020202020202020202020202020202020202020202020202020202020202"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-BINDINGREF-CROSS-CONTEXT-RECONCILIATION",
      "class": "binding-reference",
      "expected": "CAPI-E006",
      "fixture": {
        "base": "closed-key-package-model/v0",
        "operation": {
          "kind": "validate-binding-ref",
          "slotState": "RECONCILIATION_REQUIRED",
          "registeredHex": "0101010101010101010101010101010101010101010101010101010101010101",
          "suppliedHex": "0202020202020202020202020202020202020202020202020202020202020202"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-OUTER-VERSION-SWAP",
      "class": "inequality",
      "expected": "MALFORMED_BINDING",
      "fixture": {
        "base": "BIND-KAT-001",
        "operation": {
          "kind": "replace-range",
          "offset": 8,
          "length": 2,
          "valueHex": "0001"
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    },
    {
      "id": "NEG-WELCOME-CROSS-CONTEXT-SLOT",
      "class": "reference",
      "expected": "WELCOME_NO_MATCHING_KEY_PACKAGE",
      "fixture": {
        "base": "closed-key-package-model/v0",
        "operation": {
          "kind": "welcome-match",
          "slot": "slot-a",
          "reference": "reference-b",
          "records": [
            {
              "slot": "slot-b",
              "reference": "reference-b",
              "state": "UNCONSUMED"
            }
          ]
        },
        "determinism": "literal-only; no clock, randomness, environment or unordered iteration"
      }
    }
  ],
  "nonClaims": [
    "application identity, role, authority, conformance or semantics",
    "transport identifier, transport or delivery",
    "freshness or expiry beyond MLS operational lifetime checking",
    "coherent whole-profile rollback prevention",
    "legacy import, fallback or downgrade",
    "persisted layout, AAD, keyed-root coverage, HKDF labels or key versions",
    "transaction mechanics",
    "Issue #312 extension",
    "arbitrary or general topology",
    "public SDK",
    "frozen WASM feasibility",
    "production activation"
  ],
  "deferredContracts": {
    "C-FMT": [
      "persisted layout",
      "AAD",
      "keyed-root coverage",
      "HKDF labels",
      "key versions"
    ],
    "C-MUT": [
      "transaction mechanics",
      "physical atomicity"
    ],
    "F-WASM": [
      "artifact feasibility"
    ]
  },
  "ratificationGate": "C-FMT, O-SCEN and dependent implementation remain blocked until owner ratifies this exact document SHA-256"
}
```
<!-- styx-m2-binding-v0-json:end -->
