# M2 fail-closed restore compatibility contract

Status: normative candidate for C-REST under Issue #332. Exact final document and external evidence-bundle hashes require separate owner ratification before C-REC, O-SCEN, or implementation.

## 1. Scope and normative force

This document defines the closed restore decision for the exact ratified C-FMT input identified below. **MUST**, **MUST NOT**, **REJECT**, and the codes in §10 are normative. The single JSON record in §14 is closed and normative; prose explains it but adds no version, algorithm, build, encoding, authority, result, failure, or recovery path. Unknown, missing, duplicate, reordered, extra, or overlapping members and entries reject, including duplicate JSON member names.

It specifies no restore implementation, transaction, migration, rewrite, repair, compaction, deletion, cleanup, reset execution, recovery UI, or output release. It changes no C-FMT byte, key, label, version, record, binding, mutation, retention, or authority rule.

## 2. Frozen input

The only format authority is `docs/architecture/m2/storage-format.md` at `96a358cc64cf6fd76c5bbf61bd7a65f8fde9d471`, SHA-256 `b57df3a8f5dac9cc9f11702fe55d9badf9f98683e3dd7ac03aa81b8fa7932812`, re-ratified in Issue #327 comment `5898801523`. Its external evidence bundle is cited only as SHA-256 `d9bf475926e54f1221b15a9574185b81a09af1631fdaa722ef94ea969876ae3e`; access is not required. The input remains external and read-only. Drift is BLOCK.

The exact readable profile is the conjunction copied under `compatibilityRegistry`: all eight versions, algorithms and widths, big-endian integers, framing and zero-salt rules, four 32-byte HKDF outputs, magic/domain/label strings, key/envelope/AAD/plaintext/manifest/selector grammar, all 17 kind IDs and versions, bounds, registries, mappings, generation rules, crash boundaries, vectors, negative classes, and non-claims. ProductProfile is exactly 306 bytes as stated by C-FMT; its layout remains C-BIND-owned and is not independently accepted here. Compatibility is equality, never a range, minimum, semver rule, downgrade, or partial recognition. Unknown, future, missing, mixed, or downgraded versions are `UNSUPPORTED_VERSION`; other profile mismatches are `INCOMPATIBLE_FORMAT`.

## 3. Build eligibility

Byte validity and build eligibility are separate. Before reading any stored M2 or legacy byte, the one-writer Web Lock MUST be held and one complete `buildMatrix` row MUST match. Each row binds the C-FMT digest, all eight versions, OpenMLS revision, WASM path and digest, SS-0 IANA ID and name, Gate-A decisions digest, and browser/runtime class. Chromium and Firefox standard non-private, non-evicted browser profiles are the only listed classes. Mobile, native non-browser, private-browsing, and evicted/partial profiles are not eligible. No flag, acknowledgement, diagnostic override, or partly matching row widens the matrix. Any M2 store on an ineligible build is `INCOMPATIBLE_BUILD`, untouched, before unlock or decode, with compatible-build guidance.

## 4. Ordered restore decision

The phases in `phaseOrder` execute in exactly that order. A phase cannot expose plaintext, provider state, escrow, output, or authority. Any failure stops all later phases. Only `EXPOSE`, after every gate succeeds, may expose selected authority. Failure precedence is phase order, then the unique `faultPrecedence` row; physical enumeration order is irrelevant. Ambiguous, truncated, contradictory, or unexpected evidence resolves to the applicable closed failure or `INTERNAL_VALIDATION_FAILED`, never success, empty, legacy-only, fallback, or repair.

Unauthenticated selector-header inspection may distinguish a closed unsupported version from other structural incompatibility, but trusts no value. Wrapper failure precedes all such distinctions and cannot become a record oracle. Authenticated version compatibility precedes other profile, manifest, and record checks. Authentication failure is reported only after the relevant structure was safely identified by an earlier authenticated binding or fixed grammar.

## 5. Inventory, absence, and authority

`NO_M2_STATE` requires absence of every M2 fixed locator and every generation artifact under the closed inventory. It is unauthenticated and claims no freshness, non-deletion, or rollback prevention. `LEGACY_ONLY` requires the same M2 absence and separately observed legacy presence. `EMPTY` is not absence: `RESTORED_EMPTY` requires the authenticated fixed selector and the exact complete C-FMT EMPTY generation.

Exactly one authenticated selector at the fixed `STYXSEL1` locator chooses authority. Restore MUST NOT scan generations, compare counters or timestamps, choose the newest/highest/decryptable/most-complete object, fall back to an older generation, or use an unselected generation as repair material. A selector without its exact generation, orphan records, multiple selector candidates, and partial generations fail closed.

## 6. Complete-generation validation

The named manifest envelope, canonical manifest, manifest-key digest, manifest ciphertext digest, keyed root, ordered unique complete data set, every record envelope/AAD, canonical decode/re-encode, key/kind/version/scope/context/profile/write-generation relation, canonical tombstone, binding, and cross-record reference MUST all validate. Selector `selectedGeneration`, rooted manifest generation, and every authoritative data/manifest record write generation MUST agree. The selector envelope's own write generation and mutation identity need not equal the selected generation.

Missing, extra, duplicate, reordered, substituted, cross-context, cross-session, cross-profile, historical-subset, partial, forged, or invalid-lifecycle evidence exposes nothing. C-FMT's exact KeyPackage, result, escrow, hold, component, selection, retained-parent, losing-candidate, replay, binding, and absence rules remain controlling.

## 7. Reconciliation candidate and physical parent

For `RECONCILIATION_REQUIRED`, selected authority remains the authenticated original generation. Its selected `MUTATION_HOLD` is the canonical tombstone. The authenticated selector's encrypted `candidateManifestKey` is the sole candidate locator. It MUST parse as the exact canonical kind-16 manifest key with empty object ID; its context and generation MUST match the fixed locator and `candidateGeneration`; its SHA-256, manifest ciphertext digest, and candidate keyed root MUST match the authenticated selector tuple; the located candidate manifest binding digest MUST match that candidate generation's own `BINDING_PROFILE`. No enumeration, timestamp, counter, or inference may locate it.

The located candidate is a complete immutable unselected generation. Its `MUTATION_HOLD`, `COMMIT_RESULT`, `OUTPUT_ESCROW`, and `COMPONENT_SET` carry the hold/result/escrow facts identified by C-FMT. For an unresolved hold with `INDETERMINATE`, `parentGeneration` and `parentKeyedRoot` MUST equal the selector's selected generation and keyed root: this is the physical-parent relation. The hold/result `originalAuthorityDigest` and `originalAuthorityReference` MUST match each other but are logical identifiers and MUST NOT be compared to the physical parent. Terminal holds follow C-MUT and are not compared to a selector that moved. The candidate never becomes authority or repair input. Restore neither retries nor releases escrow; even committed escrow is not emitted merely because it was restored.

## 8. Legacy separation and guidance

Legacy inventory is disjoint. Legacy envelopes, ciphersuites, identifiers, records, and provider states are never decoded as M2, compared against selected SS-0, copied into M2, or used as fallback. Valid M2 plus legacy uses the M2 result with `LEGACY_PRESENT`; invalid M2 plus legacy keeps the M2 failure with that flag. All bytes remain preserved and visible re-establishment guidance may be shown. The legacy shipping ciphersuite at an M2 locator is rejected as incompatible legacy-shaped M2 input without comparing it to SS-0.

Compatible-build guidance identifies reader profile `CFMT_EXACT_B57DF3A8` and preserves bytes. Destructive reset is separate, explicit, irreversible, never automatic, and not performed here. Password change only re-wraps the same Root Storage Key and is not migration or repair.

## 9. Corruption, diagnostics, and immutability

Corruption handling is preserve-and-stop. Restore MUST NOT delete, move, rewrite, normalize, regenerate, rebuild, clear a hold, consume/invalidate a KeyPackage, discard escrow, mark legacy invalid, select fallback, or initiate reset. Logical read-disable is permitted; physical quarantine is not authorized here.

Diagnostics expose only the allowlisted stage/reason codes and counts and `legacyPresent`. They never expose keys, nonces, plaintext, binding bytes, context/session IDs, package references, digests, record keys, or escrow. Every restore attempt is byte-preserving and repeatable; repetition cannot change classification or inputs.

## 10. Closed outcomes

Inventory outcomes are exactly `NO_M2_STATE` and `LEGACY_ONLY`. Authenticated successes are exactly `RESTORED_EMPTY`, `RESTORED_ACTIVE`, and `RESTORED_RECONCILIATION_REQUIRED`. Failures are exactly the thirteen values in `resultSets.failure`. `LEGACY_PRESENT` is only a condition attached to the applicable M2 success or failure. These sets are disjoint and total under `failureDefault`.

## 11. Freshness and rollback limit

Authentication proves consistency, not freshness. Counters, timestamps, AEAD, compatible-build checks, and surviving coarse anchors are not rollback prevention. Some regressions may be noticed, but coherent replay of a complete same-key browser profile—including wrapper, selector, and anchors—can restore successfully and remain undetectable.

## 12. Fixtures and executable interpretation

The positive fixtures bind absence, legacy-only, and the four exact C-FMT vectors, including both active-parent and empty-parent reconciliation. The M2-plus-legacy fixture adds only `LEGACY_PRESENT`. Negative fixtures cover every failure and boundary named by Issue #332. `mutationCoverage` and `crashCoverage` are exhaustive obligations, not implementation claims.

The external validator parses both records with duplicate rejection, checks exact copied C-FMT coverage, mutates every listed compatibility family, runs all fixtures and crash cases through two independently structured models, combines every pair of faults, permutes enumeration order, and hashes inputs before and after. A fixture proves only this abstract contract model—not IndexedDB, product implementation, browser parity, lock behavior, recovery UX, or production readiness.

## 13. Non-claims and ratification

This contract makes no implementation, freshness, rollback-prevention, physical-erasure, zeroization, delivery, application-identity, production-readiness, arbitrary-topology, browser-parity, migration, legacy-cleanup, forgotten-password-recovery, or recovery-success claim. Final literal document and deterministic external bundle SHA-256 values must be recorded externally and separately ratified. Any byte change voids review and ratification.

## 14. Machine-readable normative record

<!-- styx-m2-restore-json:v1:start -->
```json
{
  "schema": "styx-m2-restore-compatibility/v1",
  "closed": true,
  "status": "PENDING_EXTERNAL_HASH_RATIFICATION",
  "validation": {
    "unknownMissingDuplicateReorderedOrOverlapping": "REJECT",
    "duplicateJsonMembers": "REJECT",
    "proseAddsAcceptedValue": false,
    "exactConjunction": true,
    "unexpectedSkip": "FAIL"
  },
  "provenance": {
    "issue": 332,
    "card": "C-REST",
    "exactBase": "e1538ef9c070e463a8256872a3fd0882c424e2ef",
    "cFmtCommit": "96a358cc64cf6fd76c5bbf61bd7a65f8fde9d471",
    "cFmtPath": "docs/architecture/m2/storage-format.md",
    "cFmtSha256": "b57df3a8f5dac9cc9f11702fe55d9badf9f98683e3dd7ac03aa81b8fa7932812",
    "cFmtEvidenceBundleSha256": "d9bf475926e54f1221b15a9574185b81a09af1631fdaa722ef94ea969876ae3e"
  },
  "compatibilityRegistry": {
    "versions": {
      "format": 1,
      "envelope": 1,
      "recordKey": 1,
      "plaintext": 1,
      "manifest": 1,
      "keySchedule": 1,
      "upstreamBinding": 0,
      "upstreamMutationTable": 1
    },
    "algorithms": {
      "recordAead": "AES-256-GCM",
      "nonceBytes": 12,
      "tagBytes": 16,
      "hash": "SHA-256",
      "mac": "HMAC-SHA-256",
      "kdf": "HKDF-SHA-256",
      "integerEndian": "big"
    },
    "rootStorageKey": {
      "bytes": 32,
      "source": "worker CSPRNG",
      "passwordDirectlyEncryptsRecords": false,
      "wrapper": "existing styx-vault-wrapper version 1 A256GCM under password-derived Argon2id KEK",
      "passwordChange": "atomically re-wrap same Root Storage Key; no record re-encryption"
    },
    "keySchedule": {
      "frame": "u32be(length)||bytes",
      "productProfileDigest": "SHA-256(\"STYX-M2-PROFILE-DIGEST-V1\" || frame(exact 306-byte ProductProfile))",
      "stages": [
        {
          "purpose": "namespace",
          "ikm": "Root Storage Key[32]",
          "salt": "SHA-256(\"styx/m2/fmt/v1/salt\" || frame(localContextId) || frame(productProfileDigest))",
          "info": "ASCII \"styx/m2/fmt/v1/namespace\" || u16be(1) || frame(localContextId) || frame(productProfileDigest)",
          "outputBytes": 32
        },
        {
          "purpose": "recordAead",
          "ikm": "K_namespace[32]",
          "salt": "32 zero bytes",
          "info": "ASCII \"styx/m2/fmt/v1/record-aead\" || u16be(1) || frame(complete canonical record key)",
          "outputBytes": 32
        },
        {
          "purpose": "manifestRoot",
          "ikm": "K_namespace[32]",
          "salt": "32 zero bytes",
          "info": "ASCII \"styx/m2/fmt/v1/manifest-root\" || u16be(1) || frame(localContextId) || frame(productProfileDigest)",
          "outputBytes": 32
        },
        {
          "purpose": "selectorAead",
          "ikm": "K_namespace[32]",
          "salt": "32 zero bytes",
          "info": "ASCII \"styx/m2/fmt/v1/selector-aead\" || u16be(1) || frame(fixed selector key)",
          "outputBytes": 32
        }
      ],
      "labels": [
        {
          "purpose": "namespace",
          "ascii": "styx/m2/fmt/v1/namespace",
          "outputBytes": 32
        },
        {
          "purpose": "recordAead",
          "ascii": "styx/m2/fmt/v1/record-aead",
          "outputBytes": 32
        },
        {
          "purpose": "manifestRoot",
          "ascii": "styx/m2/fmt/v1/manifest-root",
          "outputBytes": 32
        },
        {
          "purpose": "selectorAead",
          "ascii": "styx/m2/fmt/v1/selector-aead",
          "outputBytes": 32
        }
      ],
      "unknownKeyVersion": "REJECT"
    },
    "nonce": {
      "construction": "fresh 96-bit worker CSPRNG output on every encryption under a derived AEAD key; no counter and no value derived solely from persisted state",
      "perKeyWriteBound": 1000000,
      "randomCollisionUpperBound": "q*(q-1)/2^97; at q=1000000, less than 2^-57",
      "runtimeDuplicateCheck": "reject a duplicate observed within the live unlocked key namespace",
      "rollbackCaveat": "coherent profile rollback can rewind any persisted duplicate set; uniqueness relies on fresh CSPRNG entropy, not persisted state",
      "vectorsUseLiteralNonces": true,
      "reuseNegativeCase": "NEG-NONCE-REUSE"
    },
    "recordKeyGrammar": {
      "bytes": "ASCII STYXKEY1 || u16be(version=1) || scope:u8 || localContextId[32] || (secureSessionIdentity[32] iff scope=SESSION) || writeGeneration:u64be || recordKind:u16be || objectIdLength:u8 || objectId",
      "selectorFixedLocator": "ASCII STYXSEL1 || u16be(version=1) || localContextId[32]; exactly one locator for the profile lifetime, independent of session and generation",
      "scope": {
        "CONTEXT_PRESESSION": 1,
        "SESSION": 2
      },
      "localContextIdPositionCount": 1,
      "forbiddenAsKeyMaterial": [
        "raw MLS Group ID outside canonical session position",
        "raw local KeyPackage reference",
        "private or secret material"
      ],
      "objectId": "for data kinds 1..15: first 16 bytes of SHA-256(\"STYX-OBJECT-ID-V1\" || frame(localContextId) || frame(recordKind ASCII name)); for the singleton MANIFEST kind 16: objectIdLength=0 and objectId is empty; never a C-BIND logical reference or digest reinterpreted as identity",
      "reject": [
        "unknown scope/version/kind",
        "zero context",
        "missing or placeholder session",
        "session bytes in pre-session scope",
        "generation zero for data/manifest/selected selector/candidate selector",
        "noncanonical object-id length for its kind",
        "trailing bytes"
      ]
    },
    "envelope": {
      "magicHex": "53545958464d5431",
      "fields": [
        "magic[8]",
        "envelopeVersion:u16be",
        "recordKind:u16be",
        "recordKindVersion:u16be",
        "formatVersion:u16be",
        "keyVersion:u16be",
        "aeadId:u16be=1",
        "recordKeyLength:u16be",
        "aadLength:u32be",
        "plaintextLength:u32be",
        "ciphertextLength:u32be",
        "tagLength:u16be=16",
        "recordKey",
        "aad",
        "nonce[12]",
        "ciphertext",
        "tag[16]"
      ],
      "ciphertextLengthExcludesTag": true,
      "reject": [
        "unknown version/algorithm/kind",
        "wrong field order or width",
        "non-minimal or inconsistent length",
        "truncation",
        "trailing bytes",
        "size overflow",
        "plaintext length mismatch",
        "authentication failure"
      ],
      "decodeEncodeByteIdentical": true
    },
    "aad": {
      "bytes": "ASCII STYXAAD1 || formatVersion:u16be || envelopeVersion:u16be || recordKind:u16be || recordKindVersion:u16be || keyVersion:u16be || frame(canonicalRecordKey) || localContextId[32] || productProfileDigest[32] || scope:u8 || sessionDomain || writeGeneration:u64be || mutationIdentity[32] || plaintextLength:u32be",
      "sessionDomain": "secureSessionIdentity[32] || SHA-256(\"STYX-M2-BINDING-DIGEST-V1\" || frame(complete 389-byte C-BIND)) for SESSION; empty for CONTEXT_PRESESSION",
      "preSession": "scope discriminator 1 and no zero or placeholder session bytes",
      "selectorRead": "the fixed selector key is found from localContextId; its complete stored AAD is authenticated, then session/binding bytes are cross-checked against the selected generation before authority is accepted",
      "readSource": "for data and manifest records, key, context, profile, session/binding and generation/mutation are expected by caller/manifest; only the fixed selector uses selectorRead"
    },
    "plaintextFrame": {
      "bytes": "ASCII STYXPLN1 || plaintextVersion:u16be || recordKind:u16be || presence:u8 || fieldCount:u16be || ordered fields(tag:u8 || length:u32be || value[length])",
      "presence": {
        "PRESENT": 1,
        "TOMBSTONE_ABSENT": 0
      },
      "tombstoneRule": "presence=0 requires fieldCount=0 and no trailing bytes; presence=1 requires the exact closed kind schema",
      "reject": [
        "unknown presence",
        "unknown/missing/duplicate/reordered field",
        "wrong fixed width",
        "noncanonical bool or enum",
        "length overflow",
        "truncation",
        "trailing bytes"
      ]
    },
    "recordKinds": [
      {
        "id": 1,
        "name": "SLOT_REGISTRATION",
        "version": 1,
        "physicalFact": "slot-registration",
        "orderedFields": [
          "slotState:u8",
          "registeredBindingRef:b32",
          "profileDigest:b32"
        ],
        "maxPlaintextBytes": 16777216
      },
      {
        "id": 2,
        "name": "ISSUANCE_CANDIDATE",
        "version": 1,
        "physicalFact": "issuance-held-candidate",
        "orderedFields": [
          "issuanceRef:b32",
          "publicKeyPackage:bytes65535",
          "privateBundle:bytes65535",
          "localKeyPackageRef:b32",
          "mlsKeyPackageRef:b32"
        ],
        "maxPlaintextBytes": 16777216
      },
      {
        "id": 3,
        "name": "ISSUANCE_OUTCOME",
        "version": 1,
        "physicalFact": "issuance-outcome",
        "orderedFields": [
          "issuanceRef:b32",
          "outcome:u8",
          "releaseState:u8"
        ],
        "maxPlaintextBytes": 16777216
      },
      {
        "id": 4,
        "name": "KEY_PACKAGE",
        "version": 1,
        "physicalFact": "key-package-identity-private-bundle-consumption",
        "orderedFields": [
          "publicKeyPackage:bytes65535",
          "privateBundle:bytes65535",
          "localKeyPackageRef:b32",
          "mlsKeyPackageRef:b32",
          "registeredBindingRef:b32",
          "profileDigest:b32",
          "lifecycle:u8",
          "invalidPending:bool"
        ],
        "maxPlaintextBytes": 16777216
      },
      {
        "id": 5,
        "name": "SESSION_STATE",
        "version": 1,
        "physicalFact": "SESSION_TRANSITION",
        "orderedFields": [
          "providerState:bytes16777216"
        ],
        "maxPlaintextBytes": 16777216
      },
      {
        "id": 6,
        "name": "BINDING_PROFILE",
        "version": 1,
        "physicalFact": "BINDING_METADATA",
        "orderedFields": [
          "canonicalBinding:b389",
          "profileDigest:b32"
        ],
        "maxPlaintextBytes": 16777216
      },
      {
        "id": 7,
        "name": "REPLAY_RETENTION",
        "version": 1,
        "physicalFact": "REPLAY_RETENTION_STATE",
        "orderedFields": [
          "replayState:bytes16777216",
          "retentionState:bytes16777216"
        ],
        "maxPlaintextBytes": 16777216
      },
      {
        "id": 8,
        "name": "COMMIT_RESULT",
        "version": 1,
        "physicalFact": "COMMIT_RESULT_EVIDENCE",
        "orderedFields": [
          "operationIdentity:b32",
          "originalAuthorityDigest:b32",
          "originalAuthorityReference:b32",
          "candidateDigest:b32",
          "candidateReference:b32",
          "mutationSetDigest:b32",
          "mutationSetReference:b32",
          "expectedOriginalState:u8",
          "bindingRef:b32",
          "profileDigest:b32",
          "outcome:u8",
          "authenticatedByRS:bool",
          "terminal:bool"
        ],
        "maxPlaintextBytes": 16777216
      },
      {
        "id": 9,
        "name": "OUTPUT_ESCROW",
        "version": 1,
        "physicalFact": "OUTPUT_ESCROW",
        "orderedFields": [
          "operationIdentity:b32",
          "candidateDigest:b32",
          "candidateReference:b32",
          "mutationSetDigest:b32",
          "mutationSetReference:b32",
          "outputKind:u8",
          "output:bytes16777216",
          "resultDigest:b32"
        ],
        "maxPlaintextBytes": 16777216
      },
      {
        "id": 10,
        "name": "SELECTION_METADATA",
        "version": 1,
        "physicalFact": "SELECTION_METADATA",
        "orderedFields": [
          "eligibility:u8",
          "selectedCandidate:b32"
        ],
        "maxPlaintextBytes": 16777216
      },
      {
        "id": 11,
        "name": "RETAINED_PARENT",
        "version": 1,
        "physicalFact": "RETAINED_PARENT_REFERENCE",
        "orderedFields": [
          "parentReference:b32",
          "selectionRole:u8"
        ],
        "maxPlaintextBytes": 16777216
      },
      {
        "id": 12,
        "name": "LOSING_CANDIDATE",
        "version": 1,
        "physicalFact": "LOSING_CANDIDATE_EVIDENCE",
        "orderedFields": [
          "candidateReference:b32",
          "evidence:bytes16777216",
          "authoritative:bool"
        ],
        "maxPlaintextBytes": 16777216
      },
      {
        "id": 13,
        "name": "MUTATION_HOLD",
        "version": 2,
        "physicalFact": "mutation-envelope-and-reconciliation-hold",
        "orderedFields": [
          "operationIdentity:b32",
          "operation:u8",
          "scenario:u16",
          "originalApiState:u8",
          "originalAuthorityDigest:b32",
          "originalAuthorityReference:b32",
          "bindingRef:b32",
          "profileDigest:b32",
          "candidateDigest:b32",
          "candidateReference:b32",
          "componentSetDigest:b32",
          "componentSetReference:b32",
          "heldOutputKind:u8",
          "heldOutputDigest:b32",
          "heldOutputReference:b32",
          "expectedSuccessCode:u8",
          "expectedStateAfter:u8",
          "reconciliationReference:b32",
          "resultStatus:u8",
          "parentGeneration:u64",
          "parentKeyedRoot:b32"
        ],
        "maxPlaintextBytes": 16777216
      },
      {
        "id": 14,
        "name": "COMPONENT_SET",
        "version": 1,
        "physicalFact": "complete-component-set",
        "orderedFields": [
          "mutationSetDigest:b32",
          "mutationSetReference:b32",
          "entries:bytes65535"
        ],
        "maxPlaintextBytes": 16777216
      },
      {
        "id": 15,
        "name": "ABSENCE_COMMITMENTS",
        "version": 1,
        "physicalFact": "logical-tombstone-absence-commitments",
        "orderedFields": [
          "bitmap:u32",
          "reasonCodes:bytes255"
        ],
        "maxPlaintextBytes": 16777216
      },
      {
        "id": 16,
        "name": "MANIFEST",
        "version": 1,
        "physicalFact": "authenticated-manifest",
        "orderedFields": [
          "entries:bytes16777216",
          "manifestPlainDigest:b32"
        ],
        "maxPlaintextBytes": 16777216
      },
      {
        "id": 17,
        "name": "GENERATION_SELECTOR",
        "version": 3,
        "physicalFact": "authoritative-generation-selector",
        "orderedFields": [
          "generation:u64",
          "manifestKeyDigest:b32",
          "manifestCipherDigest:b32",
          "keyedRoot:b32",
          "state:u8",
          "candidateGeneration:u64",
          "candidateManifestKey:bytes255",
          "candidateManifestKeyDigest:b32",
          "candidateManifestCipherDigest:b32",
          "candidateKeyedRoot:b32"
        ],
        "maxPlaintextBytes": 16777216
      }
    ],
    "valueRegistries": {
      "slotState": {
        "EMPTY": 1,
        "ISSUANCE_HELD": 2,
        "BOUND": 3,
        "RECONCILIATION_REQUIRED": 4
      },
      "keyPackageLifecycle": {
        "UNCONSUMED": 1,
        "RESERVED": 2,
        "CONSUMED": 3,
        "INVALID": 4
      },
      "commitOutcome": {
        "COMMITTED": 1,
        "NOT_COMMITTED": 2,
        "INDETERMINATE": 3
      },
      "apiState": {
        "EMPTY": 1,
        "ACTIVE": 2,
        "RECONCILIATION_REQUIRED": 3
      },
      "selectorState": {
        "EMPTY": 1,
        "ACTIVE": 2,
        "RECONCILIATION_REQUIRED": 3
      },
      "operation": {
        "CREATE": 1,
        "RESTORE": 2,
        "JOIN_WELCOME": 3,
        "PROTECT_APPLICATION": 4,
        "OPEN_APPLICATION": 5,
        "SELF_UPDATE": 6,
        "APPLY_PEER_UPDATE": 7,
        "RECONCILE_INDETERMINATE": 8
      },
      "scenario": {
        "CAPI-S001": 1,
        "CAPI-S006": 2,
        "CAPI-S009": 3,
        "CAPI-S010": 4,
        "CAPI-S014": 5,
        "CAPI-S016": 6,
        "CAPI-S017": 7
      },
      "outputKind": {
        "NONE": 1,
        "EMBEDDED_TREE_WELCOME": 2,
        "PROTECTED_APPLICATION_BYTES": 3,
        "APPLICATION_BYTES": 4,
        "PROTECTED_COMMIT_BYTES": 5,
        "SELECTED_CANDIDATE_REF": 6
      },
      "successCode": {
        "CREATED": 1,
        "RESTORED": 2,
        "JOINED": 3,
        "APPLICATION_PROTECTED": 4,
        "APPLICATION_OPENED": 5,
        "SELF_UPDATED": 6,
        "PEER_UPDATE_APPLIED": 7,
        "CANDIDATE_SELECTED": 8,
        "RECONCILED_COMMITTED": 9,
        "DUPLICATE_IGNORED": 10
      },
      "bool": {
        "false": 0,
        "true": 1
      },
      "fieldTags": "For each recordKinds entry, orderedFields is numbered consecutively from tag 1; no other tag is valid."
    },
    "componentMapping": [
      {
        "component": "SESSION_TRANSITION",
        "recordKind": "SESSION_STATE",
        "cardinality": "exactly-one authoritative record or explicit tombstone per generation"
      },
      {
        "component": "BINDING_METADATA",
        "recordKind": "BINDING_PROFILE",
        "cardinality": "exactly-one authoritative record or explicit tombstone per generation"
      },
      {
        "component": "REPLAY_RETENTION_STATE",
        "recordKind": "REPLAY_RETENTION",
        "cardinality": "exactly-one authoritative record or explicit tombstone per generation"
      },
      {
        "component": "AUTHENTICATED_MANIFEST_UPDATE",
        "recordKind": "MANIFEST",
        "cardinality": "exactly-one authoritative record or explicit tombstone per generation"
      },
      {
        "component": "COMMIT_RESULT_EVIDENCE",
        "recordKind": "COMMIT_RESULT",
        "cardinality": "exactly-one authoritative record or explicit tombstone per generation"
      },
      {
        "component": "KEY_PACKAGE_CONSUMPTION",
        "recordKind": "KEY_PACKAGE",
        "cardinality": "exactly-one authoritative record or explicit tombstone per generation"
      },
      {
        "component": "OUTPUT_ESCROW",
        "recordKind": "OUTPUT_ESCROW",
        "cardinality": "exactly-one authoritative record or explicit tombstone per generation"
      },
      {
        "component": "SELECTION_METADATA",
        "recordKind": "SELECTION_METADATA",
        "cardinality": "exactly-one authoritative record or explicit tombstone per generation"
      },
      {
        "component": "RETAINED_PARENT_REFERENCE",
        "recordKind": "RETAINED_PARENT",
        "cardinality": "exactly-one authoritative record or explicit tombstone per generation"
      },
      {
        "component": "LOSING_CANDIDATE_EVIDENCE",
        "recordKind": "LOSING_CANDIDATE",
        "cardinality": "exactly-one authoritative record or explicit tombstone per generation"
      }
    ],
    "cBindDurableFactMapping": [
      {
        "fact": "slot registration",
        "recordKind": "SLOT_REGISTRATION",
        "coveredBy": "complete generation manifest/root and selector update"
      },
      {
        "fact": "issuance-held candidate",
        "recordKind": "ISSUANCE_CANDIDATE",
        "coveredBy": "complete generation manifest/root and selector update"
      },
      {
        "fact": "issuance outcome",
        "recordKind": "ISSUANCE_OUTCOME",
        "coveredBy": "complete generation manifest/root and selector update"
      },
      {
        "fact": "public bytes, private bundle, opaque local reference, canonical MLS KeyPackageRef mapping, context/profile, lifecycle state, reservation, invalidPending and invalidation",
        "recordKind": "KEY_PACKAGE",
        "coveredBy": "complete generation manifest/root and selector update"
      }
    ],
    "keyPackageLifecycle": {
      "states": [
        "UNCONSUMED",
        "RESERVED",
        "CONSUMED",
        "INVALID"
      ],
      "invalidPendingOnlyWith": "RESERVED",
      "restore": "exact state and flag; RESERVED never becomes retryable from parsing",
      "identityBinding": "public bytes, private components, local reference, MLS KeyPackageRef, context and profile are one non-aliasable plaintext record; local reference never appears in a storage key"
    },
    "mutationRows": [
      {
        "scenario": "CAPI-S001",
        "operation": "CREATE",
        "physical": [
          {
            "component": "SESSION_TRANSITION",
            "recordKind": "SESSION_STATE",
            "disposition": "CHANGED",
            "fact": "FOUNDER_STATE"
          },
          {
            "component": "BINDING_METADATA",
            "recordKind": "BINDING_PROFILE",
            "disposition": "CHANGED",
            "fact": "INITIAL_EXACT_BINDING_AND_PROFILE"
          },
          {
            "component": "REPLAY_RETENTION_STATE",
            "recordKind": "REPLAY_RETENTION",
            "disposition": "CHANGED",
            "fact": "INITIAL_BASELINE"
          },
          {
            "component": "AUTHENTICATED_MANIFEST_UPDATE",
            "recordKind": "MANIFEST",
            "disposition": "CHANGED",
            "fact": "FOUNDER_MANIFEST"
          },
          {
            "component": "COMMIT_RESULT_EVIDENCE",
            "recordKind": "COMMIT_RESULT",
            "disposition": "CREATED",
            "fact": "BOUND_TO_OPERATION_IDENTITY"
          },
          {
            "component": "OUTPUT_ESCROW",
            "recordKind": "OUTPUT_ESCROW",
            "disposition": "HELD",
            "fact": "EMBEDDED_TREE_WELCOME"
          }
        ]
      },
      {
        "scenario": "CAPI-S006",
        "operation": "JOIN_WELCOME",
        "physical": [
          {
            "component": "SESSION_TRANSITION",
            "recordKind": "SESSION_STATE",
            "disposition": "CHANGED",
            "fact": "JOINED_STATE"
          },
          {
            "component": "BINDING_METADATA",
            "recordKind": "BINDING_PROFILE",
            "disposition": "CHANGED",
            "fact": "JOINED_EXACT_BINDING_AND_PROFILE"
          },
          {
            "component": "REPLAY_RETENTION_STATE",
            "recordKind": "REPLAY_RETENTION",
            "disposition": "CHANGED",
            "fact": "JOINED_BASELINE"
          },
          {
            "component": "AUTHENTICATED_MANIFEST_UPDATE",
            "recordKind": "MANIFEST",
            "disposition": "CHANGED",
            "fact": "JOINED_MANIFEST"
          },
          {
            "component": "COMMIT_RESULT_EVIDENCE",
            "recordKind": "COMMIT_RESULT",
            "disposition": "CREATED",
            "fact": "BOUND_TO_OPERATION_IDENTITY"
          },
          {
            "component": "KEY_PACKAGE_CONSUMPTION",
            "recordKind": "KEY_PACKAGE",
            "disposition": "CONSUMED",
            "fact": "MATCHING_LOCAL_ONE_SHOT_REFERENCE"
          }
        ]
      },
      {
        "scenario": "CAPI-S009",
        "operation": "PROTECT_APPLICATION",
        "physical": [
          {
            "component": "SESSION_TRANSITION",
            "recordKind": "SESSION_STATE",
            "disposition": "CHANGED",
            "fact": "SENDER_RATCHET_ADVANCEMENT"
          },
          {
            "component": "BINDING_METADATA",
            "recordKind": "BINDING_PROFILE",
            "disposition": "UNCHANGED",
            "fact": "EXACT_BINDING_AND_PROFILE"
          },
          {
            "component": "REPLAY_RETENTION_STATE",
            "recordKind": "REPLAY_RETENTION",
            "disposition": "CHANGED",
            "fact": "SENDER_RATCHET_RETENTION"
          },
          {
            "component": "AUTHENTICATED_MANIFEST_UPDATE",
            "recordKind": "MANIFEST",
            "disposition": "CHANGED",
            "fact": "RATCHET_STATE_MANIFEST"
          },
          {
            "component": "COMMIT_RESULT_EVIDENCE",
            "recordKind": "COMMIT_RESULT",
            "disposition": "CREATED",
            "fact": "BOUND_TO_OPERATION_IDENTITY"
          },
          {
            "component": "OUTPUT_ESCROW",
            "recordKind": "OUTPUT_ESCROW",
            "disposition": "HELD",
            "fact": "PROTECTED_APPLICATION_BYTES"
          },
          {
            "component": "SELECTION_METADATA",
            "recordKind": "SELECTION_METADATA",
            "disposition": "UNCHANGED",
            "fact": "EPOCH_PRESERVING_ELIGIBILITY"
          },
          {
            "component": "RETAINED_PARENT_REFERENCE",
            "recordKind": "RETAINED_PARENT",
            "disposition": "UNCHANGED",
            "fact": "PRESERVED_IF_PRESENT"
          }
        ]
      },
      {
        "scenario": "CAPI-S010",
        "operation": "OPEN_APPLICATION",
        "physical": [
          {
            "component": "SESSION_TRANSITION",
            "recordKind": "SESSION_STATE",
            "disposition": "CHANGED",
            "fact": "RECEIVER_RATCHET_ADVANCEMENT"
          },
          {
            "component": "BINDING_METADATA",
            "recordKind": "BINDING_PROFILE",
            "disposition": "UNCHANGED",
            "fact": "EXACT_BINDING_AND_PROFILE"
          },
          {
            "component": "REPLAY_RETENTION_STATE",
            "recordKind": "REPLAY_RETENTION",
            "disposition": "CHANGED",
            "fact": "REPLAY_ACCEPTANCE_AND_RECEIVER_RETENTION"
          },
          {
            "component": "AUTHENTICATED_MANIFEST_UPDATE",
            "recordKind": "MANIFEST",
            "disposition": "CHANGED",
            "fact": "RATCHET_AND_REPLAY_MANIFEST"
          },
          {
            "component": "COMMIT_RESULT_EVIDENCE",
            "recordKind": "COMMIT_RESULT",
            "disposition": "CREATED",
            "fact": "BOUND_TO_OPERATION_IDENTITY"
          },
          {
            "component": "OUTPUT_ESCROW",
            "recordKind": "OUTPUT_ESCROW",
            "disposition": "HELD",
            "fact": "APPLICATION_BYTES"
          },
          {
            "component": "SELECTION_METADATA",
            "recordKind": "SELECTION_METADATA",
            "disposition": "UNCHANGED",
            "fact": "EPOCH_PRESERVING_ELIGIBILITY"
          },
          {
            "component": "RETAINED_PARENT_REFERENCE",
            "recordKind": "RETAINED_PARENT",
            "disposition": "UNCHANGED",
            "fact": "PRESERVED_IF_PRESENT"
          }
        ]
      },
      {
        "scenario": "CAPI-S014",
        "operation": "SELF_UPDATE",
        "physical": [
          {
            "component": "SESSION_TRANSITION",
            "recordKind": "SESSION_STATE",
            "disposition": "CHANGED",
            "fact": "LOCAL_UPDATE_STATE"
          },
          {
            "component": "BINDING_METADATA",
            "recordKind": "BINDING_PROFILE",
            "disposition": "UNCHANGED",
            "fact": "EXACT_BINDING_AND_PROFILE"
          },
          {
            "component": "REPLAY_RETENTION_STATE",
            "recordKind": "REPLAY_RETENTION",
            "disposition": "CHANGED",
            "fact": "EPOCH_WINDOW_ADVANCEMENT"
          },
          {
            "component": "AUTHENTICATED_MANIFEST_UPDATE",
            "recordKind": "MANIFEST",
            "disposition": "CHANGED",
            "fact": "LOCAL_UPDATE_MANIFEST"
          },
          {
            "component": "COMMIT_RESULT_EVIDENCE",
            "recordKind": "COMMIT_RESULT",
            "disposition": "CREATED",
            "fact": "BOUND_TO_OPERATION_IDENTITY"
          },
          {
            "component": "OUTPUT_ESCROW",
            "recordKind": "OUTPUT_ESCROW",
            "disposition": "HELD",
            "fact": "PROTECTED_COMMIT_BYTES"
          },
          {
            "component": "SELECTION_METADATA",
            "recordKind": "SELECTION_METADATA",
            "disposition": "ESTABLISHED",
            "fact": "IMMEDIATELY_PRECEDING_LOCAL_UPDATE_ELIGIBILITY"
          },
          {
            "component": "RETAINED_PARENT_REFERENCE",
            "recordKind": "RETAINED_PARENT",
            "disposition": "ESTABLISHED",
            "fact": "PARENT_REQUIRED_BY_CAPI_S017"
          }
        ]
      },
      {
        "scenario": "CAPI-S016",
        "operation": "APPLY_PEER_UPDATE",
        "physical": [
          {
            "component": "SESSION_TRANSITION",
            "recordKind": "SESSION_STATE",
            "disposition": "CHANGED",
            "fact": "PEER_UPDATE_STATE"
          },
          {
            "component": "BINDING_METADATA",
            "recordKind": "BINDING_PROFILE",
            "disposition": "UNCHANGED",
            "fact": "EXACT_BINDING_AND_PROFILE"
          },
          {
            "component": "REPLAY_RETENTION_STATE",
            "recordKind": "REPLAY_RETENTION",
            "disposition": "CHANGED",
            "fact": "EPOCH_WINDOW_ADVANCEMENT"
          },
          {
            "component": "AUTHENTICATED_MANIFEST_UPDATE",
            "recordKind": "MANIFEST",
            "disposition": "CHANGED",
            "fact": "PEER_UPDATE_MANIFEST"
          },
          {
            "component": "COMMIT_RESULT_EVIDENCE",
            "recordKind": "COMMIT_RESULT",
            "disposition": "CREATED",
            "fact": "BOUND_TO_OPERATION_IDENTITY"
          },
          {
            "component": "SELECTION_METADATA",
            "recordKind": "SELECTION_METADATA",
            "disposition": "INVALIDATED",
            "fact": "ANY_CAPI_S014_ELIGIBILITY"
          },
          {
            "component": "RETAINED_PARENT_REFERENCE",
            "recordKind": "RETAINED_PARENT",
            "disposition": "INVALIDATED",
            "fact": "NO_LONGER_SELECTION_AUTHORIZING"
          },
          {
            "component": "LOSING_CANDIDATE_EVIDENCE",
            "recordKind": "LOSING_CANDIDATE",
            "disposition": "INVALIDATED",
            "fact": "ANY_RETAINED_LOSER_EVIDENCE"
          }
        ]
      },
      {
        "scenario": "CAPI-S017",
        "operation": "APPLY_PEER_UPDATE",
        "physical": [
          {
            "component": "SESSION_TRANSITION",
            "recordKind": "SESSION_STATE",
            "disposition": "CHANGED_OR_UNCHANGED_BY_SELECTED_CANDIDATE",
            "fact": "CURRENT_WINNER_UNCHANGED_INCOMING_WINNER_CHANGED"
          },
          {
            "component": "BINDING_METADATA",
            "recordKind": "BINDING_PROFILE",
            "disposition": "UNCHANGED",
            "fact": "EXACT_BINDING_AND_PROFILE"
          },
          {
            "component": "REPLAY_RETENTION_STATE",
            "recordKind": "REPLAY_RETENTION",
            "disposition": "CHANGED",
            "fact": "SELECTED_EPOCH_WINDOW"
          },
          {
            "component": "AUTHENTICATED_MANIFEST_UPDATE",
            "recordKind": "MANIFEST",
            "disposition": "CHANGED",
            "fact": "SELECTED_STATE_MANIFEST"
          },
          {
            "component": "COMMIT_RESULT_EVIDENCE",
            "recordKind": "COMMIT_RESULT",
            "disposition": "CREATED",
            "fact": "BOUND_TO_OPERATION_IDENTITY"
          },
          {
            "component": "OUTPUT_ESCROW",
            "recordKind": "OUTPUT_ESCROW",
            "disposition": "HELD",
            "fact": "SELECTED_CANDIDATE_REF"
          },
          {
            "component": "SELECTION_METADATA",
            "recordKind": "SELECTION_METADATA",
            "disposition": "TERMINATED",
            "fact": "NO_FURTHER_SELECTION_FROM_OLD_PARENT"
          },
          {
            "component": "RETAINED_PARENT_REFERENCE",
            "recordKind": "RETAINED_PARENT",
            "disposition": "TERMINATED",
            "fact": "NO_LONGER_SELECTION_AUTHORIZING"
          },
          {
            "component": "LOSING_CANDIDATE_EVIDENCE",
            "recordKind": "LOSING_CANDIDATE",
            "disposition": "RETAINED_NON_AUTHORITATIVE",
            "fact": "BOUNDED_VALID_LOSER"
          }
        ]
      }
    ],
    "recoveryFactMapping": [
      {
        "fact": "MUTATION_ENVELOPE_IDENTITY",
        "recordKind": "MUTATION_HOLD"
      },
      {
        "fact": "ORIGINAL_AUTHORITY",
        "recordKind": "MUTATION_HOLD"
      },
      {
        "fact": "CANDIDATE_IDENTITY",
        "recordKind": "MUTATION_HOLD"
      },
      {
        "fact": "COMPONENT_SET_IDENTITY",
        "recordKind": "COMPONENT_SET"
      },
      {
        "fact": "ESCROW_IDENTITY_AND_CONTENT",
        "recordKind": "OUTPUT_ESCROW"
      },
      {
        "fact": "RECONCILIATION_REFERENCE",
        "recordKind": "MUTATION_HOLD"
      },
      {
        "fact": "EXPECTED_SUCCESS",
        "recordKind": "MUTATION_HOLD"
      },
      {
        "fact": "AUTHENTICATED_RS_EVIDENCE",
        "recordKind": "COMMIT_RESULT"
      }
    ],
    "manifest": {
      "entry": "u16be(keyLength)||canonicalKey||recordKind:u16be||recordKindVersion:u16be||ciphertextDigest[32]",
      "ciphertextDigest": "SHA-256(\"STYX-M2-CIPHERTEXT-DIGEST-V1\"||frame(key)||kind:u16be||kindVersion:u16be||frame(ciphertext||tag))",
      "ordering": "unsigned lexicographic canonicalKey; keys unique; every data kind 1..15 exactly once per object or explicit canonical tombstone",
      "bytes": "ASCII STYXMAN1 || manifestVersion:u16be || entryCount:u32be || sorted entries",
      "manifestRecord": "kind 16; AEAD-authenticated; keyed-root input also binds its canonical key and SHA-256 of literal manifest bytes",
      "manifestKeyDigest": "SHA-256(literal complete canonical manifest key)",
      "selector": "kind 17 version 3 at the sole fixed STYXSEL1 locator; AEAD-authenticated; plaintext binds selected generation, its manifest-key digest, manifest ciphertext digest, keyed root and API state, then always-present candidate generation, exact candidate manifest key, manifest-key digest, manifest ciphertext digest and keyed root; candidateManifestKey is encrypted and never AAD; no second locator exists",
      "candidateManifestKeyValidation": "parse exact candidateManifestKey under the canonical record-key grammar as kind 16 with empty objectId; require its generation and localContextId to equal candidateGeneration and the locator context, its SHA-256 to equal candidateManifestKeyDigest, and the located candidate manifest binding digest to match that candidate generation own BINDING_PROFILE",
      "keyedRoot": "HMAC-SHA-256(K_manifest, ASCII STYXROOT1 || version:u16be || generation:u64be of the manifest being rooted || manifestKeyLength:u16be || manifestKey || SHA-256(manifestBytes) || manifestBytes)",
      "subsetRule": "each selected or distinct candidate tuple accepts only its exactly matching complete manifest/root; omission, addition, substitution, duplicate, reorder, historical subset, partial generation or root mismatch rejects"
    },
    "generationCommit": {
      "rule": "write complete candidate data records, manifest and matching result/escrow; authority changes only through one atomic replacement of the authenticated fixed-locator GENERATION_SELECTOR; that same replacement binds any retained candidate",
      "completeOld": "selector still names old complete generation",
      "completeNew": "selector names new complete generation whose manifest/root/result/escrow all verify",
      "indeterminate": "selector names old authority and binds one complete immutable candidate/hold generation as non-authoritative evidence",
      "candidateBindingRule": "candidate locator fields are always present; when the candidate generation, exact manifest key, manifest-key digest, manifest ciphertext digest and keyed root equal the selected values there is no separate candidate and state MUST NOT be RECONCILIATION_REQUIRED; when different, state MUST be RECONCILIATION_REQUIRED, selected MUTATION_HOLD MUST be a tombstone, and candidate MUTATION_HOLD MUST be present; every other combination rejects",
      "parentBindingRule": "for an unresolved candidate MUTATION_HOLD whose resultStatus is INDETERMINATE while the selector names old authority, parentGeneration and parentKeyedRoot MUST equal the selector generation and keyedRoot; this compares physical identity only; terminal COMMITTED or NOT_COMMITTED holds are governed by C-MUT terminal rules and do not compare their parent to a selector that has moved",
      "originalAuthorityMatch": "candidate MUTATION_HOLD originalAuthorityDigest and originalAuthorityReference MUST equal the same fields in the candidate COMMIT_RESULT authenticated RS evidence; these remain C-MUT logical identifiers and are not compared with parentGeneration or parentKeyedRoot",
      "authorityRule": "only the selected generation is authoritative; the candidate is validated as complete immutable evidence and is never authority or a repair source",
      "storageReadback": [
        "COMPLETE_OLD",
        "COMPLETE_NEW"
      ],
      "memoryOnlyReadback": [
        "OLD_PLUS_ONE_IMMUTABLE_HOLD"
      ],
      "partialCandidate": "REJECT",
      "regenerateSecuritySensitiveOutput": false,
      "outcomes": {
        "COMMITTED": {
          "authority": "COMPLETE_NEW",
          "atomic": true,
          "exactlyOnce": true,
          "resultKind": "SUCCESS",
          "output": "RELEASE_MATCHING_ESCROW",
          "evidence": "MATCHING_AUTHENTICATED_RESULT_AUTHORITATIVE"
        },
        "NOT_COMMITTED": {
          "authority": "COMPLETE_OLD",
          "terminalEvidenceRequired": true,
          "candidate": "DISCARD",
          "escrow": "DISCARD",
          "resultKind": "NOT_COMMITTED",
          "output": "NONE"
        },
        "INDETERMINATE": {
          "authority": "OLD_PLUS_ONE_IMMUTABLE_HOLD",
          "causes": [
            "TIMEOUT",
            "LOST_RESPONSE",
            "ABSENT_RESULT",
            "FAILED_RESULT",
            "UNKNOWN_POST_REQUEST_FAILURE"
          ],
          "stateAfter": "RECONCILIATION_REQUIRED",
          "resultKind": "INDETERMINATE",
          "responseRequired": [
            "commitOutcome",
            "originalStateBefore",
            "reconciliationRef"
          ],
          "output": "NONE",
          "blindRetry": "FORBIDDEN"
        }
      }
    },
    "outputEscrow": {
      "binding": [
        "operationIdentity",
        "candidate",
        "mutationSetDigest",
        "outputKind",
        "authenticated result"
      ],
      "releaseAuthority": "C-MUT only; format never releases output",
      "clearRule": "clearing escrow/hold may occur only after terminal rules and cannot erase commit-result evidence required to classify an interrupted generation"
    },
    "crashModel": [
      {
        "id": "BEFORE_STAGING",
        "readbackByMemory": {
          "RETAINED": [
            "COMPLETE_OLD"
          ],
          "LOST": [
            "COMPLETE_OLD"
          ]
        },
        "apiState": "ORIGINAL",
        "output": "NONE",
        "classification": "NO_RS_REQUEST"
      },
      {
        "id": "AFTER_CANDIDATE_COMPUTATION",
        "readbackByMemory": {
          "RETAINED": [
            "COMPLETE_OLD"
          ],
          "LOST": [
            "COMPLETE_OLD"
          ]
        },
        "apiState": "ORIGINAL",
        "output": "NONE",
        "classification": "NO_RS_REQUEST"
      },
      {
        "id": "AFTER_LOCAL_STAGING",
        "readbackByMemory": {
          "RETAINED": [
            "COMPLETE_OLD"
          ],
          "LOST": [
            "COMPLETE_OLD"
          ]
        },
        "apiState": "ORIGINAL",
        "output": "NONE",
        "classification": "NO_RS_REQUEST"
      },
      {
        "id": "BEFORE_RS_REQUEST",
        "readbackByMemory": {
          "RETAINED": [
            "COMPLETE_OLD"
          ],
          "LOST": [
            "COMPLETE_OLD"
          ]
        },
        "apiState": "ORIGINAL",
        "output": "NONE",
        "classification": "NO_RS_REQUEST"
      },
      {
        "id": "DURING_RS_WORK",
        "readbackByMemory": {
          "RETAINED": [
            "COMPLETE_OLD",
            "COMPLETE_NEW",
            "OLD_PLUS_ONE_IMMUTABLE_HOLD"
          ],
          "LOST": [
            "COMPLETE_OLD",
            "COMPLETE_NEW"
          ]
        },
        "apiState": "RECONCILIATION_REQUIRED_UNTIL_TERMINAL_READBACK",
        "output": "NONE_UNTIL_COMMITTED_PROVEN",
        "classification": "AUTHENTICATED_RS_EVIDENCE_ONLY"
      },
      {
        "id": "AFTER_DURABLE_COMMIT_BEFORE_RESPONSE",
        "readbackByMemory": {
          "RETAINED": [
            "COMPLETE_NEW"
          ],
          "LOST": [
            "COMPLETE_NEW"
          ]
        },
        "apiStateByPath": {
          "ORIGINAL_TERMINAL": "ACTIVE_HOLD_RESOLVED",
          "POST_INDETERMINATE": "RECONCILIATION_REQUIRED_UNTIL_LOCAL_EMISSION_CALL_SUCCEEDS"
        },
        "outputByPath": {
          "ORIGINAL_TERMINAL": "ORIGINAL_SUCCESS_RESPONSE_PENDING",
          "POST_INDETERMINATE": "COMMITTED_ESCROW_AVAILABLE_TO_CAPI_S020_OR_S022"
        },
        "classificationByPath": {
          "ORIGINAL_TERMINAL": "CAPI_COMMITTED_RULE_NO_AP_RECONCILIATION_ROW_WITHOUT_PRIOR_REFERENCE",
          "POST_INDETERMINATE": "CAPI_S020_OR_S022"
        }
      },
      {
        "id": "AFTER_NOT_COMMITTED",
        "readbackByMemory": {
          "RETAINED": [
            "COMPLETE_OLD"
          ],
          "LOST": [
            "COMPLETE_OLD"
          ]
        },
        "apiStateByPath": {
          "ORIGINAL_TERMINAL": "ORIGINAL_STATE_HOLD_RESOLVED",
          "POST_INDETERMINATE": "ORIGINAL_STATE_HOLD_CLEARED_WHEN_NO_OUTPUT_RESPONSE_FORMED"
        },
        "outputByPath": {
          "ORIGINAL_TERMINAL": "NONE",
          "POST_INDETERMINATE": "NONE"
        },
        "classificationByPath": {
          "ORIGINAL_TERMINAL": "CAPI_NOT_COMMITTED_RULE",
          "POST_INDETERMINATE": "CAPI_S021_OR_S023"
        }
      },
      {
        "id": "AFTER_INDETERMINATE",
        "readbackByMemory": {
          "RETAINED": [
            "OLD_PLUS_ONE_IMMUTABLE_HOLD"
          ],
          "LOST": [
            "COMPLETE_OLD",
            "COMPLETE_NEW"
          ]
        },
        "apiState": "RECONCILIATION_REQUIRED",
        "output": "NONE",
        "classification": "LOST_MEMORY_REQUIRES_TERMINAL_AUTHENTICATED_C_REC_RS_READBACK"
      },
      {
        "id": "DURING_RECONCILIATION",
        "readbackByMemory": {
          "RETAINED": [
            "COMPLETE_OLD",
            "COMPLETE_NEW",
            "OLD_PLUS_ONE_IMMUTABLE_HOLD"
          ],
          "LOST": [
            "COMPLETE_OLD",
            "COMPLETE_NEW"
          ]
        },
        "apiState": "RECONCILIATION_REQUIRED_UNTIL_TERMINAL_RESPONSE_CONFIRMED",
        "output": "NONE_UNTIL_COMMITTED_PROVEN",
        "classification": "AUTHENTICATED_RS_EVIDENCE_ONLY"
      },
      {
        "id": "AFTER_AUTHORITY_SELECTION_BEFORE_OUTPUT_RESPONSE",
        "readbackByMemory": {
          "RETAINED": [
            "COMPLETE_NEW"
          ],
          "LOST": [
            "COMPLETE_NEW"
          ]
        },
        "apiStateByPath": {
          "ORIGINAL_TERMINAL": "ACTIVE_HOLD_RESOLVED",
          "POST_INDETERMINATE": "RECONCILIATION_REQUIRED_UNTIL_LOCAL_EMISSION_CALL_SUCCEEDS"
        },
        "outputByPath": {
          "ORIGINAL_TERMINAL": "ORIGINAL_SUCCESS_RESPONSE_PENDING",
          "POST_INDETERMINATE": "COMMITTED_ESCROW_AVAILABLE_TO_CAPI_S020_OR_S022"
        },
        "classificationByPath": {
          "ORIGINAL_TERMINAL": "CAPI_COMMITTED_RULE_NO_AP_RECONCILIATION_ROW_WITHOUT_PRIOR_REFERENCE",
          "POST_INDETERMINATE": "CAPI_S020_OR_S022"
        }
      },
      {
        "id": "DURING_ESCROW_OUTPUT_RESPONSE",
        "readbackByMemory": {
          "RETAINED": [
            "COMPLETE_NEW"
          ],
          "LOST": [
            "COMPLETE_NEW"
          ]
        },
        "apiStateByPath": {
          "ORIGINAL_TERMINAL": "ACTIVE_HOLD_RESOLVED_INTERNAL_EVIDENCE_RETAINED_IF_INTERRUPTED",
          "POST_INDETERMINATE": "RECONCILIATION_REQUIRED_IF_LOCAL_EMISSION_CALL_INTERRUPTED"
        },
        "outputByPath": {
          "ORIGINAL_TERMINAL": "NO_AP_RECONCILIATION_REPLAY_WITHOUT_PRIOR_REFERENCE",
          "POST_INDETERMINATE": "SAME_COMMITTED_ESCROW_MAY_BE_RETURNED_AGAIN"
        },
        "classificationByPath": {
          "ORIGINAL_TERMINAL": "CAPI_COMMITTED_RULE",
          "POST_INDETERMINATE": "CAPI_S020_OR_S022"
        }
      },
      {
        "id": "AFTER_OUTPUT_RESPONSE_LOSS",
        "readbackByMemory": {
          "RETAINED": [
            "COMPLETE_NEW"
          ],
          "LOST": [
            "COMPLETE_NEW"
          ]
        },
        "apiStateByPath": {
          "ORIGINAL_TERMINAL": "ACTIVE_HOLD_RESOLVED_INTERNAL_EVIDENCE_RETAINED",
          "POST_INDETERMINATE": "RECONCILIATION_REQUIRED_IF_LOCAL_EMISSION_CALL_DID_NOT_RETURN_SUCCESS"
        },
        "outputByPath": {
          "ORIGINAL_TERMINAL": "NO_AP_RECONCILIATION_REPLAY_WITHOUT_PRIOR_REFERENCE",
          "POST_INDETERMINATE": "SAME_COMMITTED_ESCROW_MAY_BE_RETURNED_AGAIN"
        },
        "classificationByPath": {
          "ORIGINAL_TERMINAL": "CAPI_COMMITTED_RULE",
          "POST_INDETERMINATE": "CAPI_S020_OR_S022"
        }
      }
    ],
    "negativeCases": [
      "UNKNOWN_MISSING_DUPLICATE_REORDERED_JSON_FIELD",
      "UNKNOWN_MISSING_DUPLICATE_REORDERED_PLAINTEXT_FIELD",
      "UNKNOWN_KIND_VERSION_ALGORITHM_LABEL",
      "NONCANONICAL_LENGTH_ENDIAN",
      "TRUNCATION_TRAILING_SIZE_OVERFLOW",
      "NONCE_REUSE",
      "AAD_CONTEXT_SESSION_PROFILE_KIND_VERSION_GENERATION_SUBSTITUTION",
      "KEY_OR_LABEL_COLLISION",
      "CROSS_DOMAIN_COPY",
      "MANIFEST_OMISSION_ADDITION_DUPLICATE_REORDER",
      "ROOT_OR_SELECTOR_MISMATCH",
      "HISTORICAL_SUBSET_UNDER_CURRENT_ROOT",
      "PARTIAL_GENERATION",
      "FORGED_RESULT_ESCROW_ASSOCIATION",
      "CANDIDATE_FIELDS_DIFFER_WITHOUT_RECONCILIATION_REQUIRED",
      "RECONCILIATION_REQUIRED_CANDIDATE_MISSING_OR_MISMATCHED",
      "RECONCILIATION_REQUIRED_CANDIDATE_EQUALS_SELECTED",
      "CANDIDATE_MANIFEST_KEY_MISMATCH",
      "CANDIDATE_PARENT_MISMATCH",
      "CANDIDATE_MANIFEST_KEY_SCOPE_SESSION_SUBSTITUTION"
    ],
    "nonClaims": [
      "freshness",
      "coherent complete same-key browser-profile rollback detection or prevention",
      "secure physical erasure",
      "JavaScript zeroization",
      "transport or delivery",
      "application identity",
      "production readiness",
      "arbitrary topology",
      "IndexedDB transaction implementation"
    ],
    "vectorIdentities": [
      {
        "id": "FMT-KAT-EMPTY",
        "state": "EMPTY",
        "generation": 1,
        "selectedGeneration": 1,
        "candidateGeneration": 1,
        "profileDigestHex": "5d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b",
        "keyedRootHex": "40d640a0b1c1063b970d8ddea9fc5477648f16830f301f4a920027f9e162496e",
        "selectorEnvelopeSha256": "8534cf44851d83bed98fbb8669483df30a78afaf00b61eebd23adb3ff559ae4c",
        "recordsCanonicalJsonSha256": "50799b9c7d0b46224726b684f8c83f41558ea3ccdd676410cc7632fdce55977a",
        "literalVectorCanonicalJsonSha256": "8a743399b0409aee02729e57958dc73c579fbab13dcc6fdb54bf215669599947",
        "authorityRule": "selector names this generation and repeats it as the candidate binding"
      },
      {
        "id": "FMT-KAT-ACTIVE",
        "state": "ACTIVE",
        "generation": 2,
        "selectedGeneration": 2,
        "candidateGeneration": 2,
        "profileDigestHex": "5d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b",
        "keyedRootHex": "00a83a64c4dc96a0d74e76e093ffd5c09c31819d017fcae2796cb23ce2441075",
        "selectorEnvelopeSha256": "4ee79d7db2db52c915f3e4e73be05aac6f069fe702217cb62e36501f25243a0e",
        "recordsCanonicalJsonSha256": "8136bd685d487db77ff97c4641c4e133bd772b3804d4a1e5154888746a23bf21",
        "literalVectorCanonicalJsonSha256": "3ca493066688234d82ab38f367e2e650128edc94593199990c4d0d8dda49c2fd",
        "authorityRule": "selector names this generation and repeats it as the candidate binding"
      },
      {
        "id": "FMT-KAT-HOLD",
        "state": "RECONCILIATION_REQUIRED",
        "generation": 3,
        "selectedGeneration": 2,
        "candidateGeneration": 3,
        "profileDigestHex": "5d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b",
        "keyedRootHex": "a832b12c6edb73305282da4585e40797722daf433755f0f74ac307b5ca40063a",
        "selectorEnvelopeSha256": "efddea3da8b41abb801e92ef40c45edf54fb16858f6f2ad2281edc8b3df95336",
        "recordsCanonicalJsonSha256": "24ad85169b879f783ec82944bedec1e2200da40047309c8d560b4cfcbb49f549",
        "literalVectorCanonicalJsonSha256": "f251da28335d9e02fca3401d435da59b95d782ae25af78822ae1dfb694350809",
        "authorityRule": "selector names FMT-KAT-ACTIVE as authority and binds FMT-KAT-HOLD as immutable non-authoritative evidence"
      },
      {
        "id": "FMT-KAT-EMPTY-HOLD",
        "state": "RECONCILIATION_REQUIRED",
        "generation": 4,
        "selectedGeneration": 1,
        "candidateGeneration": 4,
        "profileDigestHex": "5d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b",
        "keyedRootHex": "76991453d9f2093bbbe0c42da018a5ad2f02903f2c544c5fd9923364f2832e3f",
        "selectorEnvelopeSha256": "fccbbe3e72d6880d5e98e9e9fc307fcdadadbb935a717b1b3bb153e4a618de0e",
        "recordsCanonicalJsonSha256": "3f7e5fd63da3a27738b79506aa8336b1e5e76408e31241634b9679d64d7a9e38",
        "literalVectorCanonicalJsonSha256": "6d0dc562748cab0cfbcace64e8604ee2e2c47faa5a8d907ee241c2e6a74a1c30",
        "authorityRule": "selector names FMT-KAT-EMPTY pre-session authority and uses its pre-session selector AAD while the exact candidateManifestKey locates this SESSION-scoped immutable non-authoritative candidate"
      }
    ]
  },
  "buildMatrix": [
    {
      "readerProfile": "CFMT_EXACT_B57DF3A8",
      "cFmtDocumentSha256": "b57df3a8f5dac9cc9f11702fe55d9badf9f98683e3dd7ac03aa81b8fa7932812",
      "versions": {
        "format": 1,
        "envelope": 1,
        "recordKey": 1,
        "plaintext": 1,
        "manifest": 1,
        "keySchedule": 1,
        "upstreamBinding": 0,
        "upstreamMutationTable": 1
      },
      "openMlsRevision": "09e92777dba0528d3d29e2e5e681b7e91637c7be",
      "wasmArtifactPath": "styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm",
      "wasmArtifactSha256": "fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e",
      "ss0Ciphersuite": {
        "ianaId": "0x0001",
        "name": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
      },
      "ss0GateADecisionsSha256": "235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07",
      "buildId": "M2_WEB_CHROMIUM_STANDARD",
      "runtimeClass": "BROWSER_STANDARD_NON_PRIVATE_NON_EVICTED",
      "browserClass": "CHROMIUM"
    },
    {
      "readerProfile": "CFMT_EXACT_B57DF3A8",
      "cFmtDocumentSha256": "b57df3a8f5dac9cc9f11702fe55d9badf9f98683e3dd7ac03aa81b8fa7932812",
      "versions": {
        "format": 1,
        "envelope": 1,
        "recordKey": 1,
        "plaintext": 1,
        "manifest": 1,
        "keySchedule": 1,
        "upstreamBinding": 0,
        "upstreamMutationTable": 1
      },
      "openMlsRevision": "09e92777dba0528d3d29e2e5e681b7e91637c7be",
      "wasmArtifactPath": "styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm",
      "wasmArtifactSha256": "fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e",
      "ss0Ciphersuite": {
        "ianaId": "0x0001",
        "name": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
      },
      "ss0GateADecisionsSha256": "235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07",
      "buildId": "M2_WEB_FIREFOX_STANDARD",
      "runtimeClass": "BROWSER_STANDARD_NON_PRIVATE_NON_EVICTED",
      "browserClass": "FIREFOX"
    }
  ],
  "unsupportedRuntimeClasses": [
    "MOBILE",
    "NATIVE_NON_BROWSER",
    "PRIVATE_BROWSING",
    "EVICTED_OR_PARTIAL_PROFILE"
  ],
  "phaseOrder": [
    "LOCK",
    "BUILD_ELIGIBILITY",
    "INVENTORY",
    "WRAPPER_AUTH",
    "KEY_DERIVATION",
    "SELECTOR_HEADER",
    "SELECTOR_AUTH",
    "AUTHENTICATED_COMPATIBILITY",
    "MANIFEST_ROOT",
    "RECORD_SET",
    "RECORD_DECODE",
    "REFERENCES",
    "CLASSIFY",
    "EXPOSE"
  ],
  "phaseRules": [
    {
      "phase": "LOCK",
      "rule": "Acquire the one-writer Web Lock; read no M2 or legacy bytes before success."
    },
    {
      "phase": "BUILD_ELIGIBILITY",
      "rule": "Match one complete buildMatrix row before reading, unlocking, deriving, or decoding M2 bytes."
    },
    {
      "phase": "INVENTORY",
      "rule": "Inventory the sole fixed selector locator and all closed M2 generation artifacts; separately inventory legacy presence; no decode, comparison, scanning selection, or fallback."
    },
    {
      "phase": "WRAPPER_AUTH",
      "rule": "Unlock and authenticate the existing wrapper; failure is not a record oracle."
    },
    {
      "phase": "KEY_DERIVATION",
      "rule": "Derive only the exact C-FMT keys."
    },
    {
      "phase": "SELECTOR_HEADER",
      "rule": "Inspect only fixed structural header fields; unknown version is UNSUPPORTED_VERSION, other recognized-header incompatibility is INCOMPATIBLE_FORMAT; trust no value."
    },
    {
      "phase": "SELECTOR_AUTH",
      "rule": "Authenticate and canonically decode exactly one fixed-locator selector; never enumerate selectors or generations to choose one."
    },
    {
      "phase": "AUTHENTICATED_COMPATIBILITY",
      "rule": "Apply the entire compatibilityRegistry conjunction to authenticated values; version mismatch precedes other profile mismatch."
    },
    {
      "phase": "MANIFEST_ROOT",
      "rule": "Locate only the named manifest and verify envelope, canonical bytes, ciphertext digest, manifest-key digest, and keyed root."
    },
    {
      "phase": "RECORD_SET",
      "rule": "Require the exact ordered duplicate-free complete record set; selected or candidate subsets, additions, omissions, substitutions, or reordering reject."
    },
    {
      "phase": "RECORD_DECODE",
      "rule": "Authenticate, decode, and byte-identically re-encode every named record; validate AAD/key/kind/version/scope/context/profile/generation and tombstones."
    },
    {
      "phase": "REFERENCES",
      "rule": "Validate selector state, selected-generation equality, bindings, KeyPackage lifecycle, result/escrow/hold/component associations, and candidate parent rules."
    },
    {
      "phase": "CLASSIFY",
      "rule": "Map the authenticated selected state to exactly one success; retain reconciliation facts without retry or output release."
    },
    {
      "phase": "EXPOSE",
      "rule": "Only now expose selected authority; candidate, legacy, partial plaintext, escrow, and output remain unexposed."
    }
  ],
  "inventoryRules": {
    "fixedM2Locator": "ASCII STYXSEL1 || u16be(version=1) || localContextId[32]",
    "noM2State": "absence of every M2 fixed locator and every M2 generation artifact",
    "emptyState": "authenticated selector and complete C-FMT EMPTY generation only",
    "multipleSelectorCandidates": "SELECTOR_INVALID",
    "orphanGeneration": "PARTIAL_GENERATION",
    "legacyDomain": "disjoint; preserve, never decode as M2, import, compare against SS-0, or use as fallback"
  },
  "candidateRules": {
    "locator": "candidateManifestKey from authenticated selector plaintext only",
    "locatorValidation": "parse exact candidateManifestKey under the canonical record-key grammar as kind 16 with empty objectId; require its generation and localContextId to equal candidateGeneration and the locator context, its SHA-256 to equal candidateManifestKeyDigest, and the located candidate manifest binding digest to match that candidate generation own BINDING_PROFILE",
    "selectedRelation": "candidate locator fields are always present; when the candidate generation, exact manifest key, manifest-key digest, manifest ciphertext digest and keyed root equal the selected values there is no separate candidate and state MUST NOT be RECONCILIATION_REQUIRED; when different, state MUST be RECONCILIATION_REQUIRED, selected MUTATION_HOLD MUST be a tombstone, and candidate MUTATION_HOLD MUST be present; every other combination rejects",
    "unresolvedPhysicalParent": "for an unresolved candidate MUTATION_HOLD whose resultStatus is INDETERMINATE while the selector names old authority, parentGeneration and parentKeyedRoot MUST equal the selector generation and keyedRoot; this compares physical identity only; terminal COMMITTED or NOT_COMMITTED holds are governed by C-MUT terminal rules and do not compare their parent to a selector that has moved",
    "logicalOriginalAuthority": "candidate MUTATION_HOLD originalAuthorityDigest and originalAuthorityReference MUST equal the same fields in the candidate COMMIT_RESULT authenticated RS evidence; these remain C-MUT logical identifiers and are not compared with parentGeneration or parentKeyedRoot",
    "selectedMutationHold": "canonical tombstone when a distinct reconciliation candidate exists",
    "candidateMutationHold": "present and authenticated in the complete candidate generation",
    "candidateAuthority": false,
    "enumerationOrCounterSelection": false,
    "repairSource": false
  },
  "resultSets": {
    "inventory": [
      "NO_M2_STATE",
      "LEGACY_ONLY"
    ],
    "success": [
      "RESTORED_EMPTY",
      "RESTORED_ACTIVE",
      "RESTORED_RECONCILIATION_REQUIRED"
    ],
    "failure": [
      "LOCKED_ELSEWHERE",
      "WRAPPER_AUTH_FAILED",
      "INCOMPATIBLE_BUILD",
      "INCOMPATIBLE_FORMAT",
      "UNSUPPORTED_VERSION",
      "SELECTOR_INVALID",
      "AUTHENTICATION_FAILED",
      "MANIFEST_INVALID",
      "RECORD_SET_INCOMPLETE",
      "RECORD_INVALID",
      "REFERENCE_INCONSISTENT",
      "PARTIAL_GENERATION",
      "INTERNAL_VALIDATION_FAILED"
    ],
    "condition": [
      "LEGACY_PRESENT"
    ]
  },
  "faultPrecedence": [
    {
      "fault": "lockUnavailable",
      "phase": "LOCK",
      "result": "LOCKED_ELSEWHERE"
    },
    {
      "fault": "buildNotListed",
      "phase": "BUILD_ELIGIBILITY",
      "result": "INCOMPATIBLE_BUILD"
    },
    {
      "fault": "inventoryAmbiguous",
      "phase": "INVENTORY",
      "result": "INTERNAL_VALIDATION_FAILED"
    },
    {
      "fault": "multipleSelectorCandidates",
      "phase": "INVENTORY",
      "result": "SELECTOR_INVALID"
    },
    {
      "fault": "orphanGeneration",
      "phase": "INVENTORY",
      "result": "PARTIAL_GENERATION"
    },
    {
      "fault": "wrapperWrongOrInvalid",
      "phase": "WRAPPER_AUTH",
      "result": "WRAPPER_AUTH_FAILED"
    },
    {
      "fault": "keyDerivationFailed",
      "phase": "KEY_DERIVATION",
      "result": "INTERNAL_VALIDATION_FAILED"
    },
    {
      "fault": "selectorHeaderVersionUnknown",
      "phase": "SELECTOR_HEADER",
      "result": "UNSUPPORTED_VERSION"
    },
    {
      "fault": "selectorHeaderStructureIncompatible",
      "phase": "SELECTOR_HEADER",
      "result": "INCOMPATIBLE_FORMAT"
    },
    {
      "fault": "selectorMalformedOrMultiple",
      "phase": "SELECTOR_AUTH",
      "result": "SELECTOR_INVALID"
    },
    {
      "fault": "selectorAuthenticationFailed",
      "phase": "SELECTOR_AUTH",
      "result": "AUTHENTICATION_FAILED"
    },
    {
      "fault": "authenticatedVersionUnknownOrMixed",
      "phase": "AUTHENTICATED_COMPATIBILITY",
      "result": "UNSUPPORTED_VERSION"
    },
    {
      "fault": "authenticatedProfileIncompatible",
      "phase": "AUTHENTICATED_COMPATIBILITY",
      "result": "INCOMPATIBLE_FORMAT"
    },
    {
      "fault": "manifestOrRootMismatch",
      "phase": "MANIFEST_ROOT",
      "result": "MANIFEST_INVALID"
    },
    {
      "fault": "recordMissingExtraDuplicateReordered",
      "phase": "RECORD_SET",
      "result": "RECORD_SET_INCOMPLETE"
    },
    {
      "fault": "partialSelectedOrCandidateGeneration",
      "phase": "RECORD_SET",
      "result": "PARTIAL_GENERATION"
    },
    {
      "fault": "recordAuthenticationFailed",
      "phase": "RECORD_DECODE",
      "result": "AUTHENTICATION_FAILED"
    },
    {
      "fault": "recordCanonicalKeyKindVersionGenerationInvalid",
      "phase": "RECORD_DECODE",
      "result": "RECORD_INVALID"
    },
    {
      "fault": "candidateManifestKeyScopeSessionSubstitution",
      "phase": "RECORD_DECODE",
      "result": "RECORD_INVALID"
    },
    {
      "fault": "referenceOrLifecycleInconsistent",
      "phase": "REFERENCES",
      "result": "REFERENCE_INCONSISTENT"
    },
    {
      "fault": "candidateManifestKeyMismatch",
      "phase": "REFERENCES",
      "result": "REFERENCE_INCONSISTENT"
    },
    {
      "fault": "candidateParentMismatch",
      "phase": "REFERENCES",
      "result": "REFERENCE_INCONSISTENT"
    },
    {
      "fault": "candidateEqualsSelectedDuringReconciliation",
      "phase": "REFERENCES",
      "result": "REFERENCE_INCONSISTENT"
    },
    {
      "fault": "candidateFieldsDifferWithoutReconciliation",
      "phase": "REFERENCES",
      "result": "REFERENCE_INCONSISTENT"
    },
    {
      "fault": "unexpectedValidatorCondition",
      "phase": "CLASSIFY",
      "result": "INTERNAL_VALIDATION_FAILED"
    },
    {
      "fault": "unexpectedExposeCondition",
      "phase": "EXPOSE",
      "result": "INTERNAL_VALIDATION_FAILED"
    }
  ],
  "negativeClassMap": [
    {
      "negativeClass": "UNKNOWN_MISSING_DUPLICATE_REORDERED_JSON_FIELD",
      "fault": "unexpectedValidatorCondition",
      "phase": "CLASSIFY",
      "result": "INTERNAL_VALIDATION_FAILED"
    },
    {
      "negativeClass": "UNKNOWN_MISSING_DUPLICATE_REORDERED_PLAINTEXT_FIELD",
      "fault": "recordCanonicalKeyKindVersionGenerationInvalid",
      "phase": "RECORD_DECODE",
      "result": "RECORD_INVALID"
    },
    {
      "negativeClass": "UNKNOWN_KIND_VERSION_ALGORITHM_LABEL",
      "fault": "authenticatedVersionUnknownOrMixed",
      "phase": "AUTHENTICATED_COMPATIBILITY",
      "result": "UNSUPPORTED_VERSION"
    },
    {
      "negativeClass": "NONCANONICAL_LENGTH_ENDIAN",
      "fault": "selectorHeaderStructureIncompatible",
      "phase": "SELECTOR_HEADER",
      "result": "INCOMPATIBLE_FORMAT"
    },
    {
      "negativeClass": "TRUNCATION_TRAILING_SIZE_OVERFLOW",
      "fault": "selectorHeaderStructureIncompatible",
      "phase": "SELECTOR_HEADER",
      "result": "INCOMPATIBLE_FORMAT"
    },
    {
      "negativeClass": "NONCE_REUSE",
      "fault": "recordAuthenticationFailed",
      "phase": "RECORD_DECODE",
      "result": "AUTHENTICATION_FAILED"
    },
    {
      "negativeClass": "AAD_CONTEXT_SESSION_PROFILE_KIND_VERSION_GENERATION_SUBSTITUTION",
      "fault": "recordAuthenticationFailed",
      "phase": "RECORD_DECODE",
      "result": "AUTHENTICATION_FAILED"
    },
    {
      "negativeClass": "KEY_OR_LABEL_COLLISION",
      "fault": "authenticatedProfileIncompatible",
      "phase": "AUTHENTICATED_COMPATIBILITY",
      "result": "INCOMPATIBLE_FORMAT"
    },
    {
      "negativeClass": "CROSS_DOMAIN_COPY",
      "fault": "recordAuthenticationFailed",
      "phase": "RECORD_DECODE",
      "result": "AUTHENTICATION_FAILED"
    },
    {
      "negativeClass": "MANIFEST_OMISSION_ADDITION_DUPLICATE_REORDER",
      "fault": "manifestOrRootMismatch",
      "phase": "MANIFEST_ROOT",
      "result": "MANIFEST_INVALID"
    },
    {
      "negativeClass": "ROOT_OR_SELECTOR_MISMATCH",
      "fault": "manifestOrRootMismatch",
      "phase": "MANIFEST_ROOT",
      "result": "MANIFEST_INVALID"
    },
    {
      "negativeClass": "HISTORICAL_SUBSET_UNDER_CURRENT_ROOT",
      "fault": "manifestOrRootMismatch",
      "phase": "MANIFEST_ROOT",
      "result": "MANIFEST_INVALID"
    },
    {
      "negativeClass": "PARTIAL_GENERATION",
      "fault": "partialSelectedOrCandidateGeneration",
      "phase": "RECORD_SET",
      "result": "PARTIAL_GENERATION"
    },
    {
      "negativeClass": "FORGED_RESULT_ESCROW_ASSOCIATION",
      "fault": "referenceOrLifecycleInconsistent",
      "phase": "REFERENCES",
      "result": "REFERENCE_INCONSISTENT"
    },
    {
      "negativeClass": "CANDIDATE_FIELDS_DIFFER_WITHOUT_RECONCILIATION_REQUIRED",
      "fault": "candidateFieldsDifferWithoutReconciliation",
      "phase": "REFERENCES",
      "result": "REFERENCE_INCONSISTENT"
    },
    {
      "negativeClass": "RECONCILIATION_REQUIRED_CANDIDATE_MISSING_OR_MISMATCHED",
      "fault": "candidateManifestKeyMismatch",
      "phase": "REFERENCES",
      "result": "REFERENCE_INCONSISTENT"
    },
    {
      "negativeClass": "RECONCILIATION_REQUIRED_CANDIDATE_EQUALS_SELECTED",
      "fault": "candidateEqualsSelectedDuringReconciliation",
      "phase": "REFERENCES",
      "result": "REFERENCE_INCONSISTENT"
    },
    {
      "negativeClass": "CANDIDATE_MANIFEST_KEY_MISMATCH",
      "fault": "candidateManifestKeyMismatch",
      "phase": "REFERENCES",
      "result": "REFERENCE_INCONSISTENT"
    },
    {
      "negativeClass": "CANDIDATE_PARENT_MISMATCH",
      "fault": "candidateParentMismatch",
      "phase": "REFERENCES",
      "result": "REFERENCE_INCONSISTENT"
    },
    {
      "negativeClass": "CANDIDATE_MANIFEST_KEY_SCOPE_SESSION_SUBSTITUTION",
      "fault": "candidateManifestKeyScopeSessionSubstitution",
      "phase": "RECORD_DECODE",
      "result": "RECORD_INVALID"
    }
  ],
  "failureDefault": "INTERNAL_VALIDATION_FAILED",
  "successBySelectorState": {
    "EMPTY": "RESTORED_EMPTY",
    "ACTIVE": "RESTORED_ACTIVE",
    "RECONCILIATION_REQUIRED": "RESTORED_RECONCILIATION_REQUIRED"
  },
  "exposure": {
    "beforeEXPOSE": [],
    "atEXPOSE": [
      "SELECTED_AUTHORITY"
    ],
    "never": [
      "UNSELECTED_CANDIDATE_AS_AUTHORITY",
      "LEGACY_AS_AUTHORITY",
      "PARTIAL_PLAINTEXT",
      "ESCROW_OUTPUT_FROM_RESTORE"
    ]
  },
  "diagnostics": {
    "allowed": [
      "stageCode",
      "reasonCode",
      "m2LocatorCount",
      "m2ArtifactCount",
      "legacyPresent"
    ],
    "forbidden": [
      "raw keys",
      "nonces",
      "plaintext",
      "binding bytes",
      "context identifiers",
      "session identifiers",
      "package references",
      "digests",
      "record keys",
      "escrow content"
    ],
    "stageCodes": [
      "LOCK",
      "BUILD_ELIGIBILITY",
      "INVENTORY",
      "WRAPPER_AUTH",
      "KEY_DERIVATION",
      "SELECTOR_HEADER",
      "SELECTOR_AUTH",
      "AUTHENTICATED_COMPATIBILITY",
      "MANIFEST_ROOT",
      "RECORD_SET",
      "RECORD_DECODE",
      "REFERENCES",
      "CLASSIFY",
      "EXPOSE"
    ],
    "reasonCodes": [
      "NO_M2_STATE",
      "LEGACY_ONLY",
      "RESTORED_EMPTY",
      "RESTORED_ACTIVE",
      "RESTORED_RECONCILIATION_REQUIRED",
      "LOCKED_ELSEWHERE",
      "WRAPPER_AUTH_FAILED",
      "INCOMPATIBLE_BUILD",
      "INCOMPATIBLE_FORMAT",
      "UNSUPPORTED_VERSION",
      "SELECTOR_INVALID",
      "AUTHENTICATION_FAILED",
      "MANIFEST_INVALID",
      "RECORD_SET_INCOMPLETE",
      "RECORD_INVALID",
      "REFERENCE_INCONSISTENT",
      "PARTIAL_GENERATION",
      "INTERNAL_VALIDATION_FAILED",
      "LEGACY_PRESENT"
    ]
  },
  "corruptionAction": "PRESERVE_AND_STOP_LOGICAL_READ_DISABLE_ONLY",
  "automaticActions": {
    "rewrite": false,
    "normalize": false,
    "regenerate": false,
    "fallback": false,
    "repair": false,
    "clearHold": false,
    "consumeKeyPackage": false,
    "discardEscrow": false,
    "automaticReset": false
  },
  "guidance": {
    "compatibleBuild": "Identify the exact reader profile CFMT_EXACT_B57DF3A8 and preserve all bytes.",
    "destructiveReset": "Explicit, separate, irreversible, never automatic; not implemented here.",
    "passwordChange": "Re-wrap the same Root Storage Key; not migration or repair.",
    "legacy": "Visible re-establishment guidance only; preserve all bytes."
  },
  "fixtures": {
    "positive": [
      {
        "id": "POS-NO-M2",
        "inventory": "NONE",
        "vector": null,
        "legacy": false,
        "result": "NO_M2_STATE",
        "firstPhase": "INVENTORY",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": []
      },
      {
        "id": "POS-LEGACY-ONLY",
        "inventory": "LEGACY_ONLY",
        "vector": null,
        "legacy": true,
        "result": "LEGACY_ONLY",
        "firstPhase": "INVENTORY",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "legacy",
            "kind": "LEGACY_ENVELOPE"
          }
        ]
      },
      {
        "id": "POS-EMPTY",
        "inventory": "M2",
        "vector": "FMT-KAT-EMPTY",
        "legacy": false,
        "result": "RESTORED_EMPTY",
        "firstPhase": "EXPOSE",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "POS-ACTIVE",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "result": "RESTORED_ACTIVE",
        "firstPhase": "EXPOSE",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "POS-HOLD",
        "inventory": "M2",
        "vector": "FMT-KAT-HOLD",
        "legacy": false,
        "result": "RESTORED_RECONCILIATION_REQUIRED",
        "firstPhase": "EXPOSE",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "POS-EMPTY-HOLD",
        "inventory": "M2",
        "vector": "FMT-KAT-EMPTY-HOLD",
        "legacy": false,
        "result": "RESTORED_RECONCILIATION_REQUIRED",
        "firstPhase": "EXPOSE",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "POS-M2-LEGACY-PRESENT",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": true,
        "result": "RESTORED_ACTIVE",
        "condition": "LEGACY_PRESENT",
        "firstPhase": "EXPOSE",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          },
          {
            "id": "legacy",
            "kind": "LEGACY_ENVELOPE"
          }
        ]
      }
    ],
    "negative": [
      {
        "id": "NEG-LOCKUNAVAILABLE",
        "faults": [
          "lockUnavailable"
        ],
        "result": "LOCKED_ELSEWHERE",
        "firstPhase": "LOCK",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-BUILDNOTLISTED",
        "faults": [
          "buildNotListed"
        ],
        "result": "INCOMPATIBLE_BUILD",
        "firstPhase": "BUILD_ELIGIBILITY",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-INVENTORYAMBIGUOUS",
        "faults": [
          "inventoryAmbiguous"
        ],
        "result": "INTERNAL_VALIDATION_FAILED",
        "firstPhase": "INVENTORY",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-WRAPPERWRONGORINVALID",
        "faults": [
          "wrapperWrongOrInvalid"
        ],
        "result": "WRAPPER_AUTH_FAILED",
        "firstPhase": "WRAPPER_AUTH",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-SELECTORHEADERVERSIONUNKNOWN",
        "faults": [
          "selectorHeaderVersionUnknown"
        ],
        "result": "UNSUPPORTED_VERSION",
        "firstPhase": "SELECTOR_HEADER",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-SELECTORHEADERSTRUCTUREINCOMPATIBLE",
        "faults": [
          "selectorHeaderStructureIncompatible"
        ],
        "result": "INCOMPATIBLE_FORMAT",
        "firstPhase": "SELECTOR_HEADER",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-SELECTORMALFORMEDORMULTIPLE",
        "faults": [
          "selectorMalformedOrMultiple"
        ],
        "result": "SELECTOR_INVALID",
        "firstPhase": "SELECTOR_AUTH",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-SELECTORAUTHENTICATIONFAILED",
        "faults": [
          "selectorAuthenticationFailed"
        ],
        "result": "AUTHENTICATION_FAILED",
        "firstPhase": "SELECTOR_AUTH",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-AUTHENTICATEDVERSIONUNKNOWNORMIXED",
        "faults": [
          "authenticatedVersionUnknownOrMixed"
        ],
        "result": "UNSUPPORTED_VERSION",
        "firstPhase": "AUTHENTICATED_COMPATIBILITY",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-AUTHENTICATEDPROFILEINCOMPATIBLE",
        "faults": [
          "authenticatedProfileIncompatible"
        ],
        "result": "INCOMPATIBLE_FORMAT",
        "firstPhase": "AUTHENTICATED_COMPATIBILITY",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-MANIFESTORROOTMISMATCH",
        "faults": [
          "manifestOrRootMismatch"
        ],
        "result": "MANIFEST_INVALID",
        "firstPhase": "MANIFEST_ROOT",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-RECORDMISSINGEXTRADUPLICATEREORDERED",
        "faults": [
          "recordMissingExtraDuplicateReordered"
        ],
        "result": "RECORD_SET_INCOMPLETE",
        "firstPhase": "RECORD_SET",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-PARTIALSELECTEDORCANDIDATEGENERATION",
        "faults": [
          "partialSelectedOrCandidateGeneration"
        ],
        "result": "PARTIAL_GENERATION",
        "firstPhase": "RECORD_SET",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-RECORDAUTHENTICATIONFAILED",
        "faults": [
          "recordAuthenticationFailed"
        ],
        "result": "AUTHENTICATION_FAILED",
        "firstPhase": "RECORD_DECODE",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-RECORDCANONICALKEYKINDVERSIONGENERATIONINVALID",
        "faults": [
          "recordCanonicalKeyKindVersionGenerationInvalid"
        ],
        "result": "RECORD_INVALID",
        "firstPhase": "RECORD_DECODE",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-REFERENCEORLIFECYCLEINCONSISTENT",
        "faults": [
          "referenceOrLifecycleInconsistent"
        ],
        "result": "REFERENCE_INCONSISTENT",
        "firstPhase": "REFERENCES",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-UNEXPECTEDVALIDATORCONDITION",
        "faults": [
          "unexpectedValidatorCondition"
        ],
        "result": "INTERNAL_VALIDATION_FAILED",
        "firstPhase": "CLASSIFY",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-UNKNOWN-MIXED-VERSIONS",
        "faults": [
          "authenticatedVersionUnknownOrMixed"
        ],
        "result": "UNSUPPORTED_VERSION",
        "firstPhase": "AUTHENTICATED_COMPATIBILITY",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-INELIGIBLE-BUILD",
        "faults": [
          "buildNotListed"
        ],
        "result": "INCOMPATIBLE_BUILD",
        "firstPhase": "BUILD_ELIGIBILITY",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-MALFORMED-SELECTOR",
        "faults": [
          "selectorMalformedOrMultiple"
        ],
        "result": "SELECTOR_INVALID",
        "firstPhase": "SELECTOR_AUTH",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-SELECTOR-MANIFEST-ROOT-MISMATCH",
        "faults": [
          "manifestOrRootMismatch"
        ],
        "result": "MANIFEST_INVALID",
        "firstPhase": "MANIFEST_ROOT",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-MISSING-RECORD",
        "faults": [
          "recordMissingExtraDuplicateReordered"
        ],
        "result": "RECORD_SET_INCOMPLETE",
        "firstPhase": "RECORD_SET",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-EXTRA-RECORD",
        "faults": [
          "recordMissingExtraDuplicateReordered"
        ],
        "result": "RECORD_SET_INCOMPLETE",
        "firstPhase": "RECORD_SET",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-DUPLICATE-RECORD",
        "faults": [
          "recordMissingExtraDuplicateReordered"
        ],
        "result": "RECORD_SET_INCOMPLETE",
        "firstPhase": "RECORD_SET",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-REORDERED-RECORD",
        "faults": [
          "recordMissingExtraDuplicateReordered"
        ],
        "result": "RECORD_SET_INCOMPLETE",
        "firstPhase": "RECORD_SET",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-RECORD-KEY-SUBSTITUTION",
        "faults": [
          "recordCanonicalKeyKindVersionGenerationInvalid"
        ],
        "result": "RECORD_INVALID",
        "firstPhase": "RECORD_DECODE",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-RECORD-KIND-SUBSTITUTION",
        "faults": [
          "recordCanonicalKeyKindVersionGenerationInvalid"
        ],
        "result": "RECORD_INVALID",
        "firstPhase": "RECORD_DECODE",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-SELECTED-GENERATION-SUBSTITUTION",
        "faults": [
          "recordCanonicalKeyKindVersionGenerationInvalid"
        ],
        "result": "RECORD_INVALID",
        "firstPhase": "RECORD_DECODE",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-BAD-TOMBSTONE",
        "faults": [
          "recordCanonicalKeyKindVersionGenerationInvalid"
        ],
        "result": "RECORD_INVALID",
        "firstPhase": "RECORD_DECODE",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-PARTIAL-CANDIDATE",
        "faults": [
          "partialSelectedOrCandidateGeneration"
        ],
        "result": "PARTIAL_GENERATION",
        "firstPhase": "RECORD_SET",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-FORGED-RESULT-ESCROW-HOLD",
        "faults": [
          "referenceOrLifecycleInconsistent"
        ],
        "result": "REFERENCE_INCONSISTENT",
        "firstPhase": "REFERENCES",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-INVALID-LIFECYCLE-PAIR",
        "faults": [
          "referenceOrLifecycleInconsistent"
        ],
        "result": "REFERENCE_INCONSISTENT",
        "firstPhase": "REFERENCES",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-AMBIGUOUS-INVENTORY",
        "faults": [
          "inventoryAmbiguous"
        ],
        "result": "INTERNAL_VALIDATION_FAILED",
        "firstPhase": "INVENTORY",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-LEGACY-SHAPED-AT-M2-LOCATOR",
        "faults": [
          "selectorHeaderStructureIncompatible"
        ],
        "result": "INCOMPATIBLE_FORMAT",
        "firstPhase": "SELECTOR_HEADER",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-LEGACY-CIPHERSUITE-AT-M2-LOCATOR",
        "faults": [
          "authenticatedProfileIncompatible"
        ],
        "result": "INCOMPATIBLE_FORMAT",
        "firstPhase": "AUTHENTICATED_COMPATIBILITY",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-M2-LEGACY-PRESENT-INVALID",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": true,
        "faults": [
          "manifestOrRootMismatch"
        ],
        "result": "MANIFEST_INVALID",
        "condition": "LEGACY_PRESENT",
        "firstPhase": "MANIFEST_ROOT",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          },
          {
            "id": "legacy",
            "kind": "LEGACY_ENVELOPE"
          }
        ]
      },
      {
        "id": "NEG-CONCRETE-MULTIPLE-SELECTOR-CANDIDATES",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "faults": [
          "multipleSelectorCandidates"
        ],
        "result": "SELECTOR_INVALID",
        "firstPhase": "INVENTORY",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CONCRETE-ORPHAN-GENERATION",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "faults": [
          "orphanGeneration"
        ],
        "result": "PARTIAL_GENERATION",
        "firstPhase": "INVENTORY",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CONCRETE-KEY-DERIVATION-FAILED",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "faults": [
          "keyDerivationFailed"
        ],
        "result": "INTERNAL_VALIDATION_FAILED",
        "firstPhase": "KEY_DERIVATION",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CONCRETE-CANDIDATE-MANIFEST-KEY-SCOPE-SESSION-SUBSTITUTION",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "faults": [
          "candidateManifestKeyScopeSessionSubstitution"
        ],
        "result": "RECORD_INVALID",
        "firstPhase": "RECORD_DECODE",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CONCRETE-CANDIDATE-MANIFEST-KEY-MISMATCH",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "faults": [
          "candidateManifestKeyMismatch"
        ],
        "result": "REFERENCE_INCONSISTENT",
        "firstPhase": "REFERENCES",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CONCRETE-CANDIDATE-PARENT-MISMATCH",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "faults": [
          "candidateParentMismatch"
        ],
        "result": "REFERENCE_INCONSISTENT",
        "firstPhase": "REFERENCES",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CONCRETE-CANDIDATE-EQUALS-SELECTED-DURING-RECONCILIATION",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "faults": [
          "candidateEqualsSelectedDuringReconciliation"
        ],
        "result": "REFERENCE_INCONSISTENT",
        "firstPhase": "REFERENCES",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CONCRETE-CANDIDATE-FIELDS-DIFFER-WITHOUT-RECONCILIATION",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "faults": [
          "candidateFieldsDifferWithoutReconciliation"
        ],
        "result": "REFERENCE_INCONSISTENT",
        "firstPhase": "REFERENCES",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CONCRETE-UNEXPECTED-EXPOSE-CONDITION",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "faults": [
          "unexpectedExposeCondition"
        ],
        "result": "INTERNAL_VALIDATION_FAILED",
        "firstPhase": "EXPOSE",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CFMT-UNKNOWN_MISSING_DUPLICATE_REORDERED_JSON_FIELD",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "negativeClass": "UNKNOWN_MISSING_DUPLICATE_REORDERED_JSON_FIELD",
        "faults": [
          "unexpectedValidatorCondition"
        ],
        "result": "INTERNAL_VALIDATION_FAILED",
        "firstPhase": "CLASSIFY",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CFMT-UNKNOWN_MISSING_DUPLICATE_REORDERED_PLAINTEXT_FIELD",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "negativeClass": "UNKNOWN_MISSING_DUPLICATE_REORDERED_PLAINTEXT_FIELD",
        "faults": [
          "recordCanonicalKeyKindVersionGenerationInvalid"
        ],
        "result": "RECORD_INVALID",
        "firstPhase": "RECORD_DECODE",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CFMT-UNKNOWN_KIND_VERSION_ALGORITHM_LABEL",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "negativeClass": "UNKNOWN_KIND_VERSION_ALGORITHM_LABEL",
        "faults": [
          "authenticatedVersionUnknownOrMixed"
        ],
        "result": "UNSUPPORTED_VERSION",
        "firstPhase": "AUTHENTICATED_COMPATIBILITY",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CFMT-NONCANONICAL_LENGTH_ENDIAN",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "negativeClass": "NONCANONICAL_LENGTH_ENDIAN",
        "faults": [
          "selectorHeaderStructureIncompatible"
        ],
        "result": "INCOMPATIBLE_FORMAT",
        "firstPhase": "SELECTOR_HEADER",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CFMT-TRUNCATION_TRAILING_SIZE_OVERFLOW",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "negativeClass": "TRUNCATION_TRAILING_SIZE_OVERFLOW",
        "faults": [
          "selectorHeaderStructureIncompatible"
        ],
        "result": "INCOMPATIBLE_FORMAT",
        "firstPhase": "SELECTOR_HEADER",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CFMT-NONCE_REUSE",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "negativeClass": "NONCE_REUSE",
        "faults": [
          "recordAuthenticationFailed"
        ],
        "result": "AUTHENTICATION_FAILED",
        "firstPhase": "RECORD_DECODE",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CFMT-AAD_CONTEXT_SESSION_PROFILE_KIND_VERSION_GENERATION_SUBSTITUTION",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "negativeClass": "AAD_CONTEXT_SESSION_PROFILE_KIND_VERSION_GENERATION_SUBSTITUTION",
        "faults": [
          "recordAuthenticationFailed"
        ],
        "result": "AUTHENTICATION_FAILED",
        "firstPhase": "RECORD_DECODE",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CFMT-KEY_OR_LABEL_COLLISION",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "negativeClass": "KEY_OR_LABEL_COLLISION",
        "faults": [
          "authenticatedProfileIncompatible"
        ],
        "result": "INCOMPATIBLE_FORMAT",
        "firstPhase": "AUTHENTICATED_COMPATIBILITY",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CFMT-CROSS_DOMAIN_COPY",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "negativeClass": "CROSS_DOMAIN_COPY",
        "faults": [
          "recordAuthenticationFailed"
        ],
        "result": "AUTHENTICATION_FAILED",
        "firstPhase": "RECORD_DECODE",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CFMT-MANIFEST_OMISSION_ADDITION_DUPLICATE_REORDER",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "negativeClass": "MANIFEST_OMISSION_ADDITION_DUPLICATE_REORDER",
        "faults": [
          "manifestOrRootMismatch"
        ],
        "result": "MANIFEST_INVALID",
        "firstPhase": "MANIFEST_ROOT",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CFMT-ROOT_OR_SELECTOR_MISMATCH",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "negativeClass": "ROOT_OR_SELECTOR_MISMATCH",
        "faults": [
          "manifestOrRootMismatch"
        ],
        "result": "MANIFEST_INVALID",
        "firstPhase": "MANIFEST_ROOT",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CFMT-HISTORICAL_SUBSET_UNDER_CURRENT_ROOT",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "negativeClass": "HISTORICAL_SUBSET_UNDER_CURRENT_ROOT",
        "faults": [
          "manifestOrRootMismatch"
        ],
        "result": "MANIFEST_INVALID",
        "firstPhase": "MANIFEST_ROOT",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CFMT-PARTIAL_GENERATION",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "negativeClass": "PARTIAL_GENERATION",
        "faults": [
          "partialSelectedOrCandidateGeneration"
        ],
        "result": "PARTIAL_GENERATION",
        "firstPhase": "RECORD_SET",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CFMT-FORGED_RESULT_ESCROW_ASSOCIATION",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "negativeClass": "FORGED_RESULT_ESCROW_ASSOCIATION",
        "faults": [
          "referenceOrLifecycleInconsistent"
        ],
        "result": "REFERENCE_INCONSISTENT",
        "firstPhase": "REFERENCES",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CFMT-CANDIDATE_FIELDS_DIFFER_WITHOUT_RECONCILIATION_REQUIRED",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "negativeClass": "CANDIDATE_FIELDS_DIFFER_WITHOUT_RECONCILIATION_REQUIRED",
        "faults": [
          "candidateFieldsDifferWithoutReconciliation"
        ],
        "result": "REFERENCE_INCONSISTENT",
        "firstPhase": "REFERENCES",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CFMT-RECONCILIATION_REQUIRED_CANDIDATE_MISSING_OR_MISMATCHED",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "negativeClass": "RECONCILIATION_REQUIRED_CANDIDATE_MISSING_OR_MISMATCHED",
        "faults": [
          "candidateManifestKeyMismatch"
        ],
        "result": "REFERENCE_INCONSISTENT",
        "firstPhase": "REFERENCES",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CFMT-RECONCILIATION_REQUIRED_CANDIDATE_EQUALS_SELECTED",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "negativeClass": "RECONCILIATION_REQUIRED_CANDIDATE_EQUALS_SELECTED",
        "faults": [
          "candidateEqualsSelectedDuringReconciliation"
        ],
        "result": "REFERENCE_INCONSISTENT",
        "firstPhase": "REFERENCES",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CFMT-CANDIDATE_MANIFEST_KEY_MISMATCH",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "negativeClass": "CANDIDATE_MANIFEST_KEY_MISMATCH",
        "faults": [
          "candidateManifestKeyMismatch"
        ],
        "result": "REFERENCE_INCONSISTENT",
        "firstPhase": "REFERENCES",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CFMT-CANDIDATE_PARENT_MISMATCH",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "negativeClass": "CANDIDATE_PARENT_MISMATCH",
        "faults": [
          "candidateParentMismatch"
        ],
        "result": "REFERENCE_INCONSISTENT",
        "firstPhase": "REFERENCES",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      },
      {
        "id": "NEG-CFMT-CANDIDATE_MANIFEST_KEY_SCOPE_SESSION_SUBSTITUTION",
        "inventory": "M2",
        "vector": "FMT-KAT-ACTIVE",
        "legacy": false,
        "negativeClass": "CANDIDATE_MANIFEST_KEY_SCOPE_SESSION_SUBSTITUTION",
        "faults": [
          "candidateManifestKeyScopeSessionSubstitution"
        ],
        "result": "RECORD_INVALID",
        "firstPhase": "RECORD_DECODE",
        "gates": {
          "LOCK": "PASS",
          "BUILD_ELIGIBILITY": "PASS",
          "INVENTORY": "PASS",
          "WRAPPER_AUTH": "PASS",
          "KEY_DERIVATION": "PASS",
          "SELECTOR_HEADER": "PASS",
          "SELECTOR_AUTH": "PASS",
          "AUTHENTICATED_COMPATIBILITY": "PASS",
          "MANIFEST_ROOT": "PASS",
          "RECORD_SET": "PASS",
          "RECORD_DECODE": "PASS",
          "REFERENCES": "PASS",
          "CLASSIFY": "PASS"
        },
        "artifacts": [
          {
            "id": "fixed-selector",
            "kind": "GENERATION_SELECTOR"
          },
          {
            "id": "selected-manifest",
            "kind": "MANIFEST"
          },
          {
            "id": "selected-record-set",
            "kind": "DATA_RECORD_SET"
          }
        ]
      }
    ]
  },
  "crashCoverage": [
    {
      "id": "BEFORE_STAGING",
      "memoryModes": [
        "RETAINED",
        "LOST"
      ],
      "source": {
        "id": "BEFORE_STAGING",
        "readbackByMemory": {
          "RETAINED": [
            "COMPLETE_OLD"
          ],
          "LOST": [
            "COMPLETE_OLD"
          ]
        },
        "apiState": "ORIGINAL",
        "output": "NONE",
        "classification": "NO_RS_REQUEST"
      }
    },
    {
      "id": "AFTER_CANDIDATE_COMPUTATION",
      "memoryModes": [
        "RETAINED",
        "LOST"
      ],
      "source": {
        "id": "AFTER_CANDIDATE_COMPUTATION",
        "readbackByMemory": {
          "RETAINED": [
            "COMPLETE_OLD"
          ],
          "LOST": [
            "COMPLETE_OLD"
          ]
        },
        "apiState": "ORIGINAL",
        "output": "NONE",
        "classification": "NO_RS_REQUEST"
      }
    },
    {
      "id": "AFTER_LOCAL_STAGING",
      "memoryModes": [
        "RETAINED",
        "LOST"
      ],
      "source": {
        "id": "AFTER_LOCAL_STAGING",
        "readbackByMemory": {
          "RETAINED": [
            "COMPLETE_OLD"
          ],
          "LOST": [
            "COMPLETE_OLD"
          ]
        },
        "apiState": "ORIGINAL",
        "output": "NONE",
        "classification": "NO_RS_REQUEST"
      }
    },
    {
      "id": "BEFORE_RS_REQUEST",
      "memoryModes": [
        "RETAINED",
        "LOST"
      ],
      "source": {
        "id": "BEFORE_RS_REQUEST",
        "readbackByMemory": {
          "RETAINED": [
            "COMPLETE_OLD"
          ],
          "LOST": [
            "COMPLETE_OLD"
          ]
        },
        "apiState": "ORIGINAL",
        "output": "NONE",
        "classification": "NO_RS_REQUEST"
      }
    },
    {
      "id": "DURING_RS_WORK",
      "memoryModes": [
        "RETAINED",
        "LOST"
      ],
      "source": {
        "id": "DURING_RS_WORK",
        "readbackByMemory": {
          "RETAINED": [
            "COMPLETE_OLD",
            "COMPLETE_NEW",
            "OLD_PLUS_ONE_IMMUTABLE_HOLD"
          ],
          "LOST": [
            "COMPLETE_OLD",
            "COMPLETE_NEW"
          ]
        },
        "apiState": "RECONCILIATION_REQUIRED_UNTIL_TERMINAL_READBACK",
        "output": "NONE_UNTIL_COMMITTED_PROVEN",
        "classification": "AUTHENTICATED_RS_EVIDENCE_ONLY"
      }
    },
    {
      "id": "AFTER_DURABLE_COMMIT_BEFORE_RESPONSE",
      "memoryModes": [
        "RETAINED",
        "LOST"
      ],
      "source": {
        "id": "AFTER_DURABLE_COMMIT_BEFORE_RESPONSE",
        "readbackByMemory": {
          "RETAINED": [
            "COMPLETE_NEW"
          ],
          "LOST": [
            "COMPLETE_NEW"
          ]
        },
        "apiStateByPath": {
          "ORIGINAL_TERMINAL": "ACTIVE_HOLD_RESOLVED",
          "POST_INDETERMINATE": "RECONCILIATION_REQUIRED_UNTIL_LOCAL_EMISSION_CALL_SUCCEEDS"
        },
        "outputByPath": {
          "ORIGINAL_TERMINAL": "ORIGINAL_SUCCESS_RESPONSE_PENDING",
          "POST_INDETERMINATE": "COMMITTED_ESCROW_AVAILABLE_TO_CAPI_S020_OR_S022"
        },
        "classificationByPath": {
          "ORIGINAL_TERMINAL": "CAPI_COMMITTED_RULE_NO_AP_RECONCILIATION_ROW_WITHOUT_PRIOR_REFERENCE",
          "POST_INDETERMINATE": "CAPI_S020_OR_S022"
        }
      }
    },
    {
      "id": "AFTER_NOT_COMMITTED",
      "memoryModes": [
        "RETAINED",
        "LOST"
      ],
      "source": {
        "id": "AFTER_NOT_COMMITTED",
        "readbackByMemory": {
          "RETAINED": [
            "COMPLETE_OLD"
          ],
          "LOST": [
            "COMPLETE_OLD"
          ]
        },
        "apiStateByPath": {
          "ORIGINAL_TERMINAL": "ORIGINAL_STATE_HOLD_RESOLVED",
          "POST_INDETERMINATE": "ORIGINAL_STATE_HOLD_CLEARED_WHEN_NO_OUTPUT_RESPONSE_FORMED"
        },
        "outputByPath": {
          "ORIGINAL_TERMINAL": "NONE",
          "POST_INDETERMINATE": "NONE"
        },
        "classificationByPath": {
          "ORIGINAL_TERMINAL": "CAPI_NOT_COMMITTED_RULE",
          "POST_INDETERMINATE": "CAPI_S021_OR_S023"
        }
      }
    },
    {
      "id": "AFTER_INDETERMINATE",
      "memoryModes": [
        "RETAINED",
        "LOST"
      ],
      "source": {
        "id": "AFTER_INDETERMINATE",
        "readbackByMemory": {
          "RETAINED": [
            "OLD_PLUS_ONE_IMMUTABLE_HOLD"
          ],
          "LOST": [
            "COMPLETE_OLD",
            "COMPLETE_NEW"
          ]
        },
        "apiState": "RECONCILIATION_REQUIRED",
        "output": "NONE",
        "classification": "LOST_MEMORY_REQUIRES_TERMINAL_AUTHENTICATED_C_REC_RS_READBACK"
      }
    },
    {
      "id": "DURING_RECONCILIATION",
      "memoryModes": [
        "RETAINED",
        "LOST"
      ],
      "source": {
        "id": "DURING_RECONCILIATION",
        "readbackByMemory": {
          "RETAINED": [
            "COMPLETE_OLD",
            "COMPLETE_NEW",
            "OLD_PLUS_ONE_IMMUTABLE_HOLD"
          ],
          "LOST": [
            "COMPLETE_OLD",
            "COMPLETE_NEW"
          ]
        },
        "apiState": "RECONCILIATION_REQUIRED_UNTIL_TERMINAL_RESPONSE_CONFIRMED",
        "output": "NONE_UNTIL_COMMITTED_PROVEN",
        "classification": "AUTHENTICATED_RS_EVIDENCE_ONLY"
      }
    },
    {
      "id": "AFTER_AUTHORITY_SELECTION_BEFORE_OUTPUT_RESPONSE",
      "memoryModes": [
        "RETAINED",
        "LOST"
      ],
      "source": {
        "id": "AFTER_AUTHORITY_SELECTION_BEFORE_OUTPUT_RESPONSE",
        "readbackByMemory": {
          "RETAINED": [
            "COMPLETE_NEW"
          ],
          "LOST": [
            "COMPLETE_NEW"
          ]
        },
        "apiStateByPath": {
          "ORIGINAL_TERMINAL": "ACTIVE_HOLD_RESOLVED",
          "POST_INDETERMINATE": "RECONCILIATION_REQUIRED_UNTIL_LOCAL_EMISSION_CALL_SUCCEEDS"
        },
        "outputByPath": {
          "ORIGINAL_TERMINAL": "ORIGINAL_SUCCESS_RESPONSE_PENDING",
          "POST_INDETERMINATE": "COMMITTED_ESCROW_AVAILABLE_TO_CAPI_S020_OR_S022"
        },
        "classificationByPath": {
          "ORIGINAL_TERMINAL": "CAPI_COMMITTED_RULE_NO_AP_RECONCILIATION_ROW_WITHOUT_PRIOR_REFERENCE",
          "POST_INDETERMINATE": "CAPI_S020_OR_S022"
        }
      }
    },
    {
      "id": "DURING_ESCROW_OUTPUT_RESPONSE",
      "memoryModes": [
        "RETAINED",
        "LOST"
      ],
      "source": {
        "id": "DURING_ESCROW_OUTPUT_RESPONSE",
        "readbackByMemory": {
          "RETAINED": [
            "COMPLETE_NEW"
          ],
          "LOST": [
            "COMPLETE_NEW"
          ]
        },
        "apiStateByPath": {
          "ORIGINAL_TERMINAL": "ACTIVE_HOLD_RESOLVED_INTERNAL_EVIDENCE_RETAINED_IF_INTERRUPTED",
          "POST_INDETERMINATE": "RECONCILIATION_REQUIRED_IF_LOCAL_EMISSION_CALL_INTERRUPTED"
        },
        "outputByPath": {
          "ORIGINAL_TERMINAL": "NO_AP_RECONCILIATION_REPLAY_WITHOUT_PRIOR_REFERENCE",
          "POST_INDETERMINATE": "SAME_COMMITTED_ESCROW_MAY_BE_RETURNED_AGAIN"
        },
        "classificationByPath": {
          "ORIGINAL_TERMINAL": "CAPI_COMMITTED_RULE",
          "POST_INDETERMINATE": "CAPI_S020_OR_S022"
        }
      }
    },
    {
      "id": "AFTER_OUTPUT_RESPONSE_LOSS",
      "memoryModes": [
        "RETAINED",
        "LOST"
      ],
      "source": {
        "id": "AFTER_OUTPUT_RESPONSE_LOSS",
        "readbackByMemory": {
          "RETAINED": [
            "COMPLETE_NEW"
          ],
          "LOST": [
            "COMPLETE_NEW"
          ]
        },
        "apiStateByPath": {
          "ORIGINAL_TERMINAL": "ACTIVE_HOLD_RESOLVED_INTERNAL_EVIDENCE_RETAINED",
          "POST_INDETERMINATE": "RECONCILIATION_REQUIRED_IF_LOCAL_EMISSION_CALL_DID_NOT_RETURN_SUCCESS"
        },
        "outputByPath": {
          "ORIGINAL_TERMINAL": "NO_AP_RECONCILIATION_REPLAY_WITHOUT_PRIOR_REFERENCE",
          "POST_INDETERMINATE": "SAME_COMMITTED_ESCROW_MAY_BE_RETURNED_AGAIN"
        },
        "classificationByPath": {
          "ORIGINAL_TERMINAL": "CAPI_COMMITTED_RULE",
          "POST_INDETERMINATE": "CAPI_S020_OR_S022"
        }
      }
    }
  ],
  "mutationCoverage": {
    "versions": [
      "format",
      "envelope",
      "recordKey",
      "plaintext",
      "manifest",
      "keySchedule",
      "upstreamBinding",
      "upstreamMutationTable"
    ],
    "algorithms": [
      "recordAead",
      "nonceBytes",
      "tagBytes",
      "hash",
      "mac",
      "kdf",
      "integerEndian"
    ],
    "labels": [
      "namespace",
      "recordAead",
      "manifestRoot",
      "selectorAead"
    ],
    "recordKinds": [
      "SLOT_REGISTRATION",
      "ISSUANCE_CANDIDATE",
      "ISSUANCE_OUTCOME",
      "KEY_PACKAGE",
      "SESSION_STATE",
      "BINDING_PROFILE",
      "REPLAY_RETENTION",
      "COMMIT_RESULT",
      "OUTPUT_ESCROW",
      "SELECTION_METADATA",
      "RETAINED_PARENT",
      "LOSING_CANDIDATE",
      "MUTATION_HOLD",
      "COMPONENT_SET",
      "ABSENCE_COMMITMENTS",
      "MANIFEST",
      "GENERATION_SELECTOR"
    ],
    "selectorFields": [
      "generation:u64",
      "manifestKeyDigest:b32",
      "manifestCipherDigest:b32",
      "keyedRoot:b32",
      "state:u8",
      "candidateGeneration:u64",
      "candidateManifestKey:bytes255",
      "candidateManifestKeyDigest:b32",
      "candidateManifestCipherDigest:b32",
      "candidateKeyedRoot:b32"
    ],
    "manifestLeaves": [
      "canonicalKey",
      "recordKind",
      "recordKindVersion",
      "ciphertextDigest",
      "keyedRoot"
    ],
    "recordAndAadDomains": [
      "STYXFMT1",
      "STYXKEY1",
      "STYXSEL1",
      "STYXAAD1",
      "STYXPLN1",
      "STYXMAN1",
      "STYXROOT1",
      "STYX-M2-PROFILE-DIGEST-V1",
      "STYX-M2-BINDING-DIGEST-V1",
      "STYX-OBJECT-ID-V1",
      "STYX-M2-CIPHERTEXT-DIGEST-V1"
    ],
    "generationRelations": [
      "selectedGeneration",
      "candidateGeneration",
      "manifest generation",
      "record writeGeneration",
      "parentGeneration",
      "parentKeyedRoot"
    ],
    "associationFields": [
      "operationIdentity",
      "candidateDigest",
      "candidateReference",
      "mutationSetDigest",
      "mutationSetReference",
      "resultDigest",
      "reconciliationReference",
      "originalAuthorityDigest",
      "originalAuthorityReference",
      "componentSetDigest",
      "componentSetReference",
      "heldOutputKind",
      "heldOutputDigest",
      "heldOutputReference",
      "bindingRef"
    ],
    "lifecyclePairs": [
      "UNCONSUMED:false",
      "UNCONSUMED:true",
      "RESERVED:false",
      "RESERVED:true",
      "CONSUMED:false",
      "CONSUMED:true",
      "INVALID:false",
      "INVALID:true"
    ]
  },
  "mutationFaultByFamily": {
    "versions": "authenticatedVersionUnknownOrMixed",
    "algorithms": "authenticatedProfileIncompatible",
    "labels": "authenticatedProfileIncompatible",
    "recordKinds": "recordCanonicalKeyKindVersionGenerationInvalid",
    "selectorFields": "selectorMalformedOrMultiple",
    "manifestLeaves": "manifestOrRootMismatch",
    "recordAndAadDomains": "recordAuthenticationFailed",
    "generationRelations": "referenceOrLifecycleInconsistent",
    "associationFields": "referenceOrLifecycleInconsistent",
    "lifecyclePairs": "referenceOrLifecycleInconsistent"
  },
  "freshness": {
    "authenticatedConsistency": true,
    "freshnessClaim": false,
    "coherentWholeProfileRollbackDetection": false,
    "statement": "A coherent replay of a complete same-key browser profile, including wrapper, selector, and anchors, can restore successfully and may be undetectable."
  },
  "nonClaims": [
    "freshness",
    "coherent complete same-key browser-profile rollback detection or prevention",
    "secure physical erasure",
    "JavaScript zeroization",
    "transport or delivery",
    "application identity",
    "production readiness",
    "arbitrary topology",
    "IndexedDB transaction implementation",
    "restore implementation correctness",
    "browser parity",
    "lock reliability",
    "compatible-build availability",
    "recovery UX",
    "legacy re-establishment success",
    "forgotten-password recovery"
  ],
  "ratification": {
    "documentSha256": "MUST_BE_RECORDED_EXTERNALLY_FROM_FINAL_LITERAL_BYTES",
    "evidenceBundleSha256": "MUST_BE_RECORDED_EXTERNALLY_FROM_FINAL_LITERAL_BYTES",
    "ownerActRequired": true,
    "byteChangeInvalidatesReviewAndRatification": true
  }
}
```
<!-- styx-m2-restore-json:v1:end -->
