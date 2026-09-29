# M2 authenticated storage format and key schedule

Status: normative candidate for C-FMT under Issue #327. The exact bytes of this document and its external evidence bundle require separate owner hash-ratification before C-REST, C-REC, O-SCEN or dependent implementation starts.

## 1. Scope and precedence

This document maps the ratified C-BIND and C-MUT logical facts to one closed authenticated physical format. The machine-readable record in section 12 is normative and closed. Prose explains it but cannot add a field, value, version, algorithm, label, mapping or accepted encoding. Unknown, missing, duplicate, reordered or overlapping values reject; duplicate JSON member names reject.

It defines no database transaction API, migration, retention lifetime, disposal schedule, legacy import, recovery UX, transport, delivery or application identity. It does not reuse the legacy shipping envelope, ciphersuite identifier as a storage identifier, transport identifiers or application-semantic identifiers.

## 2. Authority and physical registry

Kinds 1 through 15 are generation data records. Kind 16 is the authenticated manifest and kind 17 is the fixed-locator authenticated generation selector. Every C-MUT component and every C-BIND durable fact has exactly one mapping in the machine record. An unchanged component is copied into the candidate generation and remains explicitly covered; absence is a canonical tombstone in `ABSENCE_COMMITMENTS`, never an omitted manifest leaf.

Record parsing never changes C-MUT ownership or disposition. In particular it cannot release escrow, turn `RESERVED` into retryable, invent a terminal outcome, or make a held candidate authoritative.

## 3. Canonical keys, envelopes and plaintext

All integers are unsigned big-endian. Keys, envelopes, AAD and plaintext frames are exactly the byte grammars in section 12. Length fields are minimal fixed-width binary integers, not varints. Decoders reject overflow, truncation, trailing bytes, unsupported values and any decode/re-encode difference.

`localContextId` appears once in the canonical key position and is always repeated in authenticated AAD. Raw Group IDs, local KeyPackage references and private material are not record keys. The SESSION scope contains the Group ID only in its defined position and binds the complete 389-byte C-BIND through a domain-separated digest. The CONTEXT_PRESESSION scope contains no zero or placeholder session value and cannot authenticate as SESSION.

## 4. AEAD and nonce rule

Every envelope uses AES-256-GCM with a 96-bit fresh worker-CSPRNG nonce and a 128-bit tag. Nonces are not counters and do not depend solely on rewindable state. At the allowed one-million writes per derived key, the random collision upper bound is below 2^-57. A live duplicate is rejected, but coherent profile rollback can rewind a persisted duplicate set; fresh entropy, not a rollback claim, is the protection. Literal KAT nonces are test inputs only.

Authentication is completed before plaintext becomes authoritative. Context, session, profile, kind, every version, canonical key, write generation, mutation identity and declared plaintext length are in AAD. Copy, swap, cross-context, cross-session, cross-profile, cross-kind, cross-version, generation substitution and truncation therefore fail closed.

## 5. Root key and domain-separated schedule

The Root Storage Key is 32 random bytes generated in the worker. The existing version-1 `styx-vault-wrapper` wraps it with A256GCM under the password-derived Argon2id KEK; the password never encrypts M2 records. Password change atomically re-wraps the same Root Storage Key and does not re-encrypt records.

HKDF-SHA-256 labels, salt, framing, version and output lengths are exact in section 12. Namespace, record, manifest/root and selector labels are distinct. The context and exact profile digest enter the schedule. Unknown key versions and label collisions reject.

## 6. Manifest, keyed root and authority selector

The manifest is a unique unsigned-lexicographic list of every authoritative data-record key, kind, version and ciphertext digest. Canonical tombstones commit required absence. The keyed root covers the selected generation, manifest key, literal manifest digest and literal manifest bytes. The manifest is itself AEAD protected; the selector binds its ciphertext digest and keyed root.

A reader accepts only the complete set named by the authenticated fixed-locator selector. Removal, addition, substitution, duplication, reorder, same-key historical subset, manifest/root mismatch and partial generation reject. Record authentication is not freshness: replay of a complete same-key browser profile, including selector and any coarse surviving anchor, remains undetectable.

## 7. Mutation generations and readback

A mutation writes a complete candidate generation, matching manifest/root, authenticated result evidence and escrow. Authority changes only through one atomic selector replacement. Before replacement readback is `COMPLETE_OLD`; after replacement it is `COMPLETE_NEW`. A retained in-memory uncertainty may additionally be `OLD_PLUS_ONE_IMMUTABLE_HOLD`, but storage-only restore never exposes that as authority and must terminally classify old or new before another operation.

The seven C-MUT rows and every named crash boundary are copied into section 12. `COMMITTED` selects complete new authority, terminal `NOT_COMMITTED` keeps complete old authority, and `INDETERMINATE` keeps old authority plus one immutable hold. No partial candidate is authoritative and security-sensitive output is read from authenticated escrow, never regenerated.

## 8. KeyPackage and binding facts

The KeyPackage record binds public bytes, all private components, opaque local reference, canonical MLS KeyPackageRef mapping, context/profile, lifecycle and `invalidPending` as one non-aliasable unit. `UNCONSUMED`, `RESERVED`, `CONSUMED` and `INVALID` restore exactly. `invalidPending=true` is valid only with `RESERVED`; parsing alone cannot make uncertainty retryable.

Slot registration, issuance-held candidate, issuance outcome, reservation, invalidation and the latch are covered by the same complete generation manifest/root and selector update. This is a physical grouping of already ratified facts, not a new transaction or disposition.

## 9. Escrow and result evidence

Escrow is bound to one operation identity, candidate, mutation-set digest, output kind and authenticated result. Only C-MUT authorizes release. Clearing a response hold never erases evidence needed to classify an interrupted prior generation. Forged, stale, cross-domain or mismatched result/escrow association rejects.

## 10. Literal generations and conformance

Section 12 contains one same-profile three-generation chain: EMPTY with one UNCONSUMED KeyPackage identity and tombstoned session facts; ACTIVE after an output-producing commit; and a RECONCILIATION_REQUIRED candidate generation after `INDETERMINATE` whose fixed selector still names the complete ACTIVE generation. Each publishes every key, nonce, AAD, plaintext, envelope, ciphertext digest, manifest, selector and keyed root. Separate negative cases mutate context, session and profile inputs.

The external validator independently extracts the closed record, implements two encoders without shared encoder code, reproduces every literal byte, decrypts and re-encodes byte-identically, recomputes all digests and roots, executes every negative class, sabotages each kind/component/label/version/leaf/selector, and exercises seven rows × three outcomes × every C-MUT crash boundary. Any skip or unexpected acceptance fails.

## 11. Limits and rollback

This format proves post-unlock record authenticity and complete-generation consistency only. It does not prove freshness, coherent profile rollback prevention, IndexedDB atomicity, implementation correctness, entropy quality, constant time, worker confinement, physical deletion, JavaScript zeroization, disposal completion or restore compatibility. Rollback of this card is removal of this file; it creates no persisted M2 bytes or migration.

## 12. Normative machine-readable record

<!-- styx-m2-storage-format-json:v1:start -->
```json
{
  "schema": "styx-m2-authenticated-storage-format/v1",
  "closed": true,
  "status": "PENDING_EXTERNAL_HASH_RATIFICATION",
  "validation": {
    "unknownMissingDuplicateReorderedOrOverlapping": "REJECT",
    "duplicateJsonMembers": "REJECT",
    "proseAddsAcceptedValue": false,
    "unexpectedSkip": "FAIL",
    "defaultViolation": "REJECT"
  },
  "provenance": {
    "exactBase": "e1538ef9c070e463a8256872a3fd0882c424e2ef",
    "cBind": {
      "commit": "b8e840838a663eaa360b15642f8139c0155d0435",
      "sha256": "2ee9b022bca9f2eb2673cc4dac30f4cfa195ccc5a72ce3ff3617c14ead1d4a42",
      "ratification": "issue-323-comment-5890060894"
    },
    "cMut": {
      "commit": "40a3dee0fcb297d6fe8efc8657a9bbe6098d099d",
      "sha256": "6c2c045c5317d6893a0bd338e728f2cdc686237af5688925f9756c014deb3060",
      "evidenceBundleSha256": "9d8bdb19b20728873ede932df2936dcc6db6dd44a072af57cf4d0320cbf56712",
      "ratification": "issue-324-comment-5890545934"
    }
  },
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
      "generation zero for data/manifest",
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
      "version": 1,
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
        "resultStatus:u8"
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
      "version": 1,
      "physicalFact": "authoritative-generation-selector",
      "orderedFields": [
        "generation:u64",
        "manifestKeyDigest:b32",
        "manifestCipherDigest:b32",
        "keyedRoot:b32",
        "state:u8"
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
    "selector": "kind 17 at the fixed STYXSEL1 locator; AEAD-authenticated; plaintext binds selected generation, manifest-key digest, manifest ciphertext digest, keyed root and API state",
    "keyedRoot": "HMAC-SHA-256(K_manifest, ASCII STYXROOT1 || version:u16be || selectedGeneration:u64be || manifestKeyLength:u16be || manifestKey || SHA-256(manifestBytes) || manifestBytes)",
    "subsetRule": "current selector accepts only exactly matching complete manifest/root; omission, addition, substitution, duplicate, reorder, historical subset, partial generation or root mismatch rejects"
  },
  "generationCommit": {
    "rule": "write complete candidate data records, manifest and matching result/escrow; authority changes only through one atomic replacement of the authenticated fixed-locator GENERATION_SELECTOR",
    "completeOld": "selector still names old complete generation",
    "completeNew": "selector names new complete generation whose manifest/root/result/escrow all verify",
    "indeterminate": "selector names old authority; one immutable candidate/hold generation is retained but never presented as authority",
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
    "FORGED_RESULT_ESCROW_ASSOCIATION"
  ],
  "vectors": [
    {
      "id": "FMT-KAT-EMPTY",
      "state": "EMPTY",
      "rootStorageKeyHex": "1111111111111111111111111111111111111111111111111111111111111111",
      "localContextIdHex": "2121212121212121212121212121212121212121212121212121212121212121",
      "secureSessionIdentityHex": null,
      "canonicalBindingHex": null,
      "profileDigestHex": "5d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b",
      "generation": 1,
      "mutationIdentityHex": "98817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c",
      "records": [
        {
          "kind": "SLOT_REGISTRATION",
          "keyHex": "535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000110ee198f351dbe0180a4af73689ae1ac1b",
          "nonceHex": "1100395cd41d08eccbb3a5b7",
          "aadHex": "53545958414144310001000100010001000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000110ee198f351dbe0180a4af73689ae1ac1b21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000005f",
          "plaintextHex": "53545958504c4e31000100010100030100000001010200000020212121212121212121212121212121212121212121212121212121212121212103000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b",
          "envelopeHex": "53545958464d54310001000100010001000100010046000000c90000005f0000005f0010535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000110ee198f351dbe0180a4af73689ae1ac1b53545958414144310001000100010001000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000110ee198f351dbe0180a4af73689ae1ac1b21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000005f1100395cd41d08eccbb3a5b7b9a30f46f0a71680d7446847691733809f4cccf9c28c02ba0e9da6dc9167729ccbcbb2d917a3fcbfa2c196e47477eae4521198f6a1fde92e76a04d30161a8816c801d6f7d916882b588998f2ababc637aad9e7c13a9e0947e2dfd566d691389d462857d2d5187d626cfbd67ca2caf8",
          "ciphertextDigestHex": "a653d691ce131cf9dc026048decfef054003cc05a1c4677bd189d7a97debf903"
        },
        {
          "kind": "ISSUANCE_CANDIDATE",
          "keyHex": "535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010002109720363a357379d720b9c00c1bc92488",
          "nonceHex": "11016952703134826e9916e2",
          "aadHex": "53545958414144310001000100020001000100000046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010002109720363a357379d720b9c00c1bc9248821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f",
          "plaintextHex": "53545958504c4e3100010002000000",
          "envelopeHex": "53545958464d54310001000200010001000100010046000000c90000000f0000000f0010535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010002109720363a357379d720b9c00c1bc9248853545958414144310001000100020001000100000046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010002109720363a357379d720b9c00c1bc9248821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f11016952703134826e9916e2ec7b733b5beeb26f6c49ceb06716e1bf793a959b41dd091d150ec263b5e1d4",
          "ciphertextDigestHex": "f43a67916c208a5b063d9133627c28c7fc4a49657ae8ac047614db3efecb802f"
        },
        {
          "kind": "ISSUANCE_OUTCOME",
          "keyHex": "535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000310bbc71a6764adaedf0ad0b60e7900e40f",
          "nonceHex": "11021891dc746add74a19db1",
          "aadHex": "53545958414144310001000100030001000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000310bbc71a6764adaedf0ad0b60e7900e40f21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f",
          "plaintextHex": "53545958504c4e3100010003000000",
          "envelopeHex": "53545958464d54310001000300010001000100010046000000c90000000f0000000f0010535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000310bbc71a6764adaedf0ad0b60e7900e40f53545958414144310001000100030001000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000310bbc71a6764adaedf0ad0b60e7900e40f21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f11021891dc746add74a19db1b3d6c87bd27b60f4f1798e2f062bd4ffbbaa2b48c7387c7bca42d97405245d",
          "ciphertextDigestHex": "a1fed9c4aa02356d93435115a226079b0ac599e86e0e68149f1284756557d988"
        },
        {
          "kind": "KEY_PACKAGE",
          "keyHex": "535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000410918b5a723c830e286b7e7a601c0be4ee",
          "nonceHex": "110376addeb069cd6bb9732f",
          "aadHex": "53545958414144310001000100040001000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000410918b5a723c830e286b7e7a601c0be4ee21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c000000d1",
          "plaintextHex": "53545958504c4e3100010004010008010000000c678bdacc7d3efcef7f94092f020000000c3cc6430c0ecada4337a26d360300000020232d780df9615a3dd2796dafe329c90f8b0c3edd41bd81791a078e3d47b358900400000020e56d6751026dbd6212134c8d6d505c8e13b935e20dd2b16038113646a40c8bee0500000020212121212121212121212121212121212121212121212121212121212121212106000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b070000000101080000000100",
          "envelopeHex": "53545958464d54310001000400010001000100010046000000c9000000d1000000d10010535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000410918b5a723c830e286b7e7a601c0be4ee53545958414144310001000100040001000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000410918b5a723c830e286b7e7a601c0be4ee21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c000000d1110376addeb069cd6bb9732f2cbcd0313300a89b74a8854bbdb697dee0c953b2cb70875ae9d9b60fe31b731d0cd364ff91a51125af89761ac81c9c774d09b4bf820f3fe9a0a854d539ba704661ec7c781804129a5411f7f0c30a8a6d3a9888b6aa0dbcbbd63c940c20744c675fc6d8b7956c29637573aa1d9cdd433c40136d46ffe93c30491ab0e6b4eb75df5f44b8ef6f4e6b36ddb8166af3b3bb82005b25d25f5087c629410aa85eb6346ec5e8f4e83286eb92e2a988c390ef82c9f9322b6e26cbb80fef46fa1942e72e62501c0c54a44d90145d860a0f61ecacf83a3d8425a080ce6d78cffb0c5d91a0a759",
          "ciphertextDigestHex": "a9f5a91630fea4012d1e43511db46a4a93ba22582f54d1d9cc4fe3100b69efad"
        },
        {
          "kind": "SESSION_STATE",
          "keyHex": "535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010005100d08b65ec848deeaa20ffe221f6eb86e",
          "nonceHex": "1104bb0b5066c9cd0c3898d2",
          "aadHex": "53545958414144310001000100050001000100000046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010005100d08b65ec848deeaa20ffe221f6eb86e21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f",
          "plaintextHex": "53545958504c4e3100010005000000",
          "envelopeHex": "53545958464d54310001000500010001000100010046000000c90000000f0000000f0010535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010005100d08b65ec848deeaa20ffe221f6eb86e53545958414144310001000100050001000100000046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010005100d08b65ec848deeaa20ffe221f6eb86e21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f1104bb0b5066c9cd0c3898d2c70b14da9c87dcd36a0511321c213cf770cbe41020e8a2501f8f78b227e503",
          "ciphertextDigestHex": "7420c38b7274b0c1f4844ececca5fab1976d24956ba6a948d6e3bef57ea744d8"
        },
        {
          "kind": "BINDING_PROFILE",
          "keyHex": "535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000610288c3c165ae84ad0d62462f4170cc2f4",
          "nonceHex": "1105eec4ce4b0c3e22eca3af",
          "aadHex": "53545958414144310001000100060001000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000610288c3c165ae84ad0d62462f4170cc2f421212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f",
          "plaintextHex": "53545958504c4e3100010006000000",
          "envelopeHex": "53545958464d54310001000600010001000100010046000000c90000000f0000000f0010535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000610288c3c165ae84ad0d62462f4170cc2f453545958414144310001000100060001000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000610288c3c165ae84ad0d62462f4170cc2f421212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f1105eec4ce4b0c3e22eca3af9cc75cb7a43b16408713ba3d84716538f1369cd46e901794512a9ef69a3c2d",
          "ciphertextDigestHex": "6854271081ff52f62d1a0237a9440d0d244053d05f1ec777f33b408e3d433197"
        },
        {
          "kind": "REPLAY_RETENTION",
          "keyHex": "535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000710c2f4aa5cd449e6792c5e56aa88a8efd1",
          "nonceHex": "1106b847c3c41a7c10455b7f",
          "aadHex": "53545958414144310001000100070001000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000710c2f4aa5cd449e6792c5e56aa88a8efd121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f",
          "plaintextHex": "53545958504c4e3100010007000000",
          "envelopeHex": "53545958464d54310001000700010001000100010046000000c90000000f0000000f0010535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000710c2f4aa5cd449e6792c5e56aa88a8efd153545958414144310001000100070001000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000710c2f4aa5cd449e6792c5e56aa88a8efd121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f1106b847c3c41a7c10455b7fbd8a16d757a3cfd0d949c4ff760a8f9af233aef4bbae640eb57f34842df2a9",
          "ciphertextDigestHex": "31e36681ce641369694b74ebf5c1cd4a418407c5101c5866c82420fe6033e424"
        },
        {
          "kind": "COMMIT_RESULT",
          "keyHex": "535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010008100c2cabad3bd2bc25c861e8dd96693601",
          "nonceHex": "110710d01e260af5d5a86901",
          "aadHex": "53545958414144310001000100080001000100000046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010008100c2cabad3bd2bc25c861e8dd9669360121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f",
          "plaintextHex": "53545958504c4e3100010008000000",
          "envelopeHex": "53545958464d54310001000800010001000100010046000000c90000000f0000000f0010535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010008100c2cabad3bd2bc25c861e8dd9669360153545958414144310001000100080001000100000046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010008100c2cabad3bd2bc25c861e8dd9669360121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f110710d01e260af5d5a86901816ac334036237593dc584cab230354508106c15e80db2779ad27b9a408750",
          "ciphertextDigestHex": "704b8aaecda4734caa6ab9320232b5894df8f7304c2d935e143d73e3a7f3560d"
        },
        {
          "kind": "OUTPUT_ESCROW",
          "keyHex": "535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010009101c283aeb8f841686caa72baea5638156",
          "nonceHex": "1108d70398280f49de0ec430",
          "aadHex": "53545958414144310001000100090001000100000046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010009101c283aeb8f841686caa72baea563815621212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f",
          "plaintextHex": "53545958504c4e3100010009000000",
          "envelopeHex": "53545958464d54310001000900010001000100010046000000c90000000f0000000f0010535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010009101c283aeb8f841686caa72baea563815653545958414144310001000100090001000100000046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010009101c283aeb8f841686caa72baea563815621212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f1108d70398280f49de0ec4303933fefaab4ff6a020a7bded78e6f68457edd687f9a51ba9296ecb0692dcf4",
          "ciphertextDigestHex": "758c03f6c1552f7d0c9768737afe93d76dee4a1f559e007daf8df281c504a879"
        },
        {
          "kind": "SELECTION_METADATA",
          "keyHex": "535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000a100a44f45fe7554cb37189c11267bfc0a3",
          "nonceHex": "1109093742d8bd61319efadd",
          "aadHex": "535459584141443100010001000a0001000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000a100a44f45fe7554cb37189c11267bfc0a321212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f",
          "plaintextHex": "53545958504c4e310001000a000000",
          "envelopeHex": "53545958464d54310001000a00010001000100010046000000c90000000f0000000f0010535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000a100a44f45fe7554cb37189c11267bfc0a3535459584141443100010001000a0001000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000a100a44f45fe7554cb37189c11267bfc0a321212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f1109093742d8bd61319efadd2de284cc67c3bd156f7503eae89d230321de8ec00c41627f47802984436eb7",
          "ciphertextDigestHex": "0d33869f65f16b8dd5d76f90a7d1e2c8fab464f0a6a726c312e6c60ebc531d3c"
        },
        {
          "kind": "RETAINED_PARENT",
          "keyHex": "535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000b105d5da34d3ab5db820dd14711c2e65bcc",
          "nonceHex": "110a90a2ec53f84740ba168d",
          "aadHex": "535459584141443100010001000b0001000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000b105d5da34d3ab5db820dd14711c2e65bcc21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f",
          "plaintextHex": "53545958504c4e310001000b000000",
          "envelopeHex": "53545958464d54310001000b00010001000100010046000000c90000000f0000000f0010535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000b105d5da34d3ab5db820dd14711c2e65bcc535459584141443100010001000b0001000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000b105d5da34d3ab5db820dd14711c2e65bcc21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f110a90a2ec53f84740ba168dd5e4e11b66b0022ad906d68caeba287234a5c4a79691b547dbe438ecee6f5c",
          "ciphertextDigestHex": "02854e7d7a9d94a98d1e9c131fad98608c3f4420bf5db6b26ce49cd7800be09e"
        },
        {
          "kind": "LOSING_CANDIDATE",
          "keyHex": "535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000c10e4f3f18409d6e6b39c6727292dfb6498",
          "nonceHex": "110ba0068f15ece2f71c7415",
          "aadHex": "535459584141443100010001000c0001000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000c10e4f3f18409d6e6b39c6727292dfb649821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f",
          "plaintextHex": "53545958504c4e310001000c000000",
          "envelopeHex": "53545958464d54310001000c00010001000100010046000000c90000000f0000000f0010535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000c10e4f3f18409d6e6b39c6727292dfb6498535459584141443100010001000c0001000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000c10e4f3f18409d6e6b39c6727292dfb649821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f110ba0068f15ece2f71c7415906fd01c5bba66b9fc468a3fda00002c0a8549f87a54bd0b41d07e6532dee4",
          "ciphertextDigestHex": "98b77e29a16f78d5211ab33f7a71076867ed9666a8974dbf9c9b6ff6a099f730"
        },
        {
          "kind": "MUTATION_HOLD",
          "keyHex": "535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000d106da7814be10eddf3f195f4cf8e959cb9",
          "nonceHex": "110c99efd98599b82de3102c",
          "aadHex": "535459584141443100010001000d0001000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000d106da7814be10eddf3f195f4cf8e959cb921212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f",
          "plaintextHex": "53545958504c4e310001000d000000",
          "envelopeHex": "53545958464d54310001000d00010001000100010046000000c90000000f0000000f0010535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000d106da7814be10eddf3f195f4cf8e959cb9535459584141443100010001000d0001000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000d106da7814be10eddf3f195f4cf8e959cb921212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f110c99efd98599b82de3102cdae169dce031bd15ffe8da471d113e88df117816fc3cf0eff2ca0f5b0bdd6e",
          "ciphertextDigestHex": "bbee98be7a6a5961e9a31531f027d48e256dad2dd59ab6aed4c1087ab43110bb"
        },
        {
          "kind": "COMPONENT_SET",
          "keyHex": "535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000e10e31ad9c06ef304519d8befb2060a3932",
          "nonceHex": "110d25705d7d316edc83c57e",
          "aadHex": "535459584141443100010001000e0001000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000e10e31ad9c06ef304519d8befb2060a393221212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f",
          "plaintextHex": "53545958504c4e310001000e000000",
          "envelopeHex": "53545958464d54310001000e00010001000100010046000000c90000000f0000000f0010535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000e10e31ad9c06ef304519d8befb2060a3932535459584141443100010001000e0001000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000e10e31ad9c06ef304519d8befb2060a393221212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f110d25705d7d316edc83c57e67a1bc2960b2352782b8491ca05be37b35a957b0b9eb98b736429c6858d02f",
          "ciphertextDigestHex": "1411af23ec3781491218eccc9b391808e7edcc35ff7ad4014deae496a49a245c"
        },
        {
          "kind": "ABSENCE_COMMITMENTS",
          "keyHex": "535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000f100379eb444bd86b2bd8a124b51796c2ec",
          "nonceHex": "110e8304c4e77cb0fcca9f44",
          "aadHex": "535459584141443100010001000f0001000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000f100379eb444bd86b2bd8a124b51796c2ec21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c00000029",
          "plaintextHex": "53545958504c4e310001000f010002010000000400003ff6020000000c020305060708090a0b0c0d0e",
          "envelopeHex": "53545958464d54310001000f00010001000100010046000000c900000029000000290010535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000f100379eb444bd86b2bd8a124b51796c2ec535459584141443100010001000f0001000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000f100379eb444bd86b2bd8a124b51796c2ec21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c00000029110e8304c4e77cb0fcca9f4437b5bc64748f2490336f4f93fd6a2756ff12f78f33c880d629732eeb0c1bf4c82ee9dac6f67341bb8de248fda0aff8fbd17a8fac57ca17ba1f",
          "ciphertextDigestHex": "60b92d5e8933bbcd82cf4c0482758379b1044160c72e952056ccd9f1604bef43"
        }
      ],
      "manifest": {
        "keyHex": "535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001001000",
        "bytesHex": "535459584d414e3100010000000f0046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000110ee198f351dbe0180a4af73689ae1ac1b00010001a653d691ce131cf9dc026048decfef054003cc05a1c4677bd189d7a97debf9030046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010002109720363a357379d720b9c00c1bc9248800020001f43a67916c208a5b063d9133627c28c7fc4a49657ae8ac047614db3efecb802f0046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000310bbc71a6764adaedf0ad0b60e7900e40f00030001a1fed9c4aa02356d93435115a226079b0ac599e86e0e68149f1284756557d9880046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000410918b5a723c830e286b7e7a601c0be4ee00040001a9f5a91630fea4012d1e43511db46a4a93ba22582f54d1d9cc4fe3100b69efad0046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010005100d08b65ec848deeaa20ffe221f6eb86e000500017420c38b7274b0c1f4844ececca5fab1976d24956ba6a948d6e3bef57ea744d80046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000610288c3c165ae84ad0d62462f4170cc2f4000600016854271081ff52f62d1a0237a9440d0d244053d05f1ec777f33b408e3d4331970046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000710c2f4aa5cd449e6792c5e56aa88a8efd10007000131e36681ce641369694b74ebf5c1cd4a418407c5101c5866c82420fe6033e4240046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010008100c2cabad3bd2bc25c861e8dd9669360100080001704b8aaecda4734caa6ab9320232b5894df8f7304c2d935e143d73e3a7f3560d0046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010009101c283aeb8f841686caa72baea563815600090001758c03f6c1552f7d0c9768737afe93d76dee4a1f559e007daf8df281c504a8790046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000a100a44f45fe7554cb37189c11267bfc0a3000a00010d33869f65f16b8dd5d76f90a7d1e2c8fab464f0a6a726c312e6c60ebc531d3c0046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000b105d5da34d3ab5db820dd14711c2e65bcc000b000102854e7d7a9d94a98d1e9c131fad98608c3f4420bf5db6b26ce49cd7800be09e0046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000c10e4f3f18409d6e6b39c6727292dfb6498000c000198b77e29a16f78d5211ab33f7a71076867ed9666a8974dbf9c9b6ff6a099f7300046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000d106da7814be10eddf3f195f4cf8e959cb9000d0001bbee98be7a6a5961e9a31531f027d48e256dad2dd59ab6aed4c1087ab43110bb0046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000e10e31ad9c06ef304519d8befb2060a3932000e00011411af23ec3781491218eccc9b391808e7edcc35ff7ad4014deae496a49a245c0046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000f100379eb444bd86b2bd8a124b51796c2ec000f000160b92d5e8933bbcd82cf4c0482758379b1044160c72e952056ccd9f1604bef43",
        "plaintextHex": "53545958504c4e31000100100100020100000662535459584d414e3100010000000f0046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000110ee198f351dbe0180a4af73689ae1ac1b00010001a653d691ce131cf9dc026048decfef054003cc05a1c4677bd189d7a97debf9030046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010002109720363a357379d720b9c00c1bc9248800020001f43a67916c208a5b063d9133627c28c7fc4a49657ae8ac047614db3efecb802f0046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000310bbc71a6764adaedf0ad0b60e7900e40f00030001a1fed9c4aa02356d93435115a226079b0ac599e86e0e68149f1284756557d9880046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000410918b5a723c830e286b7e7a601c0be4ee00040001a9f5a91630fea4012d1e43511db46a4a93ba22582f54d1d9cc4fe3100b69efad0046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010005100d08b65ec848deeaa20ffe221f6eb86e000500017420c38b7274b0c1f4844ececca5fab1976d24956ba6a948d6e3bef57ea744d80046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000610288c3c165ae84ad0d62462f4170cc2f4000600016854271081ff52f62d1a0237a9440d0d244053d05f1ec777f33b408e3d4331970046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000710c2f4aa5cd449e6792c5e56aa88a8efd10007000131e36681ce641369694b74ebf5c1cd4a418407c5101c5866c82420fe6033e4240046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010008100c2cabad3bd2bc25c861e8dd9669360100080001704b8aaecda4734caa6ab9320232b5894df8f7304c2d935e143d73e3a7f3560d0046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010009101c283aeb8f841686caa72baea563815600090001758c03f6c1552f7d0c9768737afe93d76dee4a1f559e007daf8df281c504a8790046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000a100a44f45fe7554cb37189c11267bfc0a3000a00010d33869f65f16b8dd5d76f90a7d1e2c8fab464f0a6a726c312e6c60ebc531d3c0046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000b105d5da34d3ab5db820dd14711c2e65bcc000b000102854e7d7a9d94a98d1e9c131fad98608c3f4420bf5db6b26ce49cd7800be09e0046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000c10e4f3f18409d6e6b39c6727292dfb6498000c000198b77e29a16f78d5211ab33f7a71076867ed9666a8974dbf9c9b6ff6a099f7300046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000d106da7814be10eddf3f195f4cf8e959cb9000d0001bbee98be7a6a5961e9a31531f027d48e256dad2dd59ab6aed4c1087ab43110bb0046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000e10e31ad9c06ef304519d8befb2060a3932000e00011411af23ec3781491218eccc9b391808e7edcc35ff7ad4014deae496a49a245c0046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000f100379eb444bd86b2bd8a124b51796c2ec000f000160b92d5e8933bbcd82cf4c0482758379b1044160c72e952056ccd9f1604bef430200000020ca5dcb929debc097a0e5fdb990e1c11364bc3bfb51f185890408aa43bd9fb5d1",
        "nonceHex": "110fd56a50240fd04dcdab1b",
        "aadHex": "53545958414144310001000100100001000100000036535459584b4559310001012121212121212121212121212121212121212121212121212121212121212121000000000000000100100021212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000069b",
        "envelopeHex": "53545958464d54310001001000010001000100010036000000b90000069b0000069b0010535459584b4559310001012121212121212121212121212121212121212121212121212121212121212121000000000000000100100053545958414144310001000100100001000100000036535459584b4559310001012121212121212121212121212121212121212121212121212121212121212121000000000000000100100021212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000069b110fd56a50240fd04dcdab1baf8d131633e20764d8161ee6a25199389db9da1c164f9d13e0d08442f96ef61ec2b43089a7e87a3baaa64a24c945fe0cde2c04ec7274d285975234c0a5690343492e42bb49f82b485c215bc4b20638802d2acdd936dc682f54da20fe7537346dfa9f5a63b0587c1101fb5127cfd834868f378ec664298194290d22e75f4a7fa1409ef917018202920c0587623f478be9afd4524b7da1addba1c7ac357dd1c584b48805151eff249778d09d96719cc6da56be375776d69fedfd21151ebf9fdd99789791de2fb612199f93ab02d8eb0ce4f8a2b989e4ec4a2c9ea40ae05508f8c6c8855eaff41b6e4eb82783c6fb0213cb4f78163b6e45188719da076ab707ed72e0b60c81b92a809dbaa6cc73dfd756f02670a0ba4f550e61ac8e245f0a40d94eb77e6f5b1696e5b507d23ad824ff879acb05e41b9faf2b913d08d8fc313c6541e7d26b16b5cfef817c1ec593a98106cc23d498dabda23fff016d5d9723af6cc903747c47aced6a006d3af87cd7ad7ed0c391e6602136c8e23fb73f70d062a3e79818dfa8e11d89204d68acaed10d6510e911f1aef080cac88f58fe769398e42eb55c1a46a71730fe6e05005abb3c9787f160916790e7bc54c97c5d991115da8a18f7113d4685b00c261a2e3818e05c98f822db21b8587d4977b0f1a81b0ff936b038b7989855d2bd08f9b6e36ef33f37a97e4a5b7d53343471cf1f883364d1cc24d4165a6720a1aa1f6989ebaafd6af71f87c7c172c9353a579cf1e94664e21ef8a3b835a160634d47c00b079df15187927b70074137443796a068822c8edd1bc3ae0f1c3069e826b9b30132180ab1e2daf0c1df938e7f8413a7be70cdb799e34924ffd72ab523b524f9eef4cb45770b9f6b12e439333bd77e22485df5dabf91cb6ef1b9eea675265a6d33c11f0f474df0a42388f4c3ee7a2c127fad20ff9a02e3b24303b283ee87d2118cdfe208194a1dbe420594430edf5fb458584889e7a11e9270a7cd286a2b9fc5cbf2b5eb3279feab5e6abd294f81783b0b946d7680823944df0e6e3c102f47f1adce4aa0e2d6f1cea7f3d0c8d458d072a4b98fa67702d74105283ecd21d33a63aad552222ff13fb82b6560d54a638b2862f72c623c118ea041633849454b8e22c7a44e400790432caf1378f40d7127c0116f70e3e766fe196477bf7e2832040712b21c71fedd24f201a8dc3d105a278f0a19ab5441db1945c855caf0dc7a9d649a0e5b43cc9e36d138b42cb1ff79e2d7c8202bec4d4d52efbf4efdb82bd30ef51beb286e3f9561fc1e45d1efb80f3a9916bda648d79d2421d81d66ece4d341eb12340c3ae978075e6ae67446af9873995dfa458f92625edcf6b0383406d8e2e56bbdf77bc0dd2bfac2f09801987d2ff514e91fbb237aa9de6a1e42238a5bcf992d8647ad016c8394235e7971110095aef9ee3388b312ab044fa3b134378058efa8e4bd5b12c68024dccaeb39a9b6dbcb655013e8391a2a10c78287fff5a570df15f186696dd5be8db5572a4835ced0239e1414573e689ecaab047447a7b25fb627eca3a2ade659f785dc3d53d66fd324163330a9f7ba17d0fbf55d4234c783bc95391c817b154e47713aa88e473a384170c3cb3ffcfc0179efae739c1c30bdc2b7aba2406cf64166c85431f33f835c16e02d4b559c33b53629608cf7340fccd5a4309521a2181aa51f11838f79e401d5ed4ddafbb2f938f9a8f28b2bed14aff661199541b3deac5a6383b530e10c5e30b2f6b7b7612a37d29c5b56d76a403dd819302edddf3c1088e07f50cee6d95f5ab6786ea79bf38852280cc1e3b9a174fd8124113ae8ec370c17c24eb412554df538bfbede351c9037b9b58042f967ec4c2d9dd7e9ff5ca02861ebb1748d80c1a73bd4572f38b10a7f834a5000d545096ec164157be4d0f60ca219145f5c2c2f655ec934c7690f033df3e33a9c4283b1be2a0d200070d3802f2fe2ad2820ec1848fda53cfb3794b22d3bb56e12940d705e64236c7fbcbfa562bdd5ca09afbbc0a3809b2b00019f41d2adf0b8b7cb4f790ac402ac0fbad9722c8cd2f9fb35168d4484fc47418d9a3a0349150d4530fce1d4fb263ef3815102d2e26b8f43f9d5b03c014fbcef1856b54712d0925ea95176592908cad03ab340d0a1af04a92b295af18aa0d253db6e1fb735c2428a8e485227f981acac88db086d6783e9ee8cc2af0a1cf02eb2d3f3cf40b8166c4d9f3b1eaf495c0880ac55328bc8cc79299cdeb474df8efa0d2440b504541207c1dbb994299ef971da0f755a72492c4fcdcf59c23fee62db0eb4442c8f7e1c85cb8c984f6fa54d398eecc4e0a4328f3469ed1fb025f709f17db3e4f6ab0e7db2e180dee6b236c866a03f9d6898bc52e82b586ff9285dc3a3ff76bc50051d0679b55a49dca89a",
        "ciphertextDigestHex": "da94fe6f128117e55b288d48952e791cb252542700d5ef7e38b0e16a686b596d"
      },
      "selector": {
        "keyHex": "5354595853454c3100012121212121212121212121212121212121212121212121212121212121212121",
        "selectedGeneration": 1,
        "plaintextHex": "53545958504c4e31000100110100050100000008000000000000000102000000205d8a18f17b63545d548a371c997ba493eb942ff5b18bf7c83927491144790e440300000020da94fe6f128117e55b288d48952e791cb252542700d5ef7e38b0e16a686b596d04000000203602c06aabc70b227550d782d74466c50d1e69839be51f87e03a154b660f8ef0050000000101",
        "nonceHex": "11102e902116f6552d6773f1",
        "aadHex": "5354595841414431000100010011000100010000002a5354595853454c310001212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c00000091",
        "envelopeHex": "53545958464d5431000100110001000100010001002a000000ad000000910000009100105354595853454c31000121212121212121212121212121212121212121212121212121212121212121215354595841414431000100010011000100010000002a5354595853454c310001212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000009111102e902116f6552d6773f178cb9633065492ee033bdee9eb44f954ac64165dfedc2a32e3c229a79fa405efd48bf998ec40994fe236d14a70150bcfcf2e69eb23277b611d831c53427d9f752a49732ef009f254bd4acdfe5f1e5dbcae7835bc1cdcc70e402bed5306c439fdd13d9cbe748d2b27e05d0440bd151b7743ede3d3ce704f3727a5ad18379c685df14972888a14e916446759f5707700760f0873c44266ecc7afd51bd65db250198e"
      },
      "keyedRootHex": "3602c06aabc70b227550d782d74466c50d1e69839be51f87e03a154b660f8ef0",
      "authorityRule": "selector names this generation"
    },
    {
      "id": "FMT-KAT-ACTIVE",
      "state": "ACTIVE",
      "rootStorageKeyHex": "1111111111111111111111111111111111111111111111111111111111111111",
      "localContextIdHex": "2121212121212121212121212121212121212121212121212121212121212121",
      "secureSessionIdentityHex": "48d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622",
      "canonicalBindingHex": "535459584d424e440000010020212121212121212121212121212121212121212121212121212121212121212102002048d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62203013201001a737479782d6d322d73657373696f6e2d616461707465722f76310200146d322d6f70617175652d62696e64696e672f763003000773657373696f6e0400036d6c7305000c746573742d70726f66696c6506001174776f2d6d656d6265722d64697265637407001409e92777dba0528d3d29e2e5e681b7e91637c7be080030737479782d6a732f76656e646f722f6f70656e6d6c732d7761736d2f6f70656e6d6c735f7761736d5f62672e7761736d090020fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e0a000200010b002c4d4c535f3132385f44484b454d5832353531395f41455331323847434d5f5348413235365f456432353531390c0020235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba070d000400000005",
      "profileDigestHex": "5d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b",
      "generation": 2,
      "mutationIdentityHex": "f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c73",
      "records": [
        {
          "kind": "SLOT_REGISTRATION",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000110ee198f351dbe0180a4af73689ae1ac1b",
          "nonceHex": "2200ea37af48b0ce7c9c6279",
          "aadHex": "53545958414144310001000100010001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000110ee198f351dbe0180a4af73689ae1ac1b21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000005f",
          "plaintextHex": "53545958504c4e31000100010100030100000001030200000020212121212121212121212121212121212121212121212121212121212121212103000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b",
          "envelopeHex": "53545958464d54310001000100010001000100010066000001290000005f0000005f0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000110ee198f351dbe0180a4af73689ae1ac1b53545958414144310001000100010001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000110ee198f351dbe0180a4af73689ae1ac1b21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000005f2200ea37af48b0ce7c9c6279b981121420c68337079c4c802901754c34cbe1366cb43fa15d1f809c610c387c90c17d60e7568d228c6048a3a4518b4fb8d29cc47a06114d67e1b0b2669c3a6a6d3cea4be55f5d4c1d90f13727a79626792cf208477a446505e96d6e7595136ee957c1ecaab28e783faab901d110b4",
          "ciphertextDigestHex": "404ef2cd2228509c5d92b5e5546e8178e789d2d088f6bd22d96863c5be7037a7"
        },
        {
          "kind": "ISSUANCE_CANDIDATE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020002109720363a357379d720b9c00c1bc92488",
          "nonceHex": "22017159f57730dd767817c6",
          "aadHex": "53545958414144310001000100020001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020002109720363a357379d720b9c00c1bc9248821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000000f",
          "plaintextHex": "53545958504c4e3100010002000000",
          "envelopeHex": "53545958464d54310001000200010001000100010066000001290000000f0000000f0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020002109720363a357379d720b9c00c1bc9248853545958414144310001000100020001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020002109720363a357379d720b9c00c1bc9248821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000000f22017159f57730dd767817c66145a28554951ce10b31716655dc4d9a9658edb8eb17e8b17cd7b252839d5e",
          "ciphertextDigestHex": "61dd04525dc19b487a935aed159c403de436266743bd6ffaf95e5a6af2cbffed"
        },
        {
          "kind": "ISSUANCE_OUTCOME",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000310bbc71a6764adaedf0ad0b60e7900e40f",
          "nonceHex": "22023e34bec7445728b16516",
          "aadHex": "53545958414144310001000100030001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000310bbc71a6764adaedf0ad0b60e7900e40f21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000000f",
          "plaintextHex": "53545958504c4e3100010003000000",
          "envelopeHex": "53545958464d54310001000300010001000100010066000001290000000f0000000f0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000310bbc71a6764adaedf0ad0b60e7900e40f53545958414144310001000100030001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000310bbc71a6764adaedf0ad0b60e7900e40f21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000000f22023e34bec7445728b16516a70e91c7144240a1a053f78cdc8d2a0a523c32fcc7ab3d86a6a09207b44b05",
          "ciphertextDigestHex": "8ee456b434914d9a08cab6011f8474204ba3f7de5fa5789e4159790c73bfe372"
        },
        {
          "kind": "KEY_PACKAGE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000410918b5a723c830e286b7e7a601c0be4ee",
          "nonceHex": "2203d44693fda8e193a64737",
          "aadHex": "53545958414144310001000100040001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000410918b5a723c830e286b7e7a601c0be4ee21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c73000000d1",
          "plaintextHex": "53545958504c4e3100010004010008010000000c678bdacc7d3efcef7f94092f020000000c3cc6430c0ecada4337a26d360300000020232d780df9615a3dd2796dafe329c90f8b0c3edd41bd81791a078e3d47b358900400000020e56d6751026dbd6212134c8d6d505c8e13b935e20dd2b16038113646a40c8bee0500000020212121212121212121212121212121212121212121212121212121212121212106000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b070000000101080000000100",
          "envelopeHex": "53545958464d5431000100040001000100010001006600000129000000d1000000d10010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000410918b5a723c830e286b7e7a601c0be4ee53545958414144310001000100040001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000410918b5a723c830e286b7e7a601c0be4ee21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c73000000d12203d44693fda8e193a64737244f6312118ea27545304319d98cb5630d8634bc4dcd3280bdd37f8d584443164f20a99ef6f04771261b5d93104b02d299788fa466256a04f9c29b41077b98b70ce5ce9eb45f7035a04193eca865b32f20836414a7fe97acff784ebdfaf357fdb8ab7cc667c64ba5ec7c0d0b8fa138a98d98ef411df64fda7572e1d7dca0a599b0084e5ee282a761e5ab587b988427131943b3ac4d3cbffb3a99a172b79c4a7f1f83a4d7368979b5980758c3b21a91ddb2faabc20bfa912874a90ccf18318102a52aa10a9d2daa3565262c8cc5f1c210a3efd165e2c1682b2c6e32993cbc13aa22",
          "ciphertextDigestHex": "0740fd41d0594ef1930924e7d3301346c056bf6c8038adb1b7cb004f8be84cef"
        },
        {
          "kind": "SESSION_STATE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020005100d08b65ec848deeaa20ffe221f6eb86e",
          "nonceHex": "220475a7da5186f13584086b",
          "aadHex": "53545958414144310001000100050001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020005100d08b65ec848deeaa20ffe221f6eb86e21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c7300000020",
          "plaintextHex": "53545958504c4e3100010005010001010000000c24030d889763a2732abe79ef",
          "envelopeHex": "53545958464d543100010005000100010001000100660000012900000020000000200010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020005100d08b65ec848deeaa20ffe221f6eb86e53545958414144310001000100050001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020005100d08b65ec848deeaa20ffe221f6eb86e21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c7300000020220475a7da5186f13584086b559ef766cb21474dc977fecd234bf45c298e36f3e3af918dcb1edb8582373a390912b40c5c33f6bd27f0ee61569578e4",
          "ciphertextDigestHex": "1feedb95836dad5dace9ec67e7ef270d2ee25e47c8ad53878c57a70cc05bcf7d"
        },
        {
          "kind": "BINDING_PROFILE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000610288c3c165ae84ad0d62462f4170cc2f4",
          "nonceHex": "220526c6d08fea307133c4c5",
          "aadHex": "53545958414144310001000100060001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000610288c3c165ae84ad0d62462f4170cc2f421212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c73000001be",
          "plaintextHex": "53545958504c4e31000100060100020100000185535459584d424e440000010020212121212121212121212121212121212121212121212121212121212121212102002048d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62203013201001a737479782d6d322d73657373696f6e2d616461707465722f76310200146d322d6f70617175652d62696e64696e672f763003000773657373696f6e0400036d6c7305000c746573742d70726f66696c6506001174776f2d6d656d6265722d64697265637407001409e92777dba0528d3d29e2e5e681b7e91637c7be080030737479782d6a732f76656e646f722f6f70656e6d6c732d7761736d2f6f70656e6d6c735f7761736d5f62672e7761736d090020fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e0a000200010b002c4d4c535f3132385f44484b454d5832353531395f41455331323847434d5f5348413235365f456432353531390c0020235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba070d00040000000502000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b",
          "envelopeHex": "53545958464d5431000100060001000100010001006600000129000001be000001be0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000610288c3c165ae84ad0d62462f4170cc2f453545958414144310001000100060001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000610288c3c165ae84ad0d62462f4170cc2f421212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c73000001be220526c6d08fea307133c4c5aa47b179625e68b7860d2fd1fce3952a69460f05a0e505f622c4fda5540c6cfd35d10c02cd39f198b6a884295277b3ca27e38b73624524404e2f0828669d88c5a111c0b1567686a72c3a030166e3e114a9aeca52515480bf76753d973a7ed0defa01455422adc5129ef621c03f376ce86c20a5c39208cee90a1d6d98f0bc224d60d4a8e5e0a91578133fd34d1b3704c9d51a868104dc8220060a388e4566cbf55e1ede1649318720691bc10f37f48a375e68d3e7d5977e8ab944b9f549af6a4c09753b6f26bd7b7ece412de4cccfe8f1542688aa1ab06b22293a90fbe8f9380803f4ce3c2ed3dcbb7ac6644be1ceb9a3ab7efe47ab291b5f11f4d5735845a3a916f5b83c3628e1137ba5cc68d853a6edcef038e0ebdf452bc436275c3bb06b6c74827cac31c24c2cc603e447d4a5187affc88076245e021711a7e377f43293526b3a63af2e041ca7a26f39a4bfac456c24fca650acc5e7cabde39844c6e7e5102887187bbf4c288850e7015e3b57a62584e154731d15d39d9eff9aa49b61537717e0b0e9cb0a28b41263124bbb4aeea49ef9f00963472ec251b79d278ebc422c4f4d1dafe50ab5258d6ba6df4cd42560e69a4291341f3930474a89bb003a3edf98207d25c76b07873a9942e73230",
          "ciphertextDigestHex": "65740f5c416a9612a3a1c9c7cf3e41b6e753969b639e06274eee84e9b7e7aafe"
        },
        {
          "kind": "REPLAY_RETENTION",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000710c2f4aa5cd449e6792c5e56aa88a8efd1",
          "nonceHex": "2206cfe25860afaa4b3eb6ff",
          "aadHex": "53545958414144310001000100070001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000710c2f4aa5cd449e6792c5e56aa88a8efd121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c7300000031",
          "plaintextHex": "53545958504c4e3100010007010002010000000ca1ccd8c14dc64d2e15ca5871020000000c2b9c25b5f8703721859a12c9",
          "envelopeHex": "53545958464d543100010007000100010001000100660000012900000031000000310010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000710c2f4aa5cd449e6792c5e56aa88a8efd153545958414144310001000100070001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000710c2f4aa5cd449e6792c5e56aa88a8efd121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c73000000312206cfe25860afaa4b3eb6ff4b9ed56a5e15896362aba0e036295785ba0c037808ed9bc20a14d82edca4b7db62fe1f803a55c7d065f48ac8bae0d5e48aff9c68af47430d2fd19e4b871de83e4f",
          "ciphertextDigestHex": "1590ef91070fba331ab92a6d346b4cee0c06846f8215899bff3fcde47c85ae7c"
        },
        {
          "kind": "COMMIT_RESULT",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020008100c2cabad3bd2bc25c861e8dd96693601",
          "nonceHex": "220728915c6eaa0f83eb3b00",
          "aadHex": "53545958414144310001000100080001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020008100c2cabad3bd2bc25c861e8dd9669360121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c7300000174",
          "plaintextHex": "53545958504c4e310001000801000d01000000207d642f96923a130b6be60121e1246d9a2f4715d7b4bc9ab1af4aae66d1fc46d50200000020e80096d6f42a337db9287e0f7012f883d0ba40bb8e1063567424f76b392080a9030000002025e322124057a701754d27999dffae0c35887c59b6b65ff997d704c85f9669be04000000208801cafa4e1a66435cce691ced57f873462e45bab73efd3132e796dc3dfdf54f05000000200d47082c64f148767f4cdeae883191c682e8e837ce8843a3960f18196a99bffd06000000205ccbebcf1437e9c255beae522d319ede4571751adeaa0b1d2030f102f50cdd040700000020d15c8383f7019e334fb80e7882ed70a9f78d5b9f9c18399d64040bf8785fa367080000000101090000002021212121212121212121212121212121212121212121212121212121212121210a000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0b00000001010c00000001010d0000000101",
          "envelopeHex": "53545958464d543100010008000100010001000100660000012900000174000001740010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020008100c2cabad3bd2bc25c861e8dd9669360153545958414144310001000100080001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020008100c2cabad3bd2bc25c861e8dd9669360121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c7300000174220728915c6eaa0f83eb3b009cd4e5e61730f2f301c3245b12b7227eadd82e3c092320d0d7b677bf0eb31d8e10c2b7efbe463b407f793fae782e4da5fe4a51b36f35e087cba9a1846270d561eb57a946c5c3aba41f85394871629e5a1fe90a80546c0c4889eb68eb9b96f1fd9a2a9cffd30ff0cdc5112ecab1d3af93d2ca17a8b9dc10e944d71d3dd49134e07db3a2d8093bd6dcabed5ecc6d63023baffc472638f0728bcc582c0b2861c87ae4a258bbf804c2fb264ff9e8e77e7b9d3da538158eba2af14e36ece9a2bb2b95114210296429167fcf41d51d9b8f0f6541ad8ca507566732a542d61d2a29ef700ca72f3d969c3acd36192afeaba7bc138a7107a6e73b29c4f10cc5335716bf82294b3be43bb377cdc35d8db1a28afbc1c01f1d5d7006cfc529aa25e4a66399455a3a3f838efabfc4edc7b56ee8a8b2e9ad1589d92912dc8189a331e82d503a5051008dd3ce0423f491563e55060abc32fd8b26cb6e191712fd76774c19cd12660326159b1bb147b7bc3792d1cbe35a6a848b2bd49d382f6262a85fb0e82b42e46dee7b6f",
          "ciphertextDigestHex": "06303ff00007ec28e61e61a117e55621acf3a9c597144489c6b48b294bdc3dcc"
        },
        {
          "kind": "OUTPUT_ESCROW",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020009101c283aeb8f841686caa72baea5638156",
          "nonceHex": "22080eb7e59b3f5f3c750fb7",
          "aadHex": "53545958414144310001000100090001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020009101c283aeb8f841686caa72baea563815621212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c7300000107",
          "plaintextHex": "53545958504c4e310001000901000801000000207d642f96923a130b6be60121e1246d9a2f4715d7b4bc9ab1af4aae66d1fc46d502000000208801cafa4e1a66435cce691ced57f873462e45bab73efd3132e796dc3dfdf54f03000000200d47082c64f148767f4cdeae883191c682e8e837ce8843a3960f18196a99bffd04000000205ccbebcf1437e9c255beae522d319ede4571751adeaa0b1d2030f102f50cdd040500000020d15c8383f7019e334fb80e7882ed70a9f78d5b9f9c18399d64040bf8785fa367060000000102070000000f6c69746572616c2d77656c636f6d6508000000200dc26e53f320e9df0221eb9bfc82d76513b5d21e4605de1c3c68ac8f99579812",
          "envelopeHex": "53545958464d543100010009000100010001000100660000012900000107000001070010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020009101c283aeb8f841686caa72baea563815653545958414144310001000100090001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020009101c283aeb8f841686caa72baea563815621212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000010722080eb7e59b3f5f3c750fb72afd910f7f7d1aa2ab472da39ef62d9ff08a25a5730158a9f002ef53243c7d83152bada8a95a93b4bdff29e39f6e4120132ab5dfc8470332ebfd6a9b791de4d3b500fe59e2b3251bd5bfef0cb5278b15fd06ead20918d4a18d0c4dd1b5ab3e752e7c9827ee8abb085e8a8da1cd93a5565df10ff88cac26d7f7342941ffd2318704967736428cfcab4d21c78ee8d835cdef6e8c9904f86ecd96ce4b01175e5f85604e22879aa54cdd17fe8fa200c066e85ca21f602084be9a1422847b38ede3fdce2c51701a6cebaaeb20a05ba1dfb0dbdb0ba409ac42ea6c7ed24c2afec34906423910b80629f0422dd13e2422568d4c1b84d2e6095644b750ca90b449a7229ab0d47226d95b045bb1183e0e2abb20433ffb0ce82f2fe5",
          "ciphertextDigestHex": "fcdda5925acc9da03b331d428b59e2f8a0f88beddf228fe137147b4aef5b150c"
        },
        {
          "kind": "SELECTION_METADATA",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000a100a44f45fe7554cb37189c11267bfc0a3",
          "nonceHex": "22097bdcf80dd99fbd54c1db",
          "aadHex": "535459584141443100010001000a0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000a100a44f45fe7554cb37189c11267bfc0a321212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000003a",
          "plaintextHex": "53545958504c4e310001000a0100020100000001030200000020312db076e5edf8234a2ae152e2377b65161b3234925f913e8c14d994897adc42",
          "envelopeHex": "53545958464d54310001000a00010001000100010066000001290000003a0000003a0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000a100a44f45fe7554cb37189c11267bfc0a3535459584141443100010001000a0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000a100a44f45fe7554cb37189c11267bfc0a321212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000003a22097bdcf80dd99fbd54c1dbbc071e6c6476f935eba8ba95ad786d6eccde691e9043d0c956719af6131232f98afa77ada31ea47e083b71d2882a0df3af13a1a37ea5c9f67178a4b0d9bc5546ee1bdf54e06daeee5810",
          "ciphertextDigestHex": "1711f5ab6e424d2160ed491a38f69e4a384f7fefa6daaf47759806c437eb8539"
        },
        {
          "kind": "RETAINED_PARENT",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000b105d5da34d3ab5db820dd14711c2e65bcc",
          "nonceHex": "220a9a41b88eccb864aee98a",
          "aadHex": "535459584141443100010001000b0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000b105d5da34d3ab5db820dd14711c2e65bcc21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000003a",
          "plaintextHex": "53545958504c4e310001000b0100020100000020a1fa48d0580ad34cf330beb258622722d6241b8e6ffbdb96e5e6a755582a1bea020000000102",
          "envelopeHex": "53545958464d54310001000b00010001000100010066000001290000003a0000003a0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000b105d5da34d3ab5db820dd14711c2e65bcc535459584141443100010001000b0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000b105d5da34d3ab5db820dd14711c2e65bcc21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000003a220a9a41b88eccb864aee98ae8562a2d71ff6cbbee1e3542ffd117903a400e85e09acc9dbc0f503b7edc7763ec069d838af4fdc9892aae68072da19c5612a3c6ab9cb7bd45dfa69601a10735043c97eee061541dc9d3",
          "ciphertextDigestHex": "e974d1311eb7b51ff678bd05632852ed03f98ef900f7e7477006150937bee19d"
        },
        {
          "kind": "LOSING_CANDIDATE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000c10e4f3f18409d6e6b39c6727292dfb6498",
          "nonceHex": "220b7284e73213989312899b",
          "aadHex": "535459584141443100010001000c0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000c10e4f3f18409d6e6b39c6727292dfb649821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000000f",
          "plaintextHex": "53545958504c4e310001000c000000",
          "envelopeHex": "53545958464d54310001000c00010001000100010066000001290000000f0000000f0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000c10e4f3f18409d6e6b39c6727292dfb6498535459584141443100010001000c0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000c10e4f3f18409d6e6b39c6727292dfb649821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000000f220b7284e73213989312899b5c0243600a1326d85377e130dcd5c2b8334007e959d42e0eb5143083bcdda4",
          "ciphertextDigestHex": "b9615ff4d13bf53866e60db171c77ecccda0d97500d3fc3000d2d61dde454474"
        },
        {
          "kind": "MUTATION_HOLD",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000d106da7814be10eddf3f195f4cf8e959cb9",
          "nonceHex": "220c99d3ab38e86d2b6b4577",
          "aadHex": "535459584141443100010001000d0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000d106da7814be10eddf3f195f4cf8e959cb921212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000000f",
          "plaintextHex": "53545958504c4e310001000d000000",
          "envelopeHex": "53545958464d54310001000d00010001000100010066000001290000000f0000000f0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000d106da7814be10eddf3f195f4cf8e959cb9535459584141443100010001000d0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000d106da7814be10eddf3f195f4cf8e959cb921212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000000f220c99d3ab38e86d2b6b45778869ec1775c2f909a5de2b906997eedfda215bd4362a45db702d5be64cfbd3",
          "ciphertextDigestHex": "e6de7eef67a47f43b356f2f81890bea72d1f4e1878de9d3556c06c055f796c8d"
        },
        {
          "kind": "COMPONENT_SET",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000e10e31ad9c06ef304519d8befb2060a3932",
          "nonceHex": "220dd05f5ddad7eb922db3b9",
          "aadHex": "535459584141443100010001000e0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000e10e31ad9c06ef304519d8befb2060a393221212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000007e",
          "plaintextHex": "53545958504c4e310001000e01000301000000205ccbebcf1437e9c255beae522d319ede4571751adeaa0b1d2030f102f50cdd040200000020d15c8383f7019e334fb80e7882ed70a9f78d5b9f9c18399d64040bf8785fa367030000002063616e6f6e6963616c2d636f6d706c6574652d636f6d706f6e656e742d736574",
          "envelopeHex": "53545958464d54310001000e00010001000100010066000001290000007e0000007e0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000e10e31ad9c06ef304519d8befb2060a3932535459584141443100010001000e0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000e10e31ad9c06ef304519d8befb2060a393221212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000007e220dd05f5ddad7eb922db3b975d6f7e9aaeca9a410dba8c384e9c58ef7bd9beb67884d80ffd25625f83ad734909e415ade739e0b8f5aad2f6fb6f975bc9f648d1db72ab4931408e4dfced1ea9640c03c746fdaa9ffcafcb828be31ee0db9df4b133404f01cfbad806861b446b01e3eeee8685a5160b92349a44a49cd297836f50e9e1ef36f1bcbc7fcde1f0febf8a7bd2c5aa666b90920fed580",
          "ciphertextDigestHex": "0621f569c8721a875493349f5d4465813854dde884ef91654ede32b7245b1c21"
        },
        {
          "kind": "ABSENCE_COMMITMENTS",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000f100379eb444bd86b2bd8a124b51796c2ec",
          "nonceHex": "220efe9ff7d4b25bf8e3f5e8",
          "aadHex": "535459584141443100010001000f0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000f100379eb444bd86b2bd8a124b51796c2ec21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c7300000021",
          "plaintextHex": "53545958504c4e310001000f010002010000000400001806020000000402030c0d",
          "envelopeHex": "53545958464d54310001000f000100010001000100660000012900000021000000210010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000f100379eb444bd86b2bd8a124b51796c2ec535459584141443100010001000f0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000f100379eb444bd86b2bd8a124b51796c2ec21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c7300000021220efe9ff7d4b25bf8e3f5e84cbc68a47b1cb8f9b7654b07449149d4c4ad65e88ad5f9493b919c000c69f39860104765d7a7227924b50e8c42016dfb0c",
          "ciphertextDigestHex": "899ffc64629916fa24d81907c4536a89ea7114830d7f04e5775d74856469c439"
        }
      ],
      "manifest": {
        "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002001000",
        "bytesHex": "535459584d414e3100010000000f0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000110ee198f351dbe0180a4af73689ae1ac1b00010001404ef2cd2228509c5d92b5e5546e8178e789d2d088f6bd22d96863c5be7037a70066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020002109720363a357379d720b9c00c1bc924880002000161dd04525dc19b487a935aed159c403de436266743bd6ffaf95e5a6af2cbffed0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000310bbc71a6764adaedf0ad0b60e7900e40f000300018ee456b434914d9a08cab6011f8474204ba3f7de5fa5789e4159790c73bfe3720066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000410918b5a723c830e286b7e7a601c0be4ee000400010740fd41d0594ef1930924e7d3301346c056bf6c8038adb1b7cb004f8be84cef0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020005100d08b65ec848deeaa20ffe221f6eb86e000500011feedb95836dad5dace9ec67e7ef270d2ee25e47c8ad53878c57a70cc05bcf7d0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000610288c3c165ae84ad0d62462f4170cc2f40006000165740f5c416a9612a3a1c9c7cf3e41b6e753969b639e06274eee84e9b7e7aafe0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000710c2f4aa5cd449e6792c5e56aa88a8efd1000700011590ef91070fba331ab92a6d346b4cee0c06846f8215899bff3fcde47c85ae7c0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020008100c2cabad3bd2bc25c861e8dd966936010008000106303ff00007ec28e61e61a117e55621acf3a9c597144489c6b48b294bdc3dcc0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020009101c283aeb8f841686caa72baea563815600090001fcdda5925acc9da03b331d428b59e2f8a0f88beddf228fe137147b4aef5b150c0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000a100a44f45fe7554cb37189c11267bfc0a3000a00011711f5ab6e424d2160ed491a38f69e4a384f7fefa6daaf47759806c437eb85390066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000b105d5da34d3ab5db820dd14711c2e65bcc000b0001e974d1311eb7b51ff678bd05632852ed03f98ef900f7e7477006150937bee19d0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000c10e4f3f18409d6e6b39c6727292dfb6498000c0001b9615ff4d13bf53866e60db171c77ecccda0d97500d3fc3000d2d61dde4544740066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000d106da7814be10eddf3f195f4cf8e959cb9000d0001e6de7eef67a47f43b356f2f81890bea72d1f4e1878de9d3556c06c055f796c8d0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000e10e31ad9c06ef304519d8befb2060a3932000e00010621f569c8721a875493349f5d4465813854dde884ef91654ede32b7245b1c210066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000f100379eb444bd86b2bd8a124b51796c2ec000f0001899ffc64629916fa24d81907c4536a89ea7114830d7f04e5775d74856469c439",
        "plaintextHex": "53545958504c4e31000100100100020100000842535459584d414e3100010000000f0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000110ee198f351dbe0180a4af73689ae1ac1b00010001404ef2cd2228509c5d92b5e5546e8178e789d2d088f6bd22d96863c5be7037a70066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020002109720363a357379d720b9c00c1bc924880002000161dd04525dc19b487a935aed159c403de436266743bd6ffaf95e5a6af2cbffed0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000310bbc71a6764adaedf0ad0b60e7900e40f000300018ee456b434914d9a08cab6011f8474204ba3f7de5fa5789e4159790c73bfe3720066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000410918b5a723c830e286b7e7a601c0be4ee000400010740fd41d0594ef1930924e7d3301346c056bf6c8038adb1b7cb004f8be84cef0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020005100d08b65ec848deeaa20ffe221f6eb86e000500011feedb95836dad5dace9ec67e7ef270d2ee25e47c8ad53878c57a70cc05bcf7d0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000610288c3c165ae84ad0d62462f4170cc2f40006000165740f5c416a9612a3a1c9c7cf3e41b6e753969b639e06274eee84e9b7e7aafe0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000710c2f4aa5cd449e6792c5e56aa88a8efd1000700011590ef91070fba331ab92a6d346b4cee0c06846f8215899bff3fcde47c85ae7c0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020008100c2cabad3bd2bc25c861e8dd966936010008000106303ff00007ec28e61e61a117e55621acf3a9c597144489c6b48b294bdc3dcc0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020009101c283aeb8f841686caa72baea563815600090001fcdda5925acc9da03b331d428b59e2f8a0f88beddf228fe137147b4aef5b150c0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000a100a44f45fe7554cb37189c11267bfc0a3000a00011711f5ab6e424d2160ed491a38f69e4a384f7fefa6daaf47759806c437eb85390066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000b105d5da34d3ab5db820dd14711c2e65bcc000b0001e974d1311eb7b51ff678bd05632852ed03f98ef900f7e7477006150937bee19d0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000c10e4f3f18409d6e6b39c6727292dfb6498000c0001b9615ff4d13bf53866e60db171c77ecccda0d97500d3fc3000d2d61dde4544740066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000d106da7814be10eddf3f195f4cf8e959cb9000d0001e6de7eef67a47f43b356f2f81890bea72d1f4e1878de9d3556c06c055f796c8d0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000e10e31ad9c06ef304519d8befb2060a3932000e00010621f569c8721a875493349f5d4465813854dde884ef91654ede32b7245b1c210066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000f100379eb444bd86b2bd8a124b51796c2ec000f0001899ffc64629916fa24d81907c4536a89ea7114830d7f04e5775d74856469c4390200000020d1119c5d337e2f802e13be4c149a59823b173c96d009423cf120c7e8f0c87ba1",
        "nonceHex": "220f3e33a20abe7bea4dc1e9",
        "aadHex": "53545958414144310001000100100001000100000056535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622000000000000000200100021212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000087b",
        "envelopeHex": "53545958464d54310001001000010001000100010056000001190000087b0000087b0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622000000000000000200100053545958414144310001000100100001000100000056535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622000000000000000200100021212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000087b220f3e33a20abe7bea4dc1e9eff731890a79fead19c3ca1f9fe15c47401e048e765126287a84000c219c19c94c75ea672a6dce29b19c45bf45b32cba3b333b3608f74baa3eb37b53c578e523972334a5d4c5ca189268252a484ee1826a157f9a1d8fbf57d41f333240c670701c35e34a9dc12a679ac3621d68d3f7cd3c2a94fafc1106995d4ccf58dc6b118b8f35f205e19e7e536e9fbd68470a8addb99432f077a75fd8723255feab2f641bed2d8cb746dcffbc3bb538048bae59d1e5ea304a33fb979997784ebb317c38ca2a72c6ae4a89aa9d67a5681c81f457cbf2d2fee526a27b3171f5e28829061da472e794ceae5655f903649a17ab70b7856daa9bc2e926f20048ad9e0850f0f3eb95995c7941a968084a0ddfd1049e1e60cd7602d0debd582ce3887814a2a5fd7b2166e9fc11c550be3951eac4be759e2a1594b09c4183c5c99b57eaa6aa001630ec99c5f149b70c15fe983c95e057bb7f1abeb85f6889c9ac4329b686f07c6e940fa04a5039478e10e072c920a9fe8d2f8b10fca9839e6029a3a61dff1a2080f4a855a2253ad0fd76cb36626e2de4dbfa8712a76511c5657fec31f79b901050b70a372bf9626285adfac6c0053ad405e82e69e29aaf3efc646b3562d3f03eff2733da5d5704e366d5a4ecbcc293d476ca3b75f9bbd018bef2acbcbd7a05b7f9e34f4ddc0e529ec6f146bc9ef413bc7c050b238b6c3592471a0c054139b4555996d33d03e8c1422c0869da3253b5d328963a6f5cbfa48ae025de9d80c4eb06a254d744142a791c91f4c7619b9292401adde8edf34cf07602692e4bf9fefcd788a0e697a51dcb89fd7273bb5cda984308584c176c2d6b7bab1425d5cc01e09962149db333f3e0907712ee203977a2b779a6d52114fdfb4885f3d5584e9132a922b8b9b15c211df4e03d8647218ca3156717b10498bcd93491145cb63cf76dfd3637ed0151ee2b3ce35c64358e0b408b1937a6cccc3b2b1c9cc08200bdbed274a58ad942a8e48123bd2d122ab2dfd9c8f9aa27f9f1246ebcd82a27238890430fe3ec1828bab37239a6c5da4f3e0bd282d67e3984e2522cdf182171a01510f9542e09c21a28654448f1b65a554c965da3c0b2f60e084cb1f2adc6ea791d59e27d2048db068cd6f35ca58e5a84914bf89ec86ea8efeb45ff207c1b62fba5b1f507b474351f4dd04d4e192891488b9cd1e732b5c36ad938a6cfc1023e6038ebb55433b6a867076bc17aad25b4f4fc58f89fc576b5be993cfb06f0ba746334b43159a6842ecfff6e088382daf098a7bf25a6d87a36837e900df147aa70e12f3b75e18ad6993bcf839d19c21344fb561a31bf9874f34002a3493dabc3334d8032385ddb86e4a6d99fd7f73b3830b1910f6c22d86f712325f880a694a0e9a3defe7e3ba70124d6666323a001a0cfbf1edebfa1bd9d60394ef9193b7f6a52e2c28a0bbe3cfd98077cbc67592c1068949b9092cad2a29a12e61e4f5aa4de3cca4ad337803da082be304202a7531ce9a9e7c2427aa9a547b71d32a927ea4bdb844cd6aa2f8786b5bca2147ba302f7af7fa450bdf8f27b1565ba50291873ee7b6783204dd39095aaa857d74e805ce8ba858a9b4b8f757f8451554477e1c95af12c3919c5f45ff71da6eb751b4d5ed602cfd58de9ff55540d2b97c97e737be48d7cef6c6e9e8bc4417dda34005844706f578a81cce3edcc8d7f593076a1957eb67ea85ee3e887f7d97d79a7780489a2cdfadbf3dc4b4f181bd3ef047ab646c3d6469cb41abe58f03383c1c0556d19371534d11d7864ceec6f1da7892a54a5f3fa9677de3cf7c89fdc141faf7e197387935f5672b26b7f2b46937b84652e52c2c4197d99735d529a2b2a58cbf9f6fd0082a6e3c6bff5f35c51a03cf5cc0ae8c6dde9303d9a4f8bd98d952b159c3b79f6a60c4603c08636f234965bf8d441e8f94dc2947fbc38d23bf5b66f58276196347c85feb2073a4219a657b949541e945e8830d7adf281a2126de20a94f7b202081f7be90b9255c862f6a26c721c3e379ab98f895350f4db211ebd1eaaa694596b43123e1a126627b37673ff221e68aeb2847a0c3b012206f11a1ef62ebd2b71f4b02354a0f6c3713eab0e8ac53ec5792fc2da1a5c8f36558e84016ea31fff40436c6a902a6ec46bdf6aa2f6678fd13ac91cab49f1b4f7c68942770fbaa19c91b90930d8835e75afce4f86da71dce5837c84e7141cf9a48eaf5604e402e6a93209d32ae451df89e2e17bdd11e87b5d496e5d92d3f5373f164a5fa5b6eb02e13dfaa3f83bc798665655ca78c8c97dab4b4d0e8358e20cc08b0afe75c76dbc3544801801f6a8faf0c3a1f85e700c90710343a3fe0cfeb5dd49a78b3399ee524c5125cb82fc4bdbdd134d3583bd233ff04606ca4a3bb7fe8270a14a881b53e1da0c868adfdb0ff2383ada6889948e42b1c211bd7597a09e778479e7f00b5a6bf5e1148871f339b53c23c7cdfc19164701290f39f34ecb0c52b5696dabe47438d52d4f07284854d29422588e872537670ac819b9dbee9449164281732bd89c375084e986b5c19dc7c48534a10add95eea6793047caa0c6b07355bc8f9d50661ea6999dc3a7a167a18b9023aa9bf172ee641b4b97d90c6740386f4f52c0612bc59194784b5f6d1421d0b2638b1ffb485423e2d352448489ce56b3c55ab3f90ecb66b0e0adc5c81328df93408b87b10ca4ec8436f42f31463748abcb789cd7ace13a587b5f8bec47dcba1d4522f9b3463971f38c4b301be207f93327fda773ece720fe9023fd7fa54f1070e12ce234c579958c3dcd2cbb15216c4dc3cdf3f3ce1781d4dddcb5989834463e000daef3a73f9b75617026a4e7465a2448d6669c86ac6b686cb908801e7248951da4035f0441899609b8d64568e4a85648f65af60f58e243ff2a6161b3bc979f0d85dfb767c7db5728c3a2b657cec8cdee3a7ce8a3865e7305205d4dafe24241de9dcea0de94d77e86cb28d6f4258b8a3ff190043d5ec6b79955ef0b5726697db740d525ab2a7d8958eb5d08a2278370ad8bc28f5be4d5857081d7749b9a8b02589adac983fc75f00244da37959fa6b8a080dd506e11a69aa604f6a4",
        "ciphertextDigestHex": "d05a12ab95ce67706dc201276ee53a4e2b687d4ef4f3bb7907ec63526460bdbd"
      },
      "selector": {
        "keyHex": "5354595853454c3100012121212121212121212121212121212121212121212121212121212121212121",
        "selectedGeneration": 2,
        "plaintextHex": "53545958504c4e310001001101000501000000080000000000000002020000002076646f84984b1734d44d341d3d00e4e73b79548c266523e688fc9213fc85a8440300000020d05a12ab95ce67706dc201276ee53a4e2b687d4ef4f3bb7907ec63526460bdbd04000000206dc7d7d3bd9c42ff7115838d25ddf474db5739e42e6dcee7fc8d0578d8b78a64050000000102",
        "nonceHex": "22104aea16e8b94345c52e7b",
        "aadHex": "5354595841414431000100010011000100010000002a5354595853454c310001212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c7300000091",
        "envelopeHex": "53545958464d5431000100110001000100010001002a000000ed000000910000009100105354595853454c31000121212121212121212121212121212121212121212121212121212121212121215354595841414431000100010011000100010000002a5354595853454c310001212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000009122104aea16e8b94345c52e7bb85c36f0f7e7df91779e344dfe2ac15b7cc8bbabb30119d8f7553a668d99f93918af53248a1c6351d123c15c66b24a0a3e46b7038b901a760d3f8be8baf0f0b8e7304e75b138a486bc201e62ce036f1e740919c02d0b764b8e7499a2c8afca696feaa2980e158cc63b8a7e1baff0eccece77053e328198a6e1fa0d8b7c518935d1c16bd6906ef82c573800859397331f4e2a42a4b325cab9309d4d4b69275d09c6"
      },
      "keyedRootHex": "6dc7d7d3bd9c42ff7115838d25ddf474db5739e42e6dcee7fc8d0578d8b78a64",
      "authorityRule": "selector names this generation"
    },
    {
      "id": "FMT-KAT-HOLD",
      "state": "RECONCILIATION_REQUIRED",
      "rootStorageKeyHex": "1111111111111111111111111111111111111111111111111111111111111111",
      "localContextIdHex": "2121212121212121212121212121212121212121212121212121212121212121",
      "secureSessionIdentityHex": "48d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622",
      "canonicalBindingHex": "535459584d424e440000010020212121212121212121212121212121212121212121212121212121212121212102002048d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62203013201001a737479782d6d322d73657373696f6e2d616461707465722f76310200146d322d6f70617175652d62696e64696e672f763003000773657373696f6e0400036d6c7305000c746573742d70726f66696c6506001174776f2d6d656d6265722d64697265637407001409e92777dba0528d3d29e2e5e681b7e91637c7be080030737479782d6a732f76656e646f722f6f70656e6d6c732d7761736d2f6f70656e6d6c735f7761736d5f62672e7761736d090020fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e0a000200010b002c4d4c535f3132385f44484b454d5832353531395f41455331323847434d5f5348413235365f456432353531390c0020235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba070d000400000005",
      "profileDigestHex": "5d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b",
      "generation": 3,
      "mutationIdentityHex": "299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea030",
      "records": [
        {
          "kind": "SLOT_REGISTRATION",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000110ee198f351dbe0180a4af73689ae1ac1b",
          "nonceHex": "33000f89f0ee1eacf528b684",
          "aadHex": "53545958414144310001000100010001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000110ee198f351dbe0180a4af73689ae1ac1b21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea0300000005f",
          "plaintextHex": "53545958504c4e31000100010100030100000001030200000020212121212121212121212121212121212121212121212121212121212121212103000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b",
          "envelopeHex": "53545958464d54310001000100010001000100010066000001290000005f0000005f0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000110ee198f351dbe0180a4af73689ae1ac1b53545958414144310001000100010001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000110ee198f351dbe0180a4af73689ae1ac1b21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea0300000005f33000f89f0ee1eacf528b684f920a46ac6b48e0c6b9ee91a71cb52b2e345295b18af24ac51c168d50954f240ea06a594ee820a22bf36685a408ec5e56720f9b7fc6508f1d643139b1cd48d549e548ded7d8fe0c48c4919aab7b076cc28f9bfdb8b723547eeb98f63f266878c95455cad69ff9a4b5f75bd777bdba9",
          "ciphertextDigestHex": "5239f9d2b9622e1bd8c49d76af52fb62dad3f71ef1ade65a2f8a76cd0e5c0846"
        },
        {
          "kind": "ISSUANCE_CANDIDATE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030002109720363a357379d720b9c00c1bc92488",
          "nonceHex": "33011fd42ba17beddcdde73d",
          "aadHex": "53545958414144310001000100020001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030002109720363a357379d720b9c00c1bc9248821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea0300000000f",
          "plaintextHex": "53545958504c4e3100010002000000",
          "envelopeHex": "53545958464d54310001000200010001000100010066000001290000000f0000000f0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030002109720363a357379d720b9c00c1bc9248853545958414144310001000100020001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030002109720363a357379d720b9c00c1bc9248821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea0300000000f33011fd42ba17beddcdde73d052c5c56a8bbc8c5153302e28411d485eab07320c8a4680ad93759fa91f6c1",
          "ciphertextDigestHex": "d049311a7f7638be155721d69cb75938fbcb76183176d6df88a17aa6a6f177f8"
        },
        {
          "kind": "ISSUANCE_OUTCOME",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000310bbc71a6764adaedf0ad0b60e7900e40f",
          "nonceHex": "33023375b9db1a69e80cae53",
          "aadHex": "53545958414144310001000100030001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000310bbc71a6764adaedf0ad0b60e7900e40f21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea0300000000f",
          "plaintextHex": "53545958504c4e3100010003000000",
          "envelopeHex": "53545958464d54310001000300010001000100010066000001290000000f0000000f0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000310bbc71a6764adaedf0ad0b60e7900e40f53545958414144310001000100030001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000310bbc71a6764adaedf0ad0b60e7900e40f21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea0300000000f33023375b9db1a69e80cae53c71cab3996c7a2880c28010c6d821b1ebbaefd21e97c492a43a576d65cc27d",
          "ciphertextDigestHex": "08c311795ec876b379f21785d1e73373a61306eaf6481264e3067442a5be7808"
        },
        {
          "kind": "KEY_PACKAGE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000410918b5a723c830e286b7e7a601c0be4ee",
          "nonceHex": "33033f87b13c742d13bc9bbf",
          "aadHex": "53545958414144310001000100040001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000410918b5a723c830e286b7e7a601c0be4ee21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea030000000d1",
          "plaintextHex": "53545958504c4e3100010004010008010000000c678bdacc7d3efcef7f94092f020000000c3cc6430c0ecada4337a26d360300000020232d780df9615a3dd2796dafe329c90f8b0c3edd41bd81791a078e3d47b358900400000020e56d6751026dbd6212134c8d6d505c8e13b935e20dd2b16038113646a40c8bee0500000020212121212121212121212121212121212121212121212121212121212121212106000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b070000000101080000000100",
          "envelopeHex": "53545958464d5431000100040001000100010001006600000129000000d1000000d10010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000410918b5a723c830e286b7e7a601c0be4ee53545958414144310001000100040001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000410918b5a723c830e286b7e7a601c0be4ee21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea030000000d133033f87b13c742d13bc9bbf9c958012414784e2c52f3868396563964b2d575c5e2f1358e57165be5a301003575d1d45384edb0f414dd7afa7180a93ffe42d0311a7a9e5fb07bfcf1289eff8e2183787b4cce47dcb27296d5314e6a6f0f20f0f4988ad52d04121ca0cdf2f74fdf215931c1c57cdfc2d76395abb0daee2959127dea43e55d2458966cd868be439eaa5e3e522d0579c0b019a5cd6199ca5e779b70de7d80fd7dbe0deec0688ac2bb073077d41a035479ce491f9e4efa4b7b4a1086f27cb2e00772f55a9e2dcb41abd99f142e6403f8d021d19ef4e37b56071e0f649474b3a5c12103e7552f00758",
          "ciphertextDigestHex": "bfa4368acbeab5f570ecad2abe6cd5c2c04424b6bc9077c0b14df08977b1d714"
        },
        {
          "kind": "SESSION_STATE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030005100d08b65ec848deeaa20ffe221f6eb86e",
          "nonceHex": "3304cd2ea95c610ff3b47b10",
          "aadHex": "53545958414144310001000100050001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030005100d08b65ec848deeaa20ffe221f6eb86e21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea03000000020",
          "plaintextHex": "53545958504c4e3100010005010001010000000c24030d889763a2732abe79ef",
          "envelopeHex": "53545958464d543100010005000100010001000100660000012900000020000000200010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030005100d08b65ec848deeaa20ffe221f6eb86e53545958414144310001000100050001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030005100d08b65ec848deeaa20ffe221f6eb86e21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea030000000203304cd2ea95c610ff3b47b10850d3dc6fbf05eec5da22a1f1f9fc97b24b0ba928ed50112545a48b2d981a28290bef9a98299191d1acdee482eea9269",
          "ciphertextDigestHex": "8ac90fb53b76ae5dee442405f96c2bf56f22adcc3b5d6733eb1c3d95db64ae00"
        },
        {
          "kind": "BINDING_PROFILE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000610288c3c165ae84ad0d62462f4170cc2f4",
          "nonceHex": "33054cc38fab4a398eb86ed4",
          "aadHex": "53545958414144310001000100060001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000610288c3c165ae84ad0d62462f4170cc2f421212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea030000001be",
          "plaintextHex": "53545958504c4e31000100060100020100000185535459584d424e440000010020212121212121212121212121212121212121212121212121212121212121212102002048d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62203013201001a737479782d6d322d73657373696f6e2d616461707465722f76310200146d322d6f70617175652d62696e64696e672f763003000773657373696f6e0400036d6c7305000c746573742d70726f66696c6506001174776f2d6d656d6265722d64697265637407001409e92777dba0528d3d29e2e5e681b7e91637c7be080030737479782d6a732f76656e646f722f6f70656e6d6c732d7761736d2f6f70656e6d6c735f7761736d5f62672e7761736d090020fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e0a000200010b002c4d4c535f3132385f44484b454d5832353531395f41455331323847434d5f5348413235365f456432353531390c0020235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba070d00040000000502000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b",
          "envelopeHex": "53545958464d5431000100060001000100010001006600000129000001be000001be0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000610288c3c165ae84ad0d62462f4170cc2f453545958414144310001000100060001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000610288c3c165ae84ad0d62462f4170cc2f421212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea030000001be33054cc38fab4a398eb86ed43d382801be7af70646842e18e87c9334a3fe3dd7011c62df68adafe8439c7ee14724b77350d44a4e2e44258814b0e9a2602f2edd51ee7e5477f7f69dd46fcbd4b7c16d1b0257c48a85913a8dd1b2634062745cdc88a93daf924ada11efd94d5eae64bfb2bbe955e7cb427fa1d9caa41719f3b67bebf99216dc66930120c0fea5ad6672795d134243a8e5c73dc25994c3de6dd854fb54b02bfa2619da1a9578f49099eebe5a677a8abcbf2dd3d8ae266e13a1c26447a6933cfd6f0e96c34a39effeb4573d5bb288168fd6278f662fb82e66b477417ab6ee4c1f2006a1697d14c3e7a01dfc9935776ec4aa8fb1083fb62d5e92359eca08951c3955d2a66956a6ca13c0658c1418fcc77e715b879bac94c665c90faf21ea3029d74e293375c7904285e704cf9e1e126c23f7e5c311bd6a62cbef6d943fd0f39e382d81a699111209cc1dd686f7f7e91cfa3ec5d10343f8fac538016cbce566236995f676b9229d211d953e0b73b733c6d8bd748d86f3c9c73eea92790c3ba89428a62a83e59faee2f29ed69a96c7f6d659e9c6b32beddba7f50718958eed30fd0f253b8238d3f265b201cb91d26f9ca5e95dc3e16c084f2e2ede97aa3ae5cbb4c2ea0c105f6bf3883f6acf849952636dd6c31d10e5f7",
          "ciphertextDigestHex": "c4b1ac1ea390931cfa24caa819fec04b9d5ed9f5c40891057dadb27f1bfddd4c"
        },
        {
          "kind": "REPLAY_RETENTION",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000710c2f4aa5cd449e6792c5e56aa88a8efd1",
          "nonceHex": "33064b821a759a2d80106cf3",
          "aadHex": "53545958414144310001000100070001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000710c2f4aa5cd449e6792c5e56aa88a8efd121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea03000000031",
          "plaintextHex": "53545958504c4e3100010007010002010000000ca1ccd8c14dc64d2e15ca5871020000000c2b9c25b5f8703721859a12c9",
          "envelopeHex": "53545958464d543100010007000100010001000100660000012900000031000000310010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000710c2f4aa5cd449e6792c5e56aa88a8efd153545958414144310001000100070001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000710c2f4aa5cd449e6792c5e56aa88a8efd121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea0300000003133064b821a759a2d80106cf3c81ff201e90b1cab29f2ee570ca22459788297dcb2a211b24235f56db1d55347a7be504543bb4cb34929fd16bae9260b90be274f39d3afd5d904fbb872edb9812d",
          "ciphertextDigestHex": "23edd1c3e93c0e2fd3c83f466fa6f5eba763413c2818b3beb753161aa32ea969"
        },
        {
          "kind": "COMMIT_RESULT",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030008100c2cabad3bd2bc25c861e8dd96693601",
          "nonceHex": "33072893d25ac7d338896c1f",
          "aadHex": "53545958414144310001000100080001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030008100c2cabad3bd2bc25c861e8dd9669360121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea03000000174",
          "plaintextHex": "53545958504c4e310001000801000d0100000020c71576a160a451cdf49063d0e06057d961f70ea320ed993fcbad642ff8ca36330200000020404f8ef1158e39995fc5bc3ea1d731346bf0e0856414614dcb3c585e82c3f5150300000020219ccd65d74f50c7e411e7ccd1968e2c725a3135f7fdac2ea1ee601c75054d9d04000000205c1cf96a870953a5c80c55190045bd8e2e7e3e57d5bc4de72d71f73bbdad173a0500000020ec21e5175b6177cb09ef82a4b095961913b3ecf35ba87c42653c1989af823609060000002050468bc45ffce637c1b2fcd28eb9d3f1e256a259e0103da764b524f7b2161f02070000002054ed3660c2b0997887d845b849c912d54d1b22d2371628d118b15db276e9ca43080000000102090000002021212121212121212121212121212121212121212121212121212121212121210a000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0b00000001030c00000001010d0000000100",
          "envelopeHex": "53545958464d543100010008000100010001000100660000012900000174000001740010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030008100c2cabad3bd2bc25c861e8dd9669360153545958414144310001000100080001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030008100c2cabad3bd2bc25c861e8dd9669360121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea0300000017433072893d25ac7d338896c1f7d0d3921aebabb2b1022b34668556118612944e98ace7db19c4709469dbcf4c51145017b6c3ca7291c2bb1182c3803531ea0a834642e51c6c79e1c0582a6fb1453963af6c26450e772357d92890c2f85f5474b69019db47e316f9804ceef3ff999242dac0cadf6778a6b04c3912b03c8eee24e3e98ae10181e635e4f467d30eb035907d3ea87d3607c170b308bb1e13b31c97e98a6b97c0731fd2660c7578da903bd7e534c4c2ce9089c6194eee2c9d7f966f99615d0111c9c0feea40d2228b0531ef37a41cbcc0fc47aa7d805e5bafb7b4dea428e5afe4a4fbedd66d864b4171f51f02f0e255ee94fda137526bd6eb61bef91133551771b85853cc4f29aed9e6ab20b0b973b2fd6fc6ec192f71e457fa38890530a70e122aa13558fab95bc07e76c143700a0e27a68dfd081a693df8e4863af35493b94fb33d36dc4a593f1dcf063f0a7cf052a8b0cb6ccf41c0f076a40c1049e6e7244affcf229ebdda14126f292ad0189e8e95312e67d3336a71c67ad9b0c3da8180aadc55f312f64110a5ad461cb90",
          "ciphertextDigestHex": "66f9cfa3a1a72c46ab9f4270201c6137102c29df893961986b10d699af52be80"
        },
        {
          "kind": "OUTPUT_ESCROW",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030009101c283aeb8f841686caa72baea5638156",
          "nonceHex": "3308c234c1abf77a9fa613c2",
          "aadHex": "53545958414144310001000100090001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030009101c283aeb8f841686caa72baea563815621212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea03000000115",
          "plaintextHex": "53545958504c4e31000100090100080100000020c71576a160a451cdf49063d0e06057d961f70ea320ed993fcbad642ff8ca363302000000205c1cf96a870953a5c80c55190045bd8e2e7e3e57d5bc4de72d71f73bbdad173a0300000020ec21e5175b6177cb09ef82a4b095961913b3ecf35ba87c42653c1989af823609040000002050468bc45ffce637c1b2fcd28eb9d3f1e256a259e0103da764b524f7b2161f02050000002054ed3660c2b0997887d845b849c912d54d1b22d2371628d118b15db276e9ca43060000000103070000001d6c69746572616c2d70726f7465637465642d6170706c69636174696f6e08000000208cd683a5b55ffc9a1d31dfd1a0827d203ce6a6acd2ee9609c08ba87302d392d7",
          "envelopeHex": "53545958464d543100010009000100010001000100660000012900000115000001150010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030009101c283aeb8f841686caa72baea563815653545958414144310001000100090001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030009101c283aeb8f841686caa72baea563815621212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea030000001153308c234c1abf77a9fa613c2c5308fe8ebb47c7b101fd4b4621367e5ae0fe20f45e82e3aa80b5dc986043a7e9a65d43dee7daab4e5dd1c48e2522e33bfef20019a9129bd3fb874b9d8fbce1ca82b68dc1e30a6f1397c870e0948c2b3a2085467d3900df6c84d70b9e6239f9d307f07d555de8bd4c6e2306b82a1b65981b32397874ee77ccb8d27aab38377aee232bb4cd7713d3ce5921ac23941f206d94a95ea3e8a3672cc8ecaf4b9d2130afd03ae00105c0a63001167d72c3f229bd7cf345fb0eea6816f1db123abe4cc3df77aba13ac7f0de2435268b93243e211b93aec18069a1c77c4d03e71a89cb039a1c383452d9f016798d705456443a2e4db617bc4e82ea5c24c651a072f273e10fbdbeaebbf72922dffd6af2d48d03307e3be2b60e6d325560ed875c8d0c6d77fc0daab71fb",
          "ciphertextDigestHex": "497961ad5fb0f156ebfda9c439278e70fc3073b4deb56a7b19aecbf0ae61ee67"
        },
        {
          "kind": "SELECTION_METADATA",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000a100a44f45fe7554cb37189c11267bfc0a3",
          "nonceHex": "3309403c149585b8b3699d79",
          "aadHex": "535459584141443100010001000a0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000a100a44f45fe7554cb37189c11267bfc0a321212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea0300000003a",
          "plaintextHex": "53545958504c4e310001000a0100020100000001030200000020312db076e5edf8234a2ae152e2377b65161b3234925f913e8c14d994897adc42",
          "envelopeHex": "53545958464d54310001000a00010001000100010066000001290000003a0000003a0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000a100a44f45fe7554cb37189c11267bfc0a3535459584141443100010001000a0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000a100a44f45fe7554cb37189c11267bfc0a321212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea0300000003a3309403c149585b8b3699d79d8fbd09e5332db6cdf69c637cab52176b887abf1f177286d4b23d55f2a1ef118744be1d0810e9d0fa73f4c4758d6fbaa8ff0f346617d4bd5468df2f702c38818c34f0b3e6fee2abe0ef6",
          "ciphertextDigestHex": "afaad8eef742f726453b46a01e5250d43ffa8e0fb7deaf1ee0bee3ef82e516b8"
        },
        {
          "kind": "RETAINED_PARENT",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000b105d5da34d3ab5db820dd14711c2e65bcc",
          "nonceHex": "330a540fca850ea5a0cb74db",
          "aadHex": "535459584141443100010001000b0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000b105d5da34d3ab5db820dd14711c2e65bcc21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea0300000003a",
          "plaintextHex": "53545958504c4e310001000b0100020100000020a1fa48d0580ad34cf330beb258622722d6241b8e6ffbdb96e5e6a755582a1bea020000000102",
          "envelopeHex": "53545958464d54310001000b00010001000100010066000001290000003a0000003a0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000b105d5da34d3ab5db820dd14711c2e65bcc535459584141443100010001000b0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000b105d5da34d3ab5db820dd14711c2e65bcc21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea0300000003a330a540fca850ea5a0cb74db1c11c4cc70a7e76f595da93eef8b7ceab3c71e6278faf59e2d157dc7401389b861a8f0da73279a5cf1d6962e1e973bc4a3151d154d9ffc153a7fa35d25140c4fc1f3b1cc2ca1c778a984",
          "ciphertextDigestHex": "41c468fe01c7899b04172eddc33e3d1cbd29d477ed2552a30643b4ddd3c0cef9"
        },
        {
          "kind": "LOSING_CANDIDATE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000c10e4f3f18409d6e6b39c6727292dfb6498",
          "nonceHex": "330b9954d793125d45007373",
          "aadHex": "535459584141443100010001000c0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000c10e4f3f18409d6e6b39c6727292dfb649821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea0300000000f",
          "plaintextHex": "53545958504c4e310001000c000000",
          "envelopeHex": "53545958464d54310001000c00010001000100010066000001290000000f0000000f0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000c10e4f3f18409d6e6b39c6727292dfb6498535459584141443100010001000c0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000c10e4f3f18409d6e6b39c6727292dfb649821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea0300000000f330b9954d793125d45007373f00ca079db133a3bdb68c9324a2e23101f67a00aade9c0f8295e2ef5233c8c",
          "ciphertextDigestHex": "f335dcbaaa952108ee7e557c25b93e2169cb727d9097ffd882bd59eaf6101afd"
        },
        {
          "kind": "MUTATION_HOLD",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000d106da7814be10eddf3f195f4cf8e959cb9",
          "nonceHex": "330c1cbe2a3b457fb1dd0b79",
          "aadHex": "535459584141443100010001000d0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000d106da7814be10eddf3f195f4cf8e959cb921212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea030000001f6",
          "plaintextHex": "53545958504c4e310001000d0100130100000020c71576a160a451cdf49063d0e06057d961f70ea320ed993fcbad642ff8ca3633020000000104030000000200030400000001020500000020404f8ef1158e39995fc5bc3ea1d731346bf0e0856414614dcb3c585e82c3f5150600000020219ccd65d74f50c7e411e7ccd1968e2c725a3135f7fdac2ea1ee601c75054d9d0700000020212121212121212121212121212121212121212121212121212121212121212108000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b09000000205c1cf96a870953a5c80c55190045bd8e2e7e3e57d5bc4de72d71f73bbdad173a0a00000020ec21e5175b6177cb09ef82a4b095961913b3ecf35ba87c42653c1989af8236090b0000002050468bc45ffce637c1b2fcd28eb9d3f1e256a259e0103da764b524f7b2161f020c0000002054ed3660c2b0997887d845b849c912d54d1b22d2371628d118b15db276e9ca430d00000001030e000000208cd683a5b55ffc9a1d31dfd1a0827d203ce6a6acd2ee9609c08ba87302d392d70f00000020f12427aaf4e051d0ae7d234d3fd64fbb25f5bd1b6bb5a79e80d4907e028cd2651000000001041100000001021200000020e3bfc568a860bc0a796487d5d876a826f51385a59698e6cb852407eee6bf3cc4130000000103",
          "envelopeHex": "53545958464d54310001000d0001000100010001006600000129000001f6000001f60010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000d106da7814be10eddf3f195f4cf8e959cb9535459584141443100010001000d0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000d106da7814be10eddf3f195f4cf8e959cb921212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea030000001f6330c1cbe2a3b457fb1dd0b79ac4672a652fb1b10b26a00e34d6ead6df54a1a734f8b0b9a4113bbd2c98c81a0fff969dfe2059a1aaac1f45db26b78184dc3a53270efadc88d984a0851b5fe35b03823794c39d602b47c8db6f09eccadd464a9b228df8244fb7690203355d272ccfd4bafd54d7cc2cf07914b8d9f0a90942da18bdc5908f16c74e7f43eed23234856843ea97fd39bb8b2d11cd4c3848aa6921d1b6cf36c1fc22397317d7b8865f84ae47599c60ec9dfe2f2795953ee384a5b45cc6052ac516ba9210d0462cd92f78f9f4276787693653a283eeceb206e8be4285ab61a6fde53e4f87adc8ea0b8cfd2606cc6fe3975d6c14b36d8584a19c5ccc892d929300d14426b9f8f2428b1985d07cb5c1699d2ed34ceed3137f05e55a631ec02c6d958abd9437da187d775f73343068e1da79a5aef4575fa9fcd829e7503d7b8b171c35e1916fc8597746286fd43ad9573635103f93e23018c337bc7065b73495e60b2c701161f5c95bc8c40989b0c028de6f962a459a2f2f8762d520f914cf7f70e0a32655029c06f5520a7e8e17aad37b766830cf0212c3440fa45616017efce7d6c89a050b2776375070346904df384be04072fd1165edf8b3d9ce407b98b99084a0e016da9f4f7c7c19b5e5ee9d218cb0558e025c96f1034a1cf80650a824d7f07c54d8a422d4c49780aebc6bee98f6e62d945ef30710ba4e4ea1da7e72bab3f914cd106bc14f95b0bc832d306cb51",
          "ciphertextDigestHex": "36a8ceab65535e04a9ebbe66badf043a5662f60d83a008e345df711a78abd746"
        },
        {
          "kind": "COMPONENT_SET",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000e10e31ad9c06ef304519d8befb2060a3932",
          "nonceHex": "330dca81cd3052f14e1664ac",
          "aadHex": "535459584141443100010001000e0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000e10e31ad9c06ef304519d8befb2060a393221212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea0300000007e",
          "plaintextHex": "53545958504c4e310001000e010003010000002050468bc45ffce637c1b2fcd28eb9d3f1e256a259e0103da764b524f7b2161f02020000002054ed3660c2b0997887d845b849c912d54d1b22d2371628d118b15db276e9ca43030000002063616e6f6e6963616c2d636f6d706c6574652d636f6d706f6e656e742d736574",
          "envelopeHex": "53545958464d54310001000e00010001000100010066000001290000007e0000007e0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000e10e31ad9c06ef304519d8befb2060a3932535459584141443100010001000e0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000e10e31ad9c06ef304519d8befb2060a393221212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea0300000007e330dca81cd3052f14e1664ac83d0a3b4e0859f360d1de125524ce788fb1dc05909c9397fece7d3e9774417f7bc9d9e7b802de681d3516a2634bbaa85b963abd7977cf6c2764b356553bd8126759229ae91b1302e33f9592b888fe8575cb49767522c38d3a566006e4a12271a168a01585d3c56390dfcbc429e6b93602df8deb29d68112f586477a36d89fca3436e4270f12a3857c2408a887141",
          "ciphertextDigestHex": "bd4b3269e7a6766a48cd224f77defbbfbaaad465e9096793a1dc4ce2cddc5ba9"
        },
        {
          "kind": "ABSENCE_COMMITMENTS",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000f100379eb444bd86b2bd8a124b51796c2ec",
          "nonceHex": "330ece9c78d1e27db7c94cdc",
          "aadHex": "535459584141443100010001000f0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000f100379eb444bd86b2bd8a124b51796c2ec21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea03000000020",
          "plaintextHex": "53545958504c4e310001000f010002010000000400000806020000000302030c",
          "envelopeHex": "53545958464d54310001000f000100010001000100660000012900000020000000200010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000f100379eb444bd86b2bd8a124b51796c2ec535459584141443100010001000f0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000f100379eb444bd86b2bd8a124b51796c2ec21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea03000000020330ece9c78d1e27db7c94cdc72bd57edbe623a52005257dedcd0b3525456572d573a55d532fc8109244a5fead6b72abcca9fd813f4e8299158aa4c41",
          "ciphertextDigestHex": "601eb89ddbf9d8e88c79b3fbc90a5963dc12654ec82436f6a9050cdb8e93cf12"
        }
      ],
      "manifest": {
        "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003001000",
        "bytesHex": "535459584d414e3100010000000f0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000110ee198f351dbe0180a4af73689ae1ac1b000100015239f9d2b9622e1bd8c49d76af52fb62dad3f71ef1ade65a2f8a76cd0e5c08460066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030002109720363a357379d720b9c00c1bc9248800020001d049311a7f7638be155721d69cb75938fbcb76183176d6df88a17aa6a6f177f80066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000310bbc71a6764adaedf0ad0b60e7900e40f0003000108c311795ec876b379f21785d1e73373a61306eaf6481264e3067442a5be78080066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000410918b5a723c830e286b7e7a601c0be4ee00040001bfa4368acbeab5f570ecad2abe6cd5c2c04424b6bc9077c0b14df08977b1d7140066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030005100d08b65ec848deeaa20ffe221f6eb86e000500018ac90fb53b76ae5dee442405f96c2bf56f22adcc3b5d6733eb1c3d95db64ae000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000610288c3c165ae84ad0d62462f4170cc2f400060001c4b1ac1ea390931cfa24caa819fec04b9d5ed9f5c40891057dadb27f1bfddd4c0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000710c2f4aa5cd449e6792c5e56aa88a8efd10007000123edd1c3e93c0e2fd3c83f466fa6f5eba763413c2818b3beb753161aa32ea9690066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030008100c2cabad3bd2bc25c861e8dd966936010008000166f9cfa3a1a72c46ab9f4270201c6137102c29df893961986b10d699af52be800066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030009101c283aeb8f841686caa72baea563815600090001497961ad5fb0f156ebfda9c439278e70fc3073b4deb56a7b19aecbf0ae61ee670066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000a100a44f45fe7554cb37189c11267bfc0a3000a0001afaad8eef742f726453b46a01e5250d43ffa8e0fb7deaf1ee0bee3ef82e516b80066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000b105d5da34d3ab5db820dd14711c2e65bcc000b000141c468fe01c7899b04172eddc33e3d1cbd29d477ed2552a30643b4ddd3c0cef90066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000c10e4f3f18409d6e6b39c6727292dfb6498000c0001f335dcbaaa952108ee7e557c25b93e2169cb727d9097ffd882bd59eaf6101afd0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000d106da7814be10eddf3f195f4cf8e959cb9000d000136a8ceab65535e04a9ebbe66badf043a5662f60d83a008e345df711a78abd7460066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000e10e31ad9c06ef304519d8befb2060a3932000e0001bd4b3269e7a6766a48cd224f77defbbfbaaad465e9096793a1dc4ce2cddc5ba90066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000f100379eb444bd86b2bd8a124b51796c2ec000f0001601eb89ddbf9d8e88c79b3fbc90a5963dc12654ec82436f6a9050cdb8e93cf12",
        "plaintextHex": "53545958504c4e31000100100100020100000842535459584d414e3100010000000f0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000110ee198f351dbe0180a4af73689ae1ac1b000100015239f9d2b9622e1bd8c49d76af52fb62dad3f71ef1ade65a2f8a76cd0e5c08460066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030002109720363a357379d720b9c00c1bc9248800020001d049311a7f7638be155721d69cb75938fbcb76183176d6df88a17aa6a6f177f80066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000310bbc71a6764adaedf0ad0b60e7900e40f0003000108c311795ec876b379f21785d1e73373a61306eaf6481264e3067442a5be78080066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000410918b5a723c830e286b7e7a601c0be4ee00040001bfa4368acbeab5f570ecad2abe6cd5c2c04424b6bc9077c0b14df08977b1d7140066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030005100d08b65ec848deeaa20ffe221f6eb86e000500018ac90fb53b76ae5dee442405f96c2bf56f22adcc3b5d6733eb1c3d95db64ae000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000610288c3c165ae84ad0d62462f4170cc2f400060001c4b1ac1ea390931cfa24caa819fec04b9d5ed9f5c40891057dadb27f1bfddd4c0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000710c2f4aa5cd449e6792c5e56aa88a8efd10007000123edd1c3e93c0e2fd3c83f466fa6f5eba763413c2818b3beb753161aa32ea9690066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030008100c2cabad3bd2bc25c861e8dd966936010008000166f9cfa3a1a72c46ab9f4270201c6137102c29df893961986b10d699af52be800066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030009101c283aeb8f841686caa72baea563815600090001497961ad5fb0f156ebfda9c439278e70fc3073b4deb56a7b19aecbf0ae61ee670066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000a100a44f45fe7554cb37189c11267bfc0a3000a0001afaad8eef742f726453b46a01e5250d43ffa8e0fb7deaf1ee0bee3ef82e516b80066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000b105d5da34d3ab5db820dd14711c2e65bcc000b000141c468fe01c7899b04172eddc33e3d1cbd29d477ed2552a30643b4ddd3c0cef90066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000c10e4f3f18409d6e6b39c6727292dfb6498000c0001f335dcbaaa952108ee7e557c25b93e2169cb727d9097ffd882bd59eaf6101afd0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000d106da7814be10eddf3f195f4cf8e959cb9000d000136a8ceab65535e04a9ebbe66badf043a5662f60d83a008e345df711a78abd7460066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000e10e31ad9c06ef304519d8befb2060a3932000e0001bd4b3269e7a6766a48cd224f77defbbfbaaad465e9096793a1dc4ce2cddc5ba90066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000f100379eb444bd86b2bd8a124b51796c2ec000f0001601eb89ddbf9d8e88c79b3fbc90a5963dc12654ec82436f6a9050cdb8e93cf120200000020d658e6fbcaac0bf6f8440b0590f956e57c167d27dfa3658a0f8da1b771548c46",
        "nonceHex": "330f71243e672cbf8e904b0b",
        "aadHex": "53545958414144310001000100100001000100000056535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622000000000000000300100021212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea0300000087b",
        "envelopeHex": "53545958464d54310001001000010001000100010056000001190000087b0000087b0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622000000000000000300100053545958414144310001000100100001000100000056535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622000000000000000300100021212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea0300000087b330f71243e672cbf8e904b0bb3d7cf0e8c4a725ab11638af3be2e8f62e91a81f60c517019678d55bba6d3ce12d23d0fdd3aa041098c45eec3db7fda3378a3dc5c34be2302ef32e47d34858489946b3b8373515ed8f15985bd06c045812667a01af7c0ec739b757430330835894c6a588b7bcf210b789242748f726678180c26661337a91a1b402585d25fcdfc813e9a034309c0ba4ef917b3b13c2cfac4f718061cd8c41647aca3897ee14dbda01c1b8ea11fc90201f459209370263e1e629cc5fdb515980670a283cb7f201ebad114b4ea47b5cc8f6912cd19b97a75edd075d8a8e12774e9d4354974776ae6c8849d27a8bafaf201fd015719ebdef96c6d7680d56874d716c242cfb1f2925caa074575a0f1565a317db14ce015e69030dc46de602a728337f2935131cf9a4b328ed2fd05980f338d7ace2e987e7094b90226f39a953c1fec4baad624b23a3eb20bcda9ab58c160559ee3db2bc768606448638b70c04a51e5e86d652110fd80b8e79e10d61f44bef2ab4af955073741b28d6497e751f123c44576b161463684168a8c33e69a26bddae27d744cfdbc5ac0b28ad89b1fbd4f2e5104691508e326aff05f09d84dbd172a64021db07569d416d64f2a4abc93144d28998f383331ecde7ece7cb2580d8bb5b82a9fa1ab765526f5b11c112ed1f9650ae6ba2e44a516ef4e9c71c9f5db6eb8b572de36bd079ac69ee5ea2bd3718633d90fe7703cdd350af4a4b19a83ddb82d8645331830ee354d15d3e0517ecddc26868b2d6a2b5b3d645bd2809c097335f0d9e0250e79ff310a47870fb017ef74cff7880b8897f0ab4b11062e0619ffa00fd83b40daff17d61798faa2258816a2f52324cd81bcfd34749af4195684366263a4226c721b3e0ca3dfec18dbc800f056847c7599a144b42b1c895c15eed830ceb6b8095deddbb162bcfee132fb1a75e66901fab08eb27a6733f1885bbf238ca2dbba21e02e273f23f44e094ac85ca955e66ff0385d53541488f6a6bc4fee3259b0300cf32f6613be1fe1a33d4bed33be6e91da844a521cf436f26e14e48c2102ea113ab31cd5cca21cd1bd32d21bdaa8f67c181c68595cfe99f625413ed4c60b8862f215c6a757d7b96e436e721e5ebc176116a5173692923a11ec276c553e22c838dfbf22b868c409ae28401af478e0b741ed935530ae84ad159bc0f67956045b61e5dc7214dbdd4fac73a907aaa483f43b9c87d63cf3470dde1db17f493000f592178ac73e8f20d1ed2fda42c07c28c81be552f018d6dd9a5680e55961c6cfd6019be532b22173d97496eeaca9e73c815c522883ce793995160a36ab96d5ce205db223cbe200c969706d82258dfb2657a23cbed29125378786a1a4b8b034f60d708021eedce7e7353069c449b75ae87d2b3474c04f628b38a47b44fa27bd42f63572045bc756d007df33af08e872f1559efdf5c823c21b9b8cca4de0dfd9c9e885220565c7d0c11b9c91a1e9438293e0af77e546a02c623b7ca509002db17fe57d2a211eb6b1e843140f87237b02a55d8a7b774d4a0766ba39c4f236f83e145d71aa9ab7718ecf3cc1cdab35ddf61d761dec11204bbbbcef740b326fa3b319b10c96181d4088b3546396a012a1c6ccd940c0a9b87e9e7aa11b4bb3c4ab039427738e72e82b196367d38ffa442b6b66cb0c4a9856b38b5e3eb3be21d48ca93ca249fd47b4f5eb97e1f77dbb8aa6dc8a9f7620c9aa529d3dcdee8a45f0aab61e6699900ee3e4d72ce5a43f2b7e75802458e9a23e4c58b7a210de9234ca0d48d1fe752bcbba34bab0734ceaf751fbbba83528461a4a39a0be35d114be0e7c7fb973471b1961fcbcacc0052d1092e31a9f42cb977c12f13c542aa97e3902fdb839db033b23d9565a6df2e333e9435d44061ca029b65e2cbe83acc1de0bdae4756dc84b19b9059510c04adaefebcfe4038445ce15a12347ba7ed4b62891caf8c9abbb648c83b2685e5e740dbce6e09490a1870138967850041059bd5187d4f84cf90616e70a6224a48fe6fc30ad76f65e7f80f4bc8245c34452e6cff07e1abbceeb7bd70e1c1d2128a08e03a0e5637f9d57f9ae7db40d4fbee72c6c671c27a8e2e2973117e36207c8c0d012c4960884b203b5651288cddd4e7186c1b1d46c43b6983e4626c9218b23ace49dd7ff04ed3bb00b9252cc248ce890166c1354922c1e465f8efbe1880131b88b0a30d9d4748119a4e9ca59a05569fd58dc418fbd2096fa87c2ecb075b4ea33e95fac6ba97cf6702670012753f2086f25509f4bd74b6ba7aabb3ce0c936161358f664f81f46db61a62c9f1fce6f98228845483489451f6e6efc52e3904a0e745644a950976d2f53889fa73e8a4bac524b9b554aab0c295e46b4e5a82a9d1c63bb01411564e6f41516c9a7d5956f14f3d22afd2abb28a95b5e5bfe76d0c31c3f81bd09ac2900c39a25d7036f0418858981a664c45e189c3399ae2f11b4eade4ee3a75bee1d619bcfd08b2d2dd64c3675fc919404191e1438e87bf5e77f6ee6b6d12b82c6a3e1f6015e03987521eda430e6aadb4f994580436496eacfbcfd3699b02e58786bf2a3fbc793983a049f312e00a6250a7be935e8411d1cfd8f44cd3f1610411df2610d6f1ce57fe38542d75303e8becdee7bdeb06701b966c3802898f8f5421ed556f1be6dd6c059139be57f2f6495bbd6d05a428a9cd28bc8e08f1a1384427e4ff320f20a5e6423295cce9228352f7bfa3c34d0ef20a7eac6cd7b4310823d70e9c7d4fd4d4fd7b9998bfd4689c95c58f944e513960b7642ef5fd4c43e8e3c889756752572f4408dad791d2dc888e8258bd4011cd74059bed586c8fde5c4d33802eb0f168c952f42b31acb541d6b7c6fa02202e13d0bf8c220608e3dfd20737524ba445e35d44086078baeb544e6b664d2967ca2962bc0da03208671e5737628198a001770248fd2ac180f0b06508cb981e4132f03e9e9b172ca3ef365f70146263c4c52a7290dfcbf769f51fdb6d470020eb0ebc8003719848ab378b998aeb5106baa44ac2c8fb80115ef6ecef5c480735b339c4f84abebeedddc0b4f1ecb892577cfd1adff57f94fe0dcf664d7c7e13daf6c06bcb",
        "ciphertextDigestHex": "a414e3733702a1037594525e263cf915c2291dd72c907d44a12bcda941e04ad9"
      },
      "selector": {
        "keyHex": "5354595853454c3100012121212121212121212121212121212121212121212121212121212121212121",
        "selectedGeneration": 2,
        "plaintextHex": "53545958504c4e310001001101000501000000080000000000000002020000002076646f84984b1734d44d341d3d00e4e73b79548c266523e688fc9213fc85a8440300000020d05a12ab95ce67706dc201276ee53a4e2b687d4ef4f3bb7907ec63526460bdbd04000000206dc7d7d3bd9c42ff7115838d25ddf474db5739e42e6dcee7fc8d0578d8b78a64050000000103",
        "nonceHex": "33101c940fcc940bad23cea8",
        "aadHex": "5354595841414431000100010011000100010000002a5354595853454c310001212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea03000000091",
        "envelopeHex": "53545958464d5431000100110001000100010001002a000000ed000000910000009100105354595853454c31000121212121212121212121212121212121212121212121212121212121212121215354595841414431000100010011000100010000002a5354595853454c310001212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea0300000009133101c940fcc940bad23cea8f7ca4528712feae57067b982d492df1f0d095855e92968c93e8801a5b59732b521ed1c91b80c9c7bc474c7a7fcd0538b45acbf714deca808a3c4fbcda4842138cf9a32ea339141f5db6388d2433c7a098c4e78d7308d8109ba5ef77c56a6472bd43de9c9fa0d4244b511acae0f0da3aeb345906ad35d7c57be5a64ea970f44e5cdd2f88d0e76f9d14addb24b699e59281468f0c564f9e8e65530879ea1b6a84f9d"
      },
      "keyedRootHex": "55dce1fbf6ea2065a9b4d80216c98f300bf51da19b6a8c365ec2eb935fd609a2",
      "authorityRule": "candidate generation retained but selector names FMT-KAT-ACTIVE"
    }
  ],
  "ratification": {
    "documentSha256": "MUST_BE_RECORDED_EXTERNALLY_FROM_FINAL_LITERAL_BYTES",
    "evidenceBundleSha256": "MUST_BE_RECORDED_EXTERNALLY_FROM_FINAL_LITERAL_BYTES",
    "ownerActRequired": true,
    "byteChangeInvalidatesReviewAndRatification": true
  }
}
```
<!-- styx-m2-storage-format-json:v1:end -->
