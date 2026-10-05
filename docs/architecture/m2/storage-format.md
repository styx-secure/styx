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

The manifest is a unique unsigned-lexicographic list of every authoritative data-record key, kind, version and ciphertext digest. Canonical tombstones commit required absence. The keyed root covers a generation, manifest key, literal manifest digest and literal manifest bytes. The manifest is itself AEAD protected. The version-3 selector binds the selected generation's manifest-key digest, manifest ciphertext digest and keyed root, and always binds the candidate generation, exact manifest key, manifest-key digest, manifest ciphertext digest and keyed root. `candidateManifestKey` is selector plaintext protected by AEAD; it is never AAD.

A reader accepts authority only from the complete selected set named by the authenticated fixed-locator selector. The candidate is validated as complete immutable evidence and is never authority or a repair source. All candidate locator fields are always present and equal the selected fields when no separate candidate exists. The exact candidate key must parse canonically as kind 16 with the locator's `localContextId`, `candidateGeneration`, and empty object ID; its SHA-256 must equal `candidateManifestKeyDigest`. That point lookup must yield the bound candidate manifest, and its SESSION binding digest must match the candidate's own `BINDING_PROFILE`. If candidate and selected locator facts differ, the state must be `RECONCILIATION_REQUIRED`, the selected generation's `MUTATION_HOLD` must be a tombstone, and the candidate generation's `MUTATION_HOLD` must be present; every other combination fails closed. For an unresolved hold with `resultStatus=INDETERMINATE` while the selector names the old authority, the hold's `parentGeneration` and `parentKeyedRoot` must equal the selector's physical `generation` and `keyedRoot`. This is a physical comparison only. The separate hold-versus-`COMMIT_RESULT` equality of `originalAuthorityDigest` and `originalAuthorityReference` remains the C-MUT logical comparison and is not replaced or reinterpreted. Terminal `COMMITTED` and `NOT_COMMITTED` holds follow C-MUT terminal rules, so their parent is not compared to a selector that has moved. Removal, addition, substitution, duplication, reorder, same-key historical subset, manifest/root mismatch and partial generation reject. Record authentication is not freshness: replay of a complete same-key browser profile, including selector and any coarse surviving anchor, remains undetectable.

## 7. Mutation generations and readback

A mutation writes a complete candidate generation, matching manifest/root, authenticated result evidence and escrow. Authority changes only through one atomic selector replacement. The same replacement that sets `RECONCILIATION_REQUIRED` binds the retained candidate generation, exact manifest key, manifest-key digest, manifest ciphertext digest and keyed root; no second locator, scan or inference is used. An EMPTY-origin hold authenticates the selector under the selected EMPTY authority's pre-session domain while the encrypted exact key locates the SESSION-scoped candidate. Before replacement storage readback is `COMPLETE_OLD`; after replacement it is `COMPLETE_NEW`. While SS memory is retained an uncertainty may additionally be `OLD_PLUS_ONE_IMMUTABLE_HOLD`; a storage-only reader may validate retained candidate evidence named by the selector but never exposes that candidate as authority and must terminally classify authority as old or new before another operation.

A present `MUTATION_HOLD` (still version 2) names its candidate without any plaintext field: the candidate generation is the write generation of the authenticated record key under which the hold is stored, and the candidate manifest key is the canonical kind-16 key with that key's scope, `localContextId`, `secureSessionIdentity` and write generation and empty object ID. When a selector binds the candidate, this derived locator must equal the selector's candidate fields. If the candidate and its hold are durable but the binding selector replacement did not land, the selector still names only the old authority. While SS memory retains that one unresolved hold together with its record key, SS reconciliation may derive the locator and perform one point lookup of the candidate, validate it and its stored hold and `COMMIT_RESULT`, and then change authority only through one atomic selector replacement; no scan or inference is used and a storage-only reader never follows an unbound locator.

An unbound candidate generation is preserved non-authoritative debris. Restore classifies by the selector alone, so one crash with a durable unbound candidate yields `COMPLETE_OLD` and never stops the profile; the candidate is not an orphan generation or `PARTIAL_GENERATION`. A failed binding never discards the candidate, its hold or its escrow; only terminal `NOT_COMMITTED` evidence under C-MUT discards them, and that discard is not cleanup. Its generation number is never reused: a later candidate generation exceeds every generation number present under the locator context, read from a number-only inventory that includes partially staged generations and never locates a candidate or confers authority. No cleanup is authorized here; cleanup is future work under the profile lock, only from ACTIVE, and needs its own amendment.

The seven C-MUT rows and every named crash boundary are copied into section 12. `COMMITTED` selects complete new authority, terminal `NOT_COMMITTED` keeps complete old authority, and `INDETERMINATE` keeps old authority plus one immutable hold. No partial candidate is authoritative and security-sensitive output is read from authenticated escrow, never regenerated.

## 8. KeyPackage and binding facts

The KeyPackage record binds public bytes, all private components, opaque local reference, canonical MLS KeyPackageRef mapping, context/profile, lifecycle and `invalidPending` as one non-aliasable unit. `UNCONSUMED`, `RESERVED`, `CONSUMED` and `INVALID` restore exactly. `invalidPending=true` is valid only with `RESERVED`; parsing alone cannot make uncertainty retryable.

Slot registration, issuance-held candidate, issuance outcome, reservation, invalidation and the latch are covered by the same complete generation manifest/root and selector update. This is a physical grouping of already ratified facts, not a new transaction or disposition.

## 9. Escrow and result evidence

Escrow is bound to one operation identity, candidate, mutation-set digest, output kind and authenticated result. Only C-MUT authorizes release. Clearing a response hold never erases evidence needed to classify an interrupted prior generation. Forged, stale, cross-domain or mismatched result/escrow association rejects.

## 10. Literal generations and conformance

Section 12 contains six same-profile vectors: EMPTY with one UNCONSUMED KeyPackage identity and tombstoned session facts; ACTIVE after an output-producing commit; a RECONCILIATION_REQUIRED candidate after `INDETERMINATE` whose fixed selector still names ACTIVE; an EMPTY-origin `INDETERMINATE` hold whose selector is pre-session but whose exact candidate manifest key is SESSION-scoped; and two retained unbound holds, from ACTIVE and from EMPTY, whose fixed selector is byte-identical to the parent's own and whose candidate is reachable only through the locator derived from the retained hold record key. Each publishes every key, nonce, AAD, plaintext, envelope, ciphertext digest, manifest, selector and keyed root. Negative cases include candidate-key mismatch, candidate-parent mismatch, and candidate manifest-key scope/session substitution.

The external validator independently extracts the closed record, implements two encoders without shared encoder code, reproduces every literal byte, decrypts and re-encodes byte-identically, recomputes all digests and roots, executes every negative class, sabotages each kind/component/label/version/leaf/selector, and exercises seven rows × three outcomes × every C-MUT crash boundary. Any skip or unexpected acceptance fails.

## 11. Limits and rollback

This format proves post-unlock record authenticity and complete-generation consistency only. It does not prove freshness, coherent profile rollback prevention, IndexedDB atomicity, implementation correctness, entropy quality, constant time, worker confinement, physical deletion, JavaScript zeroization, disposal completion or restore compatibility. Rollback of this card is removal of this file; it creates no persisted M2 bytes or migration.

## 12. Normative machine-readable record

<!-- styx-m2-storage-format-json:v1:start -->
```json
{
  "schema": "styx-m2-authenticated-storage-format/v3",
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
    "holdLocatorRule": "MUTATION_HOLD stays version 2 and carries no locator field; the locator of a present hold is derived from the authenticated canonical record key under which that kind-13 record is stored: the candidate generation is that key writeGeneration, and the candidate manifest key is the canonical kind-16 record key with the same scope, localContextId, secureSessionIdentity and writeGeneration and empty objectId; the record key is authenticated by the record AAD, so the derivation needs no plaintext field and no inference; when a selector binds the candidate, the derived generation and manifest key MUST equal the selector candidateGeneration and candidateManifestKey and the SHA-256 of the derived key MUST equal candidateManifestKeyDigest; the derived manifest key MUST be the located candidate manifest key and the located candidate manifest binding digest MUST match that generation own BINDING_PROFILE; a hold stored under any other generation, kind, scope, context or session than its candidate rejects; the fixed selector's authority generation MUST NOT carry a present unresolved hold, except through the one atomic GENERATION_SELECTOR replacement of retainedHoldLookup, which resolves that candidate hold with a tombstone in the same durable write",
    "retainedHoldLookup": "only SS reconciliation of the one unresolved hold retained in SS memory, whether AP reaches it through RECONCILE_INDETERMINATE or SS acts on retained internal reconciliation evidence under C-MUT, while the fixed selector names the hold parent as authority without binding a candidate, MAY derive the candidate generation and exact manifest key from the retained hold record key under holdLocatorRule and perform one point lookup of that manifest and the records it lists; SS memory retains the hold together with the record key under which it was written; no scan, enumeration, counter comparison or inference is permitted to locate the candidate, no second fixed locator exists, and the lookup confers no authority; the located generation MUST validate as complete, MUST store its MUTATION_HOLD under exactly the retained record key, that stored hold MUST equal the retained hold, its parentGeneration and parentKeyedRoot MUST equal the selector generation and keyedRoot, and its COMMIT_RESULT MUST satisfy originalAuthorityMatch; any mismatch rejects with the hold unchanged; authority then changes only through one atomic GENERATION_SELECTOR replacement under C-MUT terminal rules; a storage-only reader never derives or follows a hold locator that the selector does not bind",
    "unboundCandidate": "a candidate generation that no selector binds, including one left with a present MUTATION_HOLD after the binding selector replacement did not land and SS memory was lost, is preserved non-authoritative debris: restore classifies by the selector alone, so a single crash yields COMPLETE_OLD under C-MUT crashBoundaries and section 8; the unbound candidate is not an orphan generation and not PARTIAL_GENERATION, never stops the profile, and is not authority, evidence for another mutation or a repair source; it becomes authority only if SS reconciliation of its own retained hold under retainedHoldLookup selects it through the one atomic GENERATION_SELECTOR replacement; a failed or impossible binding never discards the candidate, its hold or its escrow, and only terminal NOT_COMMITTED evidence under C-MUT discards them, which is not cleanup; its generation number is never reused: a later candidate generation MUST exceed every generation number present under the locator context, read from a number-only inventory of every generation with any stored artifact, complete or partially staged; that inventory read chooses only a number, never locates a candidate and never confers authority; no cleanup of it is authorized by this format; cleanup is future work under the profile lock, only from ACTIVE, and requires its own amendment",
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
    "FORGED_RESULT_ESCROW_ASSOCIATION",
    "CANDIDATE_FIELDS_DIFFER_WITHOUT_RECONCILIATION_REQUIRED",
    "RECONCILIATION_REQUIRED_CANDIDATE_MISSING_OR_MISMATCHED",
    "RECONCILIATION_REQUIRED_CANDIDATE_EQUALS_SELECTED",
    "CANDIDATE_MANIFEST_KEY_MISMATCH",
    "CANDIDATE_PARENT_MISMATCH",
    "CANDIDATE_MANIFEST_KEY_SCOPE_SESSION_SUBSTITUTION",
    "HOLD_LOCATOR_DERIVATION_MISMATCH",
    "HOLD_LOCATOR_SCOPE_SESSION_SUBSTITUTION",
    "HOLD_LOCATOR_ON_NON_CANDIDATE_HOLD",
    "HOLD_LOCATOR_GENERATION_MISMATCH",
    "UNBOUND_CANDIDATE_GENERATION_REUSE"
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
          "aadHex": "535459584141443100010001000d0002000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000d106da7814be10eddf3f195f4cf8e959cb921212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f",
          "plaintextHex": "53545958504c4e310001000d000000",
          "envelopeHex": "53545958464d54310001000d00020001000100010046000000c90000000f0000000f0010535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000d106da7814be10eddf3f195f4cf8e959cb9535459584141443100010001000d0002000100000046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000d106da7814be10eddf3f195f4cf8e959cb921212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000000f110c99efd98599b82de3102cdae169dce031bd15ffe8da471d113e3b1a45e094d3674f1994263cd3ecb447",
          "ciphertextDigestHex": "a467e024445524b3c450e7153247f950eaa4a66468de93617c99bbd933d62e91"
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
        "bytesHex": "535459584d414e3100010000000f0046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000110ee198f351dbe0180a4af73689ae1ac1b00010001a653d691ce131cf9dc026048decfef054003cc05a1c4677bd189d7a97debf9030046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010002109720363a357379d720b9c00c1bc9248800020001f43a67916c208a5b063d9133627c28c7fc4a49657ae8ac047614db3efecb802f0046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000310bbc71a6764adaedf0ad0b60e7900e40f00030001a1fed9c4aa02356d93435115a226079b0ac599e86e0e68149f1284756557d9880046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000410918b5a723c830e286b7e7a601c0be4ee00040001a9f5a91630fea4012d1e43511db46a4a93ba22582f54d1d9cc4fe3100b69efad0046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010005100d08b65ec848deeaa20ffe221f6eb86e000500017420c38b7274b0c1f4844ececca5fab1976d24956ba6a948d6e3bef57ea744d80046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000610288c3c165ae84ad0d62462f4170cc2f4000600016854271081ff52f62d1a0237a9440d0d244053d05f1ec777f33b408e3d4331970046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000710c2f4aa5cd449e6792c5e56aa88a8efd10007000131e36681ce641369694b74ebf5c1cd4a418407c5101c5866c82420fe6033e4240046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010008100c2cabad3bd2bc25c861e8dd9669360100080001704b8aaecda4734caa6ab9320232b5894df8f7304c2d935e143d73e3a7f3560d0046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010009101c283aeb8f841686caa72baea563815600090001758c03f6c1552f7d0c9768737afe93d76dee4a1f559e007daf8df281c504a8790046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000a100a44f45fe7554cb37189c11267bfc0a3000a00010d33869f65f16b8dd5d76f90a7d1e2c8fab464f0a6a726c312e6c60ebc531d3c0046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000b105d5da34d3ab5db820dd14711c2e65bcc000b000102854e7d7a9d94a98d1e9c131fad98608c3f4420bf5db6b26ce49cd7800be09e0046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000c10e4f3f18409d6e6b39c6727292dfb6498000c000198b77e29a16f78d5211ab33f7a71076867ed9666a8974dbf9c9b6ff6a099f7300046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000d106da7814be10eddf3f195f4cf8e959cb9000d0002a467e024445524b3c450e7153247f950eaa4a66468de93617c99bbd933d62e910046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000e10e31ad9c06ef304519d8befb2060a3932000e00011411af23ec3781491218eccc9b391808e7edcc35ff7ad4014deae496a49a245c0046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000f100379eb444bd86b2bd8a124b51796c2ec000f000160b92d5e8933bbcd82cf4c0482758379b1044160c72e952056ccd9f1604bef43",
        "plaintextHex": "53545958504c4e31000100100100020100000662535459584d414e3100010000000f0046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000110ee198f351dbe0180a4af73689ae1ac1b00010001a653d691ce131cf9dc026048decfef054003cc05a1c4677bd189d7a97debf9030046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010002109720363a357379d720b9c00c1bc9248800020001f43a67916c208a5b063d9133627c28c7fc4a49657ae8ac047614db3efecb802f0046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000310bbc71a6764adaedf0ad0b60e7900e40f00030001a1fed9c4aa02356d93435115a226079b0ac599e86e0e68149f1284756557d9880046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000410918b5a723c830e286b7e7a601c0be4ee00040001a9f5a91630fea4012d1e43511db46a4a93ba22582f54d1d9cc4fe3100b69efad0046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010005100d08b65ec848deeaa20ffe221f6eb86e000500017420c38b7274b0c1f4844ececca5fab1976d24956ba6a948d6e3bef57ea744d80046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000610288c3c165ae84ad0d62462f4170cc2f4000600016854271081ff52f62d1a0237a9440d0d244053d05f1ec777f33b408e3d4331970046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000710c2f4aa5cd449e6792c5e56aa88a8efd10007000131e36681ce641369694b74ebf5c1cd4a418407c5101c5866c82420fe6033e4240046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010008100c2cabad3bd2bc25c861e8dd9669360100080001704b8aaecda4734caa6ab9320232b5894df8f7304c2d935e143d73e3a7f3560d0046535459584b455931000101212121212121212121212121212121212121212121212121212121212121212100000000000000010009101c283aeb8f841686caa72baea563815600090001758c03f6c1552f7d0c9768737afe93d76dee4a1f559e007daf8df281c504a8790046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000a100a44f45fe7554cb37189c11267bfc0a3000a00010d33869f65f16b8dd5d76f90a7d1e2c8fab464f0a6a726c312e6c60ebc531d3c0046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000b105d5da34d3ab5db820dd14711c2e65bcc000b000102854e7d7a9d94a98d1e9c131fad98608c3f4420bf5db6b26ce49cd7800be09e0046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000c10e4f3f18409d6e6b39c6727292dfb6498000c000198b77e29a16f78d5211ab33f7a71076867ed9666a8974dbf9c9b6ff6a099f7300046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000d106da7814be10eddf3f195f4cf8e959cb9000d0002a467e024445524b3c450e7153247f950eaa4a66468de93617c99bbd933d62e910046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000e10e31ad9c06ef304519d8befb2060a3932000e00011411af23ec3781491218eccc9b391808e7edcc35ff7ad4014deae496a49a245c0046535459584b45593100010121212121212121212121212121212121212121212121212121212121212121210000000000000001000f100379eb444bd86b2bd8a124b51796c2ec000f000160b92d5e8933bbcd82cf4c0482758379b1044160c72e952056ccd9f1604bef430200000020f2e5536ce6a5a7a37971a828805fb9c377e541dd2804713512cd11ff7a83332e",
        "nonceHex": "110fd56a50240fd04dcdab1b",
        "aadHex": "53545958414144310001000100100001000100000036535459584b4559310001012121212121212121212121212121212121212121212121212121212121212121000000000000000100100021212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000069b",
        "envelopeHex": "53545958464d54310001001000010001000100010036000000b90000069b0000069b0010535459584b4559310001012121212121212121212121212121212121212121212121212121212121212121000000000000000100100053545958414144310001000100100001000100000036535459584b4559310001012121212121212121212121212121212121212121212121212121212121212121000000000000000100100021212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000069b110fd56a50240fd04dcdab1baf8d131633e20764d8161ee6a25199389db9da1c164f9d13e0d08442f96ef61ec2b43089a7e87a3baaa64a24c945fe0cde2c04ec7274d285975234c0a5690343492e42bb49f82b485c215bc4b20638802d2acdd936dc682f54da20fe7537346dfa9f5a63b0587c1101fb5127cfd834868f378ec664298194290d22e75f4a7fa1409ef917018202920c0587623f478be9afd4524b7da1addba1c7ac357dd1c584b48805151eff249778d09d96719cc6da56be375776d69fedfd21151ebf9fdd99789791de2fb612199f93ab02d8eb0ce4f8a2b989e4ec4a2c9ea40ae05508f8c6c8855eaff41b6e4eb82783c6fb0213cb4f78163b6e45188719da076ab707ed72e0b60c81b92a809dbaa6cc73dfd756f02670a0ba4f550e61ac8e245f0a40d94eb77e6f5b1696e5b507d23ad824ff879acb05e41b9faf2b913d08d8fc313c6541e7d26b16b5cfef817c1ec593a98106cc23d498dabda23fff016d5d9723af6cc903747c47aced6a006d3af87cd7ad7ed0c391e6602136c8e23fb73f70d062a3e79818dfa8e11d89204d68acaed10d6510e911f1aef080cac88f58fe769398e42eb55c1a46a71730fe6e05005abb3c9787f160916790e7bc54c97c5d991115da8a18f7113d4685b00c261a2e3818e05c98f822db21b8587d4977b0f1a81b0ff936b038b7989855d2bd08f9b6e36ef33f37a97e4a5b7d53343471cf1f883364d1cc24d4165a6720a1aa1f6989ebaafd6af71f87c7c172c9353a579cf1e94664e21ef8a3b835a160634d47c00b079df15187927b70074137443796a068822c8edd1bc3ae0f1c3069e826b9b30132180ab1e2daf0c1df938e7f8413a7be70cdb799e34924ffd72ab523b524f9eef4cb45770b9f6b12e439333bd77e22485df5dabf91cb6ef1b9eea675265a6d33c11f0f474df0a42388f4c3ee7a2c127fad20ff9a02e3b24303b283ee87d2118cdfe208194a1dbe420594430edf5fb458584889e7a11e9270a7cd286a2b9fc5cbf2b5eb3279feab5e6abd294f81783b0b946d7680823944df0e6e3c102f47f1adce4aa0e2d6f1cea7f3d0c8d458d072a4b98fa67702d74105283ecd21d33a63aad552222ff13fb82b6560d54a638b2862f72c623c118ea041633849454b8e22c7a44e400790432caf1378f40d7127c0116f70e3e766fe196477bf7e2832040712b21c71fedd24f201a8dc3d105a278f0a19ab5441db1945c855caf0dc7a9d649a0e5b43cc9e36d138b42cb1ff79e2d7c8202bec4d4d52efbf4efdb82bd30ef51beb286e3f9561fc1e45d1efb80f3a9916bda648d79d2421d81d66ece4d341eb12340c3ae978075e6ae67446af9873995dfa458f92625edcf6b0383406d8e2e56bbdf77bc0dd2bfac2f09801987d2ff514e91fbb237aa9de6a1e42238a5bcf992d8647ad016c8394235e7971110095aef9ee3388b312ab044fa3b134378058efa8e4bd5b12c68024dccaeb39a9b6dbcb655013e8391a2a10c78287fff5a570df15f186696dd5be8db5572a4835ced0239e1414573e689ecaab047447a7b25fb627eca3a2ade659f785dc3d53d66fd324163330a9f7ba17d0fbf55d4234c783bc95391c817b154e47713aa88e473a384170c3cb3ffcfc0179efae739c1c30bdc2b7aba2406cf64166c85431f33f835c16e02d4b559c33b53629608cf7340fccd5a4309521a2181aa51f11838f79e401d5ed4ddafbb2f938f9a8f28b2bed14aff661199541b3deac5a6383b530e10c5e30b2f6b7b7612a37d29c5b56d76a403dd819302edddf3c1088e07f50cee6d95f5ab6786ea79bf38852280cc1e3b9a174fd8124113ae8ec370c17c24eb412554df538bfbede351c9037b9b58042f967ec4c2d9dd7e9ff5ca02861ebb1748d80c1a73bd4572f38b10a7f834a5000d545096ec164157be4d0f60ca219145f5c2c2f655ec934c7690f033df3e33a9c4283b1be2a0d200070d3802f2fe2ad2820ec1848fda53cf8281dcab7058a13c0b9fe827aa64341a17376ae2b0091efc607e37300077c152a019f41d2adf0b8b7cb4f790ac402ac0fbad9722c8cd2f9fb35168d4484fc47418d9a3a0349150d4530fce1d4fb263ef3815102d2e26b8f43f9d5b03c014fbcef1856b54712d0925ea95176592908cad03ab340d0a1af04a92b295af18aa0d253db6e1fb735c2428a8e485227f981acac88db086d6783e9ee8cc2af0a1cf02eb2d3f3cf40b8166c4d9f3b1eaf495c0880ac55328bc8cc79299cdeb474df8efa0d2440b504541207c1dbb994299ef971da0f755a72492c4fcdcf59c23fee62db0eb4442c8f7e1c85cb8c984f6fa54d398eecc4e0a4328f3469ed1fb025f73149e54d9fb8cc3aa426b411ce58cae6db3fda19e49d6c00442d90e4a8e5aea22563ae8b0aec798a04a49ea3ede0279f",
        "ciphertextDigestHex": "318a13dc612ff8694d7888095c584d467bc0009a12d5a70110f381cdf4b0a8b0"
      },
      "selector": {
        "keyHex": "5354595853454c3100012121212121212121212121212121212121212121212121212121212121212121",
        "selectedGeneration": 1,
        "candidateGeneration": 1,
        "plaintextHex": "53545958504c4e310001001101000a0100000008000000000000000102000000205d8a18f17b63545d548a371c997ba493eb942ff5b18bf7c83927491144790e440300000020318a13dc612ff8694d7888095c584d467bc0009a12d5a70110f381cdf4b0a8b0040000002040d640a0b1c1063b970d8ddea9fc5477648f16830f301f4a920027f9e162496e050000000101060000000800000000000000010700000036535459584b4559310001012121212121212121212121212121212121212121212121212121212121212121000000000000000100100008000000205d8a18f17b63545d548a371c997ba493eb942ff5b18bf7c83927491144790e440900000020318a13dc612ff8694d7888095c584d467bc0009a12d5a70110f381cdf4b0a8b00a0000002040d640a0b1c1063b970d8ddea9fc5477648f16830f301f4a920027f9e162496e",
        "nonceHex": "11102e902116f6552d6773f1",
        "aadHex": "5354595841414431000100010011000300010000002a5354595853454c310001212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c00000148",
        "envelopeHex": "53545958464d5431000100110003000100010001002a000000ad000001480000014800105354595853454c31000121212121212121212121212121212121212121212121212121212121212121215354595841414431000100010011000300010000002a5354595853454c310001212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000014811102e902116f6552d6773f178cb9633065492ee033bdee9eb44f654ac64165dfedc2a32e3c229a79fa405efd48bf998ec40994fe236d14a70150bcfcf2e69eb23277b611d831c53427d9f752a49732ef009194a50f9be50b0924becab39fcca28860e9c1496ff534ebb11beb19a006585502b27e05d04366995d16d45e0fa31932a13499f971f71a6e368c92449bffab0265b9129a0c7f5707700760f98e5db99a8fc8f85ac402b947e004c95e31f5a2ab1d4f157e8b3afd7bf540a5fc3821fef93d24f0074c1d4869b8aece018a70e6501f731782298d20c8eb67c4521a21b8a301bc392fe10dc9237e877126a25587364c83bd97d603932ba245248c60b397fdf25945ace9f24ae335661e204d02536cbc70067de8b819b9bf2fcd8386fce0e92cb92dd71936ea31248404e7ada0fdc65fc7b4aff07e263230b53aed77e68607ba31ada85049812a76bcc8ca4f8381f8ec533bf0ab1beaa129d78bb1082ab8b9506f4"
      },
      "keyedRootHex": "40d640a0b1c1063b970d8ddea9fc5477648f16830f301f4a920027f9e162496e",
      "authorityRule": "selector names this generation and repeats it as the candidate binding"
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
          "aadHex": "535459584141443100010001000d0002000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000d106da7814be10eddf3f195f4cf8e959cb921212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000000f",
          "plaintextHex": "53545958504c4e310001000d000000",
          "envelopeHex": "53545958464d54310001000d00020001000100010066000001290000000f0000000f0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000d106da7814be10eddf3f195f4cf8e959cb9535459584141443100010001000d0002000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000d106da7814be10eddf3f195f4cf8e959cb921212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000000f220c99d3ab38e86d2b6b45778869ec1775c2f909a5de2b906997ee6d61c3385f2a0e4f5c2e7161b966ae17",
          "ciphertextDigestHex": "9df8824cb9779cf1a98e7807078c5cc971573bff071707cecb7a7ab797fe0039"
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
        "bytesHex": "535459584d414e3100010000000f0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000110ee198f351dbe0180a4af73689ae1ac1b00010001404ef2cd2228509c5d92b5e5546e8178e789d2d088f6bd22d96863c5be7037a70066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020002109720363a357379d720b9c00c1bc924880002000161dd04525dc19b487a935aed159c403de436266743bd6ffaf95e5a6af2cbffed0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000310bbc71a6764adaedf0ad0b60e7900e40f000300018ee456b434914d9a08cab6011f8474204ba3f7de5fa5789e4159790c73bfe3720066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000410918b5a723c830e286b7e7a601c0be4ee000400010740fd41d0594ef1930924e7d3301346c056bf6c8038adb1b7cb004f8be84cef0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020005100d08b65ec848deeaa20ffe221f6eb86e000500011feedb95836dad5dace9ec67e7ef270d2ee25e47c8ad53878c57a70cc05bcf7d0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000610288c3c165ae84ad0d62462f4170cc2f40006000165740f5c416a9612a3a1c9c7cf3e41b6e753969b639e06274eee84e9b7e7aafe0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000710c2f4aa5cd449e6792c5e56aa88a8efd1000700011590ef91070fba331ab92a6d346b4cee0c06846f8215899bff3fcde47c85ae7c0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020008100c2cabad3bd2bc25c861e8dd966936010008000106303ff00007ec28e61e61a117e55621acf3a9c597144489c6b48b294bdc3dcc0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020009101c283aeb8f841686caa72baea563815600090001fcdda5925acc9da03b331d428b59e2f8a0f88beddf228fe137147b4aef5b150c0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000a100a44f45fe7554cb37189c11267bfc0a3000a00011711f5ab6e424d2160ed491a38f69e4a384f7fefa6daaf47759806c437eb85390066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000b105d5da34d3ab5db820dd14711c2e65bcc000b0001e974d1311eb7b51ff678bd05632852ed03f98ef900f7e7477006150937bee19d0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000c10e4f3f18409d6e6b39c6727292dfb6498000c0001b9615ff4d13bf53866e60db171c77ecccda0d97500d3fc3000d2d61dde4544740066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000d106da7814be10eddf3f195f4cf8e959cb9000d00029df8824cb9779cf1a98e7807078c5cc971573bff071707cecb7a7ab797fe00390066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000e10e31ad9c06ef304519d8befb2060a3932000e00010621f569c8721a875493349f5d4465813854dde884ef91654ede32b7245b1c210066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000f100379eb444bd86b2bd8a124b51796c2ec000f0001899ffc64629916fa24d81907c4536a89ea7114830d7f04e5775d74856469c439",
        "plaintextHex": "53545958504c4e31000100100100020100000842535459584d414e3100010000000f0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000110ee198f351dbe0180a4af73689ae1ac1b00010001404ef2cd2228509c5d92b5e5546e8178e789d2d088f6bd22d96863c5be7037a70066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020002109720363a357379d720b9c00c1bc924880002000161dd04525dc19b487a935aed159c403de436266743bd6ffaf95e5a6af2cbffed0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000310bbc71a6764adaedf0ad0b60e7900e40f000300018ee456b434914d9a08cab6011f8474204ba3f7de5fa5789e4159790c73bfe3720066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000410918b5a723c830e286b7e7a601c0be4ee000400010740fd41d0594ef1930924e7d3301346c056bf6c8038adb1b7cb004f8be84cef0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020005100d08b65ec848deeaa20ffe221f6eb86e000500011feedb95836dad5dace9ec67e7ef270d2ee25e47c8ad53878c57a70cc05bcf7d0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000610288c3c165ae84ad0d62462f4170cc2f40006000165740f5c416a9612a3a1c9c7cf3e41b6e753969b639e06274eee84e9b7e7aafe0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000710c2f4aa5cd449e6792c5e56aa88a8efd1000700011590ef91070fba331ab92a6d346b4cee0c06846f8215899bff3fcde47c85ae7c0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020008100c2cabad3bd2bc25c861e8dd966936010008000106303ff00007ec28e61e61a117e55621acf3a9c597144489c6b48b294bdc3dcc0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000020009101c283aeb8f841686caa72baea563815600090001fcdda5925acc9da03b331d428b59e2f8a0f88beddf228fe137147b4aef5b150c0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000a100a44f45fe7554cb37189c11267bfc0a3000a00011711f5ab6e424d2160ed491a38f69e4a384f7fefa6daaf47759806c437eb85390066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000b105d5da34d3ab5db820dd14711c2e65bcc000b0001e974d1311eb7b51ff678bd05632852ed03f98ef900f7e7477006150937bee19d0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000c10e4f3f18409d6e6b39c6727292dfb6498000c0001b9615ff4d13bf53866e60db171c77ecccda0d97500d3fc3000d2d61dde4544740066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000d106da7814be10eddf3f195f4cf8e959cb9000d00029df8824cb9779cf1a98e7807078c5cc971573bff071707cecb7a7ab797fe00390066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000e10e31ad9c06ef304519d8befb2060a3932000e00010621f569c8721a875493349f5d4465813854dde884ef91654ede32b7245b1c210066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002000f100379eb444bd86b2bd8a124b51796c2ec000f0001899ffc64629916fa24d81907c4536a89ea7114830d7f04e5775d74856469c4390200000020024a33360625df948700c82bd7fa71547bb772dbe5dbe00bf1808cd41f0d85a3",
        "nonceHex": "220f3e33a20abe7bea4dc1e9",
        "aadHex": "53545958414144310001000100100001000100000056535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622000000000000000200100021212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000087b",
        "envelopeHex": "53545958464d54310001001000010001000100010056000001190000087b0000087b0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622000000000000000200100053545958414144310001000100100001000100000056535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622000000000000000200100021212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000087b220f3e33a20abe7bea4dc1e9eff731890a79fead19c3ca1f9fe15c47401e048e765126287a84000c219c19c94c75ea672a6dce29b19c45bf45b32cba3b333b3608f74baa3eb37b53c578e523972334a5d4c5ca189268252a484ee1826a157f9a1d8fbf57d41f333240c670701c35e34a9dc12a679ac3621d68d3f7cd3c2a94fafc1106995d4ccf58dc6b118b8f35f205e19e7e536e9fbd68470a8addb99432f077a75fd8723255feab2f641bed2d8cb746dcffbc3bb538048bae59d1e5ea304a33fb979997784ebb317c38ca2a72c6ae4a89aa9d67a5681c81f457cbf2d2fee526a27b3171f5e28829061da472e794ceae5655f903649a17ab70b7856daa9bc2e926f20048ad9e0850f0f3eb95995c7941a968084a0ddfd1049e1e60cd7602d0debd582ce3887814a2a5fd7b2166e9fc11c550be3951eac4be759e2a1594b09c4183c5c99b57eaa6aa001630ec99c5f149b70c15fe983c95e057bb7f1abeb85f6889c9ac4329b686f07c6e940fa04a5039478e10e072c920a9fe8d2f8b10fca9839e6029a3a61dff1a2080f4a855a2253ad0fd76cb36626e2de4dbfa8712a76511c5657fec31f79b901050b70a372bf9626285adfac6c0053ad405e82e69e29aaf3efc646b3562d3f03eff2733da5d5704e366d5a4ecbcc293d476ca3b75f9bbd018bef2acbcbd7a05b7f9e34f4ddc0e529ec6f146bc9ef413bc7c050b238b6c3592471a0c054139b4555996d33d03e8c1422c0869da3253b5d328963a6f5cbfa48ae025de9d80c4eb06a254d744142a791c91f4c7619b9292401adde8edf34cf07602692e4bf9fefcd788a0e697a51dcb89fd7273bb5cda984308584c176c2d6b7bab1425d5cc01e09962149db333f3e0907712ee203977a2b779a6d52114fdfb4885f3d5584e9132a922b8b9b15c211df4e03d8647218ca3156717b10498bcd93491145cb63cf76dfd3637ed0151ee2b3ce35c64358e0b408b1937a6cccc3b2b1c9cc08200bdbed274a58ad942a8e48123bd2d122ab2dfd9c8f9aa27f9f1246ebcd82a27238890430fe3ec1828bab37239a6c5da4f3e0bd282d67e3984e2522cdf182171a01510f9542e09c21a28654448f1b65a554c965da3c0b2f60e084cb1f2adc6ea791d59e27d2048db068cd6f35ca58e5a84914bf89ec86ea8efeb45ff207c1b62fba5b1f507b474351f4dd04d4e192891488b9cd1e732b5c36ad938a6cfc1023e6038ebb55433b6a867076bc17aad25b4f4fc58f89fc576b5be993cfb06f0ba746334b43159a6842ecfff6e088382daf098a7bf25a6d87a36837e900df147aa70e12f3b75e18ad6993bcf839d19c21344fb561a31bf9874f34002a3493dabc3334d8032385ddb86e4a6d99fd7f73b3830b1910f6c22d86f712325f880a694a0e9a3defe7e3ba70124d6666323a001a0cfbf1edebfa1bd9d60394ef9193b7f6a52e2c28a0bbe3cfd98077cbc67592c1068949b9092cad2a29a12e61e4f5aa4de3cca4ad337803da082be304202a7531ce9a9e7c2427aa9a547b71d32a927ea4bdb844cd6aa2f8786b5bca2147ba302f7af7fa450bdf8f27b1565ba50291873ee7b6783204dd39095aaa857d74e805ce8ba858a9b4b8f757f8451554477e1c95af12c3919c5f45ff71da6eb751b4d5ed602cfd58de9ff55540d2b97c97e737be48d7cef6c6e9e8bc4417dda34005844706f578a81cce3edcc8d7f593076a1957eb67ea85ee3e887f7d97d79a7780489a2cdfadbf3dc4b4f181bd3ef047ab646c3d6469cb41abe58f03383c1c0556d19371534d11d7864ceec6f1da7892a54a5f3fa9677de3cf7c89fdc141faf7e197387935f5672b26b7f2b46937b84652e52c2c4197d99735d529a2b2a58cbf9f6fd0082a6e3c6bff5f35c51a03cf5cc0ae8c6dde9303d9a4f8bd98d952b159c3b79f6a60c4603c08636f234965bf8d441e8f94dc2947fbc38d23bf5b66f58276196347c85feb2073a4219a657b949541e945e8830d7adf281a2126de20a94f7b202081f7be90b9255c862f6a26c721c3e379ab98f895350f4db211ebd1eaaa694596b43123e1a126627b37673ff221e68aeb2847a0c3b012206f11a1ef62ebd2b71f4b02354a0f6c3713eab0e8ac53ec5792fc2da1a5c8f36558e84016ea31fff40436c6a902a6ec46bdf6aa2f6678fd13ac91cab49f1b4f7c68942770fbaa19c91b90930d8835e75afce4f86da71dce5837c84e7141cf9a48eaf5604e402e6a93209d32ae451df89e2e17bdd11e87b5d496e5d92d3f5373f164a5fa5b6eb02e13dfaa3f83bc798665655ca78c8c97dab4b4d0e8358e20cc08b0afe75c76dbc3544801801f6a8faf0c3a1f85e700c90710343a3fe0cfeb5dd49a78b3399ee524c5125cb82fc4bdbdd134d3583bd233ff04606ca4a3bb7fe8270a14a881b53e1da0c868adfdb0ff2383ada6889948e42b1c211bd7597a09e778479e7f00b5a6bf5e1148871f339b53c23c7cdfc19164701290f39f34ecb0c52b5696dabe47438d52d4f07284854d29422588e872537670ac819b9dbee9449164281732bd89c375084e986b5c19dc7c48534a10add95eea6793047caa0c6b0702e9a733e8eb5fd1483454958be7b43e5cc6bdf7c8ebb749f86f1816bc4e02c8c6f4f52c0612bc59194784b5f6d1421d0b2638b1ffb485423e2d352448489ce56b3c55ab3f90ecb66b0e0adc5c81328df93408b87b10ca4ec8436f42f31463748abcb789cd7ace13a587b5f8bec47dcba1d4522f9b3463971f38c4b301be207f93327fda773ece720fe9023fd7fa54f1070e12ce234c579958c3dcd2cbb15216c4dc3cdf3f3ce1781d4dddcb5989834463e000daef3a73f9b75617026a4e7465a2448d6669c86ac6b686cb908801e7248951da4035f0441899609b8d64568e4a85648f65af60f58e243ff2a6161b3bc979f0d85dfb767c7db5728c3a2b657cec8cdee3a7ce8a3865e7305205d4dafe24241de9dcea0de94d77e86cb28d6f4258b8a3ff190043d5ec6b79955ef0b5726697db740d525ab2a7d8958eb5d08717c2c1b98d0329bf2f7a3e2b3e1ffa2db3ac54f6d4878fe835c3ecced8124357eb01648de7a340ecff224bbe787df71",
        "ciphertextDigestHex": "1f3931b4f560fd3240d53f6e5a5bc59107f0d0d0feac8a0696ad78af0a7c864e"
      },
      "selector": {
        "keyHex": "5354595853454c3100012121212121212121212121212121212121212121212121212121212121212121",
        "selectedGeneration": 2,
        "candidateGeneration": 2,
        "plaintextHex": "53545958504c4e310001001101000a01000000080000000000000002020000002076646f84984b1734d44d341d3d00e4e73b79548c266523e688fc9213fc85a84403000000201f3931b4f560fd3240d53f6e5a5bc59107f0d0d0feac8a0696ad78af0a7c864e040000002000a83a64c4dc96a0d74e76e093ffd5c09c31819d017fcae2796cb23ce2441075050000000102060000000800000000000000020700000056535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002001000080000002076646f84984b1734d44d341d3d00e4e73b79548c266523e688fc9213fc85a84409000000201f3931b4f560fd3240d53f6e5a5bc59107f0d0d0feac8a0696ad78af0a7c864e0a0000002000a83a64c4dc96a0d74e76e093ffd5c09c31819d017fcae2796cb23ce2441075",
        "nonceHex": "22104aea16e8b94345c52e7b",
        "aadHex": "5354595841414431000100010011000300010000002a5354595853454c310001212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c7300000168",
        "envelopeHex": "53545958464d5431000100110003000100010001002a000000ed000001680000016800105354595853454c31000121212121212121212121212121212121212121212121212121212121212121215354595841414431000100010011000300010000002a5354595853454c310001212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000016822104aea16e8b94345c52e7bb85c36f0f7e7df91779e344dfe2ace5b7cc8bbabb30119d8f7553a668d99f93918af53248a1c6351d123c15c66b24a0a3e46b7038b901a760d3f8be8baf0f0b8e7304e75b1386be59f3f7ecc544142094a402d7ed2d45ad323ea93fdf9d05b287417cc8435e68cc63b8a7e76c01d5bb78ea35a986974f510c3dbb9cc1ae9f01ac3c56e5371d9bc16a4a211859397331f4e23247df1a9c0fbc596870ed2e401e6e9baaf292953f2e041bc5d4fcc6e9deec2c6f9c024a40ea9b049825d51ac817ec60a8cc1bbf3ffec361211c10509c2ab3d92e4bda74f3c4c1913df4b115e6d3e0584e951261dc7594b3c8cbf81ca3f763843cd4d0ff2cc72005ff3dafdff054d1e5b530e6936955b731a8eb2de43819b6dc4c5cb7fc2b02d82a34db6ffd65f7c1df236a2cb60580cf12615a2e6c35830679c86d0e632d8b8b8bd15fd5023bfb97eef687ef849e17aa90ede0f50565d42ec28df3c0d86040a39c38594b10f39826283c0ae77aeb8cae72164c79a90c94807e4bdb5cd5ae1e1"
      },
      "keyedRootHex": "00a83a64c4dc96a0d74e76e093ffd5c09c31819d017fcae2796cb23ce2441075",
      "authorityRule": "selector names this generation and repeats it as the candidate binding"
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
          "aadHex": "535459584141443100010001000d0002000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000d106da7814be10eddf3f195f4cf8e959cb921212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea03000000228",
          "plaintextHex": "53545958504c4e310001000d0100150100000020c71576a160a451cdf49063d0e06057d961f70ea320ed993fcbad642ff8ca3633020000000104030000000200030400000001020500000020404f8ef1158e39995fc5bc3ea1d731346bf0e0856414614dcb3c585e82c3f5150600000020219ccd65d74f50c7e411e7ccd1968e2c725a3135f7fdac2ea1ee601c75054d9d0700000020212121212121212121212121212121212121212121212121212121212121212108000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b09000000205c1cf96a870953a5c80c55190045bd8e2e7e3e57d5bc4de72d71f73bbdad173a0a00000020ec21e5175b6177cb09ef82a4b095961913b3ecf35ba87c42653c1989af8236090b0000002050468bc45ffce637c1b2fcd28eb9d3f1e256a259e0103da764b524f7b2161f020c0000002054ed3660c2b0997887d845b849c912d54d1b22d2371628d118b15db276e9ca430d00000001030e000000208cd683a5b55ffc9a1d31dfd1a0827d203ce6a6acd2ee9609c08ba87302d392d70f00000020f12427aaf4e051d0ae7d234d3fd64fbb25f5bd1b6bb5a79e80d4907e028cd2651000000001041100000001021200000020e3bfc568a860bc0a796487d5d876a826f51385a59698e6cb852407eee6bf3cc413000000010314000000080000000000000002150000002000a83a64c4dc96a0d74e76e093ffd5c09c31819d017fcae2796cb23ce2441075",
          "envelopeHex": "53545958464d54310001000d000200010001000100660000012900000228000002280010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000d106da7814be10eddf3f195f4cf8e959cb9535459584141443100010001000d0002000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000d106da7814be10eddf3f195f4cf8e959cb921212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea03000000228330c1cbe2a3b457fb1dd0b79ac4672a652fb1b10b26a00e34d6eab6df54a1a734f8b0b9a4113bbd2c98c81a0fff969dfe2059a1aaac1f45db26b78184dc3a53270efadc88d984a0851b5fe35b03823794c39d602b47c8db6f09eccadd464a9b228df8244fb7690203355d272ccfd4bafd54d7cc2cf07914b8d9f0a90942da18bdc5908f16c74e7f43eed23234856843ea97fd39bb8b2d11cd4c3848aa6921d1b6cf36c1fc22397317d7b8865f84ae47599c60ec9dfe2f2795953ee384a5b45cc6052ac516ba9210d0462cd92f78f9f4276787693653a283eeceb206e8be4285ab61a6fde53e4f87adc8ea0b8cfd2606cc6fe3975d6c14b36d8584a19c5ccc892d929300d14426b9f8f2428b1985d07cb5c1699d2ed34ceed3137f05e55a631ec02c6d958abd9437da187d775f73343068e1da79a5aef4575fa9fcd829e7503d7b8b171c35e1916fc8597746286fd43ad9573635103f93e23018c337bc7065b73495e60b2c701161f5c95bc8c40989b0c028de6f962a459a2f2f8762d520f914cf7f70e0a32655029c06f5520a7e8e17aad37b766830cf0212c3440fa45616017efce7d6c89a050b2776375070346904df384be04072fd1165edf8b3d9ce407b98b99084a0e016da9f4f7c7c19b5e5ee9d218cb0558e025c96f1034a1cf80650a824d7f07c54d8a422d4c49780aebc6bee98f6e62d945ef30710ba4e4ea1da7e72bab6cf33f9c88197cd95f9e3850e03bb99ae45f18b32976000c3de782a1f3bfbae5f769fd5275c444db3744c31ee6d4a14f06dc1e698418de056c9d81b54bab75bae4b6",
          "ciphertextDigestHex": "0019a69cfe6fae9015e32ee596119ba495bf417b352db0d13c00e0600d7dc53b"
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
        "bytesHex": "535459584d414e3100010000000f0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000110ee198f351dbe0180a4af73689ae1ac1b000100015239f9d2b9622e1bd8c49d76af52fb62dad3f71ef1ade65a2f8a76cd0e5c08460066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030002109720363a357379d720b9c00c1bc9248800020001d049311a7f7638be155721d69cb75938fbcb76183176d6df88a17aa6a6f177f80066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000310bbc71a6764adaedf0ad0b60e7900e40f0003000108c311795ec876b379f21785d1e73373a61306eaf6481264e3067442a5be78080066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000410918b5a723c830e286b7e7a601c0be4ee00040001bfa4368acbeab5f570ecad2abe6cd5c2c04424b6bc9077c0b14df08977b1d7140066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030005100d08b65ec848deeaa20ffe221f6eb86e000500018ac90fb53b76ae5dee442405f96c2bf56f22adcc3b5d6733eb1c3d95db64ae000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000610288c3c165ae84ad0d62462f4170cc2f400060001c4b1ac1ea390931cfa24caa819fec04b9d5ed9f5c40891057dadb27f1bfddd4c0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000710c2f4aa5cd449e6792c5e56aa88a8efd10007000123edd1c3e93c0e2fd3c83f466fa6f5eba763413c2818b3beb753161aa32ea9690066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030008100c2cabad3bd2bc25c861e8dd966936010008000166f9cfa3a1a72c46ab9f4270201c6137102c29df893961986b10d699af52be800066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030009101c283aeb8f841686caa72baea563815600090001497961ad5fb0f156ebfda9c439278e70fc3073b4deb56a7b19aecbf0ae61ee670066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000a100a44f45fe7554cb37189c11267bfc0a3000a0001afaad8eef742f726453b46a01e5250d43ffa8e0fb7deaf1ee0bee3ef82e516b80066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000b105d5da34d3ab5db820dd14711c2e65bcc000b000141c468fe01c7899b04172eddc33e3d1cbd29d477ed2552a30643b4ddd3c0cef90066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000c10e4f3f18409d6e6b39c6727292dfb6498000c0001f335dcbaaa952108ee7e557c25b93e2169cb727d9097ffd882bd59eaf6101afd0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000d106da7814be10eddf3f195f4cf8e959cb9000d00020019a69cfe6fae9015e32ee596119ba495bf417b352db0d13c00e0600d7dc53b0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000e10e31ad9c06ef304519d8befb2060a3932000e0001bd4b3269e7a6766a48cd224f77defbbfbaaad465e9096793a1dc4ce2cddc5ba90066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000f100379eb444bd86b2bd8a124b51796c2ec000f0001601eb89ddbf9d8e88c79b3fbc90a5963dc12654ec82436f6a9050cdb8e93cf12",
        "plaintextHex": "53545958504c4e31000100100100020100000842535459584d414e3100010000000f0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000110ee198f351dbe0180a4af73689ae1ac1b000100015239f9d2b9622e1bd8c49d76af52fb62dad3f71ef1ade65a2f8a76cd0e5c08460066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030002109720363a357379d720b9c00c1bc9248800020001d049311a7f7638be155721d69cb75938fbcb76183176d6df88a17aa6a6f177f80066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000310bbc71a6764adaedf0ad0b60e7900e40f0003000108c311795ec876b379f21785d1e73373a61306eaf6481264e3067442a5be78080066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000410918b5a723c830e286b7e7a601c0be4ee00040001bfa4368acbeab5f570ecad2abe6cd5c2c04424b6bc9077c0b14df08977b1d7140066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030005100d08b65ec848deeaa20ffe221f6eb86e000500018ac90fb53b76ae5dee442405f96c2bf56f22adcc3b5d6733eb1c3d95db64ae000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000610288c3c165ae84ad0d62462f4170cc2f400060001c4b1ac1ea390931cfa24caa819fec04b9d5ed9f5c40891057dadb27f1bfddd4c0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000710c2f4aa5cd449e6792c5e56aa88a8efd10007000123edd1c3e93c0e2fd3c83f466fa6f5eba763413c2818b3beb753161aa32ea9690066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030008100c2cabad3bd2bc25c861e8dd966936010008000166f9cfa3a1a72c46ab9f4270201c6137102c29df893961986b10d699af52be800066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030009101c283aeb8f841686caa72baea563815600090001497961ad5fb0f156ebfda9c439278e70fc3073b4deb56a7b19aecbf0ae61ee670066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000a100a44f45fe7554cb37189c11267bfc0a3000a0001afaad8eef742f726453b46a01e5250d43ffa8e0fb7deaf1ee0bee3ef82e516b80066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000b105d5da34d3ab5db820dd14711c2e65bcc000b000141c468fe01c7899b04172eddc33e3d1cbd29d477ed2552a30643b4ddd3c0cef90066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000c10e4f3f18409d6e6b39c6727292dfb6498000c0001f335dcbaaa952108ee7e557c25b93e2169cb727d9097ffd882bd59eaf6101afd0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000d106da7814be10eddf3f195f4cf8e959cb9000d00020019a69cfe6fae9015e32ee596119ba495bf417b352db0d13c00e0600d7dc53b0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000e10e31ad9c06ef304519d8befb2060a3932000e0001bd4b3269e7a6766a48cd224f77defbbfbaaad465e9096793a1dc4ce2cddc5ba90066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000003000f100379eb444bd86b2bd8a124b51796c2ec000f0001601eb89ddbf9d8e88c79b3fbc90a5963dc12654ec82436f6a9050cdb8e93cf120200000020eb829d4072495130f45be0fbb6dc9d2ba1c8351bb2eb3046ceb50b4044e3f71a",
        "nonceHex": "330f71243e672cbf8e904b0b",
        "aadHex": "53545958414144310001000100100001000100000056535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622000000000000000300100021212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea0300000087b",
        "envelopeHex": "53545958464d54310001001000010001000100010056000001190000087b0000087b0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622000000000000000300100053545958414144310001000100100001000100000056535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622000000000000000300100021212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000003299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea0300000087b330f71243e672cbf8e904b0bb3d7cf0e8c4a725ab11638af3be2e8f62e91a81f60c517019678d55bba6d3ce12d23d0fdd3aa041098c45eec3db7fda3378a3dc5c34be2302ef32e47d34858489946b3b8373515ed8f15985bd06c045812667a01af7c0ec739b757430330835894c6a588b7bcf210b789242748f726678180c26661337a91a1b402585d25fcdfc813e9a034309c0ba4ef917b3b13c2cfac4f718061cd8c41647aca3897ee14dbda01c1b8ea11fc90201f459209370263e1e629cc5fdb515980670a283cb7f201ebad114b4ea47b5cc8f6912cd19b97a75edd075d8a8e12774e9d4354974776ae6c8849d27a8bafaf201fd015719ebdef96c6d7680d56874d716c242cfb1f2925caa074575a0f1565a317db14ce015e69030dc46de602a728337f2935131cf9a4b328ed2fd05980f338d7ace2e987e7094b90226f39a953c1fec4baad624b23a3eb20bcda9ab58c160559ee3db2bc768606448638b70c04a51e5e86d652110fd80b8e79e10d61f44bef2ab4af955073741b28d6497e751f123c44576b161463684168a8c33e69a26bddae27d744cfdbc5ac0b28ad89b1fbd4f2e5104691508e326aff05f09d84dbd172a64021db07569d416d64f2a4abc93144d28998f383331ecde7ece7cb2580d8bb5b82a9fa1ab765526f5b11c112ed1f9650ae6ba2e44a516ef4e9c71c9f5db6eb8b572de36bd079ac69ee5ea2bd3718633d90fe7703cdd350af4a4b19a83ddb82d8645331830ee354d15d3e0517ecddc26868b2d6a2b5b3d645bd2809c097335f0d9e0250e79ff310a47870fb017ef74cff7880b8897f0ab4b11062e0619ffa00fd83b40daff17d61798faa2258816a2f52324cd81bcfd34749af4195684366263a4226c721b3e0ca3dfec18dbc800f056847c7599a144b42b1c895c15eed830ceb6b8095deddbb162bcfee132fb1a75e66901fab08eb27a6733f1885bbf238ca2dbba21e02e273f23f44e094ac85ca955e66ff0385d53541488f6a6bc4fee3259b0300cf32f6613be1fe1a33d4bed33be6e91da844a521cf436f26e14e48c2102ea113ab31cd5cca21cd1bd32d21bdaa8f67c181c68595cfe99f625413ed4c60b8862f215c6a757d7b96e436e721e5ebc176116a5173692923a11ec276c553e22c838dfbf22b868c409ae28401af478e0b741ed935530ae84ad159bc0f67956045b61e5dc7214dbdd4fac73a907aaa483f43b9c87d63cf3470dde1db17f493000f592178ac73e8f20d1ed2fda42c07c28c81be552f018d6dd9a5680e55961c6cfd6019be532b22173d97496eeaca9e73c815c522883ce793995160a36ab96d5ce205db223cbe200c969706d82258dfb2657a23cbed29125378786a1a4b8b034f60d708021eedce7e7353069c449b75ae87d2b3474c04f628b38a47b44fa27bd42f63572045bc756d007df33af08e872f1559efdf5c823c21b9b8cca4de0dfd9c9e885220565c7d0c11b9c91a1e9438293e0af77e546a02c623b7ca509002db17fe57d2a211eb6b1e843140f87237b02a55d8a7b774d4a0766ba39c4f236f83e145d71aa9ab7718ecf3cc1cdab35ddf61d761dec11204bbbbcef740b326fa3b319b10c96181d4088b3546396a012a1c6ccd940c0a9b87e9e7aa11b4bb3c4ab039427738e72e82b196367d38ffa442b6b66cb0c4a9856b38b5e3eb3be21d48ca93ca249fd47b4f5eb97e1f77dbb8aa6dc8a9f7620c9aa529d3dcdee8a45f0aab61e6699900ee3e4d72ce5a43f2b7e75802458e9a23e4c58b7a210de9234ca0d48d1fe752bcbba34bab0734ceaf751fbbba83528461a4a39a0be35d114be0e7c7fb973471b1961fcbcacc0052d1092e31a9f42cb977c12f13c542aa97e3902fdb839db033b23d9565a6df2e333e9435d44061ca029b65e2cbe83acc1de0bdae4756dc84b19b9059510c04adaefebcfe4038445ce15a12347ba7ed4b62891caf8c9abbb648c83b2685e5e740dbce6e09490a1870138967850041059bd5187d4f84cf90616e70a6224a48fe6fc30ad76f65e7f80f4bc8245c34452e6cff07e1abbceeb7bd70e1c1d2128a08e03a0e5637f9d57f9ae7db40d4fbee72c6c671c27a8e2e2973117e36207c8c0d012c4960884b203b5651288cddd4e7186c1b1d46c43b6983e4626c9218b23ace49dd7ff04ed3bb00b9252cc248ce890166c1354922c1e465f8efbe1880131b88b0a30d9d4748119a4e9ca59a05569fd58dc418fbd2096fa87c2ecb075b4ea33e95fac6ba97cf6702670012753f2086f25509f4bd74b6ba7aabb3ce0c936161358f664f81f46db61a62c9f1fce6f98228845483489451f6e6efc52e3904a0e745644a950976d2f53889fa73e8a4bac524b9b554aab0c295e46b4e5a82a9d1c63bb01411564e6f41516c9a7d5956f14f3d22afd2abb28a95b5e5bfe76d0c31c3f81bd09ac2900c39a25d7036f0418858981a664c45e189c3399ae2f11b4eade4ee3a75bee1d619bcfd08b2d2dd64c3675fc919404191e1438e87bf5e77f6ee6b6d12b82c6a3e1f6015e03987521eda430e6aadb4f994580436496eacfbcfd3699b02e58786bf2a3fbc793983a37f427ad7915ea033029bce073d1f504637916487d789a9ed5fcf478bbb81ec45542d75303e8becdee7bdeb06701b966c3802898f8f5421ed556f1be6dd6c059139be57f2f6495bbd6d05a428a9cd28bc8e08f1a1384427e4ff320f20a5e6423295cce9228352f7bfa3c34d0ef20a7eac6cd7b4310823d70e9c7d4fd4d4fd7b9998bfd4689c95c58f944e513960b7642ef5fd4c43e8e3c889756752572f4408dad791d2dc888e8258bd4011cd74059bed586c8fde5c4d33802eb0f168c952f42b31acb541d6b7c6fa02202e13d0bf8c220608e3dfd20737524ba445e35d44086078baeb544e6b664d2967ca2962bc0da03208671e5737628198a001770248fd2ac180f0b06508cb981e4132f03e9e9b172ca3ef365f70146263c4c52a7290dfcbf769f51fdb6d470020eb0ebc8003719848ab378b998aeb5106baa44ac2f521fbaae613b6295057eccb951c0f369760f6d1b088e13d2d8038a0494a6183e7f894819e5c7073fd2d9d27667f36c8",
        "ciphertextDigestHex": "299eee718f0816ca2eac36e1012ecf68e4af593ad56a1cd43f582d595036f04c"
      },
      "selector": {
        "keyHex": "5354595853454c3100012121212121212121212121212121212121212121212121212121212121212121",
        "selectedGeneration": 2,
        "candidateGeneration": 3,
        "plaintextHex": "53545958504c4e310001001101000a01000000080000000000000002020000002076646f84984b1734d44d341d3d00e4e73b79548c266523e688fc9213fc85a84403000000201f3931b4f560fd3240d53f6e5a5bc59107f0d0d0feac8a0696ad78af0a7c864e040000002000a83a64c4dc96a0d74e76e093ffd5c09c31819d017fcae2796cb23ce2441075050000000103060000000800000000000000030700000056535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000030010000800000020fd3e8712fa29ff99888cbbc7a695a2de07ab35db410926fc3aa9ba5911a977c20900000020299eee718f0816ca2eac36e1012ecf68e4af593ad56a1cd43f582d595036f04c0a00000020a832b12c6edb73305282da4585e40797722daf433755f0f74ac307b5ca40063a",
        "nonceHex": "33101c940fcc940bad23cea8",
        "aadHex": "5354595841414431000100010011000300010000002a5354595853454c310001212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea03000000168",
        "envelopeHex": "53545958464d5431000100110003000100010001002a000000ed000001680000016800105354595853454c31000121212121212121212121212121212121212121212121212121212121212121215354595841414431000100010011000300010000002a5354595853454c310001212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002299653ff367b9a1c574281a4e7d0184f638ec8c199b2dd935a4d0707dadea0300000016833101c940fcc940bad23cea8f7ca4528712feae57067b982d492d01f0d095855e92968c93e8801a5b59732b521ed1c91b80c9c7bc474c7a7fcd0538b45acbf714deca808a3c4fbcda4842138cf9a32ea33918e96f87ce87cd97e571eb2074c69cf52ad9117c0fd2367d9d66acfc087d5c1fe4244b511acc360e014d7f391cfcc88a811e19c7bd0adf1b73dcadfd6fd08efc1bdebb947a34b699e592814b93e8fd7d74a1253106c16acb6fad325bfd6f1044259715ff2c253b316dd759268018d1db16c64f3c2cd8c8942ce7ef8704cb255c9e456e4d79f20a47772f0bc4f0f501eb6a6da00ff680108751529f78e940722075c17687a290c6ff734f18ac29027cfefb1037aef500438ce19b3baaf4940e62de36ef2ca404d04a546cb73fa0cfdc5240d01859ede97441c3ec9f3dbc74484e6d1d3c29c15ba14cd9b071d0b71e0129a54602230d9e26a06023afbb2e3c4400459a52f7a1a11a64bb14776242e1c3d1a098764d08889b0255291b70dd7cd816d39b437b59e64ab0c5f89eb4f179815579789"
      },
      "keyedRootHex": "a832b12c6edb73305282da4585e40797722daf433755f0f74ac307b5ca40063a",
      "authorityRule": "selector names FMT-KAT-ACTIVE as authority and binds FMT-KAT-HOLD as immutable non-authoritative evidence"
    },
    {
      "id": "FMT-KAT-EMPTY-HOLD",
      "state": "RECONCILIATION_REQUIRED",
      "rootStorageKeyHex": "1111111111111111111111111111111111111111111111111111111111111111",
      "localContextIdHex": "2121212121212121212121212121212121212121212121212121212121212121",
      "secureSessionIdentityHex": "48d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622",
      "canonicalBindingHex": "535459584d424e440000010020212121212121212121212121212121212121212121212121212121212121212102002048d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62203013201001a737479782d6d322d73657373696f6e2d616461707465722f76310200146d322d6f70617175652d62696e64696e672f763003000773657373696f6e0400036d6c7305000c746573742d70726f66696c6506001174776f2d6d656d6265722d64697265637407001409e92777dba0528d3d29e2e5e681b7e91637c7be080030737479782d6a732f76656e646f722f6f70656e6d6c732d7761736d2f6f70656e6d6c735f7761736d5f62672e7761736d090020fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e0a000200010b002c4d4c535f3132385f44484b454d5832353531395f41455331323847434d5f5348413235365f456432353531390c0020235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba070d000400000005",
      "profileDigestHex": "5d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b",
      "generation": 4,
      "mutationIdentityHex": "9dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b193",
      "records": [
        {
          "kind": "SLOT_REGISTRATION",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000110ee198f351dbe0180a4af73689ae1ac1b",
          "nonceHex": "4400b9d8df6d5897786348d9",
          "aadHex": "53545958414144310001000100010001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000110ee198f351dbe0180a4af73689ae1ac1b21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b1930000005f",
          "plaintextHex": "53545958504c4e31000100010100030100000001030200000020212121212121212121212121212121212121212121212121212121212121212103000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b",
          "envelopeHex": "53545958464d54310001000100010001000100010066000001290000005f0000005f0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000110ee198f351dbe0180a4af73689ae1ac1b53545958414144310001000100010001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000110ee198f351dbe0180a4af73689ae1ac1b21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b1930000005f4400b9d8df6d5897786348d91731c36dd58db078921268cf9e1b94233c3fcaaa921d8c8d550304de80f2c2bc32d54f941750c1f9129d80d83bb499484622bf55cd34add882f3a597bc8c085bf5ca262d1d13ffcca486fe7977d1e91a002b58d5143ad16b3aac61d0103cff78efc190f291d38f60a4af58e2dfe513",
          "ciphertextDigestHex": "14a0583ad3e8025bf01f1f6357c8e58f94af9d7509946c2b970d805ee5175cc9"
        },
        {
          "kind": "ISSUANCE_CANDIDATE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040002109720363a357379d720b9c00c1bc92488",
          "nonceHex": "4401aa73f68adf385d98b224",
          "aadHex": "53545958414144310001000100020001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040002109720363a357379d720b9c00c1bc9248821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b1930000000f",
          "plaintextHex": "53545958504c4e3100010002000000",
          "envelopeHex": "53545958464d54310001000200010001000100010066000001290000000f0000000f0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040002109720363a357379d720b9c00c1bc9248853545958414144310001000100020001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040002109720363a357379d720b9c00c1bc9248821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b1930000000f4401aa73f68adf385d98b224d5c699bf19862b5ed536f96d9aac1c07f422ba0c9f3ca986e0beb1f610a699",
          "ciphertextDigestHex": "b5c433946d38e204807c239fd69b1ed9cba368652876fb00ebeacd933eb62fe2"
        },
        {
          "kind": "ISSUANCE_OUTCOME",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000310bbc71a6764adaedf0ad0b60e7900e40f",
          "nonceHex": "4402fb234d5c5210054a09d0",
          "aadHex": "53545958414144310001000100030001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000310bbc71a6764adaedf0ad0b60e7900e40f21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b1930000000f",
          "plaintextHex": "53545958504c4e3100010003000000",
          "envelopeHex": "53545958464d54310001000300010001000100010066000001290000000f0000000f0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000310bbc71a6764adaedf0ad0b60e7900e40f53545958414144310001000100030001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000310bbc71a6764adaedf0ad0b60e7900e40f21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b1930000000f4402fb234d5c5210054a09d03a3a3f202a41a15bb4917f38ddf95cbc578bfb7df5e5959e1862e69799d158",
          "ciphertextDigestHex": "18a0cf7ac52ff37f3d148ac947ec356c2d937d7190a878fe3de3c2fc97c111b2"
        },
        {
          "kind": "KEY_PACKAGE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000410918b5a723c830e286b7e7a601c0be4ee",
          "nonceHex": "4403a6ecda08dddd6852d585",
          "aadHex": "53545958414144310001000100040001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000410918b5a723c830e286b7e7a601c0be4ee21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b193000000d1",
          "plaintextHex": "53545958504c4e3100010004010008010000000c678bdacc7d3efcef7f94092f020000000c3cc6430c0ecada4337a26d360300000020232d780df9615a3dd2796dafe329c90f8b0c3edd41bd81791a078e3d47b358900400000020e56d6751026dbd6212134c8d6d505c8e13b935e20dd2b16038113646a40c8bee0500000020212121212121212121212121212121212121212121212121212121212121212106000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b070000000101080000000100",
          "envelopeHex": "53545958464d5431000100040001000100010001006600000129000000d1000000d10010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000410918b5a723c830e286b7e7a601c0be4ee53545958414144310001000100040001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000410918b5a723c830e286b7e7a601c0be4ee21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b193000000d14403a6ecda08dddd6852d585c52ddbba9c039b4a03611c75653759c06102626172016d134520cf816ef54ce0b80550d47131da797b3bf68f9db79f47c3c57a871afeb5845e7c7c028e35b02c074ef3a4c62d58955c38e457ec9c412c18e110da581812a43fcd36c4437fe60a63c535bf18a13e1bfab19ab54f0f963e6bd55b5da8e7c7f08ebdee73762f393c9f7c53e6b6b9967c8f6189e9e93aa15e92ee9cf0f5f350fb07ea02472dedea424179805f3b49071da24b4d2ad856ef87d81bfaca34ccb79f3f6ed7c5881cb884fae455a1527e1311c49b366d8d9e190af275014b382a5083fa13aef20bb67b2456",
          "ciphertextDigestHex": "9601b5aeebacc81d85755cd3c50e7391f4409acc6b58573e560e2f6ea9a93feb"
        },
        {
          "kind": "SESSION_STATE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040005100d08b65ec848deeaa20ffe221f6eb86e",
          "nonceHex": "44043d82cf1a785655e76758",
          "aadHex": "53545958414144310001000100050001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040005100d08b65ec848deeaa20ffe221f6eb86e21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b19300000020",
          "plaintextHex": "53545958504c4e3100010005010001010000000c24030d889763a2732abe79ef",
          "envelopeHex": "53545958464d543100010005000100010001000100660000012900000020000000200010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040005100d08b65ec848deeaa20ffe221f6eb86e53545958414144310001000100050001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040005100d08b65ec848deeaa20ffe221f6eb86e21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b1930000002044043d82cf1a785655e7675809d7f360dd5615808c3c713853358562836365ce22ad54f4ec8846b6dd939a7c3930ca6da4308a733d5c7c710b50a760",
          "ciphertextDigestHex": "c01f44a23c5ed35dd3a1da22283ff335f7da1cdfea17db3785f7a4bbd53db5a7"
        },
        {
          "kind": "BINDING_PROFILE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000610288c3c165ae84ad0d62462f4170cc2f4",
          "nonceHex": "4405c1c3fe7f3c7c8d08fe40",
          "aadHex": "53545958414144310001000100060001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000610288c3c165ae84ad0d62462f4170cc2f421212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b193000001be",
          "plaintextHex": "53545958504c4e31000100060100020100000185535459584d424e440000010020212121212121212121212121212121212121212121212121212121212121212102002048d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62203013201001a737479782d6d322d73657373696f6e2d616461707465722f76310200146d322d6f70617175652d62696e64696e672f763003000773657373696f6e0400036d6c7305000c746573742d70726f66696c6506001174776f2d6d656d6265722d64697265637407001409e92777dba0528d3d29e2e5e681b7e91637c7be080030737479782d6a732f76656e646f722f6f70656e6d6c732d7761736d2f6f70656e6d6c735f7761736d5f62672e7761736d090020fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e0a000200010b002c4d4c535f3132385f44484b454d5832353531395f41455331323847434d5f5348413235365f456432353531390c0020235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba070d00040000000502000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b",
          "envelopeHex": "53545958464d5431000100060001000100010001006600000129000001be000001be0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000610288c3c165ae84ad0d62462f4170cc2f453545958414144310001000100060001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000610288c3c165ae84ad0d62462f4170cc2f421212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b193000001be4405c1c3fe7f3c7c8d08fe4035650c2448fdef26efef4b30d86e6deb0554706611a71faec2b71d25d3e0a31e64007dad3f7c6a837a5e1a1d713b1bb5f925db7e31c95bcec37d3e694a24c41d819ff6828a51bf811395f22a68194a4646b287741621a93be83b81ee46354ac5cf8f10898238760a36935d9b1b0ba7551684a1acda70a78b9959ffa695ce83eee1752985f96b4b12b298d0c46b41fba8a83af4b84fe669c175f2c462b3f6eeab166f955bdf9455b9de95c9d14a1b234a5a4c056324b97d50cb37876f687843b2f82a3ee3e74cbfc682740069af7ec0feb08ea3203212429afedb581a7074c8ae04ccf2d00dbadc61fec73d6c848e3ddb56a4f1890a73f4e9b71c83636c6d50b701a06aaf558aafa2e2134ebd5781749ef712f8d25c152144c40635665d907a680fab1ac6141392ed06e694e9886e554b3ff98e9540eca393830da3e10bf9870f0eeeed1607174d193155375c6b0ce358dfd4791e8953e8cc0043a43c44b40e5766ce11518bcacf253c1aaeea1d3b79b9c08c015e03886a2b5dfa173fa68c09da8fb566157e7ecf7d95caf86c83c4d5c22234001ddbd4ad5ba8373961ef78a5456c26f8a882f5d2e56656dddce80f314f6f3259943356158efb8def4c30a423810c27e313ebbf9e9a224536892a88",
          "ciphertextDigestHex": "34cfc9266f1415b7bae5b9fd4d444b7f75d1fd8a87cb472554ba22cbfce999ea"
        },
        {
          "kind": "REPLAY_RETENTION",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000710c2f4aa5cd449e6792c5e56aa88a8efd1",
          "nonceHex": "44060b4ddf6f561c9898649e",
          "aadHex": "53545958414144310001000100070001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000710c2f4aa5cd449e6792c5e56aa88a8efd121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b19300000031",
          "plaintextHex": "53545958504c4e3100010007010002010000000ca1ccd8c14dc64d2e15ca5871020000000c2b9c25b5f8703721859a12c9",
          "envelopeHex": "53545958464d543100010007000100010001000100660000012900000031000000310010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000710c2f4aa5cd449e6792c5e56aa88a8efd153545958414144310001000100070001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000710c2f4aa5cd449e6792c5e56aa88a8efd121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b1930000003144060b4ddf6f561c9898649e4754af6923172c92c57819cf4753b3609b867460782675992e9843b0df4faba59beda75aa437909e125eba0b2eaa6a73d26c576a59e62a9795446352afe60b6fe0",
          "ciphertextDigestHex": "dcfd6e57df1ec5bc2bfb7beb2c7e93f38459142fbc043ef44938b7e567b70d0c"
        },
        {
          "kind": "COMMIT_RESULT",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040008100c2cabad3bd2bc25c861e8dd96693601",
          "nonceHex": "4407e63088816994ac4e1243",
          "aadHex": "53545958414144310001000100080001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040008100c2cabad3bd2bc25c861e8dd9669360121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b19300000174",
          "plaintextHex": "53545958504c4e310001000801000d0100000020ceb12836403bc297685b4aacdf91a28389cfeffa5e46b39b5a4c80f015d4c8c60200000020e80096d6f42a337db9287e0f7012f883d0ba40bb8e1063567424f76b392080a9030000002025e322124057a701754d27999dffae0c35887c59b6b65ff997d704c85f9669be040000002095635a4f0b5385f0e7bf3f2eabf44a77f88c85e3136b91d98b0c7929b2155de00500000020a2a766e15e1aee6dbffa873c744a72df487476c9067b54e3e6091ad88afa4c7b06000000207be273e23fe90d3beceaef753d45e1804f50275bf7e59b99979238297404fbdf0700000020a65b5579cfb0b438fb7be4d2901db39e3a78743f58bed618cf435140bd4b42d6080000000101090000002021212121212121212121212121212121212121212121212121212121212121210a000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0b00000001030c00000001010d0000000100",
          "envelopeHex": "53545958464d543100010008000100010001000100660000012900000174000001740010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040008100c2cabad3bd2bc25c861e8dd9669360153545958414144310001000100080001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040008100c2cabad3bd2bc25c861e8dd9669360121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b193000001744407e63088816994ac4e1243f5f7f65220d5ffdcdb584c9db2e24e61fc31dc04b8a0fc74163c8a00d30a5a58bee7c61ddf6ecd05ca2802377ffb34906c47bfaa0f8da9ee6945f154fa69e5ae5ae7d3419742311352082ea6df46e4b44e796f4f3cbf98cf6be91fa3b87c522d4402e1635137179528e4e875a35e1d226e7e03d1011ffd0702f6aec5d95a938b9f4dbe2c77bac901689792aec507b078739c1f9c4b1fd4439b9ee2b8bc921598b80f4d116f24aa683cdb0852da6d006f270fc9e26298416d627a649496f231510f2e60004f885d729eb350c93e2f02f88f769b42cef3d1746ac186c5a176a8d32910dbfe1e67c439ed30830ddad1e8bc4ad08256a4355244deec8d5b17c1244024e17e164c9a1b776851f703c6363a78e45088e21af4f4af1ef0fcc5e4a15823e080daeb2072a5514214c013ff91b418469d153d20199551f671dcf02d609f5f6f6156cd4ec29b8011dbaa7de4e50e6ccd02f354be02d2e65f2e8126d6a9a137cb3c757a44525964dc09483bdfc63b2ee5f06c39e9bf72db8a31fe8c1863bf2d06cbfc28",
          "ciphertextDigestHex": "0d1a9cc4fcee4ab1e2c42962a573df7406dcb28af332e49200e243e1f38c1fd7"
        },
        {
          "kind": "OUTPUT_ESCROW",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040009101c283aeb8f841686caa72baea5638156",
          "nonceHex": "440834dd4547f46d3db40d3f",
          "aadHex": "53545958414144310001000100090001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040009101c283aeb8f841686caa72baea563815621212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b19300000107",
          "plaintextHex": "53545958504c4e31000100090100080100000020ceb12836403bc297685b4aacdf91a28389cfeffa5e46b39b5a4c80f015d4c8c6020000002095635a4f0b5385f0e7bf3f2eabf44a77f88c85e3136b91d98b0c7929b2155de00300000020a2a766e15e1aee6dbffa873c744a72df487476c9067b54e3e6091ad88afa4c7b04000000207be273e23fe90d3beceaef753d45e1804f50275bf7e59b99979238297404fbdf0500000020a65b5579cfb0b438fb7be4d2901db39e3a78743f58bed618cf435140bd4b42d6060000000102070000000f6c69746572616c2d77656c636f6d650800000020a21f0dee931f1549d22380dc398a59a954c395e0a7f319a39766c9ded9542b59",
          "envelopeHex": "53545958464d543100010009000100010001000100660000012900000107000001070010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040009101c283aeb8f841686caa72baea563815653545958414144310001000100090001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040009101c283aeb8f841686caa72baea563815621212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b19300000107440834dd4547f46d3db40d3f94f0be904239df25843257606ca0dd37babeaa8c04f0530446d9ffbc0bb2a8b39cf68ee1fedbec3cf4cd68c47404ab6b474e32515310b1b178251e9d88c496589bba285952853453e69c7e66737d621316d8c825068767476c828a7dc7cf92ff6487e0424e54d3ac3fb74ae786a1e09717218d2ebe4bec5e778955d8c2134d4dcf71563eb0fb8a99fe635e138f3b15df7ec9a16f13694ef734b3fd836a018f54fc8fc6d0b7b7da4e4491e7076b2c194f66c1c20cc72691f8f7169e9708f003e840d301655dbc0fe0c6a3362222ede386325913d656eba0b3e61ff9ba3ac3efde829b83715975221ddc49479697969a32402794e6c096bb288cb101f8a95110c0a4abeb4b5a6f279f15bbfbdfd8b7de19a2f34849937a66",
          "ciphertextDigestHex": "8be154e4ed126d913dec59c5832a524f1e53b43955c504b2efcdfff2b79b4a9a"
        },
        {
          "kind": "SELECTION_METADATA",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000a100a44f45fe7554cb37189c11267bfc0a3",
          "nonceHex": "440999b6e5bf8f285dab9a6a",
          "aadHex": "535459584141443100010001000a0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000a100a44f45fe7554cb37189c11267bfc0a321212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b1930000003a",
          "plaintextHex": "53545958504c4e310001000a0100020100000001030200000020312db076e5edf8234a2ae152e2377b65161b3234925f913e8c14d994897adc42",
          "envelopeHex": "53545958464d54310001000a00010001000100010066000001290000003a0000003a0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000a100a44f45fe7554cb37189c11267bfc0a3535459584141443100010001000a0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000a100a44f45fe7554cb37189c11267bfc0a321212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b1930000003a440999b6e5bf8f285dab9a6a1e2bb4987a18271aa10c0390786e8efee0746f9547bc5d106195bde8969f28a48b6ec6abf2a410d52a33916c6b175656f344aea19c5adc562edae34ffb59a59dd6f570e36374c594b8f2",
          "ciphertextDigestHex": "d24237b960ddd7f74dba502be920ccfb9b4a8c4561b7d3017be83291bcc4a5e9"
        },
        {
          "kind": "RETAINED_PARENT",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000b105d5da34d3ab5db820dd14711c2e65bcc",
          "nonceHex": "440a57ed36ee3094381db219",
          "aadHex": "535459584141443100010001000b0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000b105d5da34d3ab5db820dd14711c2e65bcc21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b1930000003a",
          "plaintextHex": "53545958504c4e310001000b0100020100000020a1fa48d0580ad34cf330beb258622722d6241b8e6ffbdb96e5e6a755582a1bea020000000102",
          "envelopeHex": "53545958464d54310001000b00010001000100010066000001290000003a0000003a0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000b105d5da34d3ab5db820dd14711c2e65bcc535459584141443100010001000b0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000b105d5da34d3ab5db820dd14711c2e65bcc21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b1930000003a440a57ed36ee3094381db2192acfd01399c787ec805adb348b36d57afb811ecb802fc319d0a9dadfb937593b3ea3ce521f00f01f22c891669b9350f41b5701a58dbc7526dadf8cd52ce720343038591022af2d0bb539",
          "ciphertextDigestHex": "ff15d56e86e45d3fb08f89ebd30224f2e8040af42e0584e0f3ae2381cb91cc40"
        },
        {
          "kind": "LOSING_CANDIDATE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000c10e4f3f18409d6e6b39c6727292dfb6498",
          "nonceHex": "440b52798c72276de6183bf8",
          "aadHex": "535459584141443100010001000c0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000c10e4f3f18409d6e6b39c6727292dfb649821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b1930000000f",
          "plaintextHex": "53545958504c4e310001000c000000",
          "envelopeHex": "53545958464d54310001000c00010001000100010066000001290000000f0000000f0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000c10e4f3f18409d6e6b39c6727292dfb6498535459584141443100010001000c0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000c10e4f3f18409d6e6b39c6727292dfb649821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b1930000000f440b52798c72276de6183bf80911a215ebce9270709c0b82aa63f1527ae16c0282b583cfa6e1c1e42e80c2",
          "ciphertextDigestHex": "65af34d398a11d8036eb4842ff9538538957ff1902e20befedb0a4f88867c611"
        },
        {
          "kind": "MUTATION_HOLD",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000d106da7814be10eddf3f195f4cf8e959cb9",
          "nonceHex": "440cb4e023a51461ad6e34ab",
          "aadHex": "535459584141443100010001000d0002000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000d106da7814be10eddf3f195f4cf8e959cb921212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b19300000228",
          "plaintextHex": "53545958504c4e310001000d0100150100000020ceb12836403bc297685b4aacdf91a28389cfeffa5e46b39b5a4c80f015d4c8c6020000000101030000000200010400000001010500000020e80096d6f42a337db9287e0f7012f883d0ba40bb8e1063567424f76b392080a9060000002025e322124057a701754d27999dffae0c35887c59b6b65ff997d704c85f9669be0700000020212121212121212121212121212121212121212121212121212121212121212108000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b090000002095635a4f0b5385f0e7bf3f2eabf44a77f88c85e3136b91d98b0c7929b2155de00a00000020a2a766e15e1aee6dbffa873c744a72df487476c9067b54e3e6091ad88afa4c7b0b000000207be273e23fe90d3beceaef753d45e1804f50275bf7e59b99979238297404fbdf0c00000020a65b5579cfb0b438fb7be4d2901db39e3a78743f58bed618cf435140bd4b42d60d00000001020e00000020a21f0dee931f1549d22380dc398a59a954c395e0a7f319a39766c9ded9542b590f00000020496a616a9c1e9467cf95e7081d60f1e0d619b5c55e177cf249692470b4bbec2b1000000001011100000001021200000020137cc553249cd5eda2068a9c54c4355b1138803619407fd9f58403d1b3c71b5f13000000010314000000080000000000000001150000002040d640a0b1c1063b970d8ddea9fc5477648f16830f301f4a920027f9e162496e",
          "envelopeHex": "53545958464d54310001000d000200010001000100660000012900000228000002280010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000d106da7814be10eddf3f195f4cf8e959cb9535459584141443100010001000d0002000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000d106da7814be10eddf3f195f4cf8e959cb921212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b19300000228440cb4e023a51461ad6e34abd9045c96e5708ff743c85126d70e5cfd3eb22e9bcbc2376533a5853cb641264c4711cf5e1b957d3f167ad078b5824f7dc7e99cfd76641654abd86cb41f8c73d199087d05353273f46cae1366a69043f98fceedc91a8130c58ad8513965908691a602569d8665caee0a17a922f71e5a4a84a9e48233421c136f3853d01836b1e06d2ee470149191c5db74f233de783f75993c461334c810ae6200494d78c22bfc7482e3a737117ded8b10e01d77cbefed3bd8905367239fb8cbba7401fd79e13c249ef3b681c80f32e57654b46608c933193ed30163b456beb9fc17424fe92783dd9f8e35eafd7ca54a55923e843c6c2ecfeba0ff50c44e33255d3c9cf152cd28dbf46890e12ea5fef808e3793dbc3b14c88441410f5e081fd37b76fddf311a21cee8ff12a29539b4f20e8150326c24fe79b3410f826716390b866d7f210f7c5f2e7bc6e4aadf5ea772bdd7dd444ca7f13c50f5a8cad15a548a9b778fc5a08dca43727ce0aeef26909b918e6864f025931b632cdd9460fce739f51fd7043741ef0812fd1693bdcc8406b070da3379b4fbc5b763d61c489dd7db68bcfcc82eafe471c090c1d75f78eac2c9e4290db53d54046502820c0083f9ccc9918c977f0b7fc32f72c66849a59083ac56e5b3cfec47c76129135ef3c17a9a54509481185c3f51169c2ffb5660cf0b6d0208fd377dd726b4580f803860ff3fd8a711a41bf3efa95a1b4fc22f000e6dc455e0029cedcd95fee53cddf86a870d44e50570069ceba75e9d7871507c539327bfec047563c23a2365693b874c82",
          "ciphertextDigestHex": "496e155944382806af82092c4911e488de885c4c4a4d5c42d6debf835c6db391"
        },
        {
          "kind": "COMPONENT_SET",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000e10e31ad9c06ef304519d8befb2060a3932",
          "nonceHex": "440dfaf1bcb01a61386fd583",
          "aadHex": "535459584141443100010001000e0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000e10e31ad9c06ef304519d8befb2060a393221212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b1930000007e",
          "plaintextHex": "53545958504c4e310001000e01000301000000207be273e23fe90d3beceaef753d45e1804f50275bf7e59b99979238297404fbdf0200000020a65b5579cfb0b438fb7be4d2901db39e3a78743f58bed618cf435140bd4b42d6030000002063616e6f6e6963616c2d636f6d706c6574652d636f6d706f6e656e742d736574",
          "envelopeHex": "53545958464d54310001000e00010001000100010066000001290000007e0000007e0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000e10e31ad9c06ef304519d8befb2060a3932535459584141443100010001000e0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000e10e31ad9c06ef304519d8befb2060a393221212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b1930000007e440dfaf1bcb01a61386fd583823f0b49ee8f434605d4fc292e342ffb4bf15f1c5ef47b73d968991d1a731e5b87fcc669f57e169144497532b05d51c3b55bf05f35421966ec3475bc3175c29331029e4cf82a13ff070471d608ffa596cf9b3a4310257f271267e554f75ca1bc5b3c56ca143fd51cbe62441b4c7b66e1e4d53f6fd5267cf2d3e0d5b1d1eddc3e5cbf8c2b8e9209e4275b69e467bf",
          "ciphertextDigestHex": "bfabf83e85fc835c95ac66f32ee24048e9cce3e9c4bbecfc0bfac16a6475ba05"
        },
        {
          "kind": "ABSENCE_COMMITMENTS",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000f100379eb444bd86b2bd8a124b51796c2ec",
          "nonceHex": "440ed12242972f703803fe5e",
          "aadHex": "535459584141443100010001000f0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000f100379eb444bd86b2bd8a124b51796c2ec21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b19300000020",
          "plaintextHex": "53545958504c4e310001000f010002010000000400000806020000000302030c",
          "envelopeHex": "53545958464d54310001000f000100010001000100660000012900000020000000200010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000f100379eb444bd86b2bd8a124b51796c2ec535459584141443100010001000f0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000f100379eb444bd86b2bd8a124b51796c2ec21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b19300000020440ed12242972f703803fe5e024359884042fa90de5b529e5fb979fc5a56dd1264cef8d752825d9bc71ddef2b97afc4f2353cb8d45902f4f4f34f63c",
          "ciphertextDigestHex": "e6b5f9aa60922c86b97969f57ea7723e29fd3a4f16d7fc715d47cf67f37556aa"
        }
      ],
      "manifest": {
        "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004001000",
        "bytesHex": "535459584d414e3100010000000f0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000110ee198f351dbe0180a4af73689ae1ac1b0001000114a0583ad3e8025bf01f1f6357c8e58f94af9d7509946c2b970d805ee5175cc90066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040002109720363a357379d720b9c00c1bc9248800020001b5c433946d38e204807c239fd69b1ed9cba368652876fb00ebeacd933eb62fe20066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000310bbc71a6764adaedf0ad0b60e7900e40f0003000118a0cf7ac52ff37f3d148ac947ec356c2d937d7190a878fe3de3c2fc97c111b20066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000410918b5a723c830e286b7e7a601c0be4ee000400019601b5aeebacc81d85755cd3c50e7391f4409acc6b58573e560e2f6ea9a93feb0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040005100d08b65ec848deeaa20ffe221f6eb86e00050001c01f44a23c5ed35dd3a1da22283ff335f7da1cdfea17db3785f7a4bbd53db5a70066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000610288c3c165ae84ad0d62462f4170cc2f40006000134cfc9266f1415b7bae5b9fd4d444b7f75d1fd8a87cb472554ba22cbfce999ea0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000710c2f4aa5cd449e6792c5e56aa88a8efd100070001dcfd6e57df1ec5bc2bfb7beb2c7e93f38459142fbc043ef44938b7e567b70d0c0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040008100c2cabad3bd2bc25c861e8dd96693601000800010d1a9cc4fcee4ab1e2c42962a573df7406dcb28af332e49200e243e1f38c1fd70066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040009101c283aeb8f841686caa72baea5638156000900018be154e4ed126d913dec59c5832a524f1e53b43955c504b2efcdfff2b79b4a9a0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000a100a44f45fe7554cb37189c11267bfc0a3000a0001d24237b960ddd7f74dba502be920ccfb9b4a8c4561b7d3017be83291bcc4a5e90066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000b105d5da34d3ab5db820dd14711c2e65bcc000b0001ff15d56e86e45d3fb08f89ebd30224f2e8040af42e0584e0f3ae2381cb91cc400066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000c10e4f3f18409d6e6b39c6727292dfb6498000c000165af34d398a11d8036eb4842ff9538538957ff1902e20befedb0a4f88867c6110066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000d106da7814be10eddf3f195f4cf8e959cb9000d0002496e155944382806af82092c4911e488de885c4c4a4d5c42d6debf835c6db3910066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000e10e31ad9c06ef304519d8befb2060a3932000e0001bfabf83e85fc835c95ac66f32ee24048e9cce3e9c4bbecfc0bfac16a6475ba050066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000f100379eb444bd86b2bd8a124b51796c2ec000f0001e6b5f9aa60922c86b97969f57ea7723e29fd3a4f16d7fc715d47cf67f37556aa",
        "plaintextHex": "53545958504c4e31000100100100020100000842535459584d414e3100010000000f0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000110ee198f351dbe0180a4af73689ae1ac1b0001000114a0583ad3e8025bf01f1f6357c8e58f94af9d7509946c2b970d805ee5175cc90066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040002109720363a357379d720b9c00c1bc9248800020001b5c433946d38e204807c239fd69b1ed9cba368652876fb00ebeacd933eb62fe20066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000310bbc71a6764adaedf0ad0b60e7900e40f0003000118a0cf7ac52ff37f3d148ac947ec356c2d937d7190a878fe3de3c2fc97c111b20066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000410918b5a723c830e286b7e7a601c0be4ee000400019601b5aeebacc81d85755cd3c50e7391f4409acc6b58573e560e2f6ea9a93feb0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040005100d08b65ec848deeaa20ffe221f6eb86e00050001c01f44a23c5ed35dd3a1da22283ff335f7da1cdfea17db3785f7a4bbd53db5a70066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000610288c3c165ae84ad0d62462f4170cc2f40006000134cfc9266f1415b7bae5b9fd4d444b7f75d1fd8a87cb472554ba22cbfce999ea0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000710c2f4aa5cd449e6792c5e56aa88a8efd100070001dcfd6e57df1ec5bc2bfb7beb2c7e93f38459142fbc043ef44938b7e567b70d0c0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040008100c2cabad3bd2bc25c861e8dd96693601000800010d1a9cc4fcee4ab1e2c42962a573df7406dcb28af332e49200e243e1f38c1fd70066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040009101c283aeb8f841686caa72baea5638156000900018be154e4ed126d913dec59c5832a524f1e53b43955c504b2efcdfff2b79b4a9a0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000a100a44f45fe7554cb37189c11267bfc0a3000a0001d24237b960ddd7f74dba502be920ccfb9b4a8c4561b7d3017be83291bcc4a5e90066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000b105d5da34d3ab5db820dd14711c2e65bcc000b0001ff15d56e86e45d3fb08f89ebd30224f2e8040af42e0584e0f3ae2381cb91cc400066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000c10e4f3f18409d6e6b39c6727292dfb6498000c000165af34d398a11d8036eb4842ff9538538957ff1902e20befedb0a4f88867c6110066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000d106da7814be10eddf3f195f4cf8e959cb9000d0002496e155944382806af82092c4911e488de885c4c4a4d5c42d6debf835c6db3910066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000e10e31ad9c06ef304519d8befb2060a3932000e0001bfabf83e85fc835c95ac66f32ee24048e9cce3e9c4bbecfc0bfac16a6475ba050066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000004000f100379eb444bd86b2bd8a124b51796c2ec000f0001e6b5f9aa60922c86b97969f57ea7723e29fd3a4f16d7fc715d47cf67f37556aa0200000020faab73f207ced1713d133d776c94a713d6bfdfe9ce5083a7298e31aee84e8f3e",
        "nonceHex": "440faaa165e0276396c8f535",
        "aadHex": "53545958414144310001000100100001000100000056535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622000000000000000400100021212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b1930000087b",
        "envelopeHex": "53545958464d54310001001000010001000100010056000001190000087b0000087b0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622000000000000000400100053545958414144310001000100100001000100000056535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622000000000000000400100021212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd444800000000000000049dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b1930000087b440faaa165e0276396c8f535515d32baaf151ef1bf8f8899665aff4dad5ddd967d51c286e697fbd8215a1e3b062ea63a5dd89d6abeb490f045918b546495d3b61b270ebe68107872005a9404f07faad88d6839cd45016127a24bd253491973040579497f6f619c72fc05dd38b1ea791aadad06066669ffce9725db01482921a30e75aa5e4b6dd2b7ce25771b96390f71b26c9b99e68d405dd1a733d7eb6623b01373412c09b16846302ed2d26558917df3cf727c949df374f8ca2a27f7b77e56e23b192c7aeb54e63315d24ecd6ec52a28660d6366f8b4fcb073db9705b397c3289dc7224619c48c98e84ed93671320211fb11638b19d923f984245e36c715415f5c8fcfde125ae2efb37726373559fac633b9723ecee4a64625fa11a1191e9ed025d3219c7744edea91996b7d404877a850ce58bb256546a9c0c6ae38b27a798899d029d71f80a3bf62a318fda8b4b8d67b0a44d35c9eacfe47b5f525706cb2c92fe95926b304636b55f2c069b8feab05b8e163e81e8a38b4db08f5aa48100b6eae9ef62f8123c4c168c7f19acf6ae17558e41c5cc1327ec33f8d1666e95d2b0d53c967d47b5215b0e0528bd8da16662a14f4508f7ca3108cf4199b79d09c411d517851f90e03d5d3aa262a595f00ab8d044b6402748087926c74f362e0893939edc243529e64bcb37f3528281cb28bfc7cc89f03c683a55c46182985c669c25571d8db8bdf0c9f4fc3c9cf52e1e6c06512d1c6026da57d3efdce6cddedd5d2007f41a94ee676902883471591f206d4878640a9e423ca029343b61142d19bcca3a5224eb5d554cea9b4cbc52275505929369e7867b07be9a731b8f5c65c9212daf7808e62810143682a342ed5d21068fd75de04ee7460da3528bc424a8ebdb1054527f5e429396c27d857233558adee94f9596a303fe7aeb1bed29f6d46585ab1b437eeaa31d1893ab18a1598d076071482ea4ceb19aff9b35db70ef6f8c6d6d7fbf1069e3abfd63cd3d4788fd7bf653e3eb4ea2ed9ba6ca9f1aa8a4916a09288fa874848fc32dbc41572ff105aa6533cc9c39892bea304baa91ccef79ec79e5b0522a6a2055ace53495ab8158d91671fe5738cd70034622aff9b1d0924f4d79dc02c858240f14f11efb04768405a7e762a0f43d9daccd23912ffd8eba26896e68e4de6b11fc11c51356561d67d017593cf25fda85d86e2cbb1b208a6dec2aa1bd010b388139ec55c028122a3e55fbf7873b6416a34e4ab5286dbb6e8ebdcbc6127374aa1022b950e707de6a66e39a31d1785c2a1c0a2269470bd6303517c5cf16b2c3f0b382c6b3bbcc7c7bc05535bd5a4167e6a3c76dbe81b9cee4c0eb434b9ed6acc20e80a54c0c91e5902759fe17ab6e47cbdd955646e919afb6d4384c60bcd3ef3ad3781456936a8f4d13e827bf63383ce8466a73daac6b55e3b4b31ec114edaf9fed1914d09e2c9e8620c45c571e1b514f81660ecf2be803009b2f4784ff4bf8cf2016fc7f6de45ac4c7e46a9d0310d083175769021440b50538ffe5d796fdd9dfcba1292636feccb58e79a744ac8230a1645722e88ca3c014ddaf90720fd6af9b5c743bbc0a7755d2e38e305b4b0be9059a471282afbfaf880084151f7ac1aa3c9c07e4ce81efa81f99474f53d81b8907d19973b2d0ac1a0456c2bdabf0f23c2e18efaf8aa7521ef4fc82cae5aacb2f5d977c4a4205661c9783035af4842048f6e23d082278dd75b160acba0fe5620ccbf73b0e23abd68497661b242d4aa9a4bbb514ffbf4d38bef610885f17297c860ed3f564686208c8a213cfd7c2bfe0aefe23df428ad1f1aa4763049d3b533c185c3e1c2356cf5e2d56215c4b499c2517a17b591d5541084b4329438fe5d5b26051902ef7a7ef5c41905bf28523c01c1872381f901ed45f8d60bad507ec7d279df69feb340ce6b3fd579703f67b4117962ec351b7c304f18bdd6ccd54f8a1cb1770762900c47b85dbcf618bae598da907ca2cafc03cc8419e4495a32c284ad8dc147b29ed8a8057bff7da7a8b3e380b13ad7cd200f4bba4e85c5b086052160ae8fc517b013dfffc4408a2a0eadbd7180605b5e4fc9243716be6e2a79026796f46da940b956644b0bdd74010766eb2b1e3ecbd0d55ced569e911eb6c9526fd3e371efe04d6f45f34175a24eaaeb4e819f08742c2986324e2773e26705c34e41c2ea8fe4dd827f8f59e3a51e1db0414912c7f891e86e19124dd85e42dece43895042e0ae09d05c3dd5d779546307ab4480c79d74517f24e70aeee3d233d75d312f58194e8eaa52cf223651db0ca6e8cea5bd3d3083ce73410e2507461060a80eb3c2215af1812da909f7fb6d5ac187360c42a3f993b3898d09cbadda952136915812e73a40aa172a82d615a8c925689480e632d725037f107c60c7869ea72ea4d1271b849a618ae84e215e2607a187f06443cbcef9c9f9c72147833d42ad4b1bf79abcbd9142ba13c886752f84a438540f8096077e368a55c51bb8c1258a36e8559e95acb02c4073bc52bf37a7eb618e4a28d605bdf43a3ab760b661f25d14bc4538f46ad5a6062c218a648b74f43109be4276712af710ecd42f8b56e0989e9ac73a5a9041a67634acd29f313ac75b87149f070896389298032f0462bfd1ef3b5b6cab5f94e4f1782a65b9f2758366270e9a0db58159cf83045fc9f531059d6605f8315886ee6c782e155245e7229c1174045b6f947381867de44a5f37eb41914e8dbfb305cb02ef75ae3a09e7461b85d632641477563366555ce0104a412b07de6c3bf85a7d69e58a3f66a91b934a0b9682e20dac1c54f87893497d39645c8a91e7b40a668596fd43745f63d37c7f29a1b64e107f69404d4503d4090c0234f489d5dae9cd626a94d76579305e78a280f88d79489f6019eae85cc1f32e175440c2ef3c97b9316cdb430124477eb89e4a3787ce3e61a259d788bf069b3a112ab8258c6272423883073704312ee7d6df77d1e34e39b9d20e94a90c265cb8f22f80fc7c3c1dafc829b765a65814517e8a46979459c197afd2aef2151ca5564eddf234aa1d68c1595dd01615669aeec907704433ee9d2ae9b9841022270ffe8687a01b49d5c185",
        "ciphertextDigestHex": "01bc706af10ba8dfb46fde7b9c9c23b5d9c85f2b86b2a305c834394373cc21b4"
      },
      "selector": {
        "keyHex": "5354595853454c3100012121212121212121212121212121212121212121212121212121212121212121",
        "selectedGeneration": 1,
        "candidateGeneration": 4,
        "plaintextHex": "53545958504c4e310001001101000a0100000008000000000000000102000000205d8a18f17b63545d548a371c997ba493eb942ff5b18bf7c83927491144790e440300000020318a13dc612ff8694d7888095c584d467bc0009a12d5a70110f381cdf4b0a8b0040000002040d640a0b1c1063b970d8ddea9fc5477648f16830f301f4a920027f9e162496e050000000103060000000800000000000000040700000056535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000040010000800000020f614daa2bace8c9484130c4381d25ff00d5ec88fcf11d1f54a8e7f8941619322090000002001bc706af10ba8dfb46fde7b9c9c23b5d9c85f2b86b2a305c834394373cc21b40a0000002076991453d9f2093bbbe0c42da018a5ad2f02903f2c544c5fd9923364f2832e3f",
        "nonceHex": "4410c312c1555afbc3488030",
        "aadHex": "5354595841414431000100010011000300010000002a5354595853454c310001212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0100000000000000019dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b19300000168",
        "envelopeHex": "53545958464d5431000100110003000100010001002a000000ad000001680000016800105354595853454c31000121212121212121212121212121212121212121212121212121212121212121215354595841414431000100010011000300010000002a5354595853454c310001212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0100000000000000019dc85936fd0ca926bf99011661c89948c6630d35d28906922935e2ec81f9b193000001684410c312c1555afbc3488030087848edd8db65cd6dc0deea04068edb28a50c752ff40c273d689fda843aac1ce091787de034bc6dd7aae13ea44938d841d55c82d71d423e8f41737b422cc51913e952535942fbed65433f7f036d22647738ed1d7fc24404fac486b6c19780494294a69efa1f2d7f833a48f7ae967fbedc8106e638d83f61e1a87334bba9742207f9dfd9ce556fc0941a2eb9a8101dd191c85cfbd047a04ee47ce509b34191ba06e59ff02444af9fd6236a3fcfc85ed6c7b413b6be704c5f084dcfa204623fa1bd391fc5803461d6cbe181696248cc9547c9ae4ebc14584af2a4a3546d7d09eb50c2f6e906983e818230a4e0bea08452b37cb55b8e862fdfbe68530ce477168fa33e63ba3f6301a61f4f63694c3e4bd25437bdb704b2eb37350873b7374f8db909ecb73a5411e7b58825ac7f2f9b78f94b084dfe6d396fffbe0556037458e719719acd981476dc5cfae4ca3f5c519ffa3d21d238d4181338655185ab7975ba4a19cc1cca02c8ab2da9739c8dc4b38fa1291a3d46f5ccb442"
      },
      "keyedRootHex": "76991453d9f2093bbbe0c42da018a5ad2f02903f2c544c5fd9923364f2832e3f",
      "authorityRule": "selector names FMT-KAT-EMPTY pre-session authority and uses its pre-session selector AAD while the exact candidateManifestKey locates this SESSION-scoped immutable non-authoritative candidate"
    },
    {
      "id": "FMT-KAT-UNBOUND-HOLD",
      "state": "RETAINED_UNBOUND_HOLD",
      "rootStorageKeyHex": "1111111111111111111111111111111111111111111111111111111111111111",
      "localContextIdHex": "2121212121212121212121212121212121212121212121212121212121212121",
      "secureSessionIdentityHex": "48d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622",
      "canonicalBindingHex": "535459584d424e440000010020212121212121212121212121212121212121212121212121212121212121212102002048d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62203013201001a737479782d6d322d73657373696f6e2d616461707465722f76310200146d322d6f70617175652d62696e64696e672f763003000773657373696f6e0400036d6c7305000c746573742d70726f66696c6506001174776f2d6d656d6265722d64697265637407001409e92777dba0528d3d29e2e5e681b7e91637c7be080030737479782d6a732f76656e646f722f6f70656e6d6c732d7761736d2f6f70656e6d6c735f7761736d5f62672e7761736d090020fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e0a000200010b002c4d4c535f3132385f44484b454d5832353531395f41455331323847434d5f5348413235365f456432353531390c0020235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba070d000400000005",
      "profileDigestHex": "5d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b",
      "generation": 5,
      "mutationIdentityHex": "77c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e189",
      "records": [
        {
          "kind": "SLOT_REGISTRATION",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000110ee198f351dbe0180a4af73689ae1ac1b",
          "nonceHex": "550071a2af4bf04a2812dceb",
          "aadHex": "53545958414144310001000100010001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000110ee198f351dbe0180a4af73689ae1ac1b21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e1890000005f",
          "plaintextHex": "53545958504c4e31000100010100030100000001030200000020212121212121212121212121212121212121212121212121212121212121212103000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b",
          "envelopeHex": "53545958464d54310001000100010001000100010066000001290000005f0000005f0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000110ee198f351dbe0180a4af73689ae1ac1b53545958414144310001000100010001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000110ee198f351dbe0180a4af73689ae1ac1b21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e1890000005f550071a2af4bf04a2812dcebfd4eface79344432d60a4e190a64ac3b148d52d4f2e6ea8c2398766b8cfaeefef36716eabfb22145be0c9366983be5ca1c776cfff43eb3e0d9115adf43c139334b7d9d6575b259250b88cffdf85fd595827e58d7d2651ebad3d81f1d892841965fed9288c32d8207cb92e1e81de091",
          "ciphertextDigestHex": "c01d231c74cd14f1516b803239e79ec74254c78f07fb2dc0ae09cc67291a0870"
        },
        {
          "kind": "ISSUANCE_CANDIDATE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050002109720363a357379d720b9c00c1bc92488",
          "nonceHex": "55017af7f001227e57bd990c",
          "aadHex": "53545958414144310001000100020001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050002109720363a357379d720b9c00c1bc9248821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e1890000000f",
          "plaintextHex": "53545958504c4e3100010002000000",
          "envelopeHex": "53545958464d54310001000200010001000100010066000001290000000f0000000f0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050002109720363a357379d720b9c00c1bc9248853545958414144310001000100020001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050002109720363a357379d720b9c00c1bc9248821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e1890000000f55017af7f001227e57bd990c7d6606b64ec5a0e28f4aec396d75b8fb3604160dcee0e1d1fd3537309dfe7b",
          "ciphertextDigestHex": "7149feb49d0c8a313fb232d37243b350ab2e83e53640db4617716c5a7932bce3"
        },
        {
          "kind": "ISSUANCE_OUTCOME",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000310bbc71a6764adaedf0ad0b60e7900e40f",
          "nonceHex": "55023d400ec042629098fff4",
          "aadHex": "53545958414144310001000100030001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000310bbc71a6764adaedf0ad0b60e7900e40f21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e1890000000f",
          "plaintextHex": "53545958504c4e3100010003000000",
          "envelopeHex": "53545958464d54310001000300010001000100010066000001290000000f0000000f0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000310bbc71a6764adaedf0ad0b60e7900e40f53545958414144310001000100030001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000310bbc71a6764adaedf0ad0b60e7900e40f21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e1890000000f55023d400ec042629098fff463300f74c1cd2bafdb088aac4c5d0637dcd9542b7cf4de67d3d2fc1b105c2e",
          "ciphertextDigestHex": "80d4bef3bc92e437c033aea4d1e0c67a27a2f54d10fb802f491533c0580675e7"
        },
        {
          "kind": "KEY_PACKAGE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000410918b5a723c830e286b7e7a601c0be4ee",
          "nonceHex": "55031de764d3320a3305113c",
          "aadHex": "53545958414144310001000100040001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000410918b5a723c830e286b7e7a601c0be4ee21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e189000000d1",
          "plaintextHex": "53545958504c4e3100010004010008010000000c678bdacc7d3efcef7f94092f020000000c3cc6430c0ecada4337a26d360300000020232d780df9615a3dd2796dafe329c90f8b0c3edd41bd81791a078e3d47b358900400000020e56d6751026dbd6212134c8d6d505c8e13b935e20dd2b16038113646a40c8bee0500000020212121212121212121212121212121212121212121212121212121212121212106000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b070000000101080000000100",
          "envelopeHex": "53545958464d5431000100040001000100010001006600000129000000d1000000d10010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000410918b5a723c830e286b7e7a601c0be4ee53545958414144310001000100040001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000410918b5a723c830e286b7e7a601c0be4ee21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e189000000d155031de764d3320a3305113c92aa36bc09721f322ce1ded459070dccbdf83fc982a0a30d11868d4b63f5386de00535a8053c4dc03da622d3685fcb24500f807aeb5b5fcd896105ff0ee217bad3f5f1fda0ef7139c38c889652724a038eccffffe615baab9445ff9124466edf482d59c8a8a04e6e25f994ec70ecd5f2a3aaa52f9fc1b27c598589f5f5236333c2e5c0186c0a67ccde83cfe3b04d04c9dd749db48c3babd3f5b394e7cfdf0e3c42c81ff18ab6ee9696cb0b38148a9bbc424bc748edb044aa4801179f340ee7a76b9d5611a6fd851e9e8073385e39f17dc5ab156ee72d3af317283045f86453986e",
          "ciphertextDigestHex": "3e9f73e5b53f4fa40305cd1d16858a9ab5892b6bb728de773079bd4bcf8519f6"
        },
        {
          "kind": "SESSION_STATE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050005100d08b65ec848deeaa20ffe221f6eb86e",
          "nonceHex": "550458e49918b22169648633",
          "aadHex": "53545958414144310001000100050001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050005100d08b65ec848deeaa20ffe221f6eb86e21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e18900000020",
          "plaintextHex": "53545958504c4e3100010005010001010000000c24030d889763a2732abe79ef",
          "envelopeHex": "53545958464d543100010005000100010001000100660000012900000020000000200010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050005100d08b65ec848deeaa20ffe221f6eb86e53545958414144310001000100050001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050005100d08b65ec848deeaa20ffe221f6eb86e21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e18900000020550458e49918b221696486337d6f1fea0200062a023d7e838246da58bcc8dee6306307717c149aa644e071aaaf8d08d9b30f5603a80d4a745bbd711b",
          "ciphertextDigestHex": "591c935b0a0ce4dca705e5cfbfd05cd64f06c1186ef315e00c23ca189c2983be"
        },
        {
          "kind": "BINDING_PROFILE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000610288c3c165ae84ad0d62462f4170cc2f4",
          "nonceHex": "5505132927a91f4bb24c6e3b",
          "aadHex": "53545958414144310001000100060001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000610288c3c165ae84ad0d62462f4170cc2f421212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e189000001be",
          "plaintextHex": "53545958504c4e31000100060100020100000185535459584d424e440000010020212121212121212121212121212121212121212121212121212121212121212102002048d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62203013201001a737479782d6d322d73657373696f6e2d616461707465722f76310200146d322d6f70617175652d62696e64696e672f763003000773657373696f6e0400036d6c7305000c746573742d70726f66696c6506001174776f2d6d656d6265722d64697265637407001409e92777dba0528d3d29e2e5e681b7e91637c7be080030737479782d6a732f76656e646f722f6f70656e6d6c732d7761736d2f6f70656e6d6c735f7761736d5f62672e7761736d090020fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e0a000200010b002c4d4c535f3132385f44484b454d5832353531395f41455331323847434d5f5348413235365f456432353531390c0020235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba070d00040000000502000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b",
          "envelopeHex": "53545958464d5431000100060001000100010001006600000129000001be000001be0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000610288c3c165ae84ad0d62462f4170cc2f453545958414144310001000100060001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000610288c3c165ae84ad0d62462f4170cc2f421212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e189000001be5505132927a91f4bb24c6e3bf2b0e2f4e8619b53e79da679ff893cf684f6307b9be4f16f4c7f2885fd913de4dc38acda48ed672d1b40681cf3bf20da0a69e0e0ebface714124fe1a905f4a857ce1eccf659d5cee033fa19dfbf344a51f74e97b8cdd14a1cb6ab699c2893275aa49a8c1afe9b4e86165af0395b2213bb846123baeb8784612ac365a8f0efb4111834a7d1311bc02d8622fd7dac423a098d28399f14063f05adeadba5c3242aad707db1b1191d83d3a753a3d0f9ff1afed2c5051d29c21ac1748d578c446423fe177fdc2eb5ee836f678bba97b16dbef3aae3304685c79a6dadb0ee7975f7fab2f40edcfb9c241d75a7578acee82a751524e17aea0ffabb5d03bc35ae2ea437cbd17e15261bd5f259d50087a4672863f64973190cb4eed9a67c8b132d9f1cbfd2be121db35e9bac36652f1185fa1e9ecf77a4ecc4b5d1ae0e646d09bec51d1b37a0d073d2b7b23a5b5a7b18b107d8cb6ebac7259e8786f0d1fc31c12c9c4d661b3daa54598b923732cd5ce5d47174e4d1f2aab698cafb1c43cd0c61e4a821337d3e148b84282b32efc639d93ec295b5e22336d2e6ff52ae82c5465f697f0ceae740452cb3da71f96a17a7d1b08488fbf23437e4da2c4dc269c1c579c1b5a02204a3b3e88528a54c02362e0b356d7",
          "ciphertextDigestHex": "cf17b55aa487094a445d612a819da552ddb6b1b2042d5c7f4fc39150d5ecb008"
        },
        {
          "kind": "REPLAY_RETENTION",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000710c2f4aa5cd449e6792c5e56aa88a8efd1",
          "nonceHex": "5506dac3a4134e4439ed49be",
          "aadHex": "53545958414144310001000100070001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000710c2f4aa5cd449e6792c5e56aa88a8efd121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e18900000031",
          "plaintextHex": "53545958504c4e3100010007010002010000000ca1ccd8c14dc64d2e15ca5871020000000c2b9c25b5f8703721859a12c9",
          "envelopeHex": "53545958464d543100010007000100010001000100660000012900000031000000310010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000710c2f4aa5cd449e6792c5e56aa88a8efd153545958414144310001000100070001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000710c2f4aa5cd449e6792c5e56aa88a8efd121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e189000000315506dac3a4134e4439ed49be668aba654db5f73445ab343f4c965bd0014e0dca2ff961440b5234e40ca57ba5f97e8ea87f9bf707af70f06264cac9f28e5a867dcc21ae2466dc28723ebab9e9d3",
          "ciphertextDigestHex": "25fad0db210a74e7ffa43557e7ce03c30ac8adf0dd288dc85db7f494f774fad7"
        },
        {
          "kind": "COMMIT_RESULT",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050008100c2cabad3bd2bc25c861e8dd96693601",
          "nonceHex": "55071568749b7a7ada013d65",
          "aadHex": "53545958414144310001000100080001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050008100c2cabad3bd2bc25c861e8dd9669360121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e18900000174",
          "plaintextHex": "53545958504c4e310001000801000d01000000207ef1ef2caee9bad857d34c340397bf738c3f69a594b83d04b86023431ce3b5a00200000020404f8ef1158e39995fc5bc3ea1d731346bf0e0856414614dcb3c585e82c3f5150300000020219ccd65d74f50c7e411e7ccd1968e2c725a3135f7fdac2ea1ee601c75054d9d0400000020a9abb895d448ea8ebec475c988874aefd3f5392b46f3fbc209e4d55bdbab8fbe05000000205200ecdb93d8f513eec89d61c107d7354ca76f2b8976be0f396063b9c44e5290060000002013a340f9aa60b0d1b657aab5fd3e064bf404332fa24e154ca69e004aaf3452870700000020c7062028c749a1a16a7811607820d1476d7a32b44138995bc166072025a1a16a080000000102090000002021212121212121212121212121212121212121212121212121212121212121210a000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0b00000001030c00000001010d0000000100",
          "envelopeHex": "53545958464d543100010008000100010001000100660000012900000174000001740010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050008100c2cabad3bd2bc25c861e8dd9669360153545958414144310001000100080001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050008100c2cabad3bd2bc25c861e8dd9669360121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e1890000017455071568749b7a7ada013d6513620e1c56efeeab31f433d2d5e1909dac81baec50abdecccad59191266e9d2356b76daaad7a5691017c3475de64dd0b93adc07141a4dccc0935bc47df68042bc37b46c39f07b539b1eef8aa896daad8a347c3483afc91617366a7cf060b4ae4229fc5d071ce40347ea9585a08e264e70ad4eff32fb829ea02c2b383908f032212891475a7e74b21a68999b16a924a63e32bba716e3af2d2205bf76f4133dde381ebe0b6432fd6a97869c8987efcf62b442c73534f1b44cd9c3165c74c44a4a7ecd3ee5cc75e83bf716a3c849c6e3ca9f4daa140c99b3689f32c24ea56ec328cce7e812549aa2fcdfae98544c991b3f219165988f43febecf73c19acf6cd9f2777e17702e3fdf7be04578366e7089cad0af424ec5deb284c84eaf5f2e97a2e36123bc4c2ec61dc490bfddcd5c9dffde349e4a417baee44c560cf87722296e2d64575732b0ea5a7bd763da9475cab5b7ed4f5c6779c35fbae27fd804af1d8dcdcdbb64834eeb3006bc110c3a943a849e93327e07985aa87a11037e0df5efd6074b1064c8b",
          "ciphertextDigestHex": "9b1aa9d1b4e8aaa9a0a19a08d0c433828bda35f16aba1bb16c9d9b9572c81960"
        },
        {
          "kind": "OUTPUT_ESCROW",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050009101c283aeb8f841686caa72baea5638156",
          "nonceHex": "5508b74fe5a68be0c64b99f1",
          "aadHex": "53545958414144310001000100090001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050009101c283aeb8f841686caa72baea563815621212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e18900000110",
          "plaintextHex": "53545958504c4e310001000901000801000000207ef1ef2caee9bad857d34c340397bf738c3f69a594b83d04b86023431ce3b5a00200000020a9abb895d448ea8ebec475c988874aefd3f5392b46f3fbc209e4d55bdbab8fbe03000000205200ecdb93d8f513eec89d61c107d7354ca76f2b8976be0f396063b9c44e5290040000002013a340f9aa60b0d1b657aab5fd3e064bf404332fa24e154ca69e004aaf3452870500000020c7062028c749a1a16a7811607820d1476d7a32b44138995bc166072025a1a16a06000000010507000000186c69746572616c2d70726f7465637465642d636f6d6d6974080000002078b40cb3cd0d55915a7ccb54938b2cfd65a4d9db06866549ee37d976edca868d",
          "envelopeHex": "53545958464d543100010009000100010001000100660000012900000110000001100010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050009101c283aeb8f841686caa72baea563815653545958414144310001000100090001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050009101c283aeb8f841686caa72baea563815621212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e189000001105508b74fe5a68be0c64b99f1ede7f051e1781adadee9e0a25eea7ce0ea6eb6463d7c3fad80229adc9fbf6871d40051859ec0cbec2f17832ca26a3cdd1722fcc698f3d1609950f55cc9e1f1fd79d01872efd5072ba5b8d3823b512b801b4f223d337623bd5309e030046e38f2cb2d8ac37ce6737003ded54bad68ad3b48f3af547c41eaa824ab33d6bf859d083b360883c7bb2f5ed962166c917be28b6e3ca162c08af74e4b795f9aaae35252304d9af5d11dfd2c9cc7fe6edf7f61c847e4ce64563914dca6b7c2c39430c2644457c66cbb927c920170ac8d1cf87e82270022df007f5ed76eafec1b2ffcb05c01b2cfa62a5f0183a5e9143f6431351d8b898de179f5071771bd73b878b6730583071f869ee75ea44006984d0920f5ec84ef5c985a8faf908a70fb68a048b9a6",
          "ciphertextDigestHex": "4e9a46140d5f0eeadb94b0bd7dc508b0f34081dd44927f6f9c738d87e481ab95"
        },
        {
          "kind": "SELECTION_METADATA",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000a100a44f45fe7554cb37189c11267bfc0a3",
          "nonceHex": "5509e74194ac7834757749a5",
          "aadHex": "535459584141443100010001000a0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000a100a44f45fe7554cb37189c11267bfc0a321212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e1890000003a",
          "plaintextHex": "53545958504c4e310001000a0100020100000001030200000020312db076e5edf8234a2ae152e2377b65161b3234925f913e8c14d994897adc42",
          "envelopeHex": "53545958464d54310001000a00010001000100010066000001290000003a0000003a0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000a100a44f45fe7554cb37189c11267bfc0a3535459584141443100010001000a0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000a100a44f45fe7554cb37189c11267bfc0a321212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e1890000003a5509e74194ac7834757749a55151e7806943f3e34619ca46256715be0c7f86c46655ddbbb22f8d98b429463f1bcd8ce0778555ffe5f343dd69735cbd78577d4f2a738df58d47a72b4b56259bd24ed1aab2d9ceab958f",
          "ciphertextDigestHex": "b441c013ba2a92e08465a2056983d8067437e26cbeac11449e1eeeb1a92c7097"
        },
        {
          "kind": "RETAINED_PARENT",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000b105d5da34d3ab5db820dd14711c2e65bcc",
          "nonceHex": "550a178676d9ee676707a884",
          "aadHex": "535459584141443100010001000b0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000b105d5da34d3ab5db820dd14711c2e65bcc21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e1890000003a",
          "plaintextHex": "53545958504c4e310001000b0100020100000020a1fa48d0580ad34cf330beb258622722d6241b8e6ffbdb96e5e6a755582a1bea020000000102",
          "envelopeHex": "53545958464d54310001000b00010001000100010066000001290000003a0000003a0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000b105d5da34d3ab5db820dd14711c2e65bcc535459584141443100010001000b0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000b105d5da34d3ab5db820dd14711c2e65bcc21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e1890000003a550a178676d9ee676707a8840b56af9bb2256a1b4537e33d65bdc61726dbd2efecf9bb3f75e9ec8801ba1410b967c4f3c10c874841502ec3430086892d418ef32ddd42d8e8792739f92eddf4d66fae25d843056c7a3f",
          "ciphertextDigestHex": "44d40545225e63da7611973b41a8620bf990ef7292a48e1ac8a93a7e2beef466"
        },
        {
          "kind": "LOSING_CANDIDATE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000c10e4f3f18409d6e6b39c6727292dfb6498",
          "nonceHex": "550b33de34f20c3f6a5774a2",
          "aadHex": "535459584141443100010001000c0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000c10e4f3f18409d6e6b39c6727292dfb649821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e1890000000f",
          "plaintextHex": "53545958504c4e310001000c000000",
          "envelopeHex": "53545958464d54310001000c00010001000100010066000001290000000f0000000f0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000c10e4f3f18409d6e6b39c6727292dfb6498535459584141443100010001000c0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000c10e4f3f18409d6e6b39c6727292dfb649821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e1890000000f550b33de34f20c3f6a5774a22f722a14b8fd82c38d5516d49c09d660417a08a45b3d3c6dca11aa1f7f1dab",
          "ciphertextDigestHex": "6c4e7eb56343387da3d7d7a81ae137d17391e1a6329e297df993279a3d3fa30b"
        },
        {
          "kind": "MUTATION_HOLD",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000d106da7814be10eddf3f195f4cf8e959cb9",
          "nonceHex": "550c18caf879e84082b32b6e",
          "aadHex": "535459584141443100010001000d0002000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000d106da7814be10eddf3f195f4cf8e959cb921212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e18900000228",
          "plaintextHex": "53545958504c4e310001000d01001501000000207ef1ef2caee9bad857d34c340397bf738c3f69a594b83d04b86023431ce3b5a0020000000106030000000200050400000001020500000020404f8ef1158e39995fc5bc3ea1d731346bf0e0856414614dcb3c585e82c3f5150600000020219ccd65d74f50c7e411e7ccd1968e2c725a3135f7fdac2ea1ee601c75054d9d0700000020212121212121212121212121212121212121212121212121212121212121212108000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0900000020a9abb895d448ea8ebec475c988874aefd3f5392b46f3fbc209e4d55bdbab8fbe0a000000205200ecdb93d8f513eec89d61c107d7354ca76f2b8976be0f396063b9c44e52900b0000002013a340f9aa60b0d1b657aab5fd3e064bf404332fa24e154ca69e004aaf3452870c00000020c7062028c749a1a16a7811607820d1476d7a32b44138995bc166072025a1a16a0d00000001050e0000002078b40cb3cd0d55915a7ccb54938b2cfd65a4d9db06866549ee37d976edca868d0f0000002041f3a56c7d07c36f44e39da6a89c0e5a614c0c74f96468d98156abd72cb86f921000000001061100000001021200000020c514a5808ae6c4f6d918178583770dc822a810225de0a5fc6404b0e0411418ee13000000010314000000080000000000000002150000002000a83a64c4dc96a0d74e76e093ffd5c09c31819d017fcae2796cb23ce2441075",
          "envelopeHex": "53545958464d54310001000d000200010001000100660000012900000228000002280010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000d106da7814be10eddf3f195f4cf8e959cb9535459584141443100010001000d0002000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000d106da7814be10eddf3f195f4cf8e959cb921212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e18900000228550c18caf879e84082b32b6e804a21795acec0a9b7c7a51a3433cbbfa17a5e8056900c87eec7e7bbfc0f8a2c995d94307d6cfc45cd44492c9b4bcfb4205f81d7dfea620f0adf4424b07eaee4a5ece462b89aecafce5d4c909aadcc6c8b8d2d65ecbef130166fbb7ecbb0f864af5a3dc4ea3b89911c27ccaa1a783c1550e2ad9d669fdd4df39e4b50c5e65776cf7abf227b21bb8ee7cef73487ac3ac6937eb885240326328df9521a827abe59b344be535190e714664f240d0b7e068f98e1630db9671660f1f6a871bdf646a0aa93c69e642455181f82d77eedd6d02c08a2d679c6a646c56a14dcb75f601bf9776330a4eac4a42cd6874929aca91f1dac73c43fb151c9036cc66a0a41406a0b1da93eab648245bcfbf1d6e20799e51162ad5c5758dbc2c8aede4228012d619b652f412b3abd4875fc588a4acbda2f116c1b4af3d5b26a2dd4a7d11ae90c4d48fe8bbda1f2845d773d1f8194383fc5a6e1be5ad875c391b158d2ad47b48bbc839d706c32a43be7c2297e546d76d038fab3accc0f6f5293a70b86bef6dbe4fe85b69ee8c3d03d76b0b5f3d02558d7231ba4cb5a3a6960267ca27c0247eb2a4140cbbe33b60874902fa3910c2ba085bf39e4dcf06e53fa48a761f1f7fd7e05d05599440c332210f00bccdde24848196ba766d49350568ffe4391d60120fae438cb72981d7d3c053f61ed0f49b25a3db0fbbb5d5b0c0ebd9b843d92ae93ab7dc47c79e9efca5ed7ca3a4f1bcfe09d8de42a7ab830a24087a2cf4e05ab530ec6f613488ec49749cd0a3aadc4cd86b602451f4b470e1d4001113e",
          "ciphertextDigestHex": "8fabe5345d39e2642a0f2277303f73d95b7b937bf34be24fa440a92b1bfb8506"
        },
        {
          "kind": "COMPONENT_SET",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000e10e31ad9c06ef304519d8befb2060a3932",
          "nonceHex": "550d2b2f83d309304d75c02a",
          "aadHex": "535459584141443100010001000e0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000e10e31ad9c06ef304519d8befb2060a393221212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e1890000007e",
          "plaintextHex": "53545958504c4e310001000e010003010000002013a340f9aa60b0d1b657aab5fd3e064bf404332fa24e154ca69e004aaf3452870200000020c7062028c749a1a16a7811607820d1476d7a32b44138995bc166072025a1a16a030000002063616e6f6e6963616c2d636f6d706c6574652d636f6d706f6e656e742d736574",
          "envelopeHex": "53545958464d54310001000e00010001000100010066000001290000007e0000007e0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000e10e31ad9c06ef304519d8befb2060a3932535459584141443100010001000e0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000e10e31ad9c06ef304519d8befb2060a393221212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e1890000007e550d2b2f83d309304d75c02af1bba7b83d478f96050996f0821425c04d9c7c5c336c2a27f0b0126984dd6ee36a2bf5bf89eb1c0c4aed69adb231588af46dec2436807f1ea4f32033484366c17b53a85065824b9abf6eff8fd33a8da4abe24380ed533d160dc578e036f768515e879fe31e81a83bc504ae8d85b750c6825861aa4a338d755112115ea88d6c35de7efd20bee79b0220c04d5b16d7",
          "ciphertextDigestHex": "1836d1325055fd0a3e3c27245353c412dd523dedd4aa960994944bdb29405533"
        },
        {
          "kind": "ABSENCE_COMMITMENTS",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000f100379eb444bd86b2bd8a124b51796c2ec",
          "nonceHex": "550e811c2238189a60496dc9",
          "aadHex": "535459584141443100010001000f0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000f100379eb444bd86b2bd8a124b51796c2ec21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e18900000020",
          "plaintextHex": "53545958504c4e310001000f010002010000000400000806020000000302030c",
          "envelopeHex": "53545958464d54310001000f000100010001000100660000012900000020000000200010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000f100379eb444bd86b2bd8a124b51796c2ec535459584141443100010001000f0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000f100379eb444bd86b2bd8a124b51796c2ec21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e18900000020550e811c2238189a60496dc9b37ae363f6891a16b2fbce1965e55cca23378c633119b4f12df23a407e65e6805effd1563f2d7141f159333e7b2cbaaa",
          "ciphertextDigestHex": "bcc88e7412ce089f0b56801b0baddbcbe8c67b4da2ac1df80df34059ea6c6bff"
        }
      ],
      "manifest": {
        "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005001000",
        "bytesHex": "535459584d414e3100010000000f0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000110ee198f351dbe0180a4af73689ae1ac1b00010001c01d231c74cd14f1516b803239e79ec74254c78f07fb2dc0ae09cc67291a08700066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050002109720363a357379d720b9c00c1bc92488000200017149feb49d0c8a313fb232d37243b350ab2e83e53640db4617716c5a7932bce30066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000310bbc71a6764adaedf0ad0b60e7900e40f0003000180d4bef3bc92e437c033aea4d1e0c67a27a2f54d10fb802f491533c0580675e70066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000410918b5a723c830e286b7e7a601c0be4ee000400013e9f73e5b53f4fa40305cd1d16858a9ab5892b6bb728de773079bd4bcf8519f60066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050005100d08b65ec848deeaa20ffe221f6eb86e00050001591c935b0a0ce4dca705e5cfbfd05cd64f06c1186ef315e00c23ca189c2983be0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000610288c3c165ae84ad0d62462f4170cc2f400060001cf17b55aa487094a445d612a819da552ddb6b1b2042d5c7f4fc39150d5ecb0080066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000710c2f4aa5cd449e6792c5e56aa88a8efd10007000125fad0db210a74e7ffa43557e7ce03c30ac8adf0dd288dc85db7f494f774fad70066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050008100c2cabad3bd2bc25c861e8dd96693601000800019b1aa9d1b4e8aaa9a0a19a08d0c433828bda35f16aba1bb16c9d9b9572c819600066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050009101c283aeb8f841686caa72baea5638156000900014e9a46140d5f0eeadb94b0bd7dc508b0f34081dd44927f6f9c738d87e481ab950066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000a100a44f45fe7554cb37189c11267bfc0a3000a0001b441c013ba2a92e08465a2056983d8067437e26cbeac11449e1eeeb1a92c70970066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000b105d5da34d3ab5db820dd14711c2e65bcc000b000144d40545225e63da7611973b41a8620bf990ef7292a48e1ac8a93a7e2beef4660066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000c10e4f3f18409d6e6b39c6727292dfb6498000c00016c4e7eb56343387da3d7d7a81ae137d17391e1a6329e297df993279a3d3fa30b0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000d106da7814be10eddf3f195f4cf8e959cb9000d00028fabe5345d39e2642a0f2277303f73d95b7b937bf34be24fa440a92b1bfb85060066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000e10e31ad9c06ef304519d8befb2060a3932000e00011836d1325055fd0a3e3c27245353c412dd523dedd4aa960994944bdb294055330066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000f100379eb444bd86b2bd8a124b51796c2ec000f0001bcc88e7412ce089f0b56801b0baddbcbe8c67b4da2ac1df80df34059ea6c6bff",
        "plaintextHex": "53545958504c4e31000100100100020100000842535459584d414e3100010000000f0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000110ee198f351dbe0180a4af73689ae1ac1b00010001c01d231c74cd14f1516b803239e79ec74254c78f07fb2dc0ae09cc67291a08700066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050002109720363a357379d720b9c00c1bc92488000200017149feb49d0c8a313fb232d37243b350ab2e83e53640db4617716c5a7932bce30066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000310bbc71a6764adaedf0ad0b60e7900e40f0003000180d4bef3bc92e437c033aea4d1e0c67a27a2f54d10fb802f491533c0580675e70066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000410918b5a723c830e286b7e7a601c0be4ee000400013e9f73e5b53f4fa40305cd1d16858a9ab5892b6bb728de773079bd4bcf8519f60066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050005100d08b65ec848deeaa20ffe221f6eb86e00050001591c935b0a0ce4dca705e5cfbfd05cd64f06c1186ef315e00c23ca189c2983be0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000610288c3c165ae84ad0d62462f4170cc2f400060001cf17b55aa487094a445d612a819da552ddb6b1b2042d5c7f4fc39150d5ecb0080066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000710c2f4aa5cd449e6792c5e56aa88a8efd10007000125fad0db210a74e7ffa43557e7ce03c30ac8adf0dd288dc85db7f494f774fad70066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050008100c2cabad3bd2bc25c861e8dd96693601000800019b1aa9d1b4e8aaa9a0a19a08d0c433828bda35f16aba1bb16c9d9b9572c819600066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000050009101c283aeb8f841686caa72baea5638156000900014e9a46140d5f0eeadb94b0bd7dc508b0f34081dd44927f6f9c738d87e481ab950066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000a100a44f45fe7554cb37189c11267bfc0a3000a0001b441c013ba2a92e08465a2056983d8067437e26cbeac11449e1eeeb1a92c70970066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000b105d5da34d3ab5db820dd14711c2e65bcc000b000144d40545225e63da7611973b41a8620bf990ef7292a48e1ac8a93a7e2beef4660066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000c10e4f3f18409d6e6b39c6727292dfb6498000c00016c4e7eb56343387da3d7d7a81ae137d17391e1a6329e297df993279a3d3fa30b0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000d106da7814be10eddf3f195f4cf8e959cb9000d00028fabe5345d39e2642a0f2277303f73d95b7b937bf34be24fa440a92b1bfb85060066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000e10e31ad9c06ef304519d8befb2060a3932000e00011836d1325055fd0a3e3c27245353c412dd523dedd4aa960994944bdb294055330066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000005000f100379eb444bd86b2bd8a124b51796c2ec000f0001bcc88e7412ce089f0b56801b0baddbcbe8c67b4da2ac1df80df34059ea6c6bff02000000209a62d8af05e0ee352ef7f1aea757e7576398a94d4dacac7399e70777fcbccf93",
        "nonceHex": "550f644c7db897333beac757",
        "aadHex": "53545958414144310001000100100001000100000056535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622000000000000000500100021212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e1890000087b",
        "envelopeHex": "53545958464d54310001001000010001000100010056000001190000087b0000087b0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622000000000000000500100053545958414144310001000100100001000100000056535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622000000000000000500100021212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd4448000000000000000577c6cc5e4c7fbe0e0555680bc5b9255602acb26f36c25556efda240c05d5e1890000087b550f644c7db897333beac75789ac22a99f30491da79356a46ab0fa7e91d18bbf8a6441914ecd8e07298a4f2889cfbd324abce7a9b3a084d8cd6098448dd476c7723809c4aec3a407fb7b6a3eb25f17b9923ce2ac4a8d3c06d598b97885de8c5e40a1672c887bdfb5920c9b5abd2ad5053d9fb39937026843335a552684daa355e83ac4bb8ec044157625dcebd4d81d421be44ecf1e716d0c01c0d980b6ab6ed2b0705c054eeac4b5c2851070019b0ce0f5fe30325d2782f8d178c63e0ec09fb6f6d38ea5147909d6b49864214784edf8c762b9a53e0f571334489054dd6e2def0e874f2806158666d8a2ee5c3c96e01aa19032a698d2f7cb0209dbe6b1a35d6766e19f4bcd5f1af4281f40a03e8b2a3964c26f7d469a76a4538844bc945d67f391dbe476eed097d9955eb1141e121221077a6972d16b3b027efb0ef6ac89e0838479f4fcbc91591352b7dbeb13b52f1ea950cb7de22b03b33abd30d654ff69648583fd803af9512622858cb43b14a3392f4392e6ad07f0d2deb7ffcad8dce9788c3c5165e135a73f13cdf0b31b3e4b84ac3bd9e2fd26dfe84baaab95f2408964c18aa8babc6038efe823d9390a60accab4c143fbd4eb1d09ed57104b9752509f7c3db82153533d6f55b3f747445611dbc1a80c240c463136f94d26c47f86d5985ec0f9a72fe4096d66d3521ad1eafd43423d8d9a80a0f6ef64f2c2f7f7301c743149dd26e058811b43955178347e49c019c7829f2fba0720ed6a65a6b8746101b1bf6915db8aa52c10a66500759e5d6f620351e8e97e5f36b3649c8005630a047f89bbdd61fe1277ab4e9442113118728c180ac4896dd1117fdb398bc2262f18ad338fbca7ab33eddc25048aa1d2ab69eb0fba48b9411d5cae97e70cee01de4c9469564cc676870fa559dfd5a400145b401a05b63c4050ae85a406b7935c29b3def8fae070c3371900b33ccb368a091b8279812ea7765d5fff45fb36989d9ca3bcd0317efca6d5cee03c433589b27d81a382dbfdb602bca4412fe13a01a3358b0e0d5e12bc28fe5cccfdd2fa468a8a32955b8f7131ac408c955b49559e0d9cf0ae8151ee9911f4cf26097e4f2fb005058f7345e288bb89987b6072979a8c839526efae82b1f33fe8e7a25c398d7b5b48abbc22de53a9bf97bfc2e1311e819a81f25d502bcdccea192b816d3030735715ee28a15fda24bb06058d6edb0939900ada4ffe391905a8ec6515b98727aeb310bed5efa6408c9f101ed73476cb96aaa7144186a4e60f69cf925ccb3af430ba932c631c44c67604d18f383a0b9f7791f2c9bc99f1c3245d469b074a3cb979d28e3956a9e257b98f627a9c20414833911a4d490d60d1d943b77f72524befbc95f04bd7fb3349e961ce36b8d7a0d32ca7330f9dd25200b3a5be366c6f8a04abfdb872b773d0f4f24ae9532c3f9b34616d0a70d5c37ca55e781f223eba75feda95eca2c483fe8847bfaa771d649f719a117e571a7e8657e9f29874d48c683e1be0f61bcf74925223723c4032284a88860b13acc15994bbb5e2faba94092b31009c130170d2c22e626cfcb1f15b76fbf7941b31f64544f106348b1e8a42c521b3d2e096a7ee3bbc520c74ac999d9360ce7d5008935442dc421b7ae5d50cb5a9aba9781599838940172f4464e959809dfe2a7a49432c920e77cfb73dd7914c240739ba130770ebc0c8d1c7c52057dc5aee9c36ca7388cedd22052f6d3b8d2776a07572797d60416acccc3e1c53ed0c4e817c4b72d7e6f9abd99c3c3a95e90e99586db7d85babd063d9f40d7832dcf042c2edc7396c4715470df51a7643db7202c8109edd132f51b1dd6f35ff3c19965186cab55e35bc1b54c409130167f7541ece7dbac44216518a3680188ecf2be331b82d597ff0897936e71916df3a86c5aa31e1dfc02fbd2091e5ebd7cc341fdb23b0db42cc01d58f77122a7a640c2893fcaa28516da1926a2d32261c44745f1b3f46c40ee3a879660198d75d266594ab51fd58bd0fc7a5efa5c5b9297f3c11ee5f87d00b529ae84a34ebaa75dd1de0d3c932d2c47ddc38f5ed123a0955277f31cb20e11df928e5caa632637c37ccaa92fb545b3a194dec9180ee23531a790d8ad6e9cef74cc2be7f923f9ccbbe3e93d94593afd8aecc3d69a274321de4d1a04dc74cf18d170f77ff14560911b11d9bb69b2eeb0621bfd80b5b50e1e0f6eb47a69d1ee819386dd01f49fa17e06c704a56b33e1c3ba579f9b305a88b5152a212334ad8fd18ca45b7e874c8b7726ca7ebf59fa203bf26db09a643e80f5f3f8ba6fc717e551cdb09ff3258b938bc1bc5ee5efac704f12d2dd9f9b250d8c742b77dffff39e0fc13926dfd3e12c253cf8a1937daed2f2a287f5b751048d232bfc2ad9fef60d54a27e7a33ec49ac86e1822c2c7a0d295c7f8e3d2679f6eb213771e6d15c9fad902350660f9d34088d19d2c64cca1a92cf99a75fe58c0fe9cb1bde362e73ca2e12c7dc59e36af4961b6020f9fa167c8b5b62fe81bb861a7db5857154c904e7900aaff0d22f56e54649729e0f2e661aeddc4e76b8e52ca5deab999b2b1bddd5b3642351e83af7301d9531da34416bde278c70222d7eda3ca26079ec2a6d9bc89666fac938efe6a321339a6b5e047d6566826cf66dcbb79a8d7437aac5da46927683f6b6c072e5aa0b3f6dac138edf9bf7faac1514a395f705bf5ddcfafb65999f668e2b6f3b8b26e9d33b21cb23c416c40fc0afa0893e7184a7625fe0973d3ba544f8f9cf68b7b5dc0745450a8ae85d5a3bbfc94e1653ca5514dd20b6bd4061c7033c15bd29b7ca2cd12519b0d0f3abb1ef91a344867d419fe44a92b92b654e84c4c396f03be406f8cac3191a2297da02ba29056ffa0774d73b6916c6489997a572bf1c88b29cf4f302cbe85a2ec5f02cff13dd2771576b9ff0cd37ffcf45d90c8af0bb9b8ee94214f01738b1d79b2053bc934b6f96d9d4ff1b0473c45dedc42aec05bcc0f2de2fc1a616e9b57829974b1a99edd206918b0f7e42151f00a4c5114ca552f21f05d9dae575900b34accbbe70729be032ad7a8246fb835dfeb30133e3d358f8915582ba60e962291119afa591769950b749c311a",
        "ciphertextDigestHex": "d6f908e35c73798a2dc4c4d64790eaa1056bb8eb4c6164b680fc5071f2030ab8"
      },
      "selector": {
        "keyHex": "5354595853454c3100012121212121212121212121212121212121212121212121212121212121212121",
        "selectedGeneration": 2,
        "candidateGeneration": 2,
        "plaintextHex": "53545958504c4e310001001101000a01000000080000000000000002020000002076646f84984b1734d44d341d3d00e4e73b79548c266523e688fc9213fc85a84403000000201f3931b4f560fd3240d53f6e5a5bc59107f0d0d0feac8a0696ad78af0a7c864e040000002000a83a64c4dc96a0d74e76e093ffd5c09c31819d017fcae2796cb23ce2441075050000000102060000000800000000000000020700000056535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000002001000080000002076646f84984b1734d44d341d3d00e4e73b79548c266523e688fc9213fc85a84409000000201f3931b4f560fd3240d53f6e5a5bc59107f0d0d0feac8a0696ad78af0a7c864e0a0000002000a83a64c4dc96a0d74e76e093ffd5c09c31819d017fcae2796cb23ce2441075",
        "nonceHex": "22104aea16e8b94345c52e7b",
        "aadHex": "5354595841414431000100010011000300010000002a5354595853454c310001212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c7300000168",
        "envelopeHex": "53545958464d5431000100110003000100010001002a000000ed000001680000016800105354595853454c31000121212121212121212121212121212121212121212121212121212121212121215354595841414431000100010011000300010000002a5354595853454c310001212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000002f975890f278e55525effeee51a5f218c251debe9ff60d697d08f2ff4ba9a3c730000016822104aea16e8b94345c52e7bb85c36f0f7e7df91779e344dfe2ace5b7cc8bbabb30119d8f7553a668d99f93918af53248a1c6351d123c15c66b24a0a3e46b7038b901a760d3f8be8baf0f0b8e7304e75b1386be59f3f7ecc544142094a402d7ed2d45ad323ea93fdf9d05b287417cc8435e68cc63b8a7e76c01d5bb78ea35a986974f510c3dbb9cc1ae9f01ac3c56e5371d9bc16a4a211859397331f4e23247df1a9c0fbc596870ed2e401e6e9baaf292953f2e041bc5d4fcc6e9deec2c6f9c024a40ea9b049825d51ac817ec60a8cc1bbf3ffec361211c10509c2ab3d92e4bda74f3c4c1913df4b115e6d3e0584e951261dc7594b3c8cbf81ca3f763843cd4d0ff2cc72005ff3dafdff054d1e5b530e6936955b731a8eb2de43819b6dc4c5cb7fc2b02d82a34db6ffd65f7c1df236a2cb60580cf12615a2e6c35830679c86d0e632d8b8b8bd15fd5023bfb97eef687ef849e17aa90ede0f50565d42ec28df3c0d86040a39c38594b10f39826283c0ae77aeb8cae72164c79a90c94807e4bdb5cd5ae1e1"
      },
      "keyedRootHex": "a04f8b7406b8dffe559f9d2a159eca80491143a4a8fee97963eeec07149f4542",
      "authorityRule": "fixed selector is byte-identical to FMT-KAT-ACTIVE and names it as sole authority with no bound candidate; this complete immutable non-authoritative SESSION-scoped candidate is reachable only by RECONCILE_INDETERMINATE deriving its locator from the retained MUTATION_HOLD record key; after SS memory loss it is preserved debris and readback is COMPLETE_OLD"
    },
    {
      "id": "FMT-KAT-EMPTY-UNBOUND-HOLD",
      "state": "RETAINED_UNBOUND_HOLD",
      "rootStorageKeyHex": "1111111111111111111111111111111111111111111111111111111111111111",
      "localContextIdHex": "2121212121212121212121212121212121212121212121212121212121212121",
      "secureSessionIdentityHex": "48d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622",
      "canonicalBindingHex": "535459584d424e440000010020212121212121212121212121212121212121212121212121212121212121212102002048d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62203013201001a737479782d6d322d73657373696f6e2d616461707465722f76310200146d322d6f70617175652d62696e64696e672f763003000773657373696f6e0400036d6c7305000c746573742d70726f66696c6506001174776f2d6d656d6265722d64697265637407001409e92777dba0528d3d29e2e5e681b7e91637c7be080030737479782d6a732f76656e646f722f6f70656e6d6c732d7761736d2f6f70656e6d6c735f7761736d5f62672e7761736d090020fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e0a000200010b002c4d4c535f3132385f44484b454d5832353531395f41455331323847434d5f5348413235365f456432353531390c0020235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba070d000400000005",
      "profileDigestHex": "5d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b",
      "generation": 6,
      "mutationIdentityHex": "baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e9603",
      "records": [
        {
          "kind": "SLOT_REGISTRATION",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000110ee198f351dbe0180a4af73689ae1ac1b",
          "nonceHex": "6600eaaf4553f99afd0395a5",
          "aadHex": "53545958414144310001000100010001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000110ee198f351dbe0180a4af73689ae1ac1b21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e96030000005f",
          "plaintextHex": "53545958504c4e31000100010100030100000001030200000020212121212121212121212121212121212121212121212121212121212121212103000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b",
          "envelopeHex": "53545958464d54310001000100010001000100010066000001290000005f0000005f0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000110ee198f351dbe0180a4af73689ae1ac1b53545958414144310001000100010001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000110ee198f351dbe0180a4af73689ae1ac1b21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e96030000005f6600eaaf4553f99afd0395a5b424ca8df9fc51857844aaffb363df1c5ef952885578c0c5ee9b7efacbb682f1a6e38b4fac97ba6392e8ecf6052da249de6a24774595c0fb6934e1c9cfd6a04b27157760845d8b36b9365b90ec5e82defba2047c26f8256baeadca91f5ac030033c87941c8fefe1d2fafcaaf872efe",
          "ciphertextDigestHex": "7e3b0d8071c0adf7899dab3ec4b1a0c357eaf163b5185a497b1a159f4c5ad0ef"
        },
        {
          "kind": "ISSUANCE_CANDIDATE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060002109720363a357379d720b9c00c1bc92488",
          "nonceHex": "66015122a2002de5c72db8e3",
          "aadHex": "53545958414144310001000100020001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060002109720363a357379d720b9c00c1bc9248821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e96030000000f",
          "plaintextHex": "53545958504c4e3100010002000000",
          "envelopeHex": "53545958464d54310001000200010001000100010066000001290000000f0000000f0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060002109720363a357379d720b9c00c1bc9248853545958414144310001000100020001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060002109720363a357379d720b9c00c1bc9248821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e96030000000f66015122a2002de5c72db8e3a38e20c7c5ec30ea7e42a8b7b35feadd2ac5b5f5d7c4394a2522f6fd23df01",
          "ciphertextDigestHex": "2fce924fdfbd5aea7f1d7f449e5c51d9ef39094b938971e1f124e4160b41dac5"
        },
        {
          "kind": "ISSUANCE_OUTCOME",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000310bbc71a6764adaedf0ad0b60e7900e40f",
          "nonceHex": "66029376a8d232a53c8a0af6",
          "aadHex": "53545958414144310001000100030001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000310bbc71a6764adaedf0ad0b60e7900e40f21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e96030000000f",
          "plaintextHex": "53545958504c4e3100010003000000",
          "envelopeHex": "53545958464d54310001000300010001000100010066000001290000000f0000000f0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000310bbc71a6764adaedf0ad0b60e7900e40f53545958414144310001000100030001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000310bbc71a6764adaedf0ad0b60e7900e40f21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e96030000000f66029376a8d232a53c8a0af62cb381ca376e7c11e9b6f13cf9b85697348fb84f2e90e5464dcc1e8c6d1998",
          "ciphertextDigestHex": "0ae228734a67c68097633baa45224db6de717305471d49732eb1b6a847ced7de"
        },
        {
          "kind": "KEY_PACKAGE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000410918b5a723c830e286b7e7a601c0be4ee",
          "nonceHex": "66032dfa0f1de77ddb131eb6",
          "aadHex": "53545958414144310001000100040001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000410918b5a723c830e286b7e7a601c0be4ee21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e9603000000d1",
          "plaintextHex": "53545958504c4e3100010004010008010000000c678bdacc7d3efcef7f94092f020000000c3cc6430c0ecada4337a26d360300000020232d780df9615a3dd2796dafe329c90f8b0c3edd41bd81791a078e3d47b358900400000020e56d6751026dbd6212134c8d6d505c8e13b935e20dd2b16038113646a40c8bee0500000020212121212121212121212121212121212121212121212121212121212121212106000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b070000000101080000000100",
          "envelopeHex": "53545958464d5431000100040001000100010001006600000129000000d1000000d10010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000410918b5a723c830e286b7e7a601c0be4ee53545958414144310001000100040001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000410918b5a723c830e286b7e7a601c0be4ee21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e9603000000d166032dfa0f1de77ddb131eb652973216dc86bc59a19ee9ab38a33904706b3116d496e4f3b61f76535c3724f38ca77e76c7804abc51e93ad739ddfb2fddc4efa6de5558fd4ecf983794bc22b781b96ebe7d58904685b6b915c9807d84eef27b254c1cb0312a3668cbbe0641e274fa2eabdd3ea7676534538bb5dfc0860a3b0d0fb49f09d05afa4f1e0a4b03bcffee1016ef9f266c235e3f07360ac60d2ff1481b9f95f7994fe1ab363d53bd106051400d9605ca638cb072854c86e1a72d26f0517db9c952542514c5ee1d1ea4ffe5096084805260f11b9b4eb24c1bf1586ce76feeb30d83604373b38f83b1e499",
          "ciphertextDigestHex": "af978e39a24641b138ef87e2300c777deb4adb648ce78304eb2a8667a60a5971"
        },
        {
          "kind": "SESSION_STATE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060005100d08b65ec848deeaa20ffe221f6eb86e",
          "nonceHex": "6604b07b4766a103e766798d",
          "aadHex": "53545958414144310001000100050001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060005100d08b65ec848deeaa20ffe221f6eb86e21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e960300000020",
          "plaintextHex": "53545958504c4e3100010005010001010000000c24030d889763a2732abe79ef",
          "envelopeHex": "53545958464d543100010005000100010001000100660000012900000020000000200010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060005100d08b65ec848deeaa20ffe221f6eb86e53545958414144310001000100050001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060005100d08b65ec848deeaa20ffe221f6eb86e21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e9603000000206604b07b4766a103e766798d7641523aaeae9463fda580b05e9f42cd19f6836b1431e3ce82d38ff2c9d26a72fd545e7535e6b1a8f4b2ea8ab7b7ad40",
          "ciphertextDigestHex": "e4edfc9d6c520839da2fb06b84984b9baaad705c8ad93477a70b6d3533530153"
        },
        {
          "kind": "BINDING_PROFILE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000610288c3c165ae84ad0d62462f4170cc2f4",
          "nonceHex": "6605d09eee54d96b699702b2",
          "aadHex": "53545958414144310001000100060001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000610288c3c165ae84ad0d62462f4170cc2f421212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e9603000001be",
          "plaintextHex": "53545958504c4e31000100060100020100000185535459584d424e440000010020212121212121212121212121212121212121212121212121212121212121212102002048d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62203013201001a737479782d6d322d73657373696f6e2d616461707465722f76310200146d322d6f70617175652d62696e64696e672f763003000773657373696f6e0400036d6c7305000c746573742d70726f66696c6506001174776f2d6d656d6265722d64697265637407001409e92777dba0528d3d29e2e5e681b7e91637c7be080030737479782d6a732f76656e646f722f6f70656e6d6c732d7761736d2f6f70656e6d6c735f7761736d5f62672e7761736d090020fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e0a000200010b002c4d4c535f3132385f44484b454d5832353531395f41455331323847434d5f5348413235365f456432353531390c0020235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba070d00040000000502000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b",
          "envelopeHex": "53545958464d5431000100060001000100010001006600000129000001be000001be0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000610288c3c165ae84ad0d62462f4170cc2f453545958414144310001000100060001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000610288c3c165ae84ad0d62462f4170cc2f421212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e9603000001be6605d09eee54d96b699702b2cb70be1906e7f0e3537f1dee89d179f61ffa491fbb837fc83f57ccd933cef37e29a967e8d8cddff205b67a597f625a5f0926b02c22f57c387c2b52d4b2eed3c7ef78e5a6a5b90c27997f016ddbf3e174c349a080ab1b7af6018f11dd7462c457a492e2273d016166c2a49c0d40f6cb02c719aae6781985944cf3c531ab7559e3281529fa51028ac4a39940dfbd8633b9e1cac9a8f058b579ed8c0674722221579a020b2282ee62d14c44bc842091401cf4468bd4aa9965ca645dc77be4d4b84e438a7af21ac70bce214d1406e905a43cf541b80234e1a0651c0319da80ad3544f9128a6d155c46c79fd26d4c42a00964d40eb0f95bd9528b9cb892a50c99df1754c260f08c3ae46f02bc8430a5c2f2d8d082d99bed30415dbced92165059008dee53b58df0974e723e771e61e7c00d61a9332e9eec65e39b1e896113a57418186bcfbccd2f6a7c1420908b9198a8ff16843152a1b02552113e73b4d17b231232f3399d85ae33d84f94cdab1cdd37abffcc0812cff089f23d07600c2e977972e073b427f5693a48d83d83038ab27af74c2cd8c099d2adde10b68f6c83c97471fbc83644f9b38cab15d564bba8d4ccd78c746db789a7e4882737e235e5bc25a9749b18e96de52f7b0c1c24f446672f",
          "ciphertextDigestHex": "025f2b6e2df2893cb6e3cd4639add023eaf28efba8781e0cf536bed501faa758"
        },
        {
          "kind": "REPLAY_RETENTION",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000710c2f4aa5cd449e6792c5e56aa88a8efd1",
          "nonceHex": "660690f0e1ad7ad752f98d06",
          "aadHex": "53545958414144310001000100070001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000710c2f4aa5cd449e6792c5e56aa88a8efd121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e960300000031",
          "plaintextHex": "53545958504c4e3100010007010002010000000ca1ccd8c14dc64d2e15ca5871020000000c2b9c25b5f8703721859a12c9",
          "envelopeHex": "53545958464d543100010007000100010001000100660000012900000031000000310010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000710c2f4aa5cd449e6792c5e56aa88a8efd153545958414144310001000100070001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000710c2f4aa5cd449e6792c5e56aa88a8efd121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e960300000031660690f0e1ad7ad752f98d06d2df1528338d383f7633fbb145b8da4eee33531c07bc77759caaab8491edbdebecf7d729e5a544f3881e9d45fc14e6076a9c26d99e0a5074a97e3567efe8723717",
          "ciphertextDigestHex": "36d32e21d0c9b13bb4c57bad3c7a1b6a9976148fc8c0bfe17b9bb5d85ded5d51"
        },
        {
          "kind": "COMMIT_RESULT",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060008100c2cabad3bd2bc25c861e8dd96693601",
          "nonceHex": "6607fc527362b54735cbc536",
          "aadHex": "53545958414144310001000100080001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060008100c2cabad3bd2bc25c861e8dd9669360121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e960300000174",
          "plaintextHex": "53545958504c4e310001000801000d01000000202aa1037112e783a3cdb863536336a40c11980d1c09fcf00aa7bf156125ff1d6c0200000020e80096d6f42a337db9287e0f7012f883d0ba40bb8e1063567424f76b392080a9030000002025e322124057a701754d27999dffae0c35887c59b6b65ff997d704c85f9669be0400000020c64bf33e66e9fd7c22f9249fac23b8ab36fe102a47d737a21b4bbb2b800688070500000020a6e599220a9457f205dc66650aa7c157da616c3ba83721f400308a25b53446560600000020d94dbaa4bd7bb60ed6fa7f70c71a6b6b61da00ce5546f7b19354e5dbcbf19ea70700000020e91f9ae4b93701562fce1af4b3b6c64267234cb08e7cc0041a3df9ba9e14dd1f080000000101090000002021212121212121212121212121212121212121212121212121212121212121210a000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0b00000001030c00000001010d0000000100",
          "envelopeHex": "53545958464d543100010008000100010001000100660000012900000174000001740010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060008100c2cabad3bd2bc25c861e8dd9669360153545958414144310001000100080001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060008100c2cabad3bd2bc25c861e8dd9669360121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e9603000001746607fc527362b54735cbc536843ea00352e2f141e99689d0bbd822de7a21d162c933c487fa251cf671432270b06692d85641ff82ee1aae4b176becc5fd680b7c4212861fad441932744a98ba2f7b0cddb1692d6c37c9d1f4d9970200b501b662199aa843a6de3c1c987a235bfba0c51745feef20f52d775490c6a168925a7b88037f5ff9d9335c5016244aeb446e779b40bbb65c701fd0cce56c039282052e5653cfed40ad2a20cc3778d192868a739953afa27ebb292ee474dec8c0e35db095f2da20a7e9f047fa31e13530832557ef3a96d2d3420875bdbd146942780f1c989299aaee06374725a5b68b2dd64bf20a441bffa07710329446ab656491a73d63e20c1f4e06f0e92d3c1bfd506629364d0eb2a5fa8d9e665696b007f569d0879f156e79b28f52b0c0683ae4c0b44ad132dd9509c2436ef7b659b77578554c52849acd8784cb73cbbea1023b9870159f3a3ec43e90c31032506f2d452a789eca925c72e0dc23d60f2c469b875e7d9f4b90976359d4ab78835b197c2e10c176518cb11f3f5722e7cfc38f0c41f3bff109ad",
          "ciphertextDigestHex": "61cd3f02b0d855d935670b4e6949ac528984f87b84b1672b88f9139e154e546a"
        },
        {
          "kind": "OUTPUT_ESCROW",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060009101c283aeb8f841686caa72baea5638156",
          "nonceHex": "6608e52b8e7d104b3c7cb0e3",
          "aadHex": "53545958414144310001000100090001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060009101c283aeb8f841686caa72baea563815621212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e960300000107",
          "plaintextHex": "53545958504c4e310001000901000801000000202aa1037112e783a3cdb863536336a40c11980d1c09fcf00aa7bf156125ff1d6c0200000020c64bf33e66e9fd7c22f9249fac23b8ab36fe102a47d737a21b4bbb2b800688070300000020a6e599220a9457f205dc66650aa7c157da616c3ba83721f400308a25b53446560400000020d94dbaa4bd7bb60ed6fa7f70c71a6b6b61da00ce5546f7b19354e5dbcbf19ea70500000020e91f9ae4b93701562fce1af4b3b6c64267234cb08e7cc0041a3df9ba9e14dd1f060000000102070000000f6c69746572616c2d77656c636f6d65080000002095248263737fdf01ed256f079831c4abf8d51a065ff0be045ce5500c3d8c704a",
          "envelopeHex": "53545958464d543100010009000100010001000100660000012900000107000001070010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060009101c283aeb8f841686caa72baea563815653545958414144310001000100090001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060009101c283aeb8f841686caa72baea563815621212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e9603000001076608e52b8e7d104b3c7cb0e33378805945cfdc87f1779268d10ff09b67ca128eb23eea9af4aae0d9f42f4d83a0d388a818babbc7afb72399933d4f270766366dbb05dbb55567a113e8a954205d8837be6797cead9fb77ffd09d364613e855bfc8c07e582c2359c2534e3a30c437ec7a5b636bd8533a0777d356743652d2ec34b2167b8c0ada90984fb9b155d4a090ed09989baff2c48fd2c98f2a10da2ebbfa28bb5497604f8e8a618e07d01e55ffbccb8f7333db93f24c16fcd98e002ae54bb5856ebfd8e95017d03129d4c3d9048d4f47a812ba4071c9506f35f1aaa794e021439f5bdb9f169edfd71e72e523668495f59a39ad9e2e300cfe5dc6eb6edeea36f052372f5230ca6272ebad1f5e0dc9d5f2d70c97bff8ffe70995d6bfc8e510aa60a89",
          "ciphertextDigestHex": "b23885b7768a01e954ac6b6b8f0c01db47975dd23ad2ac06f918fcf730bc8dd3"
        },
        {
          "kind": "SELECTION_METADATA",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000a100a44f45fe7554cb37189c11267bfc0a3",
          "nonceHex": "660906b603ed7e18aeef3a37",
          "aadHex": "535459584141443100010001000a0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000a100a44f45fe7554cb37189c11267bfc0a321212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e96030000003a",
          "plaintextHex": "53545958504c4e310001000a0100020100000001030200000020312db076e5edf8234a2ae152e2377b65161b3234925f913e8c14d994897adc42",
          "envelopeHex": "53545958464d54310001000a00010001000100010066000001290000003a0000003a0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000a100a44f45fe7554cb37189c11267bfc0a3535459584141443100010001000a0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000a100a44f45fe7554cb37189c11267bfc0a321212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e96030000003a660906b603ed7e18aeef3a3769d68d0d64e06fedecff86aa5092e698fd3c85b3446f4dced446b78f95bc5a8f21a15173d83c94a2329d6cbf1cfb3584de73e41174329ec6930fe0b1e1e9789226c22740b28b3268633c",
          "ciphertextDigestHex": "c34914595f94820e08345416630dbca0639583d029459bb2abbfe75140c54531"
        },
        {
          "kind": "RETAINED_PARENT",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000b105d5da34d3ab5db820dd14711c2e65bcc",
          "nonceHex": "660aaa968f4c83e118e3864a",
          "aadHex": "535459584141443100010001000b0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000b105d5da34d3ab5db820dd14711c2e65bcc21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e96030000003a",
          "plaintextHex": "53545958504c4e310001000b0100020100000020a1fa48d0580ad34cf330beb258622722d6241b8e6ffbdb96e5e6a755582a1bea020000000102",
          "envelopeHex": "53545958464d54310001000b00010001000100010066000001290000003a0000003a0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000b105d5da34d3ab5db820dd14711c2e65bcc535459584141443100010001000b0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000b105d5da34d3ab5db820dd14711c2e65bcc21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e96030000003a660aaa968f4c83e118e3864a7fa7eed1d52c0881a9cfea31058a2182dc8fa55e75d0533b1282004fbc251e726a2f860622307ceb67b43a7d7846bffe60508995f295b9b3b20ec05ba59e939d11460ad30a3c083b655e",
          "ciphertextDigestHex": "44e30fd7fe0b0e6a2ca1a5a6e5e1ff7c34710e9eb95877b4f9db7bf3a9b7fe11"
        },
        {
          "kind": "LOSING_CANDIDATE",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000c10e4f3f18409d6e6b39c6727292dfb6498",
          "nonceHex": "660b1c028b1c35e6080b9bea",
          "aadHex": "535459584141443100010001000c0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000c10e4f3f18409d6e6b39c6727292dfb649821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e96030000000f",
          "plaintextHex": "53545958504c4e310001000c000000",
          "envelopeHex": "53545958464d54310001000c00010001000100010066000001290000000f0000000f0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000c10e4f3f18409d6e6b39c6727292dfb6498535459584141443100010001000c0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000c10e4f3f18409d6e6b39c6727292dfb649821212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e96030000000f660b1c028b1c35e6080b9bea7664dda79477c67747bc2a3d59e1ad2146b5f6164d3f3b3e6aaf45d35d237e",
          "ciphertextDigestHex": "bfb28f373b6a5dea1438ca9ad213771636817bc949dc5c8b5abba471b6d487e2"
        },
        {
          "kind": "MUTATION_HOLD",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000d106da7814be10eddf3f195f4cf8e959cb9",
          "nonceHex": "660cde877c01ebe678449d10",
          "aadHex": "535459584141443100010001000d0002000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000d106da7814be10eddf3f195f4cf8e959cb921212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e960300000228",
          "plaintextHex": "53545958504c4e310001000d01001501000000202aa1037112e783a3cdb863536336a40c11980d1c09fcf00aa7bf156125ff1d6c020000000101030000000200010400000001010500000020e80096d6f42a337db9287e0f7012f883d0ba40bb8e1063567424f76b392080a9060000002025e322124057a701754d27999dffae0c35887c59b6b65ff997d704c85f9669be0700000020212121212121212121212121212121212121212121212121212121212121212108000000205d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0900000020c64bf33e66e9fd7c22f9249fac23b8ab36fe102a47d737a21b4bbb2b800688070a00000020a6e599220a9457f205dc66650aa7c157da616c3ba83721f400308a25b53446560b00000020d94dbaa4bd7bb60ed6fa7f70c71a6b6b61da00ce5546f7b19354e5dbcbf19ea70c00000020e91f9ae4b93701562fce1af4b3b6c64267234cb08e7cc0041a3df9ba9e14dd1f0d00000001020e0000002095248263737fdf01ed256f079831c4abf8d51a065ff0be045ce5500c3d8c704a0f0000002058118799e4b68332ac41a79a465e1106be1b997dfc4f344c2624a8b2b9bdc2ac10000000010111000000010212000000200d2acd080b46cc33617f8ef9bc5b1d0ee31f5cd8304ca7fef37c9b4357b1022613000000010314000000080000000000000001150000002040d640a0b1c1063b970d8ddea9fc5477648f16830f301f4a920027f9e162496e",
          "envelopeHex": "53545958464d54310001000d000200010001000100660000012900000228000002280010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000d106da7814be10eddf3f195f4cf8e959cb9535459584141443100010001000d0002000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000d106da7814be10eddf3f195f4cf8e959cb921212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e960300000228660cde877c01ebe678449d100a4e1a98a5b621856fd93b784a7300499988041791b52dbc79b75b28f9939a2b1341406f5ccf698cebe23b662b5d37854fc2e677578ca4daad968f87e71cda81c418bb376af249e6930519fb4886ba4e87a75937de1a87a00891f63421eb3ff9b51fcb1ad53ac691dcf9574cba33babc6024dd2499b75207a1e96e3315a32b64b907e8515e7828378e2f27620701d5744df289777cfb5c10ab08f91119e31bd70f89741b41db084696902fe443b01c3f2ff3ed6cdc8eb70f60458ab9433573bc5a5aa24f251a302aa4bdf0cd3da0a73ac339199b08739bb19b80b60a555840f9c8ee7276dc2676b6b9bee6ed0f17ee65c2f6e90f9298961148cdd8c2fc54497823c236af258676c24d24ed9e00f2be0b3f6babc0d6057b6b076c5e4d28c8244649041d03591bb7c362b009702766fd5cd17abfb2ff5bfd434ac7a535c8b11198dc0c619a1702109af818812e2de2dde8d1968bd6eb81149d892a5d11fb7c97160ab96fa6fada0732adbd82b75ad760f63ad58c5eca0206f9236d469b1fab7bd851e75b8ed2471764016132361c3541f9ab90169c3d12affaf442f29f5678879dfdacd49f49b0012d609faf27a375b06fc98033e1bc127e981ad25d8e835321de03ee2618aea24645b972bfd5eebb2c75bfbac67d09453363d1e49fbe83a8794b19ecdddb224bf7add2caac74909faa85561120890078169ea5d63cd72d6f10777ee8aedfdefd8ff942939369cb711de1fff39613634afce365ff580262bc4b1f182c7e2be63e4119d8cc7d8a81062b9ee2b5b24b921eddea",
          "ciphertextDigestHex": "8e04f6f207b19b5aa02cda3e10924a57b1a373b396e4639eedbf59b307939e66"
        },
        {
          "kind": "COMPONENT_SET",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000e10e31ad9c06ef304519d8befb2060a3932",
          "nonceHex": "660dc934cd31c2d8580d6c54",
          "aadHex": "535459584141443100010001000e0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000e10e31ad9c06ef304519d8befb2060a393221212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e96030000007e",
          "plaintextHex": "53545958504c4e310001000e0100030100000020d94dbaa4bd7bb60ed6fa7f70c71a6b6b61da00ce5546f7b19354e5dbcbf19ea70200000020e91f9ae4b93701562fce1af4b3b6c64267234cb08e7cc0041a3df9ba9e14dd1f030000002063616e6f6e6963616c2d636f6d706c6574652d636f6d706f6e656e742d736574",
          "envelopeHex": "53545958464d54310001000e00010001000100010066000001290000007e0000007e0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000e10e31ad9c06ef304519d8befb2060a3932535459584141443100010001000e0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000e10e31ad9c06ef304519d8befb2060a393221212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e96030000007e660dc934cd31c2d8580d6c542890857bb71653d3325151f34e2e74ead600948fdfc157ea5c0b8616df546dee07bd400e31de036372a2e1b55ed38de26fc5e9f7b330675c695bc46dcbd5339e454820e4b9a534f3e60858d7fb68351e5856cfb013d2372933de338319786b7f5469919fa0953771a521f96bea255c86f259ac5b05f5ecff42b03279649e4e540f35f41c66393adfe05ee0f64ecb",
          "ciphertextDigestHex": "e571803d03ea41717d8c3cae5e3b7085e72f16bf65852347edd21912a6691747"
        },
        {
          "kind": "ABSENCE_COMMITMENTS",
          "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000f100379eb444bd86b2bd8a124b51796c2ec",
          "nonceHex": "660ea2f3f0078f8b166a61e5",
          "aadHex": "535459584141443100010001000f0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000f100379eb444bd86b2bd8a124b51796c2ec21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e960300000020",
          "plaintextHex": "53545958504c4e310001000f010002010000000400000806020000000302030c",
          "envelopeHex": "53545958464d54310001000f000100010001000100660000012900000020000000200010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000f100379eb444bd86b2bd8a124b51796c2ec535459584141443100010001000f0001000100000066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000f100379eb444bd86b2bd8a124b51796c2ec21212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e960300000020660ea2f3f0078f8b166a61e544a7e0adacd0b46156c995e5c4781539aeec35bb3876d214e38ea8f4d378067214744731440b989151082f19e3a3d3e0",
          "ciphertextDigestHex": "9497b53b5c85ac6a9ce77f48e526cbe0d3466a4a7d27fbcdab2bf46fed26f098"
        }
      ],
      "manifest": {
        "keyHex": "535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006001000",
        "bytesHex": "535459584d414e3100010000000f0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000110ee198f351dbe0180a4af73689ae1ac1b000100017e3b0d8071c0adf7899dab3ec4b1a0c357eaf163b5185a497b1a159f4c5ad0ef0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060002109720363a357379d720b9c00c1bc92488000200012fce924fdfbd5aea7f1d7f449e5c51d9ef39094b938971e1f124e4160b41dac50066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000310bbc71a6764adaedf0ad0b60e7900e40f000300010ae228734a67c68097633baa45224db6de717305471d49732eb1b6a847ced7de0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000410918b5a723c830e286b7e7a601c0be4ee00040001af978e39a24641b138ef87e2300c777deb4adb648ce78304eb2a8667a60a59710066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060005100d08b65ec848deeaa20ffe221f6eb86e00050001e4edfc9d6c520839da2fb06b84984b9baaad705c8ad93477a70b6d35335301530066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000610288c3c165ae84ad0d62462f4170cc2f400060001025f2b6e2df2893cb6e3cd4639add023eaf28efba8781e0cf536bed501faa7580066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000710c2f4aa5cd449e6792c5e56aa88a8efd10007000136d32e21d0c9b13bb4c57bad3c7a1b6a9976148fc8c0bfe17b9bb5d85ded5d510066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060008100c2cabad3bd2bc25c861e8dd966936010008000161cd3f02b0d855d935670b4e6949ac528984f87b84b1672b88f9139e154e546a0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060009101c283aeb8f841686caa72baea563815600090001b23885b7768a01e954ac6b6b8f0c01db47975dd23ad2ac06f918fcf730bc8dd30066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000a100a44f45fe7554cb37189c11267bfc0a3000a0001c34914595f94820e08345416630dbca0639583d029459bb2abbfe75140c545310066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000b105d5da34d3ab5db820dd14711c2e65bcc000b000144e30fd7fe0b0e6a2ca1a5a6e5e1ff7c34710e9eb95877b4f9db7bf3a9b7fe110066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000c10e4f3f18409d6e6b39c6727292dfb6498000c0001bfb28f373b6a5dea1438ca9ad213771636817bc949dc5c8b5abba471b6d487e20066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000d106da7814be10eddf3f195f4cf8e959cb9000d00028e04f6f207b19b5aa02cda3e10924a57b1a373b396e4639eedbf59b307939e660066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000e10e31ad9c06ef304519d8befb2060a3932000e0001e571803d03ea41717d8c3cae5e3b7085e72f16bf65852347edd21912a66917470066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000f100379eb444bd86b2bd8a124b51796c2ec000f00019497b53b5c85ac6a9ce77f48e526cbe0d3466a4a7d27fbcdab2bf46fed26f098",
        "plaintextHex": "53545958504c4e31000100100100020100000842535459584d414e3100010000000f0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000110ee198f351dbe0180a4af73689ae1ac1b000100017e3b0d8071c0adf7899dab3ec4b1a0c357eaf163b5185a497b1a159f4c5ad0ef0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060002109720363a357379d720b9c00c1bc92488000200012fce924fdfbd5aea7f1d7f449e5c51d9ef39094b938971e1f124e4160b41dac50066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000310bbc71a6764adaedf0ad0b60e7900e40f000300010ae228734a67c68097633baa45224db6de717305471d49732eb1b6a847ced7de0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000410918b5a723c830e286b7e7a601c0be4ee00040001af978e39a24641b138ef87e2300c777deb4adb648ce78304eb2a8667a60a59710066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060005100d08b65ec848deeaa20ffe221f6eb86e00050001e4edfc9d6c520839da2fb06b84984b9baaad705c8ad93477a70b6d35335301530066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000610288c3c165ae84ad0d62462f4170cc2f400060001025f2b6e2df2893cb6e3cd4639add023eaf28efba8781e0cf536bed501faa7580066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000710c2f4aa5cd449e6792c5e56aa88a8efd10007000136d32e21d0c9b13bb4c57bad3c7a1b6a9976148fc8c0bfe17b9bb5d85ded5d510066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060008100c2cabad3bd2bc25c861e8dd966936010008000161cd3f02b0d855d935670b4e6949ac528984f87b84b1672b88f9139e154e546a0066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf62200000000000000060009101c283aeb8f841686caa72baea563815600090001b23885b7768a01e954ac6b6b8f0c01db47975dd23ad2ac06f918fcf730bc8dd30066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000a100a44f45fe7554cb37189c11267bfc0a3000a0001c34914595f94820e08345416630dbca0639583d029459bb2abbfe75140c545310066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000b105d5da34d3ab5db820dd14711c2e65bcc000b000144e30fd7fe0b0e6a2ca1a5a6e5e1ff7c34710e9eb95877b4f9db7bf3a9b7fe110066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000c10e4f3f18409d6e6b39c6727292dfb6498000c0001bfb28f373b6a5dea1438ca9ad213771636817bc949dc5c8b5abba471b6d487e20066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000d106da7814be10eddf3f195f4cf8e959cb9000d00028e04f6f207b19b5aa02cda3e10924a57b1a373b396e4639eedbf59b307939e660066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000e10e31ad9c06ef304519d8befb2060a3932000e0001e571803d03ea41717d8c3cae5e3b7085e72f16bf65852347edd21912a66917470066535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf6220000000000000006000f100379eb444bd86b2bd8a124b51796c2ec000f00019497b53b5c85ac6a9ce77f48e526cbe0d3466a4a7d27fbcdab2bf46fed26f0980200000020cd4771b5f965d9b74d37867f278dfd35e12bbe57ca648a9fcfe25ebf8b2757a5",
        "nonceHex": "660f46214096926bfeef18e0",
        "aadHex": "53545958414144310001000100100001000100000056535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622000000000000000600100021212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e96030000087b",
        "envelopeHex": "53545958464d54310001001000010001000100010056000001190000087b0000087b0010535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622000000000000000600100053545958414144310001000100100001000100000056535459584b455931000102212121212121212121212121212121212121212121212121212121212121212148d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622000000000000000600100021212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b0248d642b810cf7c41714e0b3637d4e6709a5f473b250e5d11d3978336b6eaf622abca638fe4ee69a1c52676b882cd8a23bbf43b24e737c0d2c62bbaa172dd44480000000000000006baf04c2dd2f0244482e293c7fe41f7391841b751237dc381984d6eb50c1e96030000087b660f46214096926bfeef18e0dea2244081c150b8813692a362b5f59c7a12d1c60c0a5c2505a8f03fba086122c8bef9e8aa2416c333114ce997b56b1777979f383d681098e99931152693d679ac9bb3c8b6d08057374737a5d12f53c696cf15bf5f561aaa1a25d7e07b3ac1ccda7c08f390be2dab8e374ffc429e9c3d57afb9135c1dbbaea609777d0aef78971a2aad0353438f23f45655b457c45a2050f4ab852daaed288f740fbeceaca3598377f020aa8e40ec80e2a24b6adc7f9f1c5bfd1967b53cbb7cb20b80060ea73cc33eb2c53b75d8d723931e751902ceb5ebebffdb1d89da94707486a737c864c918c45f7cd051cd20d11930a9679d93f45b2f960cd1572b63cb8159e884564c41a0a99a500200bda4cad1c7ab9cbf8a7f30c423edef6280fab91993b7b69a26e67b8e5ea972c059032e9bcdab2bcdcb435212c4dd296dd079ae98be81e2928fe012e376cd2c557c7a724ab1c8fd2e7d0445b0c221a884077f3aabd88a9c9ffc6b3ebf5d4135da90e93ce6591bf72c06dcb7eb7cdb93ccd76844ac386808fb96835b71a6fb5f04d28ce98e0e6f7f33cd82ad1b6e37539cb4d317b1ad30456771627f1b56d165489dba0a2d5549fa6d3bc1e879c82e55706a71219e756a99c8f9ec4c5d66de45545ee21da6dafc46f5228c86a5f126f486e3b79a93f20f76fa00ced28398edb8d5d90ae3642dd6e04139f403c08198db1ed2f22bf81fddf6b140c9385095302b9a3be8186474f9d5f3e187a3aaa91a8ae59c03c3eb27f430979dea4cff7d5c637707f828c6ab12a29f5b65855fe4609f25f1c9fcf322630a6b1230a5f794773d2c11388d348f283b9bfce2db7b1f2a7189df8b5b61da0b1364a7011ad809b21d708e90f3ca4e34f15b75fa779f00f84900c178909cb8496261bda2cc2daa507ee9f31f5af1f48e5c1a8db8db18bb75b78addd281686bca0846265b645ad15cddd960f9699ea5658e4ada0e04f3cdd7131aaec16fd39c72036af9dfd5a93bced5a53f594156ed6dde042bc1fadfa8e13e74864c455b1cc2528339a7a9f5daf8c879d3cefcbcb07f543dd5fb55c2e8ca96cfd13614f26b7ea3cb702b4482ebc0a4ed513d1bc3e3db9902610f93194467310c488d1b7148c0a9b645a8ff0ba0ee323c135a772de63ba0f4cf3a52307af430a607e7d53cc486e20f8792c173d4531d9323bba835e2d04902ae41ff80384ba6c5164f89b51e74ce4c7b0557fe6ee081dea52e88a02c16de53b7a19feab242c1725fb70941af9336f6eabcbca05c2c26011d77ba76d0db16ec0afa1c859a5072ad6bb920e3e5d70ed83b03a39a12f650801432baff731b3828d36d7d18350ed340d20881ec367172b8689c85a6e7f702d6f3a1036aa0304bcf7145ebb7b76c0e4068a354211af9920c79264d4079bf4565abba2fac589f803b82d51931705cd9d42859ec709d40c0bb7fb661f08ff15c9d338263a253809e574e3ca025b7912072c09f2257713977c2b437779202fba82471dcd56e4ba99c72cc3db09d996f97b1c9f9c910b5fbbba678772c8a410fa83518d84fd13df6d8955985f00e2d62f52c9a01ed9881b40f5f7291c84fa74a434ee0745070e7aa2dc9021aadf72928473d9df1fad04f3e4852a7d57a9644fc1ef9267a157f53df7a6eb7a05c9a0d249e68990b0701c4968116425a81253be82fd0add29fc8eb73e1cdba5cdeea74fa2f8e77f677ae69b8cb2124bb15d5a32688f891bde542f0f5fe36238a33a33ffbca648998a6980102272a031bd28126e5a686d982dc1cd9d207d9186f0607f2ce25bc4734facc96c200995e04b8e3ee9ab3f8665f02e60b292ac4860d6cccc439cb6b429cc0206ac4e8709e64ef29555727083401cdefc5ac0967b6919cfc8f4c275979be09792cb51c9aff30e0205859b0369be2b56672bd10e48eb222c08c209c9306b7b3d12fd3b68c81e71f0fdd116ba70c909f1c620e4ae43e0aa173d92aead7cc4177e540fec70707ab9bdbd6fc6b7fc1e9ef791316e7a1cb0d63ffb4ab40230f8cc9b2806b83416d08efe7c946778fec990837ac7ce855694ab817581217011ce8f50a5bfe6a371f9720721a649fb1801c5873d0632aadcaf98c45ed81ae0e36368f7a56352fe4fc27e9127f19f865aa76591389feabb390aa8786f77964eff093890d6b8e168aceb0a5b0242a88105300396e2f9d299f4f1ae2f97cc0d457f740e751bf431eaa61626ad8b411c5f41ceb3919eaafbc9d010d4d177bc6561782311d87cf6050af19f786e655eb41e63f2690b9b926c670e4ad5d42e0801a75f33a6143ecbc1bddeda4ca1ec2c1176f5cf8875784474a9a05b44773b56480a4c22e4541e6cda136c7b7accb9a4670324794e730116b7a87efc1a520a063a86087d45dd57f2d46d0a8b0dfb6688e4519b26876399b16b9d683ff91a6a5deaf386b0041fe9e95f8c650a4adeb571e817edd01f0ad3efb374162eb30e0ee33c54392a293d4e3054df906c400bf0e58fd5129a542ae777551882c444c6e7fa5ac415fd660d5382f4f2932e34a6951e06c753422549d1a2db5afbcc87a91a3d33127085749254ac8cb0803483f4606cd2405f73ee5ba9d7bee68d28511fc2279c9a77a7f92e387029e3730857a0f7331e783fa44c0ba5dc2b995b5ede53957db6ce28d36d15546698c647ed04957aa7f3890fff93b0a237a1d7a17aacb18971d7ca632c18002236cc676391a10056f22859994c9836cfa2331bb4b972833d77b017833651104e08e43e08f06f7ff5aae88038de3fb36cfaaabf31c42f80ca7561168596d91763c9e6980e0a29696e4b76f9ce67596188183ab6d50cf6140b8e7db4023b1a77a8df694879bb2162b9869e230b671e305ba83fe2f2ecc5a17abeb937f7bc53416a11b3d22900888d6a5eb3da03cc65b45ea328737d5ac3358e0a8ef39f6bc1db99c3c5d92ede525fb95da171d2edbbd610b475422ade5f7ad742e4171e17452538c10a6368ddbc73d6be2d2ae7311f1916976548c328c1fbbbd03d11a3b050c2e16fe3a27b9d451c100714e2bab24b04471806fb9cd4a6f089baade8ecb848973ede652e14c7b793bc5c172ed35fb386f90",
        "ciphertextDigestHex": "72ae8679da8f2e35c4bb2817d7eddbf86204e1ac6a69c0ca82c5837193165eef"
      },
      "selector": {
        "keyHex": "5354595853454c3100012121212121212121212121212121212121212121212121212121212121212121",
        "selectedGeneration": 1,
        "candidateGeneration": 1,
        "plaintextHex": "53545958504c4e310001001101000a0100000008000000000000000102000000205d8a18f17b63545d548a371c997ba493eb942ff5b18bf7c83927491144790e440300000020318a13dc612ff8694d7888095c584d467bc0009a12d5a70110f381cdf4b0a8b0040000002040d640a0b1c1063b970d8ddea9fc5477648f16830f301f4a920027f9e162496e050000000101060000000800000000000000010700000036535459584b4559310001012121212121212121212121212121212121212121212121212121212121212121000000000000000100100008000000205d8a18f17b63545d548a371c997ba493eb942ff5b18bf7c83927491144790e440900000020318a13dc612ff8694d7888095c584d467bc0009a12d5a70110f381cdf4b0a8b00a0000002040d640a0b1c1063b970d8ddea9fc5477648f16830f301f4a920027f9e162496e",
        "nonceHex": "11102e902116f6552d6773f1",
        "aadHex": "5354595841414431000100010011000300010000002a5354595853454c310001212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c00000148",
        "envelopeHex": "53545958464d5431000100110003000100010001002a000000ad000001480000014800105354595853454c31000121212121212121212121212121212121212121212121212121212121212121215354595841414431000100010011000300010000002a5354595853454c310001212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121215d7f97afb28ee85e05aa9278044467ef6ed3fe0b1162195b07edfc738910126b01000000000000000198817e60d6693c8f10642099c76ac0fa757bcc8d1f892e4109ff62b25a22534c0000014811102e902116f6552d6773f178cb9633065492ee033bdee9eb44f654ac64165dfedc2a32e3c229a79fa405efd48bf998ec40994fe236d14a70150bcfcf2e69eb23277b611d831c53427d9f752a49732ef009194a50f9be50b0924becab39fcca28860e9c1496ff534ebb11beb19a006585502b27e05d04366995d16d45e0fa31932a13499f971f71a6e368c92449bffab0265b9129a0c7f5707700760f98e5db99a8fc8f85ac402b947e004c95e31f5a2ab1d4f157e8b3afd7bf540a5fc3821fef93d24f0074c1d4869b8aece018a70e6501f731782298d20c8eb67c4521a21b8a301bc392fe10dc9237e877126a25587364c83bd97d603932ba245248c60b397fdf25945ace9f24ae335661e204d02536cbc70067de8b819b9bf2fcd8386fce0e92cb92dd71936ea31248404e7ada0fdc65fc7b4aff07e263230b53aed77e68607ba31ada85049812a76bcc8ca4f8381f8ec533bf0ab1beaa129d78bb1082ab8b9506f4"
      },
      "keyedRootHex": "f187a5af559aa6cf895fccf8827a2682ed6311d7f7320a558266c0031533ea45",
      "authorityRule": "fixed selector is byte-identical to FMT-KAT-EMPTY and names the pre-session EMPTY generation as sole authority with no bound candidate; this complete immutable non-authoritative SESSION-scoped candidate is reachable only by RECONCILE_INDETERMINATE deriving its locator from the retained MUTATION_HOLD record key; after SS memory loss it is preserved debris and readback is COMPLETE_OLD"
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
