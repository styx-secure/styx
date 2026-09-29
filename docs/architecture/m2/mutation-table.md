# M2 complete mutation and record-store transaction contract

Status: normative candidate for C-MUT under Issue #324. The exact bytes of this file and the external evidence bundle require separate owner hash-ratification before C-FMT, C-RET, O-SCEN, or dependent implementation starts.

## 1. Scope and normative language

This document is the normative logical mutation and record-store (`RS`) transaction contract for the exact M2 C-API profile. **MUST**, **MUST NOT**, **REJECT**, **WARN**, and **BLOCK** are normative.

The machine-readable record in section 12 is normative and closed. Prose clarifies it but does not widen it. A conforming validator MUST reject duplicate JSON keys, unknown or missing fields or enum values, duplicate rows, overlapping row signatures, and any row, component, outcome, or crash boundary that is absent or extra relative to that record. `WARN` is informational only for the specifically enumerated unratified F-WASM provenance; it MUST NOT turn a rejection into acceptance or establish implementation authority. Every other conformance violation is `REJECT`. A conflict with the ratified C-API is `BLOCK`.

This contract defines logical identity, ownership, indivisibility, authority selection, output quarantine, and recovery facts. It does not select a physical record key, byte encoding, canonical serialization, database schema, IndexedDB transaction design, AAD layout, keyed-root construction, HKDF label, key version, migration, compatibility policy, disposal schedule, or recovery user experience.

## 2. Authority and ownership

`AP` owns opaque request and output bytes and application authorization only. It cannot choose or attest an authenticated mutation fact, candidate, parent, binding/profile fact, operation identity, commit outcome, or reconciliation evidence. Application identity, role, authority, causality, freshness, or business truth is never inferred from an M2 mutation.

`SS` validates the exact profile and binding, authenticates inputs, derives transitions and candidates, and stages a complete logical mutation. `SS` memory, ciphertext, plaintext, or local optimism is not durable authority.

`RS` assigns or co-assigns the fresh operation identity, authenticates and durably commits the complete mutation, and supplies commit/readback/reconciliation evidence. `TR` is absent. No result proves transport publication, delivery, receipt, ordering, retry, or exactly-once delivery.

One vault-owned logical mutation is indivisible. Its four C-API components are the session transition, binding metadata, replay/retention state, and authenticated-manifest update. Every mutation also includes commit-result evidence bound to the operation identity. A component that does not change is explicitly present as `UNCHANGED`; it is never omitted. Row-specific KeyPackage consumption, output escrow, selection metadata, retained-parent reference, and losing-candidate evidence are included only where the closed row table requires them. Missing or extra components reject before an RS request.

## 3. Closed `MutationEnvelope`

Before any RS commit request, `SS` and `RS` MUST form exactly one closed `MutationEnvelope` with every required field listed in the normative record. Logical digests and references are abstract identifiers; this document neither defines their bytes nor requires a canonical representation.

The `operationIdentity` MUST be fresh, non-reusable, and assigned by `SS_RS`, never by `AP`. It is not the C-API `requestId`. An AP-originated identity, a reused or duplicate identity, or a stale parent detected strictly before an RS request is `FAIL_CLOSED_INTERNAL`: candidate and escrow are discarded, no request is sent, and no commit-result evidence exists. If no existing C-API disposition can represent a proposed condition, work is `BLOCK`, not a new code.

The envelope binds the exact operation and C-API scenario, original API state, original authoritative digest/reference, exact binding/profile identity, complete candidate digest/reference, exact component set and its digest/reference, held-output kind and digest/reference when present, and expected success code/state. It also binds the reconciliation identity. No envelope field gives AP mutation authority.

Commit-result evidence is usable only when RS-authenticated and when its operation identity, original-authority digest/reference, candidate digest/reference, complete-mutation-set digest/reference, expected original state, binding, and profile all match the envelope. Unknown, stale, cross-session, cross-binding, cross-profile, duplicate, conflicting, or mismatched evidence fails closed and cannot select or discard a candidate.

## 4. Complete mutation rows

The seven and only seven C-API `RS_TRI_STATE` rows are `CAPI-S001`, `CAPI-S006`, `CAPI-S009`, `CAPI-S010`, `CAPI-S014`, `CAPI-S016`, and `CAPI-S017`. Their exact component sets and dispositions are in `mutationRows`.

* `CAPI-S001` stages founder state, initial binding/profile metadata, replay/retention baseline, authenticated manifest, result evidence, and quarantined Welcome bytes.
* `CAPI-S006` stages joined state and one-shot consumption of the matching SS/RS-owned local KeyPackage in the same mutation. It has no output.
* `CAPI-S009` stages sender-ratchet advancement and protected-application escrow. Its epoch-preserving transition leaves any CAPI-S014 selection eligibility and retained parent unchanged.
* `CAPI-S010` stages receiver-ratchet advancement and replay acceptance with plaintext escrow. Its epoch-preserving transition also leaves selection eligibility and retained parent unchanged.
* `CAPI-S014` stages the local update, epoch-window advancement, eligibility metadata, and the retained parent reference required by CAPI-S017, with protected Commit escrow.
* `CAPI-S016` stages the peer update and epoch-window advancement, invalidates CAPI-S014 eligibility and its retained-parent selection role, and invalidates any previously retained losing-candidate evidence. It authorizes no new losing-candidate retention and has no output.
* `CAPI-S017` is the only internal-envelope stale-parent exception after C-API P09 has accepted the two-candidate shape. It stages one indivisible selected complete state, terminates selection eligibility and the retained parent's selection role, and retains bounded non-authoritative losing-candidate evidence, with `selectedCandidateRef` escrow. If the current candidate wins, `SESSION_TRANSITION` is explicitly unchanged; if the incoming candidate wins, it is changed. The loser can never later become authoritative from the old parent.

C-RET owns material lifetime. These rows define logical retention and selection effect, not disposal timing.

## 5. Closed outcomes and output escrow

For every mutation row, RS returns exactly one logical outcome from `COMMITTED`, `NOT_COMMITTED`, and `INDETERMINATE`:

* `COMMITTED` atomically makes the complete candidate, matching authenticated commit-result evidence, matching logical root, and any escrow authoritative exactly once. It advances C-API state as specified and permits release of the same escrowed output.
* `NOT_COMMITTED` is accepted only from authenticated RS evidence that the original request is terminal and can no longer commit. It discards candidate and escrow and leaves or restores the complete original authority. Nonterminal absence is `INDETERMINATE`, not `NOT_COMMITTED`.
* `INDETERMINATE` includes timeout, lost response, and every absent, failed, or unknown post-request result. The original authority remains selected, exactly one immutable held mutation is retained, API state becomes `RECONCILIATION_REQUIRED`, and the response contains `commitOutcome: INDETERMINATE`, `originalStateBefore`, and an opaque `reconciliationRef`, with no operation output. Blind retry and every operation except `RECONCILE_INDETERMINATE` are forbidden.

The five escrow kinds are Welcome, protected application bytes, opened plaintext, protected Commit bytes, and `selectedCandidateRef`. Escrow bytes and their digest/reference belong to the same logical mutation as the state candidate and remain quarantined until matching `COMMITTED` evidence exists. A successful original response releases escrow under the original success code. After ambiguity, CAPI-S020 or CAPI-S022 returns the already committed escrow as `originalOutput` with `originalSuccessCode` under `RECONCILED_COMMITTED`; those rows are reachable only when AP already holds the `reconciliationRef` from an earlier `INDETERMINATE` response. Reconciliation MUST NOT replay the SS transition or regenerate security-sensitive bytes.

The original-response path and post-`INDETERMINATE` reconciliation path are distinct. On the original path, terminal `COMMITTED` selects complete new authority and terminal `NOT_COMMITTED` restores complete old authority; either resolves the mutation hold immediately. If original `COMMITTED` response emission is interrupted, SS retains internal reconciliation evidence as C-API requires, but no AP reconciliation row is claimed unless AP previously received a `reconciliationRef`; terminal `NOT_COMMITTED` retains no hold or escrow. On the post-`INDETERMINATE` path, matching committed evidence selects authority, while the hold and committed escrow remain in `RECONCILIATION_REQUIRED` only until the adapter-local response-emission call returns success. That local success is the clearing event; it is not an AP receipt acknowledgement. If the call fails or is interrupted, AP already has the reference and may repeat CAPI-S020/S022, receiving the same escrow bytes. A matching terminal `NOT_COMMITTED` reconciliation clears the hold when its no-output CAPI-S021/S023 response is formed; it never needs output replay.

`RESTORE`, `NO_CHANGE`, `NOT_COMMITTED`, `INDETERMINATE`, and `REJECTED` expose no operation output. AP receipt and exactly-once delivery are non-claims: if a response is lost after AP received bytes, reconciliation may return those same escrow bytes again. C-FMT owns persisted encoding and C-REC owns recovery consequences.

## 6. Reconciliation

Reconciliation is idempotent for original states `EMPTY` and `ACTIVE`. AP may echo only the opaque reference previously emitted by SS; AP cannot supply or override the RS outcome.

Matching proven `COMMITTED` on the post-`INDETERMINATE` path selects the already-staged candidate exactly once and reads committed escrow without transition replay. If the adapter-local response-emission call fails or is interrupted, the hold remains logically unchanged except for its authenticated committed-result status, API state remains `RECONCILIATION_REQUIRED`, and AP can repeat CAPI-S020/S022 because it already holds the earlier reference. Only successful return from that local emission call clears the hold. Matching terminal `NOT_COMMITTED` discards candidate and escrow and clears the hold when the no-output CAPI-S021/S023 response is formed. Continued `INDETERMINATE` is CAPI-S024 and leaves the hold logically unchanged. After clearing either terminal reconciliation, a repeat follows CAPI-G008 or CAPI-G016 as `NO_RECONCILIATION_PENDING`, with unchanged authority and no output. Original terminal responses are not CAPI-S020 through CAPI-S023 and follow the distinct original-response rules in §5.

CAPI-S028 reference mismatch rejects without mutation. Any mismatched reference, operation identity, candidate, parent, binding, profile, component set, original state, or RS evidence likewise fails closed and leaves the hold unchanged. The minimum facts recoverable by C-REST/C-REC are the full envelope identity, original authority, immutable candidate and component-set identities, escrow identity/content, reconciliation reference, expected success, and authenticated RS evidence. This requirement chooses no persistence format.

## 7. Serialization and concurrency

The D13/C-API `singleWriter` precondition is one worker and one writer per browser profile, enforced outside the adapter by I-LOCK. Mutating requests are serialized, and at most one mutation may be unresolved. A request arriving while a hold exists is `RECONCILIATION_REQUIRED` according to CAPI-G017 through CAPI-G023.

CAPI-S017 is the sole exception to an internal envelope original-authority reference becoming stale after C-API P09 has accepted the authenticated two-candidate shape; it is not an exception to C-API precedence, single-writer, or one-hold rules. An unrelated-parent Commit is still CAPI-S019 `UNSUPPORTED_COMMIT_SHAPE` at P09. CAPI-S017 still commits one selected complete mutation. CAPI-S011 and all rejection, restore, and reconciliation rows with C-API persistence `NONE` issue no new RS commit and create no mutation.

## 8. Crash boundaries and failure atomicity

Every named boundary in `crashBoundaries` has exactly one disposition for each listed memory condition. RS readback yields only complete old authority, complete committed new authority with matching root/result/escrow, or—only while SS memory is retained and RS remains uncertain—original authority plus one immutable hold. After worker-memory loss while RS work was uncertain, C-REC/RS authenticated readback must terminally classify `COMPLETE_OLD` or `COMPLETE_NEW` before another operation; it cannot expose an in-memory hold or promote a transient candidate. This is a logical recovery precondition, not a persistence-format choice. A committed result and escrow readback permit C-API reconciliation without regenerating the transition. There is never a partial mixture or two authoritative states.

Injected failure strictly before the commit point leaves the complete original mutation set and root authoritative. Injected failure after the commit point exposes the complete candidate set and matching root, result evidence, and escrow on readback. Failure strictly before any RS request is CAPI-E025 `FAIL_CLOSED_INTERNAL`; candidate and escrow are discarded and no RS evidence exists. The tri-state begins only once a request may have reached RS. Quota, abort, worker termination, exception, tab closure, and response loss are classified by this boundary and authenticated RS evidence, never guessed from SS memory.

## 9. No-mutation coverage

The `noMutationRows` record covers every C-API row whose persistence is `NONE`: all 16 state-matrix rows, all 25 error-definition rows, and all 22 decision rows. Each preserves C-API precedence, result kind, state, and output rules. `RESTORE` performs no new mutation; restart/readback classification belongs to C-REST/C-REC. CAPI-S011 is an exact duplicate `NO_CHANGE` with no plaintext and no transition. CAPI-S020 through CAPI-S024 and CAPI-S028 resolve or inspect the one existing hold and never create a new commit request.

## 10. F-WASM evidence boundary

F-WASM is unratified read-only feasibility evidence at commit `bc20e9273b9ae437a6416745b52793ea36ecbc76`, parent `e1538ef9c070e463a8256872a3fd0882c424e2ef`. Its result is `POSITIVE`: scratch-state pre-apply staging executes for seven classes—creation, Welcome onboarding, protect, open, outbound self-update, inbound self-update, and the two-candidate case. `COMMITTED` selection executes directly for six classes and, for Welcome onboarding, through matching durable-`COMMITTED` readback reconciliation after `INDETERMINATE`; only Welcome executes that ambiguity/reconciliation path. The probe contains a `NOT_COMMITTED` discard branch, but does not execute it. Its two-candidate test stages both candidates against a still-authoritative parent; it does not replace an already committed local update.

That evidence does not ratify this contract and does not authorize the probe-only `AuthoritySlot` as product design. It proves no IndexedDB/RS atomicity, durable receipt, output-release behavior, worker lifetime, crash recovery, production adapter, or implementation conformance. Those limitations produce the sole permitted `WARN`; they never relax a `REJECT` or `BLOCK`.

## 11. Non-claims and ratification gate

This contract makes no application-semantic, transport, delivery-receipt, arbitrary retry, coherent whole-profile rollback-prevention, physical deletion, zeroization, migration, legacy import/cleanup, Issue #312 extension, arbitrary topology, fallback-profile, public-SDK, or production-activation claim.

The SHA-256 of this final document and the SHA-256 of the external evidence bundle MUST be computed from literal final bytes and recorded together in an external owner-ratification submission. They cannot be embedded as the document's own normative digest without changing the bytes being hashed. Until the owner ratifies both exact values, status remains `PENDING_EXTERNAL_HASH_RATIFICATION`; C-FMT, C-RET, O-SCEN, and dependent implementation remain blocked. Any byte change invalidates review and ratification.

## 12. Machine-readable normative record

<!-- styx-m2-mutation-table-json:v1:start -->
```json
{
  "schema": "styx-m2-mutation-table/v1",
  "closed": true,
  "status": "PENDING_EXTERNAL_HASH_RATIFICATION",
  "validation": {
    "defaultViolation": "REJECT",
    "blockConditions": [
      "C_API_BYTE_OR_SEMANTIC_CONFLICT",
      "NO_EXISTING_C_API_DISPOSITION",
      "FROZEN_PROVENANCE_DRIFT",
      "UNRESOLVED_COMPONENT_OR_OUTCOME_BOUNDARY"
    ],
    "warningEnum": [
      "F_WASM_UNRATIFIED_FEASIBILITY_ONLY"
    ],
    "warningEffect": "INFORMATIONAL_ONLY_NEVER_ACCEPTS_INVALID_INPUT_OR_ESTABLISHES_AUTHORITY",
    "reject": [
      "UNKNOWN_FIELD",
      "MISSING_FIELD",
      "UNKNOWN_ENUM_VALUE",
      "DUPLICATE_JSON_KEY",
      "DUPLICATE_ROW",
      "OVERLAPPING_ROW",
      "MISSING_OR_EXTRA_ROW",
      "MISSING_OR_EXTRA_COMPONENT",
      "AP_ORIGINATED_OPERATION_IDENTITY",
      "STALE_OR_MISMATCHED_EVIDENCE",
      "NONTERMINAL_NOT_COMMITTED",
      "BLIND_RETRY",
      "PARTIAL_COMPONENT_APPLICATION",
      "UNSUPPORTED_CONCURRENCY"
    ]
  },
  "provenance": {
    "issue": 324,
    "card": "C-MUT",
    "exactBase": "e1538ef9c070e463a8256872a3fd0882c424e2ef",
    "cApi": {
      "path": "docs/architecture/m2/adapter-contract.md",
      "commit": "00ae21802396b85f36acea703060f140f40f6407",
      "sha256": "b77d39fbb412b0eba3a579ebf6053408186a4c11f0de07b8727b4e1147305ad9",
      "ratification": "issue-319-comment-5886838783"
    },
    "fWasm": {
      "commit": "bc20e9273b9ae437a6416745b52793ea36ecbc76",
      "parent": "e1538ef9c070e463a8256872a3fd0882c424e2ef",
      "ratification": "UNRATIFIED",
      "draftPullRequest": 322,
      "ciProvenanceOnly": "GREEN",
      "result": "POSITIVE",
      "files": [
        {
          "path": "styx-js/test/crypto/m2/wasm-staging/README.md",
          "sha256": "9ada4ed0dba0311e6b0731cd14165527b876e81efa73414d04c72554d895dce9"
        },
        {
          "path": "styx-js/test/crypto/m2/wasm-staging/staging.test.js",
          "sha256": "a913781aee5708c0d83f22aedd5c199d461f908fdafd8ac6e2feff039b8385fd"
        }
      ]
    }
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
  "enums": {
    "state": ["EMPTY", "ACTIVE", "RECONCILIATION_REQUIRED"],
    "operation": ["CREATE", "RESTORE", "JOIN_WELCOME", "PROTECT_APPLICATION", "OPEN_APPLICATION", "SELF_UPDATE", "APPLY_PEER_UPDATE", "RECONCILE_INDETERMINATE"],
    "commitOutcome": ["COMMITTED", "NOT_COMMITTED", "INDETERMINATE"],
    "resultKind": ["SUCCESS", "NO_CHANGE", "NOT_COMMITTED", "INDETERMINATE", "REJECTED"],
    "successCode": ["CREATED", "RESTORED", "JOINED", "APPLICATION_PROTECTED", "APPLICATION_OPENED", "SELF_UPDATED", "PEER_UPDATE_APPLIED", "CANDIDATE_SELECTED", "RECONCILED_COMMITTED", "DUPLICATE_IGNORED"],
    "errorCode": ["UNKNOWN_FIELD", "INVALID_REQUEST", "UNKNOWN_VALUE", "UNSUPPORTED_API_VERSION", "UNSUPPORTED_PROFILE", "BINDING_MISMATCH", "UNSUPPORTED_OPERATION", "SESSION_ALREADY_EXISTS", "NO_ACTIVE_SESSION", "NO_STORED_SESSION", "STORED_SESSION_INCOMPATIBLE", "RECONCILIATION_REQUIRED", "NO_RECONCILIATION_PENDING", "RECONCILIATION_REFERENCE_MISMATCH", "UNSUPPORTED_ONBOARDING", "WELCOME_NO_MATCHING_KEY_PACKAGE", "UNSUPPORTED_UPDATE_FORM", "UNSUPPORTED_COMMIT_SHAPE", "KEY_PACKAGE_ALREADY_CONSUMED", "AUTHENTICATION_FAILED", "AUTHENTICATED_STATE_INCONSISTENT", "EPOCH_OUTSIDE_RETAINED_WINDOW", "FUTURE_EPOCH", "VALUE_OUT_OF_RANGE", "FAIL_CLOSED_INTERNAL"],
    "component": ["SESSION_TRANSITION", "BINDING_METADATA", "REPLAY_RETENTION_STATE", "AUTHENTICATED_MANIFEST_UPDATE", "COMMIT_RESULT_EVIDENCE", "KEY_PACKAGE_CONSUMPTION", "OUTPUT_ESCROW", "SELECTION_METADATA", "RETAINED_PARENT_REFERENCE", "LOSING_CANDIDATE_EVIDENCE"],
    "componentDisposition": ["CHANGED", "UNCHANGED", "CHANGED_OR_UNCHANGED_BY_SELECTED_CANDIDATE", "CREATED", "CONSUMED", "HELD", "ESTABLISHED", "INVALIDATED", "RETAINED_NON_AUTHORITATIVE", "INVALIDATE_PRIOR_AND_RETAIN_CURRENT_NON_AUTHORITATIVE", "TERMINATED"],
    "outputKind": ["NONE", "EMBEDDED_TREE_WELCOME", "PROTECTED_APPLICATION_BYTES", "APPLICATION_BYTES", "PROTECTED_COMMIT_BYTES", "SELECTED_CANDIDATE_REF"],
    "selectionEffect": ["NOT_APPLICABLE", "PRESERVE", "ESTABLISH", "INVALIDATE", "TERMINATE"],
    "authorityReadback": ["COMPLETE_OLD", "COMPLETE_NEW", "OLD_PLUS_ONE_IMMUTABLE_HOLD"]
  },
  "ownership": {
    "AP": "OPAQUE_REQUEST_OUTPUT_AND_APPLICATION_AUTHORIZATION_ONLY",
    "SS": "VALIDATE_AUTHENTICATE_DERIVE_AND_STAGE",
    "RS": "ASSIGN_OR_COASSIGN_OPERATION_IDENTITY_AUTHENTICATE_COMMIT_AND_PROVE",
    "TR": "ABSENT"
  },
  "mutationEnvelope": {
    "closed": true,
    "required": ["operationIdentity", "operation", "scenario", "originalApiState", "originalAuthority", "bindingProfileIdentity", "candidate", "componentSet", "heldOutput", "expectedSuccess", "reconciliationIdentity"],
    "fields": {
      "operationIdentity": {"required": ["value", "assignedBy", "fresh", "reusable", "apRequestIdEqual"], "assignedBy": "SS_RS", "fresh": true, "reusable": false, "apRequestIdEqual": false},
      "operation": {"enumRef": "enums.operation"},
      "scenario": {"enum": ["CAPI-S001", "CAPI-S006", "CAPI-S009", "CAPI-S010", "CAPI-S014", "CAPI-S016", "CAPI-S017"]},
      "originalApiState": {"enum": ["EMPTY", "ACTIVE"]},
      "originalAuthority": {"required": ["digest", "reference"], "owner": "SS_RS"},
      "bindingProfileIdentity": {"required": ["bindingRef", "profile"], "owner": "SS", "profileExact": true},
      "candidate": {"required": ["digest", "reference"], "owner": "SS"},
      "componentSet": {"required": ["digest", "reference", "entries"], "owner": "SS_RS"},
      "heldOutput": {"required": ["kind", "digest", "reference"], "noneRule": "KIND_NONE_REQUIRES_DIGEST_AND_REFERENCE_NULL", "presentRule": "NON_NONE_REQUIRES_DIGEST_AND_REFERENCE"},
      "expectedSuccess": {"required": ["code", "stateAfter"], "owner": "SS"},
      "reconciliationIdentity": {"required": ["reference", "owner"], "owner": "SS_RS"}
    },
    "rowBinding": {"selector": "scenario", "mustEqualSelectedRow": ["operation", "originalApiState", "heldOutput.kind", "expectedSuccess.code", "expectedSuccess.stateAfter", "componentSet.entries"]},
    "apOriginatedOperationIdentityDisposition": "FAIL_CLOSED_INTERNAL_BEFORE_RS_REQUEST",
    "logicalIdentifiersOnly": true,
    "canonicalEncodingDefined": false
  },
  "commitResultEvidence": {
    "closed": true,
    "required": ["operationIdentity", "originalAuthorityDigest", "originalAuthorityReference", "candidateDigest", "candidateReference", "mutationSetDigest", "mutationSetReference", "expectedOriginalState", "bindingRef", "profile", "outcome", "authenticatedByRS", "terminal"],
    "matchRule": "ALL_IDENTITY_FIELDS_MUST_MATCH_ONE_HELD_ENVELOPE",
    "notCommittedRule": "ACCEPT_ONLY_WHEN_TERMINAL_TRUE_AND_REQUEST_CAN_NO_LONGER_COMMIT",
    "mismatchDisposition": "REJECT_WITHOUT_SELECT_OR_DISCARD",
    "forbidden": ["AP_SUPPLIED_OUTCOME", "UNKNOWN_EVIDENCE", "STALE_EVIDENCE", "CROSS_SESSION_EVIDENCE", "CROSS_BINDING_EVIDENCE", "CROSS_PROFILE_EVIDENCE", "DUPLICATE_CONFLICTING_EVIDENCE"]
  },
  "mutationRows": [
    {
      "scenario": "CAPI-S001", "operation": "CREATE", "stateBefore": "EMPTY", "stateAfterCommitted": "ACTIVE", "successCode": "CREATED", "outputKind": "EMBEDDED_TREE_WELCOME", "selectionEffect": "NOT_APPLICABLE", "retainedParentEffect": "NOT_APPLICABLE",
      "components": [
        {"id": "SESSION_TRANSITION", "disposition": "CHANGED", "fact": "FOUNDER_STATE"},
        {"id": "BINDING_METADATA", "disposition": "CHANGED", "fact": "INITIAL_EXACT_BINDING_AND_PROFILE"},
        {"id": "REPLAY_RETENTION_STATE", "disposition": "CHANGED", "fact": "INITIAL_BASELINE"},
        {"id": "AUTHENTICATED_MANIFEST_UPDATE", "disposition": "CHANGED", "fact": "FOUNDER_MANIFEST"},
        {"id": "COMMIT_RESULT_EVIDENCE", "disposition": "CREATED", "fact": "BOUND_TO_OPERATION_IDENTITY"},
        {"id": "OUTPUT_ESCROW", "disposition": "HELD", "fact": "EMBEDDED_TREE_WELCOME"}
      ]
    },
    {
      "scenario": "CAPI-S006", "operation": "JOIN_WELCOME", "stateBefore": "EMPTY", "stateAfterCommitted": "ACTIVE", "successCode": "JOINED", "outputKind": "NONE", "selectionEffect": "NOT_APPLICABLE", "retainedParentEffect": "NOT_APPLICABLE",
      "components": [
        {"id": "SESSION_TRANSITION", "disposition": "CHANGED", "fact": "JOINED_STATE"},
        {"id": "BINDING_METADATA", "disposition": "CHANGED", "fact": "JOINED_EXACT_BINDING_AND_PROFILE"},
        {"id": "REPLAY_RETENTION_STATE", "disposition": "CHANGED", "fact": "JOINED_BASELINE"},
        {"id": "AUTHENTICATED_MANIFEST_UPDATE", "disposition": "CHANGED", "fact": "JOINED_MANIFEST"},
        {"id": "COMMIT_RESULT_EVIDENCE", "disposition": "CREATED", "fact": "BOUND_TO_OPERATION_IDENTITY"},
        {"id": "KEY_PACKAGE_CONSUMPTION", "disposition": "CONSUMED", "fact": "MATCHING_LOCAL_ONE_SHOT_REFERENCE"}
      ]
    },
    {
      "scenario": "CAPI-S009", "operation": "PROTECT_APPLICATION", "stateBefore": "ACTIVE", "stateAfterCommitted": "ACTIVE", "successCode": "APPLICATION_PROTECTED", "outputKind": "PROTECTED_APPLICATION_BYTES", "selectionEffect": "PRESERVE", "retainedParentEffect": "PRESERVE",
      "components": [
        {"id": "SESSION_TRANSITION", "disposition": "CHANGED", "fact": "SENDER_RATCHET_ADVANCEMENT"},
        {"id": "BINDING_METADATA", "disposition": "UNCHANGED", "fact": "EXACT_BINDING_AND_PROFILE"},
        {"id": "REPLAY_RETENTION_STATE", "disposition": "CHANGED", "fact": "SENDER_RATCHET_RETENTION"},
        {"id": "AUTHENTICATED_MANIFEST_UPDATE", "disposition": "CHANGED", "fact": "RATCHET_STATE_MANIFEST"},
        {"id": "COMMIT_RESULT_EVIDENCE", "disposition": "CREATED", "fact": "BOUND_TO_OPERATION_IDENTITY"},
        {"id": "OUTPUT_ESCROW", "disposition": "HELD", "fact": "PROTECTED_APPLICATION_BYTES"},
        {"id": "SELECTION_METADATA", "disposition": "UNCHANGED", "fact": "EPOCH_PRESERVING_ELIGIBILITY"},
        {"id": "RETAINED_PARENT_REFERENCE", "disposition": "UNCHANGED", "fact": "PRESERVED_IF_PRESENT"}
      ]
    },
    {
      "scenario": "CAPI-S010", "operation": "OPEN_APPLICATION", "stateBefore": "ACTIVE", "stateAfterCommitted": "ACTIVE", "successCode": "APPLICATION_OPENED", "outputKind": "APPLICATION_BYTES", "selectionEffect": "PRESERVE", "retainedParentEffect": "PRESERVE",
      "components": [
        {"id": "SESSION_TRANSITION", "disposition": "CHANGED", "fact": "RECEIVER_RATCHET_ADVANCEMENT"},
        {"id": "BINDING_METADATA", "disposition": "UNCHANGED", "fact": "EXACT_BINDING_AND_PROFILE"},
        {"id": "REPLAY_RETENTION_STATE", "disposition": "CHANGED", "fact": "REPLAY_ACCEPTANCE_AND_RECEIVER_RETENTION"},
        {"id": "AUTHENTICATED_MANIFEST_UPDATE", "disposition": "CHANGED", "fact": "RATCHET_AND_REPLAY_MANIFEST"},
        {"id": "COMMIT_RESULT_EVIDENCE", "disposition": "CREATED", "fact": "BOUND_TO_OPERATION_IDENTITY"},
        {"id": "OUTPUT_ESCROW", "disposition": "HELD", "fact": "APPLICATION_BYTES"},
        {"id": "SELECTION_METADATA", "disposition": "UNCHANGED", "fact": "EPOCH_PRESERVING_ELIGIBILITY"},
        {"id": "RETAINED_PARENT_REFERENCE", "disposition": "UNCHANGED", "fact": "PRESERVED_IF_PRESENT"}
      ]
    },
    {
      "scenario": "CAPI-S014", "operation": "SELF_UPDATE", "stateBefore": "ACTIVE", "stateAfterCommitted": "ACTIVE", "successCode": "SELF_UPDATED", "outputKind": "PROTECTED_COMMIT_BYTES", "selectionEffect": "ESTABLISH", "retainedParentEffect": "ESTABLISH_FOR_CAPI_S017_ONLY",
      "components": [
        {"id": "SESSION_TRANSITION", "disposition": "CHANGED", "fact": "LOCAL_UPDATE_STATE"},
        {"id": "BINDING_METADATA", "disposition": "UNCHANGED", "fact": "EXACT_BINDING_AND_PROFILE"},
        {"id": "REPLAY_RETENTION_STATE", "disposition": "CHANGED", "fact": "EPOCH_WINDOW_ADVANCEMENT"},
        {"id": "AUTHENTICATED_MANIFEST_UPDATE", "disposition": "CHANGED", "fact": "LOCAL_UPDATE_MANIFEST"},
        {"id": "COMMIT_RESULT_EVIDENCE", "disposition": "CREATED", "fact": "BOUND_TO_OPERATION_IDENTITY"},
        {"id": "OUTPUT_ESCROW", "disposition": "HELD", "fact": "PROTECTED_COMMIT_BYTES"},
        {"id": "SELECTION_METADATA", "disposition": "ESTABLISHED", "fact": "IMMEDIATELY_PRECEDING_LOCAL_UPDATE_ELIGIBILITY"},
        {"id": "RETAINED_PARENT_REFERENCE", "disposition": "ESTABLISHED", "fact": "PARENT_REQUIRED_BY_CAPI_S017"}
      ]
    },
    {
      "scenario": "CAPI-S016", "operation": "APPLY_PEER_UPDATE", "stateBefore": "ACTIVE", "stateAfterCommitted": "ACTIVE", "successCode": "PEER_UPDATE_APPLIED", "outputKind": "NONE", "selectionEffect": "INVALIDATE", "retainedParentEffect": "INVALIDATE_SELECTION_ROLE",
      "components": [
        {"id": "SESSION_TRANSITION", "disposition": "CHANGED", "fact": "PEER_UPDATE_STATE"},
        {"id": "BINDING_METADATA", "disposition": "UNCHANGED", "fact": "EXACT_BINDING_AND_PROFILE"},
        {"id": "REPLAY_RETENTION_STATE", "disposition": "CHANGED", "fact": "EPOCH_WINDOW_ADVANCEMENT"},
        {"id": "AUTHENTICATED_MANIFEST_UPDATE", "disposition": "CHANGED", "fact": "PEER_UPDATE_MANIFEST"},
        {"id": "COMMIT_RESULT_EVIDENCE", "disposition": "CREATED", "fact": "BOUND_TO_OPERATION_IDENTITY"},
        {"id": "SELECTION_METADATA", "disposition": "INVALIDATED", "fact": "ANY_CAPI_S014_ELIGIBILITY"},
        {"id": "RETAINED_PARENT_REFERENCE", "disposition": "INVALIDATED", "fact": "NO_LONGER_SELECTION_AUTHORIZING"},
        {"id": "LOSING_CANDIDATE_EVIDENCE", "disposition": "INVALIDATED", "fact": "ANY_RETAINED_LOSER_EVIDENCE"}
      ]
    },
    {
      "scenario": "CAPI-S017", "operation": "APPLY_PEER_UPDATE", "stateBefore": "ACTIVE", "stateAfterCommitted": "ACTIVE", "successCode": "CANDIDATE_SELECTED", "outputKind": "SELECTED_CANDIDATE_REF", "selectionEffect": "TERMINATE", "retainedParentEffect": "TERMINATE_SELECTION_ROLE",
      "components": [
        {"id": "SESSION_TRANSITION", "disposition": "CHANGED_OR_UNCHANGED_BY_SELECTED_CANDIDATE", "fact": "CURRENT_WINNER_UNCHANGED_INCOMING_WINNER_CHANGED"},
        {"id": "BINDING_METADATA", "disposition": "UNCHANGED", "fact": "EXACT_BINDING_AND_PROFILE"},
        {"id": "REPLAY_RETENTION_STATE", "disposition": "CHANGED", "fact": "SELECTED_EPOCH_WINDOW"},
        {"id": "AUTHENTICATED_MANIFEST_UPDATE", "disposition": "CHANGED", "fact": "SELECTED_STATE_MANIFEST"},
        {"id": "COMMIT_RESULT_EVIDENCE", "disposition": "CREATED", "fact": "BOUND_TO_OPERATION_IDENTITY"},
        {"id": "OUTPUT_ESCROW", "disposition": "HELD", "fact": "SELECTED_CANDIDATE_REF"},
        {"id": "SELECTION_METADATA", "disposition": "TERMINATED", "fact": "NO_FURTHER_SELECTION_FROM_OLD_PARENT"},
        {"id": "RETAINED_PARENT_REFERENCE", "disposition": "TERMINATED", "fact": "NO_LONGER_SELECTION_AUTHORIZING"},
        {"id": "LOSING_CANDIDATE_EVIDENCE", "disposition": "RETAINED_NON_AUTHORITATIVE", "fact": "BOUNDED_VALID_LOSER"}
      ]
    }
  ],
  "outcomeRules": {
    "COMMITTED": {"authority": "COMPLETE_NEW", "atomic": true, "exactlyOnce": true, "resultKind": "SUCCESS", "output": "RELEASE_MATCHING_ESCROW", "evidence": "MATCHING_AUTHENTICATED_RESULT_AUTHORITATIVE"},
    "NOT_COMMITTED": {"authority": "COMPLETE_OLD", "terminalEvidenceRequired": true, "candidate": "DISCARD", "escrow": "DISCARD", "resultKind": "NOT_COMMITTED", "output": "NONE"},
    "INDETERMINATE": {"authority": "OLD_PLUS_ONE_IMMUTABLE_HOLD", "causes": ["TIMEOUT", "LOST_RESPONSE", "ABSENT_RESULT", "FAILED_RESULT", "UNKNOWN_POST_REQUEST_FAILURE"], "stateAfter": "RECONCILIATION_REQUIRED", "resultKind": "INDETERMINATE", "responseRequired": ["commitOutcome", "originalStateBefore", "reconciliationRef"], "output": "NONE", "blindRetry": "FORBIDDEN"}
  },
  "escrow": {
    "releaseCondition": "MATCHING_COMMITTED_EVIDENCE_FOR_SAME_OPERATION_AND_CANDIDATE",
    "sameMutationAsCandidate": true,
    "reconciliationReadsCommittedEscrow": true,
    "replayOrRegeneration": "FORBIDDEN",
    "apReceiptClaim": "NONE",
    "exactlyOnceDeliveryClaim": "NONE",
    "duplicateByteResponseAfterLostResponse": "POSSIBLE",
    "byScenario": {
      "CAPI-S001": "EMBEDDED_TREE_WELCOME",
      "CAPI-S006": "NONE",
      "CAPI-S009": "PROTECTED_APPLICATION_BYTES",
      "CAPI-S010": "APPLICATION_BYTES",
      "CAPI-S014": "PROTECTED_COMMIT_BYTES",
      "CAPI-S016": "NONE",
      "CAPI-S017": "SELECTED_CANDIDATE_REF"
    },
    "neverExposeFor": ["RESTORE", "NO_CHANGE", "NOT_COMMITTED", "INDETERMINATE", "REJECTED"]
  },
  "reconciliation": {
    "originalStateEnum": ["EMPTY", "ACTIVE"],
    "apMaySupplyOutcome": false,
    "originalTerminalPath": {"committed": "SELECT_COMPLETE_NEW_AND_RESOLVE_HOLD;_RETAIN_INTERNAL_EVIDENCE_IF_EMISSION_INTERRUPTED;_NO_AP_RECONCILIATION_ROW_WITHOUT_PRIOR_REFERENCE", "notCommitted": "RESTORE_COMPLETE_OLD_DISCARD_ESCROW_AND_RESOLVE_HOLD", "apReconciliationRow": "NONE_WITHOUT_PRIOR_INDETERMINATE_REFERENCE"},
    "matchingCommitted": {"scenarios": ["CAPI-S020", "CAPI-S022"], "precondition": "AP_HAS_REFERENCE_FROM_PRIOR_INDETERMINATE", "action": "SELECT_ALREADY_STAGED_CANDIDATE_ONCE_AND_RETAIN_RESPONSE_HOLD_UNTIL_LOCAL_EMISSION_CALL_SUCCEEDS", "output": "ORIGINAL_SUCCESS_CODE_AND_COMMITTED_ORIGINAL_OUTPUT"},
    "matchingNotCommitted": {"scenarios": ["CAPI-S021", "CAPI-S023"], "precondition": "AP_HAS_REFERENCE_FROM_PRIOR_INDETERMINATE", "action": "DISCARD_CANDIDATE_AND_ESCROW_AND_CLEAR_HOLD_WHEN_NO_OUTPUT_RESPONSE_IS_FORMED", "output": "NONE"},
    "continuedIndeterminate": {"scenario": "CAPI-S024", "action": "HOLD_UNCHANGED", "output": "NONE"},
    "referenceMismatch": {"scenario": "CAPI-S028", "action": "REJECT_WITHOUT_MUTATION_OR_HOLD_CHANGE"},
    "interruptedCommittedReconciliationRepeat": {"scenarios": ["CAPI-S020", "CAPI-S022"], "precondition": "REFERENCE_ALREADY_EMITTED_BY_PRIOR_INDETERMINATE", "state": "RECONCILIATION_REQUIRED", "clearingEvent": "ADAPTER_LOCAL_RESPONSE_EMISSION_CALL_RETURNS_SUCCESS", "sameEscrowMayRepeat": true, "apReceiptAcknowledgement": false},
    "afterHoldClearedRepeat": {"scenarios": ["CAPI-G008", "CAPI-G016"], "disposition": "NO_RECONCILIATION_PENDING", "authority": "UNCHANGED", "output": "NONE"},
    "mismatchFields": ["REFERENCE", "OPERATION_IDENTITY", "CANDIDATE", "PARENT", "BINDING", "PROFILE", "COMPONENT_SET", "ORIGINAL_STATE", "RS_EVIDENCE"]
  },
  "concurrency": {
    "precondition": "D13_SINGLE_WRITER",
    "enforcedBy": "I_LOCK_OUTSIDE_ADAPTER",
    "workersPerBrowserProfile": 1,
    "writersPerBrowserProfile": 1,
    "mutatingRequests": "SERIALIZED",
    "maximumUnresolvedMutations": 1,
    "requestDuringHold": "RECONCILIATION_REQUIRED",
    "preRequestDuplicateIdentityOrInternalEnvelopeParentMismatch": "FAIL_CLOSED_INTERNAL_AFTER_C_API_P09",
    "unrelatedIncomingCommitParent": "CAPI_S019_AT_P09_PREEMPTS_ENVELOPE_CHECK",
    "staleParentException": "CAPI-S017_ONLY_AFTER_P09_ACCEPTS_TWO_CANDIDATE_SHAPE",
    "exceptionDoesNotPermitSecondHold": true,
    "loserMayBecomeAuthoritativeFromOldParent": false
  },
  "crashBoundaries": [
    {"id": "BEFORE_STAGING", "readbackByMemory": {"RETAINED": ["COMPLETE_OLD"], "LOST": ["COMPLETE_OLD"]}, "apiState": "ORIGINAL", "output": "NONE", "classification": "NO_RS_REQUEST"},
    {"id": "AFTER_CANDIDATE_COMPUTATION", "readbackByMemory": {"RETAINED": ["COMPLETE_OLD"], "LOST": ["COMPLETE_OLD"]}, "apiState": "ORIGINAL", "output": "NONE", "classification": "NO_RS_REQUEST"},
    {"id": "AFTER_LOCAL_STAGING", "readbackByMemory": {"RETAINED": ["COMPLETE_OLD"], "LOST": ["COMPLETE_OLD"]}, "apiState": "ORIGINAL", "output": "NONE", "classification": "NO_RS_REQUEST"},
    {"id": "BEFORE_RS_REQUEST", "readbackByMemory": {"RETAINED": ["COMPLETE_OLD"], "LOST": ["COMPLETE_OLD"]}, "apiState": "ORIGINAL", "output": "NONE", "classification": "NO_RS_REQUEST"},
    {"id": "DURING_RS_WORK", "readbackByMemory": {"RETAINED": ["COMPLETE_OLD", "COMPLETE_NEW", "OLD_PLUS_ONE_IMMUTABLE_HOLD"], "LOST": ["COMPLETE_OLD", "COMPLETE_NEW"]}, "apiState": "RECONCILIATION_REQUIRED_UNTIL_TERMINAL_READBACK", "output": "NONE_UNTIL_COMMITTED_PROVEN", "classification": "AUTHENTICATED_RS_EVIDENCE_ONLY"},
    {"id": "AFTER_DURABLE_COMMIT_BEFORE_RESPONSE", "readbackByMemory": {"RETAINED": ["COMPLETE_NEW"], "LOST": ["COMPLETE_NEW"]}, "apiStateByPath": {"ORIGINAL_TERMINAL": "ACTIVE_HOLD_RESOLVED", "POST_INDETERMINATE": "RECONCILIATION_REQUIRED_UNTIL_LOCAL_EMISSION_CALL_SUCCEEDS"}, "outputByPath": {"ORIGINAL_TERMINAL": "ORIGINAL_SUCCESS_RESPONSE_PENDING", "POST_INDETERMINATE": "COMMITTED_ESCROW_AVAILABLE_TO_CAPI_S020_OR_S022"}, "classificationByPath": {"ORIGINAL_TERMINAL": "CAPI_COMMITTED_RULE_NO_AP_RECONCILIATION_ROW_WITHOUT_PRIOR_REFERENCE", "POST_INDETERMINATE": "CAPI_S020_OR_S022"}},
    {"id": "AFTER_NOT_COMMITTED", "readbackByMemory": {"RETAINED": ["COMPLETE_OLD"], "LOST": ["COMPLETE_OLD"]}, "apiStateByPath": {"ORIGINAL_TERMINAL": "ORIGINAL_STATE_HOLD_RESOLVED", "POST_INDETERMINATE": "ORIGINAL_STATE_HOLD_CLEARED_WHEN_NO_OUTPUT_RESPONSE_FORMED"}, "outputByPath": {"ORIGINAL_TERMINAL": "NONE", "POST_INDETERMINATE": "NONE"}, "classificationByPath": {"ORIGINAL_TERMINAL": "CAPI_NOT_COMMITTED_RULE", "POST_INDETERMINATE": "CAPI_S021_OR_S023"}},
    {"id": "AFTER_INDETERMINATE", "readbackByMemory": {"RETAINED": ["OLD_PLUS_ONE_IMMUTABLE_HOLD"], "LOST": ["COMPLETE_OLD", "COMPLETE_NEW"]}, "apiState": "RECONCILIATION_REQUIRED", "output": "NONE", "classification": "LOST_MEMORY_REQUIRES_TERMINAL_AUTHENTICATED_C_REC_RS_READBACK"},
    {"id": "DURING_RECONCILIATION", "readbackByMemory": {"RETAINED": ["COMPLETE_OLD", "COMPLETE_NEW", "OLD_PLUS_ONE_IMMUTABLE_HOLD"], "LOST": ["COMPLETE_OLD", "COMPLETE_NEW"]}, "apiState": "RECONCILIATION_REQUIRED_UNTIL_TERMINAL_RESPONSE_CONFIRMED", "output": "NONE_UNTIL_COMMITTED_PROVEN", "classification": "AUTHENTICATED_RS_EVIDENCE_ONLY"},
    {"id": "AFTER_AUTHORITY_SELECTION_BEFORE_OUTPUT_RESPONSE", "readbackByMemory": {"RETAINED": ["COMPLETE_NEW"], "LOST": ["COMPLETE_NEW"]}, "apiStateByPath": {"ORIGINAL_TERMINAL": "ACTIVE_HOLD_RESOLVED", "POST_INDETERMINATE": "RECONCILIATION_REQUIRED_UNTIL_LOCAL_EMISSION_CALL_SUCCEEDS"}, "outputByPath": {"ORIGINAL_TERMINAL": "ORIGINAL_SUCCESS_RESPONSE_PENDING", "POST_INDETERMINATE": "COMMITTED_ESCROW_AVAILABLE_TO_CAPI_S020_OR_S022"}, "classificationByPath": {"ORIGINAL_TERMINAL": "CAPI_COMMITTED_RULE_NO_AP_RECONCILIATION_ROW_WITHOUT_PRIOR_REFERENCE", "POST_INDETERMINATE": "CAPI_S020_OR_S022"}},
    {"id": "DURING_ESCROW_OUTPUT_RESPONSE", "readbackByMemory": {"RETAINED": ["COMPLETE_NEW"], "LOST": ["COMPLETE_NEW"]}, "apiStateByPath": {"ORIGINAL_TERMINAL": "ACTIVE_HOLD_RESOLVED_INTERNAL_EVIDENCE_RETAINED_IF_INTERRUPTED", "POST_INDETERMINATE": "RECONCILIATION_REQUIRED_IF_LOCAL_EMISSION_CALL_INTERRUPTED"}, "outputByPath": {"ORIGINAL_TERMINAL": "NO_AP_RECONCILIATION_REPLAY_WITHOUT_PRIOR_REFERENCE", "POST_INDETERMINATE": "SAME_COMMITTED_ESCROW_MAY_BE_RETURNED_AGAIN"}, "classificationByPath": {"ORIGINAL_TERMINAL": "CAPI_COMMITTED_RULE", "POST_INDETERMINATE": "CAPI_S020_OR_S022"}},
    {"id": "AFTER_OUTPUT_RESPONSE_LOSS", "readbackByMemory": {"RETAINED": ["COMPLETE_NEW"], "LOST": ["COMPLETE_NEW"]}, "apiStateByPath": {"ORIGINAL_TERMINAL": "ACTIVE_HOLD_RESOLVED_INTERNAL_EVIDENCE_RETAINED", "POST_INDETERMINATE": "RECONCILIATION_REQUIRED_IF_LOCAL_EMISSION_CALL_DID_NOT_RETURN_SUCCESS"}, "outputByPath": {"ORIGINAL_TERMINAL": "NO_AP_RECONCILIATION_REPLAY_WITHOUT_PRIOR_REFERENCE", "POST_INDETERMINATE": "SAME_COMMITTED_ESCROW_MAY_BE_RETURNED_AGAIN"}, "classificationByPath": {"ORIGINAL_TERMINAL": "CAPI_COMMITTED_RULE", "POST_INDETERMINATE": "CAPI_S020_OR_S022"}}
  ],
  "failureAtomicity": {
    "allLogicalComponentsCovered": true,
    "beforeCommitPoint": "COMPLETE_ORIGINAL_SET_AND_ROOT",
    "afterCommitPoint": "COMPLETE_CANDIDATE_SET_AND_MATCHING_ROOT_RESULT_AND_ESCROW",
    "strictlyBeforeAnyRsRequest": {"code": "FAIL_CLOSED_INTERNAL", "candidate": "DISCARD", "escrow": "DISCARD", "rsRequest": "NONE", "commitResultEvidence": "NONE"},
    "triStateBegins": "WHEN_REQUEST_MAY_HAVE_REACHED_RS",
    "faultsClassifiedByBoundaryAndEvidence": ["QUOTA", "ABORT", "WORKER_TERMINATION", "EXCEPTION", "TAB_CLOSURE", "RESPONSE_LOSS"],
    "guessFromSsMemory": "FORBIDDEN",
    "partialMixture": "FORBIDDEN",
    "twoAuthoritativeStates": "FORBIDDEN"
  },
  "noMutationRows": {
    "stateMatrix": [
      {"scenario":"CAPI-G004","operation":"PROTECT_APPLICATION","stateBefore":"EMPTY","disposition":"NO_ACTIVE_SESSION","resultKind":"REJECTED","stateAfter":"EMPTY"},
      {"scenario":"CAPI-G005","operation":"OPEN_APPLICATION","stateBefore":"EMPTY","disposition":"NO_ACTIVE_SESSION","resultKind":"REJECTED","stateAfter":"EMPTY"},
      {"scenario":"CAPI-G006","operation":"SELF_UPDATE","stateBefore":"EMPTY","disposition":"NO_ACTIVE_SESSION","resultKind":"REJECTED","stateAfter":"EMPTY"},
      {"scenario":"CAPI-G007","operation":"APPLY_PEER_UPDATE","stateBefore":"EMPTY","disposition":"NO_ACTIVE_SESSION","resultKind":"REJECTED","stateAfter":"EMPTY"},
      {"scenario":"CAPI-G008","operation":"RECONCILE_INDETERMINATE","stateBefore":"EMPTY","disposition":"NO_RECONCILIATION_PENDING","resultKind":"REJECTED","stateAfter":"EMPTY"},
      {"scenario":"CAPI-G009","operation":"CREATE","stateBefore":"ACTIVE","disposition":"SESSION_ALREADY_EXISTS","resultKind":"REJECTED","stateAfter":"ACTIVE"},
      {"scenario":"CAPI-G010","operation":"RESTORE","stateBefore":"ACTIVE","disposition":"SESSION_ALREADY_EXISTS","resultKind":"REJECTED","stateAfter":"ACTIVE"},
      {"scenario":"CAPI-G011","operation":"JOIN_WELCOME","stateBefore":"ACTIVE","disposition":"SESSION_ALREADY_EXISTS","resultKind":"REJECTED","stateAfter":"ACTIVE"},
      {"scenario":"CAPI-G016","operation":"RECONCILE_INDETERMINATE","stateBefore":"ACTIVE","disposition":"NO_RECONCILIATION_PENDING","resultKind":"REJECTED","stateAfter":"ACTIVE"},
      {"scenario":"CAPI-G017","operation":"CREATE","stateBefore":"RECONCILIATION_REQUIRED","disposition":"RECONCILIATION_REQUIRED","resultKind":"REJECTED","stateAfter":"RECONCILIATION_REQUIRED"},
      {"scenario":"CAPI-G018","operation":"RESTORE","stateBefore":"RECONCILIATION_REQUIRED","disposition":"RECONCILIATION_REQUIRED","resultKind":"REJECTED","stateAfter":"RECONCILIATION_REQUIRED"},
      {"scenario":"CAPI-G019","operation":"JOIN_WELCOME","stateBefore":"RECONCILIATION_REQUIRED","disposition":"RECONCILIATION_REQUIRED","resultKind":"REJECTED","stateAfter":"RECONCILIATION_REQUIRED"},
      {"scenario":"CAPI-G020","operation":"PROTECT_APPLICATION","stateBefore":"RECONCILIATION_REQUIRED","disposition":"RECONCILIATION_REQUIRED","resultKind":"REJECTED","stateAfter":"RECONCILIATION_REQUIRED"},
      {"scenario":"CAPI-G021","operation":"OPEN_APPLICATION","stateBefore":"RECONCILIATION_REQUIRED","disposition":"RECONCILIATION_REQUIRED","resultKind":"REJECTED","stateAfter":"RECONCILIATION_REQUIRED"},
      {"scenario":"CAPI-G022","operation":"SELF_UPDATE","stateBefore":"RECONCILIATION_REQUIRED","disposition":"RECONCILIATION_REQUIRED","resultKind":"REJECTED","stateAfter":"RECONCILIATION_REQUIRED"},
      {"scenario":"CAPI-G023","operation":"APPLY_PEER_UPDATE","stateBefore":"RECONCILIATION_REQUIRED","disposition":"RECONCILIATION_REQUIRED","resultKind":"REJECTED","stateAfter":"RECONCILIATION_REQUIRED"}
    ],
    "errorDefinitions": [
      {"scenario":"CAPI-E001","disposition":"UNKNOWN_FIELD"}, {"scenario":"CAPI-E002","disposition":"INVALID_REQUEST"}, {"scenario":"CAPI-E003","disposition":"UNKNOWN_VALUE"}, {"scenario":"CAPI-E004","disposition":"UNSUPPORTED_API_VERSION"}, {"scenario":"CAPI-E005","disposition":"UNSUPPORTED_PROFILE"},
      {"scenario":"CAPI-E006","disposition":"BINDING_MISMATCH"}, {"scenario":"CAPI-E007","disposition":"UNSUPPORTED_OPERATION"}, {"scenario":"CAPI-E008","disposition":"SESSION_ALREADY_EXISTS"}, {"scenario":"CAPI-E009","disposition":"NO_ACTIVE_SESSION"}, {"scenario":"CAPI-E010","disposition":"NO_STORED_SESSION"},
      {"scenario":"CAPI-E011","disposition":"RECONCILIATION_REQUIRED"}, {"scenario":"CAPI-E012","disposition":"NO_RECONCILIATION_PENDING"}, {"scenario":"CAPI-E013","disposition":"RECONCILIATION_REFERENCE_MISMATCH"}, {"scenario":"CAPI-E014","disposition":"VALUE_OUT_OF_RANGE"}, {"scenario":"CAPI-E015","disposition":"EPOCH_OUTSIDE_RETAINED_WINDOW"},
      {"scenario":"CAPI-E016","disposition":"FUTURE_EPOCH"}, {"scenario":"CAPI-E017","disposition":"AUTHENTICATION_FAILED"}, {"scenario":"CAPI-E018","disposition":"AUTHENTICATED_STATE_INCONSISTENT"}, {"scenario":"CAPI-E019","disposition":"UNSUPPORTED_ONBOARDING"}, {"scenario":"CAPI-E020","disposition":"STORED_SESSION_INCOMPATIBLE"},
      {"scenario":"CAPI-E021","disposition":"WELCOME_NO_MATCHING_KEY_PACKAGE"}, {"scenario":"CAPI-E022","disposition":"UNSUPPORTED_UPDATE_FORM"}, {"scenario":"CAPI-E023","disposition":"UNSUPPORTED_COMMIT_SHAPE"}, {"scenario":"CAPI-E024","disposition":"KEY_PACKAGE_ALREADY_CONSUMED"}, {"scenario":"CAPI-E025","disposition":"FAIL_CLOSED_INTERNAL"}
    ],
    "errorDefinitionCommon": {"resultKind":"REJECTED","stateAfter":"UNCHANGED","output":"NONE","newRsCommit":"NONE"},
    "decisionRows": [
      {"scenario":"CAPI-S002","operation":"CREATE","stateBefore":"EMPTY","disposition":"UNSUPPORTED_ONBOARDING","resultKind":"REJECTED","stateAfter":"EMPTY"},
      {"scenario":"CAPI-S003","operation":"RESTORE","stateBefore":"EMPTY","disposition":"RESTORED","resultKind":"SUCCESS","stateAfter":"ACTIVE"},
      {"scenario":"CAPI-S004","operation":"RESTORE","stateBefore":"EMPTY","disposition":"AUTHENTICATED_STATE_INCONSISTENT","resultKind":"REJECTED","stateAfter":"EMPTY"},
      {"scenario":"CAPI-S005","operation":"RESTORE","stateBefore":"EMPTY","disposition":"AUTHENTICATION_FAILED","resultKind":"REJECTED","stateAfter":"EMPTY"},
      {"scenario":"CAPI-S007","operation":"JOIN_WELCOME","stateBefore":"EMPTY","disposition":"KEY_PACKAGE_ALREADY_CONSUMED","resultKind":"REJECTED","stateAfter":"EMPTY"},
      {"scenario":"CAPI-S008","operation":"JOIN_WELCOME","stateBefore":"EMPTY","disposition":"UNSUPPORTED_ONBOARDING","resultKind":"REJECTED","stateAfter":"EMPTY"},
      {"scenario":"CAPI-S011","operation":"OPEN_APPLICATION","stateBefore":"ACTIVE","disposition":"DUPLICATE_IGNORED","resultKind":"NO_CHANGE","stateAfter":"ACTIVE"},
      {"scenario":"CAPI-S012","operation":"OPEN_APPLICATION","stateBefore":"ACTIVE","disposition":"EPOCH_OUTSIDE_RETAINED_WINDOW","resultKind":"REJECTED","stateAfter":"ACTIVE"},
      {"scenario":"CAPI-S013","operation":"OPEN_APPLICATION","stateBefore":"ACTIVE","disposition":"FUTURE_EPOCH","resultKind":"REJECTED","stateAfter":"ACTIVE"},
      {"scenario":"CAPI-S015","operation":"SELF_UPDATE","stateBefore":"ACTIVE","disposition":"UNSUPPORTED_UPDATE_FORM","resultKind":"REJECTED","stateAfter":"ACTIVE"},
      {"scenario":"CAPI-S018","operation":"APPLY_PEER_UPDATE","stateBefore":"ACTIVE","disposition":"UNSUPPORTED_UPDATE_FORM","resultKind":"REJECTED","stateAfter":"ACTIVE"},
      {"scenario":"CAPI-S019","operation":"APPLY_PEER_UPDATE","stateBefore":"ACTIVE","disposition":"UNSUPPORTED_COMMIT_SHAPE","resultKind":"REJECTED","stateAfter":"ACTIVE"},
      {"scenario":"CAPI-S020","operation":"RECONCILE_INDETERMINATE","stateBefore":"RECONCILIATION_REQUIRED","disposition":"RECONCILED_COMMITTED","resultKind":"SUCCESS","stateAfter":"ACTIVE"},
      {"scenario":"CAPI-S021","operation":"RECONCILE_INDETERMINATE","stateBefore":"RECONCILIATION_REQUIRED","disposition":"NOT_COMMITTED","resultKind":"NOT_COMMITTED","stateAfter":"EMPTY"},
      {"scenario":"CAPI-S022","operation":"RECONCILE_INDETERMINATE","stateBefore":"RECONCILIATION_REQUIRED","disposition":"RECONCILED_COMMITTED","resultKind":"SUCCESS","stateAfter":"ACTIVE"},
      {"scenario":"CAPI-S023","operation":"RECONCILE_INDETERMINATE","stateBefore":"RECONCILIATION_REQUIRED","disposition":"NOT_COMMITTED","resultKind":"NOT_COMMITTED","stateAfter":"ACTIVE"},
      {"scenario":"CAPI-S024","operation":"RECONCILE_INDETERMINATE","stateBefore":"RECONCILIATION_REQUIRED","disposition":"INDETERMINATE","resultKind":"INDETERMINATE","stateAfter":"RECONCILIATION_REQUIRED"},
      {"scenario":"CAPI-S025","operation":"RESTORE","stateBefore":"EMPTY","disposition":"NO_STORED_SESSION","resultKind":"REJECTED","stateAfter":"EMPTY"},
      {"scenario":"CAPI-S026","operation":"RESTORE","stateBefore":"EMPTY","disposition":"STORED_SESSION_INCOMPATIBLE","resultKind":"REJECTED","stateAfter":"EMPTY"},
      {"scenario":"CAPI-S027","operation":"JOIN_WELCOME","stateBefore":"EMPTY","disposition":"WELCOME_NO_MATCHING_KEY_PACKAGE","resultKind":"REJECTED","stateAfter":"EMPTY"},
      {"scenario":"CAPI-S028","operation":"RECONCILE_INDETERMINATE","stateBefore":"RECONCILIATION_REQUIRED","disposition":"RECONCILIATION_REFERENCE_MISMATCH","resultKind":"REJECTED","stateAfter":"RECONCILIATION_REQUIRED"},
      {"scenario":"CAPI-S029","operation":"RESTORE","stateBefore":"EMPTY","disposition":"AUTHENTICATED_STATE_INCONSISTENT","resultKind":"REJECTED","stateAfter":"EMPTY"}
    ],
    "decisionRowCommon": {"newRsCommit":"NONE","newMutation":"NONE","newEscrow":"NONE"},
    "counts": {"stateMatrix":16,"errorDefinitions":25,"decisionRows":22,"total":63}
  },
  "restore": {
    "newMutation": "NONE",
    "newRsCommit": "NONE",
    "classificationOwners": ["C_REST", "C_REC"],
    "minimumRecoveryFacts": ["MUTATION_ENVELOPE_IDENTITY", "ORIGINAL_AUTHORITY", "CANDIDATE_IDENTITY", "COMPONENT_SET_IDENTITY", "ESCROW_IDENTITY_AND_CONTENT", "RECONCILIATION_REFERENCE", "EXPECTED_SUCCESS", "AUTHENTICATED_RS_EVIDENCE"],
    "physicalFormatSelected": false
  },
  "fWasmBoundary": {
    "warning": "F_WASM_UNRATIFIED_FEASIBILITY_ONLY",
    "demonstratedCommittedClasses": ["CREATION", "WELCOME_ONBOARDING", "APPLICATION_PROTECT", "APPLICATION_OPEN", "OUTBOUND_SELF_UPDATE", "INBOUND_SELF_UPDATE", "TWO_CANDIDATE_CASE"],
    "demonstratedCommittedClassCount": 7,
    "directCommittedSelectionClasses": ["CREATION", "APPLICATION_PROTECT", "APPLICATION_OPEN", "OUTBOUND_SELF_UPDATE", "INBOUND_SELF_UPDATE", "TWO_CANDIDATE_CASE"],
    "committedSelectionViaReconciliation": ["WELCOME_ONBOARDING"],
    "indeterminateReconciliationExecutedFor": ["WELCOME_ONBOARDING"],
    "notCommittedBranch": "PRESENT_BUT_UNEXECUTED",
    "twoCandidateLimitation": "BOTH_CANDIDATES_STAGED_AGAINST_STILL_AUTHORITATIVE_PARENT_NOT_REPLACEMENT_OF_COMMITTED_LOCAL_UPDATE",
    "probeAuthoritySlotIsProductDesign": false,
    "notProven": ["RS_OR_INDEXEDDB_ATOMICITY", "DURABLE_RECEIPTS", "WORKER_LIFETIME", "CRASH_RECOVERY", "OUTPUT_RELEASE", "PRODUCTION_ADAPTER"]
  },
  "nonClaims": ["APPLICATION_SEMANTICS", "TRANSPORT_DELIVERY_OR_RECEIPT", "EXACTLY_ONCE_DELIVERY", "PHYSICAL_FORMAT", "MIGRATION", "LEGACY_IMPORT_OR_CLEANUP", "ISSUE_312_EXTENSION", "COHERENT_WHOLE_PROFILE_ROLLBACK_PREVENTION", "PHYSICAL_DELETION_OR_ZEROIZATION", "ARBITRARY_GROUP_TOPOLOGY", "FALLBACK_PROFILE", "PUBLIC_SDK", "PRODUCTION_ACTIVATION"],
  "ratification": {
    "documentPath": "docs/architecture/m2/mutation-table.md",
    "documentSha256": "MUST_BE_RECORDED_EXTERNALLY_FROM_FINAL_LITERAL_BYTES",
    "evidenceBundleSha256": "MUST_BE_RECORDED_EXTERNALLY_FROM_FINAL_LITERAL_BYTES",
    "ownerActRequired": true,
    "byteChangeInvalidatesRatification": true,
    "blockedUntilRatified": ["C_FMT", "C_RET", "O_SCEN", "DEPENDENT_IMPLEMENTATION"]
  }
}
```
<!-- styx-m2-mutation-table-json:v1:end -->
