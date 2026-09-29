# M2 retention, compaction and disposal limits

Status: normative candidate for C-RET under Issue #328. Owner ratification of the exact final document hash and external evidence-bundle hash is required before O-SCEN or dependent implementation.

## 1. Scope and normative force

This is the closed M2 logical retention contract over the exact ratified C-MUT input identified below. **MUST**, **MUST NOT**, **RETAIN**, **COMPACTION_CANDIDATE**, **LOGICALLY_DELETE**, and **BLOCK** are normative. The single machine record in §12 is normative and closed; prose only explains it. Unknown, missing, duplicate, extra, or overlapping fields, classes, owners, events, bounds, blockers, transitions, rows, or enum values reject. Every class/event pair appears exactly once, so prose cannot create an exception.

This contract assigns event-bounded lifetimes and disposal preconditions. It does not define storage bytes, keys, schemas, transactions, AEAD/AAD, HKDF labels or versions, restore algorithms, recovery UX, migration, or implementation. It does not change C-MUT components, outcomes, authority selection, reconciliation, output escrow, crash behavior, or C-BIND KeyPackage content or lifecycle.

## 2. Frozen input and ownership

The read-only input is `docs/architecture/m2/mutation-table.md` at `40a3dee0fcb297d6fe8efc8657a9bbe6098d099d`, SHA-256 `6c2c045c5317d6893a0bd338e728f2cdc686237af5688925f9756c014deb3060`. Its external evidence bundle is cited only by SHA-256 `9d8bdb19b20728873ede932df2936dcc6db6dd44a072af57cf4d0320cbf56712`; access to it is not required. Any byte or semantic drift is **BLOCK**.

`SS`, `RS`, and joint `SS_RS` ownership retain C-MUT meanings. Legacy bytes and invalidation markers remain separately `LEGACY_OWNER`-owned non-cleanup inputs. Public/non-secret status never defeats a live referential invariant. Root Storage Key and KEK wrapper are separate classes. Every session-namespace-derived key instance is classified exactly once by the closed logical role set: current authority, past epoch, replay retention, mutation candidate/hold, manifest authentication, output escrow, or KeyPackage. It follows that role plus the derived-key matrix class; an unknown or multiple role is **BLOCK** with retention. This contract deliberately names no derivation label or version.

## 3. Epoch and replay window

The required rule is current epoch plus up to five immediately preceding eligible epochs, and exactly five past epochs once five exist. Advancement inserts a new current epoch, preserves those five, and makes only older eligible material a candidate inside that row's C-MUT `REPLAY_RETENTION_STATE` change and only after reference closure. Out-of-order, duplicate, future, and outside-window inputs neither extend nor silently shrink the window. Reduction requires a new owner-ratified contract and fixtures proving no restore/replay regression.

## 4. Selection, parent, and losing candidate

CAPI-S014 establishes its exact parent and selection evidence. CAPI-S009/S010 preserve them. CAPI-S016 invalidates eligibility, the parent's selection role, and prior losing-candidate evidence exactly as C-MUT states; invalidation is not physical disposal. CAPI-S017 terminates the selection role and creates at most one non-authoritative, non-retryable loser associated with that selected transition and exact parent/evidence.

Owner decision #328 comment `5892675163` selects option A without changing any C-MUT row. At rest, only the most recent loser is retained. A committed S017 may transiently leave the prior and new loser together, so the transient maximum is two. That commit immediately triggers retention compaction: identify the newest loser from the committed S017 selection evidence, compute and authenticate the complete survivor set containing only it, commit that compacted authority, then logically delete and request database deletion of the older loser. The compaction must commit before any later RS mutation and before a new S014 becomes eligible. If it fails, both records remain but processing fails closed: no later RS mutation and no new S014 eligibility until compaction commits. Therefore a third loser is impossible. Disposed losers leave no digest, counter, reference, or diagnostic trace.

For a loser superseded by the next committed S017, owner decision `5892675163` is the exact later safety authority: only the authenticated newest-only survivor commit permits disposal of the older loser. If that commit is absent, both are retained and later RS mutation/new S014 eligibility remain blocked. Separately, an S016-invalidated loser or a terminated/invalidated parent is only a compaction candidate after proof establishes absence or supersession of every selection, hold, result, escrow, replay-window, crash-recovery, and restore reference. O-12, O-13, O-15, and O-16 remain blockers for those other compaction/finality claims; they do not override the owner-authorized post-S017 older-loser compaction.

## 5. Outcomes, holds, results, and escrow

`INDETERMINATE` retains the immutable candidate, original authority, reconciliation identity, matching authenticated result evidence, and matching escrow until authenticated terminal classification and the exact C-MUT clearing event. Continued or interrupted reconciliation retains the same hold. Matching `COMMITTED` never regenerates output; committed escrow survives interrupted local response emission and may be returned again. Local emission success is not AP receipt. Matching terminal `NOT_COMMITTED` makes candidate and escrow candidates only on C-MUT's authenticated proof and clearing event.

Cleared result evidence remains while needed to reject duplicate/conflicting replay and classify restart. No wall-clock expiry is asserted: maximums are `UNBOUNDED_UNTIL_CONDITION` with blockers. Ambiguous or unavailable evidence is **BLOCK** with retention.

## 6. KeyPackage boundary

KeyPackage lifetime is represented only through C-MUT `KEY_PACKAGE_CONSUMPTION` in CAPI-S006 and C-MUT hold/result facts. A package referenced by a hold, or whose consumption is not proven `COMMITTED`, is retained; private material is never reused. Authenticated logical terminality only makes private material a disposal candidate after no active or held mutation can reference it. Public bytes and consumption/audit facts are distinct non-secret/sensitive classes but cannot alias a new package. A lifecycle fact absent from C-MUT is **BLOCK** with retention.

## 7. Compaction and crash atomicity

Only removal inside an existing C-MUT row's `REPLAY_RETENTION_STATE` change and the post-S017 loser compaction authorized by owner decision `5892675163` are currently authorized. Every other compaction is not a C-MUT row and is **BLOCK** pending a separately ratified mutation contract. Authorized compaction must compute the complete survivor set; prove no live candidate, parent, epoch, package, result, escrow, hold, restore, or crash reference; atomically commit the new authenticated manifest/root; and only then request database deletion. Failure before authority change preserves the old complete set. Failure after exposes the complete compacted set plus harmless unreachable remnants. A partial survivor set never becomes authoritative. Corruption, quota failure, interrupted compaction, or an ambiguous graph is **BLOCK** and retains the old complete set.

## 8. Deletion, lock, and reset limits

Logical deletion and a subsequent database-deletion request are the only normative product actions here. Browser transaction completion is not durable erasure. Key destruction and memory overwrite are best-effort attempts. Garbage-collection eligibility says nothing about timing. IndexedDB/browser/storage-engine copies, backups, snapshots, wear levelling, crash remnants, JavaScript strings, WASM memory, and coherent profile copies preclude secure physical-erasure or zeroization claims.

Lock requires best-effort release/overwrite; only later implementation evidence can establish worker termination. Explicit destructive reset first removes or invalidates the KEK wrapper, then logically deletes vault authority/records, then requests ciphertext/database deletion. Surviving ciphertext is inaccessible under the removed local wrapper absent external copies. Reset proves neither physical erasure, external-copy destruction, nor forgotten-password recovery, and it does not authorize legacy cleanup.

## 9. Diagnostics

Disposal/compaction diagnostics are value-free and expose only allowlisted counts, reason codes, and completion stages. They never expose keys, plaintext, binding bytes, session identifiers, package references, candidate digests, or escrow content.

## 10. Deterministic lifecycle interpretation

Each matrix cell applies if that class exists at the named event. `RETAIN` preserves it. `COMPACTION_CANDIDATE` does not authorize deletion; every named condition and full reference closure must first hold. `LOGICALLY_DELETE` is permitted only for the ordered explicit-reset case or, for all but the most recent loser, after the authenticated retention-compaction survivor commit. `BLOCK` retains material and forbids the action named by the condition; after failed loser compaction it specifically blocks later RS mutation and new S014 eligibility. No absent class is fabricated and no time passage changes a cell.

Creation and commit retain all potentially live classes; row-specific creation is governed by C-MUT. Restart and lock retain logical state. `NOT_COMMITTED`, epoch advancement, and S016/S017 expose only the narrowly listed candidates and never bypass closure. CAPI-S014 preserves/establishes its parent. All corruption, quota, and interrupted-compaction cells block. Explicit reset follows §8.

## 11. Non-claims and ratification

This model is not browser-deletion, physical-erasure, memory-zeroization, implementation reference-tracking, crash-atomicity, quota-behavior, freshness, rollback-prevention, delivery, receipt, exactly-once delivery, migration, legacy cleanup, arbitrary-topology, Issue #312, forgotten-password recovery, or production evidence. The five-past-epoch and losing-candidate rules intentionally extend private-material lifetime.

Final literal document and external evidence-bundle SHA-256 values must be recorded externally for separate owner hash-ratification. They cannot self-identify without changing bytes. Any byte change invalidates review and ratification.

## 12. Machine-readable normative record

<!-- styx-m2-retention-json:v1:start -->
```json
{
  "schema": "styx-m2-retention-and-disposal-limits/v1",
  "closed": true,
  "status": "PENDING_EXTERNAL_HASH_RATIFICATION",
  "provenance": {
    "issue": 328,
    "card": "C-RET",
    "exactBase": "e1538ef9c070e463a8256872a3fd0882c424e2ef",
    "cMutCommit": "40a3dee0fcb297d6fe8efc8657a9bbe6098d099d",
    "cMutPath": "docs/architecture/m2/mutation-table.md",
    "cMutSha256": "6c2c045c5317d6893a0bd338e728f2cdc686237af5688925f9756c014deb3060",
    "cMutEvidenceBundleSha256": "9d8bdb19b20728873ede932df2936dcc6db6dd44a072af57cf4d0320cbf56712"
  },
  "enums": {
    "owner": [
      "SS",
      "RS",
      "SS_RS",
      "LEGACY_OWNER"
    ],
    "confidentiality": [
      "SECRET",
      "SENSITIVE_METADATA",
      "PUBLIC",
      "NON_SECRET_ALLOWLISTED",
      "UNKNOWN_LEGACY"
    ],
    "transition": [
      "RETAIN",
      "COMPACTION_CANDIDATE",
      "LOGICALLY_DELETE",
      "BLOCK"
    ],
    "event": [
      "CREATION",
      "COMMIT",
      "NOT_COMMITTED",
      "INDETERMINATE",
      "RECONCILIATION_REPEAT",
      "EPOCH_ADVANCE",
      "CAPI_S014_SELECTION",
      "CAPI_S016_SELECTION",
      "CAPI_S017_SELECTION",
      "RETENTION_COMPACTION",
      "RESTART",
      "LOCK",
      "CORRUPTION",
      "QUOTA_FAILURE",
      "COMPACTION_INTERRUPTION",
      "EXPLICIT_RESET"
    ],
    "creationTrigger": [
      "COMMITTED_SESSION_TRANSITION",
      "COMMITTED_EPOCH_ADVANCE",
      "REPLAY_RETENTION_COMPONENT",
      "BINDING_METADATA_COMPONENT",
      "AUTHENTICATED_MANIFEST_UPDATE",
      "C_MUT_ENVELOPE_STAGING",
      "INDETERMINATE_OUTCOME",
      "CAPI_S014_COMMIT",
      "CAPI_S017_COMMIT",
      "RS_RESULT",
      "CAPI_S001_STAGING",
      "CAPI_S009_STAGING",
      "CAPI_S010_STAGING",
      "CAPI_S014_STAGING",
      "CAPI_S017_STAGING",
      "LOCAL_KEY_PACKAGE_CREATION",
      "CAPI_S006_COMPONENT",
      "VAULT_INITIALIZATION",
      "SESSION_NAMESPACE_DERIVATION",
      "ALLOWLISTED_REPORT_EVENT",
      "PREEXISTING_INPUT"
    ],
    "minimum": [
      "WHILE_AUTHORITATIVE",
      "CURRENT_PLUS_FIVE_PAST_EPOCH_RULE",
      "WHILE_CURRENT_OR_PAST_EPOCH_IS_ACCEPTABLE",
      "WHILE_ANY_STATE_HOLD_RESULT_OR_RESTORE_FACT_REFERENCES_IT",
      "WHILE_AUTHORITY_OR_RECOVERY_CLASSIFICATION_REFERENCES_IT",
      "UNTIL_AUTHENTICATED_TERMINAL_CLASSIFICATION_AND_CLEARING",
      "UNTIL_TERMINAL_CLASSIFICATION_AND_NO_RECOVERY_REFERENCE",
      "UNTIL_C_MUT_CLEARING_EVENT_AND_REPLAY_CLASSIFICATION_COMPLETE",
      "UNTIL_AUTHENTICATED_TERMINAL_CLASSIFICATION_AND_C_MUT_CLEARING_EVENT",
      "UNTIL_CAPI_S016_INVALIDATION_OR_CAPI_S017_TERMINATION",
      "WHILE_SELECTION_ELIGIBILITY_OR_UNRESOLVED_OPERATION_CAN_REFERENCE_IT",
      "MOST_RECENT_UNTIL_SUPERSEDED_BY_OWNER_DECISION_5892675163_RETENTION_COMPACTION",
      "UNTIL_DUPLICATE_CONFLICTING_REPLAY_AND_RESTART_CLASSIFICATION_NO_LONGER_NEEDS_IT",
      "UNTIL_TERMINAL_CLASSIFICATION_AND_C_MUT_CLEARING_EVENT",
      "UNTIL_COMMITTED_CONSUMPTION_AND_NO_ACTIVE_OR_HELD_MUTATION_REFERENCE",
      "WHILE_ELIGIBILITY_AUDIT_OR_REFERENCE_CLOSURE_NEEDS_IT",
      "WHILE_REUSE_PREVENTION_RESULT_OR_RESTART_CLASSIFICATION_NEEDS_IT",
      "WHILE_ANY_LIVE_SESSION_NAMESPACE_MATERIAL_REQUIRES_IT",
      "UNTIL_EXPLICIT_DESTRUCTIVE_RESET_INVALIDATES_OR_REMOVES_IT",
      "WHILE_LOGICAL_ROLE_OR_REFERENCE_IS_LIVE",
      "UNTIL_DIAGNOSTIC_OWNER_POLICY_PERMITS_LOGICAL_DELETION",
      "AS_REQUIRED_BY_SEPARATE_LEGACY_OWNER"
    ],
    "maximum": [
      "UNBOUNDED_UNTIL_CONDITION"
    ],
    "blocker": [
      "SUPERSEDED_BY_COMPLETE_AUTHENTICATED_AUTHORITY_OR_EXPLICIT_RESET",
      "NOT_OLDER_THAN_FIVE_ELIGIBLE_PAST_EPOCHS",
      "LIVE_REPLAY_RESTORE_HOLD_OR_CRASH_REFERENCE",
      "LIVE_REPLAY_OR_DUPLICATE_CLASSIFICATION_REFERENCE",
      "LIVE_BINDING_PROFILE_REFERENCE",
      "LIVE_AUTHORITY_RESULT_RESTORE_OR_CRASH_REFERENCE",
      "UNRESOLVED_OR_AMBIGUOUS_OUTCOME",
      "LIVE_HOLD_RESULT_ESCROW_OR_RECOVERY_REFERENCE",
      "LIVE_HOLD_RESULT_PARENT_OR_CRASH_REFERENCE",
      "UNRESOLVED_HOLD_OR_REPEAT_RECONCILIATION",
      "OUTCOME_NOT_TERMINAL",
      "LOCAL_RESPONSE_EMISSION_NOT_SUCCESSFUL_WHERE_C_MUT_REQUIRES_IT",
      "SELECTION_ELIGIBILITY_OR_LIVE_REFERENCE",
      "LIVE_SELECTION_HOLD_RESULT_ESCROW_REPLAY_OR_CRASH_REFERENCE",
      "MOST_RECENT_LOSER_NOT_YET_SUPERSEDED",
      "OWNER_DECISION_5892675163_RETENTION_COMPACTION_NOT_COMMITTED",
      "LIVE_HOLD_RECONCILIATION_REPLAY_RESTORE_OR_CRASH_REFERENCE",
      "NO_RATIFIED_BOUNDED_COMPACTION_PROOF",
      "INDETERMINATE_OR_INTERRUPTED_RESPONSE_EMISSION",
      "NO_AP_RECEIPT_EVIDENCE",
      "CONSUMPTION_NOT_PROVEN_COMMITTED",
      "ACTIVE_OR_HELD_CAPI_S006_REFERENCE",
      "PRIVATE_MATERIAL_MUST_NEVER_BE_REUSED",
      "LIVE_PACKAGE_ELIGIBILITY_AUDIT_OR_HOLD_REFERENCE",
      "LIVE_REUSE_PREVENTION_RESULT_HOLD_OR_RESTART_REFERENCE",
      "LIVE_AUTHORITY_EPOCH_HOLD_ESCROW_PACKAGE_OR_RECOVERY_REFERENCE",
      "NO_EXPLICIT_RESET",
      "WRAPPER_REMOVAL_NOT_CONFIRMED",
      "LIVE_AUTHORITY_EPOCH_REPLAY_HOLD_ESCROW_PACKAGE_OR_RECOVERY_REFERENCE",
      "NO_SEPARATELY_RATIFIED_DIAGNOSTIC_RETENTION_POLICY",
      "LEGACY_CLEANUP_OUT_OF_SCOPE",
      "NO_OWNER_RATIFIED_MIGRATION_OR_CLEANUP"
    ],
    "condition": [
      "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL",
      "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET",
      "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST",
      "ONLY_MATERIAL_OLDER_THAN_FIVE_ELIGIBLE_PAST_EPOCHS_AND_REFERENCE_CLOSED_INSIDE_REPLAY_RETENTION_CHANGE",
      "AUTHENTICATED_TERMINAL_NOT_COMMITTED_AND_C_MUT_CLEARING_EVENT_REQUIRED",
      "C_MUT_ROLE_INVALIDATED_BUT_ALL_REFERENCES_MUST_FIRST_BE_PROVEN_ABSENT_OR_SUPERSEDED",
      "SELECTION_ROLE_TERMINATED_BUT_ALL_REFERENCES_MUST_FIRST_BE_PROVEN_ABSENT_OR_SUPERSEDED",
      "DISPOSE_ALL_BUT_MOST_RECENT_LOSER_AFTER_COMPLETE_SURVIVOR_COMMIT;_NO_RESIDUAL_DIGEST_OR_COUNTER",
      "REMOVE_OR_INVALIDATE_WRAPPER_FIRST",
      "SEPARATE_OWNER_AND_CLEANUP_CONTRACT_REQUIRED"
    ]
  },
  "materialClasses": [
    {
      "id": "CURRENT_AUTHORITATIVE_PROVIDER_SESSION_STATE",
      "owner": "SS_RS",
      "confidentiality": "SECRET",
      "creationTrigger": "COMMITTED_SESSION_TRANSITION",
      "minimum": "WHILE_AUTHORITATIVE",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "SUPERSEDED_BY_COMPLETE_AUTHENTICATED_AUTHORITY_OR_EXPLICIT_RESET"
      ]
    },
    {
      "id": "PAST_EPOCH_REPLAY_DECRYPTION_MATERIAL",
      "owner": "SS_RS",
      "confidentiality": "SECRET",
      "creationTrigger": "COMMITTED_EPOCH_ADVANCE",
      "minimum": "CURRENT_PLUS_FIVE_PAST_EPOCH_RULE",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "NOT_OLDER_THAN_FIVE_ELIGIBLE_PAST_EPOCHS",
        "LIVE_REPLAY_RESTORE_HOLD_OR_CRASH_REFERENCE"
      ]
    },
    {
      "id": "REPLAY_WINDOW_STATE",
      "owner": "SS_RS",
      "confidentiality": "SENSITIVE_METADATA",
      "creationTrigger": "REPLAY_RETENTION_COMPONENT",
      "minimum": "WHILE_CURRENT_OR_PAST_EPOCH_IS_ACCEPTABLE",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "LIVE_REPLAY_OR_DUPLICATE_CLASSIFICATION_REFERENCE"
      ]
    },
    {
      "id": "BINDING_PROFILE_METADATA",
      "owner": "SS_RS",
      "confidentiality": "SENSITIVE_METADATA",
      "creationTrigger": "BINDING_METADATA_COMPONENT",
      "minimum": "WHILE_ANY_STATE_HOLD_RESULT_OR_RESTORE_FACT_REFERENCES_IT",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "LIVE_BINDING_PROFILE_REFERENCE"
      ]
    },
    {
      "id": "AUTHENTICATED_MANIFEST_ROOT_FACTS",
      "owner": "RS",
      "confidentiality": "SENSITIVE_METADATA",
      "creationTrigger": "AUTHENTICATED_MANIFEST_UPDATE",
      "minimum": "WHILE_AUTHORITY_OR_RECOVERY_CLASSIFICATION_REFERENCES_IT",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "LIVE_AUTHORITY_RESULT_RESTORE_OR_CRASH_REFERENCE"
      ]
    },
    {
      "id": "MUTATION_CANDIDATE",
      "owner": "SS_RS",
      "confidentiality": "SECRET",
      "creationTrigger": "C_MUT_ENVELOPE_STAGING",
      "minimum": "UNTIL_AUTHENTICATED_TERMINAL_CLASSIFICATION_AND_CLEARING",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "UNRESOLVED_OR_AMBIGUOUS_OUTCOME",
        "LIVE_HOLD_RESULT_ESCROW_OR_RECOVERY_REFERENCE"
      ]
    },
    {
      "id": "ORIGINAL_AUTHORITY_REFERENCE",
      "owner": "SS_RS",
      "confidentiality": "SENSITIVE_METADATA",
      "creationTrigger": "C_MUT_ENVELOPE_STAGING",
      "minimum": "UNTIL_TERMINAL_CLASSIFICATION_AND_NO_RECOVERY_REFERENCE",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "LIVE_HOLD_RESULT_PARENT_OR_CRASH_REFERENCE"
      ]
    },
    {
      "id": "RECONCILIATION_IDENTITY",
      "owner": "SS_RS",
      "confidentiality": "SENSITIVE_METADATA",
      "creationTrigger": "C_MUT_ENVELOPE_STAGING",
      "minimum": "UNTIL_C_MUT_CLEARING_EVENT_AND_REPLAY_CLASSIFICATION_COMPLETE",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "UNRESOLVED_HOLD_OR_REPEAT_RECONCILIATION"
      ]
    },
    {
      "id": "UNRESOLVED_HOLD",
      "owner": "SS_RS",
      "confidentiality": "SENSITIVE_METADATA",
      "creationTrigger": "INDETERMINATE_OUTCOME",
      "minimum": "UNTIL_AUTHENTICATED_TERMINAL_CLASSIFICATION_AND_C_MUT_CLEARING_EVENT",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "OUTCOME_NOT_TERMINAL",
        "LOCAL_RESPONSE_EMISSION_NOT_SUCCESSFUL_WHERE_C_MUT_REQUIRES_IT"
      ]
    },
    {
      "id": "SELECTION_METADATA",
      "owner": "SS_RS",
      "confidentiality": "SENSITIVE_METADATA",
      "creationTrigger": "CAPI_S014_COMMIT",
      "minimum": "UNTIL_CAPI_S016_INVALIDATION_OR_CAPI_S017_TERMINATION",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "SELECTION_ELIGIBILITY_OR_LIVE_REFERENCE"
      ]
    },
    {
      "id": "RETAINED_PARENT",
      "owner": "SS_RS",
      "confidentiality": "SECRET",
      "creationTrigger": "CAPI_S014_COMMIT",
      "minimum": "WHILE_SELECTION_ELIGIBILITY_OR_UNRESOLVED_OPERATION_CAN_REFERENCE_IT",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "LIVE_SELECTION_HOLD_RESULT_ESCROW_REPLAY_OR_CRASH_REFERENCE"
      ]
    },
    {
      "id": "LOSING_CANDIDATE_EVIDENCE",
      "owner": "SS_RS",
      "confidentiality": "SECRET",
      "creationTrigger": "CAPI_S017_COMMIT",
      "minimum": "MOST_RECENT_UNTIL_SUPERSEDED_BY_OWNER_DECISION_5892675163_RETENTION_COMPACTION",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "MOST_RECENT_LOSER_NOT_YET_SUPERSEDED",
        "OWNER_DECISION_5892675163_RETENTION_COMPACTION_NOT_COMMITTED"
      ]
    },
    {
      "id": "COMMIT_RESULT_EVIDENCE",
      "owner": "RS",
      "confidentiality": "SENSITIVE_METADATA",
      "creationTrigger": "RS_RESULT",
      "minimum": "UNTIL_DUPLICATE_CONFLICTING_REPLAY_AND_RESTART_CLASSIFICATION_NO_LONGER_NEEDS_IT",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "LIVE_HOLD_RECONCILIATION_REPLAY_RESTORE_OR_CRASH_REFERENCE",
        "NO_RATIFIED_BOUNDED_COMPACTION_PROOF"
      ]
    },
    {
      "id": "OUTPUT_ESCROW_EMBEDDED_TREE_WELCOME",
      "owner": "SS_RS",
      "confidentiality": "SECRET",
      "creationTrigger": "CAPI_S001_STAGING",
      "minimum": "UNTIL_TERMINAL_CLASSIFICATION_AND_C_MUT_CLEARING_EVENT",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "INDETERMINATE_OR_INTERRUPTED_RESPONSE_EMISSION",
        "NO_AP_RECEIPT_EVIDENCE"
      ]
    },
    {
      "id": "OUTPUT_ESCROW_PROTECTED_APPLICATION_BYTES",
      "owner": "SS_RS",
      "confidentiality": "SECRET",
      "creationTrigger": "CAPI_S009_STAGING",
      "minimum": "UNTIL_TERMINAL_CLASSIFICATION_AND_C_MUT_CLEARING_EVENT",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "INDETERMINATE_OR_INTERRUPTED_RESPONSE_EMISSION",
        "NO_AP_RECEIPT_EVIDENCE"
      ]
    },
    {
      "id": "OUTPUT_ESCROW_APPLICATION_BYTES",
      "owner": "SS_RS",
      "confidentiality": "SECRET",
      "creationTrigger": "CAPI_S010_STAGING",
      "minimum": "UNTIL_TERMINAL_CLASSIFICATION_AND_C_MUT_CLEARING_EVENT",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "INDETERMINATE_OR_INTERRUPTED_RESPONSE_EMISSION",
        "NO_AP_RECEIPT_EVIDENCE"
      ]
    },
    {
      "id": "OUTPUT_ESCROW_PROTECTED_COMMIT_BYTES",
      "owner": "SS_RS",
      "confidentiality": "SECRET",
      "creationTrigger": "CAPI_S014_STAGING",
      "minimum": "UNTIL_TERMINAL_CLASSIFICATION_AND_C_MUT_CLEARING_EVENT",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "INDETERMINATE_OR_INTERRUPTED_RESPONSE_EMISSION",
        "NO_AP_RECEIPT_EVIDENCE"
      ]
    },
    {
      "id": "OUTPUT_ESCROW_SELECTED_CANDIDATE_REF",
      "owner": "SS_RS",
      "confidentiality": "SENSITIVE_METADATA",
      "creationTrigger": "CAPI_S017_STAGING",
      "minimum": "UNTIL_TERMINAL_CLASSIFICATION_AND_C_MUT_CLEARING_EVENT",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "INDETERMINATE_OR_INTERRUPTED_RESPONSE_EMISSION",
        "NO_AP_RECEIPT_EVIDENCE"
      ]
    },
    {
      "id": "KEY_PACKAGE_PRIVATE_MATERIAL",
      "owner": "SS_RS",
      "confidentiality": "SECRET",
      "creationTrigger": "LOCAL_KEY_PACKAGE_CREATION",
      "minimum": "UNTIL_COMMITTED_CONSUMPTION_AND_NO_ACTIVE_OR_HELD_MUTATION_REFERENCE",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "CONSUMPTION_NOT_PROVEN_COMMITTED",
        "ACTIVE_OR_HELD_CAPI_S006_REFERENCE",
        "PRIVATE_MATERIAL_MUST_NEVER_BE_REUSED"
      ]
    },
    {
      "id": "KEY_PACKAGE_PUBLIC_BYTES",
      "owner": "SS_RS",
      "confidentiality": "PUBLIC",
      "creationTrigger": "LOCAL_KEY_PACKAGE_CREATION",
      "minimum": "WHILE_ELIGIBILITY_AUDIT_OR_REFERENCE_CLOSURE_NEEDS_IT",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "LIVE_PACKAGE_ELIGIBILITY_AUDIT_OR_HOLD_REFERENCE"
      ]
    },
    {
      "id": "KEY_PACKAGE_CONSUMPTION_FACT",
      "owner": "RS",
      "confidentiality": "SENSITIVE_METADATA",
      "creationTrigger": "CAPI_S006_COMPONENT",
      "minimum": "WHILE_REUSE_PREVENTION_RESULT_OR_RESTART_CLASSIFICATION_NEEDS_IT",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "LIVE_REUSE_PREVENTION_RESULT_HOLD_OR_RESTART_REFERENCE"
      ]
    },
    {
      "id": "ROOT_STORAGE_KEY",
      "owner": "SS",
      "confidentiality": "SECRET",
      "creationTrigger": "VAULT_INITIALIZATION",
      "minimum": "WHILE_ANY_LIVE_SESSION_NAMESPACE_MATERIAL_REQUIRES_IT",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "LIVE_AUTHORITY_EPOCH_HOLD_ESCROW_PACKAGE_OR_RECOVERY_REFERENCE"
      ]
    },
    {
      "id": "KEK_WRAPPER",
      "owner": "SS_RS",
      "confidentiality": "SECRET",
      "creationTrigger": "VAULT_INITIALIZATION",
      "minimum": "UNTIL_EXPLICIT_DESTRUCTIVE_RESET_INVALIDATES_OR_REMOVES_IT",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "NO_EXPLICIT_RESET",
        "WRAPPER_REMOVAL_NOT_CONFIRMED"
      ]
    },
    {
      "id": "SESSION_NAMESPACE_DERIVED_KEYS",
      "owner": "SS",
      "confidentiality": "SECRET",
      "creationTrigger": "SESSION_NAMESPACE_DERIVATION",
      "minimum": "WHILE_LOGICAL_ROLE_OR_REFERENCE_IS_LIVE",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "LIVE_AUTHORITY_EPOCH_REPLAY_HOLD_ESCROW_PACKAGE_OR_RECOVERY_REFERENCE"
      ]
    },
    {
      "id": "VALUE_FREE_DIAGNOSTIC_RECORD",
      "owner": "SS_RS",
      "confidentiality": "NON_SECRET_ALLOWLISTED",
      "creationTrigger": "ALLOWLISTED_REPORT_EVENT",
      "minimum": "UNTIL_DIAGNOSTIC_OWNER_POLICY_PERMITS_LOGICAL_DELETION",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "NO_SEPARATELY_RATIFIED_DIAGNOSTIC_RETENTION_POLICY"
      ]
    },
    {
      "id": "LEGACY_BYTES",
      "owner": "LEGACY_OWNER",
      "confidentiality": "UNKNOWN_LEGACY",
      "creationTrigger": "PREEXISTING_INPUT",
      "minimum": "AS_REQUIRED_BY_SEPARATE_LEGACY_OWNER",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "LEGACY_CLEANUP_OUT_OF_SCOPE",
        "NO_OWNER_RATIFIED_MIGRATION_OR_CLEANUP"
      ]
    },
    {
      "id": "LEGACY_INVALIDATION_MARKERS",
      "owner": "LEGACY_OWNER",
      "confidentiality": "SENSITIVE_METADATA",
      "creationTrigger": "PREEXISTING_INPUT",
      "minimum": "AS_REQUIRED_BY_SEPARATE_LEGACY_OWNER",
      "maximum": "UNBOUNDED_UNTIL_CONDITION",
      "blockers": [
        "LEGACY_CLEANUP_OUT_OF_SCOPE",
        "NO_OWNER_RATIFIED_MIGRATION_OR_CLEANUP"
      ]
    }
  ],
  "lifecycleMatrix": [
    {
      "material": "CURRENT_AUTHORITATIVE_PROVIDER_SESSION_STATE",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "CURRENT_AUTHORITATIVE_PROVIDER_SESSION_STATE",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "CURRENT_AUTHORITATIVE_PROVIDER_SESSION_STATE",
      "event": "NOT_COMMITTED",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "CURRENT_AUTHORITATIVE_PROVIDER_SESSION_STATE",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "CURRENT_AUTHORITATIVE_PROVIDER_SESSION_STATE",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "CURRENT_AUTHORITATIVE_PROVIDER_SESSION_STATE",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "CURRENT_AUTHORITATIVE_PROVIDER_SESSION_STATE",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "CURRENT_AUTHORITATIVE_PROVIDER_SESSION_STATE",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "CURRENT_AUTHORITATIVE_PROVIDER_SESSION_STATE",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "CURRENT_AUTHORITATIVE_PROVIDER_SESSION_STATE",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "CURRENT_AUTHORITATIVE_PROVIDER_SESSION_STATE",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "CURRENT_AUTHORITATIVE_PROVIDER_SESSION_STATE",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "CURRENT_AUTHORITATIVE_PROVIDER_SESSION_STATE",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "CURRENT_AUTHORITATIVE_PROVIDER_SESSION_STATE",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "CURRENT_AUTHORITATIVE_PROVIDER_SESSION_STATE",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "CURRENT_AUTHORITATIVE_PROVIDER_SESSION_STATE",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "PAST_EPOCH_REPLAY_DECRYPTION_MATERIAL",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "PAST_EPOCH_REPLAY_DECRYPTION_MATERIAL",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "PAST_EPOCH_REPLAY_DECRYPTION_MATERIAL",
      "event": "NOT_COMMITTED",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "PAST_EPOCH_REPLAY_DECRYPTION_MATERIAL",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "PAST_EPOCH_REPLAY_DECRYPTION_MATERIAL",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "PAST_EPOCH_REPLAY_DECRYPTION_MATERIAL",
      "event": "EPOCH_ADVANCE",
      "transition": "COMPACTION_CANDIDATE",
      "condition": "ONLY_MATERIAL_OLDER_THAN_FIVE_ELIGIBLE_PAST_EPOCHS_AND_REFERENCE_CLOSED_INSIDE_REPLAY_RETENTION_CHANGE"
    },
    {
      "material": "PAST_EPOCH_REPLAY_DECRYPTION_MATERIAL",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "PAST_EPOCH_REPLAY_DECRYPTION_MATERIAL",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "PAST_EPOCH_REPLAY_DECRYPTION_MATERIAL",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "PAST_EPOCH_REPLAY_DECRYPTION_MATERIAL",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "PAST_EPOCH_REPLAY_DECRYPTION_MATERIAL",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "PAST_EPOCH_REPLAY_DECRYPTION_MATERIAL",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "PAST_EPOCH_REPLAY_DECRYPTION_MATERIAL",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "PAST_EPOCH_REPLAY_DECRYPTION_MATERIAL",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "PAST_EPOCH_REPLAY_DECRYPTION_MATERIAL",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "PAST_EPOCH_REPLAY_DECRYPTION_MATERIAL",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "REPLAY_WINDOW_STATE",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "REPLAY_WINDOW_STATE",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "REPLAY_WINDOW_STATE",
      "event": "NOT_COMMITTED",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "REPLAY_WINDOW_STATE",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "REPLAY_WINDOW_STATE",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "REPLAY_WINDOW_STATE",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "REPLAY_WINDOW_STATE",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "REPLAY_WINDOW_STATE",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "REPLAY_WINDOW_STATE",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "REPLAY_WINDOW_STATE",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "REPLAY_WINDOW_STATE",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "REPLAY_WINDOW_STATE",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "REPLAY_WINDOW_STATE",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "REPLAY_WINDOW_STATE",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "REPLAY_WINDOW_STATE",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "REPLAY_WINDOW_STATE",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "BINDING_PROFILE_METADATA",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "BINDING_PROFILE_METADATA",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "BINDING_PROFILE_METADATA",
      "event": "NOT_COMMITTED",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "BINDING_PROFILE_METADATA",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "BINDING_PROFILE_METADATA",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "BINDING_PROFILE_METADATA",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "BINDING_PROFILE_METADATA",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "BINDING_PROFILE_METADATA",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "BINDING_PROFILE_METADATA",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "BINDING_PROFILE_METADATA",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "BINDING_PROFILE_METADATA",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "BINDING_PROFILE_METADATA",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "BINDING_PROFILE_METADATA",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "BINDING_PROFILE_METADATA",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "BINDING_PROFILE_METADATA",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "BINDING_PROFILE_METADATA",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "AUTHENTICATED_MANIFEST_ROOT_FACTS",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "AUTHENTICATED_MANIFEST_ROOT_FACTS",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "AUTHENTICATED_MANIFEST_ROOT_FACTS",
      "event": "NOT_COMMITTED",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "AUTHENTICATED_MANIFEST_ROOT_FACTS",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "AUTHENTICATED_MANIFEST_ROOT_FACTS",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "AUTHENTICATED_MANIFEST_ROOT_FACTS",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "AUTHENTICATED_MANIFEST_ROOT_FACTS",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "AUTHENTICATED_MANIFEST_ROOT_FACTS",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "AUTHENTICATED_MANIFEST_ROOT_FACTS",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "AUTHENTICATED_MANIFEST_ROOT_FACTS",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "AUTHENTICATED_MANIFEST_ROOT_FACTS",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "AUTHENTICATED_MANIFEST_ROOT_FACTS",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "AUTHENTICATED_MANIFEST_ROOT_FACTS",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "AUTHENTICATED_MANIFEST_ROOT_FACTS",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "AUTHENTICATED_MANIFEST_ROOT_FACTS",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "AUTHENTICATED_MANIFEST_ROOT_FACTS",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "MUTATION_CANDIDATE",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "MUTATION_CANDIDATE",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "MUTATION_CANDIDATE",
      "event": "NOT_COMMITTED",
      "transition": "COMPACTION_CANDIDATE",
      "condition": "AUTHENTICATED_TERMINAL_NOT_COMMITTED_AND_C_MUT_CLEARING_EVENT_REQUIRED"
    },
    {
      "material": "MUTATION_CANDIDATE",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "MUTATION_CANDIDATE",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "MUTATION_CANDIDATE",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "MUTATION_CANDIDATE",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "MUTATION_CANDIDATE",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "MUTATION_CANDIDATE",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "MUTATION_CANDIDATE",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "MUTATION_CANDIDATE",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "MUTATION_CANDIDATE",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "MUTATION_CANDIDATE",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "MUTATION_CANDIDATE",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "MUTATION_CANDIDATE",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "MUTATION_CANDIDATE",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "ORIGINAL_AUTHORITY_REFERENCE",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ORIGINAL_AUTHORITY_REFERENCE",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ORIGINAL_AUTHORITY_REFERENCE",
      "event": "NOT_COMMITTED",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ORIGINAL_AUTHORITY_REFERENCE",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ORIGINAL_AUTHORITY_REFERENCE",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ORIGINAL_AUTHORITY_REFERENCE",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ORIGINAL_AUTHORITY_REFERENCE",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ORIGINAL_AUTHORITY_REFERENCE",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ORIGINAL_AUTHORITY_REFERENCE",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ORIGINAL_AUTHORITY_REFERENCE",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ORIGINAL_AUTHORITY_REFERENCE",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ORIGINAL_AUTHORITY_REFERENCE",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ORIGINAL_AUTHORITY_REFERENCE",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "ORIGINAL_AUTHORITY_REFERENCE",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "ORIGINAL_AUTHORITY_REFERENCE",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "ORIGINAL_AUTHORITY_REFERENCE",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "RECONCILIATION_IDENTITY",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "RECONCILIATION_IDENTITY",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "RECONCILIATION_IDENTITY",
      "event": "NOT_COMMITTED",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "RECONCILIATION_IDENTITY",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "RECONCILIATION_IDENTITY",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "RECONCILIATION_IDENTITY",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "RECONCILIATION_IDENTITY",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "RECONCILIATION_IDENTITY",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "RECONCILIATION_IDENTITY",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "RECONCILIATION_IDENTITY",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "RECONCILIATION_IDENTITY",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "RECONCILIATION_IDENTITY",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "RECONCILIATION_IDENTITY",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "RECONCILIATION_IDENTITY",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "RECONCILIATION_IDENTITY",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "RECONCILIATION_IDENTITY",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "UNRESOLVED_HOLD",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "UNRESOLVED_HOLD",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "UNRESOLVED_HOLD",
      "event": "NOT_COMMITTED",
      "transition": "COMPACTION_CANDIDATE",
      "condition": "AUTHENTICATED_TERMINAL_NOT_COMMITTED_AND_C_MUT_CLEARING_EVENT_REQUIRED"
    },
    {
      "material": "UNRESOLVED_HOLD",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "UNRESOLVED_HOLD",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "UNRESOLVED_HOLD",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "UNRESOLVED_HOLD",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "UNRESOLVED_HOLD",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "UNRESOLVED_HOLD",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "UNRESOLVED_HOLD",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "UNRESOLVED_HOLD",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "UNRESOLVED_HOLD",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "UNRESOLVED_HOLD",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "UNRESOLVED_HOLD",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "UNRESOLVED_HOLD",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "UNRESOLVED_HOLD",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "SELECTION_METADATA",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "SELECTION_METADATA",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "SELECTION_METADATA",
      "event": "NOT_COMMITTED",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "SELECTION_METADATA",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "SELECTION_METADATA",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "SELECTION_METADATA",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "SELECTION_METADATA",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "SELECTION_METADATA",
      "event": "CAPI_S016_SELECTION",
      "transition": "COMPACTION_CANDIDATE",
      "condition": "C_MUT_ROLE_INVALIDATED_BUT_ALL_REFERENCES_MUST_FIRST_BE_PROVEN_ABSENT_OR_SUPERSEDED"
    },
    {
      "material": "SELECTION_METADATA",
      "event": "CAPI_S017_SELECTION",
      "transition": "COMPACTION_CANDIDATE",
      "condition": "SELECTION_ROLE_TERMINATED_BUT_ALL_REFERENCES_MUST_FIRST_BE_PROVEN_ABSENT_OR_SUPERSEDED"
    },
    {
      "material": "SELECTION_METADATA",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "SELECTION_METADATA",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "SELECTION_METADATA",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "SELECTION_METADATA",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "SELECTION_METADATA",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "SELECTION_METADATA",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "SELECTION_METADATA",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "RETAINED_PARENT",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "RETAINED_PARENT",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "RETAINED_PARENT",
      "event": "NOT_COMMITTED",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "RETAINED_PARENT",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "RETAINED_PARENT",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "RETAINED_PARENT",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "RETAINED_PARENT",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "RETAINED_PARENT",
      "event": "CAPI_S016_SELECTION",
      "transition": "COMPACTION_CANDIDATE",
      "condition": "C_MUT_ROLE_INVALIDATED_BUT_ALL_REFERENCES_MUST_FIRST_BE_PROVEN_ABSENT_OR_SUPERSEDED"
    },
    {
      "material": "RETAINED_PARENT",
      "event": "CAPI_S017_SELECTION",
      "transition": "COMPACTION_CANDIDATE",
      "condition": "SELECTION_ROLE_TERMINATED_BUT_ALL_REFERENCES_MUST_FIRST_BE_PROVEN_ABSENT_OR_SUPERSEDED"
    },
    {
      "material": "RETAINED_PARENT",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "RETAINED_PARENT",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "RETAINED_PARENT",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "RETAINED_PARENT",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "RETAINED_PARENT",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "RETAINED_PARENT",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "RETAINED_PARENT",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "LOSING_CANDIDATE_EVIDENCE",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LOSING_CANDIDATE_EVIDENCE",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LOSING_CANDIDATE_EVIDENCE",
      "event": "NOT_COMMITTED",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LOSING_CANDIDATE_EVIDENCE",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LOSING_CANDIDATE_EVIDENCE",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LOSING_CANDIDATE_EVIDENCE",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LOSING_CANDIDATE_EVIDENCE",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LOSING_CANDIDATE_EVIDENCE",
      "event": "CAPI_S016_SELECTION",
      "transition": "COMPACTION_CANDIDATE",
      "condition": "C_MUT_ROLE_INVALIDATED_BUT_ALL_REFERENCES_MUST_FIRST_BE_PROVEN_ABSENT_OR_SUPERSEDED"
    },
    {
      "material": "LOSING_CANDIDATE_EVIDENCE",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LOSING_CANDIDATE_EVIDENCE",
      "event": "RETENTION_COMPACTION",
      "transition": "LOGICALLY_DELETE",
      "condition": "DISPOSE_ALL_BUT_MOST_RECENT_LOSER_AFTER_COMPLETE_SURVIVOR_COMMIT;_NO_RESIDUAL_DIGEST_OR_COUNTER"
    },
    {
      "material": "LOSING_CANDIDATE_EVIDENCE",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LOSING_CANDIDATE_EVIDENCE",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LOSING_CANDIDATE_EVIDENCE",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "LOSING_CANDIDATE_EVIDENCE",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "LOSING_CANDIDATE_EVIDENCE",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "LOSING_CANDIDATE_EVIDENCE",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "COMMIT_RESULT_EVIDENCE",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "COMMIT_RESULT_EVIDENCE",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "COMMIT_RESULT_EVIDENCE",
      "event": "NOT_COMMITTED",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "COMMIT_RESULT_EVIDENCE",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "COMMIT_RESULT_EVIDENCE",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "COMMIT_RESULT_EVIDENCE",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "COMMIT_RESULT_EVIDENCE",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "COMMIT_RESULT_EVIDENCE",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "COMMIT_RESULT_EVIDENCE",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "COMMIT_RESULT_EVIDENCE",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "COMMIT_RESULT_EVIDENCE",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "COMMIT_RESULT_EVIDENCE",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "COMMIT_RESULT_EVIDENCE",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "COMMIT_RESULT_EVIDENCE",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "COMMIT_RESULT_EVIDENCE",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "COMMIT_RESULT_EVIDENCE",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "OUTPUT_ESCROW_EMBEDDED_TREE_WELCOME",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_EMBEDDED_TREE_WELCOME",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_EMBEDDED_TREE_WELCOME",
      "event": "NOT_COMMITTED",
      "transition": "COMPACTION_CANDIDATE",
      "condition": "AUTHENTICATED_TERMINAL_NOT_COMMITTED_AND_C_MUT_CLEARING_EVENT_REQUIRED"
    },
    {
      "material": "OUTPUT_ESCROW_EMBEDDED_TREE_WELCOME",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_EMBEDDED_TREE_WELCOME",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_EMBEDDED_TREE_WELCOME",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_EMBEDDED_TREE_WELCOME",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_EMBEDDED_TREE_WELCOME",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_EMBEDDED_TREE_WELCOME",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_EMBEDDED_TREE_WELCOME",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_EMBEDDED_TREE_WELCOME",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_EMBEDDED_TREE_WELCOME",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_EMBEDDED_TREE_WELCOME",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "OUTPUT_ESCROW_EMBEDDED_TREE_WELCOME",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "OUTPUT_ESCROW_EMBEDDED_TREE_WELCOME",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "OUTPUT_ESCROW_EMBEDDED_TREE_WELCOME",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_APPLICATION_BYTES",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_APPLICATION_BYTES",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_APPLICATION_BYTES",
      "event": "NOT_COMMITTED",
      "transition": "COMPACTION_CANDIDATE",
      "condition": "AUTHENTICATED_TERMINAL_NOT_COMMITTED_AND_C_MUT_CLEARING_EVENT_REQUIRED"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_APPLICATION_BYTES",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_APPLICATION_BYTES",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_APPLICATION_BYTES",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_APPLICATION_BYTES",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_APPLICATION_BYTES",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_APPLICATION_BYTES",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_APPLICATION_BYTES",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_APPLICATION_BYTES",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_APPLICATION_BYTES",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_APPLICATION_BYTES",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_APPLICATION_BYTES",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_APPLICATION_BYTES",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_APPLICATION_BYTES",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "OUTPUT_ESCROW_APPLICATION_BYTES",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_APPLICATION_BYTES",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_APPLICATION_BYTES",
      "event": "NOT_COMMITTED",
      "transition": "COMPACTION_CANDIDATE",
      "condition": "AUTHENTICATED_TERMINAL_NOT_COMMITTED_AND_C_MUT_CLEARING_EVENT_REQUIRED"
    },
    {
      "material": "OUTPUT_ESCROW_APPLICATION_BYTES",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_APPLICATION_BYTES",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_APPLICATION_BYTES",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_APPLICATION_BYTES",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_APPLICATION_BYTES",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_APPLICATION_BYTES",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_APPLICATION_BYTES",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_APPLICATION_BYTES",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_APPLICATION_BYTES",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_APPLICATION_BYTES",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "OUTPUT_ESCROW_APPLICATION_BYTES",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "OUTPUT_ESCROW_APPLICATION_BYTES",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "OUTPUT_ESCROW_APPLICATION_BYTES",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_COMMIT_BYTES",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_COMMIT_BYTES",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_COMMIT_BYTES",
      "event": "NOT_COMMITTED",
      "transition": "COMPACTION_CANDIDATE",
      "condition": "AUTHENTICATED_TERMINAL_NOT_COMMITTED_AND_C_MUT_CLEARING_EVENT_REQUIRED"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_COMMIT_BYTES",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_COMMIT_BYTES",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_COMMIT_BYTES",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_COMMIT_BYTES",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_COMMIT_BYTES",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_COMMIT_BYTES",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_COMMIT_BYTES",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_COMMIT_BYTES",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_COMMIT_BYTES",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_COMMIT_BYTES",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_COMMIT_BYTES",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_COMMIT_BYTES",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "OUTPUT_ESCROW_PROTECTED_COMMIT_BYTES",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "OUTPUT_ESCROW_SELECTED_CANDIDATE_REF",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_SELECTED_CANDIDATE_REF",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_SELECTED_CANDIDATE_REF",
      "event": "NOT_COMMITTED",
      "transition": "COMPACTION_CANDIDATE",
      "condition": "AUTHENTICATED_TERMINAL_NOT_COMMITTED_AND_C_MUT_CLEARING_EVENT_REQUIRED"
    },
    {
      "material": "OUTPUT_ESCROW_SELECTED_CANDIDATE_REF",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_SELECTED_CANDIDATE_REF",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_SELECTED_CANDIDATE_REF",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_SELECTED_CANDIDATE_REF",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_SELECTED_CANDIDATE_REF",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_SELECTED_CANDIDATE_REF",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_SELECTED_CANDIDATE_REF",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_SELECTED_CANDIDATE_REF",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_SELECTED_CANDIDATE_REF",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "OUTPUT_ESCROW_SELECTED_CANDIDATE_REF",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "OUTPUT_ESCROW_SELECTED_CANDIDATE_REF",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "OUTPUT_ESCROW_SELECTED_CANDIDATE_REF",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "OUTPUT_ESCROW_SELECTED_CANDIDATE_REF",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "KEY_PACKAGE_PRIVATE_MATERIAL",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PRIVATE_MATERIAL",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PRIVATE_MATERIAL",
      "event": "NOT_COMMITTED",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PRIVATE_MATERIAL",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PRIVATE_MATERIAL",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PRIVATE_MATERIAL",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PRIVATE_MATERIAL",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PRIVATE_MATERIAL",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PRIVATE_MATERIAL",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PRIVATE_MATERIAL",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PRIVATE_MATERIAL",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PRIVATE_MATERIAL",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PRIVATE_MATERIAL",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "KEY_PACKAGE_PRIVATE_MATERIAL",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "KEY_PACKAGE_PRIVATE_MATERIAL",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "KEY_PACKAGE_PRIVATE_MATERIAL",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "KEY_PACKAGE_PUBLIC_BYTES",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PUBLIC_BYTES",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PUBLIC_BYTES",
      "event": "NOT_COMMITTED",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PUBLIC_BYTES",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PUBLIC_BYTES",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PUBLIC_BYTES",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PUBLIC_BYTES",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PUBLIC_BYTES",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PUBLIC_BYTES",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PUBLIC_BYTES",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PUBLIC_BYTES",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PUBLIC_BYTES",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_PUBLIC_BYTES",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "KEY_PACKAGE_PUBLIC_BYTES",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "KEY_PACKAGE_PUBLIC_BYTES",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "KEY_PACKAGE_PUBLIC_BYTES",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "KEY_PACKAGE_CONSUMPTION_FACT",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_CONSUMPTION_FACT",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_CONSUMPTION_FACT",
      "event": "NOT_COMMITTED",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_CONSUMPTION_FACT",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_CONSUMPTION_FACT",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_CONSUMPTION_FACT",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_CONSUMPTION_FACT",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_CONSUMPTION_FACT",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_CONSUMPTION_FACT",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_CONSUMPTION_FACT",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_CONSUMPTION_FACT",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_CONSUMPTION_FACT",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEY_PACKAGE_CONSUMPTION_FACT",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "KEY_PACKAGE_CONSUMPTION_FACT",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "KEY_PACKAGE_CONSUMPTION_FACT",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "KEY_PACKAGE_CONSUMPTION_FACT",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "ROOT_STORAGE_KEY",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ROOT_STORAGE_KEY",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ROOT_STORAGE_KEY",
      "event": "NOT_COMMITTED",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ROOT_STORAGE_KEY",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ROOT_STORAGE_KEY",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ROOT_STORAGE_KEY",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ROOT_STORAGE_KEY",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ROOT_STORAGE_KEY",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ROOT_STORAGE_KEY",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ROOT_STORAGE_KEY",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ROOT_STORAGE_KEY",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ROOT_STORAGE_KEY",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "ROOT_STORAGE_KEY",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "ROOT_STORAGE_KEY",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "ROOT_STORAGE_KEY",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "ROOT_STORAGE_KEY",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "KEK_WRAPPER",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEK_WRAPPER",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEK_WRAPPER",
      "event": "NOT_COMMITTED",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEK_WRAPPER",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEK_WRAPPER",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEK_WRAPPER",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEK_WRAPPER",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEK_WRAPPER",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEK_WRAPPER",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEK_WRAPPER",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEK_WRAPPER",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEK_WRAPPER",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "KEK_WRAPPER",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "KEK_WRAPPER",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "KEK_WRAPPER",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "KEK_WRAPPER",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "REMOVE_OR_INVALIDATE_WRAPPER_FIRST"
    },
    {
      "material": "SESSION_NAMESPACE_DERIVED_KEYS",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "SESSION_NAMESPACE_DERIVED_KEYS",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "SESSION_NAMESPACE_DERIVED_KEYS",
      "event": "NOT_COMMITTED",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "SESSION_NAMESPACE_DERIVED_KEYS",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "SESSION_NAMESPACE_DERIVED_KEYS",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "SESSION_NAMESPACE_DERIVED_KEYS",
      "event": "EPOCH_ADVANCE",
      "transition": "COMPACTION_CANDIDATE",
      "condition": "ONLY_MATERIAL_OLDER_THAN_FIVE_ELIGIBLE_PAST_EPOCHS_AND_REFERENCE_CLOSED_INSIDE_REPLAY_RETENTION_CHANGE"
    },
    {
      "material": "SESSION_NAMESPACE_DERIVED_KEYS",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "SESSION_NAMESPACE_DERIVED_KEYS",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "SESSION_NAMESPACE_DERIVED_KEYS",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "SESSION_NAMESPACE_DERIVED_KEYS",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "SESSION_NAMESPACE_DERIVED_KEYS",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "SESSION_NAMESPACE_DERIVED_KEYS",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "SESSION_NAMESPACE_DERIVED_KEYS",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "SESSION_NAMESPACE_DERIVED_KEYS",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "SESSION_NAMESPACE_DERIVED_KEYS",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "SESSION_NAMESPACE_DERIVED_KEYS",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "VALUE_FREE_DIAGNOSTIC_RECORD",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "VALUE_FREE_DIAGNOSTIC_RECORD",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "VALUE_FREE_DIAGNOSTIC_RECORD",
      "event": "NOT_COMMITTED",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "VALUE_FREE_DIAGNOSTIC_RECORD",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "VALUE_FREE_DIAGNOSTIC_RECORD",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "VALUE_FREE_DIAGNOSTIC_RECORD",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "VALUE_FREE_DIAGNOSTIC_RECORD",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "VALUE_FREE_DIAGNOSTIC_RECORD",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "VALUE_FREE_DIAGNOSTIC_RECORD",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "VALUE_FREE_DIAGNOSTIC_RECORD",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "VALUE_FREE_DIAGNOSTIC_RECORD",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "VALUE_FREE_DIAGNOSTIC_RECORD",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "VALUE_FREE_DIAGNOSTIC_RECORD",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "VALUE_FREE_DIAGNOSTIC_RECORD",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "VALUE_FREE_DIAGNOSTIC_RECORD",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "VALUE_FREE_DIAGNOSTIC_RECORD",
      "event": "EXPLICIT_RESET",
      "transition": "LOGICALLY_DELETE",
      "condition": "ONLY_AFTER_WRAPPER_INVALIDATION_THEN_DATABASE_DELETION_REQUEST"
    },
    {
      "material": "LEGACY_BYTES",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_BYTES",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_BYTES",
      "event": "NOT_COMMITTED",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_BYTES",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_BYTES",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_BYTES",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_BYTES",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_BYTES",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_BYTES",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_BYTES",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_BYTES",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_BYTES",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_BYTES",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "LEGACY_BYTES",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "LEGACY_BYTES",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "LEGACY_BYTES",
      "event": "EXPLICIT_RESET",
      "transition": "BLOCK",
      "condition": "SEPARATE_OWNER_AND_CLEANUP_CONTRACT_REQUIRED"
    },
    {
      "material": "LEGACY_INVALIDATION_MARKERS",
      "event": "CREATION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_INVALIDATION_MARKERS",
      "event": "COMMIT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_INVALIDATION_MARKERS",
      "event": "NOT_COMMITTED",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_INVALIDATION_MARKERS",
      "event": "INDETERMINATE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_INVALIDATION_MARKERS",
      "event": "RECONCILIATION_REPEAT",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_INVALIDATION_MARKERS",
      "event": "EPOCH_ADVANCE",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_INVALIDATION_MARKERS",
      "event": "CAPI_S014_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_INVALIDATION_MARKERS",
      "event": "CAPI_S016_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_INVALIDATION_MARKERS",
      "event": "CAPI_S017_SELECTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_INVALIDATION_MARKERS",
      "event": "RETENTION_COMPACTION",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_INVALIDATION_MARKERS",
      "event": "RESTART",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_INVALIDATION_MARKERS",
      "event": "LOCK",
      "transition": "RETAIN",
      "condition": "LIVE_OR_POTENTIALLY_REFERENCED;_NO_TIME_BASED_DISPOSAL"
    },
    {
      "material": "LEGACY_INVALIDATION_MARKERS",
      "event": "CORRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "LEGACY_INVALIDATION_MARKERS",
      "event": "QUOTA_FAILURE",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "LEGACY_INVALIDATION_MARKERS",
      "event": "COMPACTION_INTERRUPTION",
      "transition": "BLOCK",
      "condition": "AMBIGUOUS_OR_INCOMPLETE_EVIDENCE_RETAINS_OLD_COMPLETE_SET"
    },
    {
      "material": "LEGACY_INVALIDATION_MARKERS",
      "event": "EXPLICIT_RESET",
      "transition": "BLOCK",
      "condition": "SEPARATE_OWNER_AND_CLEANUP_CONTRACT_REQUIRED"
    }
  ],
  "epochRule": {
    "currentEpochs": 1,
    "maximumPastEpochs": 5,
    "pastEpochsOnceAvailable": 5,
    "advance": "INSERT_NEW_CURRENT_AND_KEEP_FIVE_IMMEDIATELY_PRECEDING_ELIGIBLE_EPOCHS",
    "olderEligible": "COMPACTION_CANDIDATE_ONLY_INSIDE_C_MUT_REPLAY_RETENTION_STATE_CHANGE_AND_AFTER_REFERENCE_CLOSURE",
    "outOfOrderDuplicateFutureOutsideWindow": "MUST_NOT_EXTEND_OR_SHRINK_WINDOW",
    "reduction": "FORBIDDEN_WITHOUT_NEW_OWNER_RATIFIED_CONTRACT_AND_NO_RESTORE_REPLAY_REGRESSION_FIXTURES"
  },
  "losingCandidateRule": {
    "maximumPerCapiS017Selection": 1,
    "maximumAtRest": 1,
    "maximumTransient": 2,
    "authoritative": false,
    "retryable": false,
    "association": "EXACT_SELECTED_TRANSITION_PARENT_AND_SELECTION_EVIDENCE",
    "successiveSelections": "ALLOW_COMMITTED_S017_TO_CREATE_AT_MOST_SECOND_TRANSIENT_LOSER;_COMPACT_BEFORE_ANY_LATER_RS_MUTATION_OR_S014_ELIGIBILITY",
    "capiS016": "INVALIDATES_PRIOR_ELIGIBILITY_AND_EVIDENCE_ROLE_BUT_DOES_NOT_PROVE_PHYSICAL_DISPOSAL",
    "compactionSafetyEvidence": "OWNER_DECISION_5892675163_AUTHORIZES_OLDER_LOSER_DISPOSAL_AFTER_AUTHENTICATED_NEWEST_ONLY_SURVIVOR_COMMIT",
    "absentEvidence": "IF_RETENTION_COMPACTION_NOT_COMMITTED_RETAIN_BOTH_AND_BLOCK_LATER_RS_MUTATION_AND_NEW_S014_ELIGIBILITY"
  },
  "retentionCompactionRule": {
    "ownerDecision": "ISSUE_328_COMMENT_5892675163_OPTION_A",
    "trigger": "IMMEDIATELY_AFTER_EACH_COMMITTED_CAPI_S017_THAT_LEAVES_TWO_LOSERS",
    "precondition": "EXACTLY_TWO_LOSERS;_NEWEST_IDENTIFIED_BY_COMMITTED_S017_SELECTION_EVIDENCE",
    "survivor": "MOST_RECENT_LOSER_ONLY",
    "disposal": "LOGICALLY_DELETE_OLDER_LOSER_AND_REQUEST_DATABASE_DELETION_AFTER_AUTHENTICATED_COMPACTION_COMMIT",
    "ordering": "COMPACTION_MUST_COMMIT_BEFORE_ANY_LATER_RS_MUTATION_AND_BEFORE_NEW_CAPI_S014_ELIGIBILITY",
    "failure": "FAIL_CLOSED;_NO_NEW_CAPI_S014_ELIGIBILITY_AND_NO_LATER_RS_MUTATION_UNTIL_COMPACTION_COMMITS",
    "thirdLoser": "IMPOSSIBLE_BECAUSE_S014_ELIGIBILITY_IS_CLOSED_WHILE_COMPACTION_PENDING",
    "atRestMaximum": 1,
    "transientMaximum": 2,
    "residualTrace": "NO_DIGEST_COUNTER_REFERENCE_OR_DIAGNOSTIC_DERIVED_FROM_DISPOSED_LOSER",
    "cMutRowsChanged": false
  },
  "retainedParentRule": {
    "capiS014": "ESTABLISH_PARENT_REQUIRED_BY_CAPI_S017",
    "capiS009S010": "PRESERVE",
    "capiS016": "TERMINATE_SELECTION_ROLE_BY_INVALIDATION",
    "capiS017": "TERMINATE_SELECTION_ROLE",
    "candidateOnlyAfter": "NO_HOLD_RESULT_ESCROW_REPLAY_WINDOW_CRASH_RECOVERY_OR_SELECTION_REFERENCE"
  },
  "resultHoldEscrowRule": {
    "indeterminate": "RETAIN_IMMUTABLE_CANDIDATE_ORIGINAL_AUTHORITY_RECONCILIATION_IDENTITY_MATCHING_RESULT_AND_ESCROW",
    "committedInterruptedEmission": "RETAIN_ESCROW_AND_INTERNAL_EVIDENCE_AS_C_MUT_REQUIRES;_DO_NOT_ASSUME_AP_RECEIPT",
    "terminalNotCommitted": "CANDIDATE_AND_ESCROW_CANDIDATE_ONLY_AFTER_AUTHENTICATED_PROOF_AND_C_MUT_CLEARING_EVENT",
    "clearedResult": "RETAIN_UNTIL_BOUNDED_PROOF_NO_DUPLICATE_CONFLICTING_REPLAY_OR_RESTART_CLASSIFICATION_NEEDS_IT",
    "wallClockExpiry": "NONE"
  },
  "keyPackageRule": {
    "cMutComponent": "KEY_PACKAGE_CONSUMPTION",
    "scenario": "CAPI-S006",
    "unresolvedOrNotCommittedConsumption": "RETAIN_PRIVATE_MATERIAL_AND_NEVER_REUSE_IT",
    "terminalCommitted": "DISPOSAL_CANDIDATE_ONLY_AFTER_NO_ACTIVE_OR_HELD_MUTATION_REFERENCE",
    "publicDistinct": true,
    "publicMayAliasNewPackage": false,
    "unknownLifecycleFact": "BLOCK_AND_RETAIN"
  },
  "sessionNamespaceKeyRule": {
    "roles": [
      "CURRENT_AUTHORITY",
      "PAST_EPOCH",
      "REPLAY_RETENTION",
      "MUTATION_CANDIDATE_AND_HOLD",
      "MANIFEST_AUTHENTICATION",
      "OUTPUT_ESCROW",
      "KEY_PACKAGE"
    ],
    "classification": "EACH_DERIVED_KEY_INSTANCE_HAS_EXACTLY_ONE_LOGICAL_ROLE",
    "lifetime": "FOLLOW_REFERENCED_ROLE_AND_SESSION_NAMESPACE_DERIVED_KEYS_MATRIX_CLASS",
    "labelsOrVersionsNamed": false,
    "unknownOrMultipleRole": "BLOCK_AND_RETAIN"
  },
  "classificationMap": {
    "componentToMaterialClass": {
      "SESSION_TRANSITION": "CURRENT_AUTHORITATIVE_PROVIDER_SESSION_STATE",
      "BINDING_METADATA": "BINDING_PROFILE_METADATA",
      "REPLAY_RETENTION_STATE": "REPLAY_WINDOW_STATE",
      "AUTHENTICATED_MANIFEST_UPDATE": "AUTHENTICATED_MANIFEST_ROOT_FACTS",
      "COMMIT_RESULT_EVIDENCE": "COMMIT_RESULT_EVIDENCE",
      "KEY_PACKAGE_CONSUMPTION": "KEY_PACKAGE_CONSUMPTION_FACT",
      "OUTPUT_ESCROW": {
        "classification": "EXACTLY_ONE_BY_SCENARIO",
        "byScenario": {
          "CAPI-S001": "OUTPUT_ESCROW_EMBEDDED_TREE_WELCOME",
          "CAPI-S009": "OUTPUT_ESCROW_PROTECTED_APPLICATION_BYTES",
          "CAPI-S010": "OUTPUT_ESCROW_APPLICATION_BYTES",
          "CAPI-S014": "OUTPUT_ESCROW_PROTECTED_COMMIT_BYTES",
          "CAPI-S017": "OUTPUT_ESCROW_SELECTED_CANDIDATE_REF"
        }
      },
      "SELECTION_METADATA": "SELECTION_METADATA",
      "RETAINED_PARENT_REFERENCE": "RETAINED_PARENT",
      "LOSING_CANDIDATE_EVIDENCE": "LOSING_CANDIDATE_EVIDENCE"
    },
    "envelopeFieldToMaterialClass": {
      "operationIdentity": "RECONCILIATION_IDENTITY",
      "operation": "RECONCILIATION_IDENTITY",
      "scenario": "RECONCILIATION_IDENTITY",
      "originalApiState": "ORIGINAL_AUTHORITY_REFERENCE",
      "originalAuthority": "ORIGINAL_AUTHORITY_REFERENCE",
      "bindingProfileIdentity": "BINDING_PROFILE_METADATA",
      "candidate": "MUTATION_CANDIDATE",
      "componentSet": "UNRESOLVED_HOLD",
      "heldOutput": {
        "classification": "EXACTLY_ONE_OUTPUT_ESCROW_CLASS_BY_SCENARIO_OR_UNRESOLVED_HOLD_WHEN_NONE"
      },
      "expectedSuccess": "UNRESOLVED_HOLD",
      "reconciliationIdentity": "RECONCILIATION_IDENTITY"
    },
    "recoveryFactToMaterialClass": {
      "MUTATION_ENVELOPE_IDENTITY": "RECONCILIATION_IDENTITY",
      "ORIGINAL_AUTHORITY": "ORIGINAL_AUTHORITY_REFERENCE",
      "CANDIDATE_IDENTITY": "MUTATION_CANDIDATE",
      "COMPONENT_SET_IDENTITY": "UNRESOLVED_HOLD",
      "ESCROW_IDENTITY_AND_CONTENT": {
        "classification": "EXACTLY_ONE_OUTPUT_ESCROW_CLASS_BY_SCENARIO"
      },
      "RECONCILIATION_REFERENCE": "RECONCILIATION_IDENTITY",
      "EXPECTED_SUCCESS": "UNRESOLVED_HOLD",
      "AUTHENTICATED_RS_EVIDENCE": "COMMIT_RESULT_EVIDENCE"
    },
    "overlapRule": "EACH_LOGICAL_FACT_INSTANCE_IS_OWNED_BY_EXACTLY_ONE_MAPPED_CLASS;_CONTAINER_REFERENCES_DO_NOT_DUPLICATE_CONTENT",
    "unknownOrMultiple": "BLOCK_AND_RETAIN"
  },
  "cMutCoverage": {
    "components": [
      "SESSION_TRANSITION",
      "BINDING_METADATA",
      "REPLAY_RETENTION_STATE",
      "AUTHENTICATED_MANIFEST_UPDATE",
      "COMMIT_RESULT_EVIDENCE",
      "KEY_PACKAGE_CONSUMPTION",
      "OUTPUT_ESCROW",
      "SELECTION_METADATA",
      "RETAINED_PARENT_REFERENCE",
      "LOSING_CANDIDATE_EVIDENCE"
    ],
    "mutationRows": [
      {
        "scenario": "CAPI-S001",
        "operation": "CREATE",
        "stateBefore": "EMPTY",
        "stateAfterCommitted": "ACTIVE",
        "successCode": "CREATED",
        "outputKind": "EMBEDDED_TREE_WELCOME",
        "selectionEffect": "NOT_APPLICABLE",
        "retainedParentEffect": "NOT_APPLICABLE",
        "components": [
          {
            "id": "SESSION_TRANSITION",
            "disposition": "CHANGED",
            "fact": "FOUNDER_STATE"
          },
          {
            "id": "BINDING_METADATA",
            "disposition": "CHANGED",
            "fact": "INITIAL_EXACT_BINDING_AND_PROFILE"
          },
          {
            "id": "REPLAY_RETENTION_STATE",
            "disposition": "CHANGED",
            "fact": "INITIAL_BASELINE"
          },
          {
            "id": "AUTHENTICATED_MANIFEST_UPDATE",
            "disposition": "CHANGED",
            "fact": "FOUNDER_MANIFEST"
          },
          {
            "id": "COMMIT_RESULT_EVIDENCE",
            "disposition": "CREATED",
            "fact": "BOUND_TO_OPERATION_IDENTITY"
          },
          {
            "id": "OUTPUT_ESCROW",
            "disposition": "HELD",
            "fact": "EMBEDDED_TREE_WELCOME"
          }
        ]
      },
      {
        "scenario": "CAPI-S006",
        "operation": "JOIN_WELCOME",
        "stateBefore": "EMPTY",
        "stateAfterCommitted": "ACTIVE",
        "successCode": "JOINED",
        "outputKind": "NONE",
        "selectionEffect": "NOT_APPLICABLE",
        "retainedParentEffect": "NOT_APPLICABLE",
        "components": [
          {
            "id": "SESSION_TRANSITION",
            "disposition": "CHANGED",
            "fact": "JOINED_STATE"
          },
          {
            "id": "BINDING_METADATA",
            "disposition": "CHANGED",
            "fact": "JOINED_EXACT_BINDING_AND_PROFILE"
          },
          {
            "id": "REPLAY_RETENTION_STATE",
            "disposition": "CHANGED",
            "fact": "JOINED_BASELINE"
          },
          {
            "id": "AUTHENTICATED_MANIFEST_UPDATE",
            "disposition": "CHANGED",
            "fact": "JOINED_MANIFEST"
          },
          {
            "id": "COMMIT_RESULT_EVIDENCE",
            "disposition": "CREATED",
            "fact": "BOUND_TO_OPERATION_IDENTITY"
          },
          {
            "id": "KEY_PACKAGE_CONSUMPTION",
            "disposition": "CONSUMED",
            "fact": "MATCHING_LOCAL_ONE_SHOT_REFERENCE"
          }
        ]
      },
      {
        "scenario": "CAPI-S009",
        "operation": "PROTECT_APPLICATION",
        "stateBefore": "ACTIVE",
        "stateAfterCommitted": "ACTIVE",
        "successCode": "APPLICATION_PROTECTED",
        "outputKind": "PROTECTED_APPLICATION_BYTES",
        "selectionEffect": "PRESERVE",
        "retainedParentEffect": "PRESERVE",
        "components": [
          {
            "id": "SESSION_TRANSITION",
            "disposition": "CHANGED",
            "fact": "SENDER_RATCHET_ADVANCEMENT"
          },
          {
            "id": "BINDING_METADATA",
            "disposition": "UNCHANGED",
            "fact": "EXACT_BINDING_AND_PROFILE"
          },
          {
            "id": "REPLAY_RETENTION_STATE",
            "disposition": "CHANGED",
            "fact": "SENDER_RATCHET_RETENTION"
          },
          {
            "id": "AUTHENTICATED_MANIFEST_UPDATE",
            "disposition": "CHANGED",
            "fact": "RATCHET_STATE_MANIFEST"
          },
          {
            "id": "COMMIT_RESULT_EVIDENCE",
            "disposition": "CREATED",
            "fact": "BOUND_TO_OPERATION_IDENTITY"
          },
          {
            "id": "OUTPUT_ESCROW",
            "disposition": "HELD",
            "fact": "PROTECTED_APPLICATION_BYTES"
          },
          {
            "id": "SELECTION_METADATA",
            "disposition": "UNCHANGED",
            "fact": "EPOCH_PRESERVING_ELIGIBILITY"
          },
          {
            "id": "RETAINED_PARENT_REFERENCE",
            "disposition": "UNCHANGED",
            "fact": "PRESERVED_IF_PRESENT"
          }
        ]
      },
      {
        "scenario": "CAPI-S010",
        "operation": "OPEN_APPLICATION",
        "stateBefore": "ACTIVE",
        "stateAfterCommitted": "ACTIVE",
        "successCode": "APPLICATION_OPENED",
        "outputKind": "APPLICATION_BYTES",
        "selectionEffect": "PRESERVE",
        "retainedParentEffect": "PRESERVE",
        "components": [
          {
            "id": "SESSION_TRANSITION",
            "disposition": "CHANGED",
            "fact": "RECEIVER_RATCHET_ADVANCEMENT"
          },
          {
            "id": "BINDING_METADATA",
            "disposition": "UNCHANGED",
            "fact": "EXACT_BINDING_AND_PROFILE"
          },
          {
            "id": "REPLAY_RETENTION_STATE",
            "disposition": "CHANGED",
            "fact": "REPLAY_ACCEPTANCE_AND_RECEIVER_RETENTION"
          },
          {
            "id": "AUTHENTICATED_MANIFEST_UPDATE",
            "disposition": "CHANGED",
            "fact": "RATCHET_AND_REPLAY_MANIFEST"
          },
          {
            "id": "COMMIT_RESULT_EVIDENCE",
            "disposition": "CREATED",
            "fact": "BOUND_TO_OPERATION_IDENTITY"
          },
          {
            "id": "OUTPUT_ESCROW",
            "disposition": "HELD",
            "fact": "APPLICATION_BYTES"
          },
          {
            "id": "SELECTION_METADATA",
            "disposition": "UNCHANGED",
            "fact": "EPOCH_PRESERVING_ELIGIBILITY"
          },
          {
            "id": "RETAINED_PARENT_REFERENCE",
            "disposition": "UNCHANGED",
            "fact": "PRESERVED_IF_PRESENT"
          }
        ]
      },
      {
        "scenario": "CAPI-S014",
        "operation": "SELF_UPDATE",
        "stateBefore": "ACTIVE",
        "stateAfterCommitted": "ACTIVE",
        "successCode": "SELF_UPDATED",
        "outputKind": "PROTECTED_COMMIT_BYTES",
        "selectionEffect": "ESTABLISH",
        "retainedParentEffect": "ESTABLISH_FOR_CAPI_S017_ONLY",
        "components": [
          {
            "id": "SESSION_TRANSITION",
            "disposition": "CHANGED",
            "fact": "LOCAL_UPDATE_STATE"
          },
          {
            "id": "BINDING_METADATA",
            "disposition": "UNCHANGED",
            "fact": "EXACT_BINDING_AND_PROFILE"
          },
          {
            "id": "REPLAY_RETENTION_STATE",
            "disposition": "CHANGED",
            "fact": "EPOCH_WINDOW_ADVANCEMENT"
          },
          {
            "id": "AUTHENTICATED_MANIFEST_UPDATE",
            "disposition": "CHANGED",
            "fact": "LOCAL_UPDATE_MANIFEST"
          },
          {
            "id": "COMMIT_RESULT_EVIDENCE",
            "disposition": "CREATED",
            "fact": "BOUND_TO_OPERATION_IDENTITY"
          },
          {
            "id": "OUTPUT_ESCROW",
            "disposition": "HELD",
            "fact": "PROTECTED_COMMIT_BYTES"
          },
          {
            "id": "SELECTION_METADATA",
            "disposition": "ESTABLISHED",
            "fact": "IMMEDIATELY_PRECEDING_LOCAL_UPDATE_ELIGIBILITY"
          },
          {
            "id": "RETAINED_PARENT_REFERENCE",
            "disposition": "ESTABLISHED",
            "fact": "PARENT_REQUIRED_BY_CAPI_S017"
          }
        ]
      },
      {
        "scenario": "CAPI-S016",
        "operation": "APPLY_PEER_UPDATE",
        "stateBefore": "ACTIVE",
        "stateAfterCommitted": "ACTIVE",
        "successCode": "PEER_UPDATE_APPLIED",
        "outputKind": "NONE",
        "selectionEffect": "INVALIDATE",
        "retainedParentEffect": "INVALIDATE_SELECTION_ROLE",
        "components": [
          {
            "id": "SESSION_TRANSITION",
            "disposition": "CHANGED",
            "fact": "PEER_UPDATE_STATE"
          },
          {
            "id": "BINDING_METADATA",
            "disposition": "UNCHANGED",
            "fact": "EXACT_BINDING_AND_PROFILE"
          },
          {
            "id": "REPLAY_RETENTION_STATE",
            "disposition": "CHANGED",
            "fact": "EPOCH_WINDOW_ADVANCEMENT"
          },
          {
            "id": "AUTHENTICATED_MANIFEST_UPDATE",
            "disposition": "CHANGED",
            "fact": "PEER_UPDATE_MANIFEST"
          },
          {
            "id": "COMMIT_RESULT_EVIDENCE",
            "disposition": "CREATED",
            "fact": "BOUND_TO_OPERATION_IDENTITY"
          },
          {
            "id": "SELECTION_METADATA",
            "disposition": "INVALIDATED",
            "fact": "ANY_CAPI_S014_ELIGIBILITY"
          },
          {
            "id": "RETAINED_PARENT_REFERENCE",
            "disposition": "INVALIDATED",
            "fact": "NO_LONGER_SELECTION_AUTHORIZING"
          },
          {
            "id": "LOSING_CANDIDATE_EVIDENCE",
            "disposition": "INVALIDATED",
            "fact": "ANY_RETAINED_LOSER_EVIDENCE"
          }
        ]
      },
      {
        "scenario": "CAPI-S017",
        "operation": "APPLY_PEER_UPDATE",
        "stateBefore": "ACTIVE",
        "stateAfterCommitted": "ACTIVE",
        "successCode": "CANDIDATE_SELECTED",
        "outputKind": "SELECTED_CANDIDATE_REF",
        "selectionEffect": "TERMINATE",
        "retainedParentEffect": "TERMINATE_SELECTION_ROLE",
        "components": [
          {
            "id": "SESSION_TRANSITION",
            "disposition": "CHANGED_OR_UNCHANGED_BY_SELECTED_CANDIDATE",
            "fact": "CURRENT_WINNER_UNCHANGED_INCOMING_WINNER_CHANGED"
          },
          {
            "id": "BINDING_METADATA",
            "disposition": "UNCHANGED",
            "fact": "EXACT_BINDING_AND_PROFILE"
          },
          {
            "id": "REPLAY_RETENTION_STATE",
            "disposition": "CHANGED",
            "fact": "SELECTED_EPOCH_WINDOW"
          },
          {
            "id": "AUTHENTICATED_MANIFEST_UPDATE",
            "disposition": "CHANGED",
            "fact": "SELECTED_STATE_MANIFEST"
          },
          {
            "id": "COMMIT_RESULT_EVIDENCE",
            "disposition": "CREATED",
            "fact": "BOUND_TO_OPERATION_IDENTITY"
          },
          {
            "id": "OUTPUT_ESCROW",
            "disposition": "HELD",
            "fact": "SELECTED_CANDIDATE_REF"
          },
          {
            "id": "SELECTION_METADATA",
            "disposition": "TERMINATED",
            "fact": "NO_FURTHER_SELECTION_FROM_OLD_PARENT"
          },
          {
            "id": "RETAINED_PARENT_REFERENCE",
            "disposition": "TERMINATED",
            "fact": "NO_LONGER_SELECTION_AUTHORIZING"
          },
          {
            "id": "LOSING_CANDIDATE_EVIDENCE",
            "disposition": "RETAINED_NON_AUTHORITATIVE",
            "fact": "BOUNDED_VALID_LOSER"
          }
        ]
      }
    ],
    "outcomes": [
      "COMMITTED",
      "NOT_COMMITTED",
      "INDETERMINATE"
    ],
    "outputKinds": [
      "EMBEDDED_TREE_WELCOME",
      "PROTECTED_APPLICATION_BYTES",
      "APPLICATION_BYTES",
      "PROTECTED_COMMIT_BYTES",
      "SELECTED_CANDIDATE_REF"
    ],
    "crashBoundaries": [
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
    "reconciliation": {
      "originalStateEnum": [
        "EMPTY",
        "ACTIVE"
      ],
      "apMaySupplyOutcome": false,
      "originalTerminalPath": {
        "committed": "SELECT_COMPLETE_NEW_AND_RESOLVE_HOLD;_RETAIN_INTERNAL_EVIDENCE_IF_EMISSION_INTERRUPTED;_NO_AP_RECONCILIATION_ROW_WITHOUT_PRIOR_REFERENCE",
        "notCommitted": "RESTORE_COMPLETE_OLD_DISCARD_ESCROW_AND_RESOLVE_HOLD",
        "apReconciliationRow": "NONE_WITHOUT_PRIOR_INDETERMINATE_REFERENCE"
      },
      "matchingCommitted": {
        "scenarios": [
          "CAPI-S020",
          "CAPI-S022"
        ],
        "precondition": "AP_HAS_REFERENCE_FROM_PRIOR_INDETERMINATE",
        "action": "SELECT_ALREADY_STAGED_CANDIDATE_ONCE_AND_RETAIN_RESPONSE_HOLD_UNTIL_LOCAL_EMISSION_CALL_SUCCEEDS",
        "output": "ORIGINAL_SUCCESS_CODE_AND_COMMITTED_ORIGINAL_OUTPUT"
      },
      "matchingNotCommitted": {
        "scenarios": [
          "CAPI-S021",
          "CAPI-S023"
        ],
        "precondition": "AP_HAS_REFERENCE_FROM_PRIOR_INDETERMINATE",
        "action": "DISCARD_CANDIDATE_AND_ESCROW_AND_CLEAR_HOLD_WHEN_NO_OUTPUT_RESPONSE_IS_FORMED",
        "output": "NONE"
      },
      "continuedIndeterminate": {
        "scenario": "CAPI-S024",
        "action": "HOLD_UNCHANGED",
        "output": "NONE"
      },
      "referenceMismatch": {
        "scenario": "CAPI-S028",
        "action": "REJECT_WITHOUT_MUTATION_OR_HOLD_CHANGE"
      },
      "interruptedCommittedReconciliationRepeat": {
        "scenarios": [
          "CAPI-S020",
          "CAPI-S022"
        ],
        "precondition": "REFERENCE_ALREADY_EMITTED_BY_PRIOR_INDETERMINATE",
        "state": "RECONCILIATION_REQUIRED",
        "clearingEvent": "ADAPTER_LOCAL_RESPONSE_EMISSION_CALL_RETURNS_SUCCESS",
        "sameEscrowMayRepeat": true,
        "apReceiptAcknowledgement": false
      },
      "afterHoldClearedRepeat": {
        "scenarios": [
          "CAPI-G008",
          "CAPI-G016"
        ],
        "disposition": "NO_RECONCILIATION_PENDING",
        "authority": "UNCHANGED",
        "output": "NONE"
      },
      "mismatchFields": [
        "REFERENCE",
        "OPERATION_IDENTITY",
        "CANDIDATE",
        "PARENT",
        "BINDING",
        "PROFILE",
        "COMPONENT_SET",
        "ORIGINAL_STATE",
        "RS_EVIDENCE"
      ]
    },
    "mutationEnvelopeRequired": [
      "operationIdentity",
      "operation",
      "scenario",
      "originalApiState",
      "originalAuthority",
      "bindingProfileIdentity",
      "candidate",
      "componentSet",
      "heldOutput",
      "expectedSuccess",
      "reconciliationIdentity"
    ],
    "commitResultEvidence": {
      "closed": true,
      "required": [
        "operationIdentity",
        "originalAuthorityDigest",
        "originalAuthorityReference",
        "candidateDigest",
        "candidateReference",
        "mutationSetDigest",
        "mutationSetReference",
        "expectedOriginalState",
        "bindingRef",
        "profile",
        "outcome",
        "authenticatedByRS",
        "terminal"
      ],
      "matchRule": "ALL_IDENTITY_FIELDS_MUST_MATCH_ONE_HELD_ENVELOPE",
      "notCommittedRule": "ACCEPT_ONLY_WHEN_TERMINAL_TRUE_AND_REQUEST_CAN_NO_LONGER_COMMIT",
      "mismatchDisposition": "REJECT_WITHOUT_SELECT_OR_DISCARD",
      "forbidden": [
        "AP_SUPPLIED_OUTCOME",
        "UNKNOWN_EVIDENCE",
        "STALE_EVIDENCE",
        "CROSS_SESSION_EVIDENCE",
        "CROSS_BINDING_EVIDENCE",
        "CROSS_PROFILE_EVIDENCE",
        "DUPLICATE_CONFLICTING_EVIDENCE"
      ]
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
    "failureAtomicity": {
      "allLogicalComponentsCovered": true,
      "beforeCommitPoint": "COMPLETE_ORIGINAL_SET_AND_ROOT",
      "afterCommitPoint": "COMPLETE_CANDIDATE_SET_AND_MATCHING_ROOT_RESULT_AND_ESCROW",
      "strictlyBeforeAnyRsRequest": {
        "code": "FAIL_CLOSED_INTERNAL",
        "candidate": "DISCARD",
        "escrow": "DISCARD",
        "rsRequest": "NONE",
        "commitResultEvidence": "NONE"
      },
      "triStateBegins": "WHEN_REQUEST_MAY_HAVE_REACHED_RS",
      "faultsClassifiedByBoundaryAndEvidence": [
        "QUOTA",
        "ABORT",
        "WORKER_TERMINATION",
        "EXCEPTION",
        "TAB_CLOSURE",
        "RESPONSE_LOSS"
      ],
      "guessFromSsMemory": "FORBIDDEN",
      "partialMixture": "FORBIDDEN",
      "twoAuthoritativeStates": "FORBIDDEN"
    },
    "restoreMinimumRecoveryFacts": [
      "MUTATION_ENVELOPE_IDENTITY",
      "ORIGINAL_AUTHORITY",
      "CANDIDATE_IDENTITY",
      "COMPONENT_SET_IDENTITY",
      "ESCROW_IDENTITY_AND_CONTENT",
      "RECONCILIATION_REFERENCE",
      "EXPECTED_SUCCESS",
      "AUTHENTICATED_RS_EVIDENCE"
    ],
    "escrowByScenario": {
      "CAPI-S001": "EMBEDDED_TREE_WELCOME",
      "CAPI-S006": "NONE",
      "CAPI-S009": "PROTECTED_APPLICATION_BYTES",
      "CAPI-S010": "APPLICATION_BYTES",
      "CAPI-S014": "PROTECTED_COMMIT_BYTES",
      "CAPI-S016": "NONE",
      "CAPI-S017": "SELECTED_CANDIDATE_REF"
    },
    "profilePastEpochWindow": 5
  },
  "compactionRule": {
    "authority": "ONLY_REMOVAL_INSIDE_EXISTING_C_MUT_REPLAY_RETENTION_STATE_CHANGE_OR_OWNER_DECISION_5892675163_LOSER_COMPACTION_IS_CURRENTLY_AUTHORIZED",
    "allOtherCompaction": "BLOCK_PENDING_SEPARATELY_RATIFIED_MUTATION_CONTRACT",
    "steps": [
      "COMPUTE_COMPLETE_SURVIVOR_SET",
      "VERIFY_NO_LIVE_REFERENCE_TO_CANDIDATE_PARENT_EPOCH_PACKAGE_RESULT_ESCROW_HOLD_RESTORE_OR_CRASH_FACT",
      "COMMIT_NEW_AUTHENTICATED_MANIFEST_AND_ROOT",
      "REQUEST_DATABASE_DELETION_OF_OBSOLETE_RECORDS"
    ],
    "beforeAuthorityChangeFailure": "OLD_COMPLETE_SET_AUTHORITATIVE",
    "afterAuthorityChangeFailure": "COMPLETE_COMPACTED_SET_AUTHORITATIVE_WITH_HARMLESS_UNREACHABLE_REMNANTS",
    "partialSurvivorAuthority": "FORBIDDEN",
    "ambiguousReferenceGraph": "BLOCK_AND_RETAIN"
  },
  "deletionSemantics": {
    "logicalDeletion": "NORMATIVE_PRODUCT_ACTION",
    "databaseDeletionRequest": "NORMATIVE_PRODUCT_ACTION_ONLY_AFTER_LOGICAL_AUTHORITY_RULES",
    "browserTransactionCompletion": "OBSERVABLE_BUT_NOT_DURABLE_ERASURE_PROOF",
    "keyDestructionAttempt": "BEST_EFFORT_NONCLAIM",
    "memoryOverwriteAttempt": "BEST_EFFORT_NONCLAIM",
    "garbageCollectionEligibility": "NONCLAIM",
    "physicalMediaErasure": "NONCLAIM"
  },
  "lockResetRule": {
    "lock": "BEST_EFFORT_RELEASE_OR_OVERWRITE;_ONLY_LATER_IMPLEMENTATION_CAN_PROVE_OWNING_WORKER_TERMINATION",
    "resetOrder": [
      "REMOVE_OR_INVALIDATE_KEK_WRAPPER",
      "LOGICALLY_DELETE_VAULT_AUTHORITY_AND_RECORDS",
      "REQUEST_CIPHERTEXT_DATABASE_DELETION"
    ],
    "resetEffect": "SURVIVING_CIPHERTEXT_INACCESSIBLE_UNDER_REMOVED_LOCAL_WRAPPER_ABSENT_EXTERNAL_COPIES",
    "resetNonclaims": [
      "PHYSICAL_ERASURE",
      "FORGOTTEN_PASSWORD_RECOVERY",
      "EXTERNAL_COPY_DESTRUCTION"
    ]
  },
  "diagnostics": {
    "allowedFields": [
      "COUNT",
      "REASON_CODE",
      "COMPLETION_STAGE"
    ],
    "forbiddenFields": [
      "KEY",
      "PLAINTEXT",
      "BINDING_BYTES",
      "SESSION_IDENTIFIER",
      "PACKAGE_REFERENCE",
      "CANDIDATE_DIGEST",
      "ESCROW_CONTENT"
    ],
    "values": "VALUE_FREE_ONLY"
  },
  "nonClaims": [
    "SECURE_PHYSICAL_ERASURE",
    "FORENSIC_DELETION",
    "JAVASCRIPT_OR_WASM_ZEROIZATION",
    "GARBAGE_COLLECTION_TIMING",
    "BROWSER_EVICTION_DURABILITY",
    "INDEXEDDB_STORAGE_ENGINE_COPY_DELETION",
    "BACKUP_SNAPSHOT_WEAR_LEVELLING_OR_CRASH_REMNANT_DELETION",
    "COHERENT_WHOLE_PROFILE_ROLLBACK_PREVENTION",
    "FRESHNESS",
    "PRODUCTION_READINESS",
    "AP_RECEIPT",
    "EXACTLY_ONCE_DELIVERY",
    "LEGACY_CLEANUP",
    "MIGRATION",
    "FORGOTTEN_PASSWORD_RECOVERY",
    "ARBITRARY_TOPOLOGY",
    "ISSUE_312_EXTENSION"
  ],
  "openBlockers": [
    "O_12",
    "O_13",
    "O_15",
    "O_16"
  ],
  "ratification": {
    "documentSha256": "MUST_BE_RECORDED_EXTERNALLY_FROM_FINAL_LITERAL_BYTES",
    "evidenceBundleSha256": "MUST_BE_RECORDED_EXTERNALLY_FROM_FINAL_LITERAL_BYTES",
    "ownerActRequired": true,
    "byteChangeInvalidatesReviewAndRatification": true,
    "blockedUntilRatified": [
      "O_SCEN",
      "DEPENDENT_IMPLEMENTATION"
    ]
  }
}
```
<!-- styx-m2-retention-json:v1:end -->
