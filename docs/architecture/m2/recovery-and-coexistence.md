# M2 recovery and legacy coexistence contract

Status: normative candidate for C-REC under Issue #335. Exact final document and external evidence-bundle hashes require separate owner ratification before O-SCEN or dependent implementation.

## 1. Scope and normative force

This document defines the closed recovery, user-choice and legacy-coexistence consequences of the exact C-MUT, C-FMT and C-REST inputs identified in §2. **MUST**, **MUST NOT**, **REJECT**, and the codes in §12 are normative. The single JSON record in §13 is closed and normative; prose explains it but adds no state, result, action, transition, authority, precondition, choice, reason, marker, reset gate or fixture. Unknown, missing, duplicate, reordered, overlapping or extra values and duplicate JSON members reject.

It implements nothing, imports no legacy state, releases no output, deletes no byte and changes no dependency byte. Stored-byte mutation, restore/recovery execution against a real profile, reset, re-establishment, invalidation and cleanup remain outside this document.

## 2. Frozen inputs and ownership

The exact external read-only inputs are C-MUT `docs/architecture/m2/mutation-table.md` at `40a3dee0fcb297d6fe8efc8657a9bbe6098d099d`, SHA-256 `6c2c045c5317d6893a0bd338e728f2cdc686237af5688925f9756c014deb3060`; C-FMT `docs/architecture/m2/storage-format.md` at `697e257ab106fa67c144f8fbbcde5c68ed4359c3`, SHA-256 `9dace4a0182c5694857cc1e8efb59257f3e4b276e8c62846d2d329626e8c963b`; and C-REST `docs/architecture/m2/restore-compatibility.md` at `2f3c1473ed2197257395ac958c1a8b7d3963af70`, SHA-256 `9582378764362d1e7df05c217ea4423fe52be0b36775371c1b91e520b4615c16`. Their ratifications and evidence-bundle hashes are copied in `provenance`. Drift is BLOCK.

Every transition and invariant is classified in `dependencyCoverage`. `DEPENDENCY_DERIVED` facts are only those entailed by the cited exact fields. `C_REC_OWNED` rules are authorized recovery consequences whose consumed dependency preconditions are cited and unchanged. A missing or insufficient field is BLOCK; prose or an evidence bundle cannot fill it.

## 3. Closed restore dispatch

Recovery begins only with one complete C-REST result and its reachable condition flag. The eighteen `dispatchRows` are total and disjoint. `LEGACY_PRESENT` is a condition, never a result or authority source. `reachableConditionRows` closes every admissible pair; any other pair rejects. `LOCKED_ELSEWHERE` and `INCOMPATIBLE_BUILD` carry no inventory-derived legacy fact.

`RESTORED_ACTIVE` and `RESTORED_EMPTY` continue only C-REST's exact selected authority. `RESTORED_RECONCILIATION_REQUIRED` preserves and exposes only C-REST's selected original authority while its retained candidate remains non-authoritative. Failure and inventory results expose no authority. A user choice, count, timestamp, decryptability, candidate, legacy byte or physical enumeration order cannot select authority. Failure preserves bytes and stops except for the closed user-facing disposition; reset eligibility is a separate boolean.

## 4. Indeterminate reconciliation

For `RESTORED_RECONCILIATION_REQUIRED`, the sole operation is `RECONCILE_INDETERMINATE`. The `reconciliation` record restates without extension the exact C-MUT fields cited by owner decision `5906058719`: original terminal COMMITTED selects complete new authority and resolves the hold, retaining internal evidence after interrupted emission but creating no AP reconciliation row without a previously emitted reference; original terminal NOT_COMMITTED restores complete old authority, discards escrow and resolves the hold. After a prior INDETERMINATE, matching COMMITTED selects the staged candidate once, retains the response hold until the adapter-local response-emission call succeeds, and returns the original success code and committed original output; matching terminal NOT_COMMITTED discards candidate and escrow and clears the hold when the no-output response is formed; continued INDETERMINATE leaves the hold unchanged and emits no output; interrupted committed reconciliation may return the same escrow again and clears only on local emission success, never AP receipt acknowledgement.

The exact outcome rows and eight related crash-boundary identifiers are copied. C-REC adds no terminal rule, exposes no candidate evidence, retries no original mutation, regenerates no output, consumes no KeyPackage, and permits no unrelated state-changing operation. Authority, hold, candidate, escrow and repeat behavior are exactly C-MUT's rules; C-FMT and C-REST remain fail-closed preconditions.

## 5. Password re-wrap and compatible-build handoff

For the M2 recovery surface, password re-wrap requires successful wrapper authentication and `RESTORED_ACTIVE` or `RESTORED_EMPTY`. This owned precondition neither grants nor removes the existing vault password-change facility for `NO_M2_STATE` or `LEGACY_ONLY`. It atomically replaces only the wrapper around the same Root Storage Key; every M2 byte and fact remains identical. A crash leaves the old or new valid wrapper. Re-wrap is unavailable during reconciliation. Wrong or forgotten credentials permit no re-wrap, reset-by-default, salvage, migration or record oracle; there is no forgotten-password recovery.

`INCOMPATIBLE_BUILD` has only `SHOW_COMPATIBLE_BUILD`: identify reader profile `CFMT_EXACT_9DACE4A0`, preserve and stop, and read or change no byte. A feature flag, acknowledgement or partial match cannot widen eligibility. It is not reset-eligible.

## 6. Legacy coexistence and re-establishment

Legacy inventory is abstract, disjoint, preserved and non-authoritative. C-REC consumes only `legacyPresent` and a bounded value-free count. It never imports, decrypts, translates, copies, selects, decodes as M2 or falls back to legacy. Valid M2 with legacy continues M2; invalid M2 with legacy remains the M2 failure. `NO_M2_STATE` and `LEGACY_ONLY` are unauthenticated inventory outcomes. `NO_M2_STATE` shows creation without asserting prior absence, deletion, freshness or rollback protection. `LEGACY_ONLY` shows visible re-establishment guidance, never conversion.

A new M2 session may be created only later under separately ratified L-REEST with visible consent. The abstract marker is not an M2 record kind, not a legacy-byte mutation, and not obtained by re-reading or reclassifying storage. The four marker states and five allowed transitions are closed. Confirmation requires a distinct post-start authority created by a C-FMT COMMITTED operation and later returned by C-REST as `RESTORED_ACTIVE`; EMPTY, reconciliation, failure or candidate evidence cannot confirm. Binding uses opaque token equality, never time. L-MARK owns encoding and physical evidence; until L-MARK and L-REEST are ratified, a real confirmation transition is BLOCK.

After confirmation no reverse transition exists. Repeated marker completion is idempotent. Legacy eligibility becomes false at confirmation, but invalidation never deletes, moves, overwrites, compacts or proves erasure of bytes. Cleanup remains deferred.

## 7. Explicit destructive reset

Reset is a separate, explicit, irreversible confirmed act. The closed eligible set contains only results that cannot arise during inventory or pre-inventory processing. Lock failure, incompatible build, wrapper credential failure, unresolved reconciliation, inventory/pre-inventory outcomes and successful restore are ineligible. Reset requires the one-writer lock, value-free disclosure of what M2 authority becomes unavailable, preserved diagnosis and an explicit no-erasure statement. It never changes legacy bytes or marker state and is never automatic, default recovery, a substitute for invalidation or cleanup, proof of physical erasure, or described as recovery of prior authority. An interruption is classified only by the next complete C-REST run. This document does not implement reset.

## 8. Lock, precedence and byte preservation

Every state-changing recovery action requires the one-writer lock. A non-holder receives only `LOCKED_ELSEWHERE`; its closed disposition is `LOCK_RETRY`, and no later gate or state detail is exposed. Ambiguous or contradictory facts choose the safer non-authorizing disposition; enumeration order cannot affect the result. Reconciliation blocks every other mutation, re-establishment and reset.

Guidance and cancellation preserve bytes. Marker transitions change only the abstract marker state. Re-wrap changes only the wrapper as described. No action here authorizes cleanup, KeyPackage consumption, escrow discard outside exact C-MUT terminal rules, repair, fallback, normalization or automatic reset.

## 9. Diagnostics and user-visible distinctions

Diagnostics are limited to the six allowlisted value-free fields. Keys, nonces, plaintext, binding bytes, context/session identifiers, package references, digests, record keys, legacy content, marker bindings and escrow are forbidden. User-visible wording distinguishes restored authority, new-session re-establishment, compatible-build handoff and destructive reset.

## 10. Fixtures and independent models

The fixture table covers all eighteen dispatch rows, every reachable condition pair, every marker transition, both reconciliation origins and continuation paths, wrapper and marker crash boundaries, positive and interrupted reset, wrong and cross-session tokens, EMPTY/reconciliation confirmation rejection, fallback, import, silent or ineligible reset, mutation retry, candidate selection, output release, cleanup and raw diagnostics. The external validator runs every fixture through two independently structured models, mutates each closed enum/table axis, combines all dispatch fault pairs, consumes and permutes physical enumeration input, interrupts transition boundaries and checks dependency bytes before and after. Unexpected skips fail.

These models prove only the abstract contract. They prove no IndexedDB behavior, browser parity, lock reliability, UI quality, cleanup, physical erasure, recovery success or production readiness.

## 11. Freshness, rollback and erasure limits

Authentication proves consistency, not freshness. Coherent whole-profile rollback may revert selected authority and marker state undetectably. Private and evicted profiles are unsupported. No timestamp, counter or marker creates a freshness, rollback-prevention, physical-erasure or JavaScript-zeroization claim.

## 12. Closed outcomes and human gate

The exact results, dispositions, reset booleans, marker states, actions, transitions, preconditions, diagnostic fields and fixtures are those in the normative record. Any missing or extra row rejects. The final document and deterministic external evidence bundle require separate owner hash-ratification. Any byte change voids review and ratification; O-SCEN and dependent implementation remain blocked until that act.

## 13. Machine-readable normative record

<!-- styx-m2-recovery-json:v1:start -->
```json
{
  "schema": "styx-m2-recovery-and-coexistence/v1",
  "closed": true,
  "status": "PENDING_EXTERNAL_HASH_RATIFICATION",
  "validation": {
    "unknownMissingDuplicateReorderedOverlappingOrExtra": "REJECT",
    "duplicateJsonMembers": "REJECT",
    "proseAddsPath": false,
    "unexpectedSkip": "FAIL"
  },
  "provenance": {
    "issue": 335,
    "card": "C-REC",
    "exactBase": "e1538ef9c070e463a8256872a3fd0882c424e2ef",
    "branch": "task/m2-c-rec",
    "ownerDecision": "issue-317-comment-5906058719",
    "dependencies": [
      {
        "card": "C-MUT",
        "commit": "40a3dee0fcb297d6fe8efc8657a9bbe6098d099d",
        "path": "docs/architecture/m2/mutation-table.md",
        "sha256": "6c2c045c5317d6893a0bd338e728f2cdc686237af5688925f9756c014deb3060",
        "evidenceBundleSha256": "9d8bdb19b20728873ede932df2936dcc6db6dd44a072af57cf4d0320cbf56712",
        "ratification": "issue-324-comment-5890545934"
      },
      {
        "card": "C-FMT",
        "commit": "697e257ab106fa67c144f8fbbcde5c68ed4359c3",
        "path": "docs/architecture/m2/storage-format.md",
        "sha256": "9dace4a0182c5694857cc1e8efb59257f3e4b276e8c62846d2d329626e8c963b",
        "evidenceBundleSha256": "43e0765f0d81994a2c00fd32ca79851b3230dcc8de7dd06bba61f2b31efa718e",
        "ratification": "issue-327-final-owner-act-9dace4a0"
      },
      {
        "card": "C-REST",
        "commit": "2f3c1473ed2197257395ac958c1a8b7d3963af70",
        "path": "docs/architecture/m2/restore-compatibility.md",
        "sha256": "9582378764362d1e7df05c217ea4423fe52be0b36775371c1b91e520b4615c16",
        "evidenceBundleSha256": "d294c83f0d409c4f3dd7716a91e674b911f33a25d39b03aa161312f7cf74f333",
        "ratification": "issue-327-final-owner-act-9dace4a0"
      }
    ]
  },
  "dependencyCoverage": [
    {
      "criterion": "AUTHORITY_AND_CRASH_CONTINUATION",
      "ownership": "DEPENDENCY_DERIVED",
      "cMut": [],
      "cFmt": [
        "generationCommit.rule",
        "generationCommit.authorityRule",
        "generationCommit.completeOld",
        "generationCommit.completeNew",
        "generationCommit.candidateBindingRule",
        "manifest.selector",
        "crashModel"
      ],
      "cRest": [
        "phaseOrder",
        "phaseRules",
        "candidateRules",
        "resultSets",
        "successBySelectorState",
        "exposure"
      ]
    },
    {
      "criterion": "RESTORE_RESULT_DISPATCH",
      "ownership": "C_REC_OWNED",
      "cMut": [],
      "cFmt": [
        "valueRegistries.selectorState",
        "crashModel"
      ],
      "cRest": [
        "resultSets.inventory",
        "resultSets.success",
        "resultSets.failure",
        "resultSets.condition",
        "successBySelectorState",
        "inventoryRules.noM2State",
        "inventoryRules.emptyState",
        "failureDefault"
      ]
    },
    {
      "criterion": "INDETERMINATE_RECONCILIATION",
      "ownership": "C_REC_OWNED",
      "cMut": [
        "reconciliation.originalTerminalPath",
        "reconciliation.matchingCommitted",
        "reconciliation.matchingNotCommitted",
        "reconciliation.continuedIndeterminate",
        "reconciliation.interruptedCommittedReconciliationRepeat",
        "outcomeRules.COMMITTED",
        "outcomeRules.NOT_COMMITTED",
        "outcomeRules.INDETERMINATE",
        "crashBoundaries[id=DURING_RS_WORK]",
        "crashBoundaries[id=AFTER_DURABLE_COMMIT_BEFORE_RESPONSE]",
        "crashBoundaries[id=AFTER_NOT_COMMITTED]",
        "crashBoundaries[id=AFTER_INDETERMINATE]",
        "crashBoundaries[id=DURING_RECONCILIATION]",
        "crashBoundaries[id=AFTER_AUTHORITY_SELECTION_BEFORE_OUTPUT_RESPONSE]",
        "crashBoundaries[id=DURING_ESCROW_OUTPUT_RESPONSE]",
        "crashBoundaries[id=AFTER_OUTPUT_RESPONSE_LOSS]"
      ],
      "cFmt": [
        "generationCommit.parentBindingRule",
        "generationCommit.originalAuthorityMatch",
        "generationCommit.outcomes",
        "recoveryFactMapping",
        "outputEscrow.releaseAuthority",
        "keyPackageLifecycle.restore",
        "crashModel",
        "valueRegistries.operation"
      ],
      "cRest": [
        "candidateRules.unresolvedPhysicalParent",
        "candidateRules.logicalOriginalAuthority",
        "candidateRules.candidateAuthority",
        "exposure.never",
        "automaticActions"
      ]
    },
    {
      "criterion": "PASSWORD_REWRAP",
      "ownership": "C_REC_OWNED",
      "cMut": [],
      "cFmt": [
        "rootStorageKey.wrapper",
        "rootStorageKey.passwordChange",
        "rootStorageKey.passwordDirectlyEncryptsRecords"
      ],
      "cRest": [
        "guidance.passwordChange",
        "phaseOrder",
        "resultSets.success",
        "successBySelectorState",
        "nonClaims",
        "faultPrecedence"
      ]
    },
    {
      "criterion": "COMPATIBLE_BUILD_HANDOFF",
      "ownership": "DEPENDENCY_DERIVED",
      "cMut": [],
      "cFmt": [
        "versions",
        "algorithms",
        "keySchedule.productProfileDigest"
      ],
      "cRest": [
        "buildMatrix",
        "unsupportedRuntimeClasses",
        "guidance.compatibleBuild",
        "resultSets.failure"
      ]
    },
    {
      "criterion": "M2_LEGACY_COEXISTENCE",
      "ownership": "C_REC_OWNED",
      "cMut": [],
      "cFmt": [
        "recordKeyGrammar.selectorFixedLocator"
      ],
      "cRest": [
        "inventoryRules.legacyDomain",
        "resultSets.condition",
        "guidance.legacy",
        "nonClaims",
        "fixtures.positive"
      ]
    },
    {
      "criterion": "INVALIDATION_AND_REESTABLISHMENT",
      "ownership": "C_REC_OWNED",
      "cMut": [],
      "cFmt": [
        "mutationRows",
        "generationCommit.outcomes.COMMITTED"
      ],
      "cRest": [
        "resultSets.success",
        "successBySelectorState",
        "inventoryRules.legacyDomain",
        "guidance.legacy"
      ]
    },
    {
      "criterion": "DESTRUCTIVE_RESET_ELIGIBILITY",
      "ownership": "C_REC_OWNED",
      "cMut": [],
      "cFmt": [
        "nonClaims[2]"
      ],
      "cRest": [
        "guidance.destructiveReset",
        "corruptionAction",
        "automaticActions",
        "resultSets.failure",
        "phaseRules"
      ]
    },
    {
      "criterion": "DIAGNOSTICS_AND_USER_CHOICES",
      "ownership": "C_REC_OWNED",
      "cMut": [],
      "cFmt": [
        "valueRegistries"
      ],
      "cRest": [
        "diagnostics",
        "resultSets",
        "faultPrecedence"
      ]
    },
    {
      "criterion": "FRESHNESS_ROLLBACK_ERASURE_LIMITS",
      "ownership": "DEPENDENCY_DERIVED",
      "cMut": [
        "nonClaims"
      ],
      "cFmt": [
        "nonClaims"
      ],
      "cRest": [
        "freshness",
        "nonClaims",
        "unsupportedRuntimeClasses"
      ]
    }
  ],
  "restoreResults": [
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
    "INTERNAL_VALIDATION_FAILED"
  ],
  "conditionEnum": [
    "LEGACY_PRESENT"
  ],
  "dispositionEnum": [
    "CONTINUE_ACTIVE",
    "CONTINUE_EMPTY",
    "RECONCILE_ONLY",
    "SHOW_CREATE",
    "SHOW_COMPATIBLE_BUILD",
    "SHOW_REESTABLISHMENT",
    "PRESERVE_AND_STOP",
    "LOCK_RETRY"
  ],
  "dispatchRows": [
    {
      "result": "NO_M2_STATE",
      "disposition": "SHOW_CREATE",
      "authority": "NONE",
      "resetEligible": false,
      "legacyCondition": "UNAVAILABLE",
      "byteAction": "PRESERVE"
    },
    {
      "result": "LEGACY_ONLY",
      "disposition": "SHOW_REESTABLISHMENT",
      "authority": "NONE",
      "resetEligible": false,
      "legacyCondition": "REQUIRED",
      "byteAction": "PRESERVE"
    },
    {
      "result": "RESTORED_EMPTY",
      "disposition": "CONTINUE_EMPTY",
      "authority": "SELECTED_AUTHORITY",
      "resetEligible": false,
      "legacyCondition": "OPTIONAL",
      "byteAction": "PRESERVE"
    },
    {
      "result": "RESTORED_ACTIVE",
      "disposition": "CONTINUE_ACTIVE",
      "authority": "SELECTED_AUTHORITY",
      "resetEligible": false,
      "legacyCondition": "OPTIONAL",
      "byteAction": "PRESERVE"
    },
    {
      "result": "RESTORED_RECONCILIATION_REQUIRED",
      "disposition": "RECONCILE_ONLY",
      "authority": "SELECTED_ORIGINAL_AUTHORITY",
      "resetEligible": false,
      "legacyCondition": "OPTIONAL",
      "byteAction": "PRESERVE"
    },
    {
      "result": "LOCKED_ELSEWHERE",
      "disposition": "LOCK_RETRY",
      "authority": "NONE",
      "resetEligible": false,
      "legacyCondition": "UNAVAILABLE",
      "byteAction": "PRESERVE"
    },
    {
      "result": "WRAPPER_AUTH_FAILED",
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": false,
      "legacyCondition": "OPTIONAL",
      "byteAction": "PRESERVE"
    },
    {
      "result": "INCOMPATIBLE_BUILD",
      "disposition": "SHOW_COMPATIBLE_BUILD",
      "authority": "NONE",
      "resetEligible": false,
      "legacyCondition": "UNAVAILABLE",
      "byteAction": "PRESERVE"
    },
    {
      "result": "INCOMPATIBLE_FORMAT",
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": true,
      "legacyCondition": "OPTIONAL",
      "byteAction": "PRESERVE"
    },
    {
      "result": "UNSUPPORTED_VERSION",
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": true,
      "legacyCondition": "OPTIONAL",
      "byteAction": "PRESERVE"
    },
    {
      "result": "SELECTOR_INVALID",
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": false,
      "legacyCondition": "OPTIONAL",
      "byteAction": "PRESERVE"
    },
    {
      "result": "AUTHENTICATION_FAILED",
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": true,
      "legacyCondition": "OPTIONAL",
      "byteAction": "PRESERVE"
    },
    {
      "result": "MANIFEST_INVALID",
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": true,
      "legacyCondition": "OPTIONAL",
      "byteAction": "PRESERVE"
    },
    {
      "result": "RECORD_SET_INCOMPLETE",
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": true,
      "legacyCondition": "OPTIONAL",
      "byteAction": "PRESERVE"
    },
    {
      "result": "RECORD_INVALID",
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": true,
      "legacyCondition": "OPTIONAL",
      "byteAction": "PRESERVE"
    },
    {
      "result": "REFERENCE_INCONSISTENT",
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": true,
      "legacyCondition": "OPTIONAL",
      "byteAction": "PRESERVE"
    },
    {
      "result": "PARTIAL_GENERATION",
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": false,
      "legacyCondition": "OPTIONAL",
      "byteAction": "PRESERVE"
    },
    {
      "result": "INTERNAL_VALIDATION_FAILED",
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": false,
      "legacyCondition": "OPTIONAL",
      "byteAction": "PRESERVE"
    }
  ],
  "reachableConditionRows": [
    {
      "result": "NO_M2_STATE",
      "legacyPresent": false,
      "disposition": "SHOW_CREATE",
      "authority": "NONE",
      "resetEligible": false
    },
    {
      "result": "LEGACY_ONLY",
      "legacyPresent": true,
      "disposition": "SHOW_REESTABLISHMENT",
      "authority": "NONE",
      "resetEligible": false
    },
    {
      "result": "RESTORED_EMPTY",
      "legacyPresent": false,
      "disposition": "CONTINUE_EMPTY",
      "authority": "SELECTED_AUTHORITY",
      "resetEligible": false
    },
    {
      "result": "RESTORED_EMPTY",
      "legacyPresent": true,
      "disposition": "CONTINUE_EMPTY",
      "authority": "SELECTED_AUTHORITY",
      "resetEligible": false
    },
    {
      "result": "RESTORED_ACTIVE",
      "legacyPresent": false,
      "disposition": "CONTINUE_ACTIVE",
      "authority": "SELECTED_AUTHORITY",
      "resetEligible": false
    },
    {
      "result": "RESTORED_ACTIVE",
      "legacyPresent": true,
      "disposition": "CONTINUE_ACTIVE",
      "authority": "SELECTED_AUTHORITY",
      "resetEligible": false
    },
    {
      "result": "RESTORED_RECONCILIATION_REQUIRED",
      "legacyPresent": false,
      "disposition": "RECONCILE_ONLY",
      "authority": "SELECTED_ORIGINAL_AUTHORITY",
      "resetEligible": false
    },
    {
      "result": "RESTORED_RECONCILIATION_REQUIRED",
      "legacyPresent": true,
      "disposition": "RECONCILE_ONLY",
      "authority": "SELECTED_ORIGINAL_AUTHORITY",
      "resetEligible": false
    },
    {
      "result": "LOCKED_ELSEWHERE",
      "legacyPresent": false,
      "disposition": "LOCK_RETRY",
      "authority": "NONE",
      "resetEligible": false
    },
    {
      "result": "WRAPPER_AUTH_FAILED",
      "legacyPresent": false,
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": false
    },
    {
      "result": "WRAPPER_AUTH_FAILED",
      "legacyPresent": true,
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": false
    },
    {
      "result": "INCOMPATIBLE_BUILD",
      "legacyPresent": false,
      "disposition": "SHOW_COMPATIBLE_BUILD",
      "authority": "NONE",
      "resetEligible": false
    },
    {
      "result": "INCOMPATIBLE_FORMAT",
      "legacyPresent": false,
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": true
    },
    {
      "result": "INCOMPATIBLE_FORMAT",
      "legacyPresent": true,
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": true
    },
    {
      "result": "UNSUPPORTED_VERSION",
      "legacyPresent": false,
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": true
    },
    {
      "result": "UNSUPPORTED_VERSION",
      "legacyPresent": true,
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": true
    },
    {
      "result": "SELECTOR_INVALID",
      "legacyPresent": false,
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": false
    },
    {
      "result": "SELECTOR_INVALID",
      "legacyPresent": true,
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": false
    },
    {
      "result": "AUTHENTICATION_FAILED",
      "legacyPresent": false,
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": true
    },
    {
      "result": "AUTHENTICATION_FAILED",
      "legacyPresent": true,
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": true
    },
    {
      "result": "MANIFEST_INVALID",
      "legacyPresent": false,
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": true
    },
    {
      "result": "MANIFEST_INVALID",
      "legacyPresent": true,
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": true
    },
    {
      "result": "RECORD_SET_INCOMPLETE",
      "legacyPresent": false,
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": true
    },
    {
      "result": "RECORD_SET_INCOMPLETE",
      "legacyPresent": true,
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": true
    },
    {
      "result": "RECORD_INVALID",
      "legacyPresent": false,
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": true
    },
    {
      "result": "RECORD_INVALID",
      "legacyPresent": true,
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": true
    },
    {
      "result": "REFERENCE_INCONSISTENT",
      "legacyPresent": false,
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": true
    },
    {
      "result": "REFERENCE_INCONSISTENT",
      "legacyPresent": true,
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": true
    },
    {
      "result": "PARTIAL_GENERATION",
      "legacyPresent": false,
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": false
    },
    {
      "result": "PARTIAL_GENERATION",
      "legacyPresent": true,
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": false
    },
    {
      "result": "INTERNAL_VALIDATION_FAILED",
      "legacyPresent": false,
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": false
    },
    {
      "result": "INTERNAL_VALIDATION_FAILED",
      "legacyPresent": true,
      "disposition": "PRESERVE_AND_STOP",
      "authority": "NONE",
      "resetEligible": false
    }
  ],
  "authorityRules": {
    "RESTORED_ACTIVE": "EXACT_C_REST_SELECTED_AUTHORITY",
    "RESTORED_EMPTY": "EXACT_C_REST_SELECTED_EMPTY_AUTHORITY",
    "RESTORED_RECONCILIATION_REQUIRED": "EXACT_C_REST_SELECTED_ORIGINAL_AUTHORITY_WITH_CANDIDATE_NON_AUTHORITATIVE",
    "allFailureAndInventoryResults": "NONE",
    "userChoiceMaySelectAuthority": false,
    "candidateAuthority": false,
    "legacyAuthority": false
  },
  "reconciliation": {
    "operation": "RECONCILE_INDETERMINATE",
    "operationSource": "C-FMT valueRegistries.operation",
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
    "outcomeRules": {
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
    },
    "crashBoundaryIds": [
      "DURING_RS_WORK",
      "AFTER_DURABLE_COMMIT_BEFORE_RESPONSE",
      "AFTER_NOT_COMMITTED",
      "AFTER_INDETERMINATE",
      "DURING_RECONCILIATION",
      "AFTER_AUTHORITY_SELECTION_BEFORE_OUTPUT_RESPONSE",
      "DURING_ESCROW_OUTPUT_RESPONSE",
      "AFTER_OUTPUT_RESPONSE_LOSS"
    ],
    "cFmtCrashRows": [
      "AFTER_INDETERMINATE",
      "DURING_RECONCILIATION"
    ],
    "candidateExposed": false,
    "newTerminalRule": false,
    "transitionReplay": false,
    "outputRegeneration": false,
    "otherStateChangingOperation": false
  },
  "passwordRewrap": {
    "scope": "M2_RECOVERY_SURFACE_ONLY",
    "eligibleResults": [
      "RESTORED_ACTIVE",
      "RESTORED_EMPTY"
    ],
    "requiresSuccessfulWrapperAuthentication": true,
    "forbiddenResult": "RESTORED_RECONCILIATION_REQUIRED",
    "existingVaultFacilityByInventoryResult": {
      "NO_M2_STATE": "UNCHANGED_BY_C_REC",
      "LEGACY_ONLY": "UNCHANGED_BY_C_REC"
    },
    "wrongOrForgottenCredentials": "NO_REWRAP_NO_RESET_NO_SALVAGE_NO_RECORD_ORACLE",
    "effect": "ATOMICALLY_REPLACE_WRAPPER_AROUND_SAME_ROOT_STORAGE_KEY",
    "m2Bytes": "BYTE_IDENTICAL",
    "crashOutcomes": [
      "OLD_VALID_WRAPPER",
      "NEW_VALID_WRAPPER"
    ],
    "forgottenPasswordRecovery": false
  },
  "compatibleBuild": {
    "result": "INCOMPATIBLE_BUILD",
    "disposition": "SHOW_COMPATIBLE_BUILD",
    "readerProfile": "CFMT_EXACT_9DACE4A0",
    "preserveAndStop": true,
    "readsOrMutatesBytes": false,
    "resetEligible": false
  },
  "legacy": {
    "input": "ABSTRACT_LEGACY_PRESENT_AND_BOUNDED_VALUE_FREE_COUNT",
    "import": false,
    "decrypt": false,
    "translate": false,
    "fallback": false,
    "selectedAuthority": false,
    "preserveBytes": true,
    "physicalInventoryOwner": "L-INV",
    "cleanup": "DEFERRED"
  },
  "marker": {
    "states": [
      "ABSENT",
      "PENDING_NEW_SESSION",
      "NEW_SESSION_CONFIRMED",
      "LEGACY_INVALIDATED"
    ],
    "completeRestoreResultRequired": true,
    "transitions": [
      {
        "id": "START",
        "from": "ABSENT",
        "event": "USER_CONFIRMED_START",
        "to": "PENDING_NEW_SESSION",
        "allowedRestoreResults": [
          "LEGACY_ONLY"
        ],
        "requiresLock": true,
        "idempotent": false
      },
      {
        "id": "CANCEL",
        "from": "PENDING_NEW_SESSION",
        "event": "USER_CANCEL_BEFORE_CONFIRMATION",
        "to": "ABSENT",
        "allowedRestoreResults": [
          "LEGACY_ONLY"
        ],
        "requiresLock": true,
        "idempotent": false
      },
      {
        "id": "CONFIRM",
        "from": "PENDING_NEW_SESSION",
        "event": "DISTINCT_POST_START_C_FMT_COMMITTED_AUTHORITY_RESTORED_ACTIVE",
        "to": "NEW_SESSION_CONFIRMED",
        "allowedRestoreResults": [
          "RESTORED_ACTIVE"
        ],
        "requiresLock": true,
        "idempotent": false
      },
      {
        "id": "COMMIT_MARKER",
        "from": "NEW_SESSION_CONFIRMED",
        "event": "ATOMIC_MARKER_COMMIT",
        "to": "LEGACY_INVALIDATED",
        "allowedRestoreResults": [
          "RESTORED_ACTIVE"
        ],
        "requiresLock": true,
        "idempotent": true
      },
      {
        "id": "REPEAT_COMPLETION",
        "from": "LEGACY_INVALIDATED",
        "event": "REPEAT_MARKER_COMPLETION",
        "to": "LEGACY_INVALIDATED",
        "allowedRestoreResults": [
          "RESTORED_ACTIVE"
        ],
        "requiresLock": true,
        "idempotent": true
      }
    ],
    "legacyEligibleByState": {
      "ABSENT": true,
      "PENDING_NEW_SESSION": true,
      "NEW_SESSION_CONFIRMED": false,
      "LEGACY_INVALIDATED": false
    },
    "binding": "OPAQUE_START_AUTHORITY_CONFIRMATION_TOKEN_EQUALITY",
    "timeOrFreshnessComparison": false,
    "encodingOwner": "L-MARK",
    "newSessionOwner": "L-REEST",
    "realConfirmationBlockedUntilOwnersRatified": true,
    "cleanupEffect": false,
    "reverseAfterConfirmation": false
  },
  "reset": {
    "requiresExplicitSeparateIrreversibleConfirmation": true,
    "eligibleResults": [
      "AUTHENTICATION_FAILED",
      "INCOMPATIBLE_FORMAT",
      "MANIFEST_INVALID",
      "RECORD_INVALID",
      "RECORD_SET_INCOMPLETE",
      "REFERENCE_INCONSISTENT",
      "UNSUPPORTED_VERSION"
    ],
    "ineligibleResults": [
      "NO_M2_STATE",
      "LEGACY_ONLY",
      "RESTORED_EMPTY",
      "RESTORED_ACTIVE",
      "RESTORED_RECONCILIATION_REQUIRED",
      "LOCKED_ELSEWHERE",
      "WRAPPER_AUTH_FAILED",
      "INCOMPATIBLE_BUILD",
      "SELECTOR_INVALID",
      "PARTIAL_GENERATION",
      "INTERNAL_VALIDATION_FAILED"
    ],
    "requiresOneWriterLock": true,
    "valueFreeAuthorityLossDisclosureRequired": true,
    "preserveDiagnosis": true,
    "legacyBytes": "UNCHANGED",
    "markerState": "UNCHANGED",
    "physicalErasureClaim": false,
    "interruptedClassification": "NEXT_COMPLETE_C_REST_RESULT_ONLY",
    "implementedHere": false
  },
  "diagnostics": {
    "allowed": [
      "restoreResult",
      "condition",
      "recoveryDisposition",
      "stageCode",
      "reasonCode",
      "boundedCount"
    ],
    "forbidden": [
      "key",
      "nonce",
      "plaintext",
      "bindingByte",
      "contextIdentifier",
      "sessionIdentifier",
      "packageReference",
      "digest",
      "recordKey",
      "legacyContent",
      "markerBinding",
      "escrow"
    ]
  },
  "precedence": {
    "requiresOneWriterLockForStateChange": true,
    "lockedDisposition": "LOCK_RETRY",
    "enumerationOrderAuthority": false,
    "ambiguousFacts": "SAFER_DISPOSITION_NO_AUTHORITY"
  },
  "limits": {
    "freshnessClaim": false,
    "coherentWholeProfileRollbackDetection": false,
    "physicalErasureClaim": false,
    "javascriptZeroizationClaim": false,
    "productionReadinessClaim": false,
    "recoverySuccessClaim": false
  },
  "faultPhaseOrder": [
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
      "result": "PARTIAL_GENERATION",
      "scope": "An orphan generation is a generation artifact with no fixed selector, or whose record key does not share the selector's local context. Records in the selector's context that the selector names neither as selected nor as candidate, whether a complete or a partially staged generation, are unbound debris: non-authoritative, preserved, never a repair source, and not `orphanGeneration`, `PARTIAL_GENERATION` or a stop. `partialSelectedOrCandidateGeneration` applies only to a generation the selector names."
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
  "fixtures": [
    {
      "id": "DISPATCH-NO_M2_STATE-NOLEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "NO_M2_STATE",
        "legacyPresent": false
      },
      "expected": {
        "disposition": "SHOW_CREATE",
        "authority": "NONE",
        "resetEligible": false,
        "agreement": {
          "disposition": "SHOW_CREATE",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "DISPATCH-LEGACY_ONLY-LEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "LEGACY_ONLY",
        "legacyPresent": true
      },
      "expected": {
        "disposition": "SHOW_REESTABLISHMENT",
        "authority": "NONE",
        "resetEligible": false,
        "agreement": {
          "disposition": "SHOW_REESTABLISHMENT",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "DISPATCH-RESTORED_EMPTY-NOLEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "RESTORED_EMPTY",
        "legacyPresent": false
      },
      "expected": {
        "disposition": "CONTINUE_EMPTY",
        "authority": "SELECTED_AUTHORITY",
        "resetEligible": false,
        "agreement": {
          "disposition": "CONTINUE_EMPTY",
          "authorityIdentity": "SELECTED_AUTHORITY",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "DISPATCH-RESTORED_EMPTY-LEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "RESTORED_EMPTY",
        "legacyPresent": true
      },
      "expected": {
        "disposition": "CONTINUE_EMPTY",
        "authority": "SELECTED_AUTHORITY",
        "resetEligible": false,
        "agreement": {
          "disposition": "CONTINUE_EMPTY",
          "authorityIdentity": "SELECTED_AUTHORITY",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "DISPATCH-RESTORED_ACTIVE-NOLEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "RESTORED_ACTIVE",
        "legacyPresent": false
      },
      "expected": {
        "disposition": "CONTINUE_ACTIVE",
        "authority": "SELECTED_AUTHORITY",
        "resetEligible": false,
        "agreement": {
          "disposition": "CONTINUE_ACTIVE",
          "authorityIdentity": "SELECTED_AUTHORITY",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "DISPATCH-RESTORED_ACTIVE-LEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "RESTORED_ACTIVE",
        "legacyPresent": true
      },
      "expected": {
        "disposition": "CONTINUE_ACTIVE",
        "authority": "SELECTED_AUTHORITY",
        "resetEligible": false,
        "agreement": {
          "disposition": "CONTINUE_ACTIVE",
          "authorityIdentity": "SELECTED_AUTHORITY",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "DISPATCH-RESTORED_RECONCILIATION_REQUIRED-NOLEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "RESTORED_RECONCILIATION_REQUIRED",
        "legacyPresent": false
      },
      "expected": {
        "disposition": "RECONCILE_ONLY",
        "authority": "SELECTED_ORIGINAL_AUTHORITY",
        "resetEligible": false,
        "agreement": {
          "disposition": "RECONCILE_ONLY",
          "authorityIdentity": "SELECTED_ORIGINAL_AUTHORITY",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "DISPATCH-RESTORED_RECONCILIATION_REQUIRED-LEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "RESTORED_RECONCILIATION_REQUIRED",
        "legacyPresent": true
      },
      "expected": {
        "disposition": "RECONCILE_ONLY",
        "authority": "SELECTED_ORIGINAL_AUTHORITY",
        "resetEligible": false,
        "agreement": {
          "disposition": "RECONCILE_ONLY",
          "authorityIdentity": "SELECTED_ORIGINAL_AUTHORITY",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "DISPATCH-LOCKED_ELSEWHERE-NOLEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "LOCKED_ELSEWHERE",
        "legacyPresent": false
      },
      "expected": {
        "disposition": "LOCK_RETRY",
        "authority": "NONE",
        "resetEligible": false,
        "agreement": {
          "disposition": "LOCK_RETRY",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-WRAPPER_AUTH_FAILED-NOLEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "WRAPPER_AUTH_FAILED",
        "legacyPresent": false
      },
      "expected": {
        "disposition": "PRESERVE_AND_STOP",
        "authority": "NONE",
        "resetEligible": false,
        "agreement": {
          "disposition": "PRESERVE_AND_STOP",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-WRAPPER_AUTH_FAILED-LEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "WRAPPER_AUTH_FAILED",
        "legacyPresent": true
      },
      "expected": {
        "disposition": "PRESERVE_AND_STOP",
        "authority": "NONE",
        "resetEligible": false,
        "agreement": {
          "disposition": "PRESERVE_AND_STOP",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-INCOMPATIBLE_BUILD-NOLEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "INCOMPATIBLE_BUILD",
        "legacyPresent": false
      },
      "expected": {
        "disposition": "SHOW_COMPATIBLE_BUILD",
        "authority": "NONE",
        "resetEligible": false,
        "agreement": {
          "disposition": "SHOW_COMPATIBLE_BUILD",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-INCOMPATIBLE_FORMAT-NOLEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "INCOMPATIBLE_FORMAT",
        "legacyPresent": false
      },
      "expected": {
        "disposition": "PRESERVE_AND_STOP",
        "authority": "NONE",
        "resetEligible": true,
        "agreement": {
          "disposition": "PRESERVE_AND_STOP",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-INCOMPATIBLE_FORMAT-LEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "INCOMPATIBLE_FORMAT",
        "legacyPresent": true
      },
      "expected": {
        "disposition": "PRESERVE_AND_STOP",
        "authority": "NONE",
        "resetEligible": true,
        "agreement": {
          "disposition": "PRESERVE_AND_STOP",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-UNSUPPORTED_VERSION-NOLEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "UNSUPPORTED_VERSION",
        "legacyPresent": false
      },
      "expected": {
        "disposition": "PRESERVE_AND_STOP",
        "authority": "NONE",
        "resetEligible": true,
        "agreement": {
          "disposition": "PRESERVE_AND_STOP",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-UNSUPPORTED_VERSION-LEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "UNSUPPORTED_VERSION",
        "legacyPresent": true
      },
      "expected": {
        "disposition": "PRESERVE_AND_STOP",
        "authority": "NONE",
        "resetEligible": true,
        "agreement": {
          "disposition": "PRESERVE_AND_STOP",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-SELECTOR_INVALID-NOLEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "SELECTOR_INVALID",
        "legacyPresent": false
      },
      "expected": {
        "disposition": "PRESERVE_AND_STOP",
        "authority": "NONE",
        "resetEligible": false,
        "agreement": {
          "disposition": "PRESERVE_AND_STOP",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-SELECTOR_INVALID-LEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "SELECTOR_INVALID",
        "legacyPresent": true
      },
      "expected": {
        "disposition": "PRESERVE_AND_STOP",
        "authority": "NONE",
        "resetEligible": false,
        "agreement": {
          "disposition": "PRESERVE_AND_STOP",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-AUTHENTICATION_FAILED-NOLEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "AUTHENTICATION_FAILED",
        "legacyPresent": false
      },
      "expected": {
        "disposition": "PRESERVE_AND_STOP",
        "authority": "NONE",
        "resetEligible": true,
        "agreement": {
          "disposition": "PRESERVE_AND_STOP",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-AUTHENTICATION_FAILED-LEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "AUTHENTICATION_FAILED",
        "legacyPresent": true
      },
      "expected": {
        "disposition": "PRESERVE_AND_STOP",
        "authority": "NONE",
        "resetEligible": true,
        "agreement": {
          "disposition": "PRESERVE_AND_STOP",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-MANIFEST_INVALID-NOLEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "MANIFEST_INVALID",
        "legacyPresent": false
      },
      "expected": {
        "disposition": "PRESERVE_AND_STOP",
        "authority": "NONE",
        "resetEligible": true,
        "agreement": {
          "disposition": "PRESERVE_AND_STOP",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-MANIFEST_INVALID-LEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "MANIFEST_INVALID",
        "legacyPresent": true
      },
      "expected": {
        "disposition": "PRESERVE_AND_STOP",
        "authority": "NONE",
        "resetEligible": true,
        "agreement": {
          "disposition": "PRESERVE_AND_STOP",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-RECORD_SET_INCOMPLETE-NOLEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "RECORD_SET_INCOMPLETE",
        "legacyPresent": false
      },
      "expected": {
        "disposition": "PRESERVE_AND_STOP",
        "authority": "NONE",
        "resetEligible": true,
        "agreement": {
          "disposition": "PRESERVE_AND_STOP",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-RECORD_SET_INCOMPLETE-LEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "RECORD_SET_INCOMPLETE",
        "legacyPresent": true
      },
      "expected": {
        "disposition": "PRESERVE_AND_STOP",
        "authority": "NONE",
        "resetEligible": true,
        "agreement": {
          "disposition": "PRESERVE_AND_STOP",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-RECORD_INVALID-NOLEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "RECORD_INVALID",
        "legacyPresent": false
      },
      "expected": {
        "disposition": "PRESERVE_AND_STOP",
        "authority": "NONE",
        "resetEligible": true,
        "agreement": {
          "disposition": "PRESERVE_AND_STOP",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-RECORD_INVALID-LEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "RECORD_INVALID",
        "legacyPresent": true
      },
      "expected": {
        "disposition": "PRESERVE_AND_STOP",
        "authority": "NONE",
        "resetEligible": true,
        "agreement": {
          "disposition": "PRESERVE_AND_STOP",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-REFERENCE_INCONSISTENT-NOLEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "REFERENCE_INCONSISTENT",
        "legacyPresent": false
      },
      "expected": {
        "disposition": "PRESERVE_AND_STOP",
        "authority": "NONE",
        "resetEligible": true,
        "agreement": {
          "disposition": "PRESERVE_AND_STOP",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-REFERENCE_INCONSISTENT-LEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "REFERENCE_INCONSISTENT",
        "legacyPresent": true
      },
      "expected": {
        "disposition": "PRESERVE_AND_STOP",
        "authority": "NONE",
        "resetEligible": true,
        "agreement": {
          "disposition": "PRESERVE_AND_STOP",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-PARTIAL_GENERATION-NOLEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "PARTIAL_GENERATION",
        "legacyPresent": false
      },
      "expected": {
        "disposition": "PRESERVE_AND_STOP",
        "authority": "NONE",
        "resetEligible": false,
        "agreement": {
          "disposition": "PRESERVE_AND_STOP",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-PARTIAL_GENERATION-LEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "PARTIAL_GENERATION",
        "legacyPresent": true
      },
      "expected": {
        "disposition": "PRESERVE_AND_STOP",
        "authority": "NONE",
        "resetEligible": false,
        "agreement": {
          "disposition": "PRESERVE_AND_STOP",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-INTERNAL_VALIDATION_FAILED-NOLEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "INTERNAL_VALIDATION_FAILED",
        "legacyPresent": false
      },
      "expected": {
        "disposition": "PRESERVE_AND_STOP",
        "authority": "NONE",
        "resetEligible": false,
        "agreement": {
          "disposition": "PRESERVE_AND_STOP",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "DISPATCH-INTERNAL_VALIDATION_FAILED-LEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "INTERNAL_VALIDATION_FAILED",
        "legacyPresent": true
      },
      "expected": {
        "disposition": "PRESERVE_AND_STOP",
        "authority": "NONE",
        "resetEligible": false,
        "agreement": {
          "disposition": "PRESERVE_AND_STOP",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "MARKER-START",
      "kind": "MARKER",
      "input": {
        "state": "ABSENT",
        "event": "USER_CONFIRMED_START",
        "lockHeld": true,
        "distinct": false,
        "restoreResult": "LEGACY_ONLY",
        "committed": false
      },
      "expected": {
        "state": "PENDING_NEW_SESSION",
        "accepted": true,
        "agreement": {
          "disposition": "MARKER_TRANSITION",
          "authorityIdentity": "UNCHANGED",
          "markerState": "PENDING_NEW_SESSION",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "MARKER-CANCEL",
      "kind": "MARKER",
      "input": {
        "state": "PENDING_NEW_SESSION",
        "event": "USER_CANCEL_BEFORE_CONFIRMATION",
        "lockHeld": true,
        "distinct": false,
        "restoreResult": "LEGACY_ONLY",
        "committed": false
      },
      "expected": {
        "state": "ABSENT",
        "accepted": true,
        "agreement": {
          "disposition": "MARKER_TRANSITION",
          "authorityIdentity": "UNCHANGED",
          "markerState": "ABSENT",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "MARKER-CONFIRM",
      "kind": "MARKER",
      "input": {
        "state": "PENDING_NEW_SESSION",
        "event": "DISTINCT_POST_START_C_FMT_COMMITTED_AUTHORITY_RESTORED_ACTIVE",
        "lockHeld": true,
        "distinct": true,
        "restoreResult": "RESTORED_ACTIVE",
        "committed": true
      },
      "expected": {
        "state": "NEW_SESSION_CONFIRMED",
        "accepted": true,
        "agreement": {
          "disposition": "MARKER_TRANSITION",
          "authorityIdentity": "UNCHANGED",
          "markerState": "NEW_SESSION_CONFIRMED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "MARKER-COMMIT_MARKER",
      "kind": "MARKER",
      "input": {
        "state": "NEW_SESSION_CONFIRMED",
        "event": "ATOMIC_MARKER_COMMIT",
        "lockHeld": true,
        "distinct": false,
        "restoreResult": "RESTORED_ACTIVE",
        "committed": false
      },
      "expected": {
        "state": "LEGACY_INVALIDATED",
        "accepted": true,
        "agreement": {
          "disposition": "MARKER_TRANSITION",
          "authorityIdentity": "UNCHANGED",
          "markerState": "LEGACY_INVALIDATED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "MARKER-REPEAT_COMPLETION",
      "kind": "MARKER",
      "input": {
        "state": "LEGACY_INVALIDATED",
        "event": "REPEAT_MARKER_COMPLETION",
        "lockHeld": true,
        "distinct": false,
        "restoreResult": "RESTORED_ACTIVE",
        "committed": false
      },
      "expected": {
        "state": "LEGACY_INVALIDATED",
        "accepted": true,
        "agreement": {
          "disposition": "MARKER_TRANSITION",
          "authorityIdentity": "UNCHANGED",
          "markerState": "LEGACY_INVALIDATED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "NEG-UNKNOWN-RESULT",
      "kind": "DISPATCH",
      "input": {
        "result": "UNKNOWN",
        "legacyPresent": false
      },
      "expected": {
        "reject": "UNKNOWN_RESULT",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "NEG-INCOMPLETE-DISPATCH",
      "kind": "DISPATCH",
      "input": {
        "result": "RESTORED_ACTIVE"
      },
      "expected": {
        "reject": "MISSING_DISPATCH_INPUT",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "NEG-LOCKED-LEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "LOCKED_ELSEWHERE",
        "legacyPresent": true
      },
      "expected": {
        "reject": "UNREACHABLE_CONDITION_PAIR",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "NEG-BUILD-LEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "INCOMPATIBLE_BUILD",
        "legacyPresent": true
      },
      "expected": {
        "reject": "UNREACHABLE_CONDITION_PAIR",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "NEG-NO-M2-LEGACY",
      "kind": "DISPATCH",
      "input": {
        "result": "NO_M2_STATE",
        "legacyPresent": true
      },
      "expected": {
        "reject": "UNREACHABLE_CONDITION_PAIR",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "C_REST_CLASSIFIED"
        }
      }
    },
    {
      "id": "NEG-SILENT-RESET",
      "kind": "ACTION",
      "input": {
        "action": "RESET",
        "confirmed": false,
        "lock": "HELD"
      },
      "expected": {
        "reject": "EXPLICIT_CONFIRMATION_REQUIRED",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "UNCHANGED",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "ACTION_GATE"
        }
      }
    },
    {
      "id": "NEG-RESET-WRONG-CREDENTIALS",
      "kind": "ACTION",
      "input": {
        "action": "RESET",
        "result": "WRAPPER_AUTH_FAILED",
        "confirmed": true,
        "lock": "HELD"
      },
      "expected": {
        "reject": "RESET_INELIGIBLE",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "UNCHANGED",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "ACTION_GATE"
        }
      }
    },
    {
      "id": "NEG-RESET-RECONCILIATION",
      "kind": "ACTION",
      "input": {
        "action": "RESET",
        "result": "RESTORED_RECONCILIATION_REQUIRED",
        "confirmed": true,
        "lock": "HELD"
      },
      "expected": {
        "reject": "RESET_INELIGIBLE",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "UNCHANGED",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "ACTION_GATE"
        }
      }
    },
    {
      "id": "NEG-FALLBACK",
      "kind": "ACTION",
      "input": {
        "action": "LEGACY_FALLBACK"
      },
      "expected": {
        "reject": "LEGACY_FALLBACK_FORBIDDEN",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "UNCHANGED",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "ACTION_GATE"
        }
      }
    },
    {
      "id": "NEG-IMPORT",
      "kind": "ACTION",
      "input": {
        "action": "LEGACY_IMPORT"
      },
      "expected": {
        "reject": "LEGACY_IMPORT_FORBIDDEN",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "UNCHANGED",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "ACTION_GATE"
        }
      }
    },
    {
      "id": "NEG-MUTATION-RETRY",
      "kind": "ACTION",
      "input": {
        "action": "RETRY_ORIGINAL_MUTATION"
      },
      "expected": {
        "reject": "MUTATION_RETRY_FORBIDDEN",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "UNCHANGED",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "ACTION_GATE"
        }
      }
    },
    {
      "id": "NEG-CANDIDATE-SELECTION",
      "kind": "ACTION",
      "input": {
        "action": "USER_SELECT_CANDIDATE"
      },
      "expected": {
        "reject": "CANDIDATE_SELECTION_FORBIDDEN",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "UNCHANGED",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "ACTION_GATE"
        }
      }
    },
    {
      "id": "NEG-OUTPUT-RELEASE",
      "kind": "ACTION",
      "input": {
        "action": "RESTORE_RELEASE_ESCROW"
      },
      "expected": {
        "reject": "RESTORE_OUTPUT_RELEASE_FORBIDDEN",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "UNCHANGED",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "ACTION_GATE"
        }
      }
    },
    {
      "id": "NEG-CLEANUP",
      "kind": "ACTION",
      "input": {
        "action": "DELETE_LEGACY"
      },
      "expected": {
        "reject": "CLEANUP_DEFERRED",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "UNCHANGED",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "ACTION_GATE"
        }
      }
    },
    {
      "id": "NEG-MARKER-REVERSE",
      "kind": "MARKER",
      "input": {
        "state": "LEGACY_INVALIDATED",
        "event": "USER_CANCEL_BEFORE_CONFIRMATION",
        "lockHeld": true
      },
      "expected": {
        "reject": "MARKER_TRANSITION_FORBIDDEN",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "UNCHANGED",
          "markerState": "LEGACY_INVALIDATED",
          "firstFailingPhase": "MARKER_GATE"
        }
      }
    },
    {
      "id": "NEG-STALE-TOKEN",
      "kind": "MARKER",
      "input": {
        "state": "PENDING_NEW_SESSION",
        "event": "DISTINCT_POST_START_C_FMT_COMMITTED_AUTHORITY_RESTORED_ACTIVE",
        "lockHeld": true,
        "distinct": false,
        "restoreResult": "RESTORED_ACTIVE",
        "committed": true
      },
      "expected": {
        "reject": "TOKEN_MISMATCH",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "UNCHANGED",
          "markerState": "PENDING_NEW_SESSION",
          "firstFailingPhase": "MARKER_GATE"
        }
      }
    },
    {
      "id": "NEG-CROSS-SESSION-TOKEN",
      "kind": "MARKER",
      "input": {
        "state": "PENDING_NEW_SESSION",
        "event": "DISTINCT_POST_START_C_FMT_COMMITTED_AUTHORITY_RESTORED_ACTIVE",
        "lockHeld": true,
        "distinct": false,
        "restoreResult": "RESTORED_ACTIVE",
        "committed": true
      },
      "expected": {
        "reject": "TOKEN_MISMATCH",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "UNCHANGED",
          "markerState": "PENDING_NEW_SESSION",
          "firstFailingPhase": "MARKER_GATE"
        }
      }
    },
    {
      "id": "NEG-EMPTY-CONFIRM",
      "kind": "MARKER",
      "input": {
        "state": "PENDING_NEW_SESSION",
        "event": "DISTINCT_POST_START_C_FMT_COMMITTED_AUTHORITY_RESTORED_ACTIVE",
        "lockHeld": true,
        "distinct": true,
        "restoreResult": "RESTORED_EMPTY",
        "committed": true
      },
      "expected": {
        "reject": "CONFIRMATION_PRECONDITION_FAILED",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "UNCHANGED",
          "markerState": "PENDING_NEW_SESSION",
          "firstFailingPhase": "MARKER_GATE"
        }
      }
    },
    {
      "id": "NEG-RECONCILIATION-CONFIRM",
      "kind": "MARKER",
      "input": {
        "state": "PENDING_NEW_SESSION",
        "event": "DISTINCT_POST_START_C_FMT_COMMITTED_AUTHORITY_RESTORED_ACTIVE",
        "lockHeld": true,
        "distinct": true,
        "restoreResult": "RESTORED_RECONCILIATION_REQUIRED",
        "committed": true
      },
      "expected": {
        "reject": "CONFIRMATION_PRECONDITION_FAILED",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "UNCHANGED",
          "markerState": "PENDING_NEW_SESSION",
          "firstFailingPhase": "MARKER_GATE"
        }
      }
    },
    {
      "id": "NEG-NO-LOCK",
      "kind": "MARKER",
      "input": {
        "state": "ABSENT",
        "event": "USER_CONFIRMED_START",
        "lockHeld": false
      },
      "expected": {
        "reject": "LOCKED_ELSEWHERE",
        "agreement": {
          "disposition": "LOCK_RETRY",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "LOCK"
        }
      }
    },
    {
      "id": "NEG-NO-M2-MARKER-START",
      "kind": "MARKER",
      "input": {
        "state": "ABSENT",
        "event": "USER_CONFIRMED_START",
        "lockHeld": true,
        "restoreResult": "NO_M2_STATE"
      },
      "expected": {
        "reject": "RESTORE_PRECONDITION_FAILED",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "UNCHANGED",
          "markerState": "ABSENT",
          "firstFailingPhase": "MARKER_GATE"
        }
      }
    },
    {
      "id": "NEG-RECONCILIATION-MARKER-COMMIT",
      "kind": "MARKER",
      "input": {
        "state": "NEW_SESSION_CONFIRMED",
        "event": "ATOMIC_MARKER_COMMIT",
        "lockHeld": true,
        "restoreResult": "RESTORED_RECONCILIATION_REQUIRED"
      },
      "expected": {
        "reject": "RESTORE_PRECONDITION_FAILED",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "UNCHANGED",
          "markerState": "NEW_SESSION_CONFIRMED",
          "firstFailingPhase": "MARKER_GATE"
        }
      }
    },
    {
      "id": "NEG-RAW-DIAGNOSTIC",
      "kind": "DIAGNOSTIC",
      "input": {
        "fields": [
          "stageCode",
          "plaintext"
        ]
      },
      "expected": {
        "reject": "RAW_VALUE_DIAGNOSTIC",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "DIAGNOSTIC_GATE"
        }
      }
    },
    {
      "id": "RECON-ORIGINAL-COMMITTED",
      "kind": "RECONCILIATION",
      "input": {
        "path": "originalTerminalPath",
        "outcome": "COMMITTED"
      },
      "expected": {
        "authority": "COMPLETE_NEW",
        "hold": "RESOLVED",
        "output": "ORIGINAL_COMMITTED_OUTPUT",
        "agreement": {
          "disposition": "RECONCILIATION_RESULT",
          "authorityIdentity": "COMPLETE_NEW",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "RECON-ORIGINAL-NOT-COMMITTED",
      "kind": "RECONCILIATION",
      "input": {
        "path": "originalTerminalPath",
        "outcome": "NOT_COMMITTED"
      },
      "expected": {
        "authority": "COMPLETE_OLD",
        "hold": "RESOLVED",
        "output": "NONE",
        "agreement": {
          "disposition": "RECONCILIATION_RESULT",
          "authorityIdentity": "COMPLETE_OLD",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "RECON-MATCHING-COMMITTED",
      "kind": "RECONCILIATION",
      "input": {
        "path": "matchingCommitted",
        "outcome": "COMMITTED"
      },
      "expected": {
        "authority": "COMPLETE_NEW",
        "hold": "UNTIL_LOCAL_EMISSION_SUCCESS",
        "output": "ORIGINAL_COMMITTED_OUTPUT",
        "agreement": {
          "disposition": "RECONCILIATION_RESULT",
          "authorityIdentity": "COMPLETE_NEW",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "RECON-MATCHING-NOT-COMMITTED",
      "kind": "RECONCILIATION",
      "input": {
        "path": "matchingNotCommitted",
        "outcome": "NOT_COMMITTED"
      },
      "expected": {
        "authority": "COMPLETE_OLD",
        "hold": "CLEAR_ON_NO_OUTPUT_RESPONSE",
        "output": "NONE",
        "agreement": {
          "disposition": "RECONCILIATION_RESULT",
          "authorityIdentity": "COMPLETE_OLD",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "RECON-CONTINUED-INDETERMINATE",
      "kind": "RECONCILIATION",
      "input": {
        "path": "continuedIndeterminate",
        "outcome": "INDETERMINATE"
      },
      "expected": {
        "authority": "OLD_PLUS_ONE_IMMUTABLE_HOLD",
        "hold": "UNCHANGED",
        "output": "NONE",
        "agreement": {
          "disposition": "RECONCILIATION_RESULT",
          "authorityIdentity": "OLD_PLUS_ONE_IMMUTABLE_HOLD",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "RECON-INTERRUPTED-COMMITTED-REPEAT",
      "kind": "RECONCILIATION",
      "input": {
        "path": "interruptedCommittedReconciliationRepeat",
        "outcome": "COMMITTED"
      },
      "expected": {
        "authority": "COMPLETE_NEW",
        "hold": "UNTIL_LOCAL_EMISSION_SUCCESS",
        "output": "SAME_ESCROW_MAY_REPEAT",
        "agreement": {
          "disposition": "RECONCILIATION_RESULT",
          "authorityIdentity": "COMPLETE_NEW",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "WRAPPER-CRASH-BEFORE-REPLACEMENT",
      "kind": "BOUNDARY",
      "input": {
        "boundary": "REWRAP_BEFORE_ATOMIC_REPLACEMENT"
      },
      "expected": {
        "wrapper": "OLD_VALID_WRAPPER",
        "m2State": "BYTE_IDENTICAL",
        "agreement": {
          "disposition": "BOUNDARY_RESULT",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "WRAPPER-CRASH-AFTER-REPLACEMENT",
      "kind": "BOUNDARY",
      "input": {
        "boundary": "REWRAP_AFTER_ATOMIC_REPLACEMENT"
      },
      "expected": {
        "wrapper": "NEW_VALID_WRAPPER",
        "m2State": "BYTE_IDENTICAL",
        "agreement": {
          "disposition": "BOUNDARY_RESULT",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "MARKER-CRASH-BEFORE-CONFIRMATION",
      "kind": "BOUNDARY",
      "input": {
        "boundary": "BEFORE_DISTINCT_SESSION_CONFIRMATION"
      },
      "expected": {
        "markerState": "PENDING_NEW_SESSION",
        "legacyAuthority": "UNCHANGED",
        "agreement": {
          "disposition": "BOUNDARY_RESULT",
          "authorityIdentity": "NONE",
          "markerState": "PENDING_NEW_SESSION",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "MARKER-CRASH-AFTER-CONFIRMATION",
      "kind": "BOUNDARY",
      "input": {
        "boundary": "AFTER_CONFIRMATION_BEFORE_MARKER_COMMIT"
      },
      "expected": {
        "markerState": "NEW_SESSION_CONFIRMED",
        "legacyEligibility": false,
        "resume": "MARKER_COMPLETION_ONLY",
        "agreement": {
          "disposition": "BOUNDARY_RESULT",
          "authorityIdentity": "NONE",
          "markerState": "NEW_SESSION_CONFIRMED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "MARKER-CRASH-AFTER-COMMIT",
      "kind": "BOUNDARY",
      "input": {
        "boundary": "AFTER_MARKER_COMMIT"
      },
      "expected": {
        "markerState": "LEGACY_INVALIDATED",
        "legacyEligibility": false,
        "agreement": {
          "disposition": "BOUNDARY_RESULT",
          "authorityIdentity": "NONE",
          "markerState": "LEGACY_INVALIDATED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "REWRAP-ACTIVE-ELIGIBLE",
      "kind": "PASSWORD_REWRAP",
      "input": {
        "result": "RESTORED_ACTIVE",
        "wrapperAuthenticated": true
      },
      "expected": {
        "accepted": true,
        "effect": "ATOMIC_WRAPPER_REPLACEMENT_ONLY",
        "agreement": {
          "disposition": "PASSWORD_REWRAP",
          "authorityIdentity": "UNCHANGED",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "REWRAP-NO-M2-EXISTING-FACILITY",
      "kind": "PASSWORD_REWRAP",
      "input": {
        "result": "NO_M2_STATE",
        "wrapperAuthenticated": false
      },
      "expected": {
        "m2RecoverySurface": "NOT_APPLICABLE",
        "existingVaultFacility": "UNCHANGED_BY_C_REC",
        "agreement": {
          "disposition": "EXISTING_VAULT_FACILITY_UNCHANGED",
          "authorityIdentity": "UNCHANGED",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "REWRAP-LEGACY-EXISTING-FACILITY",
      "kind": "PASSWORD_REWRAP",
      "input": {
        "result": "LEGACY_ONLY",
        "wrapperAuthenticated": false
      },
      "expected": {
        "m2RecoverySurface": "NOT_APPLICABLE",
        "existingVaultFacility": "UNCHANGED_BY_C_REC",
        "agreement": {
          "disposition": "EXISTING_VAULT_FACILITY_UNCHANGED",
          "authorityIdentity": "UNCHANGED",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "REWRAP-WRONG-CREDENTIAL-NO-ORACLE",
      "kind": "PASSWORD_REWRAP",
      "input": {
        "result": "RESTORED_ACTIVE",
        "wrapperAuthenticated": false
      },
      "expected": {
        "reject": "WRAPPER_AUTH_FAILED",
        "recordOracle": false,
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "UNCHANGED",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "WRAPPER_AUTH"
        }
      }
    },
    {
      "id": "RESET-CONFIRMED-ELIGIBLE",
      "kind": "ACTION",
      "input": {
        "action": "RESET",
        "result": "MANIFEST_INVALID",
        "confirmed": true,
        "token": "FRESH_BOUND_TOKEN",
        "lock": "HELD",
        "disclosure": true
      },
      "expected": {
        "accepted": true,
        "outcome": "ATOMIC_RESET",
        "agreement": {
          "disposition": "ACTION_RESULT",
          "authorityIdentity": "UNCHANGED",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "RESET-NO-LOCK",
      "kind": "ACTION",
      "input": {
        "action": "RESET",
        "result": "MANIFEST_INVALID",
        "confirmed": true,
        "token": "FRESH_BOUND_TOKEN",
        "lock": "NOT_HELD",
        "disclosure": true
      },
      "expected": {
        "reject": "LOCKED_ELSEWHERE",
        "agreement": {
          "disposition": "LOCK_RETRY",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "LOCK"
        }
      }
    },
    {
      "id": "RESET-NO-DISCLOSURE",
      "kind": "ACTION",
      "input": {
        "action": "RESET",
        "result": "MANIFEST_INVALID",
        "confirmed": true,
        "token": "FRESH_BOUND_TOKEN",
        "lock": "HELD",
        "disclosure": false
      },
      "expected": {
        "reject": "DISCLOSURE_REQUIRED",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "UNCHANGED",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "ACTION_GATE"
        }
      }
    },
    {
      "id": "RESET-STALE-TOKEN",
      "kind": "ACTION",
      "input": {
        "action": "RESET",
        "result": "MANIFEST_INVALID",
        "confirmed": true,
        "token": "STALE",
        "lock": "HELD",
        "disclosure": true
      },
      "expected": {
        "reject": "FRESH_CONFIRMATION_REQUIRED",
        "agreement": {
          "disposition": "REJECT",
          "authorityIdentity": "UNCHANGED",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "ACTION_GATE"
        }
      }
    },
    {
      "id": "RESET-CANCELLED",
      "kind": "ACTION",
      "input": {
        "action": "RESET_CANCEL",
        "result": "MANIFEST_INVALID"
      },
      "expected": {
        "accepted": false,
        "sideEffects": "NONE",
        "agreement": {
          "disposition": "ACTION_RESULT",
          "authorityIdentity": "UNCHANGED",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "NONE"
        }
      }
    },
    {
      "id": "RESET-INTERRUPTED",
      "kind": "BOUNDARY",
      "input": {
        "boundary": "DURING_RESET"
      },
      "expected": {
        "classificationSource": "NEXT_COMPLETE_C_REST_RESULT_ONLY",
        "authority": "NONE",
        "automaticCompletion": false,
        "cleanup": "NONE",
        "agreement": {
          "disposition": "BOUNDARY_RESULT",
          "authorityIdentity": "NONE",
          "markerState": "UNCHANGED",
          "firstFailingPhase": "NONE"
        }
      }
    }
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
<!-- styx-m2-recovery-json:v1:end -->
