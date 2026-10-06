// recovery.test.js — R-UX conformance tests (card R-UX of #317 G-SCOPE): value-free M2 recovery and
// reset actions in `src/storage/vault.js`.
//
// Normative source: the owner-ratified C-REC contract (`docs/architecture/m2/recovery-and-coexistence.md`,
// SHA-256 5b0d2fbd685a198e7e6e6bb10cb7740680086d27690c3cc622915e68beb94f87, #335 comment 5909885218).
// The §13 members this card consumes are transcribed verbatim below (`CREC`); its canonical-JSON SHA-256
// is pinned, so any edit of a row fails the suite. Every DISPATCH, ACTION, PASSWORD_REWRAP and DIAGNOSTIC
// fixture and the re-wrap/reset BOUNDARY fixtures are replayed through the public surface, the decision
// functions are compared with an independently structured oracle over generated inputs, and the vault
// methods run over the shared in-memory VaultDb double with the real Argon2id KDF: nothing is mocked
// but the storage engine, whose real IndexedDB behaviour belongs to B-CHR/B-FF.
//
// Card R-WIRE (#317) adds, at the end of this file, the vault-unlock → C-REST fault mapping
// (`vaultUnlockRestoreFault`, owner interpretation #317 comment 6022947656) and the three R-UX notes
// (R-UX ratification #447 comment 6013153608, items 2-4): tests W1-W10 and N1-N3.

import { describe, test, expect, beforeAll } from '@jest/globals';
import fc from 'fast-check';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import initKdf, { argon2id_derive } from '../../../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm.js';
import {
  createVault, VAULT_STATES, M2_RECOVERY, dispatchRecovery, decideRecoveryAction, decidePasswordRewrap,
  decideRecoveryDiagnostic, recoveryBoundary, recoveryGuidance, vaultUnlockRestoreFault,
} from '../../../src/storage/vault.js';
import * as vaultModule from '../../../src/storage/vault.js';
import { classifyRestore, FAULT_PRECEDENCE } from '../../../src/storage/m2/session-restore.js';
import { KdfBoundsError } from '../../../src/crypto/kdf-bounds.js';
import { VaultCryptoError, VaultCryptoErrorCodes as Codes } from '../../../src/crypto/vault-errors.js';
import { encodeMarker, M2_LEGACY_INVALIDATION } from '../../../src/storage/m2/legacy-session-invalidation.js';
import { FakeVaultDb, deepClone, seededBytes } from '../../support/fake-vault-db.js';

const wasmUrl = new URL('../../../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm_bg.wasm', import.meta.url);
const VAULT_SOURCE_URL = new URL('../../../src/storage/vault.js', import.meta.url);
beforeAll(async () => { await initKdf({ module_or_path: readFileSync(wasmUrl) }); });

const TEST_PROFILE = 'mobile-low-memory';
const realDeriveKek = async (pw, { salt, mKib, t, p, outLen }) => argon2id_derive(pw, salt, mKib, t, p, outLen);
const makeVault = (db, seed = 7) => createVault({
  db, deriveKek: realDeriveKek, randomBytes: seededBytes(seed), todayIso: () => '2026-10-05',
});
const PW = 'recovery-pass-1';
const PW2 = 'recovery-pass-2';

// ---------------------------------------------------------------------------------------------------
// C-REC §13 members consumed by R-UX, verbatim (fixtures filtered to kinds DISPATCH, ACTION,
// PASSWORD_REWRAP, DIAGNOSTIC and the boundaries WRAPPER-CRASH-* and RESET-INTERRUPTED).
// ---------------------------------------------------------------------------------------------------
const deepFreezeLiteral = (v) => {
  if (v !== null && typeof v === 'object') { Object.values(v).forEach(deepFreezeLiteral); Object.freeze(v); }
  return v;
};
const CREC = deepFreezeLiteral({
  "allFixtureRejects": [
    "CANDIDATE_SELECTION_FORBIDDEN",
    "CLEANUP_DEFERRED",
    "CONFIRMATION_PRECONDITION_FAILED",
    "DISCLOSURE_REQUIRED",
    "EXPLICIT_CONFIRMATION_REQUIRED",
    "FRESH_CONFIRMATION_REQUIRED",
    "LEGACY_FALLBACK_FORBIDDEN",
    "LEGACY_IMPORT_FORBIDDEN",
    "LOCKED_ELSEWHERE",
    "MARKER_TRANSITION_FORBIDDEN",
    "MISSING_DISPATCH_INPUT",
    "MUTATION_RETRY_FORBIDDEN",
    "RAW_VALUE_DIAGNOSTIC",
    "RESET_INELIGIBLE",
    "RESTORE_OUTPUT_RELEASE_FORBIDDEN",
    "RESTORE_PRECONDITION_FAILED",
    "TOKEN_MISMATCH",
    "UNKNOWN_RESULT",
    "UNREACHABLE_CONDITION_PAIR",
    "WRAPPER_AUTH_FAILED"
  ],
  "compatibleBuild": {
    "disposition": "SHOW_COMPATIBLE_BUILD",
    "preserveAndStop": true,
    "readerProfile": "CFMT_EXACT_B57DF3A8",
    "readsOrMutatesBytes": false,
    "resetEligible": false,
    "result": "INCOMPATIBLE_BUILD"
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
  "dispatchRows": [
    {
      "authority": "NONE",
      "byteAction": "PRESERVE",
      "disposition": "SHOW_CREATE",
      "legacyCondition": "UNAVAILABLE",
      "resetEligible": false,
      "result": "NO_M2_STATE"
    },
    {
      "authority": "NONE",
      "byteAction": "PRESERVE",
      "disposition": "SHOW_REESTABLISHMENT",
      "legacyCondition": "REQUIRED",
      "resetEligible": false,
      "result": "LEGACY_ONLY"
    },
    {
      "authority": "SELECTED_AUTHORITY",
      "byteAction": "PRESERVE",
      "disposition": "CONTINUE_EMPTY",
      "legacyCondition": "OPTIONAL",
      "resetEligible": false,
      "result": "RESTORED_EMPTY"
    },
    {
      "authority": "SELECTED_AUTHORITY",
      "byteAction": "PRESERVE",
      "disposition": "CONTINUE_ACTIVE",
      "legacyCondition": "OPTIONAL",
      "resetEligible": false,
      "result": "RESTORED_ACTIVE"
    },
    {
      "authority": "SELECTED_ORIGINAL_AUTHORITY",
      "byteAction": "PRESERVE",
      "disposition": "RECONCILE_ONLY",
      "legacyCondition": "OPTIONAL",
      "resetEligible": false,
      "result": "RESTORED_RECONCILIATION_REQUIRED"
    },
    {
      "authority": "NONE",
      "byteAction": "PRESERVE",
      "disposition": "LOCK_RETRY",
      "legacyCondition": "UNAVAILABLE",
      "resetEligible": false,
      "result": "LOCKED_ELSEWHERE"
    },
    {
      "authority": "NONE",
      "byteAction": "PRESERVE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyCondition": "OPTIONAL",
      "resetEligible": false,
      "result": "WRAPPER_AUTH_FAILED"
    },
    {
      "authority": "NONE",
      "byteAction": "PRESERVE",
      "disposition": "SHOW_COMPATIBLE_BUILD",
      "legacyCondition": "UNAVAILABLE",
      "resetEligible": false,
      "result": "INCOMPATIBLE_BUILD"
    },
    {
      "authority": "NONE",
      "byteAction": "PRESERVE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyCondition": "OPTIONAL",
      "resetEligible": true,
      "result": "INCOMPATIBLE_FORMAT"
    },
    {
      "authority": "NONE",
      "byteAction": "PRESERVE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyCondition": "OPTIONAL",
      "resetEligible": true,
      "result": "UNSUPPORTED_VERSION"
    },
    {
      "authority": "NONE",
      "byteAction": "PRESERVE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyCondition": "OPTIONAL",
      "resetEligible": false,
      "result": "SELECTOR_INVALID"
    },
    {
      "authority": "NONE",
      "byteAction": "PRESERVE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyCondition": "OPTIONAL",
      "resetEligible": true,
      "result": "AUTHENTICATION_FAILED"
    },
    {
      "authority": "NONE",
      "byteAction": "PRESERVE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyCondition": "OPTIONAL",
      "resetEligible": true,
      "result": "MANIFEST_INVALID"
    },
    {
      "authority": "NONE",
      "byteAction": "PRESERVE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyCondition": "OPTIONAL",
      "resetEligible": true,
      "result": "RECORD_SET_INCOMPLETE"
    },
    {
      "authority": "NONE",
      "byteAction": "PRESERVE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyCondition": "OPTIONAL",
      "resetEligible": true,
      "result": "RECORD_INVALID"
    },
    {
      "authority": "NONE",
      "byteAction": "PRESERVE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyCondition": "OPTIONAL",
      "resetEligible": true,
      "result": "REFERENCE_INCONSISTENT"
    },
    {
      "authority": "NONE",
      "byteAction": "PRESERVE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyCondition": "OPTIONAL",
      "resetEligible": false,
      "result": "PARTIAL_GENERATION"
    },
    {
      "authority": "NONE",
      "byteAction": "PRESERVE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyCondition": "OPTIONAL",
      "resetEligible": false,
      "result": "INTERNAL_VALIDATION_FAILED"
    }
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
  "fixtures": [
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "SHOW_CREATE",
          "firstFailingPhase": "NONE",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "SHOW_CREATE",
        "resetEligible": false
      },
      "id": "DISPATCH-NO_M2_STATE-NOLEGACY",
      "input": {
        "legacyPresent": false,
        "result": "NO_M2_STATE"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "SHOW_REESTABLISHMENT",
          "firstFailingPhase": "NONE",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "SHOW_REESTABLISHMENT",
        "resetEligible": false
      },
      "id": "DISPATCH-LEGACY_ONLY-LEGACY",
      "input": {
        "legacyPresent": true,
        "result": "LEGACY_ONLY"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "SELECTED_AUTHORITY",
          "disposition": "CONTINUE_EMPTY",
          "firstFailingPhase": "NONE",
          "markerState": "UNCHANGED"
        },
        "authority": "SELECTED_AUTHORITY",
        "disposition": "CONTINUE_EMPTY",
        "resetEligible": false
      },
      "id": "DISPATCH-RESTORED_EMPTY-NOLEGACY",
      "input": {
        "legacyPresent": false,
        "result": "RESTORED_EMPTY"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "SELECTED_AUTHORITY",
          "disposition": "CONTINUE_EMPTY",
          "firstFailingPhase": "NONE",
          "markerState": "UNCHANGED"
        },
        "authority": "SELECTED_AUTHORITY",
        "disposition": "CONTINUE_EMPTY",
        "resetEligible": false
      },
      "id": "DISPATCH-RESTORED_EMPTY-LEGACY",
      "input": {
        "legacyPresent": true,
        "result": "RESTORED_EMPTY"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "SELECTED_AUTHORITY",
          "disposition": "CONTINUE_ACTIVE",
          "firstFailingPhase": "NONE",
          "markerState": "UNCHANGED"
        },
        "authority": "SELECTED_AUTHORITY",
        "disposition": "CONTINUE_ACTIVE",
        "resetEligible": false
      },
      "id": "DISPATCH-RESTORED_ACTIVE-NOLEGACY",
      "input": {
        "legacyPresent": false,
        "result": "RESTORED_ACTIVE"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "SELECTED_AUTHORITY",
          "disposition": "CONTINUE_ACTIVE",
          "firstFailingPhase": "NONE",
          "markerState": "UNCHANGED"
        },
        "authority": "SELECTED_AUTHORITY",
        "disposition": "CONTINUE_ACTIVE",
        "resetEligible": false
      },
      "id": "DISPATCH-RESTORED_ACTIVE-LEGACY",
      "input": {
        "legacyPresent": true,
        "result": "RESTORED_ACTIVE"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "SELECTED_ORIGINAL_AUTHORITY",
          "disposition": "RECONCILE_ONLY",
          "firstFailingPhase": "NONE",
          "markerState": "UNCHANGED"
        },
        "authority": "SELECTED_ORIGINAL_AUTHORITY",
        "disposition": "RECONCILE_ONLY",
        "resetEligible": false
      },
      "id": "DISPATCH-RESTORED_RECONCILIATION_REQUIRED-NOLEGACY",
      "input": {
        "legacyPresent": false,
        "result": "RESTORED_RECONCILIATION_REQUIRED"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "SELECTED_ORIGINAL_AUTHORITY",
          "disposition": "RECONCILE_ONLY",
          "firstFailingPhase": "NONE",
          "markerState": "UNCHANGED"
        },
        "authority": "SELECTED_ORIGINAL_AUTHORITY",
        "disposition": "RECONCILE_ONLY",
        "resetEligible": false
      },
      "id": "DISPATCH-RESTORED_RECONCILIATION_REQUIRED-LEGACY",
      "input": {
        "legacyPresent": true,
        "result": "RESTORED_RECONCILIATION_REQUIRED"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "LOCK_RETRY",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "LOCK_RETRY",
        "resetEligible": false
      },
      "id": "DISPATCH-LOCKED_ELSEWHERE-NOLEGACY",
      "input": {
        "legacyPresent": false,
        "result": "LOCKED_ELSEWHERE"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "PRESERVE_AND_STOP",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "PRESERVE_AND_STOP",
        "resetEligible": false
      },
      "id": "DISPATCH-WRAPPER_AUTH_FAILED-NOLEGACY",
      "input": {
        "legacyPresent": false,
        "result": "WRAPPER_AUTH_FAILED"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "PRESERVE_AND_STOP",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "PRESERVE_AND_STOP",
        "resetEligible": false
      },
      "id": "DISPATCH-WRAPPER_AUTH_FAILED-LEGACY",
      "input": {
        "legacyPresent": true,
        "result": "WRAPPER_AUTH_FAILED"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "SHOW_COMPATIBLE_BUILD",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "SHOW_COMPATIBLE_BUILD",
        "resetEligible": false
      },
      "id": "DISPATCH-INCOMPATIBLE_BUILD-NOLEGACY",
      "input": {
        "legacyPresent": false,
        "result": "INCOMPATIBLE_BUILD"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "PRESERVE_AND_STOP",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "PRESERVE_AND_STOP",
        "resetEligible": true
      },
      "id": "DISPATCH-INCOMPATIBLE_FORMAT-NOLEGACY",
      "input": {
        "legacyPresent": false,
        "result": "INCOMPATIBLE_FORMAT"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "PRESERVE_AND_STOP",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "PRESERVE_AND_STOP",
        "resetEligible": true
      },
      "id": "DISPATCH-INCOMPATIBLE_FORMAT-LEGACY",
      "input": {
        "legacyPresent": true,
        "result": "INCOMPATIBLE_FORMAT"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "PRESERVE_AND_STOP",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "PRESERVE_AND_STOP",
        "resetEligible": true
      },
      "id": "DISPATCH-UNSUPPORTED_VERSION-NOLEGACY",
      "input": {
        "legacyPresent": false,
        "result": "UNSUPPORTED_VERSION"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "PRESERVE_AND_STOP",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "PRESERVE_AND_STOP",
        "resetEligible": true
      },
      "id": "DISPATCH-UNSUPPORTED_VERSION-LEGACY",
      "input": {
        "legacyPresent": true,
        "result": "UNSUPPORTED_VERSION"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "PRESERVE_AND_STOP",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "PRESERVE_AND_STOP",
        "resetEligible": false
      },
      "id": "DISPATCH-SELECTOR_INVALID-NOLEGACY",
      "input": {
        "legacyPresent": false,
        "result": "SELECTOR_INVALID"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "PRESERVE_AND_STOP",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "PRESERVE_AND_STOP",
        "resetEligible": false
      },
      "id": "DISPATCH-SELECTOR_INVALID-LEGACY",
      "input": {
        "legacyPresent": true,
        "result": "SELECTOR_INVALID"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "PRESERVE_AND_STOP",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "PRESERVE_AND_STOP",
        "resetEligible": true
      },
      "id": "DISPATCH-AUTHENTICATION_FAILED-NOLEGACY",
      "input": {
        "legacyPresent": false,
        "result": "AUTHENTICATION_FAILED"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "PRESERVE_AND_STOP",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "PRESERVE_AND_STOP",
        "resetEligible": true
      },
      "id": "DISPATCH-AUTHENTICATION_FAILED-LEGACY",
      "input": {
        "legacyPresent": true,
        "result": "AUTHENTICATION_FAILED"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "PRESERVE_AND_STOP",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "PRESERVE_AND_STOP",
        "resetEligible": true
      },
      "id": "DISPATCH-MANIFEST_INVALID-NOLEGACY",
      "input": {
        "legacyPresent": false,
        "result": "MANIFEST_INVALID"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "PRESERVE_AND_STOP",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "PRESERVE_AND_STOP",
        "resetEligible": true
      },
      "id": "DISPATCH-MANIFEST_INVALID-LEGACY",
      "input": {
        "legacyPresent": true,
        "result": "MANIFEST_INVALID"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "PRESERVE_AND_STOP",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "PRESERVE_AND_STOP",
        "resetEligible": true
      },
      "id": "DISPATCH-RECORD_SET_INCOMPLETE-NOLEGACY",
      "input": {
        "legacyPresent": false,
        "result": "RECORD_SET_INCOMPLETE"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "PRESERVE_AND_STOP",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "PRESERVE_AND_STOP",
        "resetEligible": true
      },
      "id": "DISPATCH-RECORD_SET_INCOMPLETE-LEGACY",
      "input": {
        "legacyPresent": true,
        "result": "RECORD_SET_INCOMPLETE"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "PRESERVE_AND_STOP",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "PRESERVE_AND_STOP",
        "resetEligible": true
      },
      "id": "DISPATCH-RECORD_INVALID-NOLEGACY",
      "input": {
        "legacyPresent": false,
        "result": "RECORD_INVALID"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "PRESERVE_AND_STOP",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "PRESERVE_AND_STOP",
        "resetEligible": true
      },
      "id": "DISPATCH-RECORD_INVALID-LEGACY",
      "input": {
        "legacyPresent": true,
        "result": "RECORD_INVALID"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "PRESERVE_AND_STOP",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "PRESERVE_AND_STOP",
        "resetEligible": true
      },
      "id": "DISPATCH-REFERENCE_INCONSISTENT-NOLEGACY",
      "input": {
        "legacyPresent": false,
        "result": "REFERENCE_INCONSISTENT"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "PRESERVE_AND_STOP",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "PRESERVE_AND_STOP",
        "resetEligible": true
      },
      "id": "DISPATCH-REFERENCE_INCONSISTENT-LEGACY",
      "input": {
        "legacyPresent": true,
        "result": "REFERENCE_INCONSISTENT"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "PRESERVE_AND_STOP",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "PRESERVE_AND_STOP",
        "resetEligible": false
      },
      "id": "DISPATCH-PARTIAL_GENERATION-NOLEGACY",
      "input": {
        "legacyPresent": false,
        "result": "PARTIAL_GENERATION"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "PRESERVE_AND_STOP",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "PRESERVE_AND_STOP",
        "resetEligible": false
      },
      "id": "DISPATCH-PARTIAL_GENERATION-LEGACY",
      "input": {
        "legacyPresent": true,
        "result": "PARTIAL_GENERATION"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "PRESERVE_AND_STOP",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "PRESERVE_AND_STOP",
        "resetEligible": false
      },
      "id": "DISPATCH-INTERNAL_VALIDATION_FAILED-NOLEGACY",
      "input": {
        "legacyPresent": false,
        "result": "INTERNAL_VALIDATION_FAILED"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "PRESERVE_AND_STOP",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "disposition": "PRESERVE_AND_STOP",
        "resetEligible": false
      },
      "id": "DISPATCH-INTERNAL_VALIDATION_FAILED-LEGACY",
      "input": {
        "legacyPresent": true,
        "result": "INTERNAL_VALIDATION_FAILED"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "REJECT",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "reject": "UNKNOWN_RESULT"
      },
      "id": "NEG-UNKNOWN-RESULT",
      "input": {
        "legacyPresent": false,
        "result": "UNKNOWN"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "REJECT",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "reject": "MISSING_DISPATCH_INPUT"
      },
      "id": "NEG-INCOMPLETE-DISPATCH",
      "input": {
        "result": "RESTORED_ACTIVE"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "REJECT",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "reject": "UNREACHABLE_CONDITION_PAIR"
      },
      "id": "NEG-LOCKED-LEGACY",
      "input": {
        "legacyPresent": true,
        "result": "LOCKED_ELSEWHERE"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "REJECT",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "reject": "UNREACHABLE_CONDITION_PAIR"
      },
      "id": "NEG-BUILD-LEGACY",
      "input": {
        "legacyPresent": true,
        "result": "INCOMPATIBLE_BUILD"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "REJECT",
          "firstFailingPhase": "C_REST_CLASSIFIED",
          "markerState": "UNCHANGED"
        },
        "reject": "UNREACHABLE_CONDITION_PAIR"
      },
      "id": "NEG-NO-M2-LEGACY",
      "input": {
        "legacyPresent": true,
        "result": "NO_M2_STATE"
      },
      "kind": "DISPATCH"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "UNCHANGED",
          "disposition": "REJECT",
          "firstFailingPhase": "ACTION_GATE",
          "markerState": "UNCHANGED"
        },
        "reject": "EXPLICIT_CONFIRMATION_REQUIRED"
      },
      "id": "NEG-SILENT-RESET",
      "input": {
        "action": "RESET",
        "confirmed": false,
        "lock": "HELD"
      },
      "kind": "ACTION"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "UNCHANGED",
          "disposition": "REJECT",
          "firstFailingPhase": "ACTION_GATE",
          "markerState": "UNCHANGED"
        },
        "reject": "RESET_INELIGIBLE"
      },
      "id": "NEG-RESET-WRONG-CREDENTIALS",
      "input": {
        "action": "RESET",
        "confirmed": true,
        "lock": "HELD",
        "result": "WRAPPER_AUTH_FAILED"
      },
      "kind": "ACTION"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "UNCHANGED",
          "disposition": "REJECT",
          "firstFailingPhase": "ACTION_GATE",
          "markerState": "UNCHANGED"
        },
        "reject": "RESET_INELIGIBLE"
      },
      "id": "NEG-RESET-RECONCILIATION",
      "input": {
        "action": "RESET",
        "confirmed": true,
        "lock": "HELD",
        "result": "RESTORED_RECONCILIATION_REQUIRED"
      },
      "kind": "ACTION"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "UNCHANGED",
          "disposition": "REJECT",
          "firstFailingPhase": "ACTION_GATE",
          "markerState": "UNCHANGED"
        },
        "reject": "LEGACY_FALLBACK_FORBIDDEN"
      },
      "id": "NEG-FALLBACK",
      "input": {
        "action": "LEGACY_FALLBACK"
      },
      "kind": "ACTION"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "UNCHANGED",
          "disposition": "REJECT",
          "firstFailingPhase": "ACTION_GATE",
          "markerState": "UNCHANGED"
        },
        "reject": "LEGACY_IMPORT_FORBIDDEN"
      },
      "id": "NEG-IMPORT",
      "input": {
        "action": "LEGACY_IMPORT"
      },
      "kind": "ACTION"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "UNCHANGED",
          "disposition": "REJECT",
          "firstFailingPhase": "ACTION_GATE",
          "markerState": "UNCHANGED"
        },
        "reject": "MUTATION_RETRY_FORBIDDEN"
      },
      "id": "NEG-MUTATION-RETRY",
      "input": {
        "action": "RETRY_ORIGINAL_MUTATION"
      },
      "kind": "ACTION"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "UNCHANGED",
          "disposition": "REJECT",
          "firstFailingPhase": "ACTION_GATE",
          "markerState": "UNCHANGED"
        },
        "reject": "CANDIDATE_SELECTION_FORBIDDEN"
      },
      "id": "NEG-CANDIDATE-SELECTION",
      "input": {
        "action": "USER_SELECT_CANDIDATE"
      },
      "kind": "ACTION"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "UNCHANGED",
          "disposition": "REJECT",
          "firstFailingPhase": "ACTION_GATE",
          "markerState": "UNCHANGED"
        },
        "reject": "RESTORE_OUTPUT_RELEASE_FORBIDDEN"
      },
      "id": "NEG-OUTPUT-RELEASE",
      "input": {
        "action": "RESTORE_RELEASE_ESCROW"
      },
      "kind": "ACTION"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "UNCHANGED",
          "disposition": "REJECT",
          "firstFailingPhase": "ACTION_GATE",
          "markerState": "UNCHANGED"
        },
        "reject": "CLEANUP_DEFERRED"
      },
      "id": "NEG-CLEANUP",
      "input": {
        "action": "DELETE_LEGACY"
      },
      "kind": "ACTION"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "REJECT",
          "firstFailingPhase": "DIAGNOSTIC_GATE",
          "markerState": "UNCHANGED"
        },
        "reject": "RAW_VALUE_DIAGNOSTIC"
      },
      "id": "NEG-RAW-DIAGNOSTIC",
      "input": {
        "fields": [
          "stageCode",
          "plaintext"
        ]
      },
      "kind": "DIAGNOSTIC"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "BOUNDARY_RESULT",
          "firstFailingPhase": "NONE",
          "markerState": "UNCHANGED"
        },
        "m2State": "BYTE_IDENTICAL",
        "wrapper": "OLD_VALID_WRAPPER"
      },
      "id": "WRAPPER-CRASH-BEFORE-REPLACEMENT",
      "input": {
        "boundary": "REWRAP_BEFORE_ATOMIC_REPLACEMENT"
      },
      "kind": "BOUNDARY"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "BOUNDARY_RESULT",
          "firstFailingPhase": "NONE",
          "markerState": "UNCHANGED"
        },
        "m2State": "BYTE_IDENTICAL",
        "wrapper": "NEW_VALID_WRAPPER"
      },
      "id": "WRAPPER-CRASH-AFTER-REPLACEMENT",
      "input": {
        "boundary": "REWRAP_AFTER_ATOMIC_REPLACEMENT"
      },
      "kind": "BOUNDARY"
    },
    {
      "expected": {
        "accepted": true,
        "agreement": {
          "authorityIdentity": "UNCHANGED",
          "disposition": "PASSWORD_REWRAP",
          "firstFailingPhase": "NONE",
          "markerState": "UNCHANGED"
        },
        "effect": "ATOMIC_WRAPPER_REPLACEMENT_ONLY"
      },
      "id": "REWRAP-ACTIVE-ELIGIBLE",
      "input": {
        "result": "RESTORED_ACTIVE",
        "wrapperAuthenticated": true
      },
      "kind": "PASSWORD_REWRAP"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "UNCHANGED",
          "disposition": "EXISTING_VAULT_FACILITY_UNCHANGED",
          "firstFailingPhase": "NONE",
          "markerState": "UNCHANGED"
        },
        "existingVaultFacility": "UNCHANGED_BY_C_REC",
        "m2RecoverySurface": "NOT_APPLICABLE"
      },
      "id": "REWRAP-NO-M2-EXISTING-FACILITY",
      "input": {
        "result": "NO_M2_STATE",
        "wrapperAuthenticated": false
      },
      "kind": "PASSWORD_REWRAP"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "UNCHANGED",
          "disposition": "EXISTING_VAULT_FACILITY_UNCHANGED",
          "firstFailingPhase": "NONE",
          "markerState": "UNCHANGED"
        },
        "existingVaultFacility": "UNCHANGED_BY_C_REC",
        "m2RecoverySurface": "NOT_APPLICABLE"
      },
      "id": "REWRAP-LEGACY-EXISTING-FACILITY",
      "input": {
        "result": "LEGACY_ONLY",
        "wrapperAuthenticated": false
      },
      "kind": "PASSWORD_REWRAP"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "UNCHANGED",
          "disposition": "REJECT",
          "firstFailingPhase": "WRAPPER_AUTH",
          "markerState": "UNCHANGED"
        },
        "recordOracle": false,
        "reject": "WRAPPER_AUTH_FAILED"
      },
      "id": "REWRAP-WRONG-CREDENTIAL-NO-ORACLE",
      "input": {
        "result": "RESTORED_ACTIVE",
        "wrapperAuthenticated": false
      },
      "kind": "PASSWORD_REWRAP"
    },
    {
      "expected": {
        "accepted": true,
        "agreement": {
          "authorityIdentity": "UNCHANGED",
          "disposition": "ACTION_RESULT",
          "firstFailingPhase": "NONE",
          "markerState": "UNCHANGED"
        },
        "outcome": "ATOMIC_RESET"
      },
      "id": "RESET-CONFIRMED-ELIGIBLE",
      "input": {
        "action": "RESET",
        "confirmed": true,
        "disclosure": true,
        "lock": "HELD",
        "result": "MANIFEST_INVALID",
        "token": "FRESH_BOUND_TOKEN"
      },
      "kind": "ACTION"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "LOCK_RETRY",
          "firstFailingPhase": "LOCK",
          "markerState": "UNCHANGED"
        },
        "reject": "LOCKED_ELSEWHERE"
      },
      "id": "RESET-NO-LOCK",
      "input": {
        "action": "RESET",
        "confirmed": true,
        "disclosure": true,
        "lock": "NOT_HELD",
        "result": "MANIFEST_INVALID",
        "token": "FRESH_BOUND_TOKEN"
      },
      "kind": "ACTION"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "UNCHANGED",
          "disposition": "REJECT",
          "firstFailingPhase": "ACTION_GATE",
          "markerState": "UNCHANGED"
        },
        "reject": "DISCLOSURE_REQUIRED"
      },
      "id": "RESET-NO-DISCLOSURE",
      "input": {
        "action": "RESET",
        "confirmed": true,
        "disclosure": false,
        "lock": "HELD",
        "result": "MANIFEST_INVALID",
        "token": "FRESH_BOUND_TOKEN"
      },
      "kind": "ACTION"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "UNCHANGED",
          "disposition": "REJECT",
          "firstFailingPhase": "ACTION_GATE",
          "markerState": "UNCHANGED"
        },
        "reject": "FRESH_CONFIRMATION_REQUIRED"
      },
      "id": "RESET-STALE-TOKEN",
      "input": {
        "action": "RESET",
        "confirmed": true,
        "disclosure": true,
        "lock": "HELD",
        "result": "MANIFEST_INVALID",
        "token": "STALE"
      },
      "kind": "ACTION"
    },
    {
      "expected": {
        "accepted": false,
        "agreement": {
          "authorityIdentity": "UNCHANGED",
          "disposition": "ACTION_RESULT",
          "firstFailingPhase": "NONE",
          "markerState": "UNCHANGED"
        },
        "sideEffects": "NONE"
      },
      "id": "RESET-CANCELLED",
      "input": {
        "action": "RESET_CANCEL",
        "result": "MANIFEST_INVALID"
      },
      "kind": "ACTION"
    },
    {
      "expected": {
        "agreement": {
          "authorityIdentity": "NONE",
          "disposition": "BOUNDARY_RESULT",
          "firstFailingPhase": "NONE",
          "markerState": "UNCHANGED"
        },
        "authority": "NONE",
        "automaticCompletion": false,
        "classificationSource": "NEXT_COMPLETE_C_REST_RESULT_ONLY",
        "cleanup": "NONE"
      },
      "id": "RESET-INTERRUPTED",
      "input": {
        "boundary": "DURING_RESET"
      },
      "kind": "BOUNDARY"
    }
  ],
  "legacy": {
    "cleanup": "DEFERRED",
    "decrypt": false,
    "fallback": false,
    "import": false,
    "input": "ABSTRACT_LEGACY_PRESENT_AND_BOUNDED_VALUE_FREE_COUNT",
    "physicalInventoryOwner": "L-INV",
    "preserveBytes": true,
    "selectedAuthority": false,
    "translate": false
  },
  "limits": {
    "coherentWholeProfileRollbackDetection": false,
    "freshnessClaim": false,
    "javascriptZeroizationClaim": false,
    "physicalErasureClaim": false,
    "productionReadinessClaim": false,
    "recoverySuccessClaim": false
  },
  "passwordRewrap": {
    "crashOutcomes": [
      "OLD_VALID_WRAPPER",
      "NEW_VALID_WRAPPER"
    ],
    "effect": "ATOMICALLY_REPLACE_WRAPPER_AROUND_SAME_ROOT_STORAGE_KEY",
    "eligibleResults": [
      "RESTORED_ACTIVE",
      "RESTORED_EMPTY"
    ],
    "existingVaultFacilityByInventoryResult": {
      "LEGACY_ONLY": "UNCHANGED_BY_C_REC",
      "NO_M2_STATE": "UNCHANGED_BY_C_REC"
    },
    "forbiddenResult": "RESTORED_RECONCILIATION_REQUIRED",
    "forgottenPasswordRecovery": false,
    "m2Bytes": "BYTE_IDENTICAL",
    "requiresSuccessfulWrapperAuthentication": true,
    "scope": "M2_RECOVERY_SURFACE_ONLY",
    "wrongOrForgottenCredentials": "NO_REWRAP_NO_RESET_NO_SALVAGE_NO_RECORD_ORACLE"
  },
  "precedence": {
    "ambiguousFacts": "SAFER_DISPOSITION_NO_AUTHORITY",
    "enumerationOrderAuthority": false,
    "lockedDisposition": "LOCK_RETRY",
    "requiresOneWriterLockForStateChange": true
  },
  "reachableConditionRows": [
    {
      "authority": "NONE",
      "disposition": "SHOW_CREATE",
      "legacyPresent": false,
      "resetEligible": false,
      "result": "NO_M2_STATE"
    },
    {
      "authority": "NONE",
      "disposition": "SHOW_REESTABLISHMENT",
      "legacyPresent": true,
      "resetEligible": false,
      "result": "LEGACY_ONLY"
    },
    {
      "authority": "SELECTED_AUTHORITY",
      "disposition": "CONTINUE_EMPTY",
      "legacyPresent": false,
      "resetEligible": false,
      "result": "RESTORED_EMPTY"
    },
    {
      "authority": "SELECTED_AUTHORITY",
      "disposition": "CONTINUE_EMPTY",
      "legacyPresent": true,
      "resetEligible": false,
      "result": "RESTORED_EMPTY"
    },
    {
      "authority": "SELECTED_AUTHORITY",
      "disposition": "CONTINUE_ACTIVE",
      "legacyPresent": false,
      "resetEligible": false,
      "result": "RESTORED_ACTIVE"
    },
    {
      "authority": "SELECTED_AUTHORITY",
      "disposition": "CONTINUE_ACTIVE",
      "legacyPresent": true,
      "resetEligible": false,
      "result": "RESTORED_ACTIVE"
    },
    {
      "authority": "SELECTED_ORIGINAL_AUTHORITY",
      "disposition": "RECONCILE_ONLY",
      "legacyPresent": false,
      "resetEligible": false,
      "result": "RESTORED_RECONCILIATION_REQUIRED"
    },
    {
      "authority": "SELECTED_ORIGINAL_AUTHORITY",
      "disposition": "RECONCILE_ONLY",
      "legacyPresent": true,
      "resetEligible": false,
      "result": "RESTORED_RECONCILIATION_REQUIRED"
    },
    {
      "authority": "NONE",
      "disposition": "LOCK_RETRY",
      "legacyPresent": false,
      "resetEligible": false,
      "result": "LOCKED_ELSEWHERE"
    },
    {
      "authority": "NONE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyPresent": false,
      "resetEligible": false,
      "result": "WRAPPER_AUTH_FAILED"
    },
    {
      "authority": "NONE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyPresent": true,
      "resetEligible": false,
      "result": "WRAPPER_AUTH_FAILED"
    },
    {
      "authority": "NONE",
      "disposition": "SHOW_COMPATIBLE_BUILD",
      "legacyPresent": false,
      "resetEligible": false,
      "result": "INCOMPATIBLE_BUILD"
    },
    {
      "authority": "NONE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyPresent": false,
      "resetEligible": true,
      "result": "INCOMPATIBLE_FORMAT"
    },
    {
      "authority": "NONE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyPresent": true,
      "resetEligible": true,
      "result": "INCOMPATIBLE_FORMAT"
    },
    {
      "authority": "NONE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyPresent": false,
      "resetEligible": true,
      "result": "UNSUPPORTED_VERSION"
    },
    {
      "authority": "NONE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyPresent": true,
      "resetEligible": true,
      "result": "UNSUPPORTED_VERSION"
    },
    {
      "authority": "NONE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyPresent": false,
      "resetEligible": false,
      "result": "SELECTOR_INVALID"
    },
    {
      "authority": "NONE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyPresent": true,
      "resetEligible": false,
      "result": "SELECTOR_INVALID"
    },
    {
      "authority": "NONE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyPresent": false,
      "resetEligible": true,
      "result": "AUTHENTICATION_FAILED"
    },
    {
      "authority": "NONE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyPresent": true,
      "resetEligible": true,
      "result": "AUTHENTICATION_FAILED"
    },
    {
      "authority": "NONE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyPresent": false,
      "resetEligible": true,
      "result": "MANIFEST_INVALID"
    },
    {
      "authority": "NONE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyPresent": true,
      "resetEligible": true,
      "result": "MANIFEST_INVALID"
    },
    {
      "authority": "NONE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyPresent": false,
      "resetEligible": true,
      "result": "RECORD_SET_INCOMPLETE"
    },
    {
      "authority": "NONE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyPresent": true,
      "resetEligible": true,
      "result": "RECORD_SET_INCOMPLETE"
    },
    {
      "authority": "NONE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyPresent": false,
      "resetEligible": true,
      "result": "RECORD_INVALID"
    },
    {
      "authority": "NONE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyPresent": true,
      "resetEligible": true,
      "result": "RECORD_INVALID"
    },
    {
      "authority": "NONE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyPresent": false,
      "resetEligible": true,
      "result": "REFERENCE_INCONSISTENT"
    },
    {
      "authority": "NONE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyPresent": true,
      "resetEligible": true,
      "result": "REFERENCE_INCONSISTENT"
    },
    {
      "authority": "NONE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyPresent": false,
      "resetEligible": false,
      "result": "PARTIAL_GENERATION"
    },
    {
      "authority": "NONE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyPresent": true,
      "resetEligible": false,
      "result": "PARTIAL_GENERATION"
    },
    {
      "authority": "NONE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyPresent": false,
      "resetEligible": false,
      "result": "INTERNAL_VALIDATION_FAILED"
    },
    {
      "authority": "NONE",
      "disposition": "PRESERVE_AND_STOP",
      "legacyPresent": true,
      "resetEligible": false,
      "result": "INTERNAL_VALIDATION_FAILED"
    }
  ],
  "reset": {
    "eligibleResults": [
      "AUTHENTICATION_FAILED",
      "INCOMPATIBLE_FORMAT",
      "MANIFEST_INVALID",
      "RECORD_INVALID",
      "RECORD_SET_INCOMPLETE",
      "REFERENCE_INCONSISTENT",
      "UNSUPPORTED_VERSION"
    ],
    "implementedHere": false,
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
    "interruptedClassification": "NEXT_COMPLETE_C_REST_RESULT_ONLY",
    "legacyBytes": "UNCHANGED",
    "markerState": "UNCHANGED",
    "physicalErasureClaim": false,
    "preserveDiagnosis": true,
    "requiresExplicitSeparateIrreversibleConfirmation": true,
    "requiresOneWriterLock": true,
    "valueFreeAuthorityLossDisclosureRequired": true
  },
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
  ]
});
const CREC_SUBSET_SHA256 = '9949dd3e60bae6a6c74b279d79aabc1c5d9ac29183f0941524579ed939c53c18';

const canonical = (v) => {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v !== null && typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
};
const byKind = (kind) => CREC.fixtures.filter((f) => f.kind === kind);

describe('C-REC transcription', () => {
  test('the transcribed C-REC subset is byte-pinned', () => {
    expect(createHash('sha256').update(canonical(CREC), 'utf8').digest('hex')).toBe(CREC_SUBSET_SHA256);
  });

  test('the transcription has the ratified sizes', () => {
    expect(CREC.restoreResults).toHaveLength(18);
    expect(CREC.dispatchRows).toHaveLength(18);
    expect(CREC.reachableConditionRows).toHaveLength(32);
    expect(CREC.dispositionEnum).toHaveLength(8);
    expect(byKind('DISPATCH')).toHaveLength(37);
    expect(byKind('ACTION')).toHaveLength(14);
    expect(byKind('PASSWORD_REWRAP')).toHaveLength(4);
    expect(byKind('DIAGNOSTIC')).toHaveLength(1);
    expect(byKind('BOUNDARY')).toHaveLength(3);
  });

  test('the module vocabulary equals the C-REC record', () => {
    expect(M2_RECOVERY.C_REC_DOCUMENT_SHA256).toBe('5b0d2fbd685a198e7e6e6bb10cb7740680086d27690c3cc622915e68beb94f87');
    expect([...M2_RECOVERY.RESULTS]).toEqual(CREC.restoreResults);
    expect([...M2_RECOVERY.DISPOSITIONS]).toEqual(CREC.dispositionEnum);
    expect([...M2_RECOVERY.RESET_ELIGIBLE_RESULTS].sort()).toEqual([...CREC.reset.eligibleResults].sort());
    expect([...M2_RECOVERY.RESET_INELIGIBLE_RESULTS].sort()).toEqual([...CREC.reset.ineligibleResults].sort());
    expect([...M2_RECOVERY.REWRAP_ELIGIBLE_RESULTS].sort()).toEqual([...CREC.passwordRewrap.eligibleResults].sort());
    expect([...M2_RECOVERY.REWRAP_EXISTING_FACILITY_RESULTS].sort())
      .toEqual(Object.keys(CREC.passwordRewrap.existingVaultFacilityByInventoryResult).sort());
    expect([...M2_RECOVERY.DIAGNOSTIC_ALLOWED]).toEqual(CREC.diagnostics.allowed);
    expect([...M2_RECOVERY.DIAGNOSTIC_FORBIDDEN]).toEqual(CREC.diagnostics.forbidden);
    expect(M2_RECOVERY.LOCKED_DISPOSITION).toBe(CREC.precedence.lockedDisposition);
    expect(M2_RECOVERY.REQUIRES_ONE_WRITER_LOCK_FOR_STATE_CHANGE).toBe(CREC.precedence.requiresOneWriterLockForStateChange);
    expect(M2_RECOVERY.RESET_LEGACY_BYTES).toBe(CREC.reset.legacyBytes);
    expect(M2_RECOVERY.RESET_MARKER_STATE).toBe(CREC.reset.markerState);
    expect(M2_RECOVERY.PHYSICAL_ERASURE_CLAIM).toBe(CREC.reset.physicalErasureClaim);
    expect(M2_RECOVERY.PHYSICAL_ERASURE_CLAIM).toBe(CREC.limits.physicalErasureClaim);
    expect(M2_RECOVERY.FRESHNESS_CLAIM).toBe(CREC.limits.freshnessClaim);
    expect(M2_RECOVERY.RECOVERY_SUCCESS_CLAIM).toBe(CREC.limits.recoverySuccessClaim);
    expect(M2_RECOVERY.FORGOTTEN_PASSWORD_RECOVERY).toBe(CREC.passwordRewrap.forgottenPasswordRecovery);
    expect(M2_RECOVERY.LEGACY_IMPORT).toBe(CREC.legacy.import);
    expect(M2_RECOVERY.LEGACY_FALLBACK).toBe(CREC.legacy.fallback);
    expect(M2_RECOVERY.CLEANUP).toBe(CREC.legacy.cleanup);
    expect(M2_RECOVERY.RESET_DISCLOSURE.interruptedClassification).toBe(CREC.reset.interruptedClassification);
    expect(M2_RECOVERY.RESET_AUTOMATIC).toBe(false);
    expect(M2_RECOVERY.RESET_PRESERVE_DIAGNOSIS).toBe(CREC.reset.preserveDiagnosis);
    expect(M2_RECOVERY.VAULT_UNLOCK_FAULTS).toHaveLength(8);
    expect(Object.isFrozen(M2_RECOVERY) && Object.isFrozen(M2_RECOVERY.RESULTS)
      && Object.isFrozen(M2_RECOVERY.RESET_DISCLOSURE)).toBe(true);
  });

  test('every reject code the surface can return is a ratified C-REC reject value', () => {
    const ratified = new Set(CREC.allFixtureRejects);
    for (const f of CREC.fixtures) if (f.expected.reject) expect(ratified.has(f.expected.reject)).toBe(true);
    for (const code of M2_RECOVERY.REJECT_CODES) expect(ratified.has(code)).toBe(true);
  });
});

// ---------------------------------------------------------------------------------------------------
// Dispatch (C-REC §3, §10)
// ---------------------------------------------------------------------------------------------------
describe('C-REC DISPATCH fixtures replay', () => {
  for (const f of byKind('DISPATCH')) {
    test(f.id, () => {
      expect(dispatchRecovery(f.input)).toEqual(f.expected);
    });
  }

  test('the 18 dispatch rows and the 32 reachable condition rows are reproduced exactly', () => {
    const reachable = [];
    for (const result of CREC.restoreResults) {
      for (const legacyPresent of [false, true]) {
        const d = dispatchRecovery({ result, legacyPresent });
        if (d.reject === undefined) {
          reachable.push({ authority: d.authority, disposition: d.disposition, legacyPresent, resetEligible: d.resetEligible, result });
        } else {
          expect(d.reject).toBe('UNREACHABLE_CONDITION_PAIR');
        }
      }
    }
    const key = (r) => canonical(r);
    expect(reachable.map(key).sort()).toEqual(CREC.reachableConditionRows.map(key).sort());
    for (const row of CREC.dispatchRows) {
      const legacyPresent = row.legacyCondition === 'REQUIRED';
      const d = dispatchRecovery({ result: row.result, legacyPresent });
      expect([d.disposition, d.authority, d.resetEligible, row.byteAction])
        .toEqual([row.disposition, row.authority, row.resetEligible, M2_RECOVERY.BYTE_ACTION]);
    }
  });

  test('malformed, extended or hostile dispatch inputs reject without throwing', () => {
    const hostile = new Proxy({ result: 'RESTORED_ACTIVE', legacyPresent: false }, {
      ownKeys() { throw new Error('trap'); },
    });
    const accessor = { legacyPresent: false };
    Object.defineProperty(accessor, 'result', { enumerable: true, get() { throw new Error('getter'); } });
    for (const input of [undefined, null, 1, 'RESTORED_ACTIVE', [], hostile, accessor,
      { result: 'RESTORED_ACTIVE', legacyPresent: false, extra: 1 },
      { result: 'RESTORED_ACTIVE', legacyPresent: 'false' },
      Object.assign(Object.create({ evil: 1 }), { result: 'RESTORED_ACTIVE', legacyPresent: false })]) {
      const d = dispatchRecovery(input);
      expect(d.reject).toBe('MISSING_DISPATCH_INPUT');
      expect(d.agreement.disposition).toBe('REJECT');
    }
  });

  test('generated inputs: no unknown result is ever dispatched to an authority', () => {
    fc.assert(fc.property(fc.string(), fc.boolean(), (result, legacyPresent) => {
      const d = dispatchRecovery({ result, legacyPresent });
      if (CREC.restoreResults.includes(result)) return d.reject === undefined || d.reject === 'UNREACHABLE_CONDITION_PAIR';
      return d.reject === 'UNKNOWN_RESULT' && d.agreement.authorityIdentity === 'NONE';
    }), { numRuns: 500 });
  });

  test('the dispatch is order-independent (enumeration order has no authority)', () => {
    for (const result of CREC.restoreResults) {
      const a = dispatchRecovery({ result, legacyPresent: true });
      const b = dispatchRecovery({ legacyPresent: true, result });
      expect(a).toEqual(b);
    }
  });
});

// ---------------------------------------------------------------------------------------------------
// ACTION, PASSWORD_REWRAP, DIAGNOSTIC, BOUNDARY fixtures (C-REC §5, §6, §7, §8, §9)
// ---------------------------------------------------------------------------------------------------
describe('C-REC ACTION fixtures replay', () => {
  for (const f of byKind('ACTION')) {
    test(f.id, () => {
      expect(decideRecoveryAction(f.input)).toEqual(f.expected);
    });
  }

  test('an unknown or malformed action is a TypeError, never an acceptance', () => {
    for (const input of [null, {}, { action: 'RESET_ALL' }, { action: 'RESET', unknown: true }, [{ action: 'RESET' }]]) {
      expect(() => decideRecoveryAction(input)).toThrow(TypeError);
    }
  });

  // An independently structured oracle of C-REC §7/§8: a table of predicates checked in the ratified
  // phase order (LOCK, then ACTION_GATE members in fixture order).
  const ORACLE_GATES = [
    ['lock', (i) => i.lock === 'HELD', 'LOCKED_ELSEWHERE', 'LOCK'],
    ['confirmed', (i) => i.confirmed === true, 'EXPLICIT_CONFIRMATION_REQUIRED', 'ACTION_GATE'],
    ['result', (i) => CREC.reset.eligibleResults.includes(i.result), 'RESET_INELIGIBLE', 'ACTION_GATE'],
    ['disclosure', (i) => i.disclosure === true, 'DISCLOSURE_REQUIRED', 'ACTION_GATE'],
    ['token', (i) => i.token === 'FRESH_BOUND_TOKEN', 'FRESH_CONFIRMATION_REQUIRED', 'ACTION_GATE'],
  ];
  const oracle = (i) => {
    const failed = ORACLE_GATES.find(([, ok]) => !ok(i));
    if (failed === undefined) return { accepted: true, outcome: 'ATOMIC_RESET' };
    return { reject: failed[2], phase: failed[3] };
  };

  test('generated RESET inputs agree with the independent oracle (gate order, no early acceptance)', () => {
    const arb = fc.record({
      action: fc.constant('RESET'),
      result: fc.constantFrom(...CREC.restoreResults, 'UNKNOWN', ''),
      confirmed: fc.constantFrom(true, false, 'true', 1),
      lock: fc.constantFrom('HELD', 'NOT_HELD', 'held', null),
      token: fc.constantFrom('FRESH_BOUND_TOKEN', 'STALE', ''),
      disclosure: fc.constantFrom(true, false, 'yes'),
    }, { requiredKeys: ['action'] });
    fc.assert(fc.property(arb, (input) => {
      const got = decideRecoveryAction(input);
      const want = oracle(input);
      if (want.accepted) return got.accepted === true && got.outcome === 'ATOMIC_RESET';
      if (got.reject !== want.reject || got.agreement.firstFailingPhase !== want.phase) return false;
      // A non-holder learns only LOCKED_ELSEWHERE / LOCK_RETRY (C-REC §8).
      if (want.reject === 'LOCKED_ELSEWHERE') {
        return Object.keys(got).sort().join() === 'agreement,reject' && got.agreement.disposition === 'LOCK_RETRY';
      }
      return true;
    }), { numRuns: 2000 });
  });

  test('every reset-ineligible result is refused even when every other gate passes', () => {
    for (const result of CREC.reset.ineligibleResults) {
      expect(decideRecoveryAction({
        action: 'RESET', result, confirmed: true, lock: 'HELD', token: 'FRESH_BOUND_TOKEN', disclosure: true,
      }).reject).toBe('RESET_INELIGIBLE');
    }
  });
});

describe('C-REC PASSWORD_REWRAP fixtures replay', () => {
  for (const f of byKind('PASSWORD_REWRAP')) {
    test(f.id, () => {
      expect(decidePasswordRewrap(f.input)).toEqual(f.expected);
    });
  }

  test('re-wrap is unavailable during reconciliation and for every failure result', () => {
    for (const result of CREC.restoreResults) {
      if (['RESTORED_ACTIVE', 'RESTORED_EMPTY', 'NO_M2_STATE', 'LEGACY_ONLY'].includes(result)) continue;
      const d = decidePasswordRewrap({ result, wrapperAuthenticated: true });
      expect(d.reject).toBe('RESTORE_PRECONDITION_FAILED');
      expect(d.accepted).toBeUndefined();
    }
    expect(CREC.passwordRewrap.forbiddenResult).toBe('RESTORED_RECONCILIATION_REQUIRED');
  });

  test('a non-holder of the lock learns only LOCKED_ELSEWHERE', () => {
    for (const result of CREC.restoreResults) {
      const d = decidePasswordRewrap({ result, wrapperAuthenticated: true, lock: 'NOT_HELD' });
      expect(d).toEqual({ reject: 'LOCKED_ELSEWHERE', agreement: { disposition: 'LOCK_RETRY', authorityIdentity: 'NONE', markerState: 'UNCHANGED', firstFailingPhase: 'LOCK' } });
    }
  });
});

describe('C-REC DIAGNOSTIC fixture and the value-free diagnostic gate', () => {
  for (const f of byKind('DIAGNOSTIC')) {
    test(f.id, () => {
      expect(decideRecoveryDiagnostic(f.input)).toEqual(f.expected);
    });
  }

  test('each allowlisted field is accepted and each forbidden field is refused', () => {
    expect(decideRecoveryDiagnostic({ fields: [...CREC.diagnostics.allowed] }).accepted).toBe(true);
    for (const field of CREC.diagnostics.forbidden) {
      expect(decideRecoveryDiagnostic({ fields: ['stageCode', field] }).reject).toBe('RAW_VALUE_DIAGNOSTIC');
    }
    for (const bad of [null, {}, { fields: 'stageCode' }, { fields: ['stageCode', 'stageCode'] },
      { fields: [1] }, { fields: [...CREC.diagnostics.allowed, 'reasonCode'] }]) {
      expect(decideRecoveryDiagnostic(bad).reject).toBe('RAW_VALUE_DIAGNOSTIC');
    }
  });

  test('generated field lists are accepted iff every field is allowlisted and distinct', () => {
    fc.assert(fc.property(fc.array(fc.oneof(fc.constantFrom(...CREC.diagnostics.allowed, ...CREC.diagnostics.forbidden), fc.string()), { maxLength: 8 }), (fields) => {
      const ok = fields.length <= 6 && new Set(fields).size === fields.length
        && fields.every((f) => CREC.diagnostics.allowed.includes(f));
      return (decideRecoveryDiagnostic({ fields }).accepted === true) === ok;
    }), { numRuns: 1000 });
  });
});

describe('C-REC BOUNDARY fixtures (re-wrap and reset)', () => {
  for (const f of byKind('BOUNDARY')) {
    test(f.id, () => {
      expect(recoveryBoundary(f.input.boundary)).toEqual(f.expected);
    });
  }
  test('an unknown boundary has no fact', () => {
    expect(recoveryBoundary('AFTER_MARKER_COMMIT')).toBeNull();
  });
});

describe('closed user-visible guidance (C-REC §9)', () => {
  test('every disposition and the two action families have distinct it-IT guidance', () => {
    const keys = [...CREC.dispositionEnum, 'PASSWORD_REWRAP', 'RESET'];
    const texts = keys.map((k) => recoveryGuidance(k));
    for (const t of texts) expect(typeof t === 'string' && t.length > 0).toBe(true);
    expect(new Set(texts).size).toBe(texts.length);
    expect(recoveryGuidance('UNKNOWN')).toBeNull();
    expect(recoveryGuidance('__proto__')).toBeNull();
  });

  test('restored authority, re-establishment, compatible-build handoff and reset are worded apart', () => {
    expect(recoveryGuidance('CONTINUE_ACTIVE')).toMatch(/ripristinata/);
    expect(recoveryGuidance('SHOW_REESTABLISHMENT')).toMatch(/nuova sessione/);
    expect(recoveryGuidance('SHOW_REESTABLISHMENT')).toMatch(/non viene convertita né importata/);
    expect(recoveryGuidance('SHOW_COMPATIBLE_BUILD')).toMatch(/CFMT_EXACT_B57DF3A8/);
    expect(CREC.compatibleBuild.readerProfile).toBe('CFMT_EXACT_B57DF3A8');
    expect(recoveryGuidance('RESET')).toMatch(/irreversibile/);
    expect(recoveryGuidance('RESET')).toMatch(/Non è un recupero/);
    expect(recoveryGuidance('RESET_NO_ERASURE')).toMatch(/non garantisce la cancellazione fisica/);
    expect(recoveryGuidance('SHOW_CREATE')).toMatch(/non attesta/);
  });

  test('no guidance claims prior absence, recoverability, erasure or freshness (C-REC §9, §11)', () => {
    const keys = [...CREC.dispositionEnum, 'PASSWORD_REWRAP', 'RESET', 'RESET_NO_ERASURE'];
    for (const k of keys) {
      const t = recoveryGuidance(k);
      expect(t).not.toMatch(/nessun dato precedente|da recuperare|è stato cancellat|sono stati cancellat|aggiornat[oa] all'ultim/);
    }
    expect(recoveryGuidance('CONTINUE_EMPTY')).toBe('Archivio ripristinato senza sessione M2 attiva.');
  });
});

// ---------------------------------------------------------------------------------------------------
// Vault methods over the storage double: best-effort reset and recovery re-wrap
// ---------------------------------------------------------------------------------------------------

// A VaultDb double that records every storage call made through it, including transaction entry and
// every operation (read or write) performed inside a transaction callback.
function tracedDb(db = new FakeVaultDb()) {
  const calls = [];
  const traced = {
    get version() { return db.version; },
    get: async (ns, key) => { calls.push(['get', ns, key]); return db.get(ns, key); },
    list: async (ns) => { calls.push(['list', ns]); return db.list(ns); },
    transaction: async (namespaces, cb) => {
      calls.push(['transaction', ...namespaces]);
      return db.transaction(namespaces, (ops) => cb({
        ...ops,
        get: (ns, key) => { calls.push(['tx-get', ns, key]); return ops.get(ns, key); },
        list: (ns) => { calls.push(['tx-list', ns]); return ops.list(ns); },
        put: (ns, key, value) => { calls.push(['put', ns, key, value === null ? null : 'value']); return ops.put(ns, key, value); },
        delete: (ns, key) => { calls.push(['delete', ns, key]); return ops.delete(ns, key); },
      }));
    },
    destroy: async () => { calls.push(['destroy']); return db.destroy(); },
  };
  return { db, traced, calls };
}
const snapshotStores = (db) => deepClone(Object.fromEntries([...db.stores].map(([ns, m]) => [ns, Object.fromEntries(m)])));

// Legacy bytes and the L-MARK marker live outside the vault database (localStorage legacy envelope;
// marker persisted by its caller). They are modelled here as caller-held bytes that the vault never sees.
function outsideBytes() {
  const legacy = new Map([['styx:mls:legacy-envelope', new TextEncoder().encode('{"v":1,"legacy":"opaque"}')]]);
  const marker = encodeMarker({ state: M2_LEGACY_INVALIDATION.STATES[1], bindingToken: new Uint8Array(32).fill(9) });
  const snap = () => ({ legacy: [...legacy].map(([k, v]) => [k, [...v]]), marker: [...marker] });
  return { snap };
}

async function unlockedVault() {
  const t = tracedDb();
  const v = makeVault(t.traced);
  await v.createVault(PW, { profile: TEST_PROFILE });
  await v.putRecord('canary', 'r1', { n: 1 });
  t.calls.length = 0;
  return { ...t, v };
}

const NOT_VALUE_FREE = /Uint8Array|rootKey|wrappedRootKey|kek|salt|ciphertext|hmac|nonce/i;
const assertValueFree = (decision) => {
  const json = JSON.stringify(decision, (k, v) => (v instanceof Uint8Array ? 'Uint8Array' : v));
  expect(json).not.toMatch(NOT_VALUE_FREE);
  expect(json).not.toContain(PW);
  expect(json).not.toContain(PW2);
};

describe('best-effort destructive reset through the vault', () => {
  test('confirmed eligible reset: disclosure, then keys → wrapper → database, legacy and marker untouched', async () => {
    const { v, db, calls } = await unlockedVault();
    const outside = outsideBytes();
    const before = outside.snap();
    const begun = await v.beginRecoveryReset({ restoreResult: 'MANIFEST_INVALID', lockHeld: true });
    expect(begun.disclosure).toEqual(M2_RECOVERY.RESET_DISCLOSURE);
    expect(begun.disclosure.physicalErasureClaim).toBe(false);
    expect(begun.disclosure.legacyBytes).toBe('UNCHANGED');
    expect(begun.disclosure.markerState).toBe('UNCHANGED');
    expect(calls).toEqual([]); // the disclosure reads and writes nothing
    assertValueFree(begun.disclosure);
    const done = await v.confirmRecoveryReset({
      restoreResult: 'MANIFEST_INVALID', lockHeld: true, confirmed: true, disclosure: true, confirmation: begun.confirmation,
    });
    expect(done).toEqual({ ...CREC.fixtures.find((f) => f.id === 'RESET-CONFIRMED-ELIGIBLE').expected, state: VAULT_STATES.UNINITIALIZED });
    expect(calls).toEqual([['transaction', 'meta'], ['put', 'meta', 'wrapper', null], ['destroy']]);
    expect(db.destroyed).toBe(1);
    expect(outside.snap()).toEqual(before);
    assertValueFree(done);
  });

  test.each(CREC.reset.eligibleResults)('every eligible result %s can be reset with a fresh confirmation', async (result) => {
    const { v, db } = await unlockedVault();
    const begun = await v.beginRecoveryReset({ restoreResult: result, lockHeld: true });
    const done = await v.confirmRecoveryReset({ restoreResult: result, lockHeld: true, confirmed: true, disclosure: true, confirmation: begun.confirmation });
    expect(done.outcome).toBe('ATOMIC_RESET');
    expect(db.destroyed).toBe(1);
  });

  test.each(CREC.reset.ineligibleResults)('ineligible %s: refused at begin and at confirm, no storage access', async (result) => {
    const { v, db, calls } = await unlockedVault();
    const before = snapshotStores(db);
    const begun = await v.beginRecoveryReset({ restoreResult: result, lockHeld: true });
    expect(begun.reject).toBe('RESET_INELIGIBLE');
    expect(begun.confirmation).toBeUndefined();
    const done = await v.confirmRecoveryReset({ restoreResult: result, lockHeld: true, confirmed: true, disclosure: true, confirmation: {} });
    expect(done.reject).toBe('RESET_INELIGIBLE');
    expect(calls).toEqual([]);
    expect(snapshotStores(db)).toEqual(before);
    expect((await v.status()).state).toBe(VAULT_STATES.UNLOCKED);
  });

  test('lock contention: a non-holder learns only LOCKED_ELSEWHERE, at begin and at confirm', async () => {
    const { v, db, calls } = await unlockedVault();
    const before = snapshotStores(db);
    const begun = await v.beginRecoveryReset({ restoreResult: 'MANIFEST_INVALID', lockHeld: false });
    const lockRow = CREC.fixtures.find((f) => f.id === 'RESET-NO-LOCK').expected;
    expect(begun).toEqual(lockRow);
    const ok = await v.beginRecoveryReset({ restoreResult: 'MANIFEST_INVALID', lockHeld: true });
    const done = await v.confirmRecoveryReset({ restoreResult: 'MANIFEST_INVALID', lockHeld: false, confirmed: true, disclosure: true, confirmation: ok.confirmation });
    expect(done).toEqual(lockRow);
    expect(calls).toEqual([]);
    expect(snapshotStores(db)).toEqual(before);
  });

  test('unconfirmed, undisclosed, stale, reused, rebound and cancelled confirmations never reset', async () => {
    const { v, db, calls } = await unlockedVault();
    const before = snapshotStores(db);
    const R = 'RECORD_INVALID';
    const attempt = (over) => v.confirmRecoveryReset({ restoreResult: R, lockHeld: true, confirmed: true, disclosure: true, ...over });

    let b = await v.beginRecoveryReset({ restoreResult: R, lockHeld: true });
    expect((await attempt({ confirmation: b.confirmation, confirmed: false })).reject).toBe('EXPLICIT_CONFIRMATION_REQUIRED');
    // The handle is single-use, whatever the decision.
    expect((await attempt({ confirmation: b.confirmation })).reject).toBe('FRESH_CONFIRMATION_REQUIRED');

    b = await v.beginRecoveryReset({ restoreResult: R, lockHeld: true });
    expect((await attempt({ confirmation: b.confirmation, disclosure: false })).reject).toBe('DISCLOSURE_REQUIRED');

    expect((await attempt({ confirmation: Object.freeze(Object.create(null)) })).reject).toBe('FRESH_CONFIRMATION_REQUIRED');

    b = await v.beginRecoveryReset({ restoreResult: R, lockHeld: true });
    const b2 = await v.beginRecoveryReset({ restoreResult: R, lockHeld: true });
    expect((await attempt({ confirmation: b.confirmation })).reject).toBe('FRESH_CONFIRMATION_REQUIRED');
    expect(b2.confirmation).not.toBe(b.confirmation);

    b = await v.beginRecoveryReset({ restoreResult: R, lockHeld: true });
    expect((await attempt({ confirmation: b.confirmation, restoreResult: 'MANIFEST_INVALID' })).reject).toBe('FRESH_CONFIRMATION_REQUIRED');

    b = await v.beginRecoveryReset({ restoreResult: R, lockHeld: true });
    expect(await v.cancelRecoveryReset()).toEqual(CREC.fixtures.find((f) => f.id === 'RESET-CANCELLED').expected);
    expect((await attempt({ confirmation: b.confirmation })).reject).toBe('FRESH_CONFIRMATION_REQUIRED');

    expect(calls).toEqual([]);
    expect(snapshotStores(db)).toEqual(before);
    expect(db.destroyed).toBe(0);
  });

  test('a confirmation does not survive lock/unlock (bound to one unlocked session)', async () => {
    const { v, db } = await unlockedVault();
    const b = await v.beginRecoveryReset({ restoreResult: 'MANIFEST_INVALID', lockHeld: true });
    await v.lock();
    await v.unlock(PW);
    const done = await v.confirmRecoveryReset({ restoreResult: 'MANIFEST_INVALID', lockHeld: true, confirmed: true, disclosure: true, confirmation: b.confirmation });
    expect(done.reject).toBe('FRESH_CONFIRMATION_REQUIRED');
    expect(db.destroyed).toBe(0);
  });

  test('a locked or uninitialized vault cannot present an eligible M2 failure', async () => {
    const { v, db } = await unlockedVault();
    await v.lock();
    expect((await v.beginRecoveryReset({ restoreResult: 'MANIFEST_INVALID', lockHeld: true })).reject).toBe('RESET_INELIGIBLE');
    const fresh = makeVault(new FakeVaultDb());
    expect((await fresh.beginRecoveryReset({ restoreResult: 'MANIFEST_INVALID', lockHeld: true })).reject).toBe('RESET_INELIGIBLE');
    expect(db.destroyed).toBe(0);
  });

  test('interrupted reset: closed INTERRUPTED outcome, no automatic completion, classified by the next C-REST run', async () => {
    const { v, db } = await unlockedVault();
    db.destroy = async () => { throw new Error('tab killed during delete'); };
    const b = await v.beginRecoveryReset({ restoreResult: 'MANIFEST_INVALID', lockHeld: true });
    const done = await v.confirmRecoveryReset({ restoreResult: 'MANIFEST_INVALID', lockHeld: true, confirmed: true, disclosure: true, confirmation: b.confirmation });
    expect(done).toEqual({ accepted: false, outcome: 'INTERRUPTED', boundary: CREC.fixtures.find((f) => f.id === 'RESET-INTERRUPTED').expected });
    // The wrapper was already overwritten (keys → wrapper → data order), so no authority remains.
    expect(db.wrapper()).toBeNull();
    // No automatic completion: a retry needs a new, explicit, fresh confirmation.
    const retry = await v.confirmRecoveryReset({ restoreResult: 'MANIFEST_INVALID', lockHeld: true, confirmed: true, disclosure: true, confirmation: b.confirmation });
    expect(retry.accepted).not.toBe(true);
    // The next load classifies from storage only; it exposes no authority.
    const next = makeVault(db);
    expect((await next.status()).state).toBe(VAULT_STATES.UNINITIALIZED);
    assertValueFree(done);
  });

  test('the existing factory reset (destroy) is unchanged: available from any state, ungated', async () => {
    const { v, db } = await unlockedVault();
    await v.lock();
    expect((await v.destroy()).state).toBe(VAULT_STATES.UNINITIALIZED);
    expect(db.destroyed).toBe(1);
  });

  test('malformed reset inputs are TypeErrors and touch nothing', async () => {
    const { v, calls } = await unlockedVault();
    for (const bad of [null, {}, { restoreResult: 'MANIFEST_INVALID', lockHeld: 'yes' }, { restoreResult: 'MANIFEST_INVALID', lockHeld: true, extra: 1 }]) {
      await expect(v.beginRecoveryReset(bad)).rejects.toThrow(TypeError);
      await expect(v.confirmRecoveryReset(bad)).rejects.toThrow(TypeError);
    }
    expect(calls).toEqual([]);
  });

  test('every confirm call consumes the open handle, a malformed one included', async () => {
    const { v, db, calls } = await unlockedVault();
    for (const bad of [null, {}, { restoreResult: 'MANIFEST_INVALID', lockHeld: 'yes' }]) {
      const begun = await v.beginRecoveryReset({ restoreResult: 'MANIFEST_INVALID', lockHeld: true });
      await expect(v.confirmRecoveryReset(bad)).rejects.toThrow(TypeError);
      const later = await v.confirmRecoveryReset({
        restoreResult: 'MANIFEST_INVALID', lockHeld: true, confirmed: true, disclosure: true, confirmation: begun.confirmation,
      });
      expect(later.reject).toBe('FRESH_CONFIRMATION_REQUIRED');
    }
    expect(calls).toEqual([]);
    expect(db.destroyed).toBe(0);
  });

  test('confirm on a vault locked after begin is RESET_INELIGIBLE and touches nothing', async () => {
    const { v, db, calls } = await unlockedVault();
    const begun = await v.beginRecoveryReset({ restoreResult: 'MANIFEST_INVALID', lockHeld: true });
    await v.lock();
    calls.length = 0;
    const out = await v.confirmRecoveryReset({
      restoreResult: 'MANIFEST_INVALID', lockHeld: true, confirmed: true, disclosure: true, confirmation: begun.confirmation,
    });
    expect(out.reject).toBe('RESET_INELIGIBLE');
    expect(calls).toEqual([]);
    expect(db.destroyed).toBe(0);
  });

  test('the reset paths never touch page storage (legacy envelope, marker) or open another database', async () => {
    const touched = [];
    const sentinel = (name) => new Proxy({}, { get: (_t, k) => { touched.push([name, String(k)]); return () => undefined; } });
    const saved = ['localStorage', 'sessionStorage', 'indexedDB'].map((k) => [k, Object.getOwnPropertyDescriptor(globalThis, k)]);
    for (const [k] of saved) Object.defineProperty(globalThis, k, { configurable: true, get: () => sentinel(k) });
    try {
      const { v, db } = await unlockedVault();
      await v.beginRecoveryReset({ restoreResult: 'RESTORED_ACTIVE', lockHeld: true }); // refused
      await v.beginRecoveryReset({ restoreResult: 'MANIFEST_INVALID', lockHeld: true });
      await v.cancelRecoveryReset();
      const begun = await v.beginRecoveryReset({ restoreResult: 'MANIFEST_INVALID', lockHeld: true });
      await v.confirmRecoveryReset({ restoreResult: 'MANIFEST_INVALID', lockHeld: true, confirmed: true, disclosure: true, confirmation: begun.confirmation });
      expect(db.destroyed).toBe(1);
    } finally {
      for (const [k, d] of saved) {
        if (d === undefined) delete globalThis[k]; else Object.defineProperty(globalThis, k, d);
      }
    }
    expect(touched).toEqual([]);
  });
});

// A database that already holds a wrapper (optionally with an orphan `rewrapPending`, or corrupt),
// opened by a vault instance that has never been loaded in this session.
async function freshInstanceOver(kind) {
  const seed = new FakeVaultDb();
  await makeVault(seed).createVault(PW, { profile: TEST_PROFILE });
  const wrapper = deepClone(seed.wrapper());
  const t = tracedDb();
  const stored = kind === 'corrupt' ? { corrupt: true }
    : kind === 'pending' ? { ...deepClone(wrapper), rewrapPending: deepClone(wrapper) } : wrapper;
  await t.db.transaction(['meta'], (ops) => ops.put('meta', 'wrapper', stored));
  const before = snapshotStores(t.db);
  return { ...t, v: makeVault(t.traced), before };
}

describe('the recovery methods never load the vault: a fresh instance refuses from memory', () => {
  const CASES = [
    ['beginRecoveryReset', { restoreResult: 'MANIFEST_INVALID', lockHeld: false }, 'LOCKED_ELSEWHERE'],
    ['beginRecoveryReset', { restoreResult: 'MANIFEST_INVALID', lockHeld: true }, 'RESET_INELIGIBLE'],
    ['beginRecoveryReset', { restoreResult: 'RESTORED_RECONCILIATION_REQUIRED', lockHeld: true }, 'RESET_INELIGIBLE'],
    ['confirmRecoveryReset', { restoreResult: 'MANIFEST_INVALID', lockHeld: false, confirmed: true, disclosure: true, confirmation: {} }, 'LOCKED_ELSEWHERE'],
    ['confirmRecoveryReset', { restoreResult: 'MANIFEST_INVALID', lockHeld: true, confirmed: true, disclosure: true, confirmation: {} }, 'RESET_INELIGIBLE'],
    ['recoveryChangePassword', { restoreResult: 'RESTORED_ACTIVE', lockHeld: false, currentPassword: PW, newPassword: PW2 }, 'LOCKED_ELSEWHERE'],
    ['recoveryChangePassword', { restoreResult: 'RESTORED_RECONCILIATION_REQUIRED', lockHeld: true, currentPassword: PW, newPassword: PW2 }, 'RESTORE_PRECONDITION_FAILED'],
    ['recoveryChangePassword', { restoreResult: 'NO_M2_STATE', lockHeld: true, currentPassword: PW, newPassword: PW2 }, 'EXISTING_VAULT_FACILITY_UNCHANGED'],
    ['recoveryChangePassword', { restoreResult: 'RESTORED_ACTIVE', lockHeld: true, currentPassword: PW, newPassword: PW2 }, 'WRAPPER_AUTH_FAILED'],
  ];
  const outcomeOf = (out) => out.reject ?? out.agreement?.disposition;
  for (const kind of ['valid', 'pending', 'corrupt']) {
    test.each(CASES)(`${kind} stored wrapper: %s %j → %s, no storage read or write`, async (method, input, expected) => {
      const { v, db, calls, before } = await freshInstanceOver(kind);
      const out = await v[method](input);
      expect(outcomeOf(out)).toBe(expected);
      expect(calls).toEqual([]);
      expect(snapshotStores(db)).toEqual(before);
      expect(db.destroyed).toBe(0);
    });
  }

  test('an existing method still loads as before (and clears an orphan rewrapPending)', async () => {
    const { v, db, calls } = await freshInstanceOver('pending');
    expect((await v.status()).state).toBe(VAULT_STATES.LOCKED);
    expect(calls.length).toBeGreaterThan(0);
    expect(db.wrapper().rewrapPending ?? null).toBeNull();
  });
});

describe('recovery password re-wrap through the vault (C-REC §5)', () => {
  test.each(['RESTORED_ACTIVE', 'RESTORED_EMPTY'])('%s + authenticated: new password unlocks, records byte-identical', async (result) => {
    const { v, db } = await unlockedVault();
    const records = deepClone(Object.fromEntries(db.stores.get('canary')));
    const rootBefore = db.wrapper().wrappedRootKey;
    const out = await v.recoveryChangePassword({ restoreResult: result, lockHeld: true, currentPassword: PW, newPassword: PW2, profile: TEST_PROFILE });
    expect(out).toEqual({ ...CREC.fixtures.find((f) => f.id === 'REWRAP-ACTIVE-ELIGIBLE').expected, state: VAULT_STATES.UNLOCKED });
    expect(Object.fromEntries(db.stores.get('canary'))).toEqual(records);
    expect(db.wrapper().wrappedRootKey).not.toBe(rootBefore);
    const reopened = makeVault(db);
    await expect(reopened.unlock(PW)).rejects.toMatchObject({ code: Codes.WRONG_PASSWORD });
    await reopened.unlock(PW2);
    expect(await reopened.getRecord('canary', 'r1')).toEqual(await v.getRecord('canary', 'r1'));
    assertValueFree(out);
  });

  test('wrong current password: WRAPPER_AUTH_FAILED, no re-wrap, no reset, no record oracle', async () => {
    const { v, db, calls } = await unlockedVault();
    const before = snapshotStores(db);
    const out = await v.recoveryChangePassword({ restoreResult: 'RESTORED_ACTIVE', lockHeld: true, currentPassword: 'not-the-password', newPassword: PW2, profile: TEST_PROFILE });
    expect(out).toEqual(CREC.fixtures.find((f) => f.id === 'REWRAP-WRONG-CREDENTIAL-NO-ORACLE').expected);
    expect(snapshotStores(db)).toEqual(before);
    expect(db.destroyed).toBe(0);
    // Only the public wrapper form is read: no record, no manifest.
    expect(calls).toEqual([['get', 'meta', 'wrapper']]);
    assertValueFree(out);
  });

  test('wrong-password result is identical for a malformed and a well-formed wrong password', async () => {
    const { v } = await unlockedVault();
    const a = await v.recoveryChangePassword({ restoreResult: 'RESTORED_ACTIVE', lockHeld: true, currentPassword: 'x', newPassword: PW2 });
    const b = await v.recoveryChangePassword({ restoreResult: 'RESTORED_ACTIVE', lockHeld: true, currentPassword: 'wrong-but-long', newPassword: PW2 });
    expect(a).toEqual(b);
  });

  test.each(CREC.restoreResults.filter((r) => !['RESTORED_ACTIVE', 'RESTORED_EMPTY', 'NO_M2_STATE', 'LEGACY_ONLY'].includes(r)))(
    '%s: re-wrap refused before any storage access', async (result) => {
      const { v, db, calls } = await unlockedVault();
      const before = snapshotStores(db);
      const out = await v.recoveryChangePassword({ restoreResult: result, lockHeld: true, currentPassword: PW, newPassword: PW2 });
      expect(out.reject).toBe('RESTORE_PRECONDITION_FAILED');
      expect(calls).toEqual([]);
      expect(snapshotStores(db)).toEqual(before);
    },
  );

  test.each(['NO_M2_STATE', 'LEGACY_ONLY'])('%s: the M2 surface is not applicable; the existing facility is unchanged', async (result) => {
    const { v, db, calls } = await unlockedVault();
    const before = snapshotStores(db);
    const out = await v.recoveryChangePassword({ restoreResult: result, lockHeld: true, currentPassword: PW, newPassword: PW2 });
    expect(out).toEqual(CREC.fixtures.find((f) => f.id === (result === 'NO_M2_STATE' ? 'REWRAP-NO-M2-EXISTING-FACILITY' : 'REWRAP-LEGACY-EXISTING-FACILITY')).expected);
    expect(calls).toEqual([]);
    expect(snapshotStores(db)).toEqual(before);
    await v.changePassword(PW2, { profile: TEST_PROFILE }); // the existing facility still works as before
    await v.lock();
    await v.unlock(PW2);
  });

  test('lock contention: a non-holder learns only LOCKED_ELSEWHERE and nothing is read', async () => {
    const { v, calls } = await unlockedVault();
    const out = await v.recoveryChangePassword({ restoreResult: 'RESTORED_ACTIVE', lockHeld: false, currentPassword: PW, newPassword: PW2 });
    expect(Object.keys(out).sort()).toEqual(['agreement', 'reject']);
    expect(out.reject).toBe('LOCKED_ELSEWHERE');
    expect(out.agreement.disposition).toBe('LOCK_RETRY');
    expect(calls).toEqual([]);
  });

  test('a locked vault cannot re-wrap on the recovery surface (no credential oracle while locked)', async () => {
    const { v, db } = await unlockedVault();
    await v.lock();
    const before = snapshotStores(db);
    const out = await v.recoveryChangePassword({ restoreResult: 'RESTORED_ACTIVE', lockHeld: true, currentPassword: PW, newPassword: PW2 });
    expect(out.reject).toBe('WRAPPER_AUTH_FAILED');
    expect(snapshotStores(db)).toEqual(before);
  });

  test('crash before the atomic replacement: the old wrapper stays valid, M2 bytes identical', async () => {
    const { v, db } = await unlockedVault();
    const records = deepClone(Object.fromEntries(db.stores.get('canary')));
    db.failOn = (ns, key, value) => key === 'manifest' && value?.generation === 3; // the commit write
    await expect(v.recoveryChangePassword({ restoreResult: 'RESTORED_ACTIVE', lockHeld: true, currentPassword: PW, newPassword: PW2, profile: TEST_PROFILE })).rejects.toThrow();
    db.failOn = null;
    expect(recoveryBoundary('REWRAP_BEFORE_ATOMIC_REPLACEMENT').wrapper).toBe('OLD_VALID_WRAPPER');
    const reopened = makeVault(db);
    await reopened.unlock(PW);
    expect(Object.fromEntries(db.stores.get('canary'))).toEqual(records);
  });

  test('crash after the atomic replacement: the new wrapper is valid, M2 bytes identical', async () => {
    const { v, db } = await unlockedVault();
    const records = deepClone(Object.fromEntries(db.stores.get('canary')));
    await v.recoveryChangePassword({ restoreResult: 'RESTORED_EMPTY', lockHeld: true, currentPassword: PW, newPassword: PW2, profile: TEST_PROFILE });
    // The process dies right after the commit: a fresh instance sees only the new wrapper.
    expect(recoveryBoundary('REWRAP_AFTER_ATOMIC_REPLACEMENT').wrapper).toBe('NEW_VALID_WRAPPER');
    const reopened = makeVault(db);
    await reopened.unlock(PW2);
    expect(Object.fromEntries(db.stores.get('canary'))).toEqual(records);
  });

  test('a policy-invalid new password is refused by the existing policy after authentication', async () => {
    const { v, db } = await unlockedVault();
    const before = snapshotStores(db);
    await expect(v.recoveryChangePassword({ restoreResult: 'RESTORED_ACTIVE', lockHeld: true, currentPassword: PW, newPassword: 'short' }))
      .rejects.toBeInstanceOf(VaultCryptoError);
    expect(snapshotStores(db)).toEqual(before);
  });
});

describe('static boundaries of the recovery section', () => {
  const src = readFileSync(VAULT_SOURCE_URL, 'utf8');
  const section = src.slice(src.indexOf('// M2 recovery and reset actions (card R-UX'));
  const methods = src.slice(src.indexOf('    async beginRecoveryReset('), src.indexOf('    /** State + non-sensitive markers.'));

  test('the recovery section performs no I/O, clock, randomness or legacy access of its own', () => {
    expect(section.length).toBeGreaterThan(1000);
    expect(methods.length).toBeGreaterThan(1000);
    for (const forbidden of ['localStorage', 'sessionStorage', 'indexedDB', 'fetch(', 'Date', 'Math.random',
      'postMessage', 'navigator', 'import(', 'legacy-session-invalidation', 'legacy-session-inventory', 'console.']) {
      expect(section).not.toContain(forbidden);
      expect(methods).not.toContain(forbidden);
    }
  });

  test('the four recovery methods never load the vault; the only storage access is the authenticated re-wrap read and destroy()', () => {
    expect(methods).not.toContain('ensureLoaded');
    expect(methods.match(/\bdb\.[a-zA-Z]+\(/g)).toEqual(['db.get(']);
    expect(methods.match(/\bapi\.[a-zA-Z]+\(/g)).toEqual(['api.destroy(']);
  });

  test('vault.js imports nothing new (no legacy, marker, adapter or worker module)', () => {
    const imports = src.match(/^import [\s\S]*?from '([^']+)';/gm).map((l) => l.match(/from '([^']+)'/)[1]);
    expect(imports.sort()).toEqual([
      '../crypto/kdf-bounds.js', '../crypto/vault-aad.js', '../crypto/vault-errors.js', '../crypto/vault-keys.js',
      '../crypto/vault-shape.js', '../utils.js', './vault-migration.js', './vault-record.js', './vault-wrapper.js',
    ]);
  });
});

// ---------------------------------------------------------------------------------------------------
// R-WIRE (#317): vault-level unlock failures → C-REST fault, and the three R-UX notes.
//
// Owner interpretation (#317 comment 6022947656, Q1 = A): `WRAPPER_AUTH` completes only when
// `vault.unlock()` completes, so `VAULT_MANIFEST_TAMPERED` (including `schema-downgrade`) after a
// successful unwrap is `wrapperWrongOrInvalid`: reset-ineligible, its only reset the existing
// `destroy()`. Every other rejection that is not wrapper/container evidence maps to `null`.
// ---------------------------------------------------------------------------------------------------

const EXPECTED_UNLOCK_FAULT_ROWS = [
  { code: 'VAULT_WRONG_PASSWORD', detail: 'ANY', fault: 'wrapperWrongOrInvalid' },
  { code: 'VAULT_WRAPPER_INVALID', detail: 'ANY', fault: 'wrapperWrongOrInvalid' },
  { code: 'VAULT_WRAPPER_UNSUPPORTED', detail: 'ANY', fault: 'wrapperWrongOrInvalid' },
  { code: 'VAULT_KEY_VERSION_UNSUPPORTED', detail: 'ANY', fault: 'wrapperWrongOrInvalid' },
  { code: 'VAULT_KDF_PARAMS_INVALID', detail: 'FIELD', fault: 'wrapperWrongOrInvalid' },
  { code: 'VAULT_KDF_PARAMS_INVALID', detail: 'REASON_EXCEPT:password-length', fault: 'wrapperWrongOrInvalid' },
  { code: 'VAULT_MANIFEST_TAMPERED', detail: 'NO_REASON', fault: 'wrapperWrongOrInvalid' },
  { code: 'VAULT_MANIFEST_TAMPERED', detail: 'REASON:schema-downgrade', fault: 'wrapperWrongOrInvalid' },
];
const WRAPPER_FAULT = 'wrapperWrongOrInvalid';
const isDeepFrozen = (v) => v === null || typeof v !== 'object'
  || (Object.isFrozen(v) && Object.values(v).every(isDeepFrozen));

// The rejection of exactly one unlock() call (never a resolution).
const unlockRejection = async (v, password) => {
  try {
    await v.unlock(password);
  } catch (e) {
    return e;
  }
  throw new Error('unlock unexpectedly resolved');
};
const stateAfter = async (v) => {
  try { return (await v.status()).state; } catch (e) { return e; }
};

// A locked vault over a traced FakeVaultDb, with the same instance kept for the reset checks.
async function lockedTracedVault(db = new FakeVaultDb()) {
  const t = tracedDb(db);
  const v = makeVault(t.traced);
  await v.createVault(PW, { profile: TEST_PROFILE });
  await v.lock();
  t.calls.length = 0;
  return { ...t, v };
}

// W2 trigger: flip one byte of the stored manifest HMAC (canonical base64 kept).
const flipManifestHmac = (db) => {
  const m = db.manifest();
  const bytes = Buffer.from(m.hmacB64, 'base64');
  bytes[0] ^= 0x01;
  m.hmacB64 = bytes.toString('base64');
};

// W3 trigger (rollback only: not reachable by a normal older-build open, which fails at INIT with
// VersionError): a vault created at database version 2, its stores copied into a version-1 database.
async function rolledBackVault() {
  const newer = new FakeVaultDb({ version: 2 });
  const creator = makeVault(newer);
  await creator.createVault(PW, { profile: TEST_PROFILE });
  await creator.lock();
  const older = new FakeVaultDb({ version: 1 });
  older.stores = new Map([...newer.stores].map(([ns, m]) => [ns, new Map([...m].map(([k, val]) => [k, deepClone(val)]))]));
  const t = tracedDb(older);
  return { ...t, v: makeVault(t.traced) };
}

// The test's reference wiring (not exported, not product code): a fault is fed to the merged C-REST
// classifier only after LOCK, BUILD_ELIGIBILITY and INVENTORY = M2 passed (F1). The vector and selector
// state are SYNTHETIC: a real run that stops at WRAPPER_AUTH has none (open product-wiring obligation).
const referenceWiring = (error, legacy) => {
  const fault = vaultUnlockRestoreFault(error);
  if (fault === null) return { observation: null, outcome: null, dispatch: null };
  const observation = { faults: [fault], inventory: 'M2', legacy, vector: 'FMT-KAT-ACTIVE', selectorState: 'ACTIVE' };
  const outcome = classifyRestore(observation);
  return { observation, outcome, dispatch: dispatchRecovery({ result: outcome.result, legacyPresent: legacy }) };
};

const assertWrapperAuthChain = (err) => {
  expect(vaultUnlockRestoreFault(err)).toBe(WRAPPER_FAULT);
  for (const legacy of [false, true]) {
    const { outcome, dispatch } = referenceWiring(err, legacy);
    expect(outcome.result).toBe('WRAPPER_AUTH_FAILED');
    expect(outcome.stage).toBe('WRAPPER_AUTH');
    expect(outcome.exposed).toBe(false);
    expect(dispatch.disposition).toBe('PRESERVE_AND_STOP');
    expect(dispatch.authority).toBe('NONE');
    expect(dispatch.resetEligible).toBe(false);
  }
};

// W4: on the same LOCKED instance, every M2 reset and re-wrap path refuses with zero storage access.
async function assertResetRefusedWithoutStorage({ v, calls, db }) {
  calls.length = 0;
  const before = snapshotStores(db);
  for (const result of ['WRAPPER_AUTH_FAILED', ...CREC.reset.eligibleResults]) {
    const begun = await v.beginRecoveryReset({ restoreResult: result, lockHeld: true });
    expect(begun.reject).toBe('RESET_INELIGIBLE');
    expect(begun.confirmation).toBeUndefined();
    const held = await v.confirmRecoveryReset({ restoreResult: result, lockHeld: true, confirmed: true, disclosure: true, confirmation: {} });
    expect(held.reject).toBe('RESET_INELIGIBLE');
    const notHeld = await v.confirmRecoveryReset({ restoreResult: result, lockHeld: false, confirmed: true, disclosure: true, confirmation: {} });
    expect(notHeld.reject).toBe('LOCKED_ELSEWHERE');
  }
  await expect(v.confirmRecoveryReset({ restoreResult: 'WRAPPER_AUTH_FAILED', lockHeld: 'yes' })).rejects.toThrow(TypeError);
  const rewrap = await v.recoveryChangePassword({ restoreResult: 'WRAPPER_AUTH_FAILED', lockHeld: true, currentPassword: PW, newPassword: PW2, profile: TEST_PROFILE });
  expect(rewrap.reject).toBe('RESTORE_PRECONDITION_FAILED');
  const forged = await v.recoveryChangePassword({ restoreResult: 'RESTORED_ACTIVE', lockHeld: true, currentPassword: PW, newPassword: PW2, profile: TEST_PROFILE });
  expect(forged.reject).toBe('WRAPPER_AUTH_FAILED');
  expect(calls).toEqual([]);
  expect(snapshotStores(db)).toEqual(before);
  expect(db.destroyed).toBe(0);
}

async function assertDestroyStillResets({ v, db }) {
  const outside = outsideBytes();
  const before = outside.snap();
  expect((await v.destroy()).state).toBe(VAULT_STATES.UNINITIALIZED);
  expect(db.destroyed).toBe(1);
  expect(db.wrapper()).toBeUndefined();
  expect(outside.snap()).toEqual(before);
}

describe('R-WIRE W1: the vault-unlock fault table', () => {
  test('VAULT_UNLOCK_FAULTS is the closed eight-row allowlist, deep-frozen, over ratified C-REST faults', () => {
    expect(JSON.parse(JSON.stringify(M2_RECOVERY.VAULT_UNLOCK_FAULTS))).toEqual(EXPECTED_UNLOCK_FAULT_ROWS);
    expect(isDeepFrozen(M2_RECOVERY.VAULT_UNLOCK_FAULTS)).toBe(true);
    const ratifiedFaults = new Set(FAULT_PRECEDENCE.map((row) => row.fault));
    for (const row of M2_RECOVERY.VAULT_UNLOCK_FAULTS) {
      expect(Object.keys(row).sort()).toEqual(['code', 'detail', 'fault']);
      expect(ratifiedFaults.has(row.fault)).toBe(true);
      expect(row.fault).not.toBe('unexpectedValidatorCondition');
      expect(Object.values(Codes)).toContain(row.code);
    }
  });
});

describe('R-WIRE W2/W3/W4/W5/W8: vault-container failures after a successful unwrap', () => {
  test('W2: a tampered manifest HMAC → VAULT_MANIFEST_TAMPERED, LOCKED, wrapperWrongOrInvalid → WRAPPER_AUTH_FAILED (synthetic composition)', async () => {
    const t = await lockedTracedVault();
    flipManifestHmac(t.db);
    const err = await unlockRejection(t.v, PW);
    expect(err).toBeInstanceOf(VaultCryptoError);
    expect(err.code).toBe(Codes.MANIFEST_TAMPERED);
    expect(err.details).toBeUndefined();
    expect(await stateAfter(t.v)).toBe(VAULT_STATES.LOCKED);
    assertWrapperAuthChain(err);
    await assertResetRefusedWithoutStorage(t);
    await assertDestroyStillResets(t);
  });

  test('W3: a rolled-back database below the signed schema marker (rollback only) → schema-downgrade → wrapperWrongOrInvalid', async () => {
    const t = await rolledBackVault();
    const err = await unlockRejection(t.v, PW);
    expect(err).toBeInstanceOf(VaultCryptoError);
    expect(err.code).toBe(Codes.MANIFEST_TAMPERED);
    expect(err.details).toEqual({ reason: 'schema-downgrade' });
    expect(await stateAfter(t.v)).toBe(VAULT_STATES.LOCKED);
    assertWrapperAuthChain(err);
    await assertResetRefusedWithoutStorage(t);
    await assertDestroyStillResets(t);
  });

  test('W8: NEG-RESET-WRONG-CREDENTIALS replays from the W2 trigger', async () => {
    const t = await lockedTracedVault();
    flipManifestHmac(t.db);
    const err = await unlockRejection(t.v, PW);
    const { outcome } = referenceWiring(err, false);
    const f = CREC.fixtures.find((x) => x.id === 'NEG-RESET-WRONG-CREDENTIALS');
    expect(f.input.result).toBe(outcome.result);
    expect(decideRecoveryAction({ ...f.input, result: outcome.result })).toEqual(f.expected);
  });
});

// A VaultDb wrapper that throws a chosen error at one storage point; the support file is unchanged.
function faultingDb(db, { getFail = null, putFail = null } = {}) {
  return {
    get version() { return db.version; },
    get: async (ns, key) => {
      if (getFail && getFail.when(ns, key)) { getFail.count = (getFail.count ?? 0) + 1; if (getFail.count >= (getFail.nth ?? 1)) throw getFail.error(); }
      return db.get(ns, key);
    },
    list: async (ns) => db.list(ns),
    transaction: async (namespaces, cb) => db.transaction(namespaces, (ops) => cb({
      ...ops,
      put: (ns, key, value) => { if (putFail && putFail.when(ns, key, value)) throw putFail.error(); return ops.put(ns, key, value); },
    })),
    destroy: async () => db.destroy(),
  };
}

const freshLockedDb = async ({ version = 1 } = {}) => {
  const db = new FakeVaultDb({ version });
  const v = makeVault(db);
  await v.createVault(PW, { profile: TEST_PROFILE });
  await v.lock();
  return db;
};
const loadedVault = async (db) => {
  const v = makeVault(db);
  expect((await v.status()).state).toBe(VAULT_STATES.LOCKED);
  return v;
};

describe('R-WIRE W6: every other row and the null set, through a real unlock()', () => {
  test('row 1: wrong password', async () => {
    const v = await loadedVault(await freshLockedDb());
    const err = await unlockRejection(v, 'wrong-password-1');
    expect(err.code).toBe(Codes.WRONG_PASSWORD);
    expect(vaultUnlockRestoreFault(err)).toBe(WRAPPER_FAULT);
    expect(await stateAfter(v)).toBe(VAULT_STATES.LOCKED);
  });

  test('row 2: a corrupted wrapper at load (ERROR)', async () => {
    const db = await freshLockedDb();
    db.wrapper().format = 'not-a-wrapper';
    const v = makeVault(db);
    const err = await unlockRejection(v, PW);
    expect(err.code).toBe(Codes.WRAPPER_INVALID);
    expect(vaultUnlockRestoreFault(err)).toBe(WRAPPER_FAULT);
    // the load failed closed into ERROR; status() re-raises the same load rejection
    expect(await stateAfter(v)).toBe(err);
  });

  test('row 3: a version-2 wrapper', async () => {
    const db = await freshLockedDb();
    db.wrapper().version = 2;
    const err = await unlockRejection(makeVault(db), PW);
    expect(err.code).toBe(Codes.WRAPPER_UNSUPPORTED);
    expect(vaultUnlockRestoreFault(err)).toBe(WRAPPER_FAULT);
  });

  test('row 4: a keyVersion-2 wrapper, at a fresh load and at unlock\'s second parse', async () => {
    const db = await freshLockedDb();
    db.wrapper().keyVersion = 2;
    const atLoad = await unlockRejection(makeVault(db), PW);
    expect(atLoad.code).toBe(Codes.KEY_VERSION_UNSUPPORTED);
    expect(vaultUnlockRestoreFault(atLoad)).toBe(WRAPPER_FAULT);

    const db2 = await freshLockedDb();
    const v = await loadedVault(db2);
    db2.wrapper().keyVersion = 2;
    const atUnlock = await unlockRejection(v, PW);
    expect(atUnlock.code).toBe(Codes.KEY_VERSION_UNSUPPORTED);
    expect(vaultUnlockRestoreFault(atUnlock)).toBe(WRAPPER_FAULT);
    expect(await stateAfter(v)).toBe(VAULT_STATES.LOCKED);
  });

  test('row 5: a non-canonical saltB64', async () => {
    const db = await freshLockedDb();
    const v = await loadedVault(db);
    db.wrapper().saltB64 = ` ${db.wrapper().saltB64}`;
    const err = await unlockRejection(v, PW);
    expect(err.code).toBe(Codes.KDF_PARAMS_INVALID);
    expect(err.details).toEqual({ field: 'saltB64' });
    expect(vaultUnlockRestoreFault(err)).toBe(WRAPPER_FAULT);
    expect(await stateAfter(v)).toBe(VAULT_STATES.LOCKED);
  });

  test('row 6: stored KDF parameters rejected by policy', async () => {
    const db = await freshLockedDb();
    const v = await loadedVault(db);
    db.wrapper().mKib = 1;
    const err = await unlockRejection(v, PW);
    expect(err.code).toBe(Codes.KDF_PARAMS_INVALID);
    expect(typeof err.details.reason).toBe('string');
    expect(err.details.reason).not.toBe('password-length');
    expect(vaultUnlockRestoreFault(err)).toBe(WRAPPER_FAULT);
    expect(await stateAfter(v)).toBe(VAULT_STATES.LOCKED);
  });

  test('null: caller preconditions (unlock from UNLOCKED; a short password)', async () => {
    const { v } = await unlockedVault();
    const twice = await unlockRejection(v, PW);
    expect(twice.code).toBe(Codes.WRONG_STATE);
    expect(twice.details.reason).toBe('state:UNLOCKED');
    expect(vaultUnlockRestoreFault(twice)).toBeNull();
    expect(await stateAfter(v)).toBe(VAULT_STATES.UNLOCKED);

    const locked = await loadedVault(await freshLockedDb());
    const short = await unlockRejection(locked, 'short');
    expect(short.code).toBe(Codes.KDF_PARAMS_INVALID);
    expect(short.details).toEqual({ reason: 'password-length' });
    expect(vaultUnlockRestoreFault(short)).toBeNull();
    expect(await stateAfter(locked)).toBe(VAULT_STATES.LOCKED);
  });

  const nativeError = () => new Error('injected storage interruption');
  const typedAbort = () => new VaultCryptoError(Codes.TX_ABORTED, 'transaction aborted');

  test.each([['native Error', nativeError], ['typed VAULT_TX_ABORTED', typedAbort]])('null: interruptions (%s) at every injected point, with the resulting state', async (_label, error) => {
    // (a) the load() wrapper read: the load rejects; status() re-raises it.
    {
      const db = await freshLockedDb();
      const v = makeVault(faultingDb(db, { getFail: { when: (ns, key) => key === 'wrapper', error } }));
      const err = await unlockRejection(v, PW);
      expect(vaultUnlockRestoreFault(err)).toBeNull();
      expect(await stateAfter(v)).toBe(err);
    }
    // (b) the orphan-pending cleanup write (state RECOVERING when it throws; the load rejection persists).
    {
      const db = await freshLockedDb();
      const w = db.wrapper();
      w.rewrapPending = { ...deepClone(w), rewrapPending: null };
      const v = makeVault(faultingDb(db, { putFail: { when: (ns, key) => key === 'wrapper', error } }));
      const err = await unlockRejection(v, PW);
      expect(vaultUnlockRestoreFault(err)).toBeNull();
      expect(await stateAfter(v)).toBe(err);
    }
    // (c) unlock's second wrapper read, outside unlock's try: the instance is left UNLOCKING.
    {
      const db = await freshLockedDb();
      const spec = { when: (ns, key) => key === 'wrapper', nth: 2, error };
      const v = makeVault(faultingDb(db, { getFail: spec }));
      const err = await unlockRejection(v, PW);
      expect(vaultUnlockRestoreFault(err)).toBeNull();
      expect(await stateAfter(v)).toBe(VAULT_STATES.UNLOCKING);
    }
    // (d) the manifest read, inside unlock's try: LOCKED.
    {
      const db = await freshLockedDb();
      const v = makeVault(faultingDb(db, { getFail: { when: (ns, key) => key === 'manifest', error } }));
      const err = await unlockRejection(v, PW);
      expect(vaultUnlockRestoreFault(err)).toBeNull();
      expect(await stateAfter(v)).toBe(VAULT_STATES.LOCKED);
    }
    // (e) the high-water reconcile write (database ahead of the signed marker): LOCKED.
    {
      const db = await freshLockedDb();
      db.version = 2;
      const v = makeVault(faultingDb(db, { putFail: { when: (ns, key) => key === 'manifest', error } }));
      const err = await unlockRejection(v, PW);
      expect(vaultUnlockRestoreFault(err)).toBeNull();
      expect(await stateAfter(v)).toBe(VAULT_STATES.LOCKED);
    }
  });

  test('null: an injected deriveKek failure (VAULT_CRYPTO_FAILED; a KdfBoundsError), LOCKED', async () => {
    for (const error of [new VaultCryptoError(Codes.CRYPTO_FAILED, 'kek derivation failed'), new KdfBoundsError('memory cost below the OWASP floor')]) {
      const db = await freshLockedDb();
      const v = createVault({ db, deriveKek: async () => { throw error; }, randomBytes: seededBytes(7), todayIso: () => '2026-10-05' });
      const err = await unlockRejection(v, PW);
      expect(err).toBe(error);
      expect(vaultUnlockRestoreFault(err)).toBeNull();
      expect(await stateAfter(v)).toBe(VAULT_STATES.LOCKED);
    }
  });
});

describe('R-WIRE W7: vaultUnlockRestoreFault is total and never invokes an accessor', () => {
  test('arbitrary values never throw and give null', () => {
    fc.assert(fc.property(fc.anything({ withObjectString: true, withNullPrototype: true }), (x) => {
      const r = vaultUnlockRestoreFault(x);
      return r === null;
    }), { numRuns: 2000 });
  });

  test('generated VaultCryptoErrors map exactly by the table', () => {
    const codes = Object.values(Codes);
    const detailArb = fc.option(fc.record({
      reason: fc.constantFrom('schema-downgrade', 'password-length', 'session-ended', 'state:LOCKED', 'other'),
      field: fc.constantFrom('saltB64', 'keyVersion', 'version'),
    }, { requiredKeys: [] }), { nil: undefined });
    fc.assert(fc.property(fc.constantFrom(...codes), detailArb, (code, details) => {
      const err = new VaultCryptoError(code, 'generated', details);
      const reason = details && Object.hasOwn(details, 'reason') ? details.reason : undefined;
      const field = details && Object.hasOwn(details, 'field') ? details.field : undefined;
      let expected = null;
      if (['VAULT_WRONG_PASSWORD', 'VAULT_WRAPPER_INVALID', 'VAULT_WRAPPER_UNSUPPORTED', 'VAULT_KEY_VERSION_UNSUPPORTED'].includes(code)) expected = WRAPPER_FAULT;
      if (code === 'VAULT_KDF_PARAMS_INVALID' && (field !== undefined || (reason !== undefined && reason !== 'password-length'))) expected = WRAPPER_FAULT;
      if (code === 'VAULT_MANIFEST_TAMPERED' && (reason === undefined || reason === 'schema-downgrade')) expected = WRAPPER_FAULT;
      return vaultUnlockRestoreFault(err) === expected;
    }), { numRuns: 2000 });
  });

  test('fixed hostile and look-alike cases are null, with no accessor invoked', () => {
    let touched = 0;
    const spy = () => { touched += 1; return 'VAULT_MANIFEST_TAMPERED'; };
    const cases = [];
    cases.push({ code: 'VAULT_MANIFEST_TAMPERED' });
    cases.push(Object.assign(new Error('x'), { code: 'VAULT_WRONG_PASSWORD' }));
    const accessorCode = new VaultCryptoError(Codes.WRONG_PASSWORD, 'x');
    Object.defineProperty(accessorCode, 'code', { get: spy });
    cases.push(accessorCode);
    const accessorDetails = new VaultCryptoError(Codes.MANIFEST_TAMPERED, 'x');
    Object.defineProperty(accessorDetails, 'details', { get: () => { touched += 1; return undefined; } });
    cases.push(accessorDetails);
    const accessorReason = new VaultCryptoError(Codes.MANIFEST_TAMPERED, 'x');
    Object.defineProperty(accessorReason, 'details', { value: Object.defineProperty({}, 'reason', { get: () => { touched += 1; return 'schema-downgrade'; }, enumerable: true }) });
    cases.push(accessorReason);
    const accessorField = new VaultCryptoError(Codes.KDF_PARAMS_INVALID, 'x');
    Object.defineProperty(accessorField, 'details', { value: Object.defineProperty({}, 'field', { get: () => { touched += 1; return 'saltB64'; }, enumerable: true }) });
    cases.push(accessorField);
    cases.push(new VaultCryptoError(Codes.MANIFEST_TAMPERED, 'x', { reason: 'future-reason' }));
    cases.push(new VaultCryptoError(Codes.WRONG_STATE, 'x', { reason: 'session-ended' }));
    cases.push(new VaultCryptoError(Codes.OPEN_FAILED, 'x', { reason: 'VersionError' }));
    const mutated = new VaultCryptoError(Codes.WRONG_PASSWORD, 'x');
    mutated.code = 'VAULT_SOMETHING_ELSE';
    cases.push(mutated);
    const nonPlainDetails = new VaultCryptoError(Codes.MANIFEST_TAMPERED, 'x');
    Object.defineProperty(nonPlainDetails, 'details', { value: Object.create({ reason: 'schema-downgrade' }) });
    cases.push(nonPlainDetails);
    const { proxy: revoked, revoke } = Proxy.revocable(new VaultCryptoError(Codes.WRONG_PASSWORD, 'x'), {});
    revoke();
    cases.push(revoked);
    cases.push(new Proxy(new VaultCryptoError(Codes.WRONG_PASSWORD, 'x'), { getPrototypeOf() { throw new Error('trap'); } }));
    cases.push(new Proxy(new VaultCryptoError(Codes.WRONG_PASSWORD, 'x'), { getOwnPropertyDescriptor() { throw new Error('trap'); } }));
    cases.push(new KdfBoundsError('memory cost below the OWASP floor'));
    for (const c of cases) {
      expect(() => vaultUnlockRestoreFault(c)).not.toThrow();
      expect(vaultUnlockRestoreFault(c)).toBeNull();
    }
    expect(touched).toBe(0);
  });
});

describe('R-WIRE W9/W10: the wiring precondition and the consuming boundary', () => {
  test('W9: the fault outside inventory M2 is never WRAPPER_AUTH_FAILED; earlier phases keep precedence', () => {
    for (const [inventory, legacy] of [['NONE', false], ['LEGACY_ONLY', true]]) {
      const out = classifyRestore({ faults: [WRAPPER_FAULT], inventory, legacy, vector: null, selectorState: 'ACTIVE' });
      expect(out.result).toBe('INTERNAL_VALIDATION_FAILED');
      expect(out.stage).toBe('CLASSIFY');
    }
    const expectedEarlier = { lockUnavailable: 'LOCKED_ELSEWHERE', buildNotListed: 'INCOMPATIBLE_BUILD', inventoryAmbiguous: 'INTERNAL_VALIDATION_FAILED' };
    for (const [earlier, result] of Object.entries(expectedEarlier)) {
      const out = classifyRestore({ faults: [WRAPPER_FAULT, earlier], inventory: 'M2', legacy: false, vector: 'FMT-KAT-ACTIVE', selectorState: 'ACTIVE' });
      expect(out.result).toBe(result);
      expect(out.stage).toBe(FAULT_PRECEDENCE.find((r) => r.fault === earlier).phase);
    }
  });

  test('W10: a null mapping forms no observation, no dispatch and never a RESTORED_* result', () => {
    const nullCases = [
      new VaultCryptoError(Codes.WRONG_STATE, 'x', { reason: 'state:UNLOCKED' }),
      new VaultCryptoError(Codes.WRONG_STATE, 'x', { reason: 'session-ended' }),
      new VaultCryptoError(Codes.KDF_PARAMS_INVALID, 'x', { reason: 'password-length' }),
      new VaultCryptoError(Codes.TX_ABORTED, 'x'),
      new VaultCryptoError(Codes.QUOTA_EXCEEDED, 'x'),
      new VaultCryptoError(Codes.BLOCKED, 'x'),
      new VaultCryptoError(Codes.OPEN_FAILED, 'x'),
      new VaultCryptoError(Codes.SCHEMA_GAP, 'x'),
      new VaultCryptoError(Codes.CRYPTO_FAILED, 'x'),
      new VaultCryptoError(Codes.MANIFEST_TAMPERED, 'x', { reason: 'future-reason' }),
      new Error('native'), new KdfBoundsError('x'), null, undefined, {}, 'VAULT_WRONG_PASSWORD',
    ];
    for (const legacy of [false, true]) {
      for (const err of nullCases) {
        const wired = referenceWiring(err, legacy);
        expect(wired).toEqual({ observation: null, outcome: null, dispatch: null });
      }
    }
    // every non-null mapping, by construction, is a non-RESTORED, non-reset-eligible result
    for (const row of M2_RECOVERY.VAULT_UNLOCK_FAULTS) {
      const err = new VaultCryptoError(row.code, 'x', row.detail === 'FIELD' ? { field: 'saltB64' }
        : row.detail.startsWith('REASON_EXCEPT:') ? { reason: 'memory cost below the OWASP floor' }
          : row.detail.startsWith('REASON:') ? { reason: row.detail.slice(7) } : undefined);
      const wired = referenceWiring(err, false);
      expect(wired.outcome.result.startsWith('RESTORED_')).toBe(false);
      expect(wired.dispatch.resetEligible).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------------------------------
// R-WIRE notes (R-UX ratification #447 comment 6013153608, items 2-4)
// ---------------------------------------------------------------------------------------------------

describe('R-WIRE N1: a malformed begin voids the open handle first (supersedes R-UX rule 5 wording)', () => {
  test('each malformed begin throws TypeError and the earlier handle is then stale', async () => {
    const { v, db, calls } = await unlockedVault();
    for (const bad of [null, {}, { restoreResult: 'MANIFEST_INVALID', lockHeld: 'yes' }, { restoreResult: 'MANIFEST_INVALID', lockHeld: true, extra: 1 }]) {
      const begun = await v.beginRecoveryReset({ restoreResult: 'MANIFEST_INVALID', lockHeld: true });
      expect(typeof begun.confirmation).toBe('object');
      await expect(v.beginRecoveryReset(bad)).rejects.toThrow(TypeError);
      const later = await v.confirmRecoveryReset({
        restoreResult: 'MANIFEST_INVALID', lockHeld: true, confirmed: true, disclosure: true, confirmation: begun.confirmation,
      });
      expect(later.reject).toBe('FRESH_CONFIRMATION_REQUIRED');
    }
    expect(calls).toEqual([]);
    expect(db.destroyed).toBe(0);
  });
});

describe('R-WIRE N2: every C-REC /reset member has a carrier (predicate table)', () => {
  const PREDICATES = {
    eligibleResults: () => [...M2_RECOVERY.RESET_ELIGIBLE_RESULTS].sort().join() === [...CREC.reset.eligibleResults].sort().join(),
    ineligibleResults: () => [...M2_RECOVERY.RESET_INELIGIBLE_RESULTS].sort().join() === [...CREC.reset.ineligibleResults].sort().join(),
    requiresOneWriterLock: () => M2_RECOVERY.REQUIRES_ONE_WRITER_LOCK_FOR_STATE_CHANGE === CREC.reset.requiresOneWriterLock,
    preserveDiagnosis: () => M2_RECOVERY.RESET_PRESERVE_DIAGNOSIS === CREC.reset.preserveDiagnosis,
    legacyBytes: () => M2_RECOVERY.RESET_LEGACY_BYTES === CREC.reset.legacyBytes,
    markerState: () => M2_RECOVERY.RESET_MARKER_STATE === CREC.reset.markerState,
    physicalErasureClaim: () => M2_RECOVERY.PHYSICAL_ERASURE_CLAIM === CREC.reset.physicalErasureClaim,
    interruptedClassification: () => M2_RECOVERY.RESET_DISCLOSURE.interruptedClassification === CREC.reset.interruptedClassification,
    requiresExplicitSeparateIrreversibleConfirmation: () => CREC.reset.requiresExplicitSeparateIrreversibleConfirmation === true
      && M2_RECOVERY.RESET_AUTOMATIC === false && M2_RECOVERY.RESET_DISCLOSURE.irreversible === true
      && decideRecoveryAction({ action: 'RESET', result: 'MANIFEST_INVALID', confirmed: false, disclosure: true, lock: 'HELD', token: 'FRESH_BOUND_TOKEN' }).reject === 'EXPLICIT_CONFIRMATION_REQUIRED',
    valueFreeAuthorityLossDisclosureRequired: () => CREC.reset.valueFreeAuthorityLossDisclosureRequired === true
      && typeof M2_RECOVERY.RESET_DISCLOSURE.authorityBecomesUnavailable === 'string'
      && M2_RECOVERY.RESET_DISCLOSURE.authorityBecomesUnavailable.length > 0
      && decideRecoveryAction({ action: 'RESET', result: 'MANIFEST_INVALID', confirmed: true, disclosure: false, lock: 'HELD', token: 'FRESH_BOUND_TOKEN' }).reject === 'DISCLOSURE_REQUIRED',
    // NOT_A_VAULT_FLAG: C-REC's statement about itself.
    implementedHere: () => CREC.reset.implementedHere === false && !Object.hasOwn(M2_RECOVERY, 'IMPLEMENTED_HERE'),
  };

  test('the predicate table covers exactly the /reset members and every predicate holds', () => {
    expect(Object.keys(PREDICATES).sort()).toEqual(Object.keys(CREC.reset).sort());
    for (const [member, holds] of Object.entries(PREDICATES)) expect([member, holds()]).toEqual([member, true]);
    expect(M2_RECOVERY.RESET_PRESERVE_DIAGNOSIS).toBe(CREC.reset.preserveDiagnosis);
  });
});

describe('R-WIRE N3: diagnostic arrays carry only their indices and length', () => {
  const ok = ['stageCode', 'reasonCode'];
  const RAW = 'RAW_VALUE_DIAGNOSTIC';

  test('extra string key, symbol key, non-enumerable index, accessor index and hostile proxies are rejected without throwing', () => {
    const extra = [...ok]; extra.note = 'x';
    const sym = [...ok]; sym[Symbol('s')] = 1;
    const hidden = [...ok]; Object.defineProperty(hidden, '1', { value: 'reasonCode', enumerable: false });
    let touched = 0;
    const accessor = [...ok]; Object.defineProperty(accessor, '0', { get: () => { touched += 1; return 'stageCode'; }, enumerable: true });
    const { proxy: revoked, revoke } = Proxy.revocable([...ok], {}); revoke();
    const throwing = new Proxy([...ok], { ownKeys() { throw new Error('trap'); } });
    const holey = ['stageCode']; holey.length = 2;
    for (const fields of [extra, sym, hidden, accessor, revoked, throwing, holey]) {
      expect(() => decideRecoveryDiagnostic({ fields })).not.toThrow();
      expect(decideRecoveryDiagnostic({ fields }).reject).toBe(RAW);
    }
    expect(touched).toBe(0);
  });

  test('plain and frozen literals of 0-6 distinct allowed names are still accepted', () => {
    for (let n = 0; n <= CREC.diagnostics.allowed.length; n += 1) {
      const fields = CREC.diagnostics.allowed.slice(0, n);
      expect(decideRecoveryDiagnostic({ fields: [...fields] }).accepted).toBe(true);
      expect(decideRecoveryDiagnostic({ fields: Object.freeze([...fields]) }).accepted).toBe(true);
    }
  });

  test('a random extra key (neither an index nor length) is always rejected', () => {
    fc.assert(fc.property(
      fc.subarray(CREC.diagnostics.allowed),
      fc.string({ minLength: 1 }).filter((k) => k !== 'length' && k !== '__proto__' && !/^(0|[1-9][0-9]*)$/.test(k)),
      (fields, key) => {
        const arr = [...fields];
        arr[key] = 'stageCode';
        return decideRecoveryDiagnostic({ fields: arr }).reject === RAW;
      },
    ), { numRuns: 1000 });
  });
});

describe('R-WIRE: the closed named-export surface of vault.js', () => {
  test('exactly the four pre-existing exports, the seven R-UX exports and vaultUnlockRestoreFault', () => {
    expect(Object.keys(vaultModule).sort()).toEqual([
      'DEFAULT_VAULT_PROFILE', 'ENABLED_NAMESPACES', 'M2_RECOVERY', 'VAULT_STATES', 'createVault',
      'decidePasswordRewrap', 'decideRecoveryAction', 'decideRecoveryDiagnostic', 'dispatchRecovery',
      'recoveryBoundary', 'recoveryGuidance', 'vaultUnlockRestoreFault',
    ]);
  });
});
