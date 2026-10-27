// OUTPUT-DIGEST-BIND (#513) tests: the held-output digest HOD bound to the escrow bytes in I-TXN.
// The fixtures and the in-memory port below are those of session-transaction.test.js, with the
// held-output digest derived from the staged bytes by a local HOD.
import { describe, expect, test } from '@jest/globals';
import { sha256 } from '@noble/hashes/sha256';
import {
  M2_KIND, encodePlaintext, encodeRecordKey, decodePlaintext,
} from '../../../src/storage/m2/session-codec.js';
import {
  computeKeyedRoot, ciphertextDigest, encodeManifest, encodeManifestKey, manifestEntry, manifestKeyDigest,
} from '../../../src/storage/m2/session-root.js';
import * as txn from '../../../src/storage/m2/session-transaction.js';

const {
  M2_OUTCOME, M2_TXN, buildMutationEnvelope, classifyAuthority, loadBoundHold, mutationRow, reconcileIndeterminate,
  runMutation,
} = txn;

const OUTPUT_KINDS = ['NONE', 'EMBEDDED_TREE_WELCOME', 'PROTECTED_APPLICATION_BYTES', 'APPLICATION_BYTES',
  'PROTECTED_COMMIT_BYTES', 'SELECTED_CANDIDATE_REF'];
// The local HOD (C-FMT outputEscrow.heldOutputDigestRule).
function hod(kind, output) {
  const label = new TextEncoder().encode('STYX-M2-HELD-OUTPUT-DIGEST-V1');
  const n = output.length;
  const framed = new Uint8Array(label.length + 5 + n);
  framed.set(label, 0);
  framed[label.length] = OUTPUT_KINDS.indexOf(kind) + 1;
  framed.set(Uint8Array.of((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255), label.length + 1);
  framed.set(output, label.length + 5);
  return sha256(framed);
}

// BASE_RESULT_TABLE (generated from the recorded base run at 33f593c; failed there = bite)
const BASE_RESULT_TABLE = {
  "T2 kind-9 filler with arbitrary projection bytes: memory-loss COMMITTED refused": 'bite',
  "T2 kind-9 filler with arbitrary projection bytes: memory-loss NOT_COMMITTED refused": 'bite',
  "T2 kind-9 filler, twin with HOD of the projection bytes: memory-loss COMMITTED reconciles": 'regression',
  "T2 kind-9 filler, twin with HOD of the projection bytes: memory-loss NOT_COMMITTED reconciles": 'regression',
  "T2 kind-9 filler: the strict loader refuses the counterexample": 'regression',
  "T2 kind-9 filler: the strict loader refuses the twin": 'regression',
  "T2 kind-9 tombstone with arbitrary projection bytes: memory-loss COMMITTED refused": 'bite',
  "T2 kind-9 tombstone with arbitrary projection bytes: memory-loss NOT_COMMITTED refused": 'bite',
  "T2 kind-9 tombstone, twin with HOD of the projection bytes: memory-loss COMMITTED reconciles": 'regression',
  "T2 kind-9 tombstone, twin with HOD of the projection bytes: memory-loss NOT_COMMITTED reconciles": 'regression',
  "T2 kind-9 tombstone: the strict loader refuses the counterexample": 'regression',
  "T2 kind-9 tombstone: the strict loader refuses the twin": 'regression',
  "T3 CAPI-S001 appended: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S001 appended: loadBoundHold refused": 'bite',
  "T3 CAPI-S001 appended: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S001 appended: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S001 appended: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S001 appended: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S001 appended: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S001 appended: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S001 appended: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S001 digest noKindByte: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S001 digest noKindByte: loadBoundHold refused": 'bite',
  "T3 CAPI-S001 digest noKindByte: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S001 digest noKindByte: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S001 digest noKindByte: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S001 digest noKindByte: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S001 digest noKindByte: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S001 digest noKindByte: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S001 digest noKindByte: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S001 digest noLength: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S001 digest noLength: loadBoundHold refused": 'bite',
  "T3 CAPI-S001 digest noLength: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S001 digest noLength: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S001 digest noLength: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S001 digest noLength: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S001 digest noLength: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S001 digest noLength: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S001 digest noLength: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S001 digest otherKind: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S001 digest otherKind: loadBoundHold refused": 'bite',
  "T3 CAPI-S001 digest otherKind: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S001 digest otherKind: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S001 digest otherKind: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S001 digest otherKind: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S001 digest otherKind: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S001 digest otherKind: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S001 digest otherKind: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S001 digest otherLabel: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S001 digest otherLabel: loadBoundHold refused": 'bite',
  "T3 CAPI-S001 digest otherLabel: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S001 digest otherLabel: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S001 digest otherLabel: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S001 digest otherLabel: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S001 digest otherLabel: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S001 digest otherLabel: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S001 digest otherLabel: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S001 firstFlipped: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S001 firstFlipped: loadBoundHold refused": 'bite',
  "T3 CAPI-S001 firstFlipped: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S001 firstFlipped: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S001 firstFlipped: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S001 firstFlipped: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S001 firstFlipped: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S001 firstFlipped: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S001 firstFlipped: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S001 lastFlipped: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S001 lastFlipped: loadBoundHold refused": 'bite',
  "T3 CAPI-S001 lastFlipped: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S001 lastFlipped: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S001 lastFlipped: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S001 lastFlipped: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S001 lastFlipped: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S001 lastFlipped: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S001 lastFlipped: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S001 truncated: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S001 truncated: loadBoundHold refused": 'bite',
  "T3 CAPI-S001 truncated: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S001 truncated: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S001 truncated: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S001 truncated: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S001 truncated: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S001 truncated: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S001 truncated: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S009 appended: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S009 appended: loadBoundHold refused": 'bite',
  "T3 CAPI-S009 appended: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S009 appended: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S009 appended: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S009 appended: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S009 appended: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S009 appended: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S009 appended: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S009 digest noKindByte: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S009 digest noKindByte: loadBoundHold refused": 'bite',
  "T3 CAPI-S009 digest noKindByte: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S009 digest noKindByte: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S009 digest noKindByte: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S009 digest noKindByte: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S009 digest noKindByte: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S009 digest noKindByte: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S009 digest noKindByte: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S009 digest noLength: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S009 digest noLength: loadBoundHold refused": 'bite',
  "T3 CAPI-S009 digest noLength: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S009 digest noLength: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S009 digest noLength: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S009 digest noLength: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S009 digest noLength: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S009 digest noLength: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S009 digest noLength: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S009 digest otherKind: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S009 digest otherKind: loadBoundHold refused": 'bite',
  "T3 CAPI-S009 digest otherKind: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S009 digest otherKind: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S009 digest otherKind: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S009 digest otherKind: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S009 digest otherKind: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S009 digest otherKind: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S009 digest otherKind: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S009 digest otherLabel: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S009 digest otherLabel: loadBoundHold refused": 'bite',
  "T3 CAPI-S009 digest otherLabel: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S009 digest otherLabel: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S009 digest otherLabel: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S009 digest otherLabel: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S009 digest otherLabel: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S009 digest otherLabel: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S009 digest otherLabel: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S009 firstFlipped: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S009 firstFlipped: loadBoundHold refused": 'bite',
  "T3 CAPI-S009 firstFlipped: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S009 firstFlipped: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S009 firstFlipped: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S009 firstFlipped: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S009 firstFlipped: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S009 firstFlipped: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S009 firstFlipped: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S009 lastFlipped: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S009 lastFlipped: loadBoundHold refused": 'bite',
  "T3 CAPI-S009 lastFlipped: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S009 lastFlipped: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S009 lastFlipped: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S009 lastFlipped: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S009 lastFlipped: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S009 lastFlipped: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S009 lastFlipped: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S009 truncated: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S009 truncated: loadBoundHold refused": 'bite',
  "T3 CAPI-S009 truncated: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S009 truncated: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S009 truncated: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S009 truncated: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S009 truncated: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S009 truncated: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S009 truncated: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S010 appended: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S010 appended: loadBoundHold refused": 'bite',
  "T3 CAPI-S010 appended: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S010 appended: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S010 appended: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S010 appended: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S010 appended: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S010 appended: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S010 appended: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S010 digest noKindByte: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S010 digest noKindByte: loadBoundHold refused": 'bite',
  "T3 CAPI-S010 digest noKindByte: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S010 digest noKindByte: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S010 digest noKindByte: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S010 digest noKindByte: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S010 digest noKindByte: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S010 digest noKindByte: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S010 digest noKindByte: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S010 digest noLength: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S010 digest noLength: loadBoundHold refused": 'bite',
  "T3 CAPI-S010 digest noLength: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S010 digest noLength: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S010 digest noLength: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S010 digest noLength: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S010 digest noLength: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S010 digest noLength: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S010 digest noLength: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S010 digest otherKind: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S010 digest otherKind: loadBoundHold refused": 'bite',
  "T3 CAPI-S010 digest otherKind: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S010 digest otherKind: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S010 digest otherKind: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S010 digest otherKind: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S010 digest otherKind: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S010 digest otherKind: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S010 digest otherKind: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S010 digest otherLabel: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S010 digest otherLabel: loadBoundHold refused": 'bite',
  "T3 CAPI-S010 digest otherLabel: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S010 digest otherLabel: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S010 digest otherLabel: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S010 digest otherLabel: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S010 digest otherLabel: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S010 digest otherLabel: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S010 digest otherLabel: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S010 firstFlipped: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S010 firstFlipped: loadBoundHold refused": 'bite',
  "T3 CAPI-S010 firstFlipped: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S010 firstFlipped: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S010 firstFlipped: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S010 firstFlipped: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S010 firstFlipped: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S010 firstFlipped: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S010 firstFlipped: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S010 lastFlipped: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S010 lastFlipped: loadBoundHold refused": 'bite',
  "T3 CAPI-S010 lastFlipped: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S010 lastFlipped: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S010 lastFlipped: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S010 lastFlipped: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S010 lastFlipped: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S010 lastFlipped: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S010 lastFlipped: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S010 truncated: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S010 truncated: loadBoundHold refused": 'bite',
  "T3 CAPI-S010 truncated: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S010 truncated: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S010 truncated: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S010 truncated: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S010 truncated: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S010 truncated: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S010 truncated: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S014 appended: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S014 appended: loadBoundHold refused": 'bite',
  "T3 CAPI-S014 appended: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S014 appended: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S014 appended: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S014 appended: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S014 appended: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S014 appended: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S014 appended: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S014 digest noKindByte: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S014 digest noKindByte: loadBoundHold refused": 'bite',
  "T3 CAPI-S014 digest noKindByte: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S014 digest noKindByte: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S014 digest noKindByte: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S014 digest noKindByte: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S014 digest noKindByte: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S014 digest noKindByte: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S014 digest noKindByte: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S014 digest noLength: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S014 digest noLength: loadBoundHold refused": 'bite',
  "T3 CAPI-S014 digest noLength: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S014 digest noLength: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S014 digest noLength: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S014 digest noLength: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S014 digest noLength: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S014 digest noLength: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S014 digest noLength: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S014 digest otherKind: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S014 digest otherKind: loadBoundHold refused": 'bite',
  "T3 CAPI-S014 digest otherKind: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S014 digest otherKind: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S014 digest otherKind: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S014 digest otherKind: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S014 digest otherKind: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S014 digest otherKind: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S014 digest otherKind: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S014 digest otherLabel: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S014 digest otherLabel: loadBoundHold refused": 'bite',
  "T3 CAPI-S014 digest otherLabel: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S014 digest otherLabel: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S014 digest otherLabel: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S014 digest otherLabel: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S014 digest otherLabel: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S014 digest otherLabel: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S014 digest otherLabel: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S014 firstFlipped: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S014 firstFlipped: loadBoundHold refused": 'bite',
  "T3 CAPI-S014 firstFlipped: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S014 firstFlipped: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S014 firstFlipped: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S014 firstFlipped: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S014 firstFlipped: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S014 firstFlipped: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S014 firstFlipped: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S014 lastFlipped: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S014 lastFlipped: loadBoundHold refused": 'bite',
  "T3 CAPI-S014 lastFlipped: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S014 lastFlipped: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S014 lastFlipped: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S014 lastFlipped: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S014 lastFlipped: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S014 lastFlipped: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S014 lastFlipped: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S014 truncated: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S014 truncated: loadBoundHold refused": 'bite',
  "T3 CAPI-S014 truncated: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S014 truncated: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S014 truncated: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S014 truncated: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S014 truncated: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S014 truncated: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S014 truncated: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S017 appended: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S017 appended: loadBoundHold refused": 'bite',
  "T3 CAPI-S017 appended: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S017 appended: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S017 appended: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S017 appended: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S017 appended: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S017 appended: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S017 appended: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S017 digest noKindByte: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S017 digest noKindByte: loadBoundHold refused": 'bite',
  "T3 CAPI-S017 digest noKindByte: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S017 digest noKindByte: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S017 digest noKindByte: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S017 digest noKindByte: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S017 digest noKindByte: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S017 digest noKindByte: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S017 digest noKindByte: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S017 digest noLength: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S017 digest noLength: loadBoundHold refused": 'bite',
  "T3 CAPI-S017 digest noLength: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S017 digest noLength: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S017 digest noLength: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S017 digest noLength: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S017 digest noLength: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S017 digest noLength: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S017 digest noLength: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S017 digest otherKind: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S017 digest otherKind: loadBoundHold refused": 'bite',
  "T3 CAPI-S017 digest otherKind: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S017 digest otherKind: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S017 digest otherKind: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S017 digest otherKind: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S017 digest otherKind: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S017 digest otherKind: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S017 digest otherKind: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S017 digest otherLabel: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S017 digest otherLabel: loadBoundHold refused": 'bite',
  "T3 CAPI-S017 digest otherLabel: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S017 digest otherLabel: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S017 digest otherLabel: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S017 digest otherLabel: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S017 digest otherLabel: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S017 digest otherLabel: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S017 digest otherLabel: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S017 firstFlipped: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S017 firstFlipped: loadBoundHold refused": 'bite',
  "T3 CAPI-S017 firstFlipped: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S017 firstFlipped: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S017 firstFlipped: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S017 firstFlipped: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S017 firstFlipped: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S017 firstFlipped: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S017 firstFlipped: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S017 lastFlipped: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S017 lastFlipped: loadBoundHold refused": 'bite',
  "T3 CAPI-S017 lastFlipped: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S017 lastFlipped: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S017 lastFlipped: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S017 lastFlipped: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S017 lastFlipped: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S017 lastFlipped: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S017 lastFlipped: runMutation NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S017 truncated: CAPI-S020/S022 repeat refused": 'bite',
  "T3 CAPI-S017 truncated: loadBoundHold refused": 'bite',
  "T3 CAPI-S017 truncated: memory-loss reconcile COMMITTED refused": 'bite',
  "T3 CAPI-S017 truncated: memory-loss reconcile INDETERMINATE refused": 'bite',
  "T3 CAPI-S017 truncated: memory-loss reconcile NOT_COMMITTED refused": 'bite',
  "T3 CAPI-S017 truncated: retained COMMITTED reconcile refused": 'bite',
  "T3 CAPI-S017 truncated: runMutation COMMITTED refused": 'bite',
  "T3 CAPI-S017 truncated: runMutation INDETERMINATE refused": 'bite',
  "T3 CAPI-S017 truncated: runMutation NOT_COMMITTED refused": 'bite',
  "T3 over-bound projection: loadBoundHold refused": 'regression',
  "T3 over-bound projection: memory-loss reconcile refused": 'bite',
  "T3 over-bound projection: retained COMMITTED reconcile refused": 'bite',
  "T3 over-bound projection: runMutation refused": 'bite',
  "T4 CAPI-S006 staged present kind-9: runMutation COMMITTED refused": 'bite',
  "T4 CAPI-S006 staged present kind-9: runMutation INDETERMINATE refused": 'bite',
  "T4 CAPI-S006 staged present kind-9: runMutation NOT_COMMITTED refused": 'bite',
  "T4 CAPI-S016 staged present kind-9: runMutation COMMITTED refused": 'bite',
  "T4 CAPI-S016 staged present kind-9: runMutation INDETERMINATE refused": 'bite',
  "T4 CAPI-S016 staged present kind-9: runMutation NOT_COMMITTED refused": 'bite',
  "T4 CAPI-S020/S022 repeat: a canonical kind-9 with other bytes than the bound projection refused": 'bite',
  "T4 bound COMMITTED selection: a canonical kind-9 with other bytes than the bound projection refused": 'bite',
  "T4 positive control: bound COMMITTED selection and repeat release the bound bytes": 'regression',
  "T4 positive control: runMutation COMMITTED with bound canonical records": 'regression',
  "T4 positive control: runMutation INDETERMINATE with bound canonical records": 'regression',
  "T4 positive control: runMutation NOT_COMMITTED with bound canonical records": 'regression',
  "T4 staged kind-13 digest differs: runMutation COMMITTED refused": 'bite',
  "T4 staged kind-13 digest differs: runMutation INDETERMINATE refused": 'regression',
  "T4 staged kind-13 digest differs: runMutation NOT_COMMITTED refused": 'bite',
  "T4 staged kind-13 kind differs: runMutation COMMITTED refused": 'bite',
  "T4 staged kind-13 kind differs: runMutation INDETERMINATE refused": 'regression',
  "T4 staged kind-13 kind differs: runMutation NOT_COMMITTED refused": 'bite',
  "T4 staged kind-13 reference differs: runMutation COMMITTED refused": 'bite',
  "T4 staged kind-13 reference differs: runMutation INDETERMINATE refused": 'regression',
  "T4 staged kind-13 reference differs: runMutation NOT_COMMITTED refused": 'bite',
  "T4 staged kind-9 mutationSetDigest differs: runMutation COMMITTED refused": 'bite',
  "T4 staged kind-9 mutationSetDigest differs: runMutation INDETERMINATE refused": 'bite',
  "T4 staged kind-9 mutationSetDigest differs: runMutation NOT_COMMITTED refused": 'bite',
  "T4 staged kind-9 operationIdentity differs: runMutation COMMITTED refused": 'bite',
  "T4 staged kind-9 operationIdentity differs: runMutation INDETERMINATE refused": 'bite',
  "T4 staged kind-9 operationIdentity differs: runMutation NOT_COMMITTED refused": 'bite',
  "T4 staged kind-9 output differs: runMutation COMMITTED refused": 'bite',
  "T4 staged kind-9 output differs: runMutation INDETERMINATE refused": 'bite',
  "T4 staged kind-9 output differs: runMutation NOT_COMMITTED refused": 'bite',
  "T4 staged kind-9 outputKind differs: runMutation COMMITTED refused": 'bite',
  "T4 staged kind-9 outputKind differs: runMutation INDETERMINATE refused": 'bite',
  "T4 staged kind-9 outputKind differs: runMutation NOT_COMMITTED refused": 'bite',
  "T5 CAPI-S001 COMMITTED: the original path gives the planned steps and result": 'regression',
  "T5 CAPI-S001 INDETERMINATE: the original path gives the planned steps and result": 'regression',
  "T5 CAPI-S001 NOT_COMMITTED: the original path gives the planned steps and result": 'regression',
  "T5 CAPI-S001 loadBoundHold returns the written hold with its digest": 'regression',
  "T5 CAPI-S001 reconcile COMMITTED with memory LOST": 'regression',
  "T5 CAPI-S001 reconcile COMMITTED with memory RETAINED": 'regression',
  "T5 CAPI-S001 reconcile NOT_COMMITTED with memory LOST": 'regression',
  "T5 CAPI-S001 reconcile NOT_COMMITTED with memory RETAINED": 'regression',
  "T5 CAPI-S009 COMMITTED: the original path gives the planned steps and result": 'regression',
  "T5 CAPI-S009 INDETERMINATE: the original path gives the planned steps and result": 'regression',
  "T5 CAPI-S009 NOT_COMMITTED: the original path gives the planned steps and result": 'regression',
  "T5 CAPI-S009 loadBoundHold returns the written hold with its digest": 'regression',
  "T5 CAPI-S009 reconcile COMMITTED with memory LOST": 'regression',
  "T5 CAPI-S009 reconcile COMMITTED with memory RETAINED": 'regression',
  "T5 CAPI-S009 reconcile NOT_COMMITTED with memory LOST": 'regression',
  "T5 CAPI-S009 reconcile NOT_COMMITTED with memory RETAINED": 'regression',
  "T5 CAPI-S010 COMMITTED: the original path gives the planned steps and result": 'regression',
  "T5 CAPI-S010 INDETERMINATE: the original path gives the planned steps and result": 'regression',
  "T5 CAPI-S010 NOT_COMMITTED: the original path gives the planned steps and result": 'regression',
  "T5 CAPI-S010 loadBoundHold returns the written hold with its digest": 'regression',
  "T5 CAPI-S010 reconcile COMMITTED with memory LOST": 'regression',
  "T5 CAPI-S010 reconcile COMMITTED with memory RETAINED": 'regression',
  "T5 CAPI-S010 reconcile NOT_COMMITTED with memory LOST": 'regression',
  "T5 CAPI-S010 reconcile NOT_COMMITTED with memory RETAINED": 'regression',
  "T5 CAPI-S014 COMMITTED: the original path gives the planned steps and result": 'regression',
  "T5 CAPI-S014 INDETERMINATE: the original path gives the planned steps and result": 'regression',
  "T5 CAPI-S014 NOT_COMMITTED: the original path gives the planned steps and result": 'regression',
  "T5 CAPI-S014 loadBoundHold returns the written hold with its digest": 'regression',
  "T5 CAPI-S014 reconcile COMMITTED with memory LOST": 'regression',
  "T5 CAPI-S014 reconcile COMMITTED with memory RETAINED": 'regression',
  "T5 CAPI-S014 reconcile NOT_COMMITTED with memory LOST": 'regression',
  "T5 CAPI-S014 reconcile NOT_COMMITTED with memory RETAINED": 'regression',
  "T5 CAPI-S017 COMMITTED: the original path gives the planned steps and result": 'regression',
  "T5 CAPI-S017 INDETERMINATE: the original path gives the planned steps and result": 'regression',
  "T5 CAPI-S017 NOT_COMMITTED: the original path gives the planned steps and result": 'regression',
  "T5 CAPI-S017 loadBoundHold returns the written hold with its digest": 'regression',
  "T5 CAPI-S017 reconcile COMMITTED with memory LOST": 'regression',
  "T5 CAPI-S017 reconcile COMMITTED with memory RETAINED": 'regression',
  "T5 CAPI-S017 reconcile NOT_COMMITTED with memory LOST": 'regression',
  "T5 CAPI-S017 reconcile NOT_COMMITTED with memory RETAINED": 'regression',
  "T6 CAPI-S006: a non-null escrow in runMutation refused": 'bite',
  "T6 CAPI-S006: a null escrow runs as at the base": 'regression',
  "T6 CAPI-S016: a non-null escrow in runMutation refused": 'bite',
  "T6 CAPI-S016: a null escrow runs as at the base": 'regression',
  "T6 parsed null output in runMutation COMMITTED refused": 'bite',
  "T6 parsed null output in runMutation INDETERMINATE refused": 'bite',
  "T6 parsed null output in runMutation NOT_COMMITTED refused": 'bite',
  "T6 stored missing output: CAPI-S020/S022 repeat refused": 'bite',
  "T6 stored missing output: loadBoundHold refused": 'regression',
  "T6 stored missing output: memory-loss reconcile COMMITTED refused": 'regression',
  "T6 stored missing output: retained COMMITTED reconcile refused": 'bite',
  "T6 stored nonByte output: CAPI-S020/S022 repeat refused": 'regression',
  "T6 stored nonByte output: loadBoundHold refused": 'regression',
  "T6 stored nonByte output: memory-loss reconcile COMMITTED refused": 'regression',
  "T6 stored nonByte output: retained COMMITTED reconcile refused": 'regression',
  "T6 stored null output: CAPI-S020/S022 repeat refused": 'bite',
  "T6 stored null output: loadBoundHold refused": 'regression',
  "T6 stored null output: memory-loss reconcile COMMITTED refused": 'regression',
  "T6 stored null output: retained COMMITTED reconcile refused": 'bite',
  "T6 structural: a missing escrow output member is MALFORMED_INPUT": 'regression',
  "T6 structural: a non-byte escrow output is MALFORMED_INPUT": 'regression',
  "T7 CAPI-S017 empty with a correct HOD: loadBoundHold refused": 'regression',
  "T7 CAPI-S017 empty with a correct HOD: memory-loss reconcile keeps the bytes opaque": 'regression',
  "T7 CAPI-S017 malformedUtf8 with a correct HOD: loadBoundHold refused": 'regression',
  "T7 CAPI-S017 malformedUtf8 with a correct HOD: memory-loss reconcile keeps the bytes opaque": 'regression',
  "T7 CAPI-S017 units257 with a correct HOD: loadBoundHold refused": 'regression',
  "T7 CAPI-S017 units257 with a correct HOD: memory-loss reconcile keeps the bytes opaque": 'regression',
  "T7 staged escrow digestLabel mismatch: runMutation refused": 'bite',
  "T7 staged escrow kind mismatch: runMutation refused": 'bite',
  "T7 staged escrow reference mismatch: runMutation refused": 'bite',
  "T7 stored escrow digestLabel mismatch: memory-loss reconcile refused": 'regression',
  "T7 stored escrow digestLabel mismatch: retained COMMITTED reconcile refused": 'regression',
  "T7 stored escrow kind mismatch: memory-loss reconcile refused": 'regression',
  "T7 stored escrow kind mismatch: retained COMMITTED reconcile refused": 'regression',
  "T7 stored escrow reference mismatch: memory-loss reconcile refused": 'regression',
  "T7 stored escrow reference mismatch: retained COMMITTED reconcile refused": 'regression',
};
// END BASE_RESULT_TABLE

// ---------------------------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------------------------

const LOCAL = new Uint8Array(32).fill(0x21);
const PROFILE = new Uint8Array(32).fill(0x31);
const ROOT_KEY = new Uint8Array(32).fill(0x11);
const SESSION_ID = new Uint8Array(32).fill(0x41);
const BINDING_DIGEST = new Uint8Array(32).fill(0x51);
const OLD_GENERATION = 1n;
const NEW_GENERATION = 2n;
const DATA_KINDS = Array.from({ length: 15 }, (_, i) => i + 1);
const MEMORY_ONLY_KINDS = new Set([
  'VALIDATE_ENVELOPE', 'COMPUTE_CANDIDATE', 'STAGE_LOCAL', 'OPEN_RS_REQUEST', 'CONFIRM_AUTHORITY',
  'REPORT_RESULT',
]);

const bytesOf = (n, seed) => Uint8Array.from({ length: n }, (_, i) => (seed + i * 7) & 0xff);
const hex = (u8) => Buffer.from(u8).toString('hex');

function recordKeyFor(generation, kind) {
  const pre = generation === OLD_GENERATION;
  return encodeRecordKey({
    scope: pre ? 1 : 2,
    localContextId: LOCAL,
    secureSessionIdentity: pre ? null : SESSION_ID,
    writeGeneration: generation,
    recordKind: kind,
  });
}

function generationFixture(generation) {
  const pre = generation === OLD_GENERATION;
  const records = DATA_KINDS.map((kind) => ({
    recordKey: recordKeyFor(generation, kind),
    recordKind: kind,
    plaintext: bytesOf(9, kind),
    ciphertext: bytesOf(17, kind + 3),
    tag: bytesOf(16, kind + 11),
  }));
  const manifestBytes = encodeManifest(records.map((r) => manifestEntry({
    recordKey: r.recordKey,
    recordKind: r.recordKind,
    ciphertextDigest: ciphertextDigest({
      recordKey: r.recordKey, recordKind: r.recordKind, ciphertext: r.ciphertext, tag: r.tag,
    }),
  })));
  const manifestKey = encodeManifestKey({
    localContextId: LOCAL,
    scope: pre ? 1 : 2,
    secureSessionIdentity: pre ? null : SESSION_ID,
    writeGeneration: generation,
  });
  return {
    generation,
    records,
    manifestKey,
    manifestBytes,
    manifestCipherDigest: bytesOf(32, Number(generation) + 0x90),
    keyedRoot: computeKeyedRoot({ manifestRootKey: ROOT_KEY, manifestKey, generation, manifestBytes }),
    sessionBindingDigest: pre ? null : BINDING_DIGEST,
  };
}

const OLD = generationFixture(OLD_GENERATION);
const NEW = generationFixture(NEW_GENERATION);

function sameTupleSelector(facts, state) {
  const digest = manifestKeyDigest(facts.manifestKey);
  return {
    presence: 1,
    generation: facts.generation,
    manifestKeyDigest: digest,
    manifestCipherDigest: facts.manifestCipherDigest,
    keyedRoot: facts.keyedRoot,
    state,
    candidateGeneration: facts.generation,
    candidateManifestKey: facts.manifestKey,
    candidateManifestKeyDigest: digest,
    candidateManifestCipherDigest: facts.manifestCipherDigest,
    candidateKeyedRoot: facts.keyedRoot,
  };
}

const PARENT_SELECTOR = encodePlaintext(M2_KIND.GENERATION_SELECTOR, sameTupleSelector(OLD, 1));
const COMMIT_SELECTOR = encodePlaintext(M2_KIND.GENERATION_SELECTOR, sameTupleSelector(NEW, 2));
const HOLD_SELECTOR = encodePlaintext(M2_KIND.GENERATION_SELECTOR, {
  presence: 1,
  generation: OLD.generation,
  manifestKeyDigest: manifestKeyDigest(OLD.manifestKey),
  manifestCipherDigest: OLD.manifestCipherDigest,
  keyedRoot: OLD.keyedRoot,
  state: 3,
  candidateGeneration: NEW.generation,
  candidateManifestKey: NEW.manifestKey,
  candidateManifestKeyDigest: manifestKeyDigest(NEW.manifestKey),
  candidateManifestCipherDigest: NEW.manifestCipherDigest,
  candidateKeyedRoot: NEW.keyedRoot,
});

const ESCROW = {
  kind: 'PROTECTED_COMMIT_BYTES',
  digest: bytesOf(32, 0xa1),
  reference: bytesOf(32, 0xa2),
  output: bytesOf(24, 0xa3),
};

function evidenceFor(envelope, outcome, overrides = {}) {
  return {
    operationIdentity: envelope.operationIdentity.value,
    originalAuthorityDigest: envelope.originalAuthority.digest,
    originalAuthorityReference: envelope.originalAuthority.reference,
    candidateDigest: envelope.candidate.digest,
    candidateReference: envelope.candidate.reference,
    mutationSetDigest: envelope.componentSet.digest,
    mutationSetReference: envelope.componentSet.reference,
    expectedOriginalState: envelope.originalApiState === 'EMPTY' ? 1 : 2,
    bindingRef: envelope.bindingProfileIdentity.bindingRef,
    profile: envelope.bindingProfileIdentity.profile,
    outcome,
    authenticatedByRS: true,
    terminal: true,
    ...overrides,
  };
}

// mutationSteps takes the plan view of a candidate: the same facts without the two generation-meta
// fields the step plan does not carry, plus the hold it is told to write.
function planInput(scenario, outcome) {
  const c = candidateInput(scenario, outcome);
  return {
    generation: c.generation,
    parentGeneration: c.parentGeneration,
    records: c.records,
    manifestKey: c.manifestKey,
    manifestBytes: c.manifestBytes,
    manifestCipherDigest: c.manifestCipherDigest,
    keyedRoot: c.keyedRoot,
    sessionBindingDigest: c.sessionBindingDigest,
    selectorBytes: c.selectorBytes,
    holdSelectorBytes: c.holdSelectorBytes,
    parentSelectorBytes: c.parentSelectorBytes,
    resultEvidence: c.resultEvidence,
    escrow: c.escrow,
    mutationHold: null,
  };
}

function envelopeInput(scenario, overrides = {}) {
  const row = mutationRow(scenario);
  const base = {
    operationIdentity: {
      value: bytesOf(32, 0x01), assignedBy: 'SS_RS', fresh: true, reusable: false, apRequestIdEqual: false,
    },
    operation: row.operation,
    scenario,
    originalApiState: row.stateBefore,
    originalAuthority: { digest: bytesOf(32, 0x02), reference: bytesOf(32, 0x03) },
    bindingProfileIdentity: { bindingRef: bytesOf(32, 0x04), profile: bytesOf(32, 0x05) },
    candidate: { digest: bytesOf(32, 0x06), reference: bytesOf(32, 0x07) },
    componentSet: {
      digest: bytesOf(32, 0x08), reference: bytesOf(32, 0x09),
      entries: row.components.map((c) => ({ ...c })),
    },
    heldOutput: row.outputKind === 'NONE'
      ? { kind: 'NONE', digest: null, reference: null }
      : { kind: row.outputKind, digest: hod(row.outputKind, ESCROW.output), reference: bytesOf(32, 0x0b) },
    expectedSuccess: { code: row.successCode, stateAfter: row.stateAfterCommitted },
    reconciliationIdentity: { reference: bytesOf(32, 0x0c), owner: 'SS_RS' },
  };
  const merged = { ...base, ...overrides };
  if (overrides.heldOutput !== undefined) merged.heldOutput = overrides.heldOutput;
  return merged;
}

function candidateInput(scenario, outcome, overrides = {}) {
  const envelope = buildMutationEnvelope(envelopeInput(scenario));
  const row = mutationRow(scenario);
  const base = {
    generation: NEW_GENERATION,
    records: NEW.records.map((r) => ({
      recordKey: r.recordKey,
      recordKind: r.recordKind,
      plaintext: r.plaintext,
      ciphertext: r.ciphertext,
      tag: r.tag,
    })),
    manifestKey: NEW.manifestKey,
    manifestBytes: NEW.manifestBytes,
    manifestCipherDigest: NEW.manifestCipherDigest,
    keyedRoot: NEW.keyedRoot,
    sessionBindingDigest: NEW.sessionBindingDigest,
    // The escrow is the row's held output: its kind, digest and reference are the envelope's heldOutput.
    escrow: row.outputKind === 'NONE' ? null : {
      ...ESCROW, kind: row.outputKind, digest: envelope.heldOutput.digest, reference: envelope.heldOutput.reference,
      output: Uint8Array.prototype.slice.call(ESCROW.output),
    },
    resultEvidence: evidenceFor(envelope, outcome),
    selectorBytes: COMMIT_SELECTOR,
    holdSelectorBytes: HOLD_SELECTOR,
    parentSelectorBytes: PARENT_SELECTOR,
    parentGeneration: OLD_GENERATION,
    parentKeyedRoot: OLD.keyedRoot,
  };
  return { ...base, ...overrides };
}

function holdRecordFor(scenario, envelopeOverrides = {}) {
  const envelope = buildMutationEnvelope(envelopeInput(scenario, envelopeOverrides));
  const row = mutationRow(scenario);
  const OPERATIONS = ['CREATE', 'RESTORE', 'JOIN_WELCOME', 'PROTECT_APPLICATION', 'OPEN_APPLICATION',
    'SELF_UPDATE', 'APPLY_PEER_UPDATE', 'RECONCILE_INDETERMINATE'];
  const OUTPUT_KINDS = ['NONE', 'EMBEDDED_TREE_WELCOME', 'PROTECTED_APPLICATION_BYTES',
    'APPLICATION_BYTES', 'PROTECTED_COMMIT_BYTES', 'SELECTED_CANDIDATE_REF'];
  const SUCCESS_CODES = ['CREATED', 'RESTORED', 'JOINED', 'APPLICATION_PROTECTED', 'APPLICATION_OPENED',
    'SELF_UPDATED', 'PEER_UPDATE_APPLIED', 'CANDIDATE_SELECTED', 'RECONCILED_COMMITTED',
    'DUPLICATE_IGNORED'];
  return {
    presence: 1,
    operationIdentity: envelope.operationIdentity.value,
    operation: OPERATIONS.indexOf(row.operation) + 1,
    scenario: M2_TXN.SCENARIOS.indexOf(scenario) + 1,
    originalApiState: row.stateBefore === 'EMPTY' ? 1 : 2,
    originalAuthorityDigest: envelope.originalAuthority.digest,
    originalAuthorityReference: envelope.originalAuthority.reference,
    bindingRef: envelope.bindingProfileIdentity.bindingRef,
    profileDigest: envelope.bindingProfileIdentity.profile,
    candidateDigest: envelope.candidate.digest,
    candidateReference: envelope.candidate.reference,
    componentSetDigest: envelope.componentSet.digest,
    componentSetReference: envelope.componentSet.reference,
    heldOutputKind: OUTPUT_KINDS.indexOf(row.outputKind) + 1,
    heldOutputDigest: envelope.heldOutput.digest,
    heldOutputReference: envelope.heldOutput.reference,
    expectedSuccessCode: SUCCESS_CODES.indexOf(row.successCode) + 1,
    expectedStateAfter: row.stateAfterCommitted === 'EMPTY' ? 1 : 2,
    reconciliationReference: envelope.reconciliationIdentity.reference,
    resultStatus: M2_OUTCOME.INDETERMINATE,
    parentGeneration: OLD_GENERATION,
    parentKeyedRoot: OLD.keyedRoot,
  };
}

/**
 * A deterministic in-memory RS port with fault injection at every durable step. `faults` is a list of
 * `{ boundary, kind, mode, remaining, id }`; a fault matches the first time a step with the same
 * boundary, kind and mode is applied, `BEFORE` raising before the durable effect and `AFTER` after it.
 */
// F2: the stored selector is an opaque C-FMT envelope. A fresh nonce per write is modelled by a
// write counter, so re-writing the same plaintext yields different envelope bytes.
let ENVELOPE_WRITES = 0;
function sealSelector(plaintext) {
  ENVELOPE_WRITES += 1;
  const nonce = new Uint8Array(12);
  new DataView(nonce.buffer).setUint32(8, ENVELOPE_WRITES);
  const out = new Uint8Array(12 + plaintext.length + 16);
  out.set(nonce, 0);
  out.set(plaintext, 12);
  out.fill(0xa5, 12 + plaintext.length); // stand-in tag: the port never interprets the envelope
  return out;
}
const selectorPreconditionFailed = () => Object.assign(
  new Error('the stored selector envelope differs from expectedSelectorBytes'),
  { code: 'SELECTOR_PRECONDITION_FAILED' },
);
// Every REPLACE_SELECTOR this module executes carries the CAS member; the port compares bytes only.
function checkSelectorPrecondition(payload, envelope) {
  if (!Object.hasOwn(payload, 'expectedSelectorBytes')) throw new Error('REPLACE_SELECTOR without expectedSelectorBytes');
  const expected = payload.expectedSelectorBytes;
  const same = expected === null ? envelope === null
    : envelope !== null && expected.length === envelope.length && expected.every((b, i) => b === envelope[i]);
  if (!same) throw selectorPreconditionFailed();
}

function makeStore() {
  const store = {
    generations: new Map(),
    selector: null,
    selectorEnvelope: null,
    sealedFor: null, // the stored plaintext object the current envelope seals
    memoryHold: null,
    applied: [],
    faults: [],
    readFault: null,
    applyCalls: 0,
  };
  const pendingRecords = new Map();
  const takeFault = (boundary, kind, mode) => {
    for (const f of store.faults) {
      if (f.remaining > 0 && f.boundary === boundary && f.kind === kind && f.mode === mode) {
        f.remaining -= 1;
        return f;
      }
    }
    return null;
  };
  const boom = (step, mode) => new Error(`injected crash ${mode} ${step.boundary}/${step.kind}`);
  // A direct test assignment of store.selector is a new durable write: it gets a new envelope.
  const currentEnvelope = () => {
    if (store.selector !== store.sealedFor) {
      store.sealedFor = store.selector;
      store.selectorEnvelope = store.selector === null ? null : sealSelector(store.selector);
    }
    return store.selectorEnvelope;
  };

  store.seed = (generations = [OLD], selector = PARENT_SELECTOR) => {
    store.generations.clear();
    pendingRecords.clear();
    for (const g of generations) {
      store.generations.set(g.generation, {
        generation: g.generation,
        records: g.records,
        manifestKey: g.manifestKey,
        manifestBytes: g.manifestBytes,
        manifestCipherDigest: g.manifestCipherDigest,
        keyedRoot: g.keyedRoot,
        sessionBindingDigest: g.sessionBindingDigest,
        mutationHold: { presence: 0 },
        escrow: null,
        resultEvidence: null,
      });
    }
    store.selector = selector === null ? null : Uint8Array.prototype.slice.call(selector);
    store.memoryHold = null;
    store.applied = [];
    store.applyCalls = 0;
    return store;
  };

  store.apply = async (step) => {
    store.applyCalls += 1;
    store.applied.push({ boundary: step.boundary, kind: step.kind });
    if (takeFault(step.boundary, step.kind, 'BEFORE')) throw boom(step, 'BEFORE');
    const { payload } = step;
    if (step.kind === 'STAGE_DATA') {
      if (!pendingRecords.has(payload.generation)) pendingRecords.set(payload.generation, new Map());
      pendingRecords.get(payload.generation).set(payload.recordKind, {
        recordKey: payload.recordKey,
        recordKind: payload.recordKind,
        plaintext: payload.plaintext,
        ciphertext: payload.ciphertext,
        tag: payload.tag,
      });
    } else if (step.kind === 'STAGE_MANIFEST') {
      const staged = pendingRecords.get(payload.generation);
      const records = staged === undefined ? [] : Array.from(staged.values());
      store.generations.set(payload.generation, {
        generation: payload.generation,
        records,
        manifestKey: payload.manifestKey,
        manifestBytes: payload.manifestBytes,
        manifestCipherDigest: payload.manifestCipherDigest,
        keyedRoot: payload.keyedRoot,
        sessionBindingDigest: payload.sessionBindingDigest,
        mutationHold: { presence: 0 },
        escrow: null,
        resultEvidence: null,
      });
    } else if (step.kind === 'STAGE_EVIDENCE') {
      const g = store.generations.get(payload.generation);
      if (g !== undefined) g.resultEvidence = payload.evidence;
    } else if (step.kind === 'STAGE_ESCROW') {
      const g = store.generations.get(payload.generation);
      if (g !== undefined) g.escrow = payload.escrow;
    } else if (step.kind === 'WRITE_HOLD') {
      const g = store.generations.get(payload.generation);
      // A conformant port stores the complete C-FMT kind-13 record in the candidate generation.
      if (g !== undefined) g.mutationHold = { ...payload.hold };
      store.memoryHold = payload.hold === null || payload.holdRecordKey === undefined || payload.holdRecordKey === null
        ? payload.hold : { ...payload.hold, recordKey: payload.holdRecordKey };
    } else if (step.kind === 'CLEAR_CANDIDATE') {
      store.generations.delete(payload.generation);
      pendingRecords.delete(payload.generation);
      store.memoryHold = null;
    } else if (step.kind === 'REPLACE_SELECTOR') {
      checkSelectorPrecondition(payload, currentEnvelope());
      store.selector = Uint8Array.prototype.slice.call(payload.selectorBytes);
      currentEnvelope();
      // The authority change is atomic with the resolution of the candidate's retained hold: the
      // selector that names a generation as authority and the tombstone of that generation's
      // unresolved hold are one durable write, so no reader ever sees a mixture.
      if (payload.resolveHoldGeneration !== null && payload.resolveHoldGeneration !== undefined) {
        const resolved = store.generations.get(payload.resolveHoldGeneration);
        if (resolved !== undefined) resolved.mutationHold = { presence: 0 };
      }
    } else if (step.kind === 'RELEASE_ESCROW') {
      store.memoryHold = null;
    }
    if (takeFault(step.boundary, step.kind, 'AFTER')) throw boom(step, 'AFTER');
    return undefined;
  };

  store.readSelector = async () => {
    if (store.readFault !== null && store.readFault.remaining > 0) {
      store.readFault.remaining -= 1;
      throw new Error('injected crash before the RS request');
    }
    const envelope = currentEnvelope();
    return store.selector === null ? null : {
      plaintext: Uint8Array.prototype.slice.call(store.selector),
      envelope: Uint8Array.prototype.slice.call(envelope),
    };
  };
  store.readGeneration = async (generation) => {
    const g = store.generations.get(generation);
    if (g === undefined) return null;
    return {
      generation: g.generation,
      records: g.records,
      manifestKey: g.manifestKey,
      manifestBytes: g.manifestBytes,
      manifestCipherDigest: g.manifestCipherDigest,
      keyedRoot: g.keyedRoot,
      sessionBindingDigest: g.sessionBindingDigest,
      mutationHold: g.mutationHold,
      escrow: g.escrow,
      resultEvidence: g.resultEvidence,
    };
  };
  store.readMemoryHold = async () => store.memoryHold;
  // Number-only inventory: every generation number with any stored artifact, complete or staged.
  store.readGenerationNumbers = async () => [...new Set([...store.generations.keys(), ...pendingRecords.keys()])];
  return store;
}

// ---------------------------------------------------------------------------------------------
// OUTPUT-DIGEST-BIND (#513): the held-output digest is HOD of the escrow bytes.
//
// Groups: every test name carries exactly one token. `[api]` calls the new export; `[bite]` fails at
// the base for the missing behaviour; `[regression]` passes at the base and at the head. The file
// imports the module as a namespace and builds every fixture with the local HOD below, so it
// collects at the base. The group of each generated cell is BASE_RESULT[cell], recorded from a base
// run (see the impact analysis).
// ---------------------------------------------------------------------------------------------

const K6 = M2_KIND.BINDING_PROFILE;
const K8 = M2_KIND.COMMIT_RESULT;
const K9 = M2_KIND.OUTPUT_ESCROW;
const K13 = M2_KIND.MUTATION_HOLD;
const K14 = M2_KIND.COMPONENT_SET;
const BINDING = bytesOf(389, 0x31);
const EXPECTED_REF = 'ref-0001:admitted-candidate';
const TE = new TextEncoder();
const be32 = (n) => Uint8Array.of((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}
const bindingDigestOf = (binding) => sha256(concat(TE.encode('STYX-M2-BINDING-DIGEST-V1'), be32(389), binding));
const outputCode = (kind) => OUTPUT_KINDS.indexOf(kind) + 1;
const codeOf = (p) => p.then(() => 'OK', (e) => e.code ?? e.message);
const ALL_CANONICAL = [K6, K8, K9, K13, K14];
const OUTPUT_ROWS = ['CAPI-S001', 'CAPI-S009', 'CAPI-S010', 'CAPI-S014', 'CAPI-S017'];
const NONE_ROWS = ['CAPI-S006', 'CAPI-S016'];
const OUTCOMES = { COMMITTED: M2_OUTCOME.COMMITTED, NOT_COMMITTED: M2_OUTCOME.NOT_COMMITTED, INDETERMINATE: M2_OUTCOME.INDETERMINATE };
const BOUND = 16777216;

// The local HOD: SHA-256(label || u8 kind code || be32 length || output), with switches for the wrong
// framings the matrix uses.
function hodWith({ label = 'STYX-M2-HELD-OUTPUT-DIGEST-V1', kindByte = true, length = true } = {}, kind, output) {
  return sha256(concat(TE.encode(label), kindByte ? Uint8Array.of(outputCode(kind)) : new Uint8Array(0),
    length ? be32(output.length) : new Uint8Array(0), output));
}

const defaultOutput = (scenario) => (mutationRow(scenario).outputKind === 'SELECTED_CANDIDATE_REF'
  ? TE.encode(EXPECTED_REF) : Uint8Array.prototype.slice.call(ESCROW.output));
const heldFor = (scenario, output, digest = null) => {
  const kind = mutationRow(scenario).outputKind;
  return { kind, digest: digest ?? hod(kind, output), reference: bytesOf(32, 0x0b) };
};

function canonicalCandidateRecords(scenario, outcome, outputBytes, {
  kinds = ALL_CANONICAL, envelopeOverrides = {}, k9Tweak = {}, forceK9 = false,
} = {}) {
  const envelope = buildMutationEnvelope(envelopeInput(scenario, envelopeOverrides));
  const row = mutationRow(scenario);
  const evidence = evidenceFor(envelope, outcome);
  const plain = {
    [K6]: encodePlaintext(K6, { presence: 1, canonicalBinding: BINDING, profileDigest: envelope.bindingProfileIdentity.profile }),
    [K8]: encodePlaintext(K8, {
      presence: 1,
      operationIdentity: evidence.operationIdentity,
      originalAuthorityDigest: evidence.originalAuthorityDigest,
      originalAuthorityReference: evidence.originalAuthorityReference,
      candidateDigest: evidence.candidateDigest,
      candidateReference: evidence.candidateReference,
      mutationSetDigest: evidence.mutationSetDigest,
      mutationSetReference: evidence.mutationSetReference,
      expectedOriginalState: evidence.expectedOriginalState,
      bindingRef: evidence.bindingRef,
      profileDigest: evidence.profile,
      outcome,
      authenticatedByRS: true,
      terminal: evidence.terminal,
    }),
    [K13]: row.outputKind === 'NONE' ? undefined : encodePlaintext(K13, holdRecordFor(scenario, envelopeOverrides)),
    [K14]: encodePlaintext(K14, {
      presence: 1, mutationSetDigest: evidence.mutationSetDigest, mutationSetReference: evidence.mutationSetReference,
      entries: bytesOf(64, 0x61),
    }),
  };
  if ((row.outputKind !== 'NONE' || forceK9) && kinds.includes(K9)) {
    plain[K9] = encodePlaintext(K9, {
      presence: 1,
      operationIdentity: evidence.operationIdentity,
      candidateDigest: evidence.candidateDigest,
      candidateReference: evidence.candidateReference,
      mutationSetDigest: evidence.mutationSetDigest,
      mutationSetReference: evidence.mutationSetReference,
      outputKind: outputCode(row.outputKind === 'NONE' ? 'PROTECTED_COMMIT_BYTES' : row.outputKind),
      output: outputBytes ?? bytesOf(4, 0x44),
      resultDigest: bytesOf(32, 0x77),
      ...k9Tweak,
    });
  }
  return NEW.records.map((r) => ({
    recordKey: r.recordKey,
    recordKind: r.recordKind,
    plaintext: kinds.includes(r.recordKind) && plain[r.recordKind] !== undefined ? plain[r.recordKind] : r.plaintext,
    ciphertext: r.ciphertext,
    tag: r.tag,
  }));
}

// The selected generation of a bound hold: the canonical tombstone of its own kind-13 record.
function selectedGeneration() {
  return { ...OLD, records: OLD.records.map((r) => (r.recordKind === K13 ? { ...r, plaintext: encodePlaintext(K13, { presence: 0 }) } : r)) };
}

/**
 * One runMutation request, not yet run. `output` is the escrowed bytes, `digest` the held-output
 * digest the envelope and the escrow label carry (default HOD of `output`), `escrowOutput` the bytes
 * the projection carries (default `output`), `k9Output`/`k9Tweak`/`k13Tweak`/`kinds`/`forceK9` shape
 * the staged canonical records, `escrow` replaces the projection outright.
 */
function mutationCase(scenario, outcome, opts = {}) {
  const row = mutationRow(scenario);
  const none = row.outputKind === 'NONE';
  const output = opts.output ?? (none ? null : defaultOutput(scenario));
  const held = none ? null : heldFor(scenario, output, opts.digest ?? null);
  const envelopeOverrides = none ? {} : { heldOutput: held };
  const envelope = buildMutationEnvelope(envelopeInput(scenario, envelopeOverrides));
  const base = candidateInput(scenario, outcome);
  const records = canonicalCandidateRecords(scenario, outcome, opts.k9Output ?? output, {
    kinds: opts.kinds ?? ALL_CANONICAL,
    envelopeOverrides,
    k9Tweak: opts.k9Tweak ?? {},
    forceK9: opts.forceK9 ?? false,
  }).map((r) => (r.recordKind === K13 && opts.k13Tweak
    ? { ...r, plaintext: encodePlaintext(K13, { ...decodePlaintext(K13, r.plaintext), ...opts.k13Tweak }) } : r));
  const escrow = Object.hasOwn(opts, 'escrow') ? opts.escrow
    : (none ? null : { kind: held.kind, digest: held.digest, reference: held.reference,
      output: Object.hasOwn(opts, 'escrowOutput') ? opts.escrowOutput : output });
  const candidate = { ...base, records, sessionBindingDigest: bindingDigestOf(BINDING), escrow };
  const store = makeStore();
  store.seed([selectedGeneration()], PARENT_SELECTOR);
  return { store, envelope, candidate, output, held };
}
const runCaseOf = (c, outcome) => runMutation({ storage: c.store, manifestRootKey: ROOT_KEY, envelope: c.envelope, candidate: c.candidate, outcome });

// A valid INDETERMINATE run: the selector binds the candidate and memory retains the hold.
async function boundStore(scenario, opts = {}) {
  const c = mutationCase(scenario, M2_OUTCOME.INDETERMINATE, opts);
  await runCaseOf(c, M2_OUTCOME.INDETERMINATE);
  return c;
}

function reconcileOf(c, outcome, memory) {
  if (memory === 'LOST') c.store.memoryHold = null;
  return reconcileIndeterminate({
    storage: c.store,
    manifestRootKey: ROOT_KEY,
    hold: memory === 'LOST' ? null : c.store.memoryHold,
    evidence: evidenceFor(c.envelope, outcome, outcome === M2_OUTCOME.INDETERMINATE ? { terminal: false } : {}),
    reference: c.envelope.reconciliationIdentity.reference,
  });
}
const loadOf = (c) => loadBoundHold({ storage: c.store, manifestRootKey: ROOT_KEY });

// A COMMITTED reconciliation whose emission is interrupted: the candidate is the authority and memory
// still holds the hold, so the next reconcile is the CAPI-S020/S022 repeat.
async function interrupted(scenario, opts = {}) {
  const c = await boundStore(scenario, opts);
  c.store.faults = [{ boundary: 'DURING_ESCROW_OUTPUT_RESPONSE', kind: 'RELEASE_ESCROW', mode: 'BEFORE', remaining: 1 }];
  await expect(reconcileOf(c, M2_OUTCOME.COMMITTED, 'RETAINED')).rejects.toThrow(/injected crash/);
  c.store.faults = [];
  return c;
}

// Stored-state rewrites after a valid run. Plaintexts are not covered by the test manifest, so no
// root or selector changes; record and projection stay equal unless a test says otherwise.
function recordIndex(g, kind) { return g.records.findIndex((r) => r.recordKind === kind); }
function setStoredOutput(c, bytes, { record = true } = {}) {
  const g = c.store.generations.get(NEW_GENERATION);
  g.escrow = { ...g.escrow, output: bytes };
  if (record) {
    const i = recordIndex(g, K9);
    const decoded = decodePlaintext(K9, g.records[i].plaintext);
    g.records = g.records.map((r, j) => (j === i ? { ...r, plaintext: encodePlaintext(K9, { ...decoded, output: bytes }) } : r));
  }
}
function setStoredRecord(c, kind, plaintext) {
  const g = c.store.generations.get(NEW_GENERATION);
  const i = recordIndex(g, kind);
  g.records = g.records.map((r, j) => (j === i ? { ...r, plaintext } : r));
}
function setStoredHeld(c, digest) {
  const g = c.store.generations.get(NEW_GENERATION);
  const i = recordIndex(g, K13);
  const decoded = decodePlaintext(K13, g.records[i].plaintext);
  if (decoded.presence === 1) setStoredRecord(c, K13, encodePlaintext(K13, { ...decoded, heldOutputDigest: digest }));
  if (g.mutationHold && g.mutationHold.presence === 1) g.mutationHold = { ...g.mutationHold, heldOutputDigest: digest };
  if (c.store.memoryHold !== null) c.store.memoryHold = { ...c.store.memoryHold, heldOutputDigest: digest };
  g.escrow = { ...g.escrow, digest };
}

const replacer = (_k, v) => (typeof v === 'bigint' ? `${v}n` : (v instanceof Uint8Array ? hex(v) : v));
const snapshot = (store) => JSON.stringify({
  selector: store.selector === null ? null : hex(store.selector),
  memoryHold: store.memoryHold,
  generations: [...store.generations.entries()],
}, replacer);

// Refusal with the class, no apply, nothing changed, never CAPI-S024.
async function expectRefused(c, promise, code) {
  const before = snapshot(c.store);
  const calls = c.store.applyCalls;
  const got = await codeOf(promise);
  expect(got).not.toBe('CAPI-S024');
  expect(got).toBe(code);
  expect(c.store.applyCalls).toBe(calls);
  expect(snapshot(c.store)).toBe(before);
}

// Byte mutations that keep ASCII ASCII, so the CAPI-S017 string rule is never what refuses.
const MUTATIONS = {
  firstFlipped: (b) => { const o = Uint8Array.prototype.slice.call(b); o[0] ^= 1; return o; },
  lastFlipped: (b) => { const o = Uint8Array.prototype.slice.call(b); o[o.length - 1] ^= 1; return o; },
  truncated: (b) => Uint8Array.prototype.slice.call(b, 0, b.length - 1),
  appended: (b) => concat(b, Uint8Array.of(0x78)),
};
const otherKind = (kind) => (kind === 'PROTECTED_COMMIT_BYTES' ? 'APPLICATION_BYTES' : 'PROTECTED_COMMIT_BYTES');
const WRONG_DIGESTS = {
  otherKind: (kind, out) => hod(otherKind(kind), out),
  otherLabel: (kind, out) => hodWith({ label: 'STYX-M2-HELD-OUTPUT-DIGEST-V2' }, kind, out),
  noKindByte: (kind, out) => hodWith({ kindByte: false }, kind, out),
  noLength: (kind, out) => hodWith({ length: false }, kind, out),
};

// Recorded base run: a cell is `bite` when its head assertion fails at the base, else `regression`.
// Generated from `ODB_RECORD_BASE=1` runs at the exact base (impact analysis, section bite).
const BASE_RESULT = BASE_RESULT_TABLE;
const groupOf = (cell) => {
  if (process.env.ODB_RECORD_BASE === '1') return 'record';
  const g = BASE_RESULT[cell];
  if (g !== 'bite' && g !== 'regression') throw new Error(`cell ${cell} has no recorded base group`);
  return g;
};
// A generated cell: its name carries the group token and the cell id.
const cell = (id, fn) => test(`[${groupOf(id)}] ${id}`, fn);

describe('OUTPUT-DIGEST-BIND', () => {
  describe('T1 HOD export', () => {
    const KAT = [
      ['HOD-KAT-1', 'PROTECTED_COMMIT_BYTES', '616263', '83d4520697f9771ab899c37a3384edcd813552212eef2b359795c7014248cbe9'],
      ['HOD-KAT-2', 'PROTECTED_APPLICATION_BYTES', '616263', 'b6e415884dc6f67fe14ce62205049a6ece054e987b015fa75a97dfe3e4b593b1'],
      ['HOD-KAT-3', 'SELECTED_CANDIDATE_REF', '7265662d31', '5f93ec1eeba325f294529c5e0573f05c679d5c366528e03d3364901fb95ea827'],
      ['HOD-KAT-4', 'EMBEDDED_TREE_WELCOME', '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        'b3b5741314e32445539715012312f88cf7f974de4f59a861fd9568becec5c280'],
    ];
    test.each(KAT)('[api] %s: the C-FMT D2 vector byte for byte', (_id, kind, outHex, digestHex) => {
      expect(hex(txn.heldOutputDigest({ kind, output: Uint8Array.from(Buffer.from(outHex, 'hex')) }))).toBe(digestHex);
      expect(hex(hod(kind, Uint8Array.from(Buffer.from(outHex, 'hex'))))).toBe(digestHex);
    });
    test('[api] the export equals the local HOD on every output kind and length, and on an offset view', () => {
      for (const kind of OUTPUT_KINDS.slice(1)) {
        for (const n of [0, 1, 255, 256, 65536]) {
          const out = bytesOf(n, n + outputCode(kind));
          expect(hex(txn.heldOutputDigest({ kind, output: out }))).toBe(hex(hod(kind, out)));
        }
      }
      const backing = bytesOf(64, 0x10);
      const view = backing.subarray(7, 40);
      expect(hex(txn.heldOutputDigest({ kind: 'APPLICATION_BYTES', output: view })))
        .toBe(hex(hod('APPLICATION_BYTES', Uint8Array.prototype.slice.call(view))));
    });
    test('[api] the bound: 16,777,216 bytes are accepted and 16,777,217 refused', () => {
      expect(txn.heldOutputDigest({ kind: 'APPLICATION_BYTES', output: new Uint8Array(BOUND) })).toHaveLength(32);
      expect(() => txn.heldOutputDigest({ kind: 'APPLICATION_BYTES', output: new Uint8Array(BOUND + 1) }))
        .toThrow(expect.objectContaining({ code: 'MALFORMED_INPUT' }));
    });
    test('[api] malformed and unsupported inputs carry the Observable 1 codes', () => {
      const out = bytesOf(3, 1);
      const cases = [
        [{ kind: 'NONE', output: out }, 'UNSUPPORTED_VALUE'],
        [{ kind: 'NOT_A_KIND', output: out }, 'UNSUPPORTED_VALUE'],
        [{ kind: 'APPLICATION_BYTES', output: [1, 2, 3] }, 'MALFORMED_INPUT'],
        [{ kind: 'APPLICATION_BYTES' }, 'MALFORMED_INPUT'],
        [{ kind: 'APPLICATION_BYTES', output: out, extra: 1 }, 'MALFORMED_INPUT'],
        [null, 'MALFORMED_INPUT'],
      ];
      for (const [input, code] of cases) {
        expect(() => txn.heldOutputDigest(input)).toThrow(expect.objectContaining({ code }));
      }
    });
    test('[api] the result is a fresh copy and does not alias the input', () => {
      const out = bytesOf(8, 3);
      const a = txn.heldOutputDigest({ kind: 'APPLICATION_BYTES', output: out });
      const b = txn.heldOutputDigest({ kind: 'APPLICATION_BYTES', output: out });
      expect(a).not.toBe(b);
      a[0] ^= 0xff;
      expect(hex(b)).toBe(hex(hod('APPLICATION_BYTES', out)));
    });
    test('[api] T5: the export yields the same fixture bytes as the local HOD', () => {
      for (const s of OUTPUT_ROWS) {
        const kind = mutationRow(s).outputKind;
        expect(hex(txn.heldOutputDigest({ kind, output: defaultOutput(s) }))).toBe(hex(hod(kind, defaultOutput(s))));
      }
    });
  });

  describe('T2 the H1 counterexamples', () => {
    const injected = TE.encode('projection-only-output');
    for (const shape of ['tombstone', 'filler']) {
      const make = async () => {
        const c = await boundStore('CAPI-S014');
        setStoredRecord(c, K9, shape === 'tombstone' ? encodePlaintext(K9, { presence: 0 }) : bytesOf(9, 0x99));
        setStoredOutput(c, injected, { record: false });
        c.store.memoryHold = null;
        return c;
      };
      for (const outcome of ['COMMITTED', 'NOT_COMMITTED']) {
        cell(`T2 kind-9 ${shape} with arbitrary projection bytes: memory-loss ${outcome} refused`, async () => {
          const c = await make();
          await expectRefused(c, reconcileOf(c, OUTCOMES[outcome], 'LOST'), 'EVIDENCE_MISMATCH');
        });
        cell(`T2 kind-9 ${shape}, twin with HOD of the projection bytes: memory-loss ${outcome} reconciles`, async () => {
          const c = await make();
          setStoredHeld(c, hod('PROTECTED_COMMIT_BYTES', injected));
          const r = await reconcileOf(c, OUTCOMES[outcome], 'LOST');
          if (outcome === 'COMMITTED') {
            expect(r).toMatchObject({ authority: 'COMPLETE_NEW' });
            expect(hex(r.output)).toBe(hex(injected));
          } else {
            expect(r).toMatchObject({ authority: 'COMPLETE_OLD', output: null });
          }
        });
      }
      cell(`T2 kind-9 ${shape}: the strict loader refuses the counterexample`, async () => {
        const c = await make();
        await expectRefused(c, loadOf(c), 'BOUND_HOLD_INVALID');
      });
      cell(`T2 kind-9 ${shape}: the strict loader refuses the twin`, async () => {
        const c = await make();
        setStoredHeld(c, hod('PROTECTED_COMMIT_BYTES', injected));
        await expectRefused(c, loadOf(c), 'BOUND_HOLD_INVALID');
      });
    }
  });

  describe('T3 byte binding matrix', () => {
    for (const s of OUTPUT_ROWS) {
      const kind = mutationRow(s).outputKind;
      const base = defaultOutput(s);
      // Bytes changed, labels kept: stored record and projection carry the changed bytes.
      for (const [m, f] of Object.entries(MUTATIONS)) {
        for (const outcome of Object.keys(OUTCOMES)) {
          cell(`T3 ${s} ${m}: runMutation ${outcome} refused`, async () => {
            const c = mutationCase(s, OUTCOMES[outcome], { digest: hod(kind, base), output: f(base) });
            await expectRefused(c, runCaseOf(c, OUTCOMES[outcome]), 'EVIDENCE_MISMATCH');
          });
          if (outcome !== 'INDETERMINATE') {
            cell(`T3 ${s} ${m}: memory-loss reconcile ${outcome} refused`, async () => {
              const c = await boundStore(s);
              setStoredOutput(c, f(base));
              c.store.memoryHold = null;
              await expectRefused(c, reconcileOf(c, OUTCOMES[outcome], 'LOST'), 'EVIDENCE_MISMATCH');
            });
          }
        }
        cell(`T3 ${s} ${m}: memory-loss reconcile INDETERMINATE refused`, async () => {
          const c = await boundStore(s);
          setStoredOutput(c, f(base));
          c.store.memoryHold = null;
          await expectRefused(c, reconcileOf(c, M2_OUTCOME.INDETERMINATE, 'LOST'), 'EVIDENCE_MISMATCH');
        });
        cell(`T3 ${s} ${m}: loadBoundHold refused`, async () => {
          const c = await boundStore(s);
          setStoredOutput(c, f(base));
          c.store.memoryHold = null;
          await expectRefused(c, loadOf(c), 'BOUND_HOLD_INVALID');
        });
        cell(`T3 ${s} ${m}: retained COMMITTED reconcile refused`, async () => {
          const c = await boundStore(s);
          setStoredOutput(c, f(base));
          await expectRefused(c, reconcileOf(c, M2_OUTCOME.COMMITTED, 'RETAINED'), 'EVIDENCE_MISMATCH');
        });
        cell(`T3 ${s} ${m}: CAPI-S020/S022 repeat refused`, async () => {
          const c = await interrupted(s);
          setStoredOutput(c, f(base));
          await expectRefused(c, reconcileOf(c, M2_OUTCOME.COMMITTED, 'RETAINED'), 'EVIDENCE_MISMATCH');
        });
      }
      // Bytes kept, digest computed wrongly: hold, escrow label and envelope carry it.
      for (const [w, f] of Object.entries(WRONG_DIGESTS)) {
        for (const outcome of Object.keys(OUTCOMES)) {
          cell(`T3 ${s} digest ${w}: runMutation ${outcome} refused`, async () => {
            const c = mutationCase(s, OUTCOMES[outcome], { digest: f(kind, base) });
            await expectRefused(c, runCaseOf(c, OUTCOMES[outcome]), 'EVIDENCE_MISMATCH');
          });
          cell(`T3 ${s} digest ${w}: memory-loss reconcile ${outcome} refused`, async () => {
            const c = await boundStore(s);
            setStoredHeld(c, f(kind, base));
            c.store.memoryHold = null;
            await expectRefused(c, reconcileOf(c, OUTCOMES[outcome], 'LOST'), 'EVIDENCE_MISMATCH');
          });
        }
        cell(`T3 ${s} digest ${w}: loadBoundHold refused`, async () => {
          const c = await boundStore(s);
          setStoredHeld(c, f(kind, base));
          c.store.memoryHold = null;
          await expectRefused(c, loadOf(c), 'BOUND_HOLD_INVALID');
        });
        cell(`T3 ${s} digest ${w}: retained COMMITTED reconcile refused`, async () => {
          const c = await boundStore(s);
          setStoredHeld(c, f(kind, base));
          await expectRefused(c, reconcileOf(c, M2_OUTCOME.COMMITTED, 'RETAINED'), 'EVIDENCE_MISMATCH');
        });
        cell(`T3 ${s} digest ${w}: CAPI-S020/S022 repeat refused`, async () => {
          const c = await interrupted(s);
          setStoredHeld(c, f(kind, base));
          await expectRefused(c, reconcileOf(c, M2_OUTCOME.COMMITTED, 'RETAINED'), 'EVIDENCE_MISMATCH');
        });
      }
    }
    // Over the bound, labels matching: the kind-9 record cannot hold it, so it is filler there.
    const big = new Uint8Array(BOUND + 1).fill(0x41);
    const bigHeld = hod('PROTECTED_COMMIT_BYTES', big);
    const bigStore = async (memory) => {
      const c = await boundStore('CAPI-S014', { kinds: [K6, K8, K13, K14] });
      setStoredHeld(c, bigHeld);
      setStoredOutput(c, big, { record: false });
      if (memory === 'LOST') c.store.memoryHold = null;
      return c;
    };
    cell('T3 over-bound projection: runMutation refused', async () => {
      const c = mutationCase('CAPI-S014', M2_OUTCOME.COMMITTED, { output: big, kinds: [K6, K8, K14] });
      await expectRefused(c, runCaseOf(c, M2_OUTCOME.COMMITTED), 'EVIDENCE_MISMATCH');
    });
    cell('T3 over-bound projection: memory-loss reconcile refused', async () => {
      const c = await bigStore('LOST');
      await expectRefused(c, reconcileOf(c, M2_OUTCOME.COMMITTED, 'LOST'), 'EVIDENCE_MISMATCH');
    });
    cell('T3 over-bound projection: retained COMMITTED reconcile refused', async () => {
      const c = await bigStore('RETAINED');
      await expectRefused(c, reconcileOf(c, M2_OUTCOME.COMMITTED, 'RETAINED'), 'EVIDENCE_MISMATCH');
    });
    cell('T3 over-bound projection: loadBoundHold refused', async () => {
      const c = await bigStore('LOST');
      await expectRefused(c, loadOf(c), 'BOUND_HOLD_INVALID');
    });
  });

  describe('T4 staged-record binding', () => {
    const s = 'CAPI-S014';
    const kind = mutationRow(s).outputKind;
    const out = defaultOutput(s);
    const other = bytesOf(24, 0x5c);
    for (const outcome of Object.keys(OUTCOMES)) {
      const k13Cases = {
        digest: { heldOutputDigest: hod(kind, other) },
        reference: { heldOutputReference: bytesOf(32, 0x0d) },
        kind: { heldOutputKind: outputCode('APPLICATION_BYTES') },
      };
      for (const [what, k13Tweak] of Object.entries(k13Cases)) {
        cell(`T4 staged kind-13 ${what} differs: runMutation ${outcome} refused`, async () => {
          const c = mutationCase(s, OUTCOMES[outcome], { k13Tweak });
          await expectRefused(c, runCaseOf(c, OUTCOMES[outcome]), 'EVIDENCE_MISMATCH');
        });
      }
      const k9Cases = {
        output: { k9Output: other },
        outputKind: { k9Tweak: { outputKind: outputCode('APPLICATION_BYTES') } },
        operationIdentity: { k9Tweak: { operationIdentity: bytesOf(32, 0xee) } },
        mutationSetDigest: { k9Tweak: { mutationSetDigest: bytesOf(32, 0xed) } },
      };
      for (const [what, opts] of Object.entries(k9Cases)) {
        cell(`T4 staged kind-9 ${what} differs: runMutation ${outcome} refused`, async () => {
          const c = mutationCase(s, OUTCOMES[outcome], opts);
          await expectRefused(c, runCaseOf(c, OUTCOMES[outcome]), 'EVIDENCE_MISMATCH');
        });
      }
      for (const n of NONE_ROWS) {
        cell(`T4 ${n} staged present kind-9: runMutation ${outcome} refused`, async () => {
          const c = mutationCase(n, OUTCOMES[outcome], { forceK9: true });
          await expectRefused(c, runCaseOf(c, OUTCOMES[outcome]), 'EVIDENCE_MISMATCH');
        });
      }
      cell(`T4 positive control: runMutation ${outcome} with bound canonical records`, async () => {
        const c = mutationCase(s, OUTCOMES[outcome]);
        const r = await runCaseOf(c, OUTCOMES[outcome]);
        expect(r.commitOutcome).toBe(outcome);
      });
    }
    const otherRecord = () => {
      const g = encodePlaintext(K9, {
        ...decodePlaintext(K9, canonicalCandidateRecords(s, M2_OUTCOME.INDETERMINATE, out).find((r) => r.recordKind === K9).plaintext),
        output: other,
      });
      return g;
    };
    cell('T4 bound COMMITTED selection: a canonical kind-9 with other bytes than the bound projection refused', async () => {
      const c = await boundStore(s);
      setStoredRecord(c, K9, otherRecord());
      await expectRefused(c, reconcileOf(c, M2_OUTCOME.COMMITTED, 'RETAINED'), 'EVIDENCE_MISMATCH');
    });
    cell('T4 CAPI-S020/S022 repeat: a canonical kind-9 with other bytes than the bound projection refused', async () => {
      const c = await interrupted(s);
      setStoredRecord(c, K9, otherRecord());
      await expectRefused(c, reconcileOf(c, M2_OUTCOME.COMMITTED, 'RETAINED'), 'EVIDENCE_MISMATCH');
    });
    cell('T4 positive control: bound COMMITTED selection and repeat release the bound bytes', async () => {
      const c = await interrupted(s);
      const r = await reconcileOf(c, M2_OUTCOME.COMMITTED, 'RETAINED');
      expect(hex(r.output)).toBe(hex(out));
    });
  });

  describe('T5 positives', () => {
    for (const s of OUTPUT_ROWS) {
      for (const outcome of Object.keys(OUTCOMES)) {
        cell(`T5 ${s} ${outcome}: the original path gives the planned steps and result`, async () => {
          const c = mutationCase(s, OUTCOMES[outcome]);
          const r = await runCaseOf(c, OUTCOMES[outcome]);
          expect(r.commitOutcome).toBe(outcome);
          expect(r.output === null ? null : hex(r.output)).toBe(outcome === 'COMMITTED' ? hex(c.output) : null);
          const durable = c.store.applied.map((a) => a.kind);
          expect(durable.length).toBeGreaterThan(0);
          expect(durable.every((k) => !MEMORY_ONLY_KINDS.has(k))).toBe(true);
        });
        if (outcome === 'INDETERMINATE') continue;
        for (const memory of ['RETAINED', 'LOST']) {
          cell(`T5 ${s} reconcile ${outcome} with memory ${memory}`, async () => {
            const c = await boundStore(s);
            const r = await reconcileOf(c, OUTCOMES[outcome], memory);
            if (outcome === 'COMMITTED') {
              expect(r.authority).toBe('COMPLETE_NEW');
              expect(hex(r.output)).toBe(hex(c.output));
            } else {
              expect(r).toMatchObject({ authority: 'COMPLETE_OLD', output: null, holds: 0 });
            }
          });
        }
      }
      cell(`T5 ${s} loadBoundHold returns the written hold with its digest`, async () => {
        const c = await boundStore(s);
        c.store.memoryHold = null;
        const { hold } = await loadOf(c);
        expect(hex(hold.heldOutputDigest)).toBe(hex(hod(mutationRow(s).outputKind, c.output)));
      });
    }
  });

  describe('T6 missing, null and non-byte outputs; NONE rows', () => {
    for (const n of NONE_ROWS) {
      cell(`T6 ${n}: a non-null escrow in runMutation refused`, async () => {
        const c = mutationCase(n, M2_OUTCOME.COMMITTED, {
          escrow: { kind: 'PROTECTED_COMMIT_BYTES', digest: bytesOf(32, 1), reference: bytesOf(32, 2), output: bytesOf(4, 3) },
        });
        await expectRefused(c, runCaseOf(c, M2_OUTCOME.COMMITTED), 'EVIDENCE_MISMATCH');
      });
      cell(`T6 ${n}: a null escrow runs as at the base`, async () => {
        const c = mutationCase(n, M2_OUTCOME.NOT_COMMITTED);
        const r = await runCaseOf(c, M2_OUTCOME.NOT_COMMITTED);
        expect(r.output).toBeNull();
      });
    }
    for (const outcome of Object.keys(OUTCOMES)) {
      cell(`T6 parsed null output in runMutation ${outcome} refused`, async () => {
        const c = mutationCase('CAPI-S014', OUTCOMES[outcome], { escrowOutput: null });
        await expectRefused(c, runCaseOf(c, OUTCOMES[outcome]), 'EVIDENCE_MISMATCH');
      });
    }
    cell('T6 structural: a missing escrow output member is MALFORMED_INPUT', async () => {
      const c = mutationCase('CAPI-S014', M2_OUTCOME.COMMITTED);
      const { output: _drop, ...rest } = c.candidate.escrow;
      c.candidate = { ...c.candidate, escrow: rest };
      await expectRefused(c, runCaseOf(c, M2_OUTCOME.COMMITTED), 'MALFORMED_INPUT');
    });
    cell('T6 structural: a non-byte escrow output is MALFORMED_INPUT', async () => {
      const c = mutationCase('CAPI-S014', M2_OUTCOME.COMMITTED, { escrowOutput: [1, 2, 3] });
      await expectRefused(c, runCaseOf(c, M2_OUTCOME.COMMITTED), 'MALFORMED_INPUT');
    });
    const STORED = { missing: undefined, null: null, nonByte: [1, 2, 3] };
    for (const [what, value] of Object.entries(STORED)) {
      const strip = (c) => {
        const g = c.store.generations.get(NEW_GENERATION);
        const { output: _drop, ...rest } = g.escrow;
        g.escrow = what === 'missing' ? rest : { ...rest, output: value };
      };
      cell(`T6 stored ${what} output: loadBoundHold refused`, async () => {
        const c = await boundStore('CAPI-S014');
        strip(c);
        c.store.memoryHold = null;
        await expectRefused(c, loadOf(c), 'BOUND_HOLD_INVALID');
      });
      cell(`T6 stored ${what} output: memory-loss reconcile COMMITTED refused`, async () => {
        const c = await boundStore('CAPI-S014');
        strip(c);
        c.store.memoryHold = null;
        await expectRefused(c, reconcileOf(c, M2_OUTCOME.COMMITTED, 'LOST'), 'EVIDENCE_MISMATCH');
      });
      cell(`T6 stored ${what} output: retained COMMITTED reconcile refused`, async () => {
        const c = await boundStore('CAPI-S014');
        strip(c);
        await expectRefused(c, reconcileOf(c, M2_OUTCOME.COMMITTED, 'RETAINED'), 'EVIDENCE_MISMATCH');
      });
      cell(`T6 stored ${what} output: CAPI-S020/S022 repeat refused`, async () => {
        const c = await interrupted('CAPI-S014');
        strip(c);
        await expectRefused(c, reconcileOf(c, M2_OUTCOME.COMMITTED, 'RETAINED'), 'EVIDENCE_MISMATCH');
      });
    }
  });

  describe('T7 regressions kept', () => {
    const s = 'CAPI-S014';
    const LABELS = {
      kind: (e) => ({ ...e, kind: 'APPLICATION_BYTES' }),
      digestLabel: (e) => ({ ...e, digest: bytesOf(32, 0x58) }),
      reference: (e) => ({ ...e, reference: bytesOf(32, 0x59) }),
    };
    for (const [what, f] of Object.entries(LABELS)) {
      cell(`T7 stored escrow ${what} mismatch: memory-loss reconcile refused`, async () => {
        const c = await boundStore(s);
        const g = c.store.generations.get(NEW_GENERATION);
        g.escrow = f(g.escrow);
        c.store.memoryHold = null;
        await expectRefused(c, reconcileOf(c, M2_OUTCOME.COMMITTED, 'LOST'), 'EVIDENCE_MISMATCH');
      });
      cell(`T7 stored escrow ${what} mismatch: retained COMMITTED reconcile refused`, async () => {
        const c = await boundStore(s);
        const g = c.store.generations.get(NEW_GENERATION);
        g.escrow = f(g.escrow);
        await expectRefused(c, reconcileOf(c, M2_OUTCOME.COMMITTED, 'RETAINED'), 'EVIDENCE_MISMATCH');
      });
      cell(`T7 staged escrow ${what} mismatch: runMutation refused`, async () => {
        const c = mutationCase(s, M2_OUTCOME.COMMITTED);
        c.candidate = { ...c.candidate, escrow: f(c.candidate.escrow) };
        await expectRefused(c, runCaseOf(c, M2_OUTCOME.COMMITTED), 'EVIDENCE_MISMATCH');
      });
    }
    const S017_BAD = {
      malformedUtf8: Uint8Array.of(0x72, 0xc3, 0x28),
      empty: new Uint8Array(0),
      units257: TE.encode('r'.repeat(257)),
    };
    for (const [what, bytes] of Object.entries(S017_BAD)) {
      cell(`T7 CAPI-S017 ${what} with a correct HOD: loadBoundHold refused`, async () => {
        const c = await boundStore('CAPI-S017', { output: bytes });
        c.store.memoryHold = null;
        await expectRefused(c, loadOf(c), 'BOUND_HOLD_INVALID');
      });
      cell(`T7 CAPI-S017 ${what} with a correct HOD: memory-loss reconcile keeps the bytes opaque`, async () => {
        const c = await boundStore('CAPI-S017', { output: bytes });
        const r = await reconcileOf(c, M2_OUTCOME.COMMITTED, 'LOST');
        expect(hex(r.output)).toBe(hex(bytes));
      });
    }
  });
});
