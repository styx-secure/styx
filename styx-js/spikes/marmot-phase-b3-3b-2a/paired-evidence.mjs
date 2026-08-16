// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — paired exact-head retained-window evidence.

import { fileURLToPath } from 'node:url';

import { B33A_MDK_PEER_LOCK_SHA256 }
  from '../marmot-phase-b3-3a/b3-3a-mdk-builder.mjs';
import {
  B33B1_APPROVED_ARTIFACT_TUPLE, B33B1_APPROVED_SOURCE_SHA,
  B33B1_APPROVED_SOURCE_TREE,
} from '../marmot-phase-b3-3b-1/verify-pins.mjs';
import {
  B33B2A_CLAIM, B33B2A_FINAL_EPOCH, B33B2A_OPERATION_SEQUENCE,
  B33B2A_REJECTED_DISTANCE, B33B2A_RETAINED_DISTANCES, B33B2A_RETENTION_POLICY,
  failB33b2a,
} from './b3-3b-2a-canonical.mjs';
import { runRetainedWindowProbe } from './retained-window-probe.mjs';

const COMMIT = /^[0-9a-f]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const GROUP_ID = /^[0-9a-f]{32}$/;
const REQUIRED_TRUE_FIELDS = Object.freeze([
  'alternateUpdateAuthors',
  'callerMetadataIgnored',
  'corruptedInWindowRejectedWithoutMutation',
  'futureEpochRejectedWithoutMutation',
  'retainedWindowAcceptedBothDirectionsExactlyOnce',
  'staleWindowRejectedBothDirectionsWithoutMutation',
]);
const REQUIRED_CASE_IDS = Object.freeze([
  'future-mdk-to-styx',
  'future-styx-to-mdk',
  'forged-metadata-styx-to-mdk',
  'corrupt-distance4-mdk-to-styx',
  'corrupt-distance4-styx-to-mdk',
  'distance4-mdk-to-styx',
  'distance4-styx-to-mdk',
  'distance5-mdk-to-styx',
  'distance5-styx-to-mdk',
  'distance6-mdk-to-styx',
  'distance6-styx-to-mdk',
]);

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function blocked(message, details = undefined) {
  failB33b2a('B33B2A_BLOCKED', message, details);
}

export function validateRetainedWindowRun(report, label = 'run') {
  if (!report || typeof report !== 'object') blocked(`${label} report is absent`);
  if (report.artifactSourceCommit !== B33B1_APPROVED_SOURCE_SHA
    || report.artifactSourceTree !== B33B1_APPROVED_SOURCE_TREE
    || !sameJson(report.candidateTuple, B33B1_APPROVED_ARTIFACT_TUPLE)) {
    blocked(`${label} artifact identity drifted`);
  }
  if (!COMMIT.test(report.sourceCommit) || !COMMIT.test(report.sourceTree)
    || !GROUP_ID.test(report.groupIdHex)
    || !DIGEST.test(report.finalGroupContextSha256Hex)
    || !DIGEST.test(report.finalRosterSha256Hex)
    || !DIGEST.test(report.participantSetSha256Hex)) {
    blocked(`${label} source or projection identity is malformed`);
  }
  if (report.finalEpoch !== B33B2A_FINAL_EPOCH
    || report.transitionCount !== 6
    || report.applicationRecordCount < 5
    || report.freshProcessRecoveryCount !== 9
    || report.freshStyxReceiverCount !== 8
    || report.retentionPolicy !== B33B2A_RETENTION_POLICY
    || report.rejectedDistance !== B33B2A_REJECTED_DISTANCE
    || !sameJson(report.retainedDistances, B33B2A_RETAINED_DISTANCES)
    || !sameJson(report.operationSequence, B33B2A_OPERATION_SEQUENCE)
    || REQUIRED_TRUE_FIELDS.some((field) => report[field] !== true)) {
    blocked(`${label} retained-window invariants were not all satisfied`);
  }
  if (!Array.isArray(report.safeCaseEvidence)
    || report.safeCaseEvidence.length !== 11
    || report.safeCaseEvidence.some((record) => !record || typeof record !== 'object'
      || !DIGEST.test(record.ciphertextSha256Hex)
      || !['MDK_TO_STYX', 'STYX_TO_MDK'].includes(record.direction)
      || !['1', '2', '3'].includes(record.messageEpoch)
      || !['1', '7'].includes(record.referenceTipEpoch))
    || !sameJson(report.safeCaseEvidence.map((record) => record.caseId), REQUIRED_CASE_IDS)) {
    blocked(`${label} safe case evidence is incomplete or malformed`);
  }
  if (!/BeyondAppRetention|beyond_app_retention/i.test(
    JSON.stringify(report.mdkDistance6Reason),
  )) {
    blocked(`${label} lacks MDK's typed stale-window reason`);
  }
  const build = report.mdkBuildEvidence;
  if (!build || build.cargoCommand !== 'cargo build --locked --target-dir <fresh-build-child>'
    || build.mdkPeerCargoLockSha256Hex !== B33A_MDK_PEER_LOCK_SHA256
    || !DIGEST.test(build.mdkExecutableSha256Hex)
    || typeof build.cargoVersion !== 'string' || build.cargoVersion.length === 0) {
    blocked(`${label} fresh locked MDK build evidence is invalid`);
  }
  return report;
}

export function validateRetainedWindowPair(firstValue, secondValue) {
  const first = validateRetainedWindowRun(firstValue, 'first run');
  const second = validateRetainedWindowRun(secondValue, 'second run');
  const failures = [];
  if (first.sourceCommit !== second.sourceCommit) failures.push('source commit drift');
  if (first.sourceTree !== second.sourceTree) failures.push('source tree drift');
  if (!sameJson(first.candidateTuple, second.candidateTuple)) failures.push('artifact tuple drift');
  if (first.groupIdHex === second.groupIdHex) failures.push('group reuse');
  if (first.participantSetSha256Hex === second.participantSetSha256Hex) {
    failures.push('participant reuse');
  }
  if (first.finalGroupContextSha256Hex === second.finalGroupContextSha256Hex) {
    failures.push('GroupContext reuse');
  }
  const normalizedCases = (report) => report.safeCaseEvidence.map((record) => ({
    accepted: record.outcome.accepted,
    caseId: record.caseId,
    direction: record.direction,
    distance: record.distance ?? null,
    messageEpoch: record.messageEpoch,
    referenceTipEpoch: record.referenceTipEpoch,
    replayDisposition: record.replayDisposition ?? null,
    type: record.type,
  }));
  if (!sameJson(normalizedCases(first), normalizedCases(second))) {
    failures.push('ordered case verdict drift');
  }
  if (failures.length !== 0) blocked('paired retained-window runs drifted or reused state', {
    failures,
  });
  return Object.freeze({
    artifactSourceCommit: first.artifactSourceCommit,
    artifactSourceTree: first.artifactSourceTree,
    candidateTuple: first.candidateTuple,
    claim: B33B2A_CLAIM,
    operationSequence: first.operationSequence,
    runs: Object.freeze([first, second]),
    sourceCommit: first.sourceCommit,
    sourceTree: first.sourceTree,
  });
}

export async function runPairedRetainedWindowEvidence() {
  const first = await runRetainedWindowProbe();
  const second = await runRetainedWindowProbe();
  return validateRetainedWindowPair(first, second);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) throw new Error('usage: paired-evidence.mjs');
  process.stdout.write(`${JSON.stringify(await runPairedRetainedWindowEvidence())}\n`);
}
