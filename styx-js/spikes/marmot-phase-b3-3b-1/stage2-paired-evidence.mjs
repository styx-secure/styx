// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — exact-final-head paired B3.3b-1 evidence runner.

import { fileURLToPath } from 'node:url';

import {
  B33B1_ERROR,
  B33B1_MAX_PAST_EPOCHS,
  failB33b1,
} from './b3-3b-1-canonical.mjs';
import {
  B33B1_STAGE1_OPERATION_SEQUENCE,
  runStage1Probe,
} from './stage1-probe.mjs';
import { B33A_MDK_PEER_LOCK_SHA256 }
  from '../marmot-phase-b3-3a/b3-3a-mdk-builder.mjs';
import {
  B33B1_APPROVED_ARTIFACT_TUPLE,
  B33B1_APPROVED_SOURCE_SHA,
  B33B1_APPROVED_SOURCE_TREE,
} from './verify-pins.mjs';

const DIGEST = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const GROUP_ID = /^[0-9a-f]{32}$/;
const REQUIRED_TRUE_FIELDS = Object.freeze([
  'mdkPreparedCommitRecoveredExactly',
  'styxLocalCommitRetriedExactly',
  'retainedTrafficAcceptedBothDirections',
  'retainedTrafficReplayRejectedBothDirections',
]);

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function blocked(message, details = undefined) {
  failB33b1(B33B1_ERROR.BLOCKED, message, details);
}

export function validateStage2Run(report, label = 'run') {
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
  if (report.finalEpoch !== '3'
    || report.transitionCount !== 2
    || report.applicationRecordCount < 4
    || report.freshProcessRecoveryCount !== 3
    || report.retentionPolicy !== B33B1_MAX_PAST_EPOCHS
    || !sameJson(report.operationSequence, B33B1_STAGE1_OPERATION_SEQUENCE)
    || REQUIRED_TRUE_FIELDS.some((field) => report[field] !== true)) {
    blocked(`${label} bounded GO invariants were not all satisfied`);
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

export function validateStage2Pair(firstValue, secondValue) {
  const first = validateStage2Run(firstValue, 'first run');
  const second = validateStage2Run(secondValue, 'second run');
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
  if (first.finalRosterSha256Hex === second.finalRosterSha256Hex) {
    failures.push('roster reuse');
  }
  if (failures.length !== 0) {
    blocked('paired runs were not exact-head and disjoint', { failures });
  }
  return Object.freeze({
    artifactSourceCommit: first.artifactSourceCommit,
    artifactSourceTree: first.artifactSourceTree,
    candidateTuple: first.candidateTuple,
    claim: 'B3.3b-1 BOUNDED_GO',
    operationSequence: first.operationSequence,
    sourceCommit: first.sourceCommit,
    sourceTree: first.sourceTree,
    runs: Object.freeze([first, second]),
  });
}

export async function runStage2PairedEvidence() {
  const first = await runStage1Probe();
  const second = await runStage1Probe();
  return validateStage2Pair(first, second);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) throw new Error('usage: stage2-paired-evidence.mjs');
  process.stdout.write(`${JSON.stringify(await runStage2PairedEvidence())}\n`);
}
