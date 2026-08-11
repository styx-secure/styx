// STYX_SPIKE_PROTOTYPE — pure same-parent one-Commit branch ordering.

import { B24_REASON } from '../marmot-phase-b2-4/b2-4-canonical.mjs';
import {
  B25_CANDIDATE_STATE,
  B25_DISPOSITION,
  B25_ERROR,
  B25_LIMITS,
  B25_REASON,
  compareCandidates,
  failB25,
} from './b2-5a-canonical.mjs';
import { buildOutcome, parseCandidateEvidence } from './b2-5a-record.mjs';

export function priorityForAuthorization(decision) {
  if (decision?.allowed !== true) {
    failB25(B25_ERROR.INVALID, 'only an authorized candidate has branch priority');
  }
  if (decision.reason === B24_REASON.ALLOW_ADD || decision.reason === B24_REASON.ALLOW_REMOVE) {
    return 0;
  }
  if (decision.reason === B24_REASON.ALLOW_SELF_UPDATE) return 1;
  failB25(B25_ERROR.INVALID, 'authorized operation is outside the bounded ordering');
}

export function selectSameParentCandidate(candidateRecords) {
  if (!Array.isArray(candidateRecords) || candidateRecords.length > B25_LIMITS.maxBatchCommits) {
    failB25(B25_ERROR.INVALID, 'candidate set has an invalid count');
  }
  const authorized = candidateRecords
    .map(parseCandidateEvidence)
    .filter((record) => record.state === B25_CANDIDATE_STATE.AUTHORIZED)
    .sort(compareCandidates);
  for (let index = 1; index < authorized.length; index += 1) {
    if (compareCandidates(authorized[index - 1], authorized[index]) === 0) {
      failB25(B25_ERROR.CORRUPT, 'two candidate records have the same total-order identity');
    }
  }
  return authorized.length === 0 ? null : authorized[0];
}

export function buildResolutionOutcomes(candidateRecords, winner) {
  const records = candidateRecords.map(parseCandidateEvidence)
    .sort((left, right) => left.commitDigestHex.localeCompare(right.commitDigestHex));
  return Object.freeze(records.map((record) => {
    let disposition;
    if (record.state === B25_CANDIDATE_STATE.AUTHORIZED) {
      disposition = record.commitDigestHex === winner?.commitDigestHex
        ? B25_DISPOSITION.SELECTED : B25_DISPOSITION.LOSING;
    } else if (record.state === B25_CANDIDATE_STATE.REJECTED) {
      disposition = B25_DISPOSITION.REJECTED;
    } else if (record.state === B25_CANDIDATE_STATE.NOT_CANDIDATE) {
      disposition = B25_DISPOSITION.NOT_CANDIDATE;
    } else {
      failB25(B25_ERROR.STATE_CONFLICT, B25_REASON.PENDING);
    }
    return buildOutcome({
      commitDigestHex: record.commitDigestHex,
      disposition,
      candidateEvidenceDigestHex: record.evidenceDigestHex,
    });
  }));
}
