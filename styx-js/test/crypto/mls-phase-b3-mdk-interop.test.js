// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, test } from '@jest/globals';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import {
  B3_FORMAT,
  B3_PRIVATE_ROOT,
  B3_RUN_ROOT,
  B3_VERSION,
  canonicalJson,
  sha256,
  validateCapabilityNoGoReport,
  validateTranscript,
} from '../../spikes/marmot-phase-b3/b3-canonical.mjs';

function transcriptRecord(evidence, operation, sequence, previousRecordSha256) {
  const record = { evidence, operation, previousRecordSha256, sequence };
  return Object.freeze({ ...record, recordSha256: sha256(canonicalJson(record)) });
}

function syntheticCapabilityNoGo(head) {
  return {
    acceptedBeforeBoundary: {
      styxDurableRestart: true,
      styxKeyPackageParsedByItsPublicCurrentProfileReader: true,
      styxKeyPackageSha256: 'a'.repeat(64),
    },
    claim: 'B3 did not establish Styx/MDK interoperability at the tested pins.',
    compatibilityEstablished: false,
    disposition: 'NO-GO',
    firstIncompatibleOperation: 'mdk_create_group_from_styx_key_package',
    format: B3_FORMAT,
    pinnedNormativeRule: { mdk: 'required 0x8001', styx: 'advertised no 0x8001' },
    rejectedValue: {
      componentIdDecimal: 0x8001,
      componentIdHex: '8001',
      keyPackageSha256: 'a'.repeat(64),
      kind: 'missing_required_application_component',
    },
    remedyOutsideContract: 'The frozen artifact cannot change in Issue #165.',
    smallestHypotheticalRemedy: 'Add 0x8001 under a separately approved baseline.',
    testedPins: {},
    transcriptHeadSha256: head,
    typedOutcomes: {
      mdk: {
        code: 'mdk_missing_required_capabilities',
        details: { missing_app_components: [0x8001] },
      },
      styx: {
        code: 'STYX_KEY_PACKAGE_MISSING_MDK_REQUIRED_GROUP_PROFILE_COMPONENT',
      },
    },
    version: B3_VERSION,
  };
}

function loadRun(name) {
  const directory = resolve(B3_RUN_ROOT, name);
  return {
    report: JSON.parse(readFileSync(resolve(directory, 'report.json'), 'utf8')),
    transcript: JSON.parse(readFileSync(resolve(directory, 'transcript.json'), 'utf8')),
  };
}

function evidenceKeys(value, result = []) {
  if (Array.isArray(value)) {
    for (const item of value) evidenceKeys(item, result);
  } else if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      result.push(key);
      evidenceKeys(item, result);
    }
  }
  return result;
}

describe('Phase B3 exact-pin MDK interoperability evidence', () => {
  test('hash-linked transcript validation fails closed on mutation', () => {
    const first = transcriptRecord({ pin: 'exact' }, 'verify_pins', 1, '0'.repeat(64));
    const second = transcriptRecord({ result: 'typed rejection' }, 'probe', 2, first.recordSha256);
    expect(validateTranscript([first, second])).toBe(second.recordSha256);

    const mutated = JSON.parse(JSON.stringify([first, second]));
    mutated[0].evidence.pin = 'drifted';
    expect(() => validateTranscript(mutated)).toThrow('transcript record digest mismatch');
  });

  test('the bounded report cannot be reinterpreted as compatibility', () => {
    const transcript = [transcriptRecord({}, 'probe', 1, '0'.repeat(64))];
    const head = validateTranscript(transcript);
    const report = syntheticCapabilityNoGo(head);
    expect(validateCapabilityNoGoReport(report, head)).toBe(report);

    expect(() => validateCapabilityNoGoReport(
      { ...report, compatibilityEstablished: true },
      head,
    )).toThrow('must fail closed as NO-GO');
  });

  test('paired exact runs, when present, reproduce the same first incompatibility', () => {
    const runAExists = existsSync(resolve(B3_RUN_ROOT, 'run-a', 'report.json'));
    const runBExists = existsSync(resolve(B3_RUN_ROOT, 'run-b', 'report.json'));
    expect(runAExists).toBe(runBExists);
    if (!runAExists) return;

    const runs = [loadRun('run-a'), loadRun('run-b')];
    for (const { report, transcript } of runs) {
      const head = validateTranscript(transcript);
      validateCapabilityNoGoReport(report, head);
      expect(report.rejectedValue.componentIdDecimal).toBe(0x8001);
      expect(report.typedOutcomes.mdk.details.missing_app_components).toEqual([0x8001]);
      const publicEvidenceKeys = evidenceKeys({ report, transcript });
      for (const forbiddenKey of [
        'databaseKey',
        'database_key',
        'privateKey',
        'providerSnapshot',
        'signerSecret',
      ]) expect(publicEvidenceKeys).not.toContain(forbiddenKey);
    }
    expect(runs[0].report.firstIncompatibleOperation)
      .toBe(runs[1].report.firstIncompatibleOperation);
    expect(runs[0].report.rejectedValue.kind).toBe(runs[1].report.rejectedValue.kind);
    expect(runs[0].report.rejectedValue.keyPackageSha256)
      .not.toBe(runs[1].report.rejectedValue.keyPackageSha256);
    expect(existsSync(resolve(B3_PRIVATE_ROOT, 'run-a'))).toBe(false);
    expect(existsSync(resolve(B3_PRIVATE_ROOT, 'run-b'))).toBe(false);
  });
});
