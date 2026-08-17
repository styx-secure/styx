import { describe, expect, test } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  canonicalJson,
  runCharacterization,
  validateEnvelope,
} from './c0-characterization-runner.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../../..');
const CORPUS = resolve(ROOT, 'conformance/application-protocol/c0-characterization/cases.json');
const REPORT = resolve(ROOT, 'conformance/application-protocol/c0-characterization/report.json');
const SCHEMA = resolve(ROOT, 'conformance/application-protocol/c0-characterization/schema.json');

describe('C0 JavaScript characterization lane', () => {
  test('regenerates the exact committed JavaScript envelope', async () => {
    const schema = JSON.parse(readFileSync(SCHEMA, 'utf8'));
    const report = JSON.parse(readFileSync(REPORT, 'utf8'));
    const envelope = await runCharacterization(CORPUS);

    validateEnvelope(envelope, schema);
    expect(canonicalJson(envelope)).toBe(
      canonicalJson(report.runtimeEnvelopes.javascript)
    );
  });
});
