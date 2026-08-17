import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import {
  canonicalJson,
  validateEnvelope,
} from '../../../styx-js/test/interop/c0-characterization-runner.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../../..');
const CASES = join(HERE, 'cases.json');
const EXPECTED = join(HERE, 'expected-classifications.json');
const REPORT = join(HERE, 'report.json');
const SCHEMA = join(HERE, 'schema.json');
const JS_RUNNER = join(ROOT, 'styx-js/test/interop/c0-characterization-runner.mjs');
const DART_RUNNER = join(ROOT, 'test_integration/bin/c0_characterization.dart');
const EXPECTED_BASES = new Set(['hypothesis-driven', 'observational-baseline']);
const EXPECTED_CLASSIFICATIONS = new Set(['MATCH', 'DIVERGENCE', 'UNSUPPORTED']);

function adapterEnvironment() {
  return {
    ...process.env,
    LANG: 'C',
    LC_ALL: 'C',
    TZ: 'UTC',
  };
}

function run(executable, args) {
  const result = spawnSync(executable, args, {
    cwd: ROOT,
    encoding: 'utf8',
    shell: false,
    env: adapterEnvironment(),
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0 || result.signal !== null) {
    const code = result.error?.code ?? result.status ?? result.signal ?? 'unknown';
    throw new Error(`ADAPTER_PROCESS_FAILED:${executable}:${code}`);
  }
  if (result.stderr !== '') throw new Error(`ADAPTER_STDERR_NOT_EMPTY:${executable}`);
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new Error(`ADAPTER_STDOUT_NOT_JSON:${executable}`);
  }
}

function assertExactIds(envelope, caseIds) {
  const actual = envelope.observations.map((observation) => observation.caseId);
  if (canonicalJson(actual) !== canonicalJson(caseIds)) {
    throw new Error(`CASE_ID_ORDER_MISMATCH:${envelope.runtime}`);
  }
  if (new Set(actual).size !== actual.length) {
    throw new Error(`CASE_ID_DUPLICATE:${envelope.runtime}`);
  }
}

function assertCorpusAndExpectationIdentity(corpus, expected) {
  if (!Array.isArray(corpus.cases)) throw new Error('CORPUS_CASES_NOT_ARRAY');
  const caseIds = corpus.cases.map((testCase) => testCase?.id);
  if (caseIds.some((caseId) => typeof caseId !== 'string')) {
    throw new Error('CORPUS_CASE_ID_INVALID');
  }
  if (new Set(caseIds).size !== caseIds.length) {
    throw new Error('CORPUS_CASE_ID_DUPLICATE');
  }
  if (expected.schemaVersion !== corpus.schemaVersion || expected.baseSha !== corpus.baseSha) {
    throw new Error('EXPECTATION_IDENTITY_MISMATCH');
  }
  if (!Array.isArray(expected.expectations)) {
    throw new Error('EXPECTATIONS_NOT_ARRAY');
  }
  if (expected.expectations.length !== caseIds.length) {
    throw new Error('EXPECTATION_CARDINALITY');
  }

  const knownIds = new Set(caseIds);
  const expectationIds = [];
  const seen = new Set();
  for (const expectation of expected.expectations) {
    const caseId = expectation?.caseId;
    if (typeof caseId !== 'string') throw new Error('EXPECTATION_CASE_ID_INVALID');
    if (seen.has(caseId)) throw new Error(`EXPECTATION_DUPLICATE:${caseId}`);
    if (!knownIds.has(caseId)) throw new Error(`EXPECTATION_UNKNOWN:${caseId}`);
    if (!EXPECTED_CLASSIFICATIONS.has(expectation.classification)) {
      throw new Error(`EXPECTATION_CLASSIFICATION_INVALID:${caseId}`);
    }
    if (!EXPECTED_BASES.has(expectation.basis)) {
      throw new Error(`EXPECTATION_BASIS_INVALID:${caseId}`);
    }
    if (typeof expectation.reason !== 'string' || expectation.reason.length === 0) {
      throw new Error(`EXPECTATION_REASON_INVALID:${caseId}`);
    }
    seen.add(caseId);
    expectationIds.push(caseId);
  }
  if (canonicalJson(expectationIds) !== canonicalJson(caseIds)) {
    throw new Error('EXPECTATION_CASE_ID_ORDER_MISMATCH');
  }
  return caseIds;
}

function classify(dartObservation, javascriptObservation) {
  if (dartObservation.status === 'UNSUPPORTED' || javascriptObservation.status === 'UNSUPPORTED') {
    return 'UNSUPPORTED';
  }
  const dartSemanticRecord = {
    status: dartObservation.status,
    value: dartObservation.value,
    reasonCode: dartObservation.reasonCode,
  };
  const javascriptSemanticRecord = {
    status: javascriptObservation.status,
    value: javascriptObservation.value,
    reasonCode: javascriptObservation.reasonCode,
  };
  return canonicalJson(dartSemanticRecord) === canonicalJson(javascriptSemanticRecord)
    ? 'MATCH'
    : 'DIVERGENCE';
}

function generateReport() {
  const corpusBytes = readFileSync(CASES);
  const corpus = JSON.parse(corpusBytes.toString('utf8'));
  const expected = JSON.parse(readFileSync(EXPECTED, 'utf8'));
  const schema = JSON.parse(readFileSync(SCHEMA, 'utf8'));
  const caseIds = assertCorpusAndExpectationIdentity(corpus, expected);
  const independentlyComputedCasesSha256 = createHash('sha256')
    .update(corpusBytes)
    .digest('hex');
  const javascriptEnvelope = run(process.execPath, [JS_RUNNER, CASES]);
  const dartEnvelope = run('dart', ['run', DART_RUNNER, CASES]);

  validateEnvelope(javascriptEnvelope, schema);
  validateEnvelope(dartEnvelope, schema);

  if (dartEnvelope.baseSha !== corpus.baseSha || javascriptEnvelope.baseSha !== corpus.baseSha) {
    throw new Error('BASE_SHA_MISMATCH');
  }
  if (
    dartEnvelope.casesSha256 !== independentlyComputedCasesSha256 ||
    javascriptEnvelope.casesSha256 !== independentlyComputedCasesSha256
  ) {
    throw new Error('CORPUS_DIGEST_MISMATCH');
  }

  assertExactIds(dartEnvelope, caseIds);
  assertExactIds(javascriptEnvelope, caseIds);

  const expectationById = new Map(
    expected.expectations.map((expectation) => [expectation.caseId, expectation])
  );
  const counts = { MATCH: 0, DIVERGENCE: 0, UNSUPPORTED: 0 };
  const classifications = corpus.cases.map((testCase, index) => {
    const dartObservation = dartEnvelope.observations[index];
    const javascriptObservation = javascriptEnvelope.observations[index];
    const classification = classify(dartObservation, javascriptObservation);
    const expectation = expectationById.get(testCase.id);
    if (!expectation) throw new Error(`EXPECTATION_MISSING:${testCase.id}`);
    if (classification !== expectation.classification) {
      throw new Error(
        `CLASSIFICATION_DRIFT:${testCase.id}:${expectation.classification}:${classification}`
      );
    }
    counts[classification] += 1;
    return {
      caseId: testCase.id,
      category: testCase.category,
      basis: expectation.basis,
      classification,
      expectationReason: expectation.reason,
      unspecifiedBehaviour: testCase.unspecifiedBehaviour,
      unspecifiedReason: testCase.unspecifiedReason,
      dart: dartObservation,
      javascript: javascriptObservation,
    };
  });

  return {
    schemaVersion: '1',
    baseSha: corpus.baseSha,
    casesSha256: dartEnvelope.casesSha256,
    runtimeEnvelopes: {
      dart: dartEnvelope,
      javascript: javascriptEnvelope,
    },
    classifications,
    summary: {
      match: String(counts.MATCH),
      divergence: String(counts.DIVERGENCE),
      unsupported: String(counts.UNSUPPORTED),
      total: String(classifications.length),
    },
    staleMetadataFindings: [
      {
        id: 'LEGACY_HLC_COUNTER_RADIX',
        status: 'DISPROVEN',
        source: 'test_integration/vectors/dart_vectors.json:_incompatibilities.hlcCounter',
        evidence: 'The current JavaScript HLC renderer uses decimal Number.toString() rather than hexadecimal output.',
      },
    ],
    staleMetadataScope: {
      assessedLegacyEntries: ['hlcCounter'],
      remainingLegacyEntries: 'OUT_OF_SCOPE_FOR_C0_1',
    },
  };
}

const mode = process.argv[2];
if (!['--check', '--write'].includes(mode) || process.argv.length !== 3) {
  throw new Error('USAGE:compare.mjs <--check|--write>');
}

const generated = canonicalJson(generateReport());
if (mode === '--write') {
  writeFileSync(REPORT, generated, { encoding: 'utf8', flag: 'w' });
} else {
  const committed = readFileSync(REPORT, 'utf8');
  if (committed !== generated) throw new Error('REPORT_BYTES_DRIFT');
}
