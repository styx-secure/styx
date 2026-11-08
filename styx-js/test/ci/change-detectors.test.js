// change-detectors.test.js — the path-aware change detectors of the three
// workflows whose aggregate gates may green-skip (ci.yml, styx-js-web.yml,
// wasm-integrity.yml).
//
// The test does not copy the detectors: it extracts the complete `run:` script
// of each workflow's change-detection step and executes it with bash, exactly
// as written, against a stub `git` that prints a chosen changed-file list. It
// fails unless it finds exactly the seven known detector conditions with their
// regular expressions unchanged.
//
// Required behaviour:
//   - a protected path yields `true` wherever it appears in the list, also when
//     the list is far larger than a pipe buffer (an early `grep -q` exit must
//     never turn a match into `false`);
//   - lists with only unprotected paths, and the empty list, yield `false`;
//   - an error of the list producer or of grep (for example an invalid regular
//     expression) fails the step instead of yielding `false`.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const WORKFLOWS = fileURLToPath(new URL('../../../.github/workflows/', import.meta.url));

// The seven detector regular expressions, byte for byte, per workflow, in
// source order. Any edit to a detector expression must update this table.
const EXPECTED = {
  'ci.yml': {
    stepId: 'filter',
    flags: ['dart'],
    eres: [
      "^(packages/|test_integration/|pubspec\\.ya?ml|pubspec\\.lock|melos\\.ya?ml|analysis_options\\.yaml|tool/|\\.github/workflows/ci\\.yml)",
    ],
  },
  'styx-js-web.yml': {
    stepId: 'f',
    flags: ['web', 'vaultdb'],
    eres: [
      "^styx-js/|^\\.github/workflows/styx-js-web\\.yml",
      "^styx-js/src/crypto/|^styx-js/src/storage/|^styx-js/src/config/|^styx-js/src/chat/styx-chat\\.js|^styx-js/src/utils\\.js|^styx-js/test/crypto/vault|^styx-js/test/storage/vault|^styx-js/test/chat/styx-chat(-invite-nonce)?\\.test\\.js|^styx-js/test/support/|^styx-js/test/fixtures/vault|^styx-js/test/fixtures/mls-state-v1/|^styx-js/playwright\\.vault[^/]*\\.config\\.js|^styx-js/apps/chat/src/(App\\.jsx|components/InstallHint\\.jsx|hooks/useStyxChat\\.js|lib/(settings|vault)[^/]*\\.js)|^styx-js/apps/chat/(e2e/vault-(settings|identity)\\.spec\\.js|playwright\\.vault-(settings|identity)\\.config\\.js|vite\\.config\\.js)|^styx-js/vendor/styx-kdf-wasm/|^styx-js/package-lock\\.json|^\\.github/workflows/styx-js-web\\.yml",
    ],
  },
  'wasm-integrity.yml': {
    stepId: 'f',
    flags: ['crate', 'light', 'kdf', 'kdflight'],
    eres: [
      "^styx-js/vendor/openmls-wasm/(patch/|build\\.sh|verify\\.sh|Cargo\\.lock|PROVENANCE\\.md|openmls_wasm(_bg)?\\.(wasm|js)|.*\\.d\\.ts|package\\.json)",
      "^styx-js/src/(crypto/mls/|chat/)|^\\.github/workflows/wasm-integrity\\.yml",
      "^styx-js/vendor/styx-kdf-wasm/",
      "^styx-js/src/crypto/kdf-bounds\\.js|^styx-js/test/crypto/kdf-|^styx-js/test/fixtures/kdf-|^styx-js/playwright\\.kdf\\.config\\.js|^\\.github/workflows/wasm-integrity\\.yml",
    ],
  },
};

/** Extract the `run: |` block of step `- id: <stepId>` (first occurrence). */
function extractStepScript(workflow, stepId) {
  const lines = readFileSync(join(WORKFLOWS, workflow), 'utf8').split('\n');
  const idIdx = lines.findIndex((l) => l.trim() === `- id: ${stepId}`);
  if (idIdx < 0) throw new Error(`${workflow}: step id ${stepId} not found`);
  const stepIndent = lines[idIdx].indexOf('-');
  let runIdx = -1;
  for (let i = idIdx + 1; i < lines.length; i++) {
    const indent = lines[i].search(/\S/);
    if (indent >= 0 && indent <= stepIndent) break; // next step or job
    if (lines[i].trim() === 'run: |') { runIdx = i; break; }
  }
  if (runIdx < 0) throw new Error(`${workflow}: run block of step ${stepId} not found`);
  const runIndent = lines[runIdx].search(/\S/);
  const body = [];
  for (let i = runIdx + 1; i < lines.length; i++) {
    const indent = lines[i].search(/\S/);
    if (indent >= 0 && indent <= runIndent) break;
    body.push(lines[i]);
  }
  while (body.length && body[body.length - 1].trim() === '') body.pop();
  const blockIndent = Math.min(...body.filter((l) => l.trim()).map((l) => l.search(/\S/)));
  return body.map((l) => l.slice(blockIndent)).join('\n') + '\n';
}

const SCRIPTS = Object.fromEntries(
  Object.entries(EXPECTED).map(([wf, { stepId }]) => [wf, extractStepScript(wf, stepId)]),
);

/** Detector conditions: every `grep -qE '<ERE>'` in the change-detection scripts. */
const detectorEres = (script) => [...script.matchAll(/grep -qE '([^']*)'/g)].map((m) => m[1]);

let dir;
let fakeBin;
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'styx-change-detectors-'));
  fakeBin = join(dir, 'bin');
  execFileSync('mkdir', ['-p', fakeBin]);
  // Stub git: base commit always present; `git diff --name-only` prints the
  // chosen list, or fails like a broken producer when FAKE_GIT_DIFF_FAIL is set.
  writeFileSync(
    join(fakeBin, 'git'),
    [
      '#!/usr/bin/env bash',
      'case "$1" in',
      '  cat-file) exit 0 ;;',
      '  diff)',
      '    if [ -n "${FAKE_GIT_DIFF_FAIL:-}" ]; then echo "fatal: bad revision" >&2; exit "$FAKE_GIT_DIFF_FAIL"; fi',
      '    cat "$FAKE_CHANGED_FILE" ;;',
      '  *) echo "unexpected git $*" >&2; exit 99 ;;',
      'esac',
      '',
    ].join('\n'),
  );
  chmodSync(join(fakeBin, 'git'), 0o755);
});
afterAll(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
});

let seq = 0;
/**
 * Run the extracted change-detection script of `workflow` as a push event
 * whose changed files are `names`. Returns {code, outputs, stderr}.
 */
function detect(workflow, names, { script = SCRIPTS[workflow], diffFail } = {}) {
  const n = seq++;
  const scriptFile = join(dir, `step-${n}.sh`);
  const listFile = join(dir, `changed-${n}.txt`);
  const outFile = join(dir, `output-${n}.txt`);
  writeFileSync(scriptFile, script);
  writeFileSync(listFile, names.length ? names.join('\n') + '\n' : '');
  writeFileSync(outFile, '');
  const env = {
    PATH: `${fakeBin}:${process.env.PATH}`,
    EVENT: 'push',
    BASE_REF: '',
    MERGE_GROUP_BASE_SHA: '',
    BEFORE: 'a'.repeat(40),
    GITHUB_OUTPUT: outFile,
    FAKE_CHANGED_FILE: listFile,
    ...(diffFail ? { FAKE_GIT_DIFF_FAIL: String(diffFail) } : {}),
  };
  let code = 0;
  let stderr = '';
  try {
    // Same invocation GitHub uses for `shell: bash`.
    execFileSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', scriptFile], {
      env,
      encoding: 'utf8',
      stdio: ['ignore', 'ignore', 'pipe'],
    });
  } catch (e) {
    code = e.status ?? -1;
    stderr = String(e.stderr ?? '');
  }
  const outputs = {};
  for (const line of readFileSync(outFile, 'utf8').split('\n')) {
    const eq = line.indexOf('=');
    if (eq > 0) outputs[line.slice(0, eq)] = line.slice(eq + 1);
  }
  return { code, outputs, stderr };
}

const allFalse = (workflow) => Object.fromEntries(EXPECTED[workflow].flags.map((f) => [f, 'false']));

// One protected path per detector, with the outputs it must produce.
const CASES = [
  { detector: 'dart', workflow: 'ci.yml', path: 'packages/styx/lib/a.dart', expect: { dart: 'true' } },
  { detector: 'web', workflow: 'styx-js-web.yml', path: 'styx-js/README.md', expect: { web: 'true', vaultdb: 'false' } },
  { detector: 'vaultdb', workflow: 'styx-js-web.yml', path: 'styx-js/src/crypto/a.js', expect: { web: 'true', vaultdb: 'true' } },
  {
    detector: 'crate', workflow: 'wasm-integrity.yml', path: 'styx-js/vendor/openmls-wasm/patch/lib.rs',
    expect: { crate: 'true', light: 'true', kdf: 'false', kdflight: 'false' },
  },
  {
    detector: 'light', workflow: 'wasm-integrity.yml', path: 'styx-js/src/chat/a.js',
    expect: { crate: 'false', light: 'true', kdf: 'false', kdflight: 'false' },
  },
  {
    detector: 'kdf', workflow: 'wasm-integrity.yml', path: 'styx-js/vendor/styx-kdf-wasm/a.wasm',
    expect: { crate: 'false', light: 'false', kdf: 'true', kdflight: 'true' },
  },
  {
    detector: 'kdflight', workflow: 'wasm-integrity.yml', path: 'styx-js/test/crypto/kdf-a.test.js',
    expect: { crate: 'false', light: 'false', kdf: 'false', kdflight: 'true' },
  },
];

// 2 000 unprotected paths sorting after every protected one (~190 KB, far
// beyond a 64 KiB pipe buffer).
const FILLER = Array.from({ length: 2000 }, (_, i) => `zz/${'x'.repeat(80)}/${String(i).padStart(5, '0')}.md`);

describe('CI change detectors: the seven real conditions are found unchanged', () => {
  test('exactly seven detector conditions, regular expressions byte for byte', () => {
    const found = Object.entries(SCRIPTS).flatMap(([wf, s]) => detectorEres(s).map((ere) => [wf, ere]));
    expect(found).toHaveLength(7);
    for (const [wf, { eres }] of Object.entries(EXPECTED)) {
      expect(detectorEres(SCRIPTS[wf])).toEqual(eres);
    }
  });

  test.each(Object.keys(EXPECTED))('%s: step keeps set -euo pipefail and uses no expressions', (wf) => {
    expect(SCRIPTS[wf].split('\n')[0]).toBe('set -euo pipefail');
    expect(SCRIPTS[wf]).not.toContain('${{');
  });

  test('FILLER is larger than a pipe buffer and matches no detector', () => {
    expect(FILLER.join('\n').length).toBeGreaterThan(2 * 65536);
    expect(detect('ci.yml', FILLER).outputs).toEqual(allFalse('ci.yml'));
  });
});

describe('CI change detectors: a protected path is never reported as unchanged', () => {
  test.each(CASES)('$detector: protected path first + 2 000 later paths → $expect', ({ workflow, path, expect: want }) => {
    const r = detect(workflow, [path, ...FILLER]);
    expect(r.code).toBe(0);
    expect(r.outputs).toEqual(want);
  });

  test.each(CASES)('$detector: repeated 20 times with the large list, always the same flags', ({ workflow, path, expect: want }) => {
    for (let k = 0; k < 20; k++) {
      const r = detect(workflow, [path, ...FILLER]);
      expect({ k, code: r.code, outputs: r.outputs }).toEqual({ k, code: 0, outputs: want });
    }
  });

  test.each(CASES)('$detector: short list → $expect', ({ workflow, path, expect: want }) => {
    const r = detect(workflow, [path, 'docs/readme.md']);
    expect(r.code).toBe(0);
    expect(r.outputs).toEqual(want);
  });

  test.each(CASES)('$detector: protected path in the middle of the large list', ({ workflow, path, expect: want }) => {
    const r = detect(workflow, [...FILLER.slice(0, 1000), path, ...FILLER.slice(1000)]);
    expect(r.code).toBe(0);
    expect(r.outputs).toEqual(want);
  });

  test.each(CASES)('$detector: protected path last in the large list', ({ workflow, path, expect: want }) => {
    const r = detect(workflow, [...FILLER, path]);
    expect(r.code).toBe(0);
    expect(r.outputs).toEqual(want);
  });
});

describe('CI change detectors: unprotected and empty lists', () => {
  test.each(Object.keys(EXPECTED))('%s: only unprotected paths (short and large) → every flag false', (wf) => {
    for (const names of [['docs/readme.md', 'zz/a.md'], FILLER]) {
      const r = detect(wf, names);
      expect(r.code).toBe(0);
      expect(r.outputs).toEqual(allFalse(wf));
    }
  });

  test.each(Object.keys(EXPECTED))('%s: empty change list → every flag false', (wf) => {
    const r = detect(wf, []);
    expect(r.code).toBe(0);
    expect(r.outputs).toEqual(allFalse(wf));
  });
});

describe('CI change detectors: errors fail the step, never yield false', () => {
  test.each(Object.keys(EXPECTED))('%s: failing list producer → step fails, no flag written', (wf) => {
    const r = detect(wf, ['docs/readme.md'], { diffFail: 3 });
    expect(r.code).not.toBe(0);
    expect(r.outputs).toEqual({});
  });

  const detectors = Object.entries(EXPECTED).flatMap(([wf, { flags, eres }]) =>
    eres.map((ere, i) => ({ workflow: wf, detector: flags[i], ere })),
  );
  test.each(detectors)('$detector: invalid regular expression → step fails, $detector not written', ({ workflow, detector, ere }) => {
    const script = SCRIPTS[workflow];
    const needle = `grep -qE '${ere}'`;
    const at = script.indexOf(needle);
    expect(at).toBeGreaterThanOrEqual(0);
    const broken = script.slice(0, at) + "grep -qE '('" + script.slice(at + needle.length);
    for (const names of [['docs/readme.md'], FILLER]) {
      const r = detect(workflow, names, { script: broken });
      expect(r.code).not.toBe(0);
      expect(r.outputs[detector]).toBeUndefined();
    }
  });
});
