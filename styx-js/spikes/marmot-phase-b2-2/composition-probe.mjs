import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

async function initializedModule(directory, discriminator) {
  const url = pathToFileURL(join(directory, 'openmls_wasm.js'));
  url.searchParams.set('phase-b2-2-composition', discriminator);
  const module = await import(url.href);
  await module.default({ module_or_path: readFileSync(join(directory, 'openmls_wasm_bg.wasm')) });
  return module;
}

function assert(condition, message) {
  if (!condition) throw new Error(`Phase B2.2 composition probe failed: ${message}`);
}

function descriptor(value) {
  if (typeof value === 'function') return `function:${value.length}`;
  return typeof value;
}

function ownSurface(owner) {
  return Object.fromEntries(Object.getOwnPropertyNames(owner).sort().map((name) => {
    const property = Object.getOwnPropertyDescriptor(owner, name);
    if ('value' in property) return [name, descriptor(property.value)];
    return [name, `accessor:${property.get?.length ?? '-'}:${property.set?.length ?? '-'}`];
  }));
}

function wrapperClasses(module) {
  return Object.fromEntries(Object.entries(module).filter(([, value]) => (
    typeof value === 'function'
      && value.prototype
      && Object.getOwnPropertyNames(value.prototype).includes('free')
  )));
}

function classSurface(module) {
  return Object.fromEntries(Object.entries(wrapperClasses(module)).map(([name, value]) => [name, {
    prototype: ownSurface(value.prototype),
    static: ownSurface(value),
  }]));
}

function setDifference(left, right) {
  return [...left].filter((value) => !right.has(value)).sort();
}

function declarationClasses(source) {
  const result = new Map();
  const pattern = /^export class ([A-Za-z0-9_$]+) \{\n([\s\S]*?)^\}$/gm;
  for (const match of source.matchAll(pattern)) {
    result.set(match[1], new Set(match[2].split('\n').map((line) => line.trim()).filter(Boolean)));
  }
  return result;
}

function initMembers(source) {
  const match = source.match(/^export interface InitOutput \{\n([\s\S]*?)^\}$/m);
  assert(match !== null, 'InitOutput exists in generated declarations');
  return new Set(match[1].split('\n').map((line) => line.trim()).filter(Boolean));
}

export async function runCompositionProbe(committedDirectory, candidateDirectory) {
  if (!committedDirectory || !candidateDirectory) {
    throw new Error('committed and candidate WASM directories are required');
  }
const committed = await initializedModule(committedDirectory, 'committed');
const candidate = await initializedModule(candidateDirectory, 'candidate');
const committedDts = readFileSync(join(committedDirectory, 'openmls_wasm.d.ts'), 'utf8');
const candidateDts = readFileSync(join(candidateDirectory, 'openmls_wasm.d.ts'), 'utf8');
const candidateJs = readFileSync(join(candidateDirectory, 'openmls_wasm.js'), 'utf8');

const expectedClasses = [
  'PhaseB2CommitProjection',
  'PhaseB2Group',
  'PhaseB2Identity',
  'PhaseB2KeyPackage',
  'PhaseB2PendingCommit',
  'PhaseB2RatchetTree',
  'PhaseB2StagedCommit',
];
const committedExports = new Set(Object.keys(committed));
const candidateExports = new Set(Object.keys(candidate));
const removedExports = setDifference(committedExports, candidateExports);
const addedExports = setDifference(candidateExports, committedExports);
assert(removedExports.length === 0, `named exports were removed: ${JSON.stringify(removedExports)}`);
assert(
  JSON.stringify(addedExports) === JSON.stringify(expectedClasses),
  `named export delta is not the exact seven B2 classes: ${JSON.stringify(addedExports)}`,
);

const beforeClasses = classSurface(committed);
const afterClasses = classSurface(candidate);
for (const [className, oldClass] of Object.entries(beforeClasses)) {
  assert(className in afterClasses, `retained wrapper class ${className} exists`);
  for (const side of ['static', 'prototype']) {
    assert(
      JSON.stringify(oldClass[side]) === JSON.stringify(afterClasses[className][side]),
      `retained raw ${className}.${side} surface is byte-exact`,
    );
  }
}
assert(
  JSON.stringify(setDifference(new Set(Object.keys(afterClasses)), new Set(Object.keys(beforeClasses))))
    === JSON.stringify(expectedClasses),
  'raw wrapper-class delta is exactly the seven B2 classes',
);

for (const className of expectedClasses) {
  const shape = afterClasses[className];
  assert(shape !== undefined, `${className} has a generated runtime wrapper`);
  assert(shape.prototype.free === 'function:0', `${className} has standard wasm-bindgen ownership`);
  for (const [member, signature] of Object.entries(shape.prototype)) {
    assert(signature !== 'undefined', `${className}.prototype.${member} is typed at runtime`);
  }
}

const committedDeclarations = declarationClasses(committedDts);
const candidateDeclarations = declarationClasses(candidateDts);
for (const [className, oldMembers] of committedDeclarations) {
  const newMembers = candidateDeclarations.get(className);
  assert(newMembers !== undefined, `retained declared class ${className} exists`);
  assert(
    setDifference(oldMembers, newMembers).length === 0
      && setDifference(newMembers, oldMembers).length === 0,
    `retained declaration ${className} is exact`,
  );
}
assert(
  JSON.stringify(setDifference(new Set(candidateDeclarations.keys()), new Set(committedDeclarations.keys())))
    === JSON.stringify(expectedClasses),
  'declaration class delta is exactly the seven B2 classes',
);
for (const className of expectedClasses) {
  const members = candidateDeclarations.get(className);
  assert(members !== undefined && members.size > 2, `${className} has a non-empty TypeScript contract`);
  assert(
    [...members].every((member) => member.includes(':') || member.endsWith(');') || member === 'private constructor();'),
    `${className} contains no untyped declaration member`,
  );
}

const committedInit = initMembers(committedDts);
const candidateInit = initMembers(candidateDts);
const removedInit = setDifference(committedInit, candidateInit);
const addedInit = setDifference(candidateInit, committedInit);
assert(removedInit.length === 0, `raw InitOutput members were removed: ${JSON.stringify(removedInit)}`);
assert(addedInit.length > 0, 'raw InitOutput contains the B2 ABI additions');
assert(
  addedInit.every((member) => (
    member.startsWith('readonly phaseb2')
      || member.startsWith('readonly __wbg_phaseb2')
  )),
  `raw InitOutput contains an undocumented non-B2 addition: ${JSON.stringify(addedInit)}`,
);

const identityWrap = Object.getOwnPropertyDescriptor(candidate.PhaseB2Identity, '__wrap');
assert(identityWrap?.enumerable === false, 'generated PhaseB2Identity.__wrap is non-enumerable');
assert(typeof identityWrap?.value === 'function' && identityWrap.value.length === 1, 'generated PhaseB2Identity.__wrap has exact arity one');
assert(!candidateDts.includes('PhaseB2Identity.__wrap'), 'generated helper is absent from TypeScript declarations');
assert(
  candidateJs.split('PhaseB2Identity.__wrap(').length - 1 === 1,
  'generated JavaScript has one PhaseB2Identity.__wrap call site',
);

const surfaceSnapshot = {
  addedInitOutputMembers: addedInit,
  addedNamedExports: addedExports,
  addedRuntimeClasses: Object.fromEntries(
    expectedClasses.map((className) => [className, afterClasses[className]]),
  ),
  addedTypeScriptDeclarations: Object.fromEntries(
    expectedClasses.map((className) => [className, [...candidateDeclarations.get(className)].sort()]),
  ),
  generatedHelperDelta: {
    'PhaseB2Identity.__wrap': {
      declarationPresent: candidateDts.includes('PhaseB2Identity.__wrap'),
      descriptor: descriptor(identityWrap.value),
      enumerable: identityWrap.enumerable,
      javascriptCallSites: candidateJs.split('PhaseB2Identity.__wrap(').length - 1,
    },
  },
  retainedNamedExportCount: committedExports.size,
};
console.log(JSON.stringify(surfaceSnapshot, null, 2));
console.log('PASS PHASE_B2_2_COMPOSITION_EXACT');
  return surfaceSnapshot;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const committedDirectory = process.argv[2] ?? process.env.B2_COMMITTED_WASM_DIR;
  const candidateDirectory = process.argv[3] ?? process.env.B2_WASM_DIR;
  await runCompositionProbe(committedDirectory, candidateDirectory);
}
