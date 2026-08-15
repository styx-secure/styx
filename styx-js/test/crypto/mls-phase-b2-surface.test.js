// Frozen, automatically discovered public surface of the generated B3.2a artifact.
// This intentionally snapshots every export, descriptor, declaration member and
// raw InitOutput member so a future generated addition cannot evade a narrow list.
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const VENDOR = join(HERE, '../../vendor/openmls-wasm');
const PRODUCT_SRC = join(HERE, '../../src');
const EXPECTED_CANONICAL_BYTES = 86893;
const EXPECTED_CANONICAL_SHA256 = '1b3dff1f3f4b7b46af5d1f5c600b5d4a9a2134e33733cf79ece4c50f8598db20';

function valueShape(value) {
  if (typeof value === 'function') return `function:${value.length}`;
  if (value === null) return 'null';
  return typeof value;
}

function descriptorMap(owner) {
  return Object.fromEntries(Object.getOwnPropertyNames(owner).sort().map((name) => {
    const property = Object.getOwnPropertyDescriptor(owner, name);
    const attributes = `${property.enumerable ? 'e' : '-'}${property.configurable ? 'c' : '-'}${property.writable ? 'w' : '-'}`;
    if ('value' in property) return [name, `${attributes}:${valueShape(property.value)}`];
    return [name, `${attributes}:accessor:${property.get?.length ?? '-'}:${property.set?.length ?? '-'}`];
  }));
}

async function discoverGeneratedSurface() {
  const moduleUrl = pathToFileURL(join(VENDOR, 'openmls_wasm.js'));
  moduleUrl.searchParams.set('surface-snapshot', 'stage2-jest');
  const wasmModule = await import(moduleUrl.href);
  const initOutput = await wasmModule.default({
    module_or_path: readFileSync(join(VENDOR, 'openmls_wasm_bg.wasm')),
  });
  const declarations = readFileSync(join(VENDOR, 'openmls_wasm.d.ts'), 'utf8');
  const namedExports = Object.keys(wasmModule).sort();
  const exportShapes = Object.fromEntries(namedExports.map((name) => {
    const value = wasmModule[name];
    if (typeof value !== 'function') return [name, valueShape(value)];
    return [name, {
      function: valueShape(value),
      own: descriptorMap(value),
      prototype: value.prototype ? descriptorMap(value.prototype) : null,
    }];
  }));
  const initOutputMembers = Object.keys(initOutput).sort()
    .map((name) => [name, valueShape(initOutput[name])]);
  const declarationClasses = Object.fromEntries(
    [...declarations.matchAll(/^export class ([A-Za-z0-9_$]+) \{\n([\s\S]*?)^\}$/gm)]
      .map((match) => [match[1], match[2].split('\n').map((line) => line.trim()).filter(Boolean).sort()])
      .sort(([left], [right]) => left.localeCompare(right)),
  );
  const declarationInitOutput = (
    declarations.match(/^export interface InitOutput \{\n([\s\S]*?)^\}$/m)?.[1]
    ?? (() => { throw new Error('InitOutput missing'); })()
  ).split('\n').map((line) => line.trim()).filter(Boolean).sort();
  return {
    declarationClasses,
    declarationInitOutput,
    exportShapes,
    initOutputMembers,
    namedExports,
  };
}

function javascriptFiles(root) {
  const files = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) files.push(...javascriptFiles(path));
    else if (entry.isFile() && /\.(?:js|mjs|cjs)$/.test(entry.name)) files.push(path);
  }
  return files.sort();
}

describe('generated OpenMLS Phase B3.2a surface', () => {
  test('the complete automatically discovered public surface matches the approved snapshot', async () => {
    const canonical = JSON.stringify(await discoverGeneratedSurface());
    expect(Buffer.byteLength(canonical)).toBe(EXPECTED_CANONICAL_BYTES);
    expect(createHash('sha256').update(canonical).digest('hex')).toBe(EXPECTED_CANONICAL_SHA256);
  });

  test('product source does not reference an isolated Phase B probe surface', () => {
    const offenders = javascriptFiles(PRODUCT_SRC)
      .filter((path) => /\b(?:PhaseB2|PhaseB31|PhaseB32)/.test(readFileSync(path, 'utf8')))
      .map((path) => path.slice(PRODUCT_SRC.length + 1));
    expect(offenders).toEqual([]);
  });
});
