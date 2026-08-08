import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import initWasm, * as wasm from '../../vendor/openmls-wasm/openmls_wasm.js';

let initialized;

export async function loadPhaseB1Wasm() {
  initialized ??= initWasm({
    module_or_path: readFileSync(fileURLToPath(
      new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url),
    )),
  });
  await initialized;
  return wasm;
}
