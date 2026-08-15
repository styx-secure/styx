// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — owner-only proof signer for the exact MDK peer.

import { readFileSync, realpathSync, statSync } from 'node:fs';
import { relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { schnorr } from '@noble/curves/secp256k1';

import { B32A_ERROR, B32A_PRIVATE_ROOT, failB32a } from './b3-2a-canonical.mjs';

const scriptPath = fileURLToPath(import.meta.url);

function exactHex(label, value, bytes) {
  if (typeof value !== 'string' || value.length !== bytes * 2 || !/^[0-9a-f]+$/.test(value)) {
    failB32a(B32A_ERROR.INVALID, `${label} is not exact lowercase hexadecimal`);
  }
}

function securePrivateFile(path) {
  const root = realpathSync(B32A_PRIVATE_ROOT);
  const real = realpathSync(path);
  const rel = relative(root, real);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || (statSync(real).mode & 0o077) !== 0) {
    failB32a(B32A_ERROR.INVALID, 'proof signer secret is outside the owner-only B3.2a root');
  }
  return real;
}

if (process.argv[2] === '--sign-account-proof') {
  const [secretPath, eventIdHex] = process.argv.slice(3);
  if (!secretPath || !eventIdHex) throw new Error('proof signer requires secret path and event id');
  exactHex('account-proof event id', eventIdHex, 32);
  const secretHex = readFileSync(securePrivateFile(secretPath), 'utf8').trim();
  exactHex('account secret', secretHex, 32);
  process.stdout.write(Buffer.from(schnorr.sign(eventIdHex, secretHex)).toString('hex'));
}

export const B32A_MDK_SIGNER_PATH = scriptPath;
