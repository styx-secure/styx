// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — owner-only synthetic MDK proof signer for B3.3a.

import { readFileSync, realpathSync, statSync } from 'node:fs';
import { relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { schnorr } from '@noble/curves/secp256k1';

import { B33A_ERROR, B33A_PRIVATE_ROOT, assertHex, failB33a }
  from './b3-3a-canonical.mjs';

export const B33A_MDK_SIGNER_PATH = fileURLToPath(import.meta.url);

function securePrivateFile(path) {
  const root = realpathSync(B33A_PRIVATE_ROOT);
  const candidate = realpathSync(path);
  const rel = relative(root, candidate);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`)
    || !statSync(candidate).isFile() || (statSync(candidate).mode & 0o077) !== 0) {
    failB33a(B33A_ERROR.INVALID, 'MDK proof signer secret is outside its owner-only root');
  }
  return candidate;
}

function main(args) {
  if (args.length !== 3 || args[0] !== '--sign-account-proof') {
    failB33a(B33A_ERROR.INVALID, 'signer requires its exact operation, secret path and event id');
  }
  const [, secretPath, eventIdHex] = args;
  assertHex('account-proof event id', eventIdHex, 32);
  const secretHex = readFileSync(securePrivateFile(secretPath), 'utf8').trim();
  assertHex('account secret', secretHex, 32);
  process.stdout.write(Buffer.from(schnorr.sign(eventIdHex, secretHex)).toString('hex'));
}

if (process.argv[1] === B33A_MDK_SIGNER_PATH) main(process.argv.slice(2));
