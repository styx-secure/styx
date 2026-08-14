// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — bounded JSONL adapter to the existing exact-pin peer.

import { spawn } from 'node:child_process';
import { readFileSync, realpathSync, statSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { schnorr } from '@noble/curves/secp256k1';

import {
  B32_PRIVATE_ROOT,
  assertHexBytes,
  failB32,
  B32_ERROR,
} from './b3-2-canonical.mjs';

const scriptPath = fileURLToPath(import.meta.url);
const scriptDirectory = dirname(scriptPath);
const defaultBinary = resolve(
  scriptDirectory,
  '..',
  'marmot-phase-b3',
  'mdk-peer',
  'target',
  'debug',
  'styx-b3-mdk-peer',
);
const RPC_TIMEOUT_MS = 60_000;

function exactKeys(value, expected, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    failB32(B32_ERROR.INVALID, `${label} must be an object`);
  }
  const keys = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (keys.length !== wanted.length || keys.some((key, index) => key !== wanted[index])) {
    failB32(B32_ERROR.INVALID, `${label} fields are not exact`);
  }
}

function securePrivateFile(path) {
  const privateRoot = realpathSync(B32_PRIVATE_ROOT);
  const real = realpathSync(path);
  const rel = relative(privateRoot, real);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`)) {
    failB32(B32_ERROR.INVALID, 'proof signer secret escaped the B3.2 private root');
  }
  if ((statSync(real).mode & 0o077) !== 0) {
    failB32(B32_ERROR.INVALID, 'proof signer secret is not owner-only');
  }
  return real;
}

export class MdkB32Peer {
  #child;
  #nextId = 1;
  #pending = new Map();
  #stderr = '';
  #spawnError;

  constructor(binary = defaultBinary) {
    this.#child = spawn(binary, [], { stdio: ['pipe', 'pipe', 'pipe'] });
    const lines = createInterface({ input: this.#child.stdout, crlfDelay: Infinity });
    lines.on('line', (line) => this.#receive(line));
    this.#child.stderr.setEncoding('utf8');
    this.#child.stderr.on('data', (chunk) => {
      this.#stderr = `${this.#stderr}${chunk}`.slice(-8192);
    });
    this.#child.on('error', (error) => {
      this.#spawnError = error;
      for (const pending of this.#pending.values()) pending.reject(error);
      this.#pending.clear();
    });
    this.#child.on('exit', (code, signal) => {
      const error = new Error(`MDK peer exited code=${code} signal=${signal}; stderr=${this.#stderr}`);
      for (const pending of this.#pending.values()) pending.reject(error);
      this.#pending.clear();
    });
  }

  #receive(line) {
    let response;
    try {
      response = JSON.parse(line);
      if (!Number.isSafeInteger(response?.id) || response.id < 1
        || typeof response?.ok !== 'boolean') {
        failB32(B32_ERROR.INVALID, 'MDK response id or disposition is invalid');
      }
      exactKeys(response, ['id', 'ok', response.ok ? 'result' : 'error'], 'MDK response');
    } catch (error) {
      for (const pending of this.#pending.values()) pending.reject(error);
      this.#pending.clear();
      return;
    }
    const pending = this.#pending.get(response.id);
    if (!pending) return;
    this.#pending.delete(response.id);
    clearTimeout(pending.timer);
    if (response.ok) pending.resolve(response.result);
    else {
      const error = new Error(response.error?.message ?? 'MDK peer rejected the request');
      error.code = response.error?.code ?? 'mdk_peer_error';
      error.details = response.error?.details ?? null;
      pending.reject(error);
    }
  }

  request(op, fields = {}) {
    if (this.#spawnError) return Promise.reject(this.#spawnError);
    const id = this.#nextId++;
    return new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`MDK peer timed out during ${op}; stderr=${this.#stderr}`));
      }, RPC_TIMEOUT_MS);
      this.#pending.set(id, { reject, resolve: resolvePromise, timer });
      this.#child.stdin.write(`${JSON.stringify({ ...fields, id, op })}\n`, (error) => {
        if (error) {
          clearTimeout(timer);
          this.#pending.delete(id);
          reject(error);
        }
      });
    });
  }

  async close() {
    if (this.#child.exitCode === null) {
      try { await this.request('checkpoint_and_exit'); } finally { this.#child.stdin.end(); }
    }
  }
}

async function signerMode(args) {
  if (args.length !== 2) throw new Error('proof signer requires secret path and event id');
  const [secretPath, eventIdHex] = args;
  assertHexBytes('account-proof event id', eventIdHex, 32);
  const secretHex = readFileSync(securePrivateFile(secretPath), 'utf8').trim();
  assertHexBytes('account secret', secretHex, 32);
  process.stdout.write(Buffer.from(schnorr.sign(eventIdHex, secretHex)).toString('hex'));
}

if (process.argv[2] === '--sign-account-proof') await signerMode(process.argv.slice(3));

export const B32_MDK_DRIVER_PATH = scriptPath;
export const B32_MDK_DEFAULT_BINARY = defaultBinary;
