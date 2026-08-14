// SPDX-License-Identifier: AGPL-3.0-or-later

import { schnorr } from '@noble/curves/secp256k1';
import { spawn } from 'node:child_process';
import { readFileSync, realpathSync, statSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  B31_PRIVATE_ROOT,
  assertExactKeys,
  assertLowerHex,
} from './b3-1-canonical.mjs';

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
const RPC_TIMEOUT_MS = 30_000;

function securePrivateFile(path) {
  const privateRoot = realpathSync(B31_PRIVATE_ROOT);
  const real = realpathSync(path);
  const rel = relative(privateRoot, real);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`)) {
    throw new Error('proof signer secret escaped the approved B3.1 private root');
  }
  const mode = statSync(real).mode & 0o777;
  if ((mode & 0o077) !== 0) throw new Error('proof signer secret is not owner-only');
  return real;
}

export class MdkB31Peer {
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
      const error = new Error(`MDK peer exited code=${code} signal=${signal}`);
      for (const pending of this.#pending.values()) pending.reject(error);
      this.#pending.clear();
    });
  }

  #receive(line) {
    let response;
    try {
      response = JSON.parse(line);
      assertExactKeys(response, ['id', 'ok', response.ok ? 'result' : 'error'], 'MDK response');
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
    const request = { id, op, ...fields };
    return new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`MDK peer timed out during ${op}; stderr=${this.#stderr}`));
      }, RPC_TIMEOUT_MS);
      this.#pending.set(id, { reject, resolve: resolvePromise, timer });
      this.#child.stdin.write(`${JSON.stringify(request)}\n`, (error) => {
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
      try {
        await this.request('checkpoint_and_exit');
      } finally {
        this.#child.stdin.end();
      }
    }
  }
}

async function signerMode(args) {
  if (args.length !== 2) throw new Error('proof signer requires secret path and event id');
  const [secretPath, eventIdHex] = args;
  assertLowerHex(eventIdHex, 32, 'event id');
  const secret = readFileSync(securePrivateFile(secretPath), 'utf8').trim();
  assertLowerHex(secret, 32, 'account secret');
  const signature = schnorr.sign(eventIdHex, secret);
  process.stdout.write(Buffer.from(signature).toString('hex'));
}

if (process.argv[2] === '--sign-account-proof') {
  await signerMode(process.argv.slice(3));
}

export const B31_MDK_DRIVER_PATH = scriptPath;
export const B31_MDK_DEFAULT_BINARY = defaultBinary;
