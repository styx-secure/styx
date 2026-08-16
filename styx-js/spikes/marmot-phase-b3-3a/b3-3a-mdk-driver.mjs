// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — strict fresh-process boundary for the pinned MDK peer.

import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { B33A_ERROR } from './b3-3a-canonical.mjs';

const directory = dirname(fileURLToPath(import.meta.url));
const DEFAULT_BINARY = resolve(
  directory, '..', 'marmot-phase-b3', 'mdk-peer', 'target', 'debug', 'styx-b3-mdk-peer',
);
const RPC_TIMEOUT_MS = 60_000;

function exactFields(value, fields, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} is not an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length
    || actual.some((field, index) => field !== expected[index])) {
    throw new Error(`${label} fields are not exact`);
  }
}

export class MdkB33aProcess {
  #child;
  #nextId = 1;
  #pending = new Map();
  #stderr = '';
  #spawnError;

  constructor(binary = DEFAULT_BINARY) {
    this.#child = spawn(binary, [], { stdio: ['pipe', 'pipe', 'pipe'] });
    createInterface({ input: this.#child.stdout, crlfDelay: Infinity })
      .on('line', (line) => this.#receive(line));
    this.#child.stderr.setEncoding('utf8');
    this.#child.stderr.on('data', (chunk) => {
      this.#stderr = `${this.#stderr}${chunk}`.slice(-8192);
    });
    this.#child.on('error', (error) => {
      this.#spawnError = error;
      this.#rejectAll(error);
    });
    this.#child.on('exit', (code, signal) => {
      this.#rejectAll(new Error(
        `MDK peer exited code=${code} signal=${signal}; stderr=${this.#stderr}`,
      ));
    });
  }

  #rejectAll(error) {
    for (const pending of this.#pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.#pending.clear();
  }

  #receive(line) {
    let response;
    try {
      if (Buffer.byteLength(line, 'utf8') > 4 * 1024 * 1024) {
        throw new Error('MDK response exceeds the B3.3a resource envelope');
      }
      response = JSON.parse(line);
      if (!Number.isSafeInteger(response?.id) || response.id < 1
        || typeof response?.ok !== 'boolean') {
        throw new Error('MDK response id or disposition is invalid');
      }
      exactFields(response, ['id', 'ok', response.ok ? 'result' : 'error'], 'MDK response');
      if (!response.ok) {
        exactFields(response.error, ['code', 'details', 'message'], 'MDK error response');
        if (typeof response.error.code !== 'string'
          || !/^[a-z0-9_]{1,96}$/.test(response.error.code)
          || typeof response.error.message !== 'string') {
          throw new Error('MDK error response is invalid');
        }
      }
    } catch (error) {
      error.code ??= B33A_ERROR.INVALID;
      this.#rejectAll(error);
      return;
    }
    const pending = this.#pending.get(response.id);
    if (!pending) {
      const error = new Error('MDK peer returned an unexpected response id');
      error.code = B33A_ERROR.INVALID;
      this.#rejectAll(error);
      return;
    }
    this.#pending.delete(response.id);
    clearTimeout(pending.timer);
    if (response.ok) pending.resolve(response.result);
    else {
      const error = new Error(response.error.message);
      error.code = response.error.code;
      error.details = response.error.details;
      pending.reject(error);
    }
  }

  request(op, fields = {}) {
    if (this.#spawnError) return Promise.reject(this.#spawnError);
    const id = this.#nextId++;
    return new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        const error = new Error(`MDK peer timed out during ${op}; stderr=${this.#stderr}`);
        error.code = B33A_ERROR.INVALID;
        reject(error);
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
