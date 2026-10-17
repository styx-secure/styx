// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — strict fresh-process boundary for the pinned MDK peer.

import { spawn as spawnProcess } from 'node:child_process';
import { createInterface } from 'node:readline';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { B33A_ERROR } from './b3-3a-canonical.mjs';

const directory = dirname(fileURLToPath(import.meta.url));
const DEFAULT_BINARY = resolve(
  directory, '..', 'marmot-phase-b3', 'mdk-peer', 'target', 'debug', 'styx-b3-mdk-peer',
);
const RPC_TIMEOUT_MS = 60_000;
// Shutdown policy. Bound for stdio to close after `exit`, and for an acknowledged peer to exit.
const DRAIN_TIMEOUT_MS = 5_000;
// close() after a terminating error (the peer announced its own exit) resolves on exit 0.
const CLOSE_RESOLVES_AFTER_TERMINATING_ERROR = true;
// Error codes whose response announces that the peer exits (RpcError::fatal_peer, terminate: true).
const TERMINATING_ERROR_CODES = new Set(['mdk_peer_quarantined']);
const PEER_EXITED = 'mdk_peer_exited';
const PEER_NOT_RUNNING = 'mdk_peer_not_running';
const PEER_SHUTDOWN_TIMEOUT = 'mdk_peer_shutdown_timeout';

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

function typedError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

export class MdkB33aProcess {
  #child;
  #nextId = 1;
  #pending = new Map();
  #stderr = '';
  #spawnError;
  #exit; // { code, signal } once the process has exited
  #stdioClosed = false; // 'close': every stdio stream closed, stdout drained through the line reader
  #acknowledged = false; // checkpoint_and_exit was acknowledged
  #terminatingError = false; // the peer answered a terminating error and exits by itself
  #drainTimer;
  #drainTimedOut = false; // persistent: a later stream closure cannot turn this into success
  #settle;
  #settled; // resolves once shutdown is complete (stdio closed) or failed (bound exceeded)

  constructor(binary = DEFAULT_BINARY, { spawn = spawnProcess } = {}) {
    this.#settled = new Promise((resolveSettled) => { this.#settle = resolveSettled; });
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
    // A write to a peer that closed its stdin (EPIPE) must reach the pending requests, never the process.
    this.#child.stdin.on('error', (error) => { this.#rejectAll(error); });
    // 'exit' can be delivered before the peer's last stdout bytes are read: libuv reaps every exited child on
    // any SIGCHLD at the end of an epoll batch. Record it and reject nothing until stdout is drained ('close').
    this.#child.on('exit', (code, signal) => {
      this.#exit = { code, signal };
      this.#armDrain();
    });
    this.#child.on('close', () => {
      clearTimeout(this.#drainTimer);
      this.#stdioClosed = true;
      this.#rejectAll(this.#exitedError());
      this.#settle();
    });
  }

  #exitedError(reason = '') {
    const { code, signal } = this.#exit ?? {};
    return typedError(PEER_EXITED,
      `MDK peer exited code=${code} signal=${signal}${reason}; stderr=${this.#stderr}`);
  }

  // Bounded drain: if stdio is not closed within DRAIN_TIMEOUT_MS, fail closed and settle shutdown as failed.
  #armDrain() {
    if (this.#drainTimer !== undefined || this.#stdioClosed) return;
    this.#drainTimer = setTimeout(() => {
      if (this.#stdioClosed) return;
      this.#drainTimedOut = true;
      this.#rejectAll(this.#exit ? this.#exitedError() : this.#timeoutError());
      this.#settle();
    }, DRAIN_TIMEOUT_MS);
    this.#drainTimer.unref?.();
  }

  #timeoutError() {
    return typedError(PEER_SHUTDOWN_TIMEOUT, 'MDK peer did not finish shutdown (exit and stdio close) '
      + `within ${DRAIN_TIMEOUT_MS} ms; stderr=${this.#stderr}`);
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
      if (TERMINATING_ERROR_CODES.has(response.error.code)) this.#terminatingError = true;
      const error = new Error(response.error.message);
      error.code = response.error.code;
      error.details = response.error.details;
      pending.reject(error);
    }
  }

  request(op, fields = {}) {
    if (this.#spawnError) return Promise.reject(this.#spawnError);
    if (this.#exit || this.#stdioClosed || this.#drainTimedOut || !this.#child.stdin.writable) {
      return Promise.reject(typedError(PEER_NOT_RUNNING,
        `MDK peer is not running; stderr=${this.#stderr}`));
    }
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

  // Acknowledged, complete, bounded shutdown. Settles only after exit and stdio closure (or the bound), so the
  // next peer never overlaps this one on the same database.
  async close() {
    let failure;
    if (!this.#acknowledged && !this.#terminatingError && !this.#exit
      && !this.#stdioClosed && !this.#spawnError) {
      try {
        await this.request('checkpoint_and_exit');
        this.#acknowledged = true;
      } catch (error) { failure = error; }
    }
    this.#child.stdin.end();
    if (!this.#exit && !this.#stdioClosed) {
      // Acknowledged (or announced) but still alive: bound the wait, then kill. The drain bound then starts.
      const liveTimer = setTimeout(() => {
        if (this.#exit || this.#stdioClosed) return;
        this.#drainTimedOut = true;
        this.#child.kill('SIGKILL');
        this.#armDrain();
      }, DRAIN_TIMEOUT_MS);
      liveTimer.unref?.();
      this.#settled.finally(() => clearTimeout(liveTimer));
    }
    await this.#settled;
    if (this.#spawnError) throw this.#spawnError;
    if (failure) throw failure; // missing acknowledgement or a write failure on a live peer
    if (this.#drainTimedOut) throw this.#timeoutError();
    const announced = this.#acknowledged
      || (this.#terminatingError && CLOSE_RESOLVES_AFTER_TERMINATING_ERROR);
    if (!announced) throw this.#exitedError(' without acknowledging shutdown');
    if (this.#exit?.code !== 0 || this.#exit?.signal !== null) {
      throw this.#exitedError(' after acknowledging shutdown');
    }
  }
}
