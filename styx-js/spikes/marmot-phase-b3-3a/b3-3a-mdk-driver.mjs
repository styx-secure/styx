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
// Shutdown policy. Default bound for each close() phase: the checkpoint_and_exit acknowledgement, a live peer's
// exit after it, and stdio closure after exit or SIGKILL. The constructor seam `drainTimeoutMs` overrides it
// (tests). A failure detected while awaiting the acknowledgement settles within 2 x the bound; an acknowledged
// peer that outlives the live bound can take 3 x the bound overall (15 s by default).
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
  #spawnError; // 'error' before the child had a pid: the spawn failed
  #childError; // 'error' on a spawned child (pid defined): it is killed once and the drain is bounded
  #killSent = false; // SIGKILL is sent at most once; a kill that itself emits 'error' must not recurse
  #abandonedAckId; // id of a checkpoint_and_exit whose bound expired: a late answer to it is ignored
  #exit; // { code, signal } once the process has exited
  #stdioClosed = false; // 'close': every stdio stream closed, stdout drained through the line reader
  #acknowledged = false; // checkpoint_and_exit was acknowledged
  #terminatingError = false; // the peer answered a terminating error and exits by itself
  #drainTimer;
  #drainTimedOut = false; // persistent: a later stream closure cannot turn this into success
  #settle;
  #settled; // resolves once shutdown is complete (stdio closed) or failed (bound exceeded)
  #drainTimeoutMs;
  #closing; // memoized close(): one shutdown, one write at most, the same settled outcome for every caller

  constructor(binary = DEFAULT_BINARY, { spawn = spawnProcess, drainTimeoutMs = DRAIN_TIMEOUT_MS } = {}) {
    if (!Number.isSafeInteger(drainTimeoutMs) || drainTimeoutMs < 1) {
      throw new TypeError('drainTimeoutMs must be a positive safe integer');
    }
    this.#drainTimeoutMs = drainTimeoutMs;
    this.#settled = new Promise((resolveSettled) => { this.#settle = resolveSettled; });
    this.#child = spawn(binary, [], { stdio: ['pipe', 'pipe', 'pipe'] });
    createInterface({ input: this.#child.stdout, crlfDelay: Infinity })
      .on('line', (line) => this.#receive(line));
    this.#child.stderr.setEncoding('utf8');
    this.#child.stderr.on('data', (chunk) => {
      this.#stderr = `${this.#stderr}${chunk}`.slice(-8192);
    });
    this.#child.on('error', (error) => {
      this.#rejectAll(error);
      if (this.#child.pid === undefined) {
        this.#spawnError ??= error;
        this.#armDrain(); // spawn failure: bound the wait for 'close' too
        return;
      }
      // An error on a spawned child (for example a failed signal): fail closed, kill it once, bound the drain.
      this.#childError ??= error;
      this.#kill();
      this.#armDrain();
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

  // Bounded drain: if stdio is not closed within the bound, fail closed and settle shutdown as failed. The timer
  // is unref'd: until it fires, the child's stdio pipes and process handle keep the event loop alive (a real
  // child that has not closed stdio still holds them), so the unref only stops a finished shutdown from holding it.
  #armDrain() {
    if (this.#drainTimer !== undefined || this.#stdioClosed) return;
    this.#drainTimer = setTimeout(() => {
      if (this.#stdioClosed) return;
      this.#drainTimedOut = true;
      this.#rejectAll(this.#exit ? this.#exitedError() : this.#timeoutError());
      this.#settle();
    }, this.#drainTimeoutMs);
    this.#drainTimer.unref?.();
  }

  #timeoutError() {
    return typedError(PEER_SHUTDOWN_TIMEOUT, 'MDK peer did not finish shutdown (exit and stdio close) '
      + `within ${this.#drainTimeoutMs} ms; stderr=${this.#stderr}`);
  }

  #ackTimeoutError() {
    return typedError(PEER_SHUTDOWN_TIMEOUT, 'MDK peer did not acknowledge checkpoint_and_exit '
      + `within ${this.#drainTimeoutMs} ms; stderr=${this.#stderr}`);
  }

  // SIGKILL a child that is still alive, then bound the drain from now. Every close() failure path with a live
  // child, and an acknowledged peer that outlives the bound, ends here.
  #kill() {
    if (this.#exit || this.#stdioClosed || this.#killSent) return;
    this.#killSent = true;
    this.#child.kill('SIGKILL');
    this.#armDrain();
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
    if (!pending && response.id === this.#abandonedAckId) {
      // A late answer to a checkpoint_and_exit whose bound expired: that shutdown has already failed. Ignore it,
      // so it cannot reject concurrent requests as an unexpected id.
      return;
    }
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
    return this.#send(op, fields, RPC_TIMEOUT_MS);
  }

  #send(op, fields, timeoutMs, timeoutError) {
    const failed = this.#spawnError ?? this.#childError;
    if (failed) return Promise.reject(failed);
    if (this.#exit || this.#stdioClosed || this.#drainTimedOut || !this.#child.stdin.writable) {
      return Promise.reject(typedError(PEER_NOT_RUNNING,
        `MDK peer is not running; stderr=${this.#stderr}`));
    }
    const id = this.#nextId++;
    return new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        if (timeoutError) {
          this.#abandonedAckId = id;
          reject(timeoutError());
          return;
        }
        const error = new Error(`MDK peer timed out during ${op}; stderr=${this.#stderr}`);
        error.code = B33A_ERROR.INVALID;
        reject(error);
      }, timeoutMs);
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
  // next peer never overlaps this one on the same database. Idempotent: every call returns the same promise.
  close() {
    this.#closing ??= this.#shutdown();
    return this.#closing;
  }

  async #shutdown() {
    let failure;
    if (!this.#acknowledged && !this.#terminatingError && !this.#exit
      && !this.#stdioClosed && !this.#spawnError && !this.#childError) {
      try {
        // Bounded: a live peer that never answers fails after the bound, not after the 60 s RPC timeout.
        await this.#send('checkpoint_and_exit', {}, this.#drainTimeoutMs, () => this.#ackTimeoutError());
        this.#acknowledged = true;
      } catch (error) { failure = error; }
    }
    this.#child.stdin.end();
    // A child error has already killed the child and bounded the drain (constructor 'error' handler).
    if (!this.#exit && !this.#stdioClosed && !this.#spawnError && !this.#childError) {
      if (failure) {
        // Failure path (no acknowledgement, write failure, error or invalid response) with a live child: kill now.
        this.#kill();
      } else {
        // Acknowledged (or announced) but still alive: bound the wait, then kill. The drain bound then starts.
        const liveTimer = setTimeout(() => {
          if (this.#exit || this.#stdioClosed) return;
          this.#drainTimedOut = true;
          this.#kill();
        }, this.#drainTimeoutMs);
        liveTimer.unref?.();
        this.#settled.finally(() => clearTimeout(liveTimer));
      }
    }
    await this.#settled;
    if (this.#spawnError) throw this.#spawnError;
    if (failure) throw failure; // missing acknowledgement or a write failure on a live peer
    if (this.#childError) throw this.#childError;
    if (this.#drainTimedOut) throw this.#timeoutError();
    const announced = this.#acknowledged
      || (this.#terminatingError && CLOSE_RESOLVES_AFTER_TERMINATING_ERROR);
    if (!announced) throw this.#exitedError(' without acknowledging shutdown');
    if (this.#exit?.code !== 0 || this.#exit?.signal !== null) {
      throw this.#exitedError(' after acknowledging shutdown');
    }
  }
}
