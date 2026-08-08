// vault-worker-runtime.js — the testable core of the vault crypto worker
// (Blocco 3, US-008). Pure factory: no Worker API — the thin entry
// (vault-worker.js) wires it to self.onmessage with FROZEN production
// dependencies. Nothing the page sends through the protocol can supply code
// or dependencies: handler overrides exist ONLY for the test-tree fixture.
//
// Worker PROCESS states (distinct from the owned vault lifecycle states):
//   NEW → INITIALIZING → READY → SHUTTING_DOWN → CLOSED
//                     ↘ FAILED (fail-closed: any unrecognized exception)

import {
  VAULT_WORKER_PROTOCOL_VERSION, MESSAGE_TYPES,
  validateRequestEnvelope, validateRequestPayload, extractEnvelopeId,
  buildResultResponse, buildErrorResponse,
} from './vault-worker-protocol.js';
import { snapshotStrictPlainObject } from './vault-shape.js';
import { VaultWorkerError, VaultWorkerErrorCodes as Codes, toWireError } from './vault-worker-errors.js';

export const WORKER_STATES = Object.freeze({
  NEW: 'NEW',
  INITIALIZING: 'INITIALIZING',
  READY: 'READY',
  SHUTTING_DOWN: 'SHUTTING_DOWN',
  FAILED: 'FAILED',
  CLOSED: 'CLOSED',
});

const INIT_PAYLOAD_KEYS = Object.freeze(['wasmUrl']);
const MAX_RESPONSE_TRANSFER_BYTES = 32 * 1024 * 1024;

const wrongState = (message, details) => new VaultWorkerError(Codes.WRONG_STATE, message, details);
const badRequest = (message, details) => new VaultWorkerError(Codes.BAD_REQUEST, message, details);

/**
 * @param {object} deps frozen by the entry point
 * @param {(message: unknown, transfer?: Transferable[]) => void} deps.postMessage
 * @param {{load: (url: string) => Promise<object>, isLoaded: () => boolean}} deps.kdfLoader
 * @param {() => void} deps.close self.close in production
 * @param {{initialize: () => Promise<object>, close: () => void}} deps.vaultLifecycle
 *   module-internal lifecycle owner; initialize returns the createVault API
 * @param {Record<string, Function>} [deps.testOverrides] TEST-TREE ONLY.
 */
export function createVaultWorkerRuntime({
  postMessage, kdfLoader, vaultLifecycle, close, testOverrides = {},
}) {
  if (vaultLifecycle === null || typeof vaultLifecycle !== 'object'
    || typeof vaultLifecycle.initialize !== 'function'
    || typeof vaultLifecycle.close !== 'function') {
    throw new TypeError('vaultLifecycle owner is required');
  }
  for (const name of Object.keys(testOverrides)) {
    if (!MESSAGE_TYPES.includes(name) || ['INIT', 'STATUS', 'SHUTDOWN'].includes(name)) {
      throw new TypeError(`test override not allowed for type: ${name}`);
    }
  }

  let state = WORKER_STATES.NEW;
  let initConfig = null; // { wasmUrl } — non-sensitive deployment config only
  let initSummary = null;
  let vault = null;
  const inFlight = new Set();
  let lifecycleQueue = Promise.resolve();
  const serializeLifecycle = (fn) => {
    const result = lifecycleQueue.then(fn);
    lifecycleQueue = result.then(() => {}, () => {});
    return result;
  };

  const statusResult = async () => {
    const vaultStatus = vault === null ? null : await vault.status();
    return {
      protocolVersion: VAULT_WORKER_PROTOCOL_VERSION,
      workerState: state,
      vaultState: vaultStatus?.state ?? null,
      capabilities: {
        kdf: kdfLoader.isLoaded(),
        storage: vault !== null,
        lifecycle: vault !== null,
        openmls: false,
      },
      versions: { wrapper: 1, record: 1, key: 1 },
    };
  };

  async function handleInit(payload) {
    const p = snapshotStrictPlainObject(payload, INIT_PAYLOAD_KEYS, (message, details) => badRequest(
      message, { phase: 'init', reason: (details?.field !== undefined ? `field:${details.field}` : 'shape').slice(0, 64) },
    ));
    if (state === WORKER_STATES.READY) {
      // Idempotent ONLY for the identical configuration.
      if (initConfig !== null && p.wasmUrl === initConfig.wasmUrl) return initSummary;
      throw wrongState('worker already initialized with a different configuration', { phase: 'init', reason: 'config-mismatch' });
    }
    if (state !== WORKER_STATES.NEW) {
      throw wrongState('INIT is only valid in the NEW state', { phase: 'init', reason: `state:${state}` });
    }
    state = WORKER_STATES.INITIALIZING;
    let summary;
    try {
      summary = await kdfLoader.load(p.wasmUrl);
      vault = await vaultLifecycle.initialize();
    } catch (e) {
      // Fail-closed: a worker whose artifact could not be verified is FAILED,
      // never half-initialized. The supervisor decides the respawn.
      state = WORKER_STATES.FAILED;
      throw e;
    }
    initConfig = Object.freeze({ wasmUrl: p.wasmUrl });
    initSummary = Object.freeze({
      protocolVersion: VAULT_WORKER_PROTOCOL_VERSION,
      workerState: WORKER_STATES.READY,
      wasmBytes: summary.wasmBytes,
      digestVerified: summary.digestVerified === true,
      katVerified: summary.katVerified === true,
    });
    state = WORKER_STATES.READY;
    return initSummary;
  }

  async function handleVaultRequest(type, payload) {
    if (state !== WORKER_STATES.READY || vault === null) {
      throw wrongState('vault lifecycle is not ready', { type, reason: `state:${state}` });
    }
    if (type === 'CREATE_VAULT') {
      return { result: await vault.createVault(payload.password, payload.profile === undefined ? {} : { profile: payload.profile }) };
    }
    if (type === 'UNLOCK') return { result: await vault.unlock(payload.password) };
    if (type === 'LOCK') return { result: await vault.lock() };
    if (type === 'GET') {
      const record = await vault.getRecord(payload.namespace, payload.recordKey);
      return { result: record === undefined ? { found: false } : { found: true, record } };
    }
    if (type === 'PUT') {
      return { result: await vault.putRecord(
        payload.namespace,
        payload.recordKey,
        payload.value,
        { contentType: payload.contentType },
      ) };
    }
    if (type === 'DELETE') return { result: await vault.deleteRecord(payload.namespace, payload.recordKey) };
    if (type === 'LIST') return { result: { keys: await vault.listRecords(payload.namespace) } };
    if (type === 'TRANSACTION') {
      return { result: await vault.transactionRecords(payload.namespace, payload.operations) };
    }
    if (type === 'MIGRATE') {
      const source = payload.namespace === 'settings' ? payload.preferences : payload.identity;
      return { result: await vault.migrate(
        payload.namespace,
        source,
        payload.namespace === 'identity' ? { pairingActive: payload.pairingActive } : {},
      ) };
    }
    if (type === 'DESTROY') return { result: await vault.destroy(), shutdown: true };
    throw wrongState('message type is reserved and not active in this build', { type, reason: 'reserved-type' });
  }

  function assertResponseTransferList(transfer) {
    if (transfer === undefined) return [];
    if (!Array.isArray(transfer)) throw new VaultWorkerError(Codes.CRASHED, 'transfer list must be an array', { reason: 'bad-transfer-list' });
    let total = 0;
    const seen = new Set();
    for (const item of transfer) {
      if (!(item instanceof ArrayBuffer)) {
        throw new VaultWorkerError(Codes.CRASHED, 'only ArrayBuffers can be transferred', { reason: 'bad-transferable' });
      }
      if (seen.has(item)) throw new VaultWorkerError(Codes.CRASHED, 'duplicate buffer in the transfer list', { reason: 'duplicate-transferable' });
      seen.add(item);
      total += item.byteLength;
    }
    if (total > MAX_RESPONSE_TRANSFER_BYTES) {
      throw new VaultWorkerError(Codes.CRASHED, 'transfer list exceeds the byte budget', { reason: 'over-transfer-budget' });
    }
    return transfer;
  }

  /** Fail-closed shutdown used for both SHUTDOWN and unrecognized exceptions. */
  function closeWorker(nextState) {
    state = nextState;
    try { vaultLifecycle.close(); } catch { /* the process is going away */ }
    vault = null;
    try { close(); } catch { /* the process is going away either way */ }
    if (nextState === WORKER_STATES.SHUTTING_DOWN) state = WORKER_STATES.CLOSED;
  }

  /**
   * Handle one message event. `origin` is defensively rejected when non-empty
   * (page→dedicated-worker messages carry an empty origin; anything else is
   * not our protocol).
   */
  async function handleMessage({ data, origin } = {}) {
    if (state === WORKER_STATES.CLOSED) return;
    const fallbackId = extractEnvelopeId(data);
    let request;
    try {
      if (typeof origin === 'string' && origin !== '') {
        throw badRequest('unexpected message origin', { reason: 'unexpected-origin' });
      }
      request = validateRequestEnvelope(data);
      if (inFlight.has(request.id)) {
        throw badRequest('request id already in flight', { reason: 'duplicate-id' });
      }
    } catch (e) {
      const wire = toWireError(e);
      postMessage(buildErrorResponse(fallbackId, wire.code, wire.details));
      return;
    }

    inFlight.add(request.id);
    try {
      let outcome;
      if (request.type === 'STATUS') {
        const payload = validateRequestPayload(request.type, request.payload);
        if (state === WORKER_STATES.SHUTTING_DOWN || state === WORKER_STATES.CLOSED) {
          throw wrongState('worker is shutting down', { type: 'STATUS', reason: `state:${state}` });
        }
        outcome = { result: await statusResult(payload) };
      } else if (request.type === 'INIT') {
        outcome = { result: await handleInit(request.payload) };
      } else if (request.type === 'SHUTDOWN') {
        validateRequestPayload(request.type, request.payload);
        outcome = { result: { closed: true }, shutdown: true };
      } else if (Object.hasOwn(testOverrides, request.type)) {
        // TEST FIXTURE ONLY (never reachable in the production entry). It may
        // deliberately violate a production schema to exercise cancellation,
        // crash, timeout and response-boundary behavior.
        outcome = await testOverrides[request.type](request.payload, { state, kdfLoader });
      } else {
        const payload = validateRequestPayload(request.type, request.payload);
        // The lifecycle itself serializes mutations, but a concurrent GET
        // could otherwise retain a local CryptoKey while LOCK completes. The
        // worker therefore orders every production vault request at the outer
        // boundary; no plaintext result can emerge after a later LOCK reply.
        outcome = await serializeLifecycle(() => handleVaultRequest(request.type, payload));
      }
      const transfer = assertResponseTransferList(outcome.transfer);
      postMessage(buildResultResponse(request.id, outcome.result ?? null), transfer);
      if (outcome.shutdown === true) closeWorker(WORKER_STATES.SHUTTING_DOWN);
    } catch (e) {
      const wire = toWireError(e);
      postMessage(buildErrorResponse(request.id, wire.code, wire.details));
      if (wire.code === Codes.CRASHED || request.type === 'DESTROY') {
        // Unrecognized exception or unserializable result: the worker is no
        // longer trustworthy. A failed factory reset is equally terminal: its
        // storage connection may be closed or deletion may still be pending.
        closeWorker(WORKER_STATES.FAILED);
      }
    } finally {
      inFlight.delete(request.id);
    }
  }

  return Object.freeze({
    handleMessage,
    getState: () => state,
  });
}
