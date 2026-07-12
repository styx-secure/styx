// vault-worker-runtime.js — the testable core of the vault crypto worker
// (Blocco 3, PR-3). Pure factory: no Worker API, no storage — the thin entry
// (vault-worker.js) wires it to self.onmessage with FROZEN production
// dependencies. Nothing the page sends through the protocol can supply code
// or dependencies: handler overrides exist ONLY for the test-tree fixture
// entry and can never touch the active types.
//
// Worker PROCESS states (not the future vault lifecycle, which is PR-5):
//   NEW → INITIALIZING → READY → SHUTTING_DOWN → CLOSED
//                     ↘ FAILED (fail-closed: any unrecognized exception)

import {
  VAULT_WORKER_PROTOCOL_VERSION, MESSAGE_TYPES, ACTIVE_TYPES,
  validateRequestEnvelope, extractEnvelopeId, buildResultResponse, buildErrorResponse,
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
 * @param {Record<string, Function>} [deps.testOverrides] TEST-TREE ONLY:
 *   handlers for RESERVED types (never for INIT/STATUS/SHUTDOWN, never for
 *   names outside the registry). The production entry passes none.
 */
export function createVaultWorkerRuntime({
  postMessage, kdfLoader, close, testOverrides = {},
}) {
  for (const name of Object.keys(testOverrides)) {
    if (!MESSAGE_TYPES.includes(name) || ACTIVE_TYPES.includes(name)) {
      throw new TypeError(`test override not allowed for type: ${name}`);
    }
  }

  let state = WORKER_STATES.NEW;
  let initConfig = null; // { wasmUrl } — non-sensitive deployment config only
  let initSummary = null;
  const inFlight = new Set();

  const statusResult = () => ({
    protocolVersion: VAULT_WORKER_PROTOCOL_VERSION,
    workerState: state,
    vaultState: null, // the vault lifecycle does not exist yet (PR-5)
    capabilities: {
      kdf: kdfLoader.isLoaded(),
      storage: false,
      lifecycle: false,
      openmls: false,
    },
    versions: { wrapper: 1, record: 1, key: 1 },
  });

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
        if (state === WORKER_STATES.SHUTTING_DOWN || state === WORKER_STATES.CLOSED) {
          throw wrongState('worker is shutting down', { type: 'STATUS', reason: `state:${state}` });
        }
        outcome = { result: statusResult() };
      } else if (request.type === 'INIT') {
        outcome = { result: await handleInit(request.payload) };
      } else if (request.type === 'SHUTDOWN') {
        outcome = { result: { closed: true }, shutdown: true };
      } else if (Object.hasOwn(testOverrides, request.type)) {
        // TEST FIXTURE ONLY (never reachable in the production entry).
        outcome = await testOverrides[request.type](request.payload, { state, kdfLoader });
      } else {
        // Reserved v1 names: recognized by the protocol, not yet active. They
        // must not derive keys, touch storage or fake a success (spec §9).
        throw wrongState('message type is reserved and not active in this build', { type: request.type, reason: 'reserved-type' });
      }
      const transfer = assertResponseTransferList(outcome.transfer);
      postMessage(buildResultResponse(request.id, outcome.result ?? null), transfer);
      if (outcome.shutdown === true) closeWorker(WORKER_STATES.SHUTTING_DOWN);
    } catch (e) {
      const wire = toWireError(e);
      postMessage(buildErrorResponse(request.id, wire.code, wire.details));
      if (wire.code === Codes.CRASHED) {
        // Unrecognized exception or unserializable result: the worker is no
        // longer trustworthy — fail closed (spec §9).
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
