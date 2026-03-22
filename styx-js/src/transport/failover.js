// styx-js/src/transport/failover.js
// Multi-transport failover with retry + exponential backoff, and outbox worker

import { TransportInterface, TransportState } from './transport-interface.js';
import { EventEmitter } from '../utils.js';

/**
 * Exception when all transports fail.
 */
export class TransportFailoverException extends Error {
  constructor(message) {
    super(message);
    this.name = 'TransportFailoverException';
  }
}

/**
 * Associates a transport with its retry and timeout policy.
 */
export class TransportPriority {
  /**
   * @param {TransportInterface} transport
   * @param {number} maxRetries
   * @param {number} timeoutMs
   */
  constructor(transport, maxRetries, timeoutMs) {
    this.transport = transport;
    this.maxRetries = maxRetries;
    this.timeoutMs = timeoutMs;
  }
}

/**
 * Multi-transport failover engine.
 * Tries transports in priority order with retry + exponential backoff.
 */
export class TransportFailover extends TransportInterface {
  /**
   * @param {TransportPriority[]} transports - Ordered by priority (highest first)
   */
  constructor(transports) {
    super();
    this._transports = transports;
    this._state = TransportState.DISCONNECTED;
    this._emitter = new EventEmitter();
    this._activeTransport = null;
    this._messageHandlers = [];
  }

  get currentState() { return this._state; }

  get isAvailable() {
    return this._transports.some((tp) => tp.transport.isAvailable);
  }

  get anyAvailable() { return this.isAvailable; }

  get activeTransportName() {
    if (!this._activeTransport) return null;
    return this._activeTransport.constructor.name;
  }

  onStateChange(callback) { return this._emitter.on('stateChange', callback); }
  onMessage(callback) { return this._emitter.on('message', callback); }

  /**
   * Connect using the highest-priority available transport.
   */
  async connect() {
    this._setState(TransportState.CONNECTING);

    for (const tp of this._transports) {
      if (!tp.transport.isAvailable) continue;

      try {
        await tp.transport.connect();

        // Subscribe to messages
        const unsubscribe = tp.transport.onMessage((msg) => {
          this._emitter.emit('message', msg);
        });
        this._messageHandlers.push(unsubscribe);

        // Monitor state changes for auto-failover
        tp.transport.onStateChange((state) => {
          if (state === TransportState.DISCONNECTED && this._activeTransport === tp.transport) {
            this._handleDisconnect();
          }
        });

        this._activeTransport = tp.transport;
        this._setState(TransportState.CONNECTED);
        return;
      } catch (e) {
        console.warn(`[Styx Failover] ${tp.transport.constructor.name} failed:`, e.message);
        continue;
      }
    }

    this._setState(TransportState.DISCONNECTED);
    throw new TransportFailoverException('All transports failed to connect');
  }

  async disconnect() {
    for (const unsub of this._messageHandlers) {
      if (typeof unsub === 'function') unsub();
    }
    this._messageHandlers = [];

    for (const tp of this._transports) {
      try { await tp.transport.disconnect(); } catch { /* ignore */ }
    }
    this._activeTransport = null;
    this._setState(TransportState.DISCONNECTED);
  }

  /**
   * Send with retry across transports.
   */
  async send(message) {
    for (const tp of this._transports) {
      if (tp.transport.currentState !== TransportState.CONNECTED) continue;

      for (let attempt = 0; attempt <= tp.maxRetries; attempt++) {
        try {
          await _withTimeout(tp.transport.send(message), tp.timeoutMs);
          return;
        } catch (e) {
          if (attempt < tp.maxRetries) {
            const delay = Math.min(100 * Math.pow(2, attempt), 5000);
            await _sleep(delay);
          }
        }
      }
    }
    throw new TransportFailoverException('All transports failed to send');
  }

  async dispose() {
    await this.disconnect();
    this._emitter.removeAllListeners();
  }

  // --- Private ---

  _setState(newState) {
    if (this._state !== newState) {
      this._state = newState;
      this._emitter.emit('stateChange', newState);
    }
  }

  async _handleDisconnect() {
    console.warn('[Styx Failover] Active transport disconnected, attempting failover...');
    this._activeTransport = null;
    try {
      await this.connect();
    } catch (e) {
      this._setState(TransportState.DISCONNECTED);
    }
  }
}

/**
 * Processes the outbox queue in causal (HLC) order.
 */
export class OutboxWorker {
  /**
   * @param {import('../storage/store-interface.js').OutboxStore} outboxStore
   * @param {import('../storage/store-interface.js').LedgerStore} ledgerStore
   * @param {TransportFailover} transport
   * @param {import('../crypto/encryption.js').StyxEncryptor} encryptor
   * @param {string} localPubkey
   * @param {string} peerPubkey
   */
  constructor({ outboxStore, ledgerStore, transport, encryptor, localPubkey, peerPubkey }) {
    this._outboxStore = outboxStore;
    this._ledgerStore = ledgerStore;
    this._transport = transport;
    this._encryptor = encryptor;
    this._localPubkey = localPubkey;
    this._peerPubkey = peerPubkey;
    this._running = false;
    this._sentCount = 0;
    this._failedCount = 0;
  }

  get isRunning() { return this._running; }
  get sentCount() { return this._sentCount; }
  get failedCount() { return this._failedCount; }
  get pendingCount() { return this._outboxStore.pendingCount(); }

  /**
   * Start the worker loop.
   */
  async start() {
    this._running = true;
    while (this._running) {
      const processed = await this.processBatch();
      if (processed === 0) {
        // Nothing to send — wait before checking again
        await _sleep(1000);
      }
    }
  }

  stop() {
    this._running = false;
  }

  /**
   * Force immediate processing of one batch.
   */
  async processNow() {
    return this.processBatch();
  }

  /**
   * Process one batch of ready-to-send events.
   * @returns {number} Events processed
   */
  async processBatch() {
    const ready = await this._outboxStore.getReadyToSend();
    if (ready.length === 0) return 0;

    let processed = 0;
    for (const entry of ready) {
      const event = await this._ledgerStore.getEventById(entry.eventId);
      if (!event) continue;

      try {
        // Serialize the event
        const serialized = new TextEncoder().encode(JSON.stringify(event.toJSON()));

        const { TransportMessage } = await import('./transport-interface.js');
        const msg = new TransportMessage({
          id: event.eventId,
          senderPubkey: this._localPubkey,
          recipientPubkey: this._peerPubkey,
          payload: serialized, // Will be encrypted by transport
          timestamp: new Date(),
        });

        await this._transport.send(msg);
        await this._outboxStore.markSent({
          eventId: entry.eventId,
          transport: this._transport.activeTransportName || 'unknown',
        });
        this._sentCount++;
        processed++;
      } catch (e) {
        await this._outboxStore.markFailed({ eventId: entry.eventId });
        this._failedCount++;
      }
    }
    return processed;
  }
}

// --- Helpers ---

function _withTimeout(promise, ms) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Timeout')), ms);
    promise.then(
      (val) => { clearTimeout(timer); resolve(val); },
      (err) => { clearTimeout(timer); reject(err); }
    );
  });
}

function _sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
