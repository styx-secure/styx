// styx-js/src/transport/nostr-transport.js
// Nostr relay-based transport — WebSocket connections to Nostr relays

import { TransportInterface, TransportState, TransportMessage } from './transport-interface.js';
import { EventEmitter, uuidv4, bytesToHex, hexToBytes, bytesToBase64, base64ToBytes, utf8Encode } from '../utils.js';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

/**
 * Manages connections to multiple Nostr relays.
 */
export class RelayPool {
  /**
   * @param {string[]} relayUrls - WebSocket relay URLs
   */
  constructor(relayUrls) {
    this._relayUrls = [...relayUrls];
    this._connections = new Map(); // url → WebSocket
    this._emitter = new EventEmitter();
    this._autoReconnect = true;
    this._reconnectAttempts = new Map(); // url → attempt count
    this._maxReconnectAttempts = 10;
    this._subscriptions = new Map(); // subId → filter (re-issued on (re)connect)
  }

  get relayUrls() { return [...this._relayUrls]; }
  get connectedCount() {
    return [...this._connections.values()].filter(
      (ws) => ws.readyState === WebSocket.OPEN
    ).length;
  }

  get messages() { return this._emitter; }

  /**
   * Connect to all relays. Returns count of successful connections.
   */
  async connectAll() {
    const results = await Promise.allSettled(
      this._relayUrls.map((url) => this._connectRelay(url))
    );
    return results.filter((r) => r.status === 'fulfilled').length;
  }

  async disconnectAll() {
    this._autoReconnect = false;
    for (const [url, ws] of this._connections) {
      ws.close();
    }
    this._connections.clear();
  }

  /**
   * Publish a Nostr event to all connected relays.
   * @param {object} event - Nostr event object
   * @returns {number} Count of relays reached
   */
  publish(event) {
    const msg = JSON.stringify(['EVENT', event]);
    let sent = 0;
    for (const [url, ws] of this._connections) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(msg);
        sent++;
      }
    }
    return sent;
  }

  /**
   * Publish an event and verify persistence by re-fetching it from the relay.
   * @param {object} event - Signed Nostr event (must have .id set)
   * @param {number} [timeoutMs=5000] - How long to wait for verification
   * @returns {Promise<{sent: number, verified: boolean}>}
   */
  async publishAndVerify(event, timeoutMs = 5000) {
    const sent = this.publish(event);
    if (sent === 0) return { sent: 0, verified: false };

    const subId = 'verify-' + event.id.slice(0, 8);

    return new Promise((resolve) => {
      const timeout = setTimeout(() => {
        this._emitter.off('message', handler);
        this._closeSubscription(subId);
        resolve({ sent, verified: false });
      }, timeoutMs);

      const handler = ({ data }) => {
        if (data[0] === 'EVENT' && data[2]?.id === event.id) {
          clearTimeout(timeout);
          this._emitter.off('message', handler);
          this._closeSubscription(subId);
          resolve({ sent, verified: true });
        }
      };

      this._emitter.on('message', handler);
      this.subscribe(subId, { ids: [event.id] });
    });
  }

  /**
   * Close a subscription on all connected relays.
   * @param {string} subscriptionId
   */
  _closeSubscription(subscriptionId) {
    const msg = JSON.stringify(['CLOSE', subscriptionId]);
    for (const [, ws] of this._connections) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(msg);
      }
    }
  }

  /**
   * Subscribe to events on all connected relays.
   * @param {string} subscriptionId
   * @param {object} filter - Nostr subscription filter
   */
  subscribe(subscriptionId, filter) {
    this._subscriptions.set(subscriptionId, filter); // remembered for re-issue on reconnect
    const msg = JSON.stringify(['REQ', subscriptionId, filter]);
    for (const [url, ws] of this._connections) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(msg);
      }
    }
  }

  /**
   * Force-refresh all relay connections and re-issue subscriptions. Call this
   * when the app returns to the foreground (mobile suspend silently kills the
   * WebSocket, leaving a half-dead connection that never delivers again).
   */
  async reconnect() {
    for (const [, ws] of this._connections) {
      try { ws.onclose = null; ws.close(); } catch { /* ignore */ }
    }
    this._connections.clear();
    this._reconnectAttempts.clear();
    this._autoReconnect = true;
    return this.connectAll(); // onopen re-issues every stored subscription
  }

  healthCheck() {
    return this._relayUrls.map((url) => ({
      url,
      isConnected:
        this._connections.has(url) &&
        this._connections.get(url).readyState === WebSocket.OPEN,
    }));
  }

  addRelay(url) {
    if (!this._relayUrls.includes(url)) {
      this._relayUrls.push(url);
    }
  }

  async removeRelay(url) {
    const ws = this._connections.get(url);
    if (ws) {
      ws.close();
      this._connections.delete(url);
    }
    this._relayUrls = this._relayUrls.filter((u) => u !== url);
  }

  async dispose() {
    await this.disconnectAll();
    this._emitter.removeAllListeners();
  }

  // --- Private ---

  _connectRelay(url) {
    return new Promise((resolve, reject) => {
      try {
        const ws = new WebSocket(url);
        const timeout = setTimeout(() => {
          ws.close();
          reject(new Error(`Timeout connecting to ${url}`));
        }, 10000);

        ws.onopen = () => {
          clearTimeout(timeout);
          this._connections.set(url, ws);
          // Re-issue every active subscription so a reconnected relay resumes
          // delivering (and replays anything stored while we were away).
          for (const [subId, filter] of this._subscriptions) {
            try { ws.send(JSON.stringify(['REQ', subId, filter])); } catch { /* ignore */ }
          }
          resolve();
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            this._emitter.emit('message', { relay: url, data });
          } catch (e) { /* ignore malformed */ }
        };

        ws.onclose = () => {
          this._connections.delete(url);
          if (this._autoReconnect) {
            this._scheduleReconnect(url);
          }
        };

        ws.onerror = (err) => {
          clearTimeout(timeout);
          this._connections.delete(url);
          reject(err);
        };
      } catch (e) {
        reject(e);
      }
    });
  }

  _scheduleReconnect(url) {
    const attempts = (this._reconnectAttempts.get(url) || 0) + 1;
    if (attempts > this._maxReconnectAttempts) return;
    this._reconnectAttempts.set(url, attempts);
    const delay = Math.min(1000 * Math.pow(2, attempts - 1), 30000);
    setTimeout(() => {
      this._connectRelay(url).then(() => {
        this._reconnectAttempts.set(url, 0);
      }).catch(() => {});
    }, delay);
  }
}

/**
 * Nostr relay transport implementing TransportInterface.
 * Messages are encrypted with the provided encryptor before being sent
 * as Nostr events, making them opaque to relays.
 */
export class NostrTransport extends TransportInterface {
  /**
   * @param {RelayPool} relayPool
   * @param {import('../crypto/encryption.js').StyxEncryptor} encryptor
   * @param {string} localPubkey - Hex-encoded pubkey used as Nostr event `pubkey` field
   * @param {string} peerPubkey - Hex-encoded tag for outgoing p-tags
   * @param {Uint8Array} [nostrSecretKey] - 32-byte secp256k1 private key for NIP-01 signing
   * @param {string} [subscriptionTag] - Hex tag for incoming p-tag subscription filter (defaults to localPubkey)
   */
  constructor(relayPool, encryptor, localPubkey, peerPubkey, nostrSecretKey, subscriptionTag) {
    super();
    this._pool = relayPool;
    this._encryptor = encryptor;
    this._localPubkey = localPubkey;
    this._peerPubkey = peerPubkey;
    this._nostrSecretKey = nostrSecretKey || null;
    this._subscriptionTag = subscriptionTag || localPubkey;
    this._state = TransportState.DISCONNECTED;
    this._emitter = new EventEmitter();
    this._subscriptionId = null;
    this._messageHandler = null;
  }

  get currentState() { return this._state; }
  get isAvailable() { return typeof WebSocket !== 'undefined'; }

  onStateChange(callback) { return this._emitter.on('stateChange', callback); }
  onMessage(callback) { return this._emitter.on('message', callback); }

  async connect() {
    this._setState(TransportState.CONNECTING);

    const connected = await this._pool.connectAll();
    if (connected === 0) {
      this._setState(TransportState.DISCONNECTED);
      throw new Error('Could not connect to any relay');
    }

    // Subscribe to events targeted at us
    this._subscriptionId = `styx-${uuidv4().slice(0, 8)}`;
    this._pool.subscribe(this._subscriptionId, {
      kinds: [30078], // Styx custom kind
      '#p': [this._subscriptionTag],
    });

    // Listen for incoming relay messages
    this._messageHandler = ({ relay, data }) => {
      this._handleRelayMessage(data);
    };
    this._pool.messages.on('message', this._messageHandler);

    this._setState(TransportState.CONNECTED);
  }

  async disconnect() {
    if (this._messageHandler) {
      this._pool.messages.off('message', this._messageHandler);
      this._messageHandler = null;
    }
    this._setState(TransportState.DISCONNECTED);
  }

  async send(message) {
    if (this._state !== TransportState.CONNECTED) {
      throw new Error('Nostr transport not connected');
    }

    // Encrypt the payload
    const serialized = new TextEncoder().encode(JSON.stringify(message.toJSON()));
    const encrypted = this._encryptor.encrypt(serialized);

    // Build Nostr event
    const nostrEvent = {
      kind: 30078,
      pubkey: this._localPubkey,
      created_at: Math.floor(Date.now() / 1000),
      tags: [['p', this._peerPubkey]],
      content: bytesToBase64(encrypted),
    };

    // NIP-01 signing: compute event id and schnorr signature
    this._signEvent(nostrEvent);

    this._pool.publish(nostrEvent);
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

  /**
   * Sign a Nostr event per NIP-01.
   * Sets event.id (SHA-256 of serialized event) and event.sig (schnorr signature).
   */
  _signEvent(event) {
    // NIP-01: id = sha256(JSON.stringify([0, pubkey, created_at, kind, tags, content]))
    const serialized = JSON.stringify([
      0,
      event.pubkey,
      event.created_at,
      event.kind,
      event.tags,
      event.content,
    ]);
    const idBytes = sha256(utf8Encode(serialized));
    event.id = bytesToHex(idBytes);

    if (this._nostrSecretKey) {
      const sigBytes = schnorr.sign(idBytes, this._nostrSecretKey);
      event.sig = bytesToHex(sigBytes);
    } else {
      // Fallback: unsigned (relay will likely reject)
      event.sig = '0'.repeat(128);
    }
  }

  _handleRelayMessage(data) {
    // Nostr relay message: ['EVENT', subscriptionId, event]
    if (!Array.isArray(data) || data[0] !== 'EVENT') return;

    const nostrEvent = data[2];
    if (!nostrEvent || !nostrEvent.content) return;

    // Skip our own events
    if (nostrEvent.pubkey === this._localPubkey) return;

    try {
      const encrypted = base64ToBytes(nostrEvent.content);
      const decrypted = this._encryptor.decrypt(encrypted);
      const json = JSON.parse(new TextDecoder().decode(decrypted));
      const msg = TransportMessage.fromJSON(json);
      this._emitter.emit('message', msg);
    } catch (e) {
      console.error('[Styx Nostr] Failed to decrypt/parse message:', e);
    }
  }
}
