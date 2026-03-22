// styx-js/src/transport/transport-interface.js
// Abstract transport interface and message types

/** @enum {string} */
export const TransportState = {
  DISCONNECTED: 'disconnected',
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
};

/**
 * A message exchanged between peers over the transport layer.
 */
export class TransportMessage {
  constructor({ id, senderPubkey, recipientPubkey, payload, timestamp }) {
    this.id = id;
    this.senderPubkey = senderPubkey;
    this.recipientPubkey = recipientPubkey;
    this.payload = payload; // Uint8Array — encrypted
    this.timestamp = timestamp || new Date();
    Object.freeze(this);
  }

  toJSON() {
    return {
      id: this.id,
      senderPubkey: this.senderPubkey,
      recipientPubkey: this.recipientPubkey,
      payload: Array.from(this.payload),
      timestamp: this.timestamp.toISOString(),
    };
  }

  static fromJSON(json) {
    return new TransportMessage({
      id: json.id,
      senderPubkey: json.senderPubkey,
      recipientPubkey: json.recipientPubkey,
      payload: new Uint8Array(json.payload),
      timestamp: new Date(json.timestamp),
    });
  }
}

/**
 * Abstract interface for all transport implementations.
 */
export class TransportInterface {
  get currentState() { return TransportState.DISCONNECTED; }
  get isAvailable() { return false; }

  /** @param {function} callback */
  onStateChange(callback) { throw new Error('Not implemented'); }

  /** @param {function} callback */
  onMessage(callback) { throw new Error('Not implemented'); }

  async connect() { throw new Error('Not implemented'); }
  async disconnect() { throw new Error('Not implemented'); }

  /** @param {TransportMessage} message */
  async send(message) { throw new Error('Not implemented'); }
}
