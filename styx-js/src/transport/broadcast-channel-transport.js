// broadcast-channel-transport.js — serverless transport over the BroadcastChannel
// API (same-origin, cross-tab). Real and zero-server: two Styx tabs on the same
// machine connect directly. Implements the same interface the orchestrator's
// WebRTC/Nostr transport will (send/onMessage), so it swaps out later.
//
// Framing: every message is broadcast to the channel wrapped as
// { to, from, data }; each transport delivers to its handler only the messages
// addressed to its own pubkey. BroadcastChannel never echoes to the sender.

export class BroadcastChannelTransport {
  /**
   * @param {string} selfPubkey this peer's public key (address)
   * @param {object} [opts]
   * @param {string} [opts.channelName='styx-chat']
   */
  constructor(selfPubkey, { channelName = 'styx-chat' } = {}) {
    this._self = selfPubkey;
    this._bc = new BroadcastChannel(channelName);
    this._handler = null;
    this._bc.onmessage = (ev) => {
      const m = ev.data;
      if (!m || m.to !== this._self) return;
      this._handler?.(m.from, m.data);
    };
  }

  /**
   * @param {(from: string, bytes: Uint8Array) => void} cb
   * @returns {() => void} unsubscribe
   */
  onMessage(cb) {
    this._handler = cb;
    return () => { this._handler = null; };
  }

  /**
   * @param {string} toPubkey
   * @param {Uint8Array} bytes
   * @param {object} [_opts] ignored (parity with NostrChatTransport)
   * @returns {Promise<void>}
   */
  async send(toPubkey, bytes, _opts) {
    this._bc.postMessage({ to: toPubkey, from: this._self, data: bytes });
  }

  close() {
    this._bc.onmessage = null;
    this._bc.close();
  }
}
