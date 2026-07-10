// relay-listener.js — subscribes to the relays for kind-1059 events p-tagged to
// the watched pubkeys, reusing styx-js's RelayPool (auto-reconnect included), and
// calls onEvent(pubkey, eventId) for each new, relevant one. Filtering/dedup is
// delegated to the pure handleRelayMessage.
import { RelayPool } from '../../styx-js/src/transport/nostr-transport.js';
import { handleRelayMessage } from './relay-message.js';

const STORED_KIND = 1059;

export class RelayListener {
  constructor({ relays, onEvent }) {
    this._pool = new RelayPool(relays);
    this._onEvent = onEvent;
    this._watched = new Set();
    this._seen = new Set();
    this._subId = 'push-bridge';
  }

  watch(pubkey) { this._watched.add(pubkey); this._resubscribe(); }

  async start(pubkeys = []) {
    pubkeys.forEach((pk) => this._watched.add(pk));
    const n = await this._pool.connectAll();
    if (n === 0) throw new Error('RelayListener: could not connect to any relay');
    this._pool.messages.on('message', ({ data }) => {
      const hit = handleRelayMessage(data, this._seen, this._watched);
      if (hit) Promise.resolve(this._onEvent(hit.pubkey, hit.eventId)).catch((e) => console.error('[listener] onEvent:', e));
    });
    this._resubscribe();
  }

  /** (Re)issue the subscription with the current watched set. */
  _resubscribe() {
    if (!this._watched.size) return;
    this._pool.subscribe(this._subId, { kinds: [STORED_KIND], '#p': [...this._watched] });
  }
}
