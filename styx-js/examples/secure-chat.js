// styx-js/examples/secure-chat.js
// Legacy local-only chat shell built with Styx.js.
//
// IMPORTANT: v1 remote ledger admission is intentionally disabled. This
// example can demonstrate local creation and pairing surfaces, but it is not a
// functioning P2P chat until separately approved admission work lands.

import {
  SovereignLedger,
  LedgerConfig,
  EventType,
  MemoryLedgerStore,
  MemoryPeerStore,
  MemoryKeyStore,
  MemoryOutboxStore,
  setBip39Wordlist,
} from '../src/index.js';

const REMOTE_MESSAGES_DISABLED_MESSAGE =
  'STYX_V1_REMOTE_ADMISSION_DISABLED: incoming peer messages are unavailable in the v1 ledger';

// In a real app, import the full BIP-39 wordlist
// import { wordlist } from './bip39-english.js';
// setBip39Wordlist(wordlist);

/**
 * Secure P2P Chat application using Styx.js
 */
class SecureChat {
  constructor() {
    this._ledger = null;
    this._onStateChange = null;
  }

  /**
   * Initialize the chat with ephemeral (in-memory) storage.
   * For persistent chat, use IndexedDB stores instead.
   */
  async initialize({ persistence = 'memory' } = {}) {
    const config = new LedgerConfig({
      relayUrls: ['wss://relay.damus.io', 'wss://nos.lol'],
      persistence,
      logLevel: 'info',
    });

    this._ledger = new SovereignLedger({
      config,
      ledgerStore: new MemoryLedgerStore(),
      peerStore: new MemoryPeerStore(),
      keyStore: new MemoryKeyStore(),
      outboxStore: new MemoryOutboxStore(),
    });

    this._ledger.onStateChange((state) => {
      console.log(`[Chat] State: ${state}`);
      if (this._onStateChange) this._onStateChange(state);
    });

    await this._ledger.initialize();
    console.log(`[Chat] Identity: ${this._ledger.identity.nodeId}`);
  }

  /**
   * Create a room and get the invite code (mnemonic).
   * Share this code with the other person.
   * @returns {Promise<string>} The mnemonic to share
   */
  async createRoom() {
    return this._ledger.startRemotePairing();
  }

  /**
   * Join a room using the invite code.
   * @param {string} mnemonic - The code received from the room creator
   */
  async joinRoom(mnemonic) {
    return this._ledger.startRemotePairing(mnemonic);
  }

  /**
   * Get the Double Check verification code.
   * Both users should see the same code and confirm verbally.
   * @returns {Promise<string>} e.g. "483 291"
   */
  async getVerificationCode() {
    return this._ledger.getDoubleCheckCode();
  }

  /**
   * Confirm the pairing after verifying the Double Check code.
   * @param {string} peerPublicKey - Hex-encoded peer public key
   * @param {string} [alias] - Friendly name for the peer
   */
  async confirmConnection(peerPublicKey, alias = 'Chat Partner') {
    await this._ledger.confirmPairing({ peerPublicKey, peerAlias: alias });
  }

  /**
   * Send a text message.
   * @param {string} text
   */
  async sendText(text) {
    const payload = new TextEncoder().encode(
      JSON.stringify({
        type: 'text',
        text,
        timestamp: new Date().toISOString(),
      })
    );
    await this._ledger.sendMessage({ payload });
  }

  /**
   * Send a typing indicator.
   */
  async sendTyping() {
    const payload = new TextEncoder().encode(
      JSON.stringify({ type: 'typing', timestamp: new Date().toISOString() })
    );
    await this._ledger.sendConfig({ payload });
  }

  /**
   * Remote message subscription is intentionally unavailable in v1.
   * @param {function(object): void} _callback
   * @throws {Error} Always, while remote admission containment is active.
   */
  onMessage(_callback) {
    throw new Error(REMOTE_MESSAGES_DISABLED_MESSAGE);
  }

  /**
   * Listen for state changes.
   */
  onStateChange(callback) {
    this._onStateChange = callback;
  }

  /**
   * Delete a message (bilateral — requires peer consent).
   * @param {string} eventId
   */
  async deleteMessage(eventId) {
    await this._ledger.requestPrune({
      targetEventId: eventId,
      reason: 'userRequest',
    });
  }

  /**
   * GDPR delete — unilateral, no consent needed.
   * @param {string} eventId
   */
  async gdprDelete(eventId) {
    await this._ledger.requestPrune({
      targetEventId: eventId,
      reason: 'gdprArticle17',
    });
  }

  /**
   * Load chat history.
   * @param {object} [options]
   * @param {Date} [options.from]
   * @param {Date} [options.to]
   * @returns {Promise<object[]>}
   */
  async getHistory({ from, to } = {}) {
    const events = from && to
      ? await this._ledger.getHistoryRange({ from, to })
      : await this._ledger.getHistory();

    return events
      .filter((e) => e.eventType === EventType.MESSAGE && !e.isPruned)
      .map((e) => ({
        sender: e.senderPubkey,
        isMe: e.senderPubkey === this._ledger.identity.publicKey.toHex(),
        eventId: e.eventId,
        timestamp: e.createdAt,
        ...JSON.parse(new TextDecoder().decode(e.payload)),
      }));
  }

  /**
   * Verify the integrity of the entire chat history.
   * @returns {Promise<boolean>}
   */
  async verifyIntegrity() {
    const error = await this._ledger.validateChain();
    return error === null;
  }

  /**
   * Export identity backup as Shamir shares.
   * @returns {Promise<string[]>} 3 shares (any 2 can restore)
   */
  async backupIdentity() {
    return this._ledger.createIdentityBackup({ threshold: 2, totalShares: 3 });
  }

  /**
   * Shut down cleanly.
   */
  async disconnect() {
    await this._ledger.shutdown();
  }
}

export { SecureChat };

// --- Quick Start ---
//
// const chat = new SecureChat();
// await chat.initialize();
//
// // User A: Create room
// const code = await chat.createRoom();
// console.log('Share this code:', code);
//
// // User B: Join room
// await chat.joinRoom('abandon ability able about above absent');
//
// // Both: Verify
// const verifyCode = await chat.getVerificationCode();
// console.log('Verify code:', verifyCode); // "483 291"
//
// // After verification
// await chat.confirmConnection(peerPubkeyHex, 'Alice');
//
// // Local creation only. Calling chat.onMessage(...) fails closed with
// // STYX_V1_REMOTE_ADMISSION_DISABLED; no working peer receive path is claimed.
// await chat.sendText('Hello from Styx!');
