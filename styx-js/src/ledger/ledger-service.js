// styx-js/src/ledger/ledger-service.js
// High-level facade for ledger operations with persistent storage

import { EventEmitter } from '../utils.js';

/**
 * High-level facade for ledger operations.
 */
export class LedgerService {
  /**
   * @param {import('./event-factory.js').EventFactory} eventFactory
   * @param {import('./chain-validator.js').ChainValidator} chainValidator
   * @param {import('../storage/store-interface.js').LedgerStore} store
   * @param {string} localPeerRole - 'A' or 'B'
   */
  constructor(eventFactory, chainValidator, store, localPeerRole) {
    this._eventFactory = eventFactory;
    this._chainValidator = chainValidator;
    this._store = store;
    this._localPeerRole = localPeerRole;
    this._emitter = new EventEmitter();
  }

  /**
   * Append a new event to the local chain
   */
  async appendEvent({ type, payload, privateKey, publicKey }) {
    const latest = await this._store.getLatestEvent();
    const vc = await this._store.getCurrentVectorClock();

    const event = await this._eventFactory.createEvent({
      type,
      payload,
      privateKey,
      publicKey,
      previousEvent: latest,
      currentVectorClock: vc,
      localPeerRole: this._localPeerRole,
    });

    await this._store.appendEvent(event);
    this._emitter.emit('newEvent', event);
    return event;
  }

  /**
   * Receive and store a remote event
   */
  async receiveRemoteEvent(event) {
    await this._store.appendEvent(event);
    this._emitter.emit('remoteEvent', event);
    this._emitter.emit('newEvent', event);
    return event;
  }

  /**
   * Returns all events ordered by HLC
   * @returns {Promise<import('./event.js').LedgerEvent[]>}
   */
  async getHistory() {
    return this._store.getAllEvents();
  }

  /**
   * Returns events within a time range
   */
  async getHistoryRange(from, to) {
    const events = await this._store.getAllEvents();
    return events.filter(
      (e) => e.createdAt >= from && e.createdAt <= to
    );
  }

  /**
   * Validate the full chain
   * @returns {Promise<import('./event.js').ChainValidationError|null>}
   */
  async validateChain() {
    const events = await this._store.getAllEvents();
    return this._chainValidator.validateFullChain(events);
  }

  /**
   * Latest event or null
   */
  async getLatestEvent() {
    return this._store.getLatestEvent();
  }

  /**
   * Reactive stream: subscribe to new events
   * @param {function} callback
   * @returns {function} unsubscribe
   */
  onNewEvent(callback) {
    return this._emitter.on('newEvent', callback);
  }

  /**
   * Reactive stream: subscribe to remote events only
   * @param {function} callback
   * @returns {function} unsubscribe
   */
  onRemoteEvent(callback) {
    return this._emitter.on('remoteEvent', callback);
  }
}
