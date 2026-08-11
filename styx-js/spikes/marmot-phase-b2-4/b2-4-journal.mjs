// STYX_SPIKE_PROTOTYPE — isolated v1 namespace for Phase B2.4 only.

import {
  B23_STORE_NAMES,
  assertString,
} from '../marmot-phase-b2-3/b2-3-canonical.mjs';
import { B23Journal } from '../marmot-phase-b2-3/b2-3-journal.mjs';
import { openVaultDb } from '../../src/storage/vault-db.js';
import {
  B24_DB_PREFIX,
  B24_ERROR,
  failB24,
} from './b2-4-canonical.mjs';

const B24_JOURNAL_TOKEN = Symbol('B24_JOURNAL_TOKEN');

function migrationV1(db) {
  for (const name of B23_STORE_NAMES) db.createObjectStore(name);
}

/** Narrow wrapper: callers never receive the permissive B2.3 journal object. */
export class B24Journal {
  #inner;

  constructor(inner, token) {
    if (token !== B24_JOURNAL_TOKEN) {
      failB24(B24_ERROR.INVALID, 'B2.4 journals must be created by the namespace factory');
    }
    this.#inner = inner;
    Object.freeze(this);
  }

  initialize(args) { return this.#inner.initialize(args); }

  read(groupIdHex) { return this.#inner.read(groupIdHex); }

  cas(args) { return this.#inner.cas(args); }

  recordPublishIntent(groupIdHex, artifact) {
    return this.#inner.recordPublishIntent(groupIdHex, artifact);
  }

  appendPublicationEvidence(groupIdHex, payloadBytes) {
    return this.#inner.appendPublicationEvidence(groupIdHex, payloadBytes);
  }

  close() { this.#inner.close(); }

  destroy() { return this.#inner.destroy(); }
}

export function createB24JournalForDb(db, options = {}) {
  if (typeof db?.name !== 'string' || !db.name.startsWith(B24_DB_PREFIX)) {
    failB24(B24_ERROR.INVALID, 'the database is outside the B2.4 namespace');
  }
  return new B24Journal(new B23Journal(db, options), B24_JOURNAL_TOKEN);
}

export async function openB24Journal({
  databaseTag,
  indexedDBImpl = globalThis.indexedDB,
  setTimeoutImpl = globalThis.setTimeout.bind(globalThis),
  clearTimeoutImpl = globalThis.clearTimeout.bind(globalThis),
  randomBytes = globalThis.crypto?.getRandomValues?.bind(globalThis.crypto),
} = {}) {
  assertString('databaseTag', databaseTag, { min: 1, max: 64, pattern: /^[a-z0-9-]+$/ });
  const db = await openVaultDb({
    name: `${B24_DB_PREFIX}${databaseTag}`,
    version: 1,
    migrations: { 1: migrationV1 },
    indexedDBImpl,
    setTimeoutImpl,
    clearTimeoutImpl,
  });
  return createB24JournalForDb(db, { randomBytes });
}
