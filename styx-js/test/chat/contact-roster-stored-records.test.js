// test/chat/contact-roster-stored-records.test.js
// A contact index written before inbound validation existed may hold fields of
// the wrong type. load() neutralises them, so listing and sorting never throw,
// and the cleaned index is written back at the next save.
import { describe, test, expect } from '@jest/globals';
import { ContactRoster } from '../../src/chat/contact-roster.js';

const INDEX_KEY = 'styx:contacts';

function memBackend(initial = {}) {
  const m = new Map(Object.entries(initial));
  return {
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async set(k, v) { m.set(k, v); },
    async delete(k) { m.delete(k); },
  };
}

const poisoned = { valueOf: 0, toString: 0 };

describe('ContactRoster stored-record neutralisation', () => {
  test('a non-primitive lastTs is neutralised at load; list() sorts without throwing', async () => {
    const backend = memBackend({
      [INDEX_KEY]: {
        aa: { pubkey: 'aa', alias: 'A', unread: 2, lastPreview: 'x', lastTs: poisoned, verified: false, verifiedAt: null },
        bb: { pubkey: 'bb', alias: 'B', unread: 0, lastPreview: 'y', lastTs: 300, verified: true, verifiedAt: 5 },
      },
    });
    const roster = new ContactRoster({ backend });
    await roster.load();
    const list = await roster.list();
    expect(list.map((c) => c.pubkey)).toEqual(['bb', 'aa']);
    expect(list[1]).toMatchObject({ pubkey: 'aa', lastTs: null, unread: 2, lastPreview: 'x' });
    expect(list[0]).toMatchObject({ pubkey: 'bb', lastTs: 300, verified: true, verifiedAt: 5 });
  });

  test('fields of the wrong type take their empty value; non-object records are dropped', async () => {
    const backend = memBackend({
      [INDEX_KEY]: {
        aa: { alias: poisoned, unread: '3', lastPreview: poisoned, lastTs: '12', verified: 'yes', verifiedAt: poisoned },
        bb: 'not a record',
        cc: [1, 2],
      },
    });
    const roster = new ContactRoster({ backend });
    await roster.load();
    expect(await roster.list()).toEqual([{
      pubkey: 'aa', alias: '', unread: 0, lastPreview: null, lastTs: null,
      verified: false, verifiedAt: null, online: false,
    }]);
  });

  test('the cleaned index is written back at the next save', async () => {
    const backend = memBackend({
      [INDEX_KEY]: { aa: { pubkey: 'aa', alias: 'A', unread: 0, lastPreview: null, lastTs: poisoned } },
    });
    const roster = new ContactRoster({ backend });
    await roster.load();
    await roster.clearUnread('aa');
    expect((await backend.get(INDEX_KEY)).aa.lastTs).toBeNull();
  });

  test('a malformed index loads as empty', async () => {
    for (const index of ['x', [1], 7]) {
      const roster = new ContactRoster({ backend: memBackend({ [INDEX_KEY]: index }) });
      // eslint-disable-next-line no-await-in-loop
      await roster.load();
      // eslint-disable-next-line no-await-in-loop
      expect(await roster.list()).toEqual([]);
    }
  });

  test('touch() refuses a timestamp outside the accepted range', async () => {
    const roster = new ContactRoster({ backend: memBackend() });
    await roster.load();
    await roster.add({ pubkey: 'aa', alias: 'A' });
    await expect(roster.touch('aa', { preview: 'x', ts: poisoned })).rejects.toThrow(TypeError);
    await expect(roster.touch('aa', { preview: 'x', ts: 1.5 })).rejects.toThrow(TypeError);
    expect((await roster.get('aa')).lastTs).toBeNull();
  });
});
