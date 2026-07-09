// test/chat/contact-roster.test.js
import { describe, test, expect, beforeEach } from '@jest/globals';
import { ContactRoster } from '../../src/chat/contact-roster.js';

/** Minimal in-memory KV backend for tests. */
function memoryBackend() {
  const map = new Map();
  return {
    async get(key) {
      return map.has(key) ? map.get(key) : null;
    },
    async set(key, value) {
      map.set(key, value);
    },
    async delete(key) {
      map.delete(key);
    },
  };
}

describe('ContactRoster', () => {
  let roster;

  beforeEach(async () => {
    roster = new ContactRoster({ backend: memoryBackend() });
    await roster.load();
  });

  test('add then list returns the contact with defaults', async () => {
    await roster.add({ pubkey: 'aa', alias: 'Alice' });

    const list = await roster.list();

    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({
      pubkey: 'aa',
      alias: 'Alice',
      unread: 0,
      online: false,
      lastPreview: null,
      lastTs: null,
    });
  });

  test('re-adding an existing pubkey updates alias but keeps metadata', async () => {
    await roster.add({ pubkey: 'aa', alias: 'Alice' });
    await roster.touch('aa', { preview: 'hi', ts: 100, incrementUnread: true });

    await roster.add({ pubkey: 'aa', alias: 'Alice Smith' });

    const c = await roster.get('aa');
    expect(c.alias).toBe('Alice Smith');
    expect(c.unread).toBe(1);
    expect(c.lastPreview).toBe('hi');
  });

  test('list is ordered by lastTs desc, inactive contacts last', async () => {
    await roster.add({ pubkey: 'aa', alias: 'Alice' });
    await roster.add({ pubkey: 'bb', alias: 'Bob' });
    await roster.add({ pubkey: 'cc', alias: 'Carol' });
    await roster.touch('aa', { preview: 'x', ts: 100 });
    await roster.touch('bb', { preview: 'y', ts: 300 });

    const order = (await roster.list()).map((c) => c.pubkey);

    expect(order).toEqual(['bb', 'aa', 'cc']);
  });

  test('touch with incrementUnread bumps the counter, clearUnread resets it', async () => {
    await roster.add({ pubkey: 'aa', alias: 'Alice' });
    await roster.touch('aa', { preview: 'm1', ts: 1, incrementUnread: true });
    await roster.touch('aa', { preview: 'm2', ts: 2, incrementUnread: true });

    expect((await roster.get('aa')).unread).toBe(2);

    await roster.clearUnread('aa');
    expect((await roster.get('aa')).unread).toBe(0);
  });

  test('remove deletes the contact', async () => {
    await roster.add({ pubkey: 'aa', alias: 'Alice' });
    await roster.remove('aa');

    expect(await roster.get('aa')).toBeNull();
    expect(await roster.list()).toHaveLength(0);
  });

  test('update merges a partial patch', async () => {
    await roster.add({ pubkey: 'aa', alias: 'Alice' });
    await roster.update('aa', { alias: 'Renamed' });

    expect((await roster.get('aa')).alias).toBe('Renamed');
  });

  test('operations on an unknown contact throw', async () => {
    await expect(
      roster.touch('zz', { preview: 'x', ts: 1 }),
    ).rejects.toThrow('Unknown contact');
    await expect(roster.update('zz', { alias: 'x' })).rejects.toThrow(
      'Unknown contact',
    );
  });

  test('setOnline flips the runtime presence flag without persisting', async () => {
    await roster.add({ pubkey: 'aa', alias: 'Alice' });

    await roster.setOnline('aa', true);
    expect((await roster.get('aa')).online).toBe(true);

    await roster.setOnline('aa', false);
    expect((await roster.get('aa')).online).toBe(false);
  });

  test('onChanged fires with the full list after a mutation', async () => {
    const seen = [];
    roster.onChanged((list) => seen.push(list));

    await roster.add({ pubkey: 'aa', alias: 'Alice' });

    expect(seen).toHaveLength(1);
    expect(seen[0][0].pubkey).toBe('aa');
  });

  test('metadata persists across a reload with the same backend', async () => {
    const backend = memoryBackend();
    const first = new ContactRoster({ backend });
    await first.load();
    await first.add({ pubkey: 'aa', alias: 'Alice' });
    await first.touch('aa', { preview: 'saved', ts: 42, incrementUnread: true });

    const second = new ContactRoster({ backend });
    await second.load();
    const c = await second.get('aa');

    expect(c).toMatchObject({
      alias: 'Alice',
      lastPreview: 'saved',
      lastTs: 42,
      unread: 1,
      online: false,
    });
  });

  test('using the roster before load() throws', async () => {
    const fresh = new ContactRoster({ backend: memoryBackend() });
    await expect(fresh.list()).rejects.toThrow('call load() first');
  });
});
