// Configuration-only tests: no relay connection is ever started here.
import { describe, test, expect } from '@jest/globals';
import { createStyxClient, SDK_INTERFACE_VERSION } from '../../src/sdk/index.js';
import { isAllowedRelayUrl, isPublicRelayHost } from '../../src/sdk/relay-url.js';

const SEP = ':' + '/' + '/';
const host = ['relay', 'example', 'test'].join('.');
const url = (authority, scheme = 'wss', suffix = '') => [scheme, SEP, authority, suffix].join('');
const config = (overrides = {}) => ({
  interfaceVersion: SDK_INTERFACE_VERSION,
  relays: [`ws${SEP}127.0.0.1:7000`],
  ports: {
    storage: { put() {}, get() {}, update() {}, remove() {}, list() {} },
    session: { seal() {}, open() {} },
    identity: { getPublicKey() {}, sign() {} },
  },
  ...overrides,
});
const code = (value) => createStyxClient(value).code;

test('caller-allowlisted wss configuration is accepted without calling a port', () => {
  const value = config({ publicRelayHosts: [host], relays: [url(host)] });
  let calls = 0;
  for (const port of Object.values(value.ports)) {
    for (const name of Object.keys(port)) port[name] = () => { calls += 1; throw new Error('port called'); };
  }
  expect(createStyxClient(value).ok).toBe(true);
  expect(calls).toBe(0);
});

describe('M3-PUBLIC-RELAYS exact configuration', () => {
  const long253 = ['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(61)].join('.');
  const valid = [host, 'a.b', 'xn--bcher-kva.example.test', 'relay.0xzz', `${'a'.repeat(63)}.test`, long253];
  const invalid = ['', 'single', 'Relay.example.test', 'relay..example.test', '.relay.test', 'relay.test.',
    '-a.test', 'a-.test', `${'a'.repeat(64)}.test`, `${long253}d`, 'relay.123', 'relay.0x7f',
    'relay.0x', 'relay.0XAB', '127.0.0.1', '[::1]', 'relay_1.test', 'relay%2e.test', 'relay.test:443',
    'bücher.test', 'relay.test\n', 'relay.test\r', 'relay.test\u2028', 'relay.test\u2029'];

  test.each(valid)('accepts exact ASCII host %s', (name) => {
    expect(isPublicRelayHost(name)).toBe(true);
    expect(createStyxClient(config({ publicRelayHosts: [name], relays: [url(name)] })).ok).toBe(true);
  });
  test.each(invalid)('rejects malformed host %s', (name) => {
    expect(isPublicRelayHost(name)).toBe(false);
    expect(code(config({ publicRelayHosts: [name] }))).toBe('E_SDK_INVALID_CONFIG');
  });
  test('list type, count, distinctness, sparse/accessor entries; absent differs from undefined', () => {
    const names = Array.from({ length: 16 }, (_, i) => `r${i}.example.test`);
    expect(createStyxClient(config({ publicRelayHosts: names })).ok).toBe(true);
    expect(createStyxClient(config()).ok).toBe(true);
    const getter = [host];
    Object.defineProperty(getter, '0', { get() { throw new Error('never read'); } });
    for (const value of [[], [...names, 'last.example.test'], [host, host], host, null, undefined, [1], [host, ,], getter]) {
      expect(code(config({ publicRelayHosts: value }))).toBe('E_SDK_INVALID_CONFIG');
    }
    const ownGetter = config();
    Object.defineProperty(ownGetter, 'publicRelayHosts', { get() { throw new Error('never read'); } });
    expect(code(ownGetter)).toBe('E_SDK_INVALID_CONFIG');
  });
  test.each([url(host), url(host, 'wss', '/'), url(host.toUpperCase(), 'WSS')])('accepts unchanged remote string %s', (value) => {
    expect(isAllowedRelayUrl(value, [host])).toBe(true);
    expect(createStyxClient(config({ publicRelayHosts: [host], relays: [value] })).ok).toBe(true);
    expect(code(config({ relays: [value] }))).toBe('E_SDK_INVALID_CONFIG');
  });
  test.each([
    url(host, 'ws'), url(`${host}:`), url(`${host}:443`), url(`${host}:8443`), url(host, 'wss', '/x'),
    url(host, 'wss', '?x=1'), url(host, 'wss', '#f'), url(`u@${host}`), url('other.example.test'),
    url(`${host}.`), url('10.0.0.1'), url('[2001:db8::1]'), url(host, 'wss', '//'),
    url(host, 'wss', '\n'), url('relay%2eexample.test'), url(host, 'wss', '/?'), url(host, 'wss', '/#'),
  ])('rejects remote string %s', (value) => {
    expect(isAllowedRelayUrl(value, [host])).toBe(false);
    expect(code(config({ publicRelayHosts: [host], relays: [value] }))).toBe('E_SDK_INVALID_CONFIG');
  });
  test('old version is unsupported before malformed fields', () => {
    expect(SDK_INTERFACE_VERSION).toBe('styx-m3-sdk/0.2.0-experimental');
    expect(code(config({ interfaceVersion: 'styx-m3-sdk/0.1.0-experimental', publicRelayHosts: [] })))
      .toBe('E_SDK_UNSUPPORTED_VERSION');
  });
});

test('an old-version inbound event is discarded before session open; admitted URL is unchanged', async () => {
  const original = globalThis.WebSocket;
  const sockets = [];
  let opened = 0;
  const events = [];
  const endpoint = url(host.toUpperCase(), 'WSS', '/');
  class SyntheticSocket {
    static OPEN = 1;
    constructor(address) {
      this.address = address;
      this.readyState = 0;
      sockets.push(this);
      queueMicrotask(() => { this.readyState = 1; this.onopen?.(); });
    }
    send(raw) {
      const frame = JSON.parse(raw);
      if (frame[0] === 'REQ') this.subscription = frame[1];
    }
    close() { this.readyState = 3; this.onclose?.(); }
  }
  globalThis.WebSocket = SyntheticSocket;
  const value = config({ publicRelayHosts: [host], relays: [endpoint], delivery: { perRelayTimeoutMs: 11000 } });
  value.ports.storage.list = () => [];
  value.ports.identity.getPublicKey = () => 'a'.repeat(64);
  value.ports.session.open = () => { opened += 1; return { plaintext: new Uint8Array([1]) }; };
  const created = createStyxClient(value);
  expect(created.ok).toBe(true);
  try {
    await created.value.onEvent((event) => events.push(event));
    expect((await created.value.start()).ok).toBe(true);
    expect(sockets).toHaveLength(1);
    expect(sockets[0].address).toBe(endpoint);
    sockets[0].onmessage({ data: JSON.stringify(['EVENT', sockets[0].subscription, {
      id: '0'.repeat(64), pubkey: 'b'.repeat(64), created_at: 1, kind: 4741,
      tags: [['p', 'a'.repeat(64)], ['v', 'styx-m3-sdk/0.1.0-experimental'], ['n', '0'.repeat(32)]],
      content: 'AQ==', sig: '0'.repeat(128),
    }]) });
    for (let i = 0; i < 40; i += 1) await Promise.resolve();
    expect(events.filter((event) => event.kind === 'INBOUND_DISCARDED'))
      .toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_INBOUND_INVALID' }]);
    expect(events.some((event) => event.kind === 'MESSAGE_RECEIVED')).toBe(false);
    expect(opened).toBe(0);
  } finally {
    expect((await created.value.shutdown()).ok).toBe(true);
    expect(sockets.every((socket) => socket.readyState === 3)).toBe(true);
    globalThis.WebSocket = original;
  }
});

// Original I-SDK URL cases are moved here byte-for-byte, including their assertions.
describe('unchanged I-SDK loopback rule', () => {
  test('relay strings accepted', () => {
    const accepted = [
      `ws${SEP}127.0.0.1:7000`, `wss${SEP}127.255.255.254/x?y=1`, `WS${SEP}127.0.0.1`, `ws${SEP}127.0.0.1:080`,
      `ws${SEP}127.0.0.1:`, `ws${SEP}[::1]:1`, `ws${SEP}[0:0:0:0:0:0:0:1]`, `ws${SEP}[::0001]/`,
      `ws${SEP}[::0.0.0.1]`, `wSs${SEP}127.0.0.1/a/b%20c?q=1&r=%2F`, `ws${SEP}127.0.0.1:99999`,
    ];
    for (const url of accepted) {
      expect([url, createStyxClient(config({ relays: [url] })).ok]).toEqual([url, true]);
    }
  });

  test('relay strings rejected (non-loopback hosts are assembled at run time)', () => {
    const ws = (host) => ['ws', SEP, host].join('');
    const rejected = [
      ws('localhost'), ws('128.0.0.1'), ws('10.0.0.1'), ws('127.0.0.01'), ws('127.1'),
      ws('[::ffff:127.0.0.1]'), ws('[v1.x]'), ws('[::1%25lo]'), ws(['u', '@', '127.0.0.1'].join('')),
      ws('127.0.0.1#f'), ws('127.0.0.1/%zz'), ws('127.0.0.1/%2'), ws('127.0.0.1/a b'), ws('127.0.0.1/a\\b'),
      ['http', SEP, '127.0.0.1'].join(''), '', ws(''), ws('[::2]'), ws('[1::1]'), ws('[::1'),
      ws('127.0.0.1:x'), ws('127.0.0.1 '), ['ws', ':', '127.0.0.1'].join(''), ws('256.0.0.1'),
      ws('[::1:2:3:4:5:6:7:8]'), ws('[::1]x'),
    ];
    for (const url of rejected) {
      expect([url, code(config({ relays: [url] }))]).toEqual([url, 'E_SDK_INVALID_CONFIG']);
    }
  });

});
