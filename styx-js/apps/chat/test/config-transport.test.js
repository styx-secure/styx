// test/config-transport.test.js — which transport the app is allowed to use.
// The unauthenticated BroadcastChannel transport must be reachable only in the
// relay-less dev mode (?local=1); a deployed app talks to relays and must never
// silently opt into it.
import { describe, test, expect } from '@jest/globals';
import { transportOptions } from '../src/lib/config.js';

describe('transportOptions', () => {
  test('with relays configured, the insecure transport stays forbidden', () => {
    expect(transportOptions(['wss://relay.damus.io'])).toEqual({
      relays: ['wss://relay.damus.io'],
      allowInsecureTransport: false,
    });
  });

  test('with several relays, still forbidden', () => {
    const relays = ['wss://a', 'wss://b'];
    expect(transportOptions(relays).allowInsecureTransport).toBe(false);
  });

  test('with no relays (?local=1), the dev transport is explicitly opted into', () => {
    expect(transportOptions([])).toEqual({ relays: [], allowInsecureTransport: true });
  });

  test('a missing/invalid relay list degrades to the dev transport, never to a silent none', () => {
    expect(transportOptions(undefined).allowInsecureTransport).toBe(true);
    expect(transportOptions(null).relays).toEqual([]);
  });
});
