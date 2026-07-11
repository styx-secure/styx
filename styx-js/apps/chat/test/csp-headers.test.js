// test/csp-headers.test.js — the served CSP must be strict where it counts.
import { describe, test, expect } from '@jest/globals';
import { buildCsp } from '../static-server.mjs';

describe('buildCsp', () => {
  const csp = buildCsp();

  test('locks the default to none', () => {
    expect(csp).toMatch(/(^|; )default-src 'none'(;|$)/);
  });

  test('allows wasm compilation but never inline scripts', () => {
    expect(csp).toContain("script-src 'self' 'wasm-unsafe-eval'");
    // no unsafe-inline / unsafe-eval on the script directive
    expect(csp).not.toMatch(/script-src[^;]*'unsafe-inline'/);
    expect(csp).not.toMatch(/script-src[^;]*'unsafe-eval'/);
  });

  test('connect-src is limited to self and the default relays', () => {
    expect(csp).toMatch(/connect-src 'self' wss:\/\/relay\.damus\.io wss:\/\/nos\.lol/);
  });

  test('a deployer can extend connect-src via STYX_CONNECT_SRC', () => {
    const withExtra = buildCsp('https://push.example wss://relay.self.host');
    expect(withExtra).toContain("connect-src 'self' wss://relay.damus.io wss://nos.lol https://push.example wss://relay.self.host");
  });

  test('frames and objects and base-uri are shut', () => {
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("base-uri 'none'");
  });
});
