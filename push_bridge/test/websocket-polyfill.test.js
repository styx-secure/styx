// test/websocket-polyfill.test.js — after importing the polyfill, a global
// WebSocket must exist (native on Node 21+, ws fallback on Node 20).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import '../src/websocket-polyfill.js';

test('a global WebSocket is available after importing the polyfill', () => {
  assert.equal(typeof globalThis.WebSocket, 'function');
});
