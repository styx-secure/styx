// websocket-polyfill.js — RelayPool (from styx-js) uses a GLOBAL `WebSocket`,
// which only exists natively in Node 21+. Ensure one on older runtimes (Node 20
// LTS) by falling back to the `ws` package. Import this FIRST, before anything
// that constructs a RelayPool.
if (typeof globalThis.WebSocket === 'undefined') {
  const { WebSocket } = await import('ws');
  globalThis.WebSocket = WebSocket;
}
