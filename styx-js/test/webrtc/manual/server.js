#!/usr/bin/env node
/**
 * Minimal signaling server for manual WebRTC testing.
 *
 * Usage: node test/webrtc/manual/server.js
 * Then open http://localhost:3456 in two different browsers.
 */

import { createServer } from 'http';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { WebSocketServer } from 'ws';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = 3456;

const html = readFileSync(join(__dirname, 'index.html'), 'utf-8');
const nostrHtml = readFileSync(join(__dirname, 'nostr-signaling.html'), 'utf-8');
const chatHtml = readFileSync(join(__dirname, 'nostr-chat.html'), 'utf-8');

const httpServer = createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  if (req.url === '/nostr') {
    res.end(nostrHtml);
  } else if (req.url === '/chat') {
    res.end(chatHtml);
  } else {
    res.end(html);
  }
});

const wss = new WebSocketServer({ server: httpServer });
const peers = new Map(); // ws → { id, ready }
let nextId = 1;

function checkReady() {
  const readyList = [...peers.entries()].filter(([, p]) => p.ready);
  if (readyList.length >= 2) {
    // Tell the lowest-ID peer to create the offer
    readyList.sort((a, b) => a[1].id - b[1].id);
    const offererWs = readyList[0][0];
    offererWs.send(JSON.stringify({ type: 'start-offer' }));
    console.log(`  → Told peer ${readyList[0][1].id} to create offer`);
  }
}

wss.on('connection', (ws) => {
  const id = nextId++;
  peers.set(ws, { id, ready: false });
  console.log(`Peer ${id} connected (${peers.size} total)`);

  ws.send(JSON.stringify({ type: 'welcome', id }));

  ws.on('message', (raw) => {
    const msg = JSON.parse(raw.toString());

    if (msg.type === 'ready') {
      peers.get(ws).ready = true;
      console.log(`Peer ${id} ready`);
      checkReady();
      return;
    }

    // Forward signaling (offer, answer, candidate) to all other peers
    for (const [peerWs, peerInfo] of peers) {
      if (peerWs !== ws && peerWs.readyState === 1) {
        peerWs.send(raw.toString());
      }
    }
  });

  ws.on('close', () => {
    console.log(`Peer ${id} disconnected`);
    peers.delete(ws);
  });
});

httpServer.listen(PORT, () => {
  console.log(`\n  Signaling server running on http://localhost:${PORT}`);
  console.log(`  Open this URL in two different browsers (Chrome + Edge, etc.)\n`);
});
