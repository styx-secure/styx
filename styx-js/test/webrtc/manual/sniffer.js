#!/usr/bin/env node
/**
 * WebSocket proxy/sniffer: sits between browser and Nostr relay.
 * Browser connects to ws://localhost:17888, proxy forwards to wss://nos.lol.
 * All traffic is logged in readable format.
 *
 * Usage: node test/webrtc/manual/sniffer.js
 */

import { WebSocketServer, WebSocket } from 'ws';

const RELAY = process.env.RELAY || 'ws://localhost:17777';
const PORT = 17888;

const wss = new WebSocketServer({ port: PORT });
let connId = 0;

// Colors for terminal
const CYAN = '\x1b[36m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED = '\x1b[31m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';

function formatNostrMsg(raw, direction, id) {
  const arrow = direction === 'out' ? `${CYAN}BROWSER → RELAY${RESET}` : `${GREEN}RELAY → BROWSER${RESET}`;
  const prefix = `${DIM}[peer ${id}]${RESET} ${arrow}`;

  try {
    const msg = JSON.parse(raw);
    const type = msg[0];

    if (type === 'EVENT' && msg[1]?.content) {
      const event = msg[1];
      const content = event.content;
      const isEncrypted = content.length > 50 && !content.startsWith('{');
      console.log(`${prefix} EVENT`);
      console.log(`  kind: ${event.kind}, pubkey: ${event.pubkey?.slice(0, 16)}...`);
      console.log(`  tags: ${JSON.stringify(event.tags)}`);
      if (isEncrypted) {
        console.log(`  content: ${YELLOW}[ENCRYPTED]${RESET} ${content.slice(0, 60)}...`);
        console.log(`  ${DIM}(${content.length} chars of ciphertext — relay CANNOT read this)${RESET}`);
      } else {
        console.log(`  content: ${content.slice(0, 200)}`);
      }
      console.log();
      return;
    }

    if (type === 'EVENT' && msg[2]?.content) {
      const event = msg[2];
      const content = event.content;
      const isEncrypted = content.length > 50 && !content.startsWith('{');
      console.log(`${prefix} EVENT (received)`);
      console.log(`  kind: ${event.kind}, from: ${event.pubkey?.slice(0, 16)}...`);
      console.log(`  tags: ${JSON.stringify(event.tags)}`);
      if (isEncrypted) {
        console.log(`  content: ${YELLOW}[ENCRYPTED]${RESET} ${content.slice(0, 60)}...`);
        console.log(`  ${DIM}(${content.length} chars of ciphertext)${RESET}`);
      } else {
        console.log(`  content: ${content.slice(0, 200)}`);
      }
      console.log();
      return;
    }

    if (type === 'REQ') {
      console.log(`${prefix} REQ subscription=${msg[1]} filter=${JSON.stringify(msg[2])}`);
      return;
    }

    if (type === 'OK') {
      const accepted = msg[2];
      const reason = msg[3] || '';
      console.log(`${prefix} OK ${accepted ? `${GREEN}accepted${RESET}` : `${RED}REJECTED: ${reason}${RESET}`}`);
      return;
    }

    if (type === 'EOSE') {
      console.log(`${prefix} ${DIM}EOSE (end of stored events)${RESET}`);
      return;
    }

    if (type === 'NOTICE') {
      console.log(`${prefix} ${YELLOW}NOTICE: ${msg[1]}${RESET}`);
      return;
    }

    console.log(`${prefix} ${raw.slice(0, 200)}`);
  } catch {
    console.log(`${prefix} ${raw.slice(0, 200)}`);
  }
}

wss.on('connection', (clientWs) => {
  const id = ++connId;
  console.log(`\n${GREEN}═══ Peer ${id} connected ═══${RESET}\n`);

  const relayWs = new WebSocket(RELAY);

  relayWs.on('open', () => {
    console.log(`${DIM}[peer ${id}]${RESET} Connected to relay ${RELAY}\n`);
  });

  // Browser → Relay
  clientWs.on('message', (data) => {
    const raw = data.toString();
    formatNostrMsg(raw, 'out', id);
    if (relayWs.readyState === WebSocket.OPEN) {
      relayWs.send(raw);
    }
  });

  // Relay → Browser
  relayWs.on('message', (data) => {
    const raw = data.toString();
    formatNostrMsg(raw, 'in', id);
    if (clientWs.readyState === WebSocket.OPEN) {
      clientWs.send(raw);
    }
  });

  clientWs.on('close', () => {
    console.log(`${RED}═══ Peer ${id} disconnected ═══${RESET}\n`);
    relayWs.close();
  });

  relayWs.on('close', () => {
    clientWs.close();
  });

  relayWs.on('error', (e) => {
    console.log(`${RED}[peer ${id}] Relay error: ${e.message}${RESET}`);
  });
});

console.log(`
${GREEN}╔════════════════════════════════════════════════════╗
║  Nostr WebSocket Sniffer                           ║
║  Browser → ws://localhost:${PORT} → wss://nos.lol   ║
║                                                    ║
║  All traffic logged below in readable format.      ║
║  Encrypted content marked as [ENCRYPTED].          ║
╚════════════════════════════════════════════════════╝${RESET}
`);
