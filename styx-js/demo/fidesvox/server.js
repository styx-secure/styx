#!/usr/bin/env node
/**
 * FidesVox Demo Server
 *
 * Express app with JWT auth, SQLite persistence, and Nostr subscriber.
 *
 * Usage:
 *   1. docker compose -f docker-compose.test.yml up -d   (start strfry)
 *   2. node demo/fidesvox/server.js                       (start this server)
 *   3. Open http://localhost:3456/login in a browser
 */

import express from 'express';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { readFileSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import WebSocket from 'ws';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { x25519 } from '@noble/curves/ed25519';

import db, {
  insertUser,
  getUserByEmail,
  getUserById,
  updateUserPubkey,
  updateUserKeypair,
  insertResponse,
  insertPrivateReport,
  insertMetadata,
  getAllResponses,
  getAllPrivateReports,
  getAllMetadata,
} from './db.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = 3456;
const RELAY_URL = 'ws://localhost:17777';
const JWT_SECRET = 'fidesvox-demo-secret';

// --- Server Nostr identity (hardcoded for demo) ---
const SERVER_PRIV_HEX = '2a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc03';
const SERVER_PRIV = hexToBytes(SERVER_PRIV_HEX);
const SERVER_PUB = bytesToHex(schnorr.getPublicKey(SERVER_PRIV));

// --- Colors ---
const C = { reset: '\x1b[0m', green: '\x1b[32m', yellow: '\x1b[33m', cyan: '\x1b[36m', red: '\x1b[31m', dim: '\x1b[2m', magenta: '\x1b[35m' };

function log(color, label, msg) {
  const t = new Date().toLocaleTimeString('it-IT', { hour12: false });
  console.log(`${C.dim}${t}${C.reset} ${color}[${label}]${C.reset} ${msg}`);
}

// --- Load styx-js bundle for inline embedding ---
const BUNDLE_PATH = join(__dirname, '..', '..', 'dist', 'fidesvox.min.js');
const styxBundle = existsSync(BUNDLE_PATH) ? readFileSync(BUNDLE_PATH, 'utf-8') : null;

if (styxBundle) {
  log(C.green, 'BUNDLE', `Loaded styx-js bundle: ${(styxBundle.length / 1024).toFixed(1)}KB`);
} else {
  log(C.yellow, 'BUNDLE', 'Bundle not found — forms will use CDN. Run: npm run build:fidesvox');
}

// --- Survey schema (for validation) ---
const formHtmlRaw = readFileSync(join(__dirname, 'pages', 'form.html'), 'utf-8');
const schemaMatch = formHtmlRaw.match(/const SCHEMA = ({[\s\S]*?});/);
let SURVEY_SCHEMA = { questions: [] };
try { SURVEY_SCHEMA = JSON.parse(schemaMatch?.[1] || '{"questions":[]}'); } catch {}
const PRIVATE_FIELDS = new Set(
  (SURVEY_SCHEMA.questions || []).filter(q => q.private).map(q => q.id)
);

// --- Helpers ---
function bytesToHex(b) { return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join(''); }
function hexToBytes(h) { const a = new Uint8Array(h.length / 2); for (let i = 0; i < h.length; i += 2) a[i / 2] = parseInt(h.substr(i, 2), 16); return a; }
function concatBytes(...arrays) {
  const r = new Uint8Array(arrays.reduce((s, a) => s + a.length, 0));
  let o = 0; for (const a of arrays) { r.set(a, o); o += a.length; }
  return r;
}

function signEvent(event) {
  const ser = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
  const idBytes = sha256(new TextEncoder().encode(ser));
  event.id = bytesToHex(idBytes);
  event.sig = bytesToHex(schnorr.sign(idBytes, SERVER_PRIV));
  return event;
}

function verifyEvent(event) {
  const ser = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
  const idBytes = sha256(new TextEncoder().encode(ser));
  const expectedId = bytesToHex(idBytes);
  if (event.id !== expectedId) return false;
  try {
    return schnorr.verify(hexToBytes(event.sig), idBytes, hexToBytes(event.pubkey));
  } catch { return false; }
}

// --- Server-side decryption ---
function decryptWithServerKey(encryptedContent) {
  try {
    // Format: ephemeralPubkeyHex (64 chars) + base64(nonce || ciphertext || tag)
    const ephPubHex = encryptedContent.slice(0, 64);
    const b64 = encryptedContent.slice(64);
    const combined = Uint8Array.from(atob(b64), c => c.charCodeAt(0));

    const ephPub = hexToBytes(ephPubHex);
    const sharedSecret = x25519.getSharedSecret(SERVER_PRIV, ephPub);
    const encKey = hkdf(sha256, sharedSecret, 'fidesvox-e2e', '', 32);

    const nonce = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    const decipher = chacha20poly1305(encKey, nonce);
    const plaintext = decipher.decrypt(ciphertext);

    return new TextDecoder().decode(plaintext);
  } catch (err) {
    log(C.red, 'DECRYPT', `Failed to decrypt: ${err.message}`);
    return null;
  }
}

// --- PoW verification + Rate limiting ---
const POW_DIFFICULTY = 20;
const rateLimitMap = new Map(); // pubkey → { count, firstSeen }
const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const RATE_LIMIT_MAX = 5; // max events per pubkey per window

function verifyPoW(event) {
  const nonceTag = event.tags?.find(t => t[0] === 'nonce');
  if (!nonceTag) return false;

  const claimedDifficulty = parseInt(nonceTag[2]);
  if (claimedDifficulty < POW_DIFFICULTY) return false;

  // Recompute event ID and check leading zeros
  const ser = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
  const hash = sha256(new TextEncoder().encode(ser));
  const computedId = bytesToHex(hash);

  if (computedId !== event.id) return false;

  // Count leading zero bits
  let bits = 0;
  for (const byte of hash) {
    if (byte === 0) { bits += 8; continue; }
    bits += Math.clz32(byte) - 24;
    break;
  }

  return bits >= POW_DIFFICULTY;
}

function checkRateLimit(pubkey) {
  const now = Date.now();
  const entry = rateLimitMap.get(pubkey);

  if (!entry || (now - entry.firstSeen) > RATE_LIMIT_WINDOW_MS) {
    rateLimitMap.set(pubkey, { count: 1, firstSeen: now });
    return true;
  }

  entry.count++;
  if (entry.count > RATE_LIMIT_MAX) {
    return false;
  }
  return true;
}

// Clean up rate limit map periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitMap) {
    if ((now - entry.firstSeen) > RATE_LIMIT_WINDOW_MS) rateLimitMap.delete(key);
  }
}, 60000);

// --- Auth middleware ---
function requireAuth(req, res, next) {
  const token = req.cookies?.jwt;
  if (!token) return res.redirect('/login');
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.redirect('/login');
  }
}

function requireAuthApi(req, res, next) {
  const token = req.cookies?.jwt;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// --- Express App ---
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// --- Serve styx-js bundle ---
if (styxBundle) {
  app.get('/styx.js', (req, res) => {
    res.type('application/javascript').send(styxBundle);
  });
}

// --- Page Routes ---
app.get('/', (req, res) => res.redirect('/login'));

app.get('/register', (req, res) => {
  res.sendFile(join(__dirname, 'pages', 'register.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(join(__dirname, 'pages', 'login.html'));
});

app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(join(__dirname, 'pages', 'dashboard.html'));
});

app.get('/form/:surveyId', (req, res) => {
  // Read form HTML, inject the RPG's pubkey if available
  let html = readFileSync(join(__dirname, 'pages', 'form.html'), 'utf-8');

  // Find the first user with a nostr_pubkey to use as recipient
  const rpg = db.prepare('SELECT nostr_pubkey FROM users WHERE nostr_pubkey IS NOT NULL LIMIT 1').get();
  if (rpg?.nostr_pubkey) {
    html = html.replace(
      /recipientPubKey:\s*'[^']*'/,
      `recipientPubKey: '${rpg.nostr_pubkey}'`
    );
  }

  // Inject surveyId
  html = html.replace(
    /surveyId:\s*'[^']*'/,
    `surveyId: '${req.params.surveyId}'`
  );

  // Embed styx-js bundle inline — makes the HTML fully self-contained
  if (styxBundle) {
    // Inject bundle as a regular <script> BEFORE the module script
    // The IIFE sets window.Styx, the module script destructures from it
    const bundleScript = `<script>\n// styx-js (${(styxBundle.length/1024).toFixed(0)}KB inline)\n${styxBundle}\n</script>\n`;
    html = html.replace('<script type="module">', bundleScript + '<script type="module">');

    // Replace CDN imports with destructuring from the global Styx
    const importBlock = /\/\/ __STYX_BUNDLE_PLACEHOLDER__\n\/\/ CDN fallback.*\nimport \{[^}]*\} from [^\n]*\nimport \{[^}]*\} from [^\n]*\nimport \{[^}]*\} from [^\n]*\nimport \{[^}]*\} from [^\n]*\nimport \{[^}]*\} from [^\n]*/;
    html = html.replace(importBlock,
      `const { schnorr, sha256, chacha20poly1305, hkdf, x25519 } = Styx;`
    );
    log(C.green, 'FORM', `Generated self-contained HTML (${(html.length/1024).toFixed(0)}KB total)`);
  }

  res.type('html').send(html);
});

// --- API Routes ---

app.post('/api/register', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send('Email and password are required');
  }

  if (password.length < 6) {
    return res.status(400).send('Password must be at least 6 characters');
  }

  const existing = getUserByEmail.get(email);
  if (existing) {
    return res.status(409).send('Email already registered');
  }

  const hash = bcrypt.hashSync(password, 10);
  try {
    insertUser.run(email, hash);
    log(C.green, 'AUTH', `New user registered: ${email}`);
    res.redirect('/login');
  } catch (err) {
    log(C.red, 'AUTH', `Registration error: ${err.message}`);
    res.status(500).send('Registration failed');
  }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send('Email and password are required');
  }

  const user = getUserByEmail.get(email);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).send('Invalid email or password');
  }

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
  res.cookie('jwt', token, { httpOnly: true, path: '/', maxAge: 86400000 });
  log(C.green, 'AUTH', `User logged in: ${email}`);
  res.redirect('/dashboard');
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('jwt', { path: '/' });
  res.redirect('/login');
});

app.post('/api/keypair', requireAuthApi, (req, res) => {
  const { pubkey, encryptedPrivkey } = req.body;
  if (!pubkey || typeof pubkey !== 'string' || pubkey.length !== 64) {
    return res.status(400).json({ error: 'Invalid pubkey (must be 64-char hex)' });
  }

  if (encryptedPrivkey) {
    // Save both pubkey and encrypted private key blob
    const blob = JSON.stringify(encryptedPrivkey);
    updateUserKeypair.run(pubkey, blob, req.user.id);
    log(C.green, 'KEYPAIR', `User ${req.user.email} set pubkey + encrypted blob: ${pubkey.slice(0, 16)}...`);
  } else {
    updateUserPubkey.run(pubkey, req.user.id);
    log(C.green, 'KEYPAIR', `User ${req.user.email} set pubkey: ${pubkey.slice(0, 16)}...`);
  }
  res.json({ success: true });
});

app.get('/api/me', requireAuthApi, (req, res) => {
  const user = getUserById.get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({
    id: user.id,
    email: user.email,
    nostr_pubkey: user.nostr_pubkey,
    encrypted_privkey_blob: user.encrypted_privkey_blob ? JSON.parse(user.encrypted_privkey_blob) : null,
    created_at: user.created_at,
    server_pubkey: SERVER_PUB,
  });
});

app.get('/api/reports', requireAuthApi, (req, res) => {
  const responses = getAllResponses();
  const privateReports = getAllPrivateReports();
  const metadata = getAllMetadata();

  res.json({
    survey_responses: responses,
    private_reports: privateReports,
    report_metadata: metadata,
  });
});

// --- Nostr Subscriber ---
let relayWs = null;
let eventCount = 0;

function connectToRelay() {
  relayWs = new WebSocket(RELAY_URL);

  relayWs.on('open', () => {
    log(C.green, 'RELAY', `Connected to ${RELAY_URL}`);
    log(C.green, 'RELAY', `Server pubkey: ${SERVER_PUB.slice(0, 16)}...`);

    // Subscribe to fidesvox events
    relayWs.send(JSON.stringify(['REQ', 'fv-all', {
      kinds: [4000, 4001, 4002],
      '#t': ['fidesvox'],
    }]));
    log(C.cyan, 'SUB', 'Subscribed to fidesvox kinds [4000, 4001, 4002]');
  });

  relayWs.on('message', (raw) => {
    const msg = JSON.parse(raw.toString());

    if (msg[0] === 'EOSE') return;
    if (msg[0] === 'OK') {
      if (msg[2]) {
        log(C.dim, 'OK', `Event ${msg[1].slice(0, 12)}... accepted by relay`);
      } else {
        log(C.red, 'REJECT', `Event rejected: ${msg[3]}`);
      }
      return;
    }
    if (msg[0] !== 'EVENT' || !msg[2]) return;

    processEvent(msg[2]);
  });

  relayWs.on('close', () => {
    log(C.yellow, 'RELAY', 'Disconnected. Reconnecting in 3s...');
    setTimeout(connectToRelay, 3000);
  });

  relayWs.on('error', (e) => {
    log(C.red, 'RELAY', `Error: ${e.message}`);
  });
}

function processEvent(event) {
  // Verify NIP-01 signature
  if (!verifyEvent(event)) {
    log(C.red, 'REJECT', `Invalid signature from ${event.pubkey.slice(0, 12)}...`);
    return;
  }

  // Verify Proof of Work (NIP-13)
  if (!verifyPoW(event)) {
    log(C.red, 'SPAM', `Missing or invalid PoW from ${event.pubkey.slice(0, 12)}... — rejected`);
    return;
  }

  // Rate limiting per pubkey
  if (!checkRateLimit(event.pubkey)) {
    log(C.red, 'RATE', `Rate limit exceeded for ${event.pubkey.slice(0, 12)}... — rejected`);
    return;
  }

  eventCount++;
  const now = new Date().toISOString();

  if (event.kind === 4000) {
    // PRIVATE report — encrypted blob, store as-is
    // Try to extract survey_id and org_id from decryption is not possible
    // since this is encrypted for the RPG, not the server.
    // Store with placeholder survey/org from tags or defaults.
    insertPrivateReport.run(
      'survey-demo-001',
      'org-nexadata',
      event.content,
      event.id,
      now
    );
    log(C.green, 'DB', `Saved PRIVATE report (kind 4000) — ${event.content.length} bytes encrypted`);
  }

  if (event.kind === 4001) {
    // PUBLIC + META combined — encrypted for the server, decrypt it
    const plaintext = decryptWithServerKey(event.content);
    if (!plaintext) {
      log(C.red, 'DECRYPT', 'Could not decrypt kind 4001 event');
      return;
    }

    let content;
    try {
      content = JSON.parse(plaintext);
    } catch {
      log(C.red, 'PARSE', 'Invalid JSON in decrypted kind 4001');
      return;
    }

    // Defense: check no private fields leaked in public answers
    if (content.public_answers) {
      const leaked = Object.keys(content.public_answers).filter(k => PRIVATE_FIELDS.has(k));
      if (leaked.length > 0) {
        log(C.red, 'SECURITY', `Rejected: public answers contain private fields: ${leaked.join(', ')}`);
        return;
      }
    }

    // Save survey response (public answers)
    insertResponse.run(
      content.survey_id || 'unknown',
      content.org_id || 'unknown',
      JSON.stringify(content.public_answers || {}),
      event.id,
      now
    );
    log(C.green, 'DB', `Saved PUBLIC response for survey ${content.survey_id}`);
    log(C.dim, 'DB', `  Answers: ${JSON.stringify(content.public_answers)}`);

    // Save metadata
    insertMetadata.run(
      content.survey_id || 'unknown',
      content.org_id || 'unknown',
      content.channel || 'WEB',
      'nostr',
      content.has_private_bucket ? 1 : 0,
      event.id + '-meta',
      now
    );
    log(C.green, 'DB', `Saved METADATA for survey ${content.survey_id}`);

    // Publish receipt (kind 4003)
    publishReceipt(event.pubkey, content.survey_id || 'unknown', event.id);
  }

  if (event.kind === 4002) {
    // METADATA only (legacy or standalone)
    const plaintext = decryptWithServerKey(event.content);
    let content = {};
    if (plaintext) {
      try { content = JSON.parse(plaintext); } catch { /* ignore */ }
    }

    insertMetadata.run(
      content.survey_id || 'unknown',
      content.org_id || 'unknown',
      content.channel || 'WEB',
      content.source || 'nostr',
      content.has_private_bucket ? 1 : 0,
      event.id,
      now
    );
    log(C.green, 'DB', `Saved METADATA (kind 4002) for survey ${content.survey_id || 'unknown'}`);

    publishReceipt(event.pubkey, content.survey_id || 'unknown', event.id);
  }
}

function publishReceipt(recipientPubKey, surveyId, originalEventId) {
  const receipt = signEvent({
    pubkey: SERVER_PUB,
    created_at: Math.floor(Date.now() / 1000),
    kind: 4003,
    tags: [
      ['p', recipientPubKey],
      ['t', 'fidesvox'],
      ['e', originalEventId],
    ],
    content: JSON.stringify({
      status: 'received',
      survey_id: surveyId,
      timestamp: new Date().toISOString(),
    }),
  });

  if (relayWs && relayWs.readyState === WebSocket.OPEN) {
    relayWs.send(JSON.stringify(['EVENT', receipt]));
    log(C.magenta, 'RECEIPT', `Published receipt (kind 4003) for ${recipientPubKey.slice(0, 12)}... (survey: ${surveyId})`);
  }
}

// --- Start ---
app.listen(PORT, () => {
  console.log(`
${C.green}+-----------------------------------------------------------+
|  FidesVox Demo Server                                     |
|                                                           |
|  Register: http://localhost:${PORT}/register                 |
|  Login:    http://localhost:${PORT}/login                    |
|  Form:     http://localhost:${PORT}/form/survey-demo-001     |
|  Relay:    ${RELAY_URL}                              |
|  DB:       demo/fidesvox/fidesvox.db                      |
|                                                           |
|  Server pubkey: ${SERVER_PUB.slice(0, 40)}...  |
+-----------------------------------------------------------+${C.reset}
`);
  connectToRelay();
});
