/**
 * Prototype identity port -- PROTOTYPE (branch proto/sdk-demo-2026-10, not for merge).
 *
 * Lives OUTSIDE styx-js/src/sdk/** on purpose: the identity port is supplied
 * by the caller (C-SDK 8.3) and is the only place that holds a secret key.
 * The SDK sees `getPublicKey()` and `sign({ digest })`; the invite flow also
 * uses two prototype extensions that keep the secret inside the port:
 * `giftWrap({ rumor, recipient })` and `unwrapGift(event)` (NIP-59 with
 * NIP-44 v2 from the `nostr-tools` library; no own cipher code).
 *
 * Two ways to obtain keys, both deliberately simple:
 *   - createSeedIdentity({ seed }): in memory, secret = SHA-256(label || seed).
 *     For tests and throwaway demo runs only.
 *   - createFileIdentity({ path, passphrase }): one local file, created on
 *     first use with a random key, encrypted with scrypt (N=2^15, r=8, p=1)
 *     + AES-256-GCM from node:crypto; the passphrase comes from the caller
 *     (the demo reads it from the environment). Mode 0600. No rotation, no
 *     backup, no hardware binding.
 */

import { readFileSync, writeFileSync, existsSync, renameSync } from 'node:fs';
import { scryptSync, randomBytes as nodeRandom, createCipheriv, createDecipheriv } from 'node:crypto';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { v2 as nip44 } from 'nostr-tools/nip44';
import { bytesToHex, hexToBytes, utf8Encode } from '../src/utils.js';

const HEX64 = /^[0-9a-f]{64}$/;
const TWO_DAYS = 2 * 24 * 3600;

/** NIP-01 event id. */
export function eventId(ev) {
  return bytesToHex(sha256(utf8Encode(JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]))));
}

/** NIP-01 verification: id binds content and the schnorr signature verifies. */
export function verifyEvent(ev) {
  try {
    if (!ev || !HEX64.test(ev.pubkey) || !HEX64.test(ev.id) || typeof ev.sig !== 'string') return false;
    if (eventId(ev) !== ev.id) return false;
    return schnorr.verify(hexToBytes(ev.sig), hexToBytes(ev.id), hexToBytes(ev.pubkey));
  } catch {
    return false;
  }
}

function signWith(sk, ev) {
  const out = { ...ev, pubkey: bytesToHex(schnorr.getPublicKey(sk)) };
  out.id = eventId(out);
  out.sig = bytesToHex(schnorr.sign(hexToBytes(out.id), sk));
  return out;
}

const randomPast = (now) => now - Math.floor(Math.random() * TWO_DAYS);

function makePort(sk) {
  const pk = bytesToHex(schnorr.getPublicKey(sk));
  return Object.freeze({
    getPublicKey: () => pk,
    sign: ({ digest }) => schnorr.sign(digest, sk),

    /**
     * NIP-59: rumor (unsigned, author = us) -> seal kind 13 signed by us,
     * NIP-44 to recipient -> gift wrap kind 1059 signed by a one-time key,
     * NIP-44 to recipient, p-tagged to recipient.
     */
    giftWrap({ rumor, recipient }) {
      if (!HEX64.test(recipient)) throw new Error('giftWrap: bad recipient');
      const now = Math.floor(Date.now() / 1000);
      const r = { kind: rumor.kind, content: rumor.content, tags: rumor.tags ?? [], created_at: rumor.created_at ?? now, pubkey: pk };
      r.id = eventId(r);
      const seal = signWith(sk, {
        kind: 13, tags: [], created_at: randomPast(now),
        content: nip44.encrypt(JSON.stringify(r), nip44.utils.getConversationKey(sk, recipient)),
      });
      const eph = schnorr.utils.randomPrivateKey();
      const wrap = signWith(eph, {
        kind: 1059, tags: [['p', recipient]], created_at: randomPast(now),
        content: nip44.encrypt(JSON.stringify(seal), nip44.utils.getConversationKey(eph, recipient)),
      });
      eph.fill(0);
      return wrap;
    },

    /**
     * Unwrap a kind-1059 addressed to us. Returns { rumor, sealPubkey } only
     * when the wrap and the seal both verify and the rumor's author is the
     * seal signer; throws otherwise.
     */
    unwrapGift(wrap) {
      if (!wrap || wrap.kind !== 1059 || !verifyEvent(wrap)) throw new Error('unwrap: bad wrap');
      const seal = JSON.parse(nip44.decrypt(wrap.content, nip44.utils.getConversationKey(sk, wrap.pubkey)));
      if (!seal || seal.kind !== 13 || !verifyEvent(seal)) throw new Error('unwrap: bad seal');
      const rumor = JSON.parse(nip44.decrypt(seal.content, nip44.utils.getConversationKey(sk, seal.pubkey)));
      if (!rumor || rumor.pubkey !== seal.pubkey || eventId(rumor) !== rumor.id) throw new Error('unwrap: rumor author is not the seal signer');
      return { rumor, sealPubkey: seal.pubkey };
    },
  });
}

/** In-memory identity from a seed (tests, throwaway runs). */
export function createSeedIdentity({ seed }) {
  if (typeof seed !== 'string' || seed.length < 8) throw new Error('seed identity: seed of at least 8 chars required');
  const sk = sha256(utf8Encode(`styx-proto-identity:v0:${seed}`));
  return makePort(sk);
}

const KDF = { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

/** Persisted identity: one passphrase-encrypted local file. */
export function createFileIdentity({ path, passphrase }) {
  if (typeof passphrase !== 'string' || passphrase.length < 12) throw new Error('file identity: passphrase of at least 12 chars required');
  let sk;
  if (existsSync(path)) {
    const f = JSON.parse(readFileSync(path, 'utf8'));
    if (f.v !== 1 || f.kdf !== 'scrypt') throw new Error('file identity: unknown format');
    const key = scryptSync(passphrase, Buffer.from(f.salt, 'base64'), 32, { N: f.N, r: f.r, p: f.p, maxmem: KDF.maxmem });
    const d = createDecipheriv('aes-256-gcm', key, Buffer.from(f.iv, 'base64'));
    d.setAAD(Buffer.from(f.pub, 'utf8'));
    d.setAuthTag(Buffer.from(f.tag, 'base64'));
    try {
      sk = new Uint8Array(Buffer.concat([d.update(Buffer.from(f.ct, 'base64')), d.final()]));
    } catch {
      throw new Error('file identity: wrong passphrase or damaged file');
    }
    if (bytesToHex(schnorr.getPublicKey(sk)) !== f.pub) throw new Error('file identity: key does not match stored public key');
  } else {
    sk = schnorr.utils.randomPrivateKey();
    const pub = bytesToHex(schnorr.getPublicKey(sk));
    const salt = nodeRandom(16);
    const iv = nodeRandom(12);
    const key = scryptSync(passphrase, salt, 32, KDF);
    const c = createCipheriv('aes-256-gcm', key, iv);
    c.setAAD(Buffer.from(pub, 'utf8'));
    const ct = Buffer.concat([c.update(Buffer.from(sk)), c.final()]);
    const body = {
      v: 1, kdf: 'scrypt', N: KDF.N, r: KDF.r, p: KDF.p, cipher: 'aes-256-gcm', pub,
      salt: salt.toString('base64'), iv: iv.toString('base64'), ct: ct.toString('base64'), tag: c.getAuthTag().toString('base64'),
    };
    writeFileSync(path + '.tmp', JSON.stringify(body), { mode: 0o600 });
    renameSync(path + '.tmp', path);
  }
  return makePort(sk);
}
