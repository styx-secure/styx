// PROTOTYPE tests: identity port (seed + passphrase file) and NIP-59 wrap/unwrap.
import { describe, test, expect } from '@jest/globals';
import { mkdtempSync, readFileSync, statSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { schnorr } from '@noble/curves/secp256k1';
import { createSeedIdentity, createFileIdentity, verifyEvent, eventId } from '../../proto/identity.js';
import { hexToBytes, bytesToHex } from '../../src/utils.js';

const PASS = 'synthetic-test-passphrase-1';

describe('identity port', () => {
  test('seed identity is deterministic and signs verifiable schnorr signatures', () => {
    const a = createSeedIdentity({ seed: 'seed-one-xyz' });
    const b = createSeedIdentity({ seed: 'seed-one-xyz' });
    const c = createSeedIdentity({ seed: 'seed-two-xyz' });
    expect(a.getPublicKey()).toBe(b.getPublicKey());
    expect(a.getPublicKey()).not.toBe(c.getPublicKey());
    expect(a.getPublicKey()).toMatch(/^[0-9a-f]{64}$/);
    const digest = new Uint8Array(32).fill(7);
    expect(schnorr.verify(a.sign({ digest }), digest, hexToBytes(a.getPublicKey()))).toBe(true);
    expect(() => createSeedIdentity({ seed: 'short' })).toThrow();
    expect(Object.isFrozen(a)).toBe(true);
    expect(Object.keys(a).sort()).toEqual(['getPublicKey', 'giftWrap', 'sign', 'unwrapGift']);
  });

  test('file identity: created once, reloaded with the passphrase, refused with a wrong one; secret not in the file', () => {
    const dir = mkdtempSync(join(process.env.TMPDIR || tmpdir(), 'styx-id-'));
    try {
      const path = join(dir, 'id.json');
      const a = createFileIdentity({ path, passphrase: PASS });
      expect((statSync(path).mode & 0o777).toString(8)).toBe('600');
      const b = createFileIdentity({ path, passphrase: PASS });
      expect(b.getPublicKey()).toBe(a.getPublicKey());
      expect(() => createFileIdentity({ path, passphrase: 'wrong-passphrase-123' })).toThrow(/wrong passphrase/);
      expect(() => createFileIdentity({ path, passphrase: 'short' })).toThrow();
      const f = JSON.parse(readFileSync(path, 'utf8'));
      expect(Object.keys(f).sort()).toEqual(['N', 'cipher', 'ct', 'iv', 'kdf', 'p', 'pub', 'r', 'salt', 'tag', 'v']);
      // tamper with the public key -> AAD mismatch -> refused
      writeFileSync(path, JSON.stringify({ ...f, pub: createSeedIdentity({ seed: 'other-seed-1' }).getPublicKey() }));
      expect(() => createFileIdentity({ path, passphrase: PASS })).toThrow();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('NIP-59 gift wrap: only the recipient unwraps; author is the seal signer; wrap key is one-time', () => {
    const alice = createSeedIdentity({ seed: 'alice-gw-seed' });
    const bob = createSeedIdentity({ seed: 'bob-gw-seed' });
    const eve = createSeedIdentity({ seed: 'eve-gw-seed' });
    const w1 = alice.giftWrap({ rumor: { kind: 4744, content: 'secret-welcome', tags: [['e', 'a'.repeat(64)]] }, recipient: bob.getPublicKey() });
    const w2 = alice.giftWrap({ rumor: { kind: 4744, content: 'secret-welcome', tags: [] }, recipient: bob.getPublicKey() });
    expect(w1.kind).toBe(1059);
    expect(verifyEvent(w1)).toBe(true);
    expect(w1.pubkey).not.toBe(alice.getPublicKey());
    expect(w1.pubkey).not.toBe(w2.pubkey);
    expect(w1.tags).toEqual([['p', bob.getPublicKey()]]);
    expect(JSON.stringify(w1)).not.toContain('secret-welcome');
    const u = bob.unwrapGift(w1);
    expect(u.sealPubkey).toBe(alice.getPublicKey());
    expect(u.rumor.content).toBe('secret-welcome');
    expect(() => eve.unwrapGift(w1)).toThrow();
    // a tampered wrap fails its signature check
    expect(() => bob.unwrapGift({ ...w1, content: w1.content.slice(0, -4) + 'AAAA' })).toThrow();
    expect(eventId(w1)).toBe(w1.id);
    expect(bytesToHex(hexToBytes(w1.sig))).toBe(w1.sig);
  });
});
