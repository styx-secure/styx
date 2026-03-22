import { describe, test, expect } from '@jest/globals';
import { Signer } from '../../src/crypto/signer.js';
import { Verifier } from '../../src/crypto/signer.js';
import { IdentityManager } from '../../src/crypto/identity.js';
import { utf8Encode } from '../../src/utils.js';

describe('Signer and Verifier', () => {
  const signer = new Signer();
  const verifier = new Verifier();
  const im = new IdentityManager();

  test('sign returns a 64-byte signature', async () => {
    const kp = await im.generate();
    const payload = utf8Encode('test message');
    const sig = await signer.sign(payload, kp.privateKey);
    expect(sig).toBeInstanceOf(Uint8Array);
    expect(sig.length).toBe(64);
  });

  test('verify returns true for correct signature', async () => {
    const kp = await im.generate();
    const payload = utf8Encode('hello styx');
    const sig = await signer.sign(payload, kp.privateKey);
    const valid = await verifier.verify(payload, sig, kp.publicKey);
    expect(valid).toBe(true);
  });

  test('verify returns false with wrong public key', async () => {
    const kp1 = await im.generate();
    const kp2 = await im.generate();
    const payload = utf8Encode('message');
    const sig = await signer.sign(payload, kp1.privateKey);
    const valid = await verifier.verify(payload, sig, kp2.publicKey);
    expect(valid).toBe(false);
  });

  test('verify returns false with tampered payload', async () => {
    const kp = await im.generate();
    const payload = utf8Encode('original');
    const sig = await signer.sign(payload, kp.privateKey);
    const tampered = utf8Encode('tampered');
    const valid = await verifier.verify(tampered, sig, kp.publicKey);
    expect(valid).toBe(false);
  });

  test('verify returns false with tampered signature', async () => {
    const kp = await im.generate();
    const payload = utf8Encode('data');
    const sig = await signer.sign(payload, kp.privateKey);
    const tamperedSig = new Uint8Array(sig);
    tamperedSig[0] ^= 0xff;
    const valid = await verifier.verify(payload, tamperedSig, kp.publicKey);
    expect(valid).toBe(false);
  });

  test('different messages produce different signatures', async () => {
    const kp = await im.generate();
    const sig1 = await signer.sign(utf8Encode('msg1'), kp.privateKey);
    const sig2 = await signer.sign(utf8Encode('msg2'), kp.privateKey);
    expect(Buffer.from(sig1).equals(Buffer.from(sig2))).toBe(false);
  });
});
