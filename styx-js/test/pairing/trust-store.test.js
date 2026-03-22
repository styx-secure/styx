import { describe, test, expect, beforeEach, beforeAll } from '@jest/globals';
import {
  TrustStoreManager,
  QrPairingData,
  QrPairingService,
  RemotePairingService,
  RemotePairingState,
} from '../../src/pairing/trust-store.js';
import { StyxPublicKey } from '../../src/crypto/identity.js';
import { Spake2Protocol } from '../../src/crypto/spake2.js';
import { MnemonicGenerator, DoubleCheckVerifier } from '../../src/crypto/mnemonic.js';
import { MemoryPeerStore } from '../../src/storage/memory-store.js';
import { createTestKeyPair, loadTestWordlist } from '../setup.js';

beforeAll(() => {
  loadTestWordlist();
});

describe('TrustStoreManager', () => {
  let peerStore, trustStore;

  beforeEach(() => {
    peerStore = new MemoryPeerStore();
    trustStore = new TrustStoreManager(peerStore);
  });

  test('addTrustedPeer and isTrusted', async () => {
    const kp = await createTestKeyPair();
    await trustStore.addTrustedPeer(kp.publicKey, 'Alice');
    expect(await trustStore.isTrusted(kp.publicKey)).toBe(true);
  });

  test('isTrusted returns false for unknown peer', async () => {
    const kp = await createTestKeyPair();
    expect(await trustStore.isTrusted(kp.publicKey)).toBe(false);
  });

  test('revokePeer makes isTrusted return false', async () => {
    const kp = await createTestKeyPair();
    await trustStore.addTrustedPeer(kp.publicKey, 'Alice');
    await trustStore.revokePeer(kp.publicKey);
    expect(await trustStore.isTrusted(kp.publicKey)).toBe(false);
  });

  test('getActivePeer returns first active, null when none', async () => {
    expect(await trustStore.getActivePeer()).toBeNull();
    const kp = await createTestKeyPair();
    await trustStore.addTrustedPeer(kp.publicKey, 'Alice');
    const peer = await trustStore.getActivePeer();
    expect(peer).not.toBeNull();
    expect(peer.alias).toBe('Alice');
  });

  test('updatePeerKey and getRekeyHistory', async () => {
    const kp1 = await createTestKeyPair();
    const kp2 = await createTestKeyPair();
    await trustStore.addTrustedPeer(kp1.publicKey, 'Alice');
    await trustStore.updatePeerKey(kp1.publicKey, kp2.publicKey);

    expect(await trustStore.isTrusted(kp1.publicKey)).toBe(false);
    expect(await trustStore.isTrusted(kp2.publicKey)).toBe(true);

    const history = await trustStore.getRekeyHistory(kp2.publicKey);
    expect(history.length).toBeGreaterThanOrEqual(1);
  });
});

describe('QrPairingData', () => {
  test('toQrPayload / fromQrPayload roundtrip', async () => {
    const kp = await createTestKeyPair();
    const nonce = new Uint8Array(16).fill(42);
    const data = new QrPairingData(kp.publicKey, nonce, ['wss://relay1.example']);
    const payload = data.toQrPayload();
    const restored = QrPairingData.fromQrPayload(payload);

    expect(restored.publicKey.toHex()).toBe(kp.publicKey.toHex());
    expect(restored.nonce).toEqual(nonce);
    expect(restored.relayHints).toEqual(['wss://relay1.example']);
  });

  test('roundtrip with no relay hints', async () => {
    const kp = await createTestKeyPair();
    const nonce = new Uint8Array(16).fill(7);
    const data = new QrPairingData(kp.publicKey, nonce, []);
    const payload = data.toQrPayload();
    const restored = QrPairingData.fromQrPayload(payload);

    expect(restored.relayHints).toEqual([]);
  });

  test('estimatedBytes', async () => {
    const kp = await createTestKeyPair();
    const nonce = new Uint8Array(16);
    const data = new QrPairingData(kp.publicKey, nonce, ['wss://r.example']);
    // 32 (pubkey) + 16 (nonce) + 1 (len byte) + hints length
    expect(data.estimatedBytes).toBe(32 + 16 + 1 + 'wss://r.example'.length);
  });
});

describe('QrPairingService', () => {
  let peerStore, trustStore, qrService;

  beforeEach(() => {
    peerStore = new MemoryPeerStore();
    trustStore = new TrustStoreManager(peerStore);
    qrService = new QrPairingService(trustStore);
  });

  test('generateQrData returns data with nonce', async () => {
    const kp = await createTestKeyPair();
    const data = qrService.generateQrData(kp.publicKey, ['wss://r.example']);
    expect(data.publicKey.toHex()).toBe(kp.publicKey.toHex());
    expect(data.nonce.length).toBe(16);
  });

  test('processScannedQr succeeds with valid payload', async () => {
    const localKp = await createTestKeyPair();
    const remoteKp = await createTestKeyPair();
    const qrData = new QrPairingData(remoteKp.publicKey, new Uint8Array(16), []);
    const payload = qrData.toQrPayload();

    const result = qrService.processScannedQr(payload, localKp.publicKey);
    expect(result.isValid).toBe(true);
    expect(result.peerPublicKey.toHex()).toBe(remoteKp.publicKey.toHex());
  });

  test('processScannedQr rejects self-pairing', async () => {
    const kp = await createTestKeyPair();
    const qrData = new QrPairingData(kp.publicKey, new Uint8Array(16), []);
    const payload = qrData.toQrPayload();

    const result = qrService.processScannedQr(payload, kp.publicKey);
    expect(result.isValid).toBe(false);
    expect(result.errorMessage).toContain('self');
  });

  test('processScannedQr handles invalid payload', () => {
    const kp = StyxPublicKey.fromHex('aa'.repeat(32));
    const result = qrService.processScannedQr('invalid!!!', kp);
    expect(result.isValid).toBe(false);
  });

  test('completePairing persists peer', async () => {
    const kp = await createTestKeyPair();
    await qrService.completePairing(kp.publicKey, 'Bob');
    expect(await trustStore.isTrusted(kp.publicKey)).toBe(true);
  });
});

describe('RemotePairingService', () => {
  let peerStore, trustStore, service;

  beforeEach(() => {
    peerStore = new MemoryPeerStore();
    trustStore = new TrustStoreManager(peerStore);
  });

  function createService() {
    return new RemotePairingService({
      spake2Protocol: new Spake2Protocol(),
      mnemonicGenerator: new MnemonicGenerator(),
      doubleCheckVerifier: new DoubleCheckVerifier(),
      trustStore,
      timeoutMs: 30000,
    });
  }

  test('generateMnemonic sets state to MNEMONIC_GENERATED', () => {
    const svc = createService();
    const mnemonic = svc.generateMnemonic(6);
    expect(mnemonic.split(' ')).toHaveLength(6);
    expect(svc.state).toBe(RemotePairingState.MNEMONIC_GENERATED);
  });

  test('full remote pairing flow', async () => {
    const initiator = createService();
    const responder = createService();
    const kpA = await createTestKeyPair();
    const kpB = await createTestKeyPair();

    const mnemonic = initiator.generateMnemonic(6);
    const msgA = initiator.startAsInitiator(mnemonic, kpA.publicKey);
    expect(initiator.state).toBe(RemotePairingState.WAITING_FOR_PEER);

    const msgB = responder.startAsResponder(mnemonic, kpB.publicKey);
    expect(responder.state).toBe(RemotePairingState.WAITING_FOR_PEER);

    const successA = initiator.processPeerMessage(msgB);
    expect(successA).toBe(true);
    expect(initiator.state).toBe(RemotePairingState.DOUBLE_CHECK_PENDING);

    const successB = responder.processPeerMessage(msgA);
    expect(successB).toBe(true);
    expect(responder.state).toBe(RemotePairingState.DOUBLE_CHECK_PENDING);

    // Double Check codes should match
    const codeA = initiator.getDoubleCheckCode();
    const codeB = responder.getDoubleCheckCode();
    expect(codeA).toBe(codeB);
    expect(codeA).toMatch(/^\d{3} \d{3}$/);

    // Confirm pairing
    await initiator.confirmDoubleCheck(true, kpB.publicKey, 'Bob');
    expect(initiator.state).toBe(RemotePairingState.COMPLETED);
    expect(await trustStore.isTrusted(kpB.publicKey)).toBe(true);
  });

  test('wrong password leads to different session keys', () => {
    const svc1 = createService();
    const svc2 = createService();
    const kpA = StyxPublicKey.fromHex('aa'.repeat(32));
    const kpB = StyxPublicKey.fromHex('bb'.repeat(32));

    const msg1 = svc1.startAsInitiator('abandon ability able about above absent', kpA);
    const msg2 = svc2.startAsResponder('absorb abstract absurd abuse access accident', kpB);

    // Processing should still succeed (SPAKE2 derives keys regardless)
    // but the session keys will differ, so Double Check codes won't match
    svc1.processPeerMessage(msg2);
    svc2.processPeerMessage(msg1);

    if (svc1.state === RemotePairingState.DOUBLE_CHECK_PENDING &&
        svc2.state === RemotePairingState.DOUBLE_CHECK_PENDING) {
      const code1 = svc1.getDoubleCheckCode();
      const code2 = svc2.getDoubleCheckCode();
      expect(code1).not.toBe(code2);
    }
  });

  test('confirmDoubleCheck with false sets FAILED', async () => {
    const svc = createService();
    const kpA = await createTestKeyPair();
    const kpB = await createTestKeyPair();

    const mnemonic = svc.generateMnemonic(6);
    const msg = svc.startAsInitiator(mnemonic, kpA.publicKey);

    const resp = createService();
    const msgB = resp.startAsResponder(mnemonic, kpB.publicKey);
    svc.processPeerMessage(msgB);

    await svc.confirmDoubleCheck(false, kpB.publicKey, 'Bob');
    expect(svc.state).toBe(RemotePairingState.FAILED);
  });

  test('deriveSharedTag is deterministic', () => {
    const tag1 = RemotePairingService.deriveSharedTag('abandon ability able');
    const tag2 = RemotePairingService.deriveSharedTag('abandon ability able');
    expect(tag1).toBe(tag2);
    expect(tag1).toHaveLength(16); // 8 bytes hex
  });

  test('cancel destroys session', async () => {
    const svc = createService();
    const kp = await createTestKeyPair();
    svc.generateMnemonic(6);
    svc.startAsInitiator(svc._mnemonic, kp.publicKey);
    svc.cancel();
    expect(svc.state).toBe(RemotePairingState.FAILED);
  });

  test('dispose cleans up', async () => {
    const svc = createService();
    const kp = await createTestKeyPair();
    svc.generateMnemonic(6);
    svc.startAsInitiator(svc._mnemonic, kp.publicKey);
    svc.dispose();
    // Should not throw
  });

  test('stateStream emits state changes', () => {
    const svc = createService();
    const states = [];
    svc.stateStream.on('stateChange', (s) => states.push(s));
    svc.generateMnemonic(6);
    expect(states).toContain(RemotePairingState.MNEMONIC_GENERATED);
  });
});
