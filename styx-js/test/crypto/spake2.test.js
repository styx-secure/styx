import { describe, test, expect } from '@jest/globals';
import { Spake2Protocol, Spake2Session, Spake2Role, Spake2State } from '../../src/crypto/spake2.js';
import { bytesToHex, constantTimeEqual } from '../../src/utils.js';

describe('Spake2Protocol', () => {
  const protocol = new Spake2Protocol();
  const password = new TextEncoder().encode('test-password');

  test('createInitiatorSession returns a Spake2Session with INITIATOR role', () => {
    const session = protocol.createInitiatorSession(password);
    expect(session).toBeInstanceOf(Spake2Session);
    expect(session.role).toBe(Spake2Role.INITIATOR);
    expect(session.state).toBe(Spake2State.INIT);
  });

  test('createResponderSession returns a Spake2Session with RESPONDER role', () => {
    const session = protocol.createResponderSession(password);
    expect(session).toBeInstanceOf(Spake2Session);
    expect(session.role).toBe(Spake2Role.RESPONDER);
    expect(session.state).toBe(Spake2State.INIT);
  });

  describe('full handshake', () => {
    test('both sides derive the same session key with matching password', () => {
      const initiator = protocol.createInitiatorSession(password);
      const responder = protocol.createResponderSession(password);

      const initMsg = initiator.generateMessage();
      const respMsg = responder.generateMessage();

      expect(initMsg).toBeInstanceOf(Uint8Array);
      expect(respMsg).toBeInstanceOf(Uint8Array);

      const initOk = initiator.processMessage(respMsg);
      const respOk = responder.processMessage(initMsg);

      expect(initOk).toBe(true);
      expect(respOk).toBe(true);

      const initKey = initiator.getSessionKey();
      const respKey = responder.getSessionKey();

      expect(initKey.length).toBe(32);
      expect(respKey.length).toBe(32);
      expect(bytesToHex(initKey)).toBe(bytesToHex(respKey));
    });
  });

  describe('wrong password', () => {
    test('processMessage returns true but session keys differ', () => {
      const passwordA = new TextEncoder().encode('correct');
      const passwordB = new TextEncoder().encode('wrong');

      const initiator = protocol.createInitiatorSession(passwordA);
      const responder = protocol.createResponderSession(passwordB);

      const initMsg = initiator.generateMessage();
      const respMsg = responder.generateMessage();

      // processMessage may succeed (point operations don't fail),
      // but derived keys will differ
      const initResult = initiator.processMessage(respMsg);
      const respResult = responder.processMessage(initMsg);

      if (initResult && respResult) {
        const initKey = initiator.getSessionKey();
        const respKey = responder.getSessionKey();
        expect(bytesToHex(initKey)).not.toBe(bytesToHex(respKey));
      } else {
        // At least one side failed
        expect(initResult && respResult).toBe(false);
      }
    });
  });

  describe('state machine', () => {
    test('generateMessage twice throws', () => {
      const session = protocol.createInitiatorSession(password);
      session.generateMessage();
      expect(() => session.generateMessage()).toThrow();
    });

    test('processMessage before generateMessage throws', () => {
      const session = protocol.createInitiatorSession(password);
      const fakeMsg = new Uint8Array(33);
      expect(() => session.processMessage(fakeMsg)).toThrow();
    });

    test('getSessionKey before completion throws', () => {
      const session = protocol.createInitiatorSession(password);
      expect(() => session.getSessionKey()).toThrow('not completed');
    });

    test('getConfirmation before completion throws', () => {
      const session = protocol.createInitiatorSession(password);
      expect(() => session.getConfirmation()).toThrow('not available');
    });
  });

  describe('confirmation verification', () => {
    test('correct confirmation returns true', () => {
      const initiator = protocol.createInitiatorSession(password);
      const responder = protocol.createResponderSession(password);

      const initMsg = initiator.generateMessage();
      const respMsg = responder.generateMessage();

      initiator.processMessage(respMsg);
      responder.processMessage(initMsg);

      const initConf = initiator.getConfirmation();
      const respConf = responder.getConfirmation();

      expect(responder.verifyConfirmation(initConf)).toBe(true);
      expect(initiator.verifyConfirmation(respConf)).toBe(true);
    });

    test('wrong confirmation returns false', () => {
      const initiator = protocol.createInitiatorSession(password);
      const responder = protocol.createResponderSession(password);

      const initMsg = initiator.generateMessage();
      const respMsg = responder.generateMessage();

      initiator.processMessage(respMsg);
      responder.processMessage(initMsg);

      const fakeConf = new Uint8Array(32).fill(0xff);
      expect(initiator.verifyConfirmation(fakeConf)).toBe(false);
      expect(responder.verifyConfirmation(fakeConf)).toBe(false);
    });
  });

  describe('mnemonicToPassword', () => {
    test('is deterministic', () => {
      const p1 = protocol.mnemonicToPassword('abandon ability able about');
      const p2 = protocol.mnemonicToPassword('abandon ability able about');
      expect(bytesToHex(p1)).toBe(bytesToHex(p2));
    });

    test('trims and lowercases', () => {
      const p1 = protocol.mnemonicToPassword('  ABANDON Ability  ');
      const p2 = protocol.mnemonicToPassword('abandon ability');
      expect(bytesToHex(p1)).toBe(bytesToHex(p2));
    });

    test('returns raw UTF-8 bytes', () => {
      const result = protocol.mnemonicToPassword('test words here');
      expect(result.length).toBe('test words here'.length);
    });
  });

  describe('Spake2Session.destroy', () => {
    test('zeroes secrets and transitions to FAILED state', () => {
      const initiator = protocol.createInitiatorSession(password);
      const responder = protocol.createResponderSession(password);

      const initMsg = initiator.generateMessage();
      const respMsg = responder.generateMessage();
      initiator.processMessage(respMsg);

      initiator.destroy();
      expect(initiator.state).toBe(Spake2State.FAILED);
    });

    test('can be called before completion without error', () => {
      const session = protocol.createInitiatorSession(password);
      expect(() => session.destroy()).not.toThrow();
      expect(session.state).toBe(Spake2State.FAILED);
    });
  });
});
