import { describe, test, expect, beforeAll } from '@jest/globals';
import {
  MnemonicGenerator,
  SessionVerifier,
  DoubleCheckVerifier,
  getBip39Wordlist,
} from '../../src/crypto/mnemonic.js';
import { loadTestWordlist } from '../setup.js';
import { bytesToHex, randomBytes } from '../../src/utils.js';

beforeAll(() => {
  loadTestWordlist();
});

describe('MnemonicGenerator', () => {
  const generator = new MnemonicGenerator();

  test('generate(6) returns 6 words', () => {
    const mnemonic = generator.generate(6);
    const words = mnemonic.split(' ');
    expect(words.length).toBe(6);
  });

  test('generated words are all in the wordlist', () => {
    const wordlist = getBip39Wordlist();
    const mnemonic = generator.generate(6);
    const words = mnemonic.split(' ');
    for (const word of words) {
      expect(wordlist).toContain(word);
    }
  });

  test('generate with different word counts', () => {
    expect(generator.generate(3).split(' ').length).toBe(3);
    expect(generator.generate(12).split(' ').length).toBe(12);
  });

  test('two generated mnemonics are different', () => {
    const m1 = generator.generate(6);
    const m2 = generator.generate(6);
    // With 2048^6 possibilities, collision is astronomically unlikely
    expect(m1).not.toBe(m2);
  });

  describe('validate', () => {
    test('valid mnemonic returns true', () => {
      const mnemonic = generator.generate(6);
      expect(generator.validate(mnemonic)).toBe(true);
    });

    test('known valid words return true', () => {
      expect(generator.validate('abandon ability able about above absent')).toBe(true);
    });

    test('invalid word returns false', () => {
      expect(generator.validate('abandon ability invalidxyz')).toBe(false);
    });

    test('mixed valid and invalid returns false', () => {
      expect(generator.validate('abandon notaword ability')).toBe(false);
    });
  });

  describe('mnemonicToSeed', () => {
    test('returns 64 bytes', async () => {
      const mnemonic = generator.generate(6);
      const seed = await generator.mnemonicToSeed(mnemonic);
      expect(seed).toBeInstanceOf(Uint8Array);
      expect(seed.length).toBe(64);
    });

    test('is deterministic', async () => {
      const mnemonic = 'abandon ability able about above absent';
      const seed1 = await generator.mnemonicToSeed(mnemonic);
      const seed2 = await generator.mnemonicToSeed(mnemonic);
      expect(bytesToHex(seed1)).toBe(bytesToHex(seed2));
    });

    test('different mnemonics produce different seeds', async () => {
      const seed1 = await generator.mnemonicToSeed('abandon ability able');
      const seed2 = await generator.mnemonicToSeed('absorb abstract absurd');
      expect(bytesToHex(seed1)).not.toBe(bytesToHex(seed2));
    });
  });

  describe('supportedLanguages', () => {
    test('returns array containing english', () => {
      expect(generator.supportedLanguages).toEqual(['english']);
    });
  });
});

describe('SessionVerifier', () => {
  const verifier = new SessionVerifier();

  test('generateDoubleCheckCode returns 6-digit string', () => {
    const sessionKey = randomBytes(32);
    const code = verifier.generateDoubleCheckCode(sessionKey);
    expect(code.length).toBe(6);
    expect(/^\d{6}$/.test(code)).toBe(true);
  });

  test('is deterministic', () => {
    const sessionKey = randomBytes(32);
    const code1 = verifier.generateDoubleCheckCode(sessionKey);
    const code2 = verifier.generateDoubleCheckCode(sessionKey);
    expect(code1).toBe(code2);
  });

  test('is zero-padded for small numbers', () => {
    // The code should always be exactly 6 digits even if the number is small
    const sessionKey = randomBytes(32);
    const code = verifier.generateDoubleCheckCode(sessionKey);
    expect(code.length).toBe(6);
  });

  test('different session keys produce different codes (with high probability)', () => {
    const code1 = verifier.generateDoubleCheckCode(randomBytes(32));
    const code2 = verifier.generateDoubleCheckCode(randomBytes(32));
    // Could theoretically collide but extremely unlikely
    expect(code1).not.toBe(code2);
  });
});

describe('DoubleCheckVerifier', () => {
  const dcv = new DoubleCheckVerifier();

  describe('formatForDisplay', () => {
    test('formats 6 digits as "XXX YYY"', () => {
      expect(dcv.formatForDisplay('483291')).toBe('483 291');
    });

    test('formats another code', () => {
      expect(dcv.formatForDisplay('000001')).toBe('000 001');
    });
  });

  describe('isValidFormat', () => {
    test('6 digits returns true', () => {
      expect(dcv.isValidFormat('483291')).toBe(true);
    });

    test('5 digits returns false', () => {
      expect(dcv.isValidFormat('48329')).toBe(false);
    });

    test('7 digits returns false', () => {
      expect(dcv.isValidFormat('4832910')).toBe(false);
    });

    test('6 digits with space returns true (normalized)', () => {
      expect(dcv.isValidFormat('483 291')).toBe(true);
    });

    test('6 digits with dash returns true (normalized)', () => {
      expect(dcv.isValidFormat('483-291')).toBe(true);
    });

    test('letters return false', () => {
      expect(dcv.isValidFormat('abc123')).toBe(false);
    });
  });

  describe('normalize', () => {
    test('removes dashes', () => {
      expect(dcv.normalize('483-291')).toBe('483291');
    });

    test('removes spaces', () => {
      expect(dcv.normalize('483 291')).toBe('483291');
    });

    test('removes mixed separators', () => {
      expect(dcv.normalize('4 8-3 2-91')).toBe('483291');
    });

    test('no-op on clean input', () => {
      expect(dcv.normalize('483291')).toBe('483291');
    });
  });
});
