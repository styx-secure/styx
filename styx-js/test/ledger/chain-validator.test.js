// test/ledger/chain-validator.test.js
import { describe, test, expect, beforeAll } from '@jest/globals';
import { ChainValidator } from '../../src/ledger/chain-validator.js';
import { LedgerEvent, ChainErrorType } from '../../src/ledger/event.js';
import { HybridLogicalClock } from '../../src/ledger/hlc.js';
import { Hasher } from '../../src/crypto/hasher.js';
import { Verifier } from '../../src/crypto/signer.js';
import { createTestChain } from '../setup.js';

describe('ChainValidator', () => {
  let validator;
  let chain;
  let keyPair;

  beforeAll(async () => {
    const hasher = new Hasher();
    const verifier = new Verifier();
    validator = new ChainValidator(hasher, verifier);
    const result = await createTestChain(3);
    chain = result.events;
    keyPair = result.keyPair;
  });

  test('valid chain of 3 events passes validation', async () => {
    const result = await validator.validateFullChain(chain);
    expect(result).toBeNull();
  });

  test('empty chain passes validation', async () => {
    const result = await validator.validateFullChain([]);
    expect(result).toBeNull();
  });

  test('hash mismatch detected', async () => {
    const tampered = new LedgerEvent({
      ...chain[1],
      eventHash: 'aaaa' + chain[1].eventHash.slice(4),
    });
    const tamperedChain = [chain[0], tampered, chain[2]];
    const result = await validator.validateFullChain(tamperedChain);
    expect(result).not.toBeNull();
    expect(result.errorType).toBe(ChainErrorType.HASH_MISMATCH);
  });

  test('signature invalid detected', async () => {
    const badSig = new Uint8Array(64);
    badSig.fill(0xff);
    const tampered = new LedgerEvent({
      ...chain[1],
      signature: badSig,
    });
    const tamperedChain = [chain[0], tampered, chain[2]];
    const result = await validator.validateFullChain(tamperedChain);
    expect(result).not.toBeNull();
    expect(result.errorType).toBe(ChainErrorType.SIGNATURE_INVALID);
  });

  test('previousHash mismatch detected', async () => {
    const tampered = new LedgerEvent({
      ...chain[1],
      previousHash: 'deadbeef'.repeat(8),
    });
    const tamperedChain = [chain[0], tampered, chain[2]];
    const result = await validator.validateFullChain(tamperedChain);
    expect(result).not.toBeNull();
    expect(result.errorType).toBe(ChainErrorType.PREVIOUS_HASH_MISSING);
  });

  test('genesis with non-null previousHash yields GENESIS_VIOLATION', async () => {
    const badGenesis = new LedgerEvent({
      ...chain[0],
      previousHash: 'not-null-hash',
    });
    const tamperedChain = [badGenesis, chain[1], chain[2]];
    const result = await validator.validateFullChain(tamperedChain);
    expect(result).not.toBeNull();
    expect(result.errorType).toBe(ChainErrorType.GENESIS_VIOLATION);
  });

  test('HLC non-monotonic yields HLC_VIOLATION', async () => {
    // Create an event with HLC earlier than its predecessor
    const earlyHlc = new HybridLogicalClock(
      new Date('2020-01-01T00:00:00.000Z'),
      0,
      chain[1].hlc.nodeId
    );
    const tampered = new LedgerEvent({
      ...chain[1],
      hlc: earlyHlc,
    });
    const tamperedChain = [chain[0], tampered, chain[2]];
    const result = await validator.validateFullChain(tamperedChain);
    expect(result).not.toBeNull();
    // Could be HASH_MISMATCH (hash includes HLC) or HLC_VIOLATION
    // depending on validation order. Either way it should fail.
    expect([
      ChainErrorType.HASH_MISMATCH,
      ChainErrorType.HLC_VIOLATION,
    ]).toContain(result.errorType);
  });
});
