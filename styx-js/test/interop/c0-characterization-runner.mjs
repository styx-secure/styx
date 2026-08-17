import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

import { Hasher } from '../../src/crypto/hasher.js';
import { StyxPrivateKey, StyxPublicKey } from '../../src/crypto/identity.js';
import { Signer, Verifier } from '../../src/crypto/signer.js';
import { EventFactory } from '../../src/ledger/event-factory.js';
import {
  ChainErrorType,
  EventType,
  LedgerEvent,
} from '../../src/ledger/event.js';
import { DeterministicMerge } from '../../src/ledger/fork-merge.js';
import { HybridLogicalClock } from '../../src/ledger/hlc.js';
import { ChainValidator } from '../../src/ledger/chain-validator.js';
import { VectorClock } from '../../src/ledger/vector-clock.js';
import { bytesToHex, hexToBytes } from '../../src/utils.js';

const BASE_SHA = 'f0f7c35fa030477f56ea3b29efa1381f0d2dc972';
const SCHEMA_VERSION = '1';

function compareCodeUnits(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === 'object') {
    const result = {};
    for (const key of Object.keys(value).sort(compareCodeUnits)) {
      result[key] = canonicalize(value[key]);
    }
    return result;
  }
  return value;
}

export function canonicalJson(value) {
  return `${JSON.stringify(canonicalize(value))}\n`;
}

function resolveRef(rootSchema, reference) {
  if (!reference.startsWith('#/')) {
    throw new Error(`SCHEMA_EXTERNAL_REF:${reference}`);
  }
  return reference
    .slice(2)
    .split('/')
    .reduce((value, component) => value[component], rootSchema);
}

function matchesType(value, type) {
  if (type === 'null') return value === null;
  if (type === 'array') return Array.isArray(value);
  if (type === 'object') {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }
  return typeof value === type;
}

function validateNode(value, schema, rootSchema, path) {
  if (schema.$ref) {
    validateNode(value, resolveRef(rootSchema, schema.$ref), rootSchema, path);
    return;
  }
  if (schema.oneOf) {
    let matches = 0;
    for (const candidate of schema.oneOf) {
      try {
        validateNode(value, candidate, rootSchema, path);
        matches += 1;
      } catch {
        // A oneOf candidate that fails is expected and not diagnostic by itself.
      }
    }
    if (matches !== 1) throw new Error(`SCHEMA_ONE_OF:${path}`);
    return;
  }
  if (Object.hasOwn(schema, 'const') && value !== schema.const) {
    throw new Error(`SCHEMA_CONST:${path}`);
  }
  if (schema.enum && !schema.enum.includes(value)) {
    throw new Error(`SCHEMA_ENUM:${path}`);
  }
  if (schema.type && !matchesType(value, schema.type)) {
    throw new Error(`SCHEMA_TYPE:${path}:${schema.type}`);
  }
  if (schema.pattern && !new RegExp(schema.pattern).test(value)) {
    throw new Error(`SCHEMA_PATTERN:${path}`);
  }
  if (schema.type === 'array') {
    value.forEach((item, index) => {
      validateNode(item, schema.items, rootSchema, `${path}[${index}]`);
    });
  }
  if (schema.type === 'object') {
    for (const required of schema.required ?? []) {
      if (!Object.hasOwn(value, required)) {
        throw new Error(`SCHEMA_REQUIRED:${path}.${required}`);
      }
    }
    for (const [key, child] of Object.entries(value)) {
      if (schema.properties?.[key]) {
        validateNode(child, schema.properties[key], rootSchema, `${path}.${key}`);
      } else if (schema.additionalProperties === false) {
        throw new Error(`SCHEMA_EXTRA:${path}.${key}`);
      } else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
        validateNode(child, schema.additionalProperties, rootSchema, `${path}.${key}`);
      }
    }
  }
}

export function validateEnvelope(envelope, schema) {
  validateNode(envelope, schema, schema, '$');
}

function observed(caseId, value, observedToken, reasonCode = null) {
  return {
    caseId,
    status: 'OBSERVED',
    value,
    reasonCode,
    observedToken,
  };
}

function unsupported(caseId, reasonCode, observedToken) {
  return {
    caseId,
    status: 'UNSUPPORTED',
    value: null,
    reasonCode,
    observedToken,
  };
}

function decimal(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) throw new Error('HARNESS_DECIMAL_INPUT');
  return number;
}

function clockValue(clock) {
  const counter = Number.isNaN(clock.counter) ? 'NaN' : String(clock.counter);
  return {
    kind: 'clock',
    canonical: clock.toCanonical(),
    epochMicros: String(BigInt(clock.timestamp.getTime()) * 1000n),
    counter,
    nodeId: clock.nodeId,
  };
}

function vectorValue(clock) {
  return {
    a: String(clock.a),
    b: String(clock.b),
    total: String(clock.total),
  };
}

function eventForOrdering(input) {
  return new LedgerEvent({
    eventId: input.id,
    eventType: EventType.TRANSACTION,
    payload: new Uint8Array(),
    previousHash: null,
    eventHash: input.id,
    hlc: HybridLogicalClock.fromCanonical(
      '2026-02-24T12:00:00.123Z-0042-a1b2c3d4'
    ),
    vectorClock: new VectorClock(decimal(input.a), decimal(input.b)),
    senderPubkey: input.sender,
    signature: new Uint8Array(64),
    createdAt: new Date('2026-02-24T12:00:00.123Z'),
  });
}

function chainEvent({
  id,
  previousHash = null,
  eventHash = '00'.repeat(32),
  senderPublicKeyHex,
  signature = new Uint8Array(64),
}) {
  return new LedgerEvent({
    eventId: id,
    eventType: EventType.TRANSACTION,
    payload: new Uint8Array([1]),
    previousHash,
    eventHash,
    hlc: HybridLogicalClock.fromCanonical(
      '2026-02-24T12:00:00.123Z-0042-a1b2c3d4'
    ),
    vectorClock: new VectorClock(1, 0),
    senderPubkey: senderPublicKeyHex,
    signature,
    createdAt: new Date('2026-02-24T12:00:00.123Z'),
  });
}

function chainErrorCode(error) {
  const mapping = {
    [ChainErrorType.HASH_MISMATCH]: 'CHAIN_HASH_MISMATCH',
    [ChainErrorType.SIGNATURE_INVALID]: 'CHAIN_SIGNATURE_INVALID',
    [ChainErrorType.PREVIOUS_HASH_MISSING]: 'CHAIN_PREVIOUS_HASH_MISMATCH',
    [ChainErrorType.HLC_VIOLATION]: 'CHAIN_HLC_VIOLATION',
    [ChainErrorType.GENESIS_VIOLATION]: 'CHAIN_GENESIS_VIOLATION',
  };
  return error === null ? 'CHAIN_VALID' : mapping[error.errorType];
}

async function runCase(testCase) {
  const { id, operation, input } = testCase;
  const hasher = new Hasher();

  if (testCase.category === 'hlc') {
    try {
      if (operation === 'parse-render') {
        return observed(
          id,
          clockValue(HybridLogicalClock.fromCanonical(input.canonical)),
          'HybridLogicalClock.fromCanonical:return'
        );
      }
      if (operation === 'bytes') {
        const clock = HybridLogicalClock.fromCanonical(input.canonical);
        return observed(
          id,
          { kind: 'bytes', hex: bytesToHex(clock.toBytes()) },
          'HybridLogicalClock.toBytes:return'
        );
      }
      if (operation === 'compare') {
        const left = HybridLogicalClock.fromCanonical(input.left);
        const right = HybridLogicalClock.fromCanonical(input.right);
        return observed(
          id,
          { kind: 'comparison', relation: String(left.compareTo(right)) },
          'HybridLogicalClock.compareTo:return'
        );
      }
    } catch {
      return observed(
        id,
        { kind: 'error', code: 'HLC_PARSE_ERROR' },
        'HybridLogicalClock.fromCanonical:throw',
        'HLC_PARSE_ERROR'
      );
    }
  }

  if (testCase.category === 'vector-clock') {
    if (operation === 'three-party-topology') {
      return unsupported(
        id,
        'VECTOR_TOPOLOGY_TWO_PARTY_ONLY',
        'VectorClock.constructor:two-components'
      );
    }
    if (operation === 'merge-relation') {
      const left = new VectorClock(decimal(input.left.a), decimal(input.left.b));
      const right = new VectorClock(decimal(input.right.a), decimal(input.right.b));
      return observed(
        id,
        {
          kind: 'merge-relation',
          merged: vectorValue(left.merge(right)),
          relation: left.causalRelation(right),
        },
        'VectorClock.merge.causalRelation:return'
      );
    }
    const clock = new VectorClock(decimal(input.a), decimal(input.b));
    if (operation === 'project') {
      return observed(
        id,
        { ...vectorValue(clock), bytesHex: bytesToHex(clock.toBytes()) },
        'VectorClock.project:return'
      );
    }
    if (operation === 'bytes') {
      try {
        return observed(
          id,
          { kind: 'bytes', hex: bytesToHex(clock.toBytes()) },
          'VectorClock.toBytes:return'
        );
      } catch {
        return observed(
          id,
          { kind: 'error', code: 'VECTOR_BYTES_RANGE' },
          'VectorClock.toBytes:throw',
          'VECTOR_BYTES_RANGE'
        );
      }
    }
    if (operation === 'increment') {
      try {
        const result = clock.increment(input.role);
        return observed(
          id,
          { kind: 'vector', ...vectorValue(result) },
          'VectorClock.increment:return'
        );
      } catch {
        return observed(
          id,
          { kind: 'error', code: 'VECTOR_ROLE_INVALID' },
          'VectorClock.increment:throw',
          'VECTOR_ROLE_INVALID'
        );
      }
    }
  }

  if (testCase.category === 'hashing') {
    if (operation === 'sha256') {
      return observed(
        id,
        { kind: 'hash', hex: bytesToHex(hasher.hash(hexToBytes(input.dataHex))) },
        'Hasher.hash:return'
      );
    }
    if (operation === 'chain-hash') {
      const previous = input.previousHex === null ? null : hexToBytes(input.previousHex);
      return observed(
        id,
        {
          kind: 'hash',
          hex: bytesToHex(hasher.chainHash(previous, hexToBytes(input.payloadHex))),
        },
        'Hasher.chainHash:return'
      );
    }
    if (operation === 'composite-hash') {
      return observed(
        id,
        {
          kind: 'hash',
          hex: bytesToHex(
            hasher.compositeHash(input.segmentsHex.map(hexToBytes))
          ),
        },
        'Hasher.compositeHash:return'
      );
    }
    if (operation === 'segmentation-witness') {
      const left = bytesToHex(
        hasher.compositeHash(input.leftSegmentsHex.map(hexToBytes))
      );
      const right = bytesToHex(
        hasher.compositeHash(input.rightSegmentsHex.map(hexToBytes))
      );
      return observed(
        id,
        { kind: 'segmentation-witness', leftHex: left, rightHex: right, equal: left === right },
        'Hasher.compositeHash:segment-boundaries-erased'
      );
    }
  }

  if (testCase.category === 'event-hash') {
    const factory = new EventFactory(new Signer(), hasher);
    if (operation === 'fixed-preimage') {
      const result = factory.computeHashBytes({
        previousHash: input.previousHash,
        eventType: input.eventType,
        payload: hexToBytes(input.payloadHex),
        hlcBytes: hexToBytes(input.hlcBytesHex),
      });
      return observed(
        id,
        { kind: 'event-hash', hex: bytesToHex(result) },
        'EventFactory.computeHashBytes:return'
      );
    }
    if (operation === 'genesis-projection') {
      const event = await factory.createGenesisEvent({
        privateKey: new StyxPrivateKey(hexToBytes(input.privateSeedHex)),
        publicKey: new StyxPublicKey(hexToBytes(input.publicKeyHex)),
        nodeId: input.nodeId,
      });
      return observed(
        id,
        {
          kind: 'genesis-projection',
          eventType: event.eventType,
          payloadHex: bytesToHex(event.payload),
          previousHash: event.previousHash,
          vectorClock: vectorValue(event.vectorClock),
        },
        'EventFactory.createGenesisEvent:deterministic-fields'
      );
    }
    if (operation === 'deterministic-genesis-hash') {
      return unsupported(
        id,
        'GENESIS_CLOCK_NOT_INJECTABLE',
        'EventFactory.createGenesisEvent:wall-clock-bound'
      );
    }
  }

  if (testCase.category === 'ordering') {
    const ordered = new DeterministicMerge()
      .orderConcurrentEvents(input.events.map(eventForOrdering))
      .map((event) => event.eventId);
    return observed(
      id,
      { kind: 'ordered-event-ids', ids: ordered },
      'DeterministicMerge.orderConcurrentEvents:return'
    );
  }

  if (testCase.category === 'chain-validation') {
    const validator = new ChainValidator(hasher, new Verifier());
    if (operation === 'empty-chain') {
      const error = await validator.validateFullChain([]);
      return observed(
        id,
        { kind: 'chain-result', code: chainErrorCode(error) },
        'ChainValidator.validateFullChain:return'
      );
    }
    if (operation === 'genesis-previous-hash') {
      const event = chainEvent({
        id,
        previousHash: input.previousHash,
        senderPublicKeyHex: input.senderPublicKeyHex,
      });
      const error = await validator.validateFullChain([event]);
      return observed(
        id,
        { kind: 'chain-result', code: chainErrorCode(error) },
        'ChainValidator.validateFullChain:return',
        chainErrorCode(error)
      );
    }
    if (operation === 'hash-mismatch') {
      const event = chainEvent({ id, senderPublicKeyHex: input.senderPublicKeyHex });
      const error = await validator.validateFullChain([event]);
      return observed(
        id,
        { kind: 'chain-result', code: chainErrorCode(error) },
        'ChainValidator.validateFullChain:return',
        chainErrorCode(error)
      );
    }
    if (operation === 'signature-invalid') {
      const hlc = HybridLogicalClock.fromCanonical(
        '2026-02-24T12:00:00.123Z-0042-a1b2c3d4'
      );
      const factory = new EventFactory(new Signer(), hasher);
      const hash = bytesToHex(factory.computeHashBytes({
        previousHash: null,
        eventType: EventType.TRANSACTION,
        payload: new Uint8Array([1]),
        hlcBytes: hlc.toBytes(),
      }));
      const event = chainEvent({
        id,
        eventHash: hash,
        senderPublicKeyHex: input.senderPublicKeyHex,
      });
      const error = await validator.validateFullChain([event]);
      return observed(
        id,
        { kind: 'chain-result', code: chainErrorCode(error) },
        'ChainValidator.validateFullChain:return',
        chainErrorCode(error)
      );
    }
    if (operation === 'previous-hash-mismatch') {
      const previous = chainEvent({
        id: 'previous',
        eventHash: '11'.repeat(32),
        senderPublicKeyHex: input.senderPublicKeyHex,
      });
      const event = chainEvent({
        id,
        previousHash: '22'.repeat(32),
        senderPublicKeyHex: input.senderPublicKeyHex,
      });
      const error = await validator.validateEvent(
        event,
        previous,
        new StyxPublicKey(hexToBytes(input.senderPublicKeyHex))
      );
      return observed(
        id,
        { kind: 'chain-result', code: chainErrorCode(error) },
        'ChainValidator.validateEvent:return',
        chainErrorCode(error)
      );
    }
  }

  throw new Error(`HARNESS_UNKNOWN_CASE:${id}`);
}

export async function runCharacterization(corpusPath) {
  const raw = readFileSync(corpusPath);
  const corpus = JSON.parse(raw.toString('utf8'));
  if (corpus.schemaVersion !== SCHEMA_VERSION || corpus.baseSha !== BASE_SHA) {
    throw new Error('HARNESS_CORPUS_IDENTITY');
  }
  const observations = [];
  for (const testCase of corpus.cases) {
    observations.push(await runCase(testCase));
  }
  return {
    schemaVersion: SCHEMA_VERSION,
    runtime: 'javascript',
    baseSha: BASE_SHA,
    casesSha256: createHash('sha256').update(raw).digest('hex'),
    observations,
  };
}

async function main() {
  if (process.argv.length !== 3) {
    throw new Error('USAGE:c0-characterization-runner.mjs <cases.json>');
  }
  process.stdout.write(canonicalJson(await runCharacterization(process.argv[2])));
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    process.stderr.write(`C0_RUNNER_FAILED:${error.message}\n`);
    process.exitCode = 1;
  });
}
