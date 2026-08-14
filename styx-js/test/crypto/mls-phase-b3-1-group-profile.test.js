import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { schnorr } from '@noble/curves/secp256k1';

import {
  B31CanonicalError,
  B31_GROUP_CONTEXT_COMPONENT_IDS,
  B31_REQUIRED_COMPONENT_IDS,
  B31_SUPPORTED_COMPONENT_IDS,
  assertExactComponentIds,
  bytesEqual,
  decodeCanonicalQuicVarint,
  decodeGroupProfileBytes,
  encodeCanonicalQuicVarint,
  encodeGroupProfileBytes,
} from '../../spikes/marmot-phase-b3-1/b3-1-canonical.mjs';
import { createAccountIdentityProofV2 }
  from '../../spikes/marmot-phase-b1/identity-proof-v2.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const STYX_JS = join(HERE, '../..');
const FIXTURE = join(STYX_JS, 'test/fixtures/mls-state-b2-7');
const GENERATOR = join(
  STYX_JS,
  'spikes/marmot-phase-b3-1/generate-b2-7-legacy-fixture.mjs',
);
const PATCH = join(STYX_JS, 'vendor/openmls-wasm/patch/lib.rs');
const EXPECTED_WRITER = 'ed5e740d9c93aa46aa1afb7b6065e4b5b92be972a8a080ddd0a35091260691bb';
const EXPECTED_SOURCE_HEAD = 'a69df78c720bc679840172f68a68327ef603636c';
let wasmPromise;

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function free(value) {
  try { value?.free?.(); } catch { /* test cleanup */ }
}

async function loadWasm() {
  if (!wasmPromise) {
    wasmPromise = (async () => {
      const moduleUrl = pathToFileURL(join(STYX_JS, 'vendor/openmls-wasm/openmls_wasm.js'));
      moduleUrl.searchParams.set('b3-1-group-profile-test', '1');
      const wasm = await import(moduleUrl.href);
      await wasm.default({
        module_or_path: readFileSync(
          join(STYX_JS, 'vendor/openmls-wasm/openmls_wasm_bg.wasm'),
        ),
      });
      return wasm;
    })();
  }
  return wasmPromise;
}

describe('Phase B3.1 Stage 1 source and outgoing-artifact evidence', () => {
  test('the B2.7 fixture is exact, synthetic and provenance-bound', () => {
    const contextBytes = readFileSync(join(FIXTURE, 'context.json'));
    const envelopeBytes = readFileSync(join(FIXTURE, 'envelope.json'));
    const context = JSON.parse(contextBytes);
    const envelope = JSON.parse(envelopeBytes);
    const payload = Buffer.from(envelope.payload, 'base64');

    expect(contextBytes.length).toBe(1894);
    expect(sha256(contextBytes)).toBe(
      'bce0e4f5e1bafbbf0239145161557a748db4c2792a8aa5bd33c6ea7bb2fc047d',
    );
    expect(envelopeBytes.length).toBe(19497);
    expect(sha256(envelopeBytes)).toBe(
      'fe33df74090d6d792b2715c468d5e6c19b87ad6bb0aeab335ee2180c331d20ad',
    );
    expect(payload.length).toBe(14233);
    expect(sha256(payload)).toBe(
      '809e339a3679798baf382c3be09db12f3980e79b704d36d1b281a91a5c105685',
    );
    expect(envelope.payloadSha256).toBe(sha256(payload));
    expect(context.sourceHead).toBe(EXPECTED_SOURCE_HEAD);
    expect(envelope.sourceHead).toBe(EXPECTED_SOURCE_HEAD);
    expect(context.wasmArtifactSha256).toBe(EXPECTED_WRITER);
    expect(envelope.wasmArtifactSha256).toBe(EXPECTED_WRITER);
    expect(context.selfCheck).toBe('restore-reference-decrypt-and-reply-pass');
    expect(Buffer.from(context.groupId, 'base64').toString('utf8'))
      .toBe('styx-b2-7-writer-fixture-v1');
  });

  test('the one-shot generator binds the exact outgoing tuple and refuses overwrite', () => {
    const generator = readFileSync(GENERATOR, 'utf8');
    expect(Buffer.byteLength(generator)).toBe(7378);
    expect(sha256(generator)).toBe(
      '059268ac2a85616a67feee5cede38fd7368e0317bacedb8595ce1bd7530ef7b6',
    );
    expect(generator).toContain(`const EXPECTED_WRITER_SHA256 =\n  '${EXPECTED_WRITER}'`);
    expect(generator).toContain(`const SOURCE_HEAD = '${EXPECTED_SOURCE_HEAD}'`);
    expect(generator).toContain("flag: 'wx'");
    expect(generator).not.toContain('existsSync');
  });

  test('the isolated Rust source freezes B2 and separates B3.1 roles and limits', () => {
    const source = readFileSync(PATCH, 'utf8');
    expect(source).toContain('const PHASE_B2_COMPONENTS: [ComponentId; 3]');
    expect(source).toContain('const PHASE_B31_SUPPORTED_COMPONENTS: [ComponentId; 4]');
    expect(source).toContain('const PHASE_B31_REQUIRED_COMPONENTS: [ComponentId; 4]');
    expect(source).toContain('const GROUP_PROFILE_V1_COMPONENT_ID: ComponentId = 0x8001;');
    expect(source).toContain('const PHASE_B31_GROUP_PROFILE_NAME_MAX_BYTES: usize = 256;');
    expect(source).toContain('const PHASE_B31_GROUP_PROFILE_DESCRIPTION_MAX_BYTES: usize = 4096;');
    expect(source).toContain('fn phase_b31_read_canonical_quic_varint(');
    expect(source).toContain('fn phase_b31_decode_group_profile(');
    expect(source).toContain('fn phase_b31_validate_group_context_extensions(');
    expect(source).toContain('pub struct PhaseB31KeyPackage(OpenMlsKeyPackage);');
  });
});

describe('Phase B3.1 canonical JavaScript codec', () => {
  const encoder = new TextEncoder();

  test.each([
    [0, 1], [63, 1], [64, 2], [16383, 2], [16384, 4], [(2 ** 30) - 1, 4],
    [2 ** 30, 8],
  ])('round-trips canonical QUIC varint %i at width %i', (value, width) => {
    const encoded = encodeCanonicalQuicVarint(value);
    expect(encoded.length).toBe(width);
    expect(decodeCanonicalQuicVarint(encoded)).toEqual({ nextOffset: width, value, width });
  });

  test.each([
    Uint8Array.of(0x40, 0x00),
    Uint8Array.of(0x80, 0x00, 0x00, 0x00),
    Uint8Array.of(0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
  ])('rejects non-minimal QUIC varints', (bytes) => {
    expect(() => decodeCanonicalQuicVarint(bytes))
      .toThrow(expect.objectContaining({ code: 'B31_NON_CANONICAL' }));
  });

  test('preserves byte equality without Unicode normalization', () => {
    const composed = encodeGroupProfileBytes(encoder.encode('é'), encoder.encode('profile'));
    const decomposed = encodeGroupProfileBytes(encoder.encode('e\u0301'), encoder.encode('profile'));
    expect(bytesEqual(composed, decomposed)).toBe(false);
    expect(bytesEqual(decodeGroupProfileBytes(composed).name, encoder.encode('é'))).toBe(true);
    expect(bytesEqual(decodeGroupProfileBytes(decomposed).name, encoder.encode('e\u0301'))).toBe(true);
  });

  test('distinguishes absence, zero-length payload and canonical present-empty state', () => {
    const presentEmpty = encodeGroupProfileBytes(new Uint8Array(), new Uint8Array());
    expect([...presentEmpty]).toEqual([0, 0]);
    expect(decodeGroupProfileBytes(presentEmpty)).toEqual({
      description: new Uint8Array(),
      name: new Uint8Array(),
    });
    expect(() => decodeGroupProfileBytes(new Uint8Array())).toThrow(B31CanonicalError);
    expect(() => decodeGroupProfileBytes(Uint8Array.of(0))).toThrow(B31CanonicalError);
  });

  test('rejects limits, truncation, trailing bytes and every required invalid UTF-8 class', () => {
    expect(() => encodeGroupProfileBytes(new Uint8Array(257).fill(0x61), new Uint8Array()))
      .toThrow(expect.objectContaining({ code: 'B31_RESOURCE_LIMIT' }));
    expect(() => encodeGroupProfileBytes(new Uint8Array(), new Uint8Array(4097).fill(0x62)))
      .toThrow(expect.objectContaining({ code: 'B31_RESOURCE_LIMIT' }));
    expect(() => decodeGroupProfileBytes(Uint8Array.of(1, 0x61)))
      .toThrow(expect.objectContaining({ code: 'B31_MALFORMED' }));
    expect(() => decodeGroupProfileBytes(Uint8Array.of(0, 0, 0)))
      .toThrow(expect.objectContaining({ code: 'B31_MALFORMED' }));
    for (const invalid of [
      [0xc0, 0x80],
      [0xed, 0xa0, 0x80],
      [0xf4, 0x90, 0x80, 0x80],
      [0xe2, 0x82],
      [0x80],
    ]) {
      expect(() => decodeGroupProfileBytes(Uint8Array.of(invalid.length, ...invalid, 0)))
        .toThrow(expect.objectContaining({ code: 'B31_MALFORMED' }));
    }
  });

  test('requires exact, ordered and unique B3.1 component sets', () => {
    expect(assertExactComponentIds(
      [...B31_SUPPORTED_COMPONENT_IDS], B31_SUPPORTED_COMPONENT_IDS, 'supported components',
    )).toEqual(B31_SUPPORTED_COMPONENT_IDS);
    expect(assertExactComponentIds(
      [...B31_REQUIRED_COMPONENT_IDS], B31_REQUIRED_COMPONENT_IDS, 'required components',
    )).toEqual(B31_REQUIRED_COMPONENT_IDS);
    expect(assertExactComponentIds(
      [...B31_GROUP_CONTEXT_COMPONENT_IDS],
      B31_GROUP_CONTEXT_COMPONENT_IDS,
      'GroupContext components',
    )).toEqual(B31_GROUP_CONTEXT_COMPONENT_IDS);
    expect(() => assertExactComponentIds(
      [0x8001, 0x8009, 0x8003, 0x800c],
      B31_SUPPORTED_COMPONENT_IDS,
      'supported components',
    )).toThrow(expect.objectContaining({ code: 'B31_PROFILE_MISMATCH' }));
  });
});

describe('Phase B3.1 installed WASM surface', () => {
  test('emitted bytes advertise the exact isolated profile and reject cross-profile parsing', async () => {
    const wasm = await loadWasm();
    const provider = new wasm.Provider();
    const accountPrivateKey = new Uint8Array(32);
    accountPrivateKey[31] = 0x31;
    const accountPublicKey = Uint8Array.from(schnorr.getPublicKey(accountPrivateKey));
    const identity = new wasm.PhaseB2Identity(provider, accountPublicKey);
    const proof = createAccountIdentityProofV2(
      accountPrivateKey,
      identity.leaf_signature_key(),
      1_786_435_231,
    );
    let b31;
    let parsedB31;
    let b2;
    let parsedB2;
    try {
      b31 = identity.b3_1_key_package(provider, proof);
      const b31Bytes = Uint8Array.from(b31.to_framed_bytes());
      parsedB31 = wasm.PhaseB31KeyPackage.from_framed_bytes(b31Bytes);
      expect([...parsedB31.supported_component_ids()]).toEqual(
        [...B31_SUPPORTED_COMPONENT_IDS],
      );
      expect([...parsedB31.component_ids()]).toEqual([1, 0x8009]);
      expect(parsedB31.ciphersuite_id()).toBe(1);
      expect(parsedB31.is_last_resort()).toBe(false);
      expect(() => wasm.PhaseB2KeyPackage.from_framed_bytes(b31Bytes)).toThrow();

      b2 = identity.key_package(provider, proof);
      const b2Bytes = Uint8Array.from(b2.to_framed_bytes());
      parsedB2 = wasm.PhaseB2KeyPackage.from_framed_bytes(b2Bytes);
      expect([...parsedB2.supported_component_ids()]).toEqual([0x8003, 0x8009, 0x800c]);
      expect(() => wasm.PhaseB31KeyPackage.from_framed_bytes(b2Bytes)).toThrow();
    } finally {
      free(parsedB2);
      free(b2);
      free(parsedB31);
      free(b31);
      free(identity);
      free(provider);
    }
  });
});
