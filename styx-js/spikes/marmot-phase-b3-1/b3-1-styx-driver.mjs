// SPDX-License-Identifier: AGPL-3.0-or-later

import { randomBytes } from 'node:crypto';
import { chmodSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { schnorr } from '@noble/curves/secp256k1';

import { createAccountIdentityProofV2 } from '../marmot-phase-b1/identity-proof-v2.js';
import {
  B31_FOUNDING_DESCRIPTION,
  B31_FOUNDING_NAME,
  B31_SUPPORTED_COMPONENT_IDS,
  bytesEqual,
  decodeGroupProfileBytes,
  encodeGroupProfileBytes,
  hexBytes,
  sha256,
} from './b3-1-canonical.mjs';

const PROOF_CREATED_AT = 1_786_572_031;
const UTF8 = new TextEncoder();

function ownerOnlyWrite(path, contents) {
  writeFileSync(path, contents, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  chmodSync(path, 0o600);
}

function free(value) {
  try { value?.free?.(); } catch { /* best-effort private-run cleanup */ }
}

export class StyxB31Peer {
  #wasm;
  #wasmBytes;
  #provider;
  #identity;
  #accountPrivateKey;
  #accountPublicKey;
  #leafSignatureKey;
  #privateDirectory;
  #keyPackageBytes;

  static async create(privateDirectory) {
    const instance = new StyxB31Peer(privateDirectory);
    await instance.#initialize();
    return instance;
  }

  constructor(privateDirectory) {
    this.#privateDirectory = resolve(privateDirectory);
  }

  async #initialize() {
    const wasmPath = new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url);
    const moduleUrl = new URL('../../vendor/openmls-wasm/openmls_wasm.js', import.meta.url);
    moduleUrl.searchParams.set('b3-1', `${process.pid}-${Date.now()}`);
    this.#wasmBytes = readFileSync(wasmPath);
    this.#wasm = await import(moduleUrl.href);
    await this.#wasm.default({ module_or_path: this.#wasmBytes });

    this.#accountPrivateKey = Uint8Array.from(randomBytes(32));
    this.#accountPublicKey = Uint8Array.from(schnorr.getPublicKey(this.#accountPrivateKey));
    this.#provider = new this.#wasm.Provider();
    this.#identity = new this.#wasm.PhaseB2Identity(this.#provider, this.#accountPublicKey);
    this.#leafSignatureKey = Uint8Array.from(this.#identity.leaf_signature_key());
    const proof = createAccountIdentityProofV2(
      this.#accountPrivateKey,
      this.#leafSignatureKey,
      PROOF_CREATED_AT,
    );
    const keyPackage = this.#identity.b3_1_key_package(this.#provider, proof);
    try {
      this.#keyPackageBytes = Uint8Array.from(keyPackage.to_framed_bytes());
    } finally {
      free(keyPackage);
    }
    const parsed = this.#wasm.PhaseB31KeyPackage.from_framed_bytes(this.#keyPackageBytes);
    try {
      if (parsed.is_last_resort()) {
        throw new Error('Styx B3.1 generated a forbidden last-resort KeyPackage');
      }
      if (parsed.ciphersuite_id() !== 1) {
        throw new Error('Styx B3.1 generated the wrong ciphersuite');
      }
      const supported = [...parsed.supported_component_ids()];
      if (supported.length !== B31_SUPPORTED_COMPONENT_IDS.length
        || supported.some((value, index) => value !== B31_SUPPORTED_COMPONENT_IDS[index])) {
        throw new Error('Styx B3.1 emitted an unexpected supported-component set');
      }
    } finally {
      free(parsed);
    }

    const providerState = Uint8Array.from(this.#provider.serialize_state());
    ownerOnlyWrite(
      resolve(this.#privateDirectory, 'styx-account-secret.hex'),
      Buffer.from(this.#accountPrivateKey).toString('hex'),
    );
    ownerOnlyWrite(
      resolve(this.#privateDirectory, 'styx-provider-state.hex'),
      Buffer.from(providerState).toString('hex'),
    );
    ownerOnlyWrite(
      resolve(this.#privateDirectory, 'styx-identity.json'),
      JSON.stringify({
        accountPublicKeyHex: Buffer.from(this.#accountPublicKey).toString('hex'),
        leafSignatureKeyHex: Buffer.from(this.#leafSignatureKey).toString('hex'),
      }),
    );
    this.#restart();
  }

  #restart() {
    const stateHex = readFileSync(
      resolve(this.#privateDirectory, 'styx-provider-state.hex'),
      'utf8',
    ).trim();
    free(this.#identity);
    free(this.#provider);
    this.#provider = new this.#wasm.Provider();
    this.#provider.restore_state(hexBytes(stateHex, 'Styx B3.1 provider state'));
    this.#identity = this.#wasm.PhaseB2Identity.load(
      this.#provider,
      this.#accountPublicKey,
      this.#leafSignatureKey,
    );
    if (!this.#identity) throw new Error('Styx B3.1 identity did not survive durable restart');
  }

  publicKeyPackage() {
    const parsed = this.#wasm.PhaseB31KeyPackage.from_framed_bytes(this.#keyPackageBytes);
    try {
      return {
        accountIdentityHex: Buffer.from(parsed.credential_identity()).toString('hex'),
        ciphersuite: parsed.ciphersuite_id(),
        componentIds: [...parsed.component_ids()],
        identityProofHex: Buffer.from(parsed.identity_proof()).toString('hex'),
        internalGroupProfileCodecValidated: true,
        isLastResort: parsed.is_last_resort(),
        keyPackageHex: Buffer.from(this.#keyPackageBytes).toString('hex'),
        keyPackageSha256: sha256(this.#keyPackageBytes),
        leafSignatureKeyHex: Buffer.from(parsed.leaf_signature_key()).toString('hex'),
        providerStateCommitmentSha256: sha256(
          hexBytes(
            readFileSync(
              resolve(this.#privateDirectory, 'styx-provider-state.hex'),
              'utf8',
            ).trim(),
            'Styx B3.1 provider state',
          ),
        ),
        supportedComponentIds: [...parsed.supported_component_ids()],
        wasmSha256: sha256(this.#wasmBytes),
      };
    } finally {
      free(parsed);
    }
  }

  expectedGroupProfile() {
    const name = UTF8.encode(B31_FOUNDING_NAME);
    const description = UTF8.encode(B31_FOUNDING_DESCRIPTION);
    const encoded = encodeGroupProfileBytes(name, description);
    const decoded = decodeGroupProfileBytes(encoded);
    if (!bytesEqual(decoded.name, name) || !bytesEqual(decoded.description, description)) {
      throw new Error('Styx B3.1 canonical group-profile round trip failed');
    }
    return {
      description,
      encoded,
      name,
    };
  }

  proveJoinRequiresExternalRatchetTree(welcomeHex) {
    const welcome = hexBytes(welcomeHex, 'MDK Welcome');
    let captured;
    try {
      this.#wasm.PhaseB2Group.join(this.#provider, welcome, undefined);
    } catch (error) {
      captured = {
        errorMessage: String(error?.message ?? error),
        errorName: error?.constructor?.name ?? 'Error',
      };
    }
    if (!captured) throw new Error('Styx unexpectedly joined without an external RatchetTree');
    return {
      ...captured,
      errorCode: 'STYX_PUBLIC_JOIN_REQUIRES_EXTERNAL_RATCHET_TREE',
      welcomeSha256: sha256(welcome),
    };
  }
}
