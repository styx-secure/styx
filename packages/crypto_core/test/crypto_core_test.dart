import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto_core/crypto_core.dart';
import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

void main() {
  test('end-to-end: generate → sign → verify → hash → X25519', () async {
    // 1. Generate identity
    final manager = IdentityManager();
    final kp = await manager.generate();
    expect(kp.privateKeyBytes.length, 32);
    expect(kp.publicKeyBytes.length, 32);

    // 2. Sign a payload
    final signer = Signer();
    final payload = Uint8List.fromList(utf8.encode('hello styx'));
    final sig = await signer.sign(payload, kp);
    expect(sig.length, 64);

    // 3. Verify signature
    final verifier = Verifier();
    final valid = await verifier.verify(
      payload: payload,
      signatureBytes: sig,
      publicKeyBytes: kp.publicKeyBytes,
    );
    expect(valid, isTrue);

    // 4. Hash payload
    final hasher = Hasher();
    final h0 = hasher.hash(payload);
    expect(h0.length, 32);

    // 5. Chain hash
    final h1 = hasher.chainHash(previousHash: h0, payload: sig);
    expect(h1.length, 32);
    expect(h1, isNot(equals(h0)));

    // 6. Convert to X25519
    final converter = KeyConverter();
    final xKp = converter.convertToX25519(kp);
    expect(xKp.privateKeyBytes.length, 32);
    expect(xKp.publicKeyBytes.length, 32);

    // 7. Verify DH works with converted keys
    final kp2 = await manager.generate();
    final xKp2 = converter.convertToX25519(kp2);
    final x25519 = X25519();

    final shared1 = await x25519.sharedSecretKey(
      keyPair: SimpleKeyPairData(
        xKp.privateKeyBytes,
        publicKey: SimplePublicKey(
          xKp.publicKeyBytes,
          type: KeyPairType.x25519,
        ),
        type: KeyPairType.x25519,
      ),
      remotePublicKey: SimplePublicKey(
        xKp2.publicKeyBytes,
        type: KeyPairType.x25519,
      ),
    );

    final shared2 = await x25519.sharedSecretKey(
      keyPair: SimpleKeyPairData(
        xKp2.privateKeyBytes,
        publicKey: SimplePublicKey(
          xKp2.publicKeyBytes,
          type: KeyPairType.x25519,
        ),
        type: KeyPairType.x25519,
      ),
      remotePublicKey: SimplePublicKey(
        xKp.publicKeyBytes,
        type: KeyPairType.x25519,
      ),
    );

    expect(
      await shared1.extractBytes(),
      equals(await shared2.extractBytes()),
    );
  });
}
