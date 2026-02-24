import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:test/test.dart';

void main() {
  test('end-to-end: generate → sign → verify → hash → X25519', () async {
    // 1. Generate identity
    final manager = IdentityManager();
    final kp = await manager.generate();
    expect(kp.privateKey.bytes.length, 32);
    expect(kp.publicKey.bytes.length, 32);

    // 2. Sign a payload
    final signer = Signer();
    final payload = Uint8List.fromList(utf8.encode('hello styx'));
    final sig = await signer.sign(payload, kp.privateKey);
    expect(sig.length, 64);

    // 3. Verify signature
    final verifier = Verifier();
    final valid = await verifier.verify(
      payload: payload,
      signatureBytes: sig,
      publicKey: kp.publicKey,
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
    final xPub = converter.ed25519PublicToX25519(kp.publicKey);
    final xPriv = converter.ed25519PrivateToX25519(kp.privateKey);
    expect(xPub.length, 32);
    expect(xPriv.length, 32);

    // 7. Verify DH works with converted keys
    final kp2 = await manager.generate();
    final xPub2 = converter.ed25519PublicToX25519(kp2.publicKey);
    final xPriv2 = converter.ed25519PrivateToX25519(kp2.privateKey);
    final x25519 = X25519();

    final shared1 = await x25519.sharedSecretKey(
      keyPair: SimpleKeyPairData(
        xPriv,
        publicKey: SimplePublicKey(
          xPub,
          type: KeyPairType.x25519,
        ),
        type: KeyPairType.x25519,
      ),
      remotePublicKey: SimplePublicKey(
        xPub2,
        type: KeyPairType.x25519,
      ),
    );

    final shared2 = await x25519.sharedSecretKey(
      keyPair: SimpleKeyPairData(
        xPriv2,
        publicKey: SimplePublicKey(
          xPub2,
          type: KeyPairType.x25519,
        ),
        type: KeyPairType.x25519,
      ),
      remotePublicKey: SimplePublicKey(
        xPub,
        type: KeyPairType.x25519,
      ),
    );

    expect(
      await shared1.extractBytes(),
      equals(await shared2.extractBytes()),
    );
  });
}
