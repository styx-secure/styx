import 'dart:typed_data';

import 'package:crypto_core/crypto_core.dart';
import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

void main() {
  final manager = IdentityManager();
  final converter = KeyConverter();

  group('KeyConverter', () {
    test('convertToX25519 produces 32-byte keys', () async {
      final ed = await manager.generate();
      final x = converter.convertToX25519(ed);
      expect(x.privateKeyBytes.length, 32);
      expect(x.publicKeyBytes.length, 32);
    });

    test('convertPublicKey produces 32-byte key', () async {
      final ed = await manager.generate();
      final xPub = converter.convertPublicKey(ed.publicKeyBytes);
      expect(xPub.length, 32);
    });

    test('conversion is deterministic', () async {
      final ed = await manager.generate();
      final x1 = converter.convertToX25519(ed);
      final x2 = converter.convertToX25519(ed);
      expect(x1, equals(x2));
    });

    test('different Ed25519 keys produce different X25519 keys', () async {
      final ed1 = await manager.generate();
      final ed2 = await manager.generate();
      final x1 = converter.convertToX25519(ed1);
      final x2 = converter.convertToX25519(ed2);
      expect(x1.privateKeyBytes, isNot(equals(x2.privateKeyBytes)));
      expect(x1.publicKeyBytes, isNot(equals(x2.publicKeyBytes)));
    });

    test('convertPublicKey rejects wrong length', () {
      expect(
        () => converter.convertPublicKey(Uint8List(16)),
        throwsArgumentError,
      );
    });

    test('DH round-trip: two peers derive same shared secret', () async {
      // Generate two Ed25519 key pairs
      final edAlice = await manager.generate();
      final edBob = await manager.generate();

      // Convert to X25519
      final xAlice = converter.convertToX25519(edAlice);
      final xBob = converter.convertToX25519(edBob);

      // Perform X25519 DH using the cryptography package
      final x25519 = X25519();

      final aliceKeyPair = SimpleKeyPairData(
        xAlice.privateKeyBytes,
        publicKey: SimplePublicKey(
          xAlice.publicKeyBytes,
          type: KeyPairType.x25519,
        ),
        type: KeyPairType.x25519,
      );

      final bobKeyPair = SimpleKeyPairData(
        xBob.privateKeyBytes,
        publicKey: SimplePublicKey(
          xBob.publicKeyBytes,
          type: KeyPairType.x25519,
        ),
        type: KeyPairType.x25519,
      );

      // Alice computes shared secret with Bob's public key
      final aliceShared = await x25519.sharedSecretKey(
        keyPair: aliceKeyPair,
        remotePublicKey: SimplePublicKey(
          xBob.publicKeyBytes,
          type: KeyPairType.x25519,
        ),
      );

      // Bob computes shared secret with Alice's public key
      final bobShared = await x25519.sharedSecretKey(
        keyPair: bobKeyPair,
        remotePublicKey: SimplePublicKey(
          xAlice.publicKeyBytes,
          type: KeyPairType.x25519,
        ),
      );

      final aliceBytes = await aliceShared.extractBytes();
      final bobBytes = await bobShared.extractBytes();

      expect(aliceBytes, equals(bobBytes));
      expect(aliceBytes.length, 32);
    });
  });
}
