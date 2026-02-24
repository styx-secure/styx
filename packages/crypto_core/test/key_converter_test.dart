import 'package:cryptography/cryptography.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:test/test.dart';

void main() {
  final manager = IdentityManager();
  final converter = KeyConverter();

  group('KeyConverter', () {
    test('ed25519PublicToX25519 produces 32-byte key', () async {
      final ed = await manager.generate();
      final xPub = converter.ed25519PublicToX25519(ed.publicKey);
      expect(xPub.length, 32);
    });

    test('ed25519PrivateToX25519 produces 32-byte key', () async {
      final ed = await manager.generate();
      final xPriv = converter.ed25519PrivateToX25519(ed.privateKey);
      expect(xPriv.length, 32);
    });

    test('conversion is deterministic', () async {
      final ed = await manager.generate();
      final xPub1 = converter.ed25519PublicToX25519(ed.publicKey);
      final xPub2 = converter.ed25519PublicToX25519(ed.publicKey);
      expect(xPub1, equals(xPub2));

      final xPriv1 = converter.ed25519PrivateToX25519(ed.privateKey);
      final xPriv2 = converter.ed25519PrivateToX25519(ed.privateKey);
      expect(xPriv1, equals(xPriv2));
    });

    test('different Ed25519 keys produce different X25519 keys', () async {
      final ed1 = await manager.generate();
      final ed2 = await manager.generate();
      final xPub1 = converter.ed25519PublicToX25519(ed1.publicKey);
      final xPub2 = converter.ed25519PublicToX25519(ed2.publicKey);
      expect(xPub1, isNot(equals(xPub2)));
    });

    test('DH round-trip: two peers derive same shared secret', () async {
      // Generate two Ed25519 key pairs
      final edAlice = await manager.generate();
      final edBob = await manager.generate();

      // Convert to X25519
      final xAlicePub = converter.ed25519PublicToX25519(edAlice.publicKey);
      final xAlicePriv = converter.ed25519PrivateToX25519(edAlice.privateKey);
      final xBobPub = converter.ed25519PublicToX25519(edBob.publicKey);
      final xBobPriv = converter.ed25519PrivateToX25519(edBob.privateKey);

      // Perform X25519 DH using the cryptography package
      final x25519 = X25519();

      final aliceKeyPair = SimpleKeyPairData(
        xAlicePriv,
        publicKey: SimplePublicKey(
          xAlicePub,
          type: KeyPairType.x25519,
        ),
        type: KeyPairType.x25519,
      );

      final bobKeyPair = SimpleKeyPairData(
        xBobPriv,
        publicKey: SimplePublicKey(
          xBobPub,
          type: KeyPairType.x25519,
        ),
        type: KeyPairType.x25519,
      );

      // Alice computes shared secret with Bob's public key
      final aliceShared = await x25519.sharedSecretKey(
        keyPair: aliceKeyPair,
        remotePublicKey: SimplePublicKey(
          xBobPub,
          type: KeyPairType.x25519,
        ),
      );

      // Bob computes shared secret with Alice's public key
      final bobShared = await x25519.sharedSecretKey(
        keyPair: bobKeyPair,
        remotePublicKey: SimplePublicKey(
          xAlicePub,
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
