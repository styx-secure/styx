import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:test/test.dart';

void main() {
  final dh = DiffieHellman();

  group('DiffieHellman', () {
    test('T2.1 — DH round-trip: two peers derive same shared secret', () async {
      final alice = await dh.generateEphemeralKeyPair();
      final bob = await dh.generateEphemeralKeyPair();

      final aliceSecret = await dh.computeSharedSecret(
        localPrivateKey: alice.privateKey,
        remotePublicKey: bob.publicKey,
      );
      final bobSecret = await dh.computeSharedSecret(
        localPrivateKey: bob.privateKey,
        remotePublicKey: alice.publicKey,
      );

      expect(aliceSecret, equals(bobSecret));
      expect(aliceSecret.length, 32);
    });

    test('T2.2 — DH commutativity: 100 random keypairs', () async {
      for (var i = 0; i < 100; i++) {
        final a = await dh.generateEphemeralKeyPair();
        final b = await dh.generateEphemeralKeyPair();

        final ab = await dh.computeSharedSecret(
          localPrivateKey: a.privateKey,
          remotePublicKey: b.publicKey,
        );
        final ba = await dh.computeSharedSecret(
          localPrivateKey: b.privateKey,
          remotePublicKey: a.publicKey,
        );

        expect(ab, equals(ba), reason: 'Pair $i failed commutativity');
      }
    });

    test('T2.3 — DH uniqueness: 100 different pairs', () async {
      final secrets = <String>{};
      for (var i = 0; i < 100; i++) {
        final a = await dh.generateEphemeralKeyPair();
        final b = await dh.generateEphemeralKeyPair();

        final secret = await dh.computeSharedSecret(
          localPrivateKey: a.privateKey,
          remotePublicKey: b.publicKey,
        );
        final hex = secret
            .map((b) => b.toRadixString(16).padLeft(2, '0'))
            .join();
        secrets.add(hex);
      }
      expect(secrets.length, 100);
    });

    test('T2.4 — DH with itself: same keypair', () async {
      final kp = await dh.generateEphemeralKeyPair();
      final secret = await dh.computeSharedSecret(
        localPrivateKey: kp.privateKey,
        remotePublicKey: kp.publicKey,
      );
      expect(secret.length, 32);
      // Should not be all zeros.
      expect(secret.any((b) => b != 0), isTrue);
    });

    test('T2.5 — Ephemeral keypair uniqueness: generate 100', () async {
      final pubKeys = <String>{};
      for (var i = 0; i < 100; i++) {
        final kp = await dh.generateEphemeralKeyPair();
        final hex = kp.publicKey
            .map((b) => b.toRadixString(16).padLeft(2, '0'))
            .join();
        pubKeys.add(hex);
      }
      expect(pubKeys.length, 100);
    });

    test('T2.6 — Ephemeral keypair sizes', () async {
      final kp = await dh.generateEphemeralKeyPair();
      expect(kp.publicKey.length, 32);
      expect(kp.privateKey.length, 32);
    });
  });

  group('X25519KeyPair', () {
    test('destroy zeroes key material', () async {
      final kp = await dh.generateEphemeralKeyPair();
      expect(kp.isDestroyed, isFalse);
      kp.destroy();
      expect(kp.isDestroyed, isTrue);
      expect(() => kp.publicKey, throwsStateError);
      expect(() => kp.privateKey, throwsStateError);
    });

    test('defensive copies prevent external mutation', () async {
      final kp = await dh.generateEphemeralKeyPair();
      final pub1 = kp.publicKey;
      pub1[0] ^= 0xFF;
      final pub2 = kp.publicKey;
      expect(pub1[0], isNot(equals(pub2[0])));
    });
  });
}
