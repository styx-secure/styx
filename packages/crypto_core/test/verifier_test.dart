import 'dart:typed_data';

import 'package:crypto_core/crypto_core.dart';
import 'package:test/test.dart';

void main() {
  final manager = IdentityManager();
  final signer = Signer();
  final verifier = Verifier();

  group('Verifier', () {
    test('sign+verify round-trip succeeds', () async {
      final kp = await manager.generate();
      final payload = Uint8List.fromList([1, 2, 3, 4]);
      final sig = await signer.sign(payload, kp);

      final valid = await verifier.verify(
        payload: payload,
        signatureBytes: sig,
        publicKeyBytes: kp.publicKeyBytes,
      );
      expect(valid, isTrue);
    });

    test('fails with altered payload', () async {
      final kp = await manager.generate();
      final payload = Uint8List.fromList([1, 2, 3, 4]);
      final sig = await signer.sign(payload, kp);

      final altered = Uint8List.fromList([1, 2, 3, 5]);
      final valid = await verifier.verify(
        payload: altered,
        signatureBytes: sig,
        publicKeyBytes: kp.publicKeyBytes,
      );
      expect(valid, isFalse);
    });

    test('fails with wrong public key', () async {
      final kp1 = await manager.generate();
      final kp2 = await manager.generate();
      final payload = Uint8List.fromList([1, 2, 3, 4]);
      final sig = await signer.sign(payload, kp1);

      final valid = await verifier.verify(
        payload: payload,
        signatureBytes: sig,
        publicKeyBytes: kp2.publicKeyBytes,
      );
      expect(valid, isFalse);
    });

    test('fails with altered signature', () async {
      final kp = await manager.generate();
      final payload = Uint8List.fromList([1, 2, 3, 4]);
      final sig = await signer.sign(payload, kp);

      sig[0] ^= 0xFF; // Flip bits in first byte
      final valid = await verifier.verify(
        payload: payload,
        signatureBytes: sig,
        publicKeyBytes: kp.publicKeyBytes,
      );
      expect(valid, isFalse);
    });

    test('empty payload sign+verify', () async {
      final kp = await manager.generate();
      final payload = Uint8List(0);
      final sig = await signer.sign(payload, kp);

      final valid = await verifier.verify(
        payload: payload,
        signatureBytes: sig,
        publicKeyBytes: kp.publicKeyBytes,
      );
      expect(valid, isTrue);
    });

    test('1-byte payload sign+verify', () async {
      final kp = await manager.generate();
      final payload = Uint8List.fromList([42]);
      final sig = await signer.sign(payload, kp);

      final valid = await verifier.verify(
        payload: payload,
        signatureBytes: sig,
        publicKeyBytes: kp.publicKeyBytes,
      );
      expect(valid, isTrue);
    });

    test('10MB payload sign without error', () async {
      final kp = await manager.generate();
      final payload = Uint8List(10 * 1024 * 1024); // 10MB of zeros
      final sig = await signer.sign(payload, kp);
      expect(sig.length, 64);
    });

    test('returns false for malformed signature bytes', () async {
      final kp = await manager.generate();
      final payload = Uint8List.fromList([1, 2, 3]);

      final valid = await verifier.verify(
        payload: payload,
        signatureBytes: Uint8List(10), // Wrong length
        publicKeyBytes: kp.publicKeyBytes,
      );
      expect(valid, isFalse);
    });
  });
}
