import 'dart:typed_data';

import 'package:glados/glados.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';

void main() {
  final manager = IdentityManager();
  final signer = Signer();
  final verifier = Verifier();
  final hasher = Hasher();

  group('Property-based tests', () {
    Glados(any.list(any.int)).test(
      'sign then verify always succeeds (T1.31)',
      (payload) async {
        final kp = await manager.generate();
        final payloadBytes = Uint8List.fromList(
          payload.map((v) => v & 0xFF).toList(),
        );
        final sig = await signer.sign(payloadBytes, kp.privateKey);
        final valid = await verifier.verify(
          payload: payloadBytes,
          signatureBytes: sig,
          publicKey: kp.publicKey,
        );
        expect(valid, isTrue);
      },
    );

    Glados(any.list(any.int)).test(
      'signature is not transferable between keys (T1.33)',
      (payload) async {
        final kpA = await manager.generate();
        final kpB = await manager.generate();
        final payloadBytes = Uint8List.fromList(
          payload.map((v) => v & 0xFF).toList(),
        );
        final sig = await signer.sign(payloadBytes, kpA.privateKey);
        final valid = await verifier.verify(
          payload: payloadBytes,
          signatureBytes: sig,
          publicKey: kpB.publicKey,
        );
        expect(valid, isFalse);
      },
    );

    Glados(any.list(any.int)).test(
      'hash is deterministic (T1.34)',
      (data) {
        final bytes = Uint8List.fromList(
          data.map((v) => v & 0xFF).toList(),
        );
        final h1 = hasher.hash(bytes);
        final h2 = hasher.hash(bytes);
        expect(h1, equals(h2));
      },
    );
  });
}
