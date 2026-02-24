import 'dart:typed_data';

import 'package:glados/glados.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';

void main() {
  final dh = DiffieHellman();
  final kd = KeyDerivation();
  final protocol = Spake2Protocol();

  Glados<int>(any.intInRange(0, 255)).test(
    'T2.29 — DH commutativity property',
    (seed) async {
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

      expect(ab, equals(ba));
    },
  );

  Glados<List<int>>(any.list(any.intInRange(0, 255))).test(
    'T2.30 — HKDF determinism property',
    (infoList) async {
      final secret = Uint8List.fromList(List.generate(32, (i) => i));
      final info = Uint8List.fromList(
        infoList.map((v) => v & 0xFF).toList(),
      );

      final r1 = await kd.deriveKey(sharedSecret: secret, info: info);
      final r2 = await kd.deriveKey(sharedSecret: secret, info: info);

      expect(r1, equals(r2));
    },
  );

  Glados<List<int>>(any.list(any.intInRange(0, 255))).test(
    'T2.31 — SPAKE2 correctness property',
    (pwList) {
      // Ensure at least 1 byte password
      final pwBytes = pwList.isEmpty ? [42] : pwList;
      final password = Uint8List.fromList(
        pwBytes.map((v) => v & 0xFF).toList(),
      );

      final a = protocol.createInitiatorSession(password);
      final b = protocol.createResponderSession(password);

      final msgA = a.generateMessage();
      final msgB = b.generateMessage();

      final aOk = a.processMessage(msgB);
      final bOk = b.processMessage(msgA);

      expect(aOk, isTrue);
      expect(bOk, isTrue);
      expect(a.getSessionKey(), equals(b.getSessionKey()));
    },
  );
}
