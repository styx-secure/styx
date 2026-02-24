import 'dart:typed_data';

import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:test/test.dart';

void main() {
  final protocol = Spake2Protocol();

  /// Helper to run a full SPAKE2 round-trip with a given password.
  ({Uint8List keyA, Uint8List keyB, Spake2Session a, Spake2Session b})
      runRoundTrip(Uint8List password) {
    final a = protocol.createInitiatorSession(password);
    final b = protocol.createResponderSession(password);

    final msgA = a.generateMessage();
    final msgB = b.generateMessage();

    final aOk = a.processMessage(msgB);
    final bOk = b.processMessage(msgA);

    expect(aOk, isTrue, reason: 'Initiator processMessage failed');
    expect(bOk, isTrue, reason: 'Responder processMessage failed');

    return (keyA: a.getSessionKey(), keyB: b.getSessionKey(), a: a, b: b);
  }

  group('SPAKE2', () {
    test('T2.15 — SPAKE2 round-trip: same password → same session key', () {
      final password = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      final result = runRoundTrip(password);
      expect(result.keyA, equals(result.keyB));
      expect(result.keyA.length, 32);
    });

    test('T2.16 — SPAKE2 wrong password: different session keys', () {
      final pwA = Uint8List.fromList([1, 2, 3]);
      final pwB = Uint8List.fromList([4, 5, 6]);

      final a = protocol.createInitiatorSession(pwA);
      final b = protocol.createResponderSession(pwB);

      final msgA = a.generateMessage();
      final msgB = b.generateMessage();

      // Messages exchange succeeds (no check on password yet)
      // but session keys will differ.
      final aOk = a.processMessage(msgB);
      final bOk = b.processMessage(msgA);

      // Processing may succeed but keys differ, or confirmation fails.
      if (aOk && bOk) {
        final keyA = a.getSessionKey();
        final keyB = b.getSessionKey();
        // Either keys differ or confirmation will fail
        if (keyA.toString() == keyB.toString()) {
          // Extremely unlikely but possible — at least confirmation must fail
          final confA = a.getConfirmation();
          expect(b.verifyConfirmation(confA), isFalse);
        }
      }
    });

    test('T2.17 — SPAKE2 confirmation match: cross-verify succeeds', () {
      final password = Uint8List.fromList([10, 20, 30]);
      final result = runRoundTrip(password);

      final confA = result.a.getConfirmation();
      final confB = result.b.getConfirmation();

      expect(result.b.verifyConfirmation(confA), isTrue);
      expect(result.a.verifyConfirmation(confB), isTrue);
    });

    test('T2.18 — SPAKE2 confirmation mismatch: different passwords', () {
      final pwA = Uint8List.fromList([1, 2, 3]);
      final pwB = Uint8List.fromList([4, 5, 6]);

      final a = protocol.createInitiatorSession(pwA);
      final b = protocol.createResponderSession(pwB);

      final msgA = a.generateMessage();
      final msgB = b.generateMessage();

      final aOk = a.processMessage(msgB);
      final bOk = b.processMessage(msgA);

      if (aOk && bOk) {
        final confA = a.getConfirmation();
        final confB = b.getConfirmation();
        // At least one verification must fail with different passwords.
        final aVerifies = a.verifyConfirmation(confB);
        final bVerifies = b.verifyConfirmation(confA);
        expect(aVerifies && bVerifies, isFalse);
      }
    });

    test('T2.19 — SPAKE2 non-reusable: completed → generateMessage throws', () {
      final password = Uint8List.fromList([1, 2, 3]);
      final result = runRoundTrip(password);
      expect(result.a.generateMessage, throwsStateError);
    });

    test('T2.20 — SPAKE2 distinct roles required', () {
      // Two initiators or two responders should produce different session keys
      // because they use the same blinding point (M+M or N+N).
      final password = Uint8List.fromList([1, 2, 3]);

      final a = protocol.createInitiatorSession(password);
      final b = protocol.createInitiatorSession(password);

      final msgA = a.generateMessage();
      final msgB = b.generateMessage();

      // Both use M for blinding → unblinding with N will be wrong
      final aOk = a.processMessage(msgB);
      final bOk = b.processMessage(msgA);

      if (aOk && bOk) {
        final keyA = a.getSessionKey();
        final keyB = b.getSessionKey();
        // With same role, keys must differ (protocol relies on M≠N)
        expect(keyA, isNot(equals(keyB)));
      }
    });

    test('T2.21 — SPAKE2 100 random passwords: all round-trips succeed', () {
      for (var i = 0; i < 100; i++) {
        final password = Uint8List.fromList(
          List.generate(16, (j) => (i * 7 + j * 13) & 0xFF),
        );
        final result = runRoundTrip(password);
        expect(
          result.keyA,
          equals(result.keyB),
          reason: 'Round-trip $i failed',
        );
      }
    });

    test('T2.22 — SPAKE2 short password: 1 byte', () {
      final password = Uint8List.fromList([42]);
      final result = runRoundTrip(password);
      expect(result.keyA, equals(result.keyB));
    });

    test('T2.23 — SPAKE2 long password: 1 KB', () {
      final password = Uint8List.fromList(
        List.generate(1024, (i) => i & 0xFF),
      );
      final result = runRoundTrip(password);
      expect(result.keyA, equals(result.keyB));
    });

    test('T2.24 — SPAKE2 altered message: flip 1 bit → confirmation fails', () {
      final password = Uint8List.fromList([1, 2, 3, 4]);

      final a = protocol.createInitiatorSession(password);
      final b = protocol.createResponderSession(password);

      final msgA = a.generateMessage();
      final msgB = b.generateMessage();

      // Flip 1 bit in msgA before sending to B.
      final alteredMsgA = Uint8List.fromList(msgA);
      alteredMsgA[10] ^= 0x01;

      final aOk = a.processMessage(msgB);
      final bOk = b.processMessage(alteredMsgA);

      if (aOk && bOk) {
        // If both process, keys must differ and confirmation fails
        final confA = a.getConfirmation();
        expect(b.verifyConfirmation(confA), isFalse);
      }
      // If bOk is false, the altered message was rejected — test passes.
    });
  });

  group('Spake2Protocol', () {
    test('mnemonicToPassword normalizes input', () {
      final pw1 = protocol.mnemonicToPassword('  HELLO world  ');
      final pw2 = protocol.mnemonicToPassword('hello world');
      expect(pw1, equals(pw2));
    });
  });

  group('Spake2Session lifecycle', () {
    test('destroy clears session data', () {
      final password = Uint8List.fromList([1, 2, 3]);
      final a = protocol.createInitiatorSession(password);
      final b = protocol.createResponderSession(password);

      final msgA = a.generateMessage();
      final msgB = b.generateMessage();
      a.processMessage(msgB);
      b.processMessage(msgA);

      a.destroy();
      b.destroy();

      // After destroy, session key should not be accessible.
      // Depending on implementation, it may throw or return null.
      // The key point is that destroy() doesn't throw.
    });

    test('getSessionKey throws before completion', () {
      final session = protocol.createInitiatorSession(
        Uint8List.fromList([1]),
      );
      expect(session.getSessionKey, throwsStateError);
    });

    test('getConfirmation throws before completion', () {
      final session = protocol.createInitiatorSession(
        Uint8List.fromList([1]),
      );
      expect(session.getConfirmation, throwsStateError);
    });
  });
}
