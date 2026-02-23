import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto_core/crypto_core.dart';
import 'package:glados/glados.dart';

void main() {
  final hasher = Hasher();

  String toHex(Uint8List bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  group('Hasher', () {
    test('SHA-256 of empty string matches RFC 6234', () {
      final result = hasher.hash(Uint8List(0));
      expect(
        toHex(result),
        'e3b0c44298fc1c149afbf4c8996fb924'
        '27ae41e4649b934ca495991b7852b855',
      );
    });

    test('SHA-256 of "abc" matches RFC 6234', () {
      final result = hasher.hash(
        Uint8List.fromList(utf8.encode('abc')),
      );
      expect(
        toHex(result),
        'ba7816bf8f01cfea414140de5dae2223'
        'b00361a396177a9cb410ff61f20015ad',
      );
    });

    test('hash is deterministic', () {
      final data = Uint8List.fromList([1, 2, 3]);
      expect(hasher.hash(data), equals(hasher.hash(data)));
    });

    test('hash output is 32 bytes', () {
      final result = hasher.hash(Uint8List.fromList([0]));
      expect(result.length, 32);
    });

    test('chainHash computes SHA-256(prev || payload)', () {
      final prev = hasher.hash(
        Uint8List.fromList(utf8.encode('genesis')),
      );
      final payload = Uint8List.fromList(utf8.encode('event1'));

      final chained = hasher.chainHash(
        previousHash: prev,
        payload: payload,
      );
      expect(chained.length, 32);

      // Verify manually: hash(prev + payload)
      final combined = Uint8List(prev.length + payload.length)
        ..setRange(0, prev.length, prev)
        ..setRange(
          prev.length,
          prev.length + payload.length,
          payload,
        );
      expect(chained, equals(hasher.hash(combined)));
    });

    test('chain of 3 links is consistent', () {
      final h0 = hasher.hash(
        Uint8List.fromList(utf8.encode('genesis')),
      );
      final h1 = hasher.chainHash(
        previousHash: h0,
        payload: Uint8List.fromList(utf8.encode('event1')),
      );
      final h2 = hasher.chainHash(
        previousHash: h1,
        payload: Uint8List.fromList(utf8.encode('event2')),
      );

      // All different
      expect(h0, isNot(equals(h1)));
      expect(h1, isNot(equals(h2)));
      expect(h0, isNot(equals(h2)));

      // Deterministic
      final h2Again = hasher.chainHash(
        previousHash: h1,
        payload: Uint8List.fromList(utf8.encode('event2')),
      );
      expect(h2, equals(h2Again));
    });

    test('altering one byte in chain changes output', () {
      final h0 = hasher.hash(Uint8List(0));
      final h1a = hasher.chainHash(
        previousHash: h0,
        payload: Uint8List.fromList([1, 2, 3]),
      );
      final h1b = hasher.chainHash(
        previousHash: h0,
        payload: Uint8List.fromList([1, 2, 4]),
      );
      expect(h1a, isNot(equals(h1b)));
    });
  });

  group('Hasher property-based', () {
    Glados2(any.list(any.int), any.list(any.int)).test(
      'different inputs produce different hashes',
      (a, b) {
        if (a.length == b.length) {
          var same = true;
          for (var i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
              same = false;
              break;
            }
          }
          if (same) return;
        }
        final bytesA = Uint8List.fromList(
          a.map((v) => v & 0xFF).toList(),
        );
        final bytesB = Uint8List.fromList(
          b.map((v) => v & 0xFF).toList(),
        );
        // Skip if masking made them equal
        if (bytesA.length == bytesB.length) {
          var same = true;
          for (var i = 0; i < bytesA.length; i++) {
            if (bytesA[i] != bytesB[i]) {
              same = false;
              break;
            }
          }
          if (same) return;
        }
        final hashA = hasher.hash(bytesA);
        final hashB = hasher.hash(bytesB);
        expect(hashA, isNot(equals(hashB)));
      },
    );
  });
}
