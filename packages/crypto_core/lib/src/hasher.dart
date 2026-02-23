import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

/// SHA-256 hashing with hash-chain support.
class Hasher {
  /// Computes the SHA-256 hash of [data], returning 32 bytes.
  Uint8List hash(Uint8List data) {
    final digest = crypto.sha256.convert(data);
    return Uint8List.fromList(digest.bytes);
  }

  /// Computes `SHA-256(previousHash || payload)`.
  Uint8List chainHash({
    required Uint8List previousHash,
    required Uint8List payload,
  }) {
    final combined = Uint8List(previousHash.length + payload.length)
      ..setRange(0, previousHash.length, previousHash)
      ..setRange(
        previousHash.length,
        previousHash.length + payload.length,
        payload,
      );
    return hash(combined);
  }
}
