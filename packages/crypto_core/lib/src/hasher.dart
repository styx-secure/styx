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
  ///
  /// If [previousHash] is `null` (genesis event), hashes only [payload].
  Uint8List chainHash({
    required Uint8List? previousHash,
    required Uint8List payload,
  }) {
    if (previousHash == null) {
      return hash(payload);
    }
    final combined = Uint8List(previousHash.length + payload.length)
      ..setRange(0, previousHash.length, previousHash)
      ..setRange(
        previousHash.length,
        previousHash.length + payload.length,
        payload,
      );
    return hash(combined);
  }

  /// Computes `SHA-256(segments[0] || segments[1] || ...)`.
  Uint8List compositeHash(List<Uint8List> segments) {
    var totalLength = 0;
    for (final segment in segments) {
      totalLength += segment.length;
    }
    final combined = Uint8List(totalLength);
    var offset = 0;
    for (final segment in segments) {
      combined.setRange(offset, offset + segment.length, segment);
      offset += segment.length;
    }
    return hash(combined);
  }
}
