import 'dart:convert';
import 'dart:typed_data';

import 'package:meta/meta.dart';

/// A single share from Shamir's Secret Sharing.
@immutable
class ShamirShare {
  /// Creates a share with [index] (1..n) and [data].
  const ShamirShare({required this.index, required this.data});

  /// Deserializes a share from the format
  /// `styx-share-v1:{index}:{base64data}`.
  ///
  /// Throws [FormatException] if the encoding is invalid.
  factory ShamirShare.deserialize(String encoded) {
    final parts = encoded.split(':');
    if (parts.length != 3 || parts[0] != 'styx-share-v1') {
      throw const FormatException('Invalid share format');
    }
    final index = int.tryParse(parts[1]);
    if (index == null || index < 1) {
      throw const FormatException('Invalid share index');
    }
    final data = Uint8List.fromList(base64Decode(parts[2]));
    return ShamirShare(index: index, data: data);
  }

  /// Share index (1..n, never 0).
  final int index;

  /// Share bytes (same length as the original secret).
  final Uint8List data;

  /// Serializes this share to `styx-share-v1:{index}:{base64data}`.
  String serialize() => 'styx-share-v1:$index:${base64Encode(data)}';

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is ShamirShare &&
          index == other.index &&
          _bytesEqual(data, other.data);

  @override
  int get hashCode => Object.hash(index, Object.hashAll(data));
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
