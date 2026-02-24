import 'dart:typed_data';

import 'package:meta/meta.dart';
import 'package:styx_crypto_core/src/_list_equality.dart';

/// An immutable Ed25519 public key (32 bytes).
@immutable
final class StyxPublicKey {
  /// Creates a [StyxPublicKey] with a defensive copy of [bytes].
  ///
  /// Throws [ArgumentError] if [bytes] is not exactly 32 bytes.
  StyxPublicKey(Uint8List bytes) : bytes = Uint8List.fromList(bytes) {
    if (bytes.length != 32) {
      throw ArgumentError.value(
        bytes.length,
        'bytes',
        'Must be exactly 32 bytes',
      );
    }
  }

  /// Creates a [StyxPublicKey] from a hex string.
  ///
  /// Throws [FormatException] if [hex] is not valid hex.
  /// Throws [ArgumentError] if the decoded bytes are not 32 bytes.
  factory StyxPublicKey.fromHex(String hex) {
    if (hex.length != 64) {
      throw ArgumentError.value(
        hex,
        'hex',
        'Must be exactly 64 hex characters (32 bytes)',
      );
    }
    final bytes = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      final byteHex = hex.substring(i * 2, i * 2 + 2);
      final value = int.tryParse(byteHex, radix: 16);
      if (value == null) {
        throw FormatException('Invalid hex character', hex, i * 2);
      }
      bytes[i] = value;
    }
    return StyxPublicKey(bytes);
  }

  /// The 32-byte Ed25519 public key.
  final Uint8List bytes;

  /// Returns the hex-encoded representation of this key.
  String toHex() =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is StyxPublicKey && uint8ListEquals(bytes, other.bytes);

  @override
  int get hashCode => Object.hashAll(bytes);
}
