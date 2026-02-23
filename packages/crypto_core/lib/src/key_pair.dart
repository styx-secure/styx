import 'dart:typed_data';

import 'package:crypto_core/src/_list_equality.dart';
import 'package:meta/meta.dart';

/// Immutable wrapper for an Ed25519 key pair.
@immutable
final class KeyPair {
  /// Creates a [KeyPair] with defensive copies of the provided bytes.
  ///
  /// Both [privateKeyBytes] and [publicKeyBytes] must be exactly 32 bytes.
  KeyPair({
    required Uint8List privateKeyBytes,
    required Uint8List publicKeyBytes,
  })  : privateKeyBytes = Uint8List.fromList(privateKeyBytes),
        publicKeyBytes = Uint8List.fromList(publicKeyBytes) {
    if (privateKeyBytes.length != 32) {
      throw ArgumentError.value(
        privateKeyBytes.length,
        'privateKeyBytes',
        'Must be exactly 32 bytes',
      );
    }
    if (publicKeyBytes.length != 32) {
      throw ArgumentError.value(
        publicKeyBytes.length,
        'publicKeyBytes',
        'Must be exactly 32 bytes',
      );
    }
  }

  /// The 32-byte Ed25519 private key (seed).
  final Uint8List privateKeyBytes;

  /// The 32-byte Ed25519 public key.
  final Uint8List publicKeyBytes;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is KeyPair &&
          uint8ListEquals(privateKeyBytes, other.privateKeyBytes) &&
          uint8ListEquals(publicKeyBytes, other.publicKeyBytes);

  @override
  int get hashCode => Object.hash(
        Object.hashAll(privateKeyBytes),
        Object.hashAll(publicKeyBytes),
      );
}
