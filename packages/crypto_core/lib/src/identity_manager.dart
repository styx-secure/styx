import 'dart:typed_data';

import 'package:crypto_core/src/key_pair.dart';
import 'package:cryptography/cryptography.dart' hide KeyPair;

/// Generates, exports, and imports Ed25519 key pairs.
class IdentityManager {
  final _algorithm = Ed25519();

  /// Generates a new random Ed25519 key pair.
  Future<KeyPair> generate() async {
    final simpleKeyPair = await _algorithm.newKeyPair();
    final privateKey = await simpleKeyPair.extractPrivateKeyBytes();
    final publicKey = await simpleKeyPair.extractPublicKey();
    return KeyPair(
      privateKeyBytes: Uint8List.fromList(privateKey),
      publicKeyBytes: Uint8List.fromList(publicKey.bytes),
    );
  }

  /// Serializes a [KeyPair] to 64 bytes (32 private + 32 public).
  Uint8List exportBytes(KeyPair keyPair) {
    return Uint8List(64)
      ..setRange(0, 32, keyPair.privateKeyBytes)
      ..setRange(32, 64, keyPair.publicKeyBytes);
  }

  /// Deserializes a [KeyPair] from 64 bytes.
  ///
  /// Throws [ArgumentError] if [bytes] is not exactly 64 bytes.
  KeyPair importBytes(Uint8List bytes) {
    if (bytes.length != 64) {
      throw ArgumentError.value(
        bytes.length,
        'bytes',
        'Must be exactly 64 bytes',
      );
    }
    return KeyPair(
      privateKeyBytes: Uint8List.sublistView(bytes, 0, 32),
      publicKeyBytes: Uint8List.sublistView(bytes, 32, 64),
    );
  }
}
