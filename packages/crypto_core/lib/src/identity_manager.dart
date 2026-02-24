import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:styx_crypto_core/src/styx_key_pair.dart';
import 'package:styx_crypto_core/src/styx_private_key.dart';
import 'package:styx_crypto_core/src/styx_public_key.dart';

/// Generates, exports, and imports Ed25519 key pairs.
class IdentityManager {
  final _algorithm = Ed25519();

  /// Generates a new random Ed25519 key pair.
  Future<StyxKeyPair> generate() async {
    final simpleKeyPair = await _algorithm.newKeyPair();
    final privateKeyBytes = await simpleKeyPair.extractPrivateKeyBytes();
    final publicKey = await simpleKeyPair.extractPublicKey();
    return StyxKeyPair(
      privateKey: StyxPrivateKey(Uint8List.fromList(privateKeyBytes)),
      publicKey: StyxPublicKey(Uint8List.fromList(publicKey.bytes)),
    );
  }

  /// Serializes a [StyxPublicKey] to its raw 32 bytes.
  Uint8List exportPublicKey(StyxPublicKey publicKey) =>
      Uint8List.fromList(publicKey.bytes);

  /// Deserializes a [StyxPublicKey] from 32 bytes.
  ///
  /// Throws [ArgumentError] if [bytes] is not exactly 32 bytes.
  StyxPublicKey importPublicKey(Uint8List bytes) => StyxPublicKey(bytes);

  /// Serializes a [StyxPrivateKey] to its raw 32 bytes.
  Uint8List exportPrivateKey(StyxPrivateKey privateKey) =>
      Uint8List.fromList(privateKey.bytes);

  /// Reconstructs a [StyxKeyPair] from a 32-byte private key seed.
  ///
  /// Derives the public key from the seed via `Ed25519().newKeyPairFromSeed()`.
  Future<StyxKeyPair> importPrivateKey(Uint8List bytes) async {
    final seed = StyxPrivateKey(bytes);
    final simpleKeyPair = await _algorithm.newKeyPairFromSeed(seed.bytes);
    final publicKey = await simpleKeyPair.extractPublicKey();
    return StyxKeyPair(
      privateKey: seed,
      publicKey: StyxPublicKey(Uint8List.fromList(publicKey.bytes)),
    );
  }
}
