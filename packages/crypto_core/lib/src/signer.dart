import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:styx_crypto_core/src/styx_private_key.dart';

/// Signs payloads using Ed25519.
class Signer {
  final _algorithm = Ed25519();

  /// Signs [payload] with the given [privateKey]
  /// and returns a 64-byte signature.
  Future<Uint8List> sign(
    Uint8List payload,
    StyxPrivateKey privateKey,
  ) async {
    final simpleKeyPair = await _algorithm.newKeyPairFromSeed(privateKey.bytes);
    final signature = await _algorithm.sign(
      payload,
      keyPair: simpleKeyPair,
    );
    return Uint8List.fromList(signature.bytes);
  }
}
