import 'dart:typed_data';

import 'package:crypto_core/src/key_pair.dart';
import 'package:cryptography/cryptography.dart' hide KeyPair;

/// Signs payloads using Ed25519.
class Signer {
  final _algorithm = Ed25519();

  /// Signs [payload] with the given [keyPair]
  /// and returns a 64-byte signature.
  Future<Uint8List> sign(
    Uint8List payload,
    KeyPair keyPair,
  ) async {
    final simpleKeyPair = SimpleKeyPairData(
      List<int>.from(keyPair.privateKeyBytes),
      publicKey: SimplePublicKey(
        List<int>.from(keyPair.publicKeyBytes),
        type: KeyPairType.ed25519,
      ),
      type: KeyPairType.ed25519,
    );
    final signature = await _algorithm.sign(
      payload,
      keyPair: simpleKeyPair,
    );
    return Uint8List.fromList(signature.bytes);
  }
}
