import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:styx_crypto_core/src/styx_public_key.dart';

/// Verifies Ed25519 signatures.
class Verifier {
  final _algorithm = Ed25519();

  /// Returns `true` if the [signatureBytes] are a valid Ed25519 signature
  /// of [payload] under [publicKey].
  Future<bool> verify({
    required Uint8List payload,
    required Uint8List signatureBytes,
    required StyxPublicKey publicKey,
  }) async {
    try {
      final simplePublicKey = SimplePublicKey(
        publicKey.bytes,
        type: KeyPairType.ed25519,
      );
      final signature = Signature(signatureBytes, publicKey: simplePublicKey);
      return await _algorithm.verify(payload, signature: signature);
      // The cryptography package throws StateError for malformed signatures.
      // ignore: avoid_catching_errors
    } on Error {
      return false;
    } on Exception {
      return false;
    }
  }
}
