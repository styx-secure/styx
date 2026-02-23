import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// Verifies Ed25519 signatures.
class Verifier {
  final _algorithm = Ed25519();

  /// Returns `true` if the [signatureBytes] are a valid Ed25519 signature
  /// of [payload] under [publicKeyBytes].
  Future<bool> verify({
    required Uint8List payload,
    required Uint8List signatureBytes,
    required Uint8List publicKeyBytes,
  }) async {
    try {
      final publicKey = SimplePublicKey(
        publicKeyBytes,
        type: KeyPairType.ed25519,
      );
      final signature = Signature(signatureBytes, publicKey: publicKey);
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
