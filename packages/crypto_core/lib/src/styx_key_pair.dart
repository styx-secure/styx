import 'package:styx_crypto_core/src/styx_private_key.dart';
import 'package:styx_crypto_core/src/styx_public_key.dart';

/// An Ed25519 key pair consisting of a public key and a private key.
final class StyxKeyPair {
  /// Creates a [StyxKeyPair] from the given [publicKey] and [privateKey].
  const StyxKeyPair({
    required this.publicKey,
    required this.privateKey,
  });

  /// The Ed25519 public key.
  final StyxPublicKey publicKey;

  /// The Ed25519 private key (seed).
  final StyxPrivateKey privateKey;
}
