import 'package:meta/meta.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';

/// Identity of the local Styx peer.
@immutable
class StyxIdentity {
  /// Creates a [StyxIdentity].
  const StyxIdentity({
    required this.publicKey,
    required this.nodeId,
    required this.peerRole,
  });

  /// Ed25519 public key.
  final StyxPublicKey publicKey;

  /// Node ID for HLC (first 8 hex chars of the public key).
  final String nodeId;

  /// Peer role ('A' or 'B', determined at pairing time).
  final String peerRole;
}
