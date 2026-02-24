import 'dart:typed_data';

import 'package:styx_crypto_core/src/identity_manager.dart';
import 'package:styx_crypto_core/src/shamir/shamir_reconstructor.dart';
import 'package:styx_crypto_core/src/shamir/shamir_share.dart';
import 'package:styx_crypto_core/src/shamir/shamir_splitter.dart';
import 'package:styx_crypto_core/src/styx_key_pair.dart';
import 'package:styx_crypto_core/src/styx_private_key.dart';

/// Key backup and restore orchestration using Shamir's Secret Sharing.
class KeyBackup {
  /// Creates a [KeyBackup] with the given [splitter] and [reconstructor].
  KeyBackup({
    required ShamirSplitter splitter,
    required ShamirReconstructor reconstructor,
  })  : _splitter = splitter,
        _reconstructor = reconstructor;

  final ShamirSplitter _splitter;
  final ShamirReconstructor _reconstructor;
  final _identityManager = IdentityManager();

  /// Creates a backup of [privateKey] as Shamir shares.
  ///
  /// Default: 2-of-3 (any 2 shares sufficient to reconstruct).
  List<ShamirShare> backupPrivateKey({
    required StyxPrivateKey privateKey,
    int threshold = 2,
    int totalShares = 3,
  }) {
    return _splitter.split(
      secret: privateKey.bytes,
      threshold: threshold,
      totalShares: totalShares,
    );
  }

  /// Restores a key pair from a set of Shamir shares.
  ///
  /// Reconstructs the private key seed, then derives the public key.
  Future<StyxKeyPair> restoreFromShares(List<ShamirShare> shares) async {
    final seed = _reconstructor.reconstruct(shares);
    return _identityManager.importPrivateKey(Uint8List.fromList(seed));
  }
}
