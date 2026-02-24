import 'package:styx_crypto_core/styx_crypto_core.dart';

/// Service for creating and restoring Shamir's Secret Sharing backups.
///
/// Splits a private key into N shares with a threshold of K required
/// for reconstruction. Shares can be serialized for QR codes or text.
class ShamirBackupService {
  /// Creates a [ShamirBackupService].
  ShamirBackupService({
    required KeyBackup keyBackup,
    required SecureKeyStore secureKeyStore,
  })  : _keyBackup = keyBackup,
        _secureKeyStore = secureKeyStore;

  final KeyBackup _keyBackup;
  final SecureKeyStore _secureKeyStore;

  /// Creates a backup of [privateKey] as serialized Shamir shares.
  ///
  /// Returns [totalShares] serialized strings, of which [threshold]
  /// are needed for reconstruction.
  List<String> createBackup({
    required StyxPrivateKey privateKey,
    int threshold = 2,
    int totalShares = 3,
  }) {
    final shares = _keyBackup.backupPrivateKey(
      privateKey: privateKey,
      threshold: threshold,
      totalShares: totalShares,
    );
    return shares.map((s) => s.serialize()).toList();
  }

  /// Restores a key pair from serialized shares and saves it.
  ///
  /// Deserializes the shares, reconstructs the private key, and stores
  /// the resulting key pair in the [SecureKeyStore].
  Future<StyxKeyPair> restoreFromBackup({
    required List<String> serializedShares,
    required String keyId,
  }) async {
    final shares = serializedShares.map(ShamirShare.deserialize).toList();
    final keyPair = await _keyBackup.restoreFromShares(shares);
    await _secureKeyStore.storeKeyPair(keyId: keyId, keyPair: keyPair);
    return keyPair;
  }

  /// Verifies that a set of shares can reconstruct a valid key.
  ///
  /// Attempts reconstruction without saving. Returns true if successful.
  Future<bool> verifyShares(List<String> serializedShares) async {
    try {
      final shares = serializedShares.map(ShamirShare.deserialize).toList();
      final keyPair = await _keyBackup.restoreFromShares(shares);
      // Check that the key is valid (32 bytes).
      return keyPair.privateKey.bytes.length == 32;
    } on Object {
      return false;
    }
  }
}
