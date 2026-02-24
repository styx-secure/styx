import 'dart:math';
import 'dart:typed_data';

import 'package:meta/meta.dart';
import 'package:styx/src/pairing/qr_pairing_data.dart';
import 'package:styx/src/trust/trust_store_manager.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';

/// Result of processing a scanned QR code.
@immutable
class PairingResult {
  /// Creates a [PairingResult].
  const PairingResult({
    required this.peerPublicKey,
    required this.relayHints,
    required this.isValid,
    this.errorMessage,
  });

  /// The peer's public key from the QR code.
  final StyxPublicKey peerPublicKey;

  /// Relay hints from the QR code.
  final List<String> relayHints;

  /// Whether the QR data is valid.
  final bool isValid;

  /// Error message if invalid.
  final String? errorMessage;
}

/// Service for QR-based direct pairing.
///
/// Generates QR data with anti-replay nonces and processes scanned QR codes.
class QrPairingService {
  /// Creates a [QrPairingService].
  QrPairingService({
    required TrustStoreManager trustStore,
    Random? random,
  })  : _trustStore = trustStore,
        _random = random ?? Random.secure();

  final TrustStoreManager _trustStore;
  final Random _random;

  /// Recent nonces for anti-replay (max 100, expire after 5 min).
  final _recentNonces = <String, DateTime>{};
  static const _maxNonces = 100;
  static const _nonceExpiry = Duration(minutes: 5);

  /// Generates QR data containing the local public key and a fresh nonce.
  QrPairingData generateQrData({
    required StyxPublicKey localPublicKey,
    List<String>? relayHints,
  }) {
    final nonce = Uint8List(16);
    for (var i = 0; i < 16; i++) {
      nonce[i] = _random.nextInt(256);
    }
    return QrPairingData(
      publicKey: localPublicKey,
      nonce: nonce,
      relayHints: relayHints,
    );
  }

  /// Processes a scanned QR payload.
  ///
  /// Validates format, checks nonce anti-replay, and returns the result.
  PairingResult processScannedQr({
    required String qrPayload,
    required StyxPublicKey localPublicKey,
  }) {
    _pruneExpiredNonces();

    try {
      final data = QrPairingData.fromQrPayload(qrPayload);

      // Anti-replay: check nonce uniqueness.
      final nonceKey = String.fromCharCodes(data.nonce);
      if (_recentNonces.containsKey(nonceKey)) {
        return PairingResult(
          peerPublicKey: data.publicKey,
          relayHints: data.relayHints ?? [],
          isValid: false,
          errorMessage: 'Nonce already used (replay attempt)',
        );
      }
      _recentNonces[nonceKey] = DateTime.now();

      return PairingResult(
        peerPublicKey: data.publicKey,
        relayHints: data.relayHints ?? [],
        isValid: true,
      );
    } on FormatException catch (e) {
      return PairingResult(
        peerPublicKey: StyxPublicKey(Uint8List(32)),
        relayHints: const [],
        isValid: false,
        errorMessage: 'Invalid QR format: ${e.message}',
      );
    } on Object catch (e) {
      return PairingResult(
        peerPublicKey: StyxPublicKey(Uint8List(32)),
        relayHints: const [],
        isValid: false,
        errorMessage: 'Invalid QR data: $e',
      );
    }
  }

  /// Completes pairing by saving the peer in the trust store.
  Future<void> completePairing({
    required StyxPublicKey peerPublicKey,
    required String? peerAlias,
  }) async {
    await _trustStore.addTrustedPeer(
      peerPublicKey: peerPublicKey,
      alias: peerAlias,
    );
  }

  void _pruneExpiredNonces() {
    final now = DateTime.now();
    _recentNonces.removeWhere(
      (_, timestamp) => now.difference(timestamp) > _nonceExpiry,
    );
    // Keep max 100 entries.
    while (_recentNonces.length > _maxNonces) {
      _recentNonces.remove(_recentNonces.keys.first);
    }
  }
}
