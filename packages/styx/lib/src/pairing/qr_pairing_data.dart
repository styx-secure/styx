import 'dart:convert';
import 'dart:typed_data';

import 'package:meta/meta.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';

/// Data structure for QR code payload containing pairing information.
///
/// JSON format: `{"pk":"<hex>","n":"<base64>","r":["wss://..."]}`
@immutable
class QrPairingData {
  /// Creates a [QrPairingData].
  const QrPairingData({
    required this.publicKey,
    required this.nonce,
    this.relayHints,
  });

  /// Deserializes from a QR payload string.
  factory QrPairingData.fromQrPayload(String payload) {
    final map = jsonDecode(payload) as Map<String, dynamic>;
    final pk = map['pk'] as String?;
    final n = map['n'] as String?;
    if (pk == null || n == null) {
      throw const FormatException('Missing required fields: pk, n');
    }

    final relays = map['r'] as List<dynamic>?;
    return QrPairingData(
      publicKey: StyxPublicKey.fromHex(pk),
      nonce: base64Decode(n),
      relayHints: relays?.cast<String>(),
    );
  }

  /// Ed25519 public key of the peer.
  final StyxPublicKey publicKey;

  /// One-time nonce (16 bytes) for anti-replay.
  final Uint8List nonce;

  /// Suggested Nostr relay URLs (optional).
  final List<String>? relayHints;

  /// Serializes as compact JSON for a QR code.
  String toQrPayload() {
    final map = <String, dynamic>{
      'pk': publicKey.toHex(),
      'n': base64Encode(nonce),
    };
    if (relayHints != null && relayHints!.isNotEmpty) {
      map['r'] = relayHints;
    }
    return jsonEncode(map);
  }

  /// Estimated byte size of the QR payload.
  int get estimatedBytes => toQrPayload().length;
}
