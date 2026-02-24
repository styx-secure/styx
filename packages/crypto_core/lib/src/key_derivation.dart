import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// A pair of directional keys for bidirectional encryption.
final class DirectionalKeys {
  /// Creates a [DirectionalKeys] with defensive copies.
  DirectionalKeys({
    required Uint8List sendKey,
    required Uint8List receiveKey,
  })  : _sendKey = Uint8List.fromList(sendKey),
        _receiveKey = Uint8List.fromList(receiveKey);

  final Uint8List _sendKey;
  final Uint8List _receiveKey;
  bool _destroyed = false;

  /// The 32-byte key for encrypting outgoing messages.
  ///
  /// Throws [StateError] if destroyed.
  Uint8List get sendKey {
    _checkNotDestroyed();
    return Uint8List.fromList(_sendKey);
  }

  /// The 32-byte key for decrypting incoming messages.
  ///
  /// Throws [StateError] if destroyed.
  Uint8List get receiveKey {
    _checkNotDestroyed();
    return Uint8List.fromList(_receiveKey);
  }

  /// Whether these keys have been destroyed.
  bool get isDestroyed => _destroyed;

  /// Overwrites all key material with zeros.
  void destroy() {
    _sendKey.fillRange(0, _sendKey.length, 0);
    _receiveKey.fillRange(0, _receiveKey.length, 0);
    _destroyed = true;
  }

  void _checkNotDestroyed() {
    if (_destroyed) {
      throw StateError('DirectionalKeys have been destroyed');
    }
  }
}

/// HKDF-SHA256 key derivation.
class KeyDerivation {
  /// Derives a symmetric key from a DH shared secret.
  ///
  /// [sharedSecret] — output of DH (32 bytes).
  /// [salt] — optional salt (null = HKDF without salt).
  /// [info] — application context (e.g., "styx-session-v1").
  /// [outputLength] — key length in bytes (default: 32 for AES-256).
  Future<Uint8List> deriveKey({
    required Uint8List sharedSecret,
    required Uint8List info,
    Uint8List? salt,
    int outputLength = 32,
  }) async {
    final hkdf = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: outputLength,
    );

    final secretKey = SecretKey(sharedSecret);
    final derived = await hkdf.deriveKey(
      secretKey: secretKey,
      nonce: salt ?? Uint8List(0),
      info: info,
    );

    return Uint8List.fromList(await derived.extractBytes());
  }

  /// Derives a pair of directional keys (A→B and B→A).
  ///
  /// Public keys are sorted lexicographically so both peers derive the
  /// same pair regardless of who calls this method.
  Future<DirectionalKeys> deriveDirectionalKeys({
    required Uint8List sharedSecret,
    required Uint8List localPubKey,
    required Uint8List remotePubKey,
  }) async {
    // Sort pubkeys lexicographically to get a canonical order.
    final comparison = _comparePubKeys(localPubKey, remotePubKey);
    final Uint8List lowerKey;
    final Uint8List higherKey;
    if (comparison < 0) {
      lowerKey = localPubKey;
      higherKey = remotePubKey;
    } else {
      lowerKey = remotePubKey;
      higherKey = localPubKey;
    }

    final sendInfo = _buildInfo('styx-send-', lowerKey, higherKey);
    final recvInfo = _buildInfo('styx-recv-', lowerKey, higherKey);

    // The peer with the lexicographically lower key uses send/recv as-is.
    // The peer with the higher key swaps them.
    final key1 = await deriveKey(
      sharedSecret: sharedSecret,
      info: sendInfo,
    );
    final key2 = await deriveKey(
      sharedSecret: sharedSecret,
      info: recvInfo,
    );

    final localIsLower = comparison < 0;
    return DirectionalKeys(
      sendKey: localIsLower ? key1 : key2,
      receiveKey: localIsLower ? key2 : key1,
    );
  }
}

/// Compares two byte arrays lexicographically.
int _comparePubKeys(Uint8List a, Uint8List b) {
  final len = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < len; i++) {
    if (a[i] != b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/// Builds an HKDF info parameter by concatenating a prefix with two keys.
Uint8List _buildInfo(String prefix, Uint8List key1, Uint8List key2) {
  final prefixBytes = Uint8List.fromList(prefix.codeUnits);
  final result = Uint8List(prefixBytes.length + key1.length + key2.length)
    ..setRange(0, prefixBytes.length, prefixBytes)
    ..setRange(prefixBytes.length, prefixBytes.length + key1.length, key1)
    ..setRange(
      prefixBytes.length + key1.length,
      prefixBytes.length + key1.length + key2.length,
      key2,
    );
  return result;
}
