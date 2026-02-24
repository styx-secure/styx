import 'dart:typed_data';

/// An Ed25519 private key (seed, 32 bytes) with secure destruction.
final class StyxPrivateKey {
  /// Creates a [StyxPrivateKey] with a defensive copy of [bytes].
  ///
  /// Throws [ArgumentError] if [bytes] is not exactly 32 bytes.
  StyxPrivateKey(Uint8List bytes) : _bytes = Uint8List.fromList(bytes) {
    if (bytes.length != 32) {
      throw ArgumentError.value(
        bytes.length,
        'bytes',
        'Must be exactly 32 bytes',
      );
    }
  }

  final Uint8List _bytes;
  bool _destroyed = false;

  /// Returns a defensive copy of the private key bytes.
  ///
  /// Throws [StateError] if this key has been destroyed.
  Uint8List get bytes {
    if (_destroyed) {
      throw StateError('Private key has been destroyed');
    }
    return Uint8List.fromList(_bytes);
  }

  /// Whether this key has been destroyed.
  bool get isDestroyed => _destroyed;

  /// Overwrites the key material with zeros and marks this key as destroyed.
  void destroy() {
    _bytes.fillRange(0, _bytes.length, 0);
    _destroyed = true;
  }
}
