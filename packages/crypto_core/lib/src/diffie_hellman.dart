import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// An ephemeral X25519 key pair for Diffie-Hellman key exchange.
final class X25519KeyPair {
  /// Creates an [X25519KeyPair] with defensive copies of [publicKey] and
  /// [privateKey].
  X25519KeyPair({
    required Uint8List publicKey,
    required Uint8List privateKey,
  })  : _publicKey = Uint8List.fromList(publicKey),
        _privateKey = Uint8List.fromList(privateKey);

  final Uint8List _publicKey;
  final Uint8List _privateKey;
  bool _destroyed = false;

  /// The 32-byte X25519 public key.
  ///
  /// Throws [StateError] if this key pair has been destroyed.
  Uint8List get publicKey {
    _checkNotDestroyed();
    return Uint8List.fromList(_publicKey);
  }

  /// The 32-byte X25519 private key.
  ///
  /// Throws [StateError] if this key pair has been destroyed.
  Uint8List get privateKey {
    _checkNotDestroyed();
    return Uint8List.fromList(_privateKey);
  }

  /// Whether this key pair has been destroyed.
  bool get isDestroyed => _destroyed;

  /// Overwrites all key material with zeros.
  void destroy() {
    _publicKey.fillRange(0, _publicKey.length, 0);
    _privateKey.fillRange(0, _privateKey.length, 0);
    _destroyed = true;
  }

  void _checkNotDestroyed() {
    if (_destroyed) {
      throw StateError('X25519KeyPair has been destroyed');
    }
  }
}

/// X25519 Diffie-Hellman key exchange.
class DiffieHellman {
  final _algorithm = X25519();

  /// Generates an ephemeral X25519 key pair for a DH session.
  Future<X25519KeyPair> generateEphemeralKeyPair() async {
    final keyPair = await _algorithm.newKeyPair();
    final privateKeyBytes = await keyPair.extractPrivateKeyBytes();
    final publicKey = await keyPair.extractPublicKey();
    return X25519KeyPair(
      publicKey: Uint8List.fromList(publicKey.bytes),
      privateKey: Uint8List.fromList(privateKeyBytes),
    );
  }

  /// Computes the shared secret from [localPrivateKey] and [remotePublicKey].
  ///
  /// Returns a 32-byte shared secret. This raw output must be passed through
  /// HKDF before use as a symmetric key.
  Future<Uint8List> computeSharedSecret({
    required Uint8List localPrivateKey,
    required Uint8List remotePublicKey,
  }) async {
    final keyPair = SimpleKeyPairData(
      localPrivateKey,
      publicKey: SimplePublicKey(
        // The local public key is not used for the computation,
        // but the API requires it. We pass an empty placeholder.
        Uint8List(32),
        type: KeyPairType.x25519,
      ),
      type: KeyPairType.x25519,
    );

    final remoteKey = SimplePublicKey(
      remotePublicKey,
      type: KeyPairType.x25519,
    );

    final sharedSecret = await _algorithm.sharedSecretKey(
      keyPair: keyPair,
      remotePublicKey: remoteKey,
    );

    return Uint8List.fromList(await sharedSecret.extractBytes());
  }
}
