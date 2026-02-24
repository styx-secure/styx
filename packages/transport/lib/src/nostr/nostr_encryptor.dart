import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';

/// End-to-end encryption for Nostr transport using ChaCha20-Poly1305.
///
/// Derives a shared symmetric key from X25519 DH + HKDF, then encrypts
/// each message with a random 12-byte nonce.
class NostrEncryptor {
  /// Creates a [NostrEncryptor] with the given X25519 key material.
  ///
  /// [localPrivateKey] — 32-byte X25519 private key.
  /// [remotePublicKey] — 32-byte X25519 public key of the peer.
  NostrEncryptor({
    required Uint8List localPrivateKey,
    required Uint8List remotePublicKey,
  })  : _localPrivateKey = Uint8List.fromList(localPrivateKey),
        _remotePublicKey = Uint8List.fromList(remotePublicKey);

  final Uint8List _localPrivateKey;
  final Uint8List _remotePublicKey;
  Uint8List? _symmetricKey;

  static const _info = 'styx-transport-v1';

  /// Initializes the shared symmetric key via DH + HKDF.
  ///
  /// Must be called before [encrypt] or [decrypt].
  Future<void> initialize() async {
    final dh = DiffieHellman();
    final sharedSecret = await dh.computeSharedSecret(
      localPrivateKey: _localPrivateKey,
      remotePublicKey: _remotePublicKey,
    );

    final kdf = KeyDerivation();
    _symmetricKey = await kdf.deriveKey(
      sharedSecret: sharedSecret,
      info: Uint8List.fromList(_info.codeUnits),
    );
  }

  /// Encrypts [plaintext] with ChaCha20-Poly1305.
  ///
  /// Returns `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
  Future<Uint8List> encrypt(Uint8List plaintext) async {
    _checkInitialized();

    final algorithm = Chacha20.poly1305Aead();
    final nonce = _generateNonce();
    final secretKey = SecretKey(_symmetricKey!);

    final secretBox = await algorithm.encrypt(
      plaintext,
      secretKey: secretKey,
      nonce: nonce,
    );

    // nonce || ciphertext || mac
    final result = BytesBuilder(copy: false)
      ..add(nonce)
      ..add(secretBox.cipherText)
      ..add(secretBox.mac.bytes);
    return result.toBytes();
  }

  /// Decrypts data produced by [encrypt].
  ///
  /// [data] must be `nonce (12) || ciphertext || tag (16)`.
  /// Throws [SecretBoxAuthenticationError] if the tag is invalid.
  Future<Uint8List> decrypt(Uint8List data) async {
    _checkInitialized();

    if (data.length < 28) {
      throw ArgumentError('Encrypted data too short (min 28 bytes)');
    }

    final algorithm = Chacha20.poly1305Aead();
    final nonce = Uint8List.sublistView(data, 0, 12);
    final cipherText = Uint8List.sublistView(data, 12, data.length - 16);
    final mac = Mac(Uint8List.sublistView(data, data.length - 16));

    final secretKey = SecretKey(_symmetricKey!);

    final secretBox = SecretBox(
      cipherText,
      nonce: nonce,
      mac: mac,
    );

    final plaintext = await algorithm.decrypt(
      secretBox,
      secretKey: secretKey,
    );

    return Uint8List.fromList(plaintext);
  }

  Uint8List _generateNonce() {
    final random = Random.secure();
    final nonce = Uint8List(12);
    for (var i = 0; i < 12; i++) {
      nonce[i] = random.nextInt(256);
    }
    return nonce;
  }

  void _checkInitialized() {
    if (_symmetricKey == null) {
      throw StateError(
        'NostrEncryptor not initialized. Call initialize() first.',
      );
    }
  }
}
