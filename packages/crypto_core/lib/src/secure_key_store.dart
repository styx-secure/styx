import 'dart:convert';
import 'dart:typed_data';

import 'package:styx_crypto_core/src/styx_key_pair.dart';
import 'package:styx_crypto_core/src/styx_private_key.dart';
import 'package:styx_crypto_core/src/styx_public_key.dart';

/// Abstract interface for hardware-backed key persistence.
///
/// Implementations may use Android Keystore / iOS Keychain
/// (via `FlutterSecureKeyStore` in the Flutter layer) or an
/// in-memory store for testing.
abstract class SecureKeyStore {
  /// Stores a key pair under [keyId].
  ///
  /// Overwrites any existing key pair with the same [keyId].
  Future<void> storeKeyPair({
    required String keyId,
    required StyxKeyPair keyPair,
  });

  /// Retrieves the key pair stored under [keyId].
  ///
  /// Returns `null` if no key pair exists for [keyId].
  Future<StyxKeyPair?> retrieveKeyPair(String keyId);

  /// Deletes the key pair stored under [keyId].
  ///
  /// No-op if [keyId] does not exist.
  Future<void> deleteKeyPair(String keyId);

  /// Returns `true` if a key pair exists for [keyId].
  Future<bool> hasKeyPair(String keyId);

  /// Stores a binary secret under [key].
  Future<void> storeSecret({
    required String key,
    required Uint8List value,
  });

  /// Retrieves the binary secret stored under [key].
  ///
  /// Returns `null` if no secret exists for [key].
  Future<Uint8List?> retrieveSecret(String key);

  /// Deletes the secret stored under [key].
  Future<void> deleteSecret(String key);

  /// Deletes all stored keys and secrets.
  Future<void> deleteAll();
}

/// In-memory implementation of [SecureKeyStore] for testing.
///
/// Uses Base64 encoding internally to mirror the serialization
/// constraints of `flutter_secure_storage` (string-only values).
class InMemoryKeyStore implements SecureKeyStore {
  final Map<String, String> _store = {};

  @override
  Future<void> storeKeyPair({
    required String keyId,
    required StyxKeyPair keyPair,
  }) async {
    final pubB64 = base64Encode(keyPair.publicKey.bytes);
    final privB64 = base64Encode(keyPair.privateKey.bytes);
    _store['$keyId.pub'] = pubB64;
    _store['$keyId.priv'] = privB64;
  }

  @override
  Future<StyxKeyPair?> retrieveKeyPair(String keyId) async {
    final pubB64 = _store['$keyId.pub'];
    final privB64 = _store['$keyId.priv'];
    if (pubB64 == null || privB64 == null) return null;
    return StyxKeyPair(
      publicKey: StyxPublicKey(Uint8List.fromList(base64Decode(pubB64))),
      privateKey: StyxPrivateKey(Uint8List.fromList(base64Decode(privB64))),
    );
  }

  @override
  Future<void> deleteKeyPair(String keyId) async {
    _store
      ..remove('$keyId.pub')
      ..remove('$keyId.priv');
  }

  @override
  Future<bool> hasKeyPair(String keyId) async =>
      _store.containsKey('$keyId.pub') && _store.containsKey('$keyId.priv');

  @override
  Future<void> storeSecret({
    required String key,
    required Uint8List value,
  }) async {
    _store[key] = base64Encode(value);
  }

  @override
  Future<Uint8List?> retrieveSecret(String key) async {
    final b64 = _store[key];
    if (b64 == null) return null;
    return Uint8List.fromList(base64Decode(b64));
  }

  @override
  Future<void> deleteSecret(String key) async {
    _store.remove(key);
  }

  @override
  Future<void> deleteAll() async {
    _store.clear();
  }
}
