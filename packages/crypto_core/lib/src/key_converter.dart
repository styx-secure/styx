import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:crypto_core/src/key_pair.dart';

/// The prime field for Curve25519: p = 2^255 - 19.
final BigInt _p = BigInt.two.pow(255) - BigInt.from(19);

/// Converts Ed25519 key pairs to X25519 key pairs.
class KeyConverter {
  /// Converts a full Ed25519 [KeyPair] to an X25519 [KeyPair].
  ///
  /// Private key: SHA-512(seed)[0:32] with X25519 clamping (RFC 7748).
  /// Public key: Edwards-to-Montgomery conversion.
  KeyPair convertToX25519(KeyPair ed25519KeyPair) {
    final privateKey = _convertPrivateKey(ed25519KeyPair.privateKeyBytes);
    final publicKey = convertPublicKey(ed25519KeyPair.publicKeyBytes);
    return KeyPair(privateKeyBytes: privateKey, publicKeyBytes: publicKey);
  }

  /// Converts an Ed25519 public key to an X25519 public key.
  ///
  /// Uses the Edwards-to-Montgomery map: `u = (1 + y) / (1 - y) mod p`.
  Uint8List convertPublicKey(Uint8List ed25519PublicKeyBytes) {
    if (ed25519PublicKeyBytes.length != 32) {
      throw ArgumentError.value(
        ed25519PublicKeyBytes.length,
        'ed25519PublicKeyBytes',
        'Must be exactly 32 bytes',
      );
    }

    // Ed25519 public key encodes the y-coordinate in little-endian,
    // with the sign bit in the high bit of byte 31.
    final yBytes = Uint8List.fromList(ed25519PublicKeyBytes);
    // Clear the sign bit to get the y-coordinate.
    yBytes[31] &= 0x7F;

    final y = _decodeLittleEndian(yBytes);

    // u = (1 + y) / (1 - y) mod p
    final numerator = (BigInt.one + y) % _p;
    final denominator = (BigInt.one - y) % _p;
    final u = (numerator * _modInverse(denominator, _p)) % _p;

    return _encodeLittleEndian(u);
  }

  Uint8List _convertPrivateKey(Uint8List seed) {
    final h = crypto.sha512.convert(seed).bytes;
    final key = Uint8List.fromList(h.sublist(0, 32));
    // X25519 clamping (RFC 7748)
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    return key;
  }
}

BigInt _decodeLittleEndian(Uint8List bytes) {
  var result = BigInt.zero;
  for (var i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8) | BigInt.from(bytes[i]);
  }
  return result;
}

Uint8List _encodeLittleEndian(BigInt value) {
  final result = Uint8List(32);
  var v = value;
  for (var i = 0; i < 32; i++) {
    result[i] = (v & BigInt.from(0xFF)).toInt();
    v >>= 8;
  }
  return result;
}

/// Computes the modular inverse using extended Euclidean algorithm.
BigInt _modInverse(BigInt a, BigInt m) {
  final normalized = a % m;
  return normalized.modInverse(m);
}
