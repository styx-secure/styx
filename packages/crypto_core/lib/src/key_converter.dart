import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:styx_crypto_core/src/styx_private_key.dart';
import 'package:styx_crypto_core/src/styx_public_key.dart';

/// The prime field for Curve25519: p = 2^255 - 19.
final BigInt _p = BigInt.two.pow(255) - BigInt.from(19);

/// Converts Ed25519 keys to X25519 keys.
class KeyConverter {
  /// Converts an Ed25519 public key to an X25519 public key.
  ///
  /// Uses the Edwards-to-Montgomery map: `u = (1 + y) / (1 - y) mod p`.
  Uint8List ed25519PublicToX25519(StyxPublicKey publicKey) {
    final keyBytes = publicKey.bytes;

    // Ed25519 public key encodes the y-coordinate in little-endian,
    // with the sign bit in the high bit of byte 31.
    final yBytes = Uint8List.fromList(keyBytes);
    // Clear the sign bit to get the y-coordinate.
    yBytes[31] &= 0x7F;

    final y = _decodeLittleEndian(yBytes);

    // u = (1 + y) / (1 - y) mod p
    final numerator = (BigInt.one + y) % _p;
    final denominator = (BigInt.one - y) % _p;
    final u = (numerator * _modInverse(denominator, _p)) % _p;

    return _encodeLittleEndian(u);
  }

  /// Converts an Ed25519 private key (seed) to an X25519 private key.
  ///
  /// Applies SHA-512 to the seed and clamps per RFC 7748.
  Uint8List ed25519PrivateToX25519(StyxPrivateKey privateKey) {
    final h = crypto.sha512.convert(privateKey.bytes).bytes;
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
