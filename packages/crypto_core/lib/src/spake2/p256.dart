import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:meta/meta.dart';

// ---------------------------------------------------------------------------
// NIST P-256 (secp256r1) curve parameters
// ---------------------------------------------------------------------------

/// The prime modulus p of the P-256 field.
final BigInt p256Prime = BigInt.parse(
  'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
  radix: 16,
);

/// The curve coefficient a = -3 mod p.
final BigInt p256A = p256Prime - BigInt.from(3);

/// The curve coefficient b.
final BigInt p256B = BigInt.parse(
  '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
  radix: 16,
);

/// The order n of the base point G.
final BigInt p256Order = BigInt.parse(
  'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
  radix: 16,
);

/// The base point G of P-256.
final P256Point p256G = P256Point(
  BigInt.parse(
    '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
    radix: 16,
  ),
  BigInt.parse(
    '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
    radix: 16,
  ),
);

// ---------------------------------------------------------------------------
// SPAKE2 M and N points from RFC 9382, Section 4 (P-256)
// ---------------------------------------------------------------------------

/// M point for the initiator (from RFC 9382 Section 4).
final P256Point spake2M = P256Point(
  BigInt.parse(
    '886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f',
    radix: 16,
  ),
  BigInt.parse(
    '5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20',
    radix: 16,
  ),
);

/// N point for the responder (from RFC 9382 Section 4).
final P256Point spake2N = P256Point(
  BigInt.parse(
    'd8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49',
    radix: 16,
  ),
  BigInt.parse(
    '07d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7',
    radix: 16,
  ),
);

// ---------------------------------------------------------------------------
// P-256 Affine Point
// ---------------------------------------------------------------------------

/// The point at infinity (identity element) on P-256.
final P256Point p256Infinity = P256Point._infinity();

/// A point on the P-256 curve in affine coordinates.
///
/// The point at infinity is represented by [isInfinity] == true.
@immutable
class P256Point {
  /// Creates a finite point with coordinates ([x], [y]).
  const P256Point(this.x, this.y) : isInfinity = false;

  /// Creates the point at infinity (identity element).
  P256Point._infinity()
      : x = BigInt.zero,
        y = BigInt.zero,
        isInfinity = true;

  /// Decodes a point from uncompressed SEC1 format.
  ///
  /// Throws [ArgumentError] if the encoding is invalid.
  factory P256Point.fromUncompressedBytes(Uint8List bytes) {
    if (bytes.length == 1 && bytes[0] == 0) {
      return p256Infinity;
    }
    if (bytes.length != 65 || bytes[0] != 0x04) {
      throw ArgumentError('Invalid uncompressed point encoding');
    }
    final x = _readBigInt(bytes, 1, 32);
    final y = _readBigInt(bytes, 33, 32);
    return P256Point(x, y);
  }

  /// The x-coordinate.
  final BigInt x;

  /// The y-coordinate.
  final BigInt y;

  /// Whether this is the point at infinity.
  final bool isInfinity;

  /// Encodes this point in uncompressed SEC1 format (0x04 || x || y).
  ///
  /// Returns a single zero byte for the point at infinity.
  Uint8List toUncompressedBytes() {
    if (isInfinity) return Uint8List(1);
    final result = Uint8List(65);
    result[0] = 0x04;
    _writeBigInt(result, 1, x);
    _writeBigInt(result, 33, y);
    return result;
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is P256Point &&
          isInfinity == other.isInfinity &&
          x == other.x &&
          y == other.y;

  @override
  int get hashCode => Object.hash(x, y, isInfinity);
}

// ---------------------------------------------------------------------------
// P-256 arithmetic
// ---------------------------------------------------------------------------

/// Adds two points on P-256.
P256Point p256Add(P256Point p1, P256Point p2) {
  if (p1.isInfinity) return p2;
  if (p2.isInfinity) return p1;

  final p = p256Prime;

  if (p1.x == p2.x) {
    if ((p1.y + p2.y) % p == BigInt.zero) {
      return p256Infinity;
    }
    // Same point → double
    return p256Double(p1);
  }

  // λ = (y2 - y1) / (x2 - x1) mod p
  final dx = (p2.x - p1.x) % p;
  final dy = (p2.y - p1.y) % p;
  final lambda = (dy * dx.modInverse(p)) % p;

  // x3 = λ² - x1 - x2
  final x3 = (lambda * lambda - p1.x - p2.x) % p;
  // y3 = λ(x1 - x3) - y1
  final y3 = (lambda * (p1.x - x3) - p1.y) % p;

  return P256Point(x3, y3);
}

/// Doubles a point on P-256.
P256Point p256Double(P256Point pt) {
  if (pt.isInfinity) return pt;

  final p = p256Prime;

  // λ = (3·x² + a) / (2·y) mod p
  final x2 = (pt.x * pt.x) % p;
  final num = (BigInt.from(3) * x2 + p256A) % p;
  final den = (BigInt.two * pt.y) % p;
  final lambda = (num * den.modInverse(p)) % p;

  final x3 = (lambda * lambda - BigInt.two * pt.x) % p;
  final y3 = (lambda * (pt.x - x3) - pt.y) % p;

  return P256Point(x3, y3);
}

/// Scalar multiplication: computes [scalar] * [point] on P-256.
///
/// Uses the double-and-add algorithm.
P256Point p256ScalarMul(P256Point point, BigInt scalar) {
  final s = scalar % p256Order;
  if (s == BigInt.zero) return p256Infinity;

  var result = p256Infinity;
  var temp = point;

  var k = s;
  while (k > BigInt.zero) {
    if (k.isOdd) {
      result = p256Add(result, temp);
    }
    temp = p256Double(temp);
    k >>= 1;
  }

  return result;
}

/// Negates a point on P-256: returns (x, -y mod p).
P256Point p256Negate(P256Point pt) {
  if (pt.isInfinity) return pt;
  return P256Point(pt.x, (p256Prime - pt.y) % p256Prime);
}

/// Subtracts [p2] from [p1]: computes p1 + (-p2).
P256Point p256Sub(P256Point p1, P256Point p2) => p256Add(p1, p256Negate(p2));

/// Converts a password byte array to a scalar for SPAKE2 blinding.
///
/// Computes `SHA-256(password) mod n` where n is the P-256 order.
BigInt passwordToScalar(Uint8List password) {
  final digest = crypto.sha256.convert(password);
  final hash = _readBigInt(Uint8List.fromList(digest.bytes), 0, 32);
  final scalar = hash % p256Order;
  // Ensure non-zero (extremely unlikely with SHA-256, but safe)
  if (scalar == BigInt.zero) return BigInt.one;
  return scalar;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

void _writeBigInt(Uint8List buffer, int offset, BigInt value) {
  var v = value;
  for (var i = 31; i >= 0; i--) {
    buffer[offset + i] = (v & BigInt.from(0xFF)).toInt();
    v >>= 8;
  }
}

BigInt _readBigInt(Uint8List bytes, int offset, int length) {
  var result = BigInt.zero;
  for (var i = 0; i < length; i++) {
    result = (result << 8) | BigInt.from(bytes[offset + i]);
  }
  return result;
}
