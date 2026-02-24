import 'dart:math';
import 'dart:typed_data';

import 'package:styx_crypto_core/src/shamir/gf256.dart';
import 'package:styx_crypto_core/src/shamir/shamir_share.dart';

/// Splits a secret into shares using Shamir's Secret Sharing over GF(256).
class ShamirSplitter {
  final Random _random = Random.secure();

  /// Splits [secret] into [totalShares] shares, of which [threshold]
  /// are needed to reconstruct the original.
  ///
  /// Each byte of the secret is processed independently: a random
  /// polynomial of degree `threshold - 1` is generated with the
  /// secret byte as the constant coefficient, then evaluated at
  /// points x = 1, 2, ..., totalShares.
  ///
  /// Throws [ArgumentError] if parameters are invalid.
  List<ShamirShare> split({
    required Uint8List secret,
    int threshold = 2,
    int totalShares = 3,
  }) {
    if (secret.isEmpty) {
      throw ArgumentError('Secret must not be empty');
    }
    if (threshold < 1) {
      throw ArgumentError('Threshold must be at least 1');
    }
    if (totalShares < threshold) {
      throw ArgumentError(
        'Total shares ($totalShares) must be >= threshold ($threshold)',
      );
    }
    if (totalShares > 255) {
      throw ArgumentError('Total shares must be <= 255');
    }

    // Allocate share data buffers.
    final shareData = List.generate(
      totalShares,
      (_) => Uint8List(secret.length),
    );

    // Process each byte of the secret independently.
    for (var byteIndex = 0; byteIndex < secret.length; byteIndex++) {
      // Generate random polynomial coefficients.
      // coeffs[0] = secret byte, coeffs[1..threshold-1] = random
      final coeffs = Uint8List(threshold);
      coeffs[0] = secret[byteIndex];
      for (var c = 1; c < threshold; c++) {
        coeffs[c] = _random.nextInt(256);
      }

      // Evaluate polynomial at x = 1, 2, ..., totalShares
      for (var shareIndex = 0; shareIndex < totalShares; shareIndex++) {
        final x = shareIndex + 1; // x in [1..n]
        shareData[shareIndex][byteIndex] = _evaluatePolynomial(coeffs, x);
      }
    }

    return [
      for (var i = 0; i < totalShares; i++)
        ShamirShare(index: i + 1, data: shareData[i]),
    ];
  }

  /// Evaluates polynomial at [x] in GF(256) using Horner's method.
  int _evaluatePolynomial(Uint8List coeffs, int x) {
    // P(x) = c[0] + c[1]*x + c[2]*x^2 + ...
    // Horner's: P(x) = c[0] + x*(c[1] + x*(c[2] + ...))
    var result = 0;
    for (var i = coeffs.length - 1; i >= 0; i--) {
      result = gf256Add(gf256Mul(result, x), coeffs[i]);
    }
    return result;
  }
}
