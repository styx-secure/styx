import 'dart:typed_data';

import 'package:styx_crypto_core/src/shamir/gf256.dart';
import 'package:styx_crypto_core/src/shamir/shamir_share.dart';

/// Exception thrown when there are insufficient shares to reconstruct.
class InsufficientSharesException implements Exception {
  /// Creates an [InsufficientSharesException].
  const InsufficientSharesException(this.message);

  /// Description of the error.
  final String message;

  @override
  String toString() => 'InsufficientSharesException: $message';
}

/// Exception thrown when a share is invalid or corrupted.
class InvalidShareException implements Exception {
  /// Creates an [InvalidShareException].
  const InvalidShareException(this.message);

  /// Description of the error.
  final String message;

  @override
  String toString() => 'InvalidShareException: $message';
}

/// Reconstructs a secret from Shamir shares using Lagrange interpolation
/// over GF(256).
class ShamirReconstructor {
  /// Reconstructs the secret from [shares].
  ///
  /// Throws [InsufficientSharesException] if too few shares are provided.
  /// Throws [InvalidShareException] if shares are malformed.
  Uint8List reconstruct(List<ShamirShare> shares) {
    if (shares.isEmpty) {
      throw const InsufficientSharesException(
        'At least one share is required',
      );
    }

    // Validate all shares have the same data length.
    final dataLen = shares[0].data.length;
    for (final share in shares) {
      if (share.data.length != dataLen) {
        throw const InvalidShareException(
          'All shares must have the same data length',
        );
      }
    }

    // Validate no duplicate indices.
    final indices = shares.map((s) => s.index).toSet();
    if (indices.length != shares.length) {
      throw const InvalidShareException('Duplicate share indices');
    }

    // Reconstruct each byte using Lagrange interpolation at x = 0.
    final result = Uint8List(dataLen);
    final xs = shares.map((s) => s.index).toList();

    for (var byteIndex = 0; byteIndex < dataLen; byteIndex++) {
      final ys = shares.map((s) => s.data[byteIndex]).toList();
      result[byteIndex] = _lagrangeInterpolateAtZero(xs, ys);
    }

    return result;
  }

  /// Lagrange interpolation at x = 0 in GF(256).
  ///
  /// Given points (xs\[i\], ys\[i\]), computes f(0).
  int _lagrangeInterpolateAtZero(List<int> xs, List<int> ys) {
    var result = 0;
    final k = xs.length;

    for (var i = 0; i < k; i++) {
      // Compute Lagrange basis polynomial L_i(0)
      var numerator = 1;
      var denominator = 1;

      for (var j = 0; j < k; j++) {
        if (i == j) continue;
        // L_i(0) = ∏_{j≠i} (0 - x_j) / (x_i - x_j)
        //        = ∏_{j≠i} x_j / (x_i ⊕ x_j)
        // In GF(256): subtraction = addition = XOR, and 0 - x_j = x_j
        numerator = gf256Mul(numerator, xs[j]);
        denominator = gf256Mul(denominator, gf256Add(xs[i], xs[j]));
      }

      // L_i(0) = numerator / denominator
      final basis = gf256Div(numerator, denominator);
      // f(0) += y_i * L_i(0)
      result = gf256Add(result, gf256Mul(ys[i], basis));
    }

    return result;
  }
}
