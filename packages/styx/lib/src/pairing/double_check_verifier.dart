import 'dart:typed_data';

import 'package:styx_crypto_core/styx_crypto_core.dart';

/// Generates and validates 6-digit Double Check verification codes.
///
/// Both peers derive the same code from the shared session key
/// and verify it out-of-band (voice call, in person, etc.).
class DoubleCheckVerifier {
  /// Creates a [DoubleCheckVerifier].
  DoubleCheckVerifier({required SessionVerifier sessionVerifier})
    : _sessionVerifier = sessionVerifier;

  final SessionVerifier _sessionVerifier;

  /// Generates a 6-digit verification code from [sessionKey].
  String generateCode(Uint8List sessionKey) =>
      _sessionVerifier.generateDoubleCheckCode(sessionKey);

  /// Formats the code for display with a space (e.g. "483 291").
  String formatForDisplay(String code) {
    final normalized = normalize(code);
    if (normalized.length != 6) return normalized;
    return '${normalized.substring(0, 3)} ${normalized.substring(3)}';
  }

  /// Validates that the input has a valid 6-digit format.
  bool isValidFormat(String input) {
    final normalized = normalize(input);
    if (normalized.length != 6) return false;
    return RegExp(r'^\d{6}$').hasMatch(normalized);
  }

  /// Normalizes user input by removing spaces and dashes.
  String normalize(String input) => input.replaceAll(RegExp(r'[\s\-]'), '');
}
