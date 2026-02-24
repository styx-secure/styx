import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

/// Generates a 6-digit Double Check verification code from a session key.
class SessionVerifier {
  static final Uint8List _suffix =
      Uint8List.fromList(utf8.encode('styx-double-check-v1'));

  /// Generates a 6-digit verification code from [sessionKey].
  ///
  /// Both peers derive the same code and verify it out-of-band.
  /// The code is `SHA-256(sessionKey || "styx-double-check-v1")` truncated
  /// to the first 3 bytes, converted to a number modulo 1,000,000, and
  /// zero-padded to 6 digits.
  String generateDoubleCheckCode(Uint8List sessionKey) {
    final totalLength = sessionKey.length + _suffix.length;
    final combined = Uint8List(totalLength)
      ..setRange(0, sessionKey.length, sessionKey)
      ..setRange(sessionKey.length, totalLength, _suffix);

    final digest = crypto.sha256.convert(combined);

    // Take first 3 bytes → 24-bit number → mod 1,000,000
    final code =
        (digest.bytes[0] << 16 | digest.bytes[1] << 8 | digest.bytes[2]) %
            1000000;

    return code.toString().padLeft(6, '0');
  }
}
