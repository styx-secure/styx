import 'dart:convert';
import 'dart:typed_data';

import 'package:styx_crypto_core/src/spake2/spake2_session.dart';

/// Orchestrates SPAKE2 protocol sessions.
class Spake2Protocol {
  /// Creates a SPAKE2 session as initiator.
  ///
  /// [password] — the mnemonic code converted to bytes.
  Spake2Session createInitiatorSession(Uint8List password) =>
      Spake2Session(role: Spake2Role.initiator, password: password);

  /// Creates a SPAKE2 session as responder.
  ///
  /// [password] — the mnemonic code converted to bytes.
  Spake2Session createResponderSession(Uint8List password) =>
      Spake2Session(role: Spake2Role.responder, password: password);

  /// Converts a BIP-39 mnemonic to bytes for SPAKE2.
  ///
  /// Uses UTF-8 encoding of the normalized (trimmed, lowered) mnemonic.
  Uint8List mnemonicToPassword(String mnemonic) =>
      Uint8List.fromList(utf8.encode(mnemonic.trim().toLowerCase()));
}
