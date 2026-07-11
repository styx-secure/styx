import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:styx_crypto_core/src/spake2/p256.dart';

/// The role in a SPAKE2 exchange.
enum Spake2Role {
  /// The initiator (uses M point).
  initiator,

  /// The responder (uses N point).
  responder,
}

/// The state of a SPAKE2 session.
enum Spake2State {
  /// Initial state — no message generated yet.
  init,

  /// Our message has been generated and sent.
  messageSent,

  /// The session is complete — session key is available.
  completed,

  /// The session has failed.
  failed,
}

/// A SPAKE2 session implementing RFC 9382 on P-256.
///
/// Usage:
/// 1. Create a session with a role and password.
/// 2. Call [generateMessage] to get the message to send to the peer.
/// 3. Call [processMessage] with the peer's message.
/// 4. Call [getSessionKey] to get the derived session key.
/// 5. Use [getConfirmation] / [verifyConfirmation] for mutual auth.
/// 6. Call [destroy] when done.
class Spake2Session {
  /// Creates a new SPAKE2 session.
  Spake2Session({
    required this.role,
    required Uint8List password,
  }) : _passwordScalar = passwordToScalar(password);

  /// The role of this session.
  final Spake2Role role;

  Spake2State _state = Spake2State.init;
  final BigInt _passwordScalar;

  // Our random scalar and generated message.
  BigInt? _randomScalar;
  P256Point? _ourMessage;
  Uint8List? _ourMessageBytes;

  // Peer's message.
  Uint8List? _peerMessageBytes;

  // Derived values.
  Uint8List? _sessionKey;
  Uint8List? _confirmationKey;

  /// The current state of this session.
  Spake2State get state => _state;

  /// Generates the message to send to the peer.
  ///
  /// For the initiator: `pA = x*G + pw*M`
  /// For the responder: `pB = y*G + pw*N`
  ///
  /// Throws [StateError] if not in [Spake2State.init].
  Uint8List generateMessage() {
    if (_state != Spake2State.init) {
      throw StateError(
        'Cannot generate message in state $_state',
      );
    }

    // Generate random scalar in [1, n-1].
    _randomScalar = _generateRandomScalar();

    // Compute x*G (or y*G)
    final xG = p256ScalarMul(p256G, _randomScalar!);

    // Compute pw*M (initiator) or pw*N (responder)
    final blindingPoint = role == Spake2Role.initiator ? spake2M : spake2N;
    final pwBlind = p256ScalarMul(blindingPoint, _passwordScalar);

    // T = xG + pwBlind
    _ourMessage = p256Add(xG, pwBlind);
    _ourMessageBytes = _ourMessage!.toUncompressedBytes();

    _state = Spake2State.messageSent;
    return Uint8List.fromList(_ourMessageBytes!);
  }

  /// Processes the message received from the peer.
  ///
  /// Returns `true` if processing succeeded.
  /// Returns `false` if the message is invalid.
  ///
  /// Throws [StateError] if not in [Spake2State.messageSent].
  bool processMessage(Uint8List peerMessage) {
    if (_state != Spake2State.messageSent) {
      throw StateError(
        'Cannot process message in state $_state',
      );
    }

    try {
      _peerMessageBytes = Uint8List.fromList(peerMessage);
      final peerPoint = P256Point.fromUncompressedBytes(peerMessage);

      if (peerPoint.isInfinity) {
        _state = Spake2State.failed;
        return false;
      }

      // Remove the password blinding from the peer's message.
      // If we are initiator, peer used N, so: K = x*(pB - pw*N)
      // If we are responder, peer used M, so: K = y*(pA - pw*M)
      final peerBlindingPoint = role == Spake2Role.initiator
          ? spake2N
          : spake2M;
      final pwBlind = p256ScalarMul(peerBlindingPoint, _passwordScalar);
      final unblinded = p256Sub(peerPoint, pwBlind);

      // K = randomScalar * unblinded = x*y*G (the shared secret point)
      final sharedPoint = p256ScalarMul(unblinded, _randomScalar!);

      if (sharedPoint.isInfinity) {
        _state = Spake2State.failed;
        return false;
      }

      // Derive session key from transcript:
      // transcript = len(A) || A || len(B) || B ||
      //              len(pA) || pA || len(pB) || pB ||
      //              len(K) || K
      //
      // Simplified: we hash the concatenation of both messages and K.
      final kBytes = sharedPoint.toUncompressedBytes();

      final Uint8List pABytes;
      final Uint8List pBBytes;
      if (role == Spake2Role.initiator) {
        pABytes = _ourMessageBytes!;
        pBBytes = _peerMessageBytes!;
      } else {
        pABytes = _peerMessageBytes!;
        pBBytes = _ourMessageBytes!;
      }

      // Hash the full transcript per RFC 9382:
      // TT = Hash(len(context) || context || len(idA) || idA ||
      //          len(idB) || idB || len(M) || M || len(N) || N ||
      //          len(pA) || pA || len(pB) || pB || len(K) || K)
      //
      // We use a simplified transcript for the 2-peer Styx system:
      // TT = SHA-256( pA || pB || K )
      final transcript = _buildTranscript(pABytes, pBBytes, kBytes);
      final hash = crypto.sha256.convert(transcript);
      final hashBytes = Uint8List.fromList(hash.bytes);

      // Split into session key (first 16 bytes) and confirmation key (last 16)
      _sessionKey = Uint8List.fromList(hashBytes.sublist(0, 32));

      // Derive separate confirmation keys using HMAC
      final confirmHash = crypto.sha256.convert(
        Uint8List.fromList([
          ...hashBytes,
          ...Uint8List.fromList('styx-spake2-confirm'.codeUnits),
        ]),
      );
      _confirmationKey = Uint8List.fromList(confirmHash.bytes);

      _state = Spake2State.completed;
      return true;
    } on Object {
      _state = Spake2State.failed;
      return false;
    }
  }

  /// Returns the derived 32-byte session key.
  ///
  /// Throws [StateError] if the session is not completed.
  Uint8List getSessionKey() {
    if (_state != Spake2State.completed) {
      throw StateError('Session key not available in state $_state');
    }
    return Uint8List.fromList(_sessionKey!);
  }

  /// Returns the confirmation value for mutual verification.
  ///
  /// Throws [StateError] if the session is not completed.
  Uint8List getConfirmation() {
    if (_state != Spake2State.completed) {
      throw StateError('Confirmation not available in state $_state');
    }
    // HMAC(confirmationKey, role || ourMessage || peerMessage)
    final roleByte = role == Spake2Role.initiator ? 0x01 : 0x02;
    final data = Uint8List.fromList([
      roleByte,
      ..._ourMessageBytes!,
      ..._peerMessageBytes!,
    ]);
    final hmac = crypto.Hmac(crypto.sha256, _confirmationKey!);
    final digest = hmac.convert(data);
    return Uint8List.fromList(digest.bytes);
  }

  /// Verifies the confirmation value received from the peer.
  ///
  /// Returns `true` if the peer's confirmation matches expected value.
  bool verifyConfirmation(Uint8List peerConfirmation) {
    if (_state != Spake2State.completed) {
      throw StateError('Cannot verify confirmation in state $_state');
    }

    // Compute what the peer should have sent:
    // HMAC(confirmationKey, peerRole || peerMessage || ourMessage)
    final peerRoleByte = role == Spake2Role.initiator ? 0x02 : 0x01;
    final data = Uint8List.fromList([
      peerRoleByte,
      ..._peerMessageBytes!,
      ..._ourMessageBytes!,
    ]);
    final hmac = crypto.Hmac(crypto.sha256, _confirmationKey!);
    final expected = hmac.convert(data);
    final expectedBytes = Uint8List.fromList(expected.bytes);

    // Constant-time comparison
    if (peerConfirmation.length != expectedBytes.length) return false;
    var diff = 0;
    for (var i = 0; i < expectedBytes.length; i++) {
      diff |= peerConfirmation[i] ^ expectedBytes[i];
    }
    return diff == 0;
  }

  /// Destroys all sensitive session data.
  void destroy() {
    _randomScalar = null;
    _ourMessage = null;
    if (_sessionKey != null) {
      _sessionKey!.fillRange(0, _sessionKey!.length, 0);
    }
    if (_confirmationKey != null) {
      _confirmationKey!.fillRange(0, _confirmationKey!.length, 0);
    }
    _sessionKey = null;
    _confirmationKey = null;
    _ourMessageBytes = null;
    _peerMessageBytes = null;
  }
}

/// Generates a random scalar in [1, n-1] for P-256.
BigInt _generateRandomScalar() {
  final random = Random.secure();
  final bytes = Uint8List(32);
  for (var i = 0; i < 32; i++) {
    bytes[i] = random.nextInt(256);
  }
  // Convert to BigInt and reduce mod (n-1), then add 1 to ensure [1, n-1].
  var scalar = BigInt.zero;
  for (var i = 0; i < 32; i++) {
    scalar = (scalar << 8) | BigInt.from(bytes[i]);
  }
  return (scalar % (p256Order - BigInt.one)) + BigInt.one;
}

/// Builds the transcript for session key derivation.
Uint8List _buildTranscript(
  Uint8List pABytes,
  Uint8List pBBytes,
  Uint8List kBytes,
) {
  return Uint8List.fromList([...pABytes, ...pBBytes, ...kBytes]);
}
