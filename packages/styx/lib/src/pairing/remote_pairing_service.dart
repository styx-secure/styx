import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:styx/src/pairing/double_check_verifier.dart';
import 'package:styx/src/trust/trust_store_manager.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';

/// State of the remote pairing process.
enum RemotePairingState {
  /// Not started.
  idle,

  /// Mnemonic generated, waiting to start.
  mnemonicGenerated,

  /// Waiting for peer to respond.
  waitingForPeer,

  /// SPAKE2 exchange in progress.
  spake2InProgress,

  /// Double Check code available for verification.
  doubleCheckPending,

  /// Pairing completed successfully.
  completed,

  /// Pairing failed.
  failed,
}

/// Service for remote pairing via SPAKE2 + mnemonic + Double Check.
///
/// Protocol flow:
/// 1. Initiator generates mnemonic, communicates out-of-band
/// 2. Both create SPAKE2 sessions from mnemonic password
/// 3. Exchange SPAKE2 messages via transport (tagged with shared tag)
/// 4. Derive session key → 6-digit Double Check code
/// 5. Users verify code out-of-band
/// 6. Exchange Ed25519 public keys encrypted with session key
/// 7. Store peers in trust store
class RemotePairingService {
  /// Creates a [RemotePairingService].
  RemotePairingService({
    required Spake2Protocol spake2Protocol,
    required MnemonicGenerator mnemonicGenerator,
    required DoubleCheckVerifier doubleCheckVerifier,
    required TrustStoreManager trustStore,
    this.timeout = const Duration(minutes: 5),
  }) : _spake2Protocol = spake2Protocol,
       _mnemonicGenerator = mnemonicGenerator,
       _doubleCheckVerifier = doubleCheckVerifier,
       _trustStore = trustStore;

  final Spake2Protocol _spake2Protocol;
  final MnemonicGenerator _mnemonicGenerator;
  final DoubleCheckVerifier _doubleCheckVerifier;
  final TrustStoreManager _trustStore;

  /// Timeout for pairing.
  final Duration timeout;

  RemotePairingState _state = RemotePairingState.idle;
  final _stateController = StreamController<RemotePairingState>.broadcast();

  Uint8List? _sessionKey;

  /// The peer's public key, set when received via encrypted channel.
  StyxPublicKey? peerPublicKey;

  /// Current pairing state.
  RemotePairingState get state => _state;

  /// Stream of state changes.
  Stream<RemotePairingState> get stateStream => _stateController.stream;

  /// Generates a mnemonic for out-of-band communication.
  String generateMnemonic({int wordCount = 6}) {
    final mnemonic = _mnemonicGenerator.generate(wordCount: wordCount);
    _setState(RemotePairingState.mnemonicGenerated);
    return mnemonic;
  }

  /// Starts pairing as the initiator.
  ///
  /// Creates a SPAKE2 session and returns the outgoing message.
  Future<Uint8List> startAsInitiator({
    required String mnemonic,
    required StyxPublicKey localPublicKey,
  }) async {
    _setState(RemotePairingState.waitingForPeer);

    final password = _spake2Protocol.mnemonicToPassword(mnemonic);
    final session = _spake2Protocol.createInitiatorSession(password);

    final outMessage = session.generateMessage();
    _setState(RemotePairingState.spake2InProgress);

    // Return the SPAKE2 message to be sent to the responder.
    // The caller is responsible for transport.
    _sessionData = _SessionData(session: session, localPubkey: localPublicKey);
    return outMessage;
  }

  /// Starts pairing as the responder.
  ///
  /// Creates a SPAKE2 session and generates the response message.
  Future<Uint8List> startAsResponder({
    required String mnemonic,
    required StyxPublicKey localPublicKey,
  }) async {
    _setState(RemotePairingState.spake2InProgress);

    final password = _spake2Protocol.mnemonicToPassword(mnemonic);
    final session = _spake2Protocol.createResponderSession(password);

    final outMessage = session.generateMessage();

    _sessionData = _SessionData(session: session, localPubkey: localPublicKey);
    return outMessage;
  }

  /// Processes the peer's SPAKE2 message.
  ///
  /// After processing, the session key and Double Check code become
  /// available.
  bool processPeerMessage(Uint8List peerMessage) {
    if (_sessionData == null) return false;

    final success = _sessionData!.session.processMessage(peerMessage);
    if (!success) {
      _setState(RemotePairingState.failed);
      return false;
    }

    _sessionKey = _sessionData!.session.getSessionKey();
    _setState(RemotePairingState.doubleCheckPending);
    return true;
  }

  /// Returns the 6-digit Double Check code.
  ///
  /// Only available after SPAKE2 completes (state = doubleCheckPending).
  String getDoubleCheckCode() {
    if (_sessionKey == null) {
      throw StateError('Session key not yet available');
    }
    return _doubleCheckVerifier.generateCode(_sessionKey!);
  }

  /// Confirms or rejects the Double Check verification.
  ///
  /// If [codeMatches] is true, saves the peer and completes pairing.
  /// If false, the pairing fails.
  Future<void> confirmDoubleCheck({
    required bool codeMatches,
    required String? peerAlias,
  }) async {
    if (!codeMatches) {
      _setState(RemotePairingState.failed);
      return;
    }

    if (peerPublicKey != null) {
      await _trustStore.addTrustedPeer(
        peerPublicKey: peerPublicKey!,
        alias: peerAlias,
      );
    }

    _setState(RemotePairingState.completed);
  }

  /// Cancels the pairing process.
  Future<void> cancel() async {
    _cleanup();
    _setState(RemotePairingState.idle);
  }

  /// Releases resources.
  Future<void> dispose() async {
    _cleanup();
    await _stateController.close();
  }

  /// Derives a shared tag from a mnemonic for relay-based discovery.
  ///
  /// `SHA-256(mnemonic)[0:8]` hex-encoded.
  static String deriveSharedTag(String mnemonic) {
    final hash = crypto.sha256.convert(utf8.encode(mnemonic));
    return hash.bytes
        .sublist(0, 8)
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
  }

  _SessionData? _sessionData;

  void _setState(RemotePairingState newState) {
    _state = newState;
    _stateController.add(newState);
  }

  void _cleanup() {
    _sessionData?.session.destroy();
    _sessionData = null;
    _sessionKey = null;
    peerPublicKey = null;
  }
}

class _SessionData {
  _SessionData({required this.session, required this.localPubkey});
  final Spake2Session session;
  final StyxPublicKey localPubkey;
}
