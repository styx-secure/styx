import 'dart:async';

import 'package:enough_mail/enough_mail.dart';
import 'package:styx_transport/src/email/email_config.dart';
import 'package:styx_transport/src/email/email_encoder.dart';
import 'package:styx_transport/src/email/imap_watcher.dart';
import 'package:styx_transport/src/transport_interface.dart';
import 'package:styx_transport/src/transport_message.dart';

/// Abstract SMTP client interface for testability.
abstract class SmtpSender {
  /// Connects to the SMTP server and authenticates.
  Future<void> connect();

  /// Sends a MIME message.
  Future<void> sendMessage(MimeMessage message);

  /// Disconnects from the SMTP server.
  Future<void> disconnect();

  /// Whether the SMTP client is connected.
  bool get isConnected;
}

/// Email-based transport implementing [TransportInterface].
///
/// Uses SMTP for sending and IMAP (via [ImapWatcher]) for receiving.
/// This is the fallback transport when Nostr relays are unavailable.
class EmailTransport implements TransportInterface {
  /// Creates an [EmailTransport].
  EmailTransport({
    required EmailConfig config,
    required EmailEncoder encoder,
    required ImapWatcher watcher,
    required SmtpSender smtpSender,
  })  : _config = config,
        _encoder = encoder,
        _watcher = watcher,
        _smtpSender = smtpSender;

  final EmailConfig _config;
  final EmailEncoder _encoder;
  final ImapWatcher _watcher;
  final SmtpSender _smtpSender;

  TransportState _state = TransportState.disconnected;
  final _stateController = StreamController<TransportState>.broadcast();
  final _messageController = StreamController<TransportMessage>.broadcast();
  StreamSubscription<MimeMessage>? _watcherSub;

  @override
  TransportState get currentState => _state;

  @override
  Stream<TransportState> get stateChanges => _stateController.stream;

  @override
  Stream<TransportMessage> get messages => _messageController.stream;

  @override
  bool get isAvailable => _state == TransportState.connected;

  @override
  Future<void> connect() async {
    _setState(TransportState.connecting);

    try {
      await _smtpSender.connect();
      await _watcher.connect();

      _watcherSub = _watcher.messages.listen(_handleIncomingEmail);

      _setState(TransportState.connected);
    } on Object {
      _setState(TransportState.disconnected);
    }
  }

  @override
  Future<void> disconnect() async {
    await _watcherSub?.cancel();
    _watcherSub = null;

    await _watcher.disconnect();
    await _smtpSender.disconnect();

    _setState(TransportState.disconnected);
  }

  @override
  Future<void> send(TransportMessage message) async {
    if (_state != TransportState.connected) {
      throw StateError('Cannot send: email transport is not connected');
    }

    final mimeMessage = _encoder.encode(
      message: message,
      senderEmail: _config.sender,
      recipientEmail: _config.recipientAddress,
    );

    await _smtpSender.sendMessage(mimeMessage);
  }

  /// Checks if the SMTP connection is available.
  Future<bool> checkAvailability() async {
    try {
      if (!_smtpSender.isConnected) return false;
      return true;
    } on Object {
      return false;
    }
  }

  /// Disposes the transport.
  Future<void> dispose() async {
    await disconnect();
    await _stateController.close();
    await _messageController.close();
  }

  void _handleIncomingEmail(MimeMessage email) {
    final message = _encoder.decode(email);
    if (message != null) {
      _messageController.add(message);
    }
  }

  void _setState(TransportState state) {
    _state = state;
    _stateController.add(state);
  }
}
