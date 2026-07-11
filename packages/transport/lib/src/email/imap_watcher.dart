import 'dart:async';

import 'package:enough_mail/enough_mail.dart';

/// Abstract IMAP client interface for testability.
abstract class ImapClientAdapter {
  /// Connects to the IMAP server.
  Future<void> connect();

  /// Disconnects from the IMAP server.
  Future<void> disconnect();

  /// Whether the client is connected.
  bool get isConnected;

  /// Starts polling/IDLE for new messages.
  Future<void> startPolling(Duration duration);

  /// Stops polling/IDLE.
  Future<void> stopPolling();

  /// Whether polling is active.
  bool get isPolling;

  /// Stream of newly loaded messages.
  Stream<MimeMessage> get onNewMessage;

  /// Stream of connection lost events.
  Stream<void> get onConnectionLost;

  /// Stream of connection re-established events.
  Stream<void> get onConnectionReEstablished;

  /// Fetches recent unread messages matching [searchQuery].
  Future<List<MimeMessage>> fetchUnread(String searchQuery);

  /// Marks a message as read by its UID.
  Future<void> markAsRead(int uid);
}

/// Monitors an inbox for incoming Styx messages via IMAP IDLE or polling.
class ImapWatcher {
  /// Creates an [ImapWatcher].
  ImapWatcher({
    required ImapClientAdapter client,
    required String subjectFilter,
    Duration pollingInterval = const Duration(seconds: 60),
  }) : _client = client,
       _subjectFilter = subjectFilter,
       _pollingInterval = pollingInterval;

  final ImapClientAdapter _client;
  final String _subjectFilter;
  final Duration _pollingInterval;

  final _messageController = StreamController<MimeMessage>.broadcast();
  StreamSubscription<MimeMessage>? _newMailSub;
  StreamSubscription<void>? _connLostSub;
  StreamSubscription<void>? _connRestoredSub;
  bool _connected = false;

  /// Stream of incoming Styx messages.
  Stream<MimeMessage> get messages => _messageController.stream;

  /// Whether the watcher is connected.
  bool get isConnected => _connected;

  /// Connects to the IMAP server and starts monitoring.
  Future<void> connect() async {
    await _client.connect();
    _connected = true;

    _newMailSub = _client.onNewMessage.listen(_handleNewMessage);

    _connLostSub = _client.onConnectionLost.listen((_) {
      _connected = false;
    });

    _connRestoredSub = _client.onConnectionReEstablished.listen((_) {
      _connected = true;
    });

    await _client.startPolling(_pollingInterval);
  }

  /// Disconnects from the IMAP server.
  Future<void> disconnect() async {
    await _newMailSub?.cancel();
    _newMailSub = null;
    await _connLostSub?.cancel();
    _connLostSub = null;
    await _connRestoredSub?.cancel();
    _connRestoredSub = null;

    if (_client.isPolling) {
      await _client.stopPolling();
    }
    await _client.disconnect();
    _connected = false;
  }

  /// Fetches unread Styx messages from the inbox.
  Future<List<MimeMessage>> fetchUnreadStyxMessages() async {
    return _client.fetchUnread(_subjectFilter);
  }

  /// Marks a message as read.
  Future<void> markAsRead(MimeMessage message) async {
    final uid = message.uid;
    if (uid != null) {
      await _client.markAsRead(uid);
    }
  }

  /// Disposes the watcher.
  Future<void> dispose() async {
    await disconnect();
    await _messageController.close();
  }

  void _handleNewMessage(MimeMessage message) {
    final subject = message.decodeSubject();
    if (subject != null && subject.contains(_subjectFilter)) {
      _messageController.add(message);
    }
  }
}
