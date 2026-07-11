import 'dart:async';
import 'dart:typed_data';

import 'package:enough_mail/enough_mail.dart';
import 'package:styx_transport/src/email/email_config.dart';
import 'package:styx_transport/src/email/email_encoder.dart';
import 'package:styx_transport/src/email/email_transport.dart';
import 'package:styx_transport/src/email/imap_watcher.dart';
import 'package:styx_transport/src/transport_interface.dart';
import 'package:styx_transport/src/transport_message.dart';
import 'package:test/test.dart';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

class FakeSmtpSender implements SmtpSender {
  FakeSmtpSender({this.failOnConnect = false, this.failOnSend = false});

  final bool failOnConnect;
  final bool failOnSend;
  final sent = <MimeMessage>[];
  bool _connected = false;

  @override
  Future<void> connect() async {
    if (failOnConnect) throw Exception('SMTP connection failed');
    _connected = true;
  }

  @override
  Future<void> sendMessage(MimeMessage message) async {
    if (failOnSend) throw Exception('SMTP send failed');
    sent.add(message);
  }

  @override
  Future<void> disconnect() async {
    _connected = false;
  }

  @override
  bool get isConnected => _connected;
}

class FakeImapClientAdapter implements ImapClientAdapter {
  FakeImapClientAdapter({this.failOnConnect = false});

  final bool failOnConnect;
  bool _connected = false;
  bool _polling = false;
  Duration? pollingDuration;

  final _newMessageController = StreamController<MimeMessage>.broadcast();
  final _connLostController = StreamController<void>.broadcast();
  final _connRestoredController = StreamController<void>.broadcast();

  final List<int> markedAsRead = [];
  List<MimeMessage> unreadMessages = [];

  @override
  Future<void> connect() async {
    if (failOnConnect) throw Exception('IMAP connection failed');
    _connected = true;
  }

  @override
  Future<void> disconnect() async {
    _connected = false;
  }

  @override
  bool get isConnected => _connected;

  @override
  Future<void> startPolling(Duration duration) async {
    pollingDuration = duration;
    _polling = true;
  }

  @override
  Future<void> stopPolling() async {
    _polling = false;
  }

  @override
  bool get isPolling => _polling;

  @override
  Stream<MimeMessage> get onNewMessage => _newMessageController.stream;

  @override
  Stream<void> get onConnectionLost => _connLostController.stream;

  @override
  Stream<void> get onConnectionReEstablished => _connRestoredController.stream;

  @override
  Future<List<MimeMessage>> fetchUnread(String searchQuery) async =>
      unreadMessages;

  @override
  Future<void> markAsRead(int uid) async {
    markedAsRead.add(uid);
  }

  /// Simulate a new message arriving.
  void simulateNewMessage(MimeMessage message) {
    _newMessageController.add(message);
  }

  /// Simulate connection loss.
  void simulateConnectionLost() {
    _connLostController.add(null);
  }

  /// Simulate connection restored.
  void simulateConnectionRestored() {
    _connRestoredController.add(null);
  }

  Future<void> dispose() async {
    await _newMessageController.close();
    await _connLostController.close();
    await _connRestoredController.close();
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const _senderPubkey =
    'aabbccdd11223344aabbccdd11223344'
    'aabbccdd11223344aabbccdd11223344';
const _recipientPubkey =
    '11223344aabbccdd11223344aabbccdd'
    '11223344aabbccdd11223344aabbccdd';

EmailConfig _testConfig() => const EmailConfig(
  imapHost: 'imap.test.com',
  imapPort: 993,
  smtpHost: 'smtp.test.com',
  smtpPort: 465,
  username: 'alice@test.com',
  password: 'secret',
  recipientAddress: 'bob@test.com',
);

TransportMessage _testMessage({String id = 'msg-1'}) => TransportMessage(
  id: id,
  senderPubkey: _senderPubkey,
  recipientPubkey: _recipientPubkey,
  payload: Uint8List.fromList('hello email'.codeUnits),
  timestamp: DateTime.utc(2026, 2, 24),
);

/// Creates a fake Styx MimeMessage for receive tests.
MimeMessage _buildStyxMime(TransportMessage message) {
  final encoder = EmailEncoder();
  final mime = encoder.encode(
    message: message,
    senderEmail: 'alice@test.com',
    recipientEmail: 'bob@test.com',
  );
  // Re-parse to simulate network transit.
  return MimeMessage.parseFromText(mime.renderMessage());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

void main() {
  // T8.7 — Send with SMTP mock
  test('T8.7: send via SMTP mock succeeds', () async {
    final smtp = FakeSmtpSender();
    final imapClient = FakeImapClientAdapter();
    final config = _testConfig();
    final encoder = EmailEncoder();
    final filter = EmailEncoder.subjectPattern(
      _recipientPubkey.substring(0, 8),
    );
    final watcher = ImapWatcher(
      client: imapClient,
      subjectFilter: filter,
    );

    final transport = EmailTransport(
      config: config,
      encoder: encoder,
      watcher: watcher,
      smtpSender: smtp,
    );

    await transport.connect();
    expect(transport.isAvailable, isTrue);

    await transport.send(_testMessage());

    expect(smtp.sent, hasLength(1));
    final subject = smtp.sent.first.decodeSubject();
    expect(subject, contains('STYX:v1'));

    await transport.dispose();
    await imapClient.dispose();
  });

  // T8.8 — Send with SMTP down
  test('T8.8: send with SMTP down throws', () async {
    final smtp = FakeSmtpSender(failOnSend: true);
    final imapClient = FakeImapClientAdapter();
    final config = _testConfig();
    final encoder = EmailEncoder();
    final filter = EmailEncoder.subjectPattern('11223344');
    final watcher = ImapWatcher(
      client: imapClient,
      subjectFilter: filter,
    );

    final transport = EmailTransport(
      config: config,
      encoder: encoder,
      watcher: watcher,
      smtpSender: smtp,
    );

    await transport.connect();

    expect(
      () => transport.send(_testMessage()),
      throwsA(isA<Exception>()),
    );

    await transport.dispose();
    await imapClient.dispose();
  });

  // T8.9 — Receive via IMAP mock
  test('T8.9: receive via IMAP mock emits TransportMessage', () async {
    final smtp = FakeSmtpSender();
    final imapClient = FakeImapClientAdapter();
    final config = _testConfig();
    final encoder = EmailEncoder();
    final filter = EmailEncoder.subjectPattern('11223344');
    final watcher = ImapWatcher(
      client: imapClient,
      subjectFilter: filter,
    );

    final transport = EmailTransport(
      config: config,
      encoder: encoder,
      watcher: watcher,
      smtpSender: smtp,
    );

    await transport.connect();

    final received = <TransportMessage>[];
    final sub = transport.messages.listen(received.add);

    final message = _testMessage();
    final styxMime = _buildStyxMime(message);
    imapClient.simulateNewMessage(styxMime);

    await Future<void>.delayed(const Duration(milliseconds: 50));

    expect(received, hasLength(1));
    expect(received.first.id, message.id);
    expect(received.first.payload, equals(message.payload));

    await sub.cancel();
    await transport.dispose();
    await imapClient.dispose();
  });

  // T8.10 — Filter non-Styx emails
  test('T8.10: non-Styx email is filtered out', () async {
    final smtp = FakeSmtpSender();
    final imapClient = FakeImapClientAdapter();
    final config = _testConfig();
    final encoder = EmailEncoder();
    final filter = EmailEncoder.subjectPattern('11223344');
    final watcher = ImapWatcher(
      client: imapClient,
      subjectFilter: filter,
    );

    final transport = EmailTransport(
      config: config,
      encoder: encoder,
      watcher: watcher,
      smtpSender: smtp,
    );

    await transport.connect();

    final received = <TransportMessage>[];
    final sub = transport.messages.listen(received.add);

    // Send a normal email (not Styx).
    final normalMime = MessageBuilder()
      ..from = [const MailAddress(null, 'someone@test.com')]
      ..to = [const MailAddress(null, 'alice@test.com')]
      ..subject = 'Hello friend!'
      ..addTextPlain('Not a Styx message.');
    imapClient.simulateNewMessage(
      normalMime.buildMimeMessage(),
    );

    await Future<void>.delayed(const Duration(milliseconds: 50));

    expect(received, isEmpty);

    await sub.cancel();
    await transport.dispose();
    await imapClient.dispose();
  });

  // T8.11 — Credentials error
  test('T8.11: bad credentials result in disconnected state', () async {
    final smtp = FakeSmtpSender(failOnConnect: true);
    final imapClient = FakeImapClientAdapter();
    final config = _testConfig();
    final encoder = EmailEncoder();
    final filter = EmailEncoder.subjectPattern('11223344');
    final watcher = ImapWatcher(
      client: imapClient,
      subjectFilter: filter,
    );

    final transport = EmailTransport(
      config: config,
      encoder: encoder,
      watcher: watcher,
      smtpSender: smtp,
    );

    await transport.connect();

    expect(transport.currentState, TransportState.disconnected);
    expect(transport.isAvailable, isFalse);

    await transport.dispose();
    await imapClient.dispose();
  });

  // T8.12 — IsAvailable true
  test('T8.12: isAvailable true when connected', () async {
    final smtp = FakeSmtpSender();
    final imapClient = FakeImapClientAdapter();
    final config = _testConfig();
    final encoder = EmailEncoder();
    final filter = EmailEncoder.subjectPattern('11223344');
    final watcher = ImapWatcher(
      client: imapClient,
      subjectFilter: filter,
    );

    final transport = EmailTransport(
      config: config,
      encoder: encoder,
      watcher: watcher,
      smtpSender: smtp,
    );

    await transport.connect();
    expect(transport.isAvailable, isTrue);

    final available = await transport.checkAvailability();
    expect(available, isTrue);

    await transport.dispose();
    await imapClient.dispose();
  });

  // T8.13 — IsAvailable false
  test('T8.13: isAvailable false when disconnected', () async {
    final smtp = FakeSmtpSender();
    final imapClient = FakeImapClientAdapter();
    final config = _testConfig();
    final encoder = EmailEncoder();
    final filter = EmailEncoder.subjectPattern('11223344');
    final watcher = ImapWatcher(
      client: imapClient,
      subjectFilter: filter,
    );

    final transport = EmailTransport(
      config: config,
      encoder: encoder,
      watcher: watcher,
      smtpSender: smtp,
    );

    expect(transport.isAvailable, isFalse);

    final available = await transport.checkAvailability();
    expect(available, isFalse);

    await transport.dispose();
    await imapClient.dispose();
  });

  // T8.14 — IDLE reconnect
  test('T8.14: IMAP reconnect after connection loss', () async {
    final imapClient = FakeImapClientAdapter();
    final filter = EmailEncoder.subjectPattern('11223344');
    final watcher = ImapWatcher(
      client: imapClient,
      subjectFilter: filter,
    );

    await watcher.connect();
    expect(watcher.isConnected, isTrue);

    // Simulate connection loss.
    imapClient.simulateConnectionLost();
    await Future<void>.delayed(Duration.zero);
    expect(watcher.isConnected, isFalse);

    // Simulate connection restored.
    imapClient.simulateConnectionRestored();
    await Future<void>.delayed(Duration.zero);
    expect(watcher.isConnected, isTrue);

    await watcher.dispose();
    await imapClient.dispose();
  });

  // T8.15 — Polling fallback
  test('T8.15: polling fallback works', () async {
    final imapClient = FakeImapClientAdapter();
    final filter = EmailEncoder.subjectPattern('11223344');
    final watcher = ImapWatcher(
      client: imapClient,
      subjectFilter: filter,
      pollingInterval: const Duration(seconds: 30),
    );

    await watcher.connect();

    expect(imapClient.isPolling, isTrue);
    expect(
      imapClient.pollingDuration,
      const Duration(seconds: 30),
    );

    // Simulate receiving a message via polling.
    final received = <MimeMessage>[];
    final sub = watcher.messages.listen(received.add);

    final message = _testMessage();
    final styxMime = _buildStyxMime(message);
    imapClient.simulateNewMessage(styxMime);

    await Future<void>.delayed(const Duration(milliseconds: 50));

    expect(received, hasLength(1));

    await sub.cancel();
    await watcher.dispose();
    await imapClient.dispose();
  });
}
