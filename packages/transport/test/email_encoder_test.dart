import 'dart:typed_data';

import 'package:enough_mail/enough_mail.dart';
import 'package:styx_transport/src/email/email_encoder.dart';
import 'package:styx_transport/src/transport_message.dart';
import 'package:test/test.dart';

TransportMessage _testMessage({
  String id = 'msg-1',
  String senderPubkey = 'aabbccdd11223344aabbccdd11223344'
      'aabbccdd11223344aabbccdd11223344',
  String recipientPubkey = '11223344aabbccdd11223344aabbccdd'
      '11223344aabbccdd11223344aabbccdd',
  Uint8List? payload,
}) {
  return TransportMessage(
    id: id,
    senderPubkey: senderPubkey,
    recipientPubkey: recipientPubkey,
    payload: payload ?? Uint8List.fromList([1, 2, 3, 4, 5]),
    timestamp: DateTime.utc(2026, 2, 24),
  );
}

void main() {
  final encoder = EmailEncoder();

  // T8.1 — Encode/decode round-trip
  test('T8.1: encode/decode round-trip', () {
    final message = _testMessage();

    final mime = encoder.encode(
      message: message,
      senderEmail: 'alice@test.com',
      recipientEmail: 'bob@test.com',
    );

    // Re-parse from rendered text to simulate network transit.
    final rendered = mime.renderMessage();
    final received = MimeMessage.parseFromText(rendered);

    final decoded = encoder.decode(received);

    expect(decoded, isNotNull);
    expect(decoded!.id, message.id);
    expect(decoded.senderPubkey, message.senderPubkey);
    expect(decoded.recipientPubkey, message.recipientPubkey);
    expect(decoded.payload, equals(message.payload));
  });

  // T8.2 — Subject pattern format
  test('T8.2: subject pattern is correct', () {
    final pattern = EmailEncoder.subjectPattern('a1b2c3d4');
    expect(pattern, '[STYX:v1:a1b2c3d4]');

    final message = _testMessage(
      recipientPubkey: 'a1b2c3d4eeff0011a1b2c3d4eeff0011'
          'a1b2c3d4eeff0011a1b2c3d4eeff0011',
    );

    final mime = encoder.encode(
      message: message,
      senderEmail: 'alice@test.com',
      recipientEmail: 'bob@test.com',
    );

    final subject = mime.decodeSubject();
    expect(subject, '[STYX:v1:a1b2c3d4]');
  });

  // T8.3 — Binary attachment present and correct type
  test('T8.3: binary attachment is present', () {
    final message = _testMessage();

    final mime = encoder.encode(
      message: message,
      senderEmail: 'alice@test.com',
      recipientEmail: 'bob@test.com',
    );

    expect(mime.hasAttachments(), isTrue);

    final rendered = mime.renderMessage();
    final parsed = MimeMessage.parseFromText(rendered);

    // Find the attachment part.
    final attachments = parsed.findContentInfo();
    expect(attachments, isNotEmpty);
  });

  // T8.4 — Non-Styx email returns null
  test('T8.4: non-Styx email returns null', () {
    final builder = MessageBuilder()
      ..from = [const MailAddress(null, 'someone@test.com')]
      ..to = [const MailAddress(null, 'me@test.com')]
      ..subject = 'Regular email subject'
      ..addTextPlain('Hello, this is a normal email.');

    final mime = builder.buildMimeMessage();
    final rendered = mime.renderMessage();
    final received = MimeMessage.parseFromText(rendered);

    final decoded = encoder.decode(received);
    expect(decoded, isNull);
  });

  // T8.5 — Corrupted attachment returns null
  test('T8.5: corrupted attachment returns null', () {
    // Build an email with a Styx subject but garbage attachment.
    final builder = MessageBuilder()
      ..from = [const MailAddress(null, 'alice@test.com')]
      ..to = [const MailAddress(null, 'bob@test.com')]
      ..subject = '[STYX:v1:a1b2c3d4]'
      ..addTextPlain('corrupted')
      ..addBinary(
        Uint8List.fromList([0xFF, 0xFE, 0xFD, 0x00, 0x01]),
        MediaType.fromSubtype(MediaSubtype.applicationOctetStream),
        filename: 'styx_msg_bad.bin',
      );

    final mime = builder.buildMimeMessage();
    final rendered = mime.renderMessage();
    final received = MimeMessage.parseFromText(rendered);

    final decoded = encoder.decode(received);
    expect(decoded, isNull);
  });

  // T8.6 — Large payload (500 KB)
  test('T8.6: large payload round-trip (500 KB)', () {
    final largePayload = Uint8List(500 * 1024);
    for (var i = 0; i < largePayload.length; i++) {
      largePayload[i] = i & 0xFF;
    }

    final message = _testMessage(payload: largePayload);

    final mime = encoder.encode(
      message: message,
      senderEmail: 'alice@test.com',
      recipientEmail: 'bob@test.com',
    );

    final rendered = mime.renderMessage();
    final received = MimeMessage.parseFromText(rendered);

    final decoded = encoder.decode(received);

    expect(decoded, isNotNull);
    expect(decoded!.payload.length, largePayload.length);
    expect(decoded.payload, equals(largePayload));
  });
}
