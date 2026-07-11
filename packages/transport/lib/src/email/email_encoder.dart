import 'dart:convert';
import 'dart:typed_data';

import 'package:enough_mail/enough_mail.dart';
import 'package:styx_transport/src/transport_message.dart';

/// Encodes [TransportMessage] as MIME email with binary attachment
/// and decodes received emails back.
class EmailEncoder {
  /// Subject pattern prefix for Styx messages.
  static const _subjectPrefix = '[STYX:v1:';

  /// Returns the subject pattern for filtering Styx emails.
  ///
  /// Format: `[STYX:v1:a1b2c3d4]` where the 8 chars are from [pubkeyShort].
  static String subjectPattern(String pubkeyShort) =>
      '$_subjectPrefix$pubkeyShort]';

  /// Encodes a [TransportMessage] as a MIME email with binary attachment.
  MimeMessage encode({
    required TransportMessage message,
    required String senderEmail,
    required String recipientEmail,
  }) {
    final recipientShort = message.recipientPubkey.length >= 8
        ? message.recipientPubkey.substring(0, 8)
        : message.recipientPubkey;

    final subject = subjectPattern(recipientShort);
    final jsonBytes = Uint8List.fromList(
      utf8.encode(jsonEncode(message.toJson())),
    );
    final filename = 'styx_msg_${message.id}.bin';

    final builder = MessageBuilder()
      ..from = [MailAddress(null, senderEmail)]
      ..to = [MailAddress(null, recipientEmail)]
      ..subject = subject
      ..addTextPlain('Styx encrypted message')
      ..addBinary(
        jsonBytes,
        MediaType.fromSubtype(MediaSubtype.applicationOctetStream),
        filename: filename,
      );

    return builder.buildMimeMessage();
  }

  /// Decodes a received [MimeMessage] into a [TransportMessage].
  ///
  /// Returns `null` if the email is not a valid Styx message.
  TransportMessage? decode(MimeMessage email) {
    final subject = email.decodeSubject();
    if (subject == null || !_isStyxSubject(subject)) {
      return null;
    }

    try {
      final attachmentData = _extractAttachment(email);
      if (attachmentData == null) return null;

      final jsonStr = utf8.decode(attachmentData);
      final json = jsonDecode(jsonStr) as Map<String, dynamic>;
      return TransportMessage.fromJson(json);
    } on Object {
      return null;
    }
  }

  /// Checks if a subject matches the Styx pattern.
  static bool _isStyxSubject(String subject) =>
      subject.startsWith(_subjectPrefix) && subject.endsWith(']');

  /// Extracts the first binary attachment from a MIME message.
  static Uint8List? _extractAttachment(MimeMessage message) {
    // Search all parts for an attachment.
    final parts = message.findContentInfo();

    for (final info in parts) {
      final part = message.getPart(info.fetchId);
      if (part != null) {
        final binary = part.decodeContentBinary();
        if (binary != null) return Uint8List.fromList(binary);
      }
    }

    // Fallback: search multipart structure directly.
    if (message.parts != null) {
      for (final part in message.parts!) {
        final disposition = part.getHeaderContentDisposition();
        if (disposition?.disposition == ContentDisposition.attachment) {
          final binary = part.decodeContentBinary();
          if (binary != null) return Uint8List.fromList(binary);
        }

        // Check nested text content as fallback (for simple messages).
        final contentType = part.getHeaderContentType();
        if (contentType?.mediaType.sub == MediaSubtype.applicationOctetStream) {
          final binary = part.decodeContentBinary();
          if (binary != null) return Uint8List.fromList(binary);
        }
      }
    }

    return null;
  }
}
