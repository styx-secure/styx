import 'package:meta/meta.dart';

/// Configuration for email-based transport (IMAP + SMTP).
@immutable
class EmailConfig {
  /// Creates an [EmailConfig].
  const EmailConfig({
    required this.imapHost,
    required this.imapPort,
    required this.smtpHost,
    required this.smtpPort,
    required this.username,
    required this.password,
    required this.recipientAddress,
    this.useSsl = true,
    this.senderAddress,
  });

  /// IMAP server hostname.
  final String imapHost;

  /// IMAP server port (typically 993 for SSL).
  final int imapPort;

  /// SMTP server hostname.
  final String smtpHost;

  /// SMTP server port (typically 465 for SSL or 587 for STARTTLS).
  final int smtpPort;

  /// Login username.
  final String username;

  /// Login password or OAuth2 token.
  final String password;

  /// Whether to use SSL/TLS.
  final bool useSsl;

  /// Sender address (defaults to [username] if null).
  final String? senderAddress;

  /// Recipient email address.
  final String recipientAddress;

  /// Effective sender address.
  String get sender => senderAddress ?? username;
}
