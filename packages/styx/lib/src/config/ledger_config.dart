import 'package:meta/meta.dart';
import 'package:styx_ledger_engine/styx_ledger_engine.dart';
import 'package:styx_push_bridge_client/styx_push_bridge_client.dart';
import 'package:styx_transport/styx_transport.dart';

/// Log level for Styx internal logging.
enum LogLevel {
  /// No logging.
  none,

  /// Only errors.
  error,

  /// Warnings and errors.
  warning,

  /// Informational messages.
  info,

  /// Debug messages.
  debug,
}

/// Configuration for the Styx library.
@immutable
class LedgerConfig {
  /// Creates a [LedgerConfig].
  const LedgerConfig({
    this.databasePath,
    this.relayUrls = const ['wss://relay.damus.io', 'wss://nos.lol'],
    this.emailConfig,
    this.pushBridgeUrl,
    this.privacyProfile = PrivacyProfile.balanced,
    this.retentionPeriod,
    this.retentionTypes = const [EventType.transaction],
    this.enableTor = false,
    this.torTimeout = const Duration(seconds: 120),
    this.logLevel = LogLevel.warning,
  });

  /// SQLCipher database path (null = default platform path).
  final String? databasePath;

  /// Nostr relay URLs.
  final List<String> relayUrls;

  /// Email transport configuration (optional).
  final EmailConfig? emailConfig;

  /// Push Bridge server URL (optional).
  final String? pushBridgeUrl;

  /// Privacy profile for push notifications.
  final PrivacyProfile privacyProfile;

  /// Retention period for automatic pruning (null = disabled).
  final Duration? retentionPeriod;

  /// Event types subject to retention policy.
  final List<EventType> retentionTypes;

  /// Whether to enable Tor routing.
  final bool enableTor;

  /// Tor bootstrap timeout.
  final Duration torTimeout;

  /// Internal log level.
  final LogLevel logLevel;
}
