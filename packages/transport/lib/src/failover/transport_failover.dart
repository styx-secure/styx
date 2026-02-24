import 'dart:async';
import 'dart:math';

import 'package:meta/meta.dart';
import 'package:styx_transport/src/transport_interface.dart';
import 'package:styx_transport/src/transport_message.dart';

/// A transport with its retry/timeout policy.
@immutable
class TransportPriority {
  /// Creates a [TransportPriority].
  const TransportPriority({
    required this.transport,
    required this.maxRetries,
    required this.timeout,
  });

  /// The transport implementation.
  final TransportInterface transport;

  /// Maximum retry attempts before falling through.
  final int maxRetries;

  /// Timeout per send attempt.
  final Duration timeout;
}

/// Multi-transport failover engine.
///
/// Tries transports in priority order with retry + exponential backoff.
/// Default hierarchy: Nostr (3 retries, 5s) → Email (2 retries, 30s).
class TransportFailover implements TransportInterface {
  /// Creates a [TransportFailover].
  TransportFailover({required List<TransportPriority> transports})
      : _transports = List.unmodifiable(transports);

  final List<TransportPriority> _transports;

  TransportState _state = TransportState.disconnected;
  final _stateController = StreamController<TransportState>.broadcast();
  final _messageController = StreamController<TransportMessage>.broadcast();
  final _subscriptions = <StreamSubscription<TransportMessage>>[];

  /// The configured transport priorities.
  List<TransportPriority> get transports => _transports;

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

    var anyConnected = false;
    for (final t in _transports) {
      try {
        await t.transport.connect();
        _subscriptions.add(
          t.transport.messages.listen(_messageController.add),
        );
        anyConnected = true;
      } on Object {
        // Continue to next transport.
      }
    }

    _setState(
      anyConnected ? TransportState.connected : TransportState.disconnected,
    );
  }

  @override
  Future<void> disconnect() async {
    for (final sub in _subscriptions) {
      await sub.cancel();
    }
    _subscriptions.clear();

    for (final t in _transports) {
      try {
        await t.transport.disconnect();
      } on Object {
        // Ignore disconnect errors.
      }
    }

    _setState(TransportState.disconnected);
  }

  /// Sends a message using the failover hierarchy.
  ///
  /// Tries each transport in order with retries and exponential backoff.
  /// Throws if all transports fail.
  @override
  Future<void> send(TransportMessage message) async {
    for (final t in _transports) {
      for (var attempt = 0; attempt < t.maxRetries; attempt++) {
        try {
          await t.transport.send(message).timeout(t.timeout);
          return;
        } on Object {
          if (attempt < t.maxRetries - 1) {
            await _backoff(attempt);
          }
        }
      }
    }
    throw TransportFailoverException(
      'All transports failed for message ${message.id}',
    );
  }

  /// Checks if at least one transport is available.
  bool get anyAvailable => _transports.any((t) => t.transport.isAvailable);

  /// Disposes the failover engine.
  Future<void> dispose() async {
    await disconnect();
    await _stateController.close();
    await _messageController.close();
  }

  void _setState(TransportState state) {
    _state = state;
    _stateController.add(state);
  }

  /// Exponential backoff: min(100ms * 2^attempt, 5s).
  static Future<void> _backoff(int attempt) async {
    final delayMs = min(100 * (1 << attempt), 5000);
    await Future<void>.delayed(Duration(milliseconds: delayMs));
  }
}

/// Exception thrown when all transports in the failover chain fail.
class TransportFailoverException implements Exception {
  /// Creates a [TransportFailoverException].
  const TransportFailoverException(this.message);

  /// The error message.
  final String message;

  @override
  String toString() => 'TransportFailoverException: $message';
}
