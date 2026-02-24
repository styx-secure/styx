import 'package:styx_transport/src/transport_message.dart';

/// State of a transport connection.
enum TransportState {
  /// Not connected.
  disconnected,

  /// Connection in progress.
  connecting,

  /// Connected and ready.
  connected,
}

/// Abstract interface for transport implementations.
abstract class TransportInterface {
  /// Sends a [message] to the recipient indicated in the message.
  Future<void> send(TransportMessage message);

  /// Stream of incoming messages.
  Stream<TransportMessage> get messages;

  /// Stream of connection state changes.
  Stream<TransportState> get stateChanges;

  /// Current connection state.
  TransportState get currentState;

  /// Connects to the transport network.
  Future<void> connect();

  /// Disconnects from the transport network.
  Future<void> disconnect();

  /// Whether the transport is currently available (connected).
  bool get isAvailable;
}
