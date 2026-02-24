import 'dart:async';
import 'dart:convert';

/// Factory function to create WebSocket-like connections.
///
/// Returns a [RelayConnection] for the given [url].
typedef WebSocketFactory = Future<RelayConnection> Function(String url);

/// Minimal WebSocket connection abstraction for testing.
abstract class RelayConnection {
  /// Stream of incoming messages (JSON strings).
  Stream<String> get messages;

  /// Sends a JSON string to the relay.
  void send(String data);

  /// Closes the connection.
  Future<void> close();

  /// Whether the connection is currently open.
  bool get isOpen;
}

/// Health status of a relay.
class RelayHealth {
  /// Creates a [RelayHealth].
  const RelayHealth({
    required this.url,
    required this.isConnected,
  });

  /// The relay URL.
  final String url;

  /// Whether the relay is currently connected.
  final bool isConnected;
}

/// Manages a pool of Nostr relay connections.
class RelayPool {
  /// Creates a [RelayPool] with the given [relayUrls] and [factory].
  RelayPool({
    required List<String> relayUrls,
    required WebSocketFactory factory,
  })  : _relayUrls = List.of(relayUrls),
        _factory = factory;

  final List<String> _relayUrls;
  final WebSocketFactory _factory;
  final Map<String, RelayConnection> _connections = {};
  final _messageController = StreamController<String>.broadcast();

  final Map<String, StreamSubscription<String>> _subscriptions = {};

  /// Stream of incoming messages from all relays.
  Stream<String> get messages => _messageController.stream;

  /// Currently configured relay URLs.
  List<String> get relayUrls => List.unmodifiable(_relayUrls);

  /// Connects to all relays. Returns the number of successful connections.
  Future<int> connectAll() async {
    var connected = 0;
    for (final url in _relayUrls) {
      if (await _connectRelay(url)) {
        connected++;
      }
    }
    return connected;
  }

  /// Disconnects from all relays.
  Future<void> disconnectAll() async {
    for (final entry in _subscriptions.entries) {
      await entry.value.cancel();
    }
    _subscriptions.clear();

    for (final conn in _connections.values) {
      await conn.close();
    }
    _connections.clear();
  }

  /// Publishes a JSON event to all connected relays.
  ///
  /// Returns the number of relays the message was sent to.
  int publish(Map<String, dynamic> event) {
    final json = jsonEncode(['EVENT', event]);
    var count = 0;
    for (final conn in _connections.values) {
      if (conn.isOpen) {
        conn.send(json);
        count++;
      }
    }
    return count;
  }

  /// Subscribes to events matching [filter] on all connected relays.
  void subscribe(String subscriptionId, Map<String, dynamic> filter) {
    final json = jsonEncode(['REQ', subscriptionId, filter]);
    for (final conn in _connections.values) {
      if (conn.isOpen) {
        conn.send(json);
      }
    }
  }

  /// Returns health status of all relays.
  List<RelayHealth> healthCheck() {
    return _relayUrls.map((url) {
      final conn = _connections[url];
      return RelayHealth(
        url: url,
        isConnected: conn != null && conn.isOpen,
      );
    }).toList();
  }

  /// Adds a relay URL to the pool.
  ///
  /// Does not automatically connect; call [connectAll] or connect manually.
  void addRelay(String url) {
    if (!_relayUrls.contains(url)) {
      _relayUrls.add(url);
    }
  }

  /// Removes a relay from the pool and disconnects it.
  Future<void> removeRelay(String url) async {
    _relayUrls.remove(url);
    final sub = _subscriptions.remove(url);
    await sub?.cancel();
    final conn = _connections.remove(url);
    await conn?.close();
  }

  /// Number of currently connected relays.
  int get connectedCount => _connections.values.where((c) => c.isOpen).length;

  /// Disposes the pool.
  Future<void> dispose() async {
    await disconnectAll();
    await _messageController.close();
  }

  Future<bool> _connectRelay(String url) async {
    try {
      final conn = await _factory(url);
      _connections[url] = conn;
      _subscriptions[url] = conn.messages.listen(
        _messageController.add,
        onError: (_) {},
      );
      return true;
    } on Object {
      return false;
    }
  }
}
