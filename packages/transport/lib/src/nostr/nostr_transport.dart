import 'dart:async';
import 'dart:convert';

import 'package:styx_transport/src/nostr/nostr_encryptor.dart';
import 'package:styx_transport/src/nostr/relay_pool.dart';
import 'package:styx_transport/src/transport_interface.dart';
import 'package:styx_transport/src/transport_message.dart';
import 'package:uuid/uuid.dart';

const _uuid = Uuid();

/// Nostr-based transport that composes [RelayPool] and [NostrEncryptor].
///
/// Provides end-to-end encrypted messaging over Nostr relays with
/// LRU deduplication.
class NostrTransport implements TransportInterface {
  /// Creates a [NostrTransport].
  ///
  /// [relayPool] — manages relay connections.
  /// [encryptor] — handles E2E encryption.
  /// [localPubkey] — hex-encoded local public key.
  /// [remotePubkey] — hex-encoded remote peer public key.
  /// [maxDedup] — maximum dedup cache size (default: 1000).
  NostrTransport({
    required RelayPool relayPool,
    required NostrEncryptor encryptor,
    required this.localPubkey,
    required this.remotePubkey,
    int maxDedup = 1000,
  })  : _relayPool = relayPool,
        _encryptor = encryptor,
        _maxDedup = maxDedup;

  final RelayPool _relayPool;
  final NostrEncryptor _encryptor;

  /// Hex-encoded local public key.
  final String localPubkey;

  /// Hex-encoded remote peer public key.
  final String remotePubkey;

  final int _maxDedup;

  TransportState _state = TransportState.disconnected;
  final _stateController = StreamController<TransportState>.broadcast();
  final _messageController = StreamController<TransportMessage>.broadcast();
  StreamSubscription<String>? _relaySubscription;

  // LRU dedup cache: insertion-ordered set of message IDs.
  final _dedupCache = <String>{};
  final _dedupOrder = <String>[];

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

    final connected = await _relayPool.connectAll();
    if (connected == 0) {
      _setState(TransportState.disconnected);
      return;
    }

    _relaySubscription = _relayPool.messages.listen(_handleRelayMessage);
    _setState(TransportState.connected);
  }

  @override
  Future<void> disconnect() async {
    await _relaySubscription?.cancel();
    _relaySubscription = null;
    await _relayPool.disconnectAll();
    _setState(TransportState.disconnected);
  }

  @override
  Future<void> send(TransportMessage message) async {
    if (_state != TransportState.connected) {
      throw StateError('Cannot send: transport is not connected');
    }

    final encrypted = await _encryptor.encrypt(message.payload);

    final event = {
      'id': message.id,
      'pubkey': localPubkey,
      'kind': 30078,
      'tags': [
        ['p', message.recipientPubkey],
      ],
      'content': base64Encode(encrypted),
      'created_at': message.timestamp.millisecondsSinceEpoch ~/ 1000,
    };

    _relayPool.publish(event);
    _addToDedup(message.id);
  }

  /// Disposes the transport.
  Future<void> dispose() async {
    await disconnect();
    await _stateController.close();
    await _messageController.close();
  }

  Future<void> _handleRelayMessage(String raw) async {
    try {
      final parsed = jsonDecode(raw) as List<dynamic>;
      if (parsed.length < 3 || parsed[0] != 'EVENT') return;

      final event = parsed[2] as Map<String, dynamic>;
      final id = event['id'] as String;

      // Dedup check.
      if (_dedupCache.contains(id)) return;

      // Check if addressed to us.
      final tags = event['tags'] as List<dynamic>;
      final pTag = tags.cast<List<dynamic>>().where(
            (t) => t.isNotEmpty && t[0] == 'p',
          );
      if (pTag.isEmpty) return;
      final recipient = pTag.first[1] as String;
      if (recipient != localPubkey) return;

      final content = base64Decode(event['content'] as String);
      final decrypted = await _encryptor.decrypt(content);

      final senderPubkey = event['pubkey'] as String;
      final createdAt = event['created_at'] as int;

      final message = TransportMessage(
        id: id,
        senderPubkey: senderPubkey,
        recipientPubkey: localPubkey,
        payload: decrypted,
        timestamp: DateTime.fromMillisecondsSinceEpoch(
          createdAt * 1000,
          isUtc: true,
        ),
      );

      _addToDedup(id);
      _messageController.add(message);
    } on Object {
      // Ignore malformed messages.
    }
  }

  void _addToDedup(String id) {
    if (_dedupCache.length >= _maxDedup) {
      final oldest = _dedupOrder.removeAt(0);
      _dedupCache.remove(oldest);
    }
    _dedupCache.add(id);
    _dedupOrder.add(id);
  }

  void _setState(TransportState state) {
    _state = state;
    _stateController.add(state);
  }

  /// Creates a new unique message ID.
  static String newMessageId() => _uuid.v4();
}
