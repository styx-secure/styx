import 'dart:async';

import 'package:styx_transport/src/tor/tor_manager.dart';
import 'package:styx_transport/src/transport_interface.dart';
import 'package:styx_transport/src/transport_message.dart';

/// Decorator that routes a [TransportInterface] through Tor.
///
/// Wraps any transport implementation to add Tor SOCKS5 proxy routing.
/// Ensures Tor is bootstrapped before the inner transport connects.
class TorTransportDecorator implements TransportInterface {
  /// Creates a [TorTransportDecorator].
  TorTransportDecorator({
    required TransportInterface inner,
    required TorManager torManager,
  }) : _inner = inner,
       _torManager = torManager;

  final TransportInterface _inner;
  final TorManager _torManager;

  @override
  TransportState get currentState => _inner.currentState;

  @override
  Stream<TransportState> get stateChanges => _inner.stateChanges;

  @override
  Stream<TransportMessage> get messages => _inner.messages;

  @override
  bool get isAvailable =>
      _torManager.state == TorState.ready && _inner.isAvailable;

  @override
  Future<void> connect() async {
    if (_torManager.state != TorState.ready) {
      await _torManager.start();
    }
    if (_torManager.state != TorState.ready) {
      throw StateError('Tor failed to bootstrap');
    }
    await _inner.connect();
  }

  @override
  Future<void> disconnect() async {
    await _inner.disconnect();
  }

  @override
  Future<void> send(TransportMessage message) => _inner.send(message);
}
