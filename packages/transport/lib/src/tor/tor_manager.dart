import 'dart:async';

/// State of the Tor bootstrap process.
enum TorState {
  /// Tor is not running.
  stopped,

  /// Tor is bootstrapping.
  bootstrapping,

  /// Tor is ready (SOCKS5 proxy available).
  ready,

  /// Tor encountered an error.
  error,
}

/// Abstract interface for the Tor engine, enabling testability.
abstract class TorEngine {
  /// Starts the Tor process and returns the SOCKS5 port.
  Future<int> start();

  /// Stops the Tor process.
  Future<void> stop();

  /// Current bootstrap progress (0–100).
  int get bootstrapProgress;
}

/// Manages the Tor SOCKS5 proxy lifecycle.
class TorManager {
  /// Creates a [TorManager] with the given [engine].
  TorManager({required TorEngine engine}) : _engine = engine;

  final TorEngine _engine;

  TorState _state = TorState.stopped;
  int _socksPort = 0;
  final _stateController = StreamController<TorState>.broadcast();

  /// Current state.
  TorState get state => _state;

  /// Stream of state changes.
  Stream<TorState> get stateStream => _stateController.stream;

  /// SOCKS5 port (valid only when [state] is [TorState.ready]).
  int get socksPort => _socksPort;

  /// Bootstrap progress (0–100).
  int get bootstrapProgress => _engine.bootstrapProgress;

  /// Starts Tor with an optional [timeout].
  ///
  /// If already running or ready, this is a no-op.
  Future<void> start({
    Duration timeout = const Duration(seconds: 120),
  }) async {
    if (_state == TorState.ready || _state == TorState.bootstrapping) {
      return;
    }

    _setState(TorState.bootstrapping);

    try {
      _socksPort = await _engine.start().timeout(timeout);
      _setState(TorState.ready);
    } on TimeoutException {
      _setState(TorState.error);
    } on Object {
      _setState(TorState.error);
    }
  }

  /// Stops Tor.
  Future<void> stop() async {
    if (_state == TorState.stopped) return;

    try {
      await _engine.stop();
    } on Object {
      // Ignore stop errors.
    }

    _socksPort = 0;
    _setState(TorState.stopped);
  }

  /// Disposes the manager.
  Future<void> dispose() async {
    await stop();
    await _stateController.close();
  }

  void _setState(TorState state) {
    _state = state;
    _stateController.add(state);
  }
}
