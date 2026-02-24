import 'dart:async';

import 'package:styx_transport/src/tor/tor_manager.dart';
import 'package:test/test.dart';

class FakeTorEngine implements TorEngine {
  FakeTorEngine({
    this.startDelay = Duration.zero,
    this.port = 9050,
    this.failOnStart = false,
  });

  final Duration startDelay;
  final int port;
  final bool failOnStart;
  int _progress = 0;
  bool started = false;

  @override
  Future<int> start() async {
    if (failOnStart) throw Exception('Tor start failed');
    await Future<void>.delayed(startDelay);
    _progress = 100;
    started = true;
    return port;
  }

  @override
  Future<void> stop() async {
    _progress = 0;
    started = false;
  }

  @override
  int get bootstrapProgress => _progress;
}

void main() {
  // T9.1 — Start → state ready
  test('T9.1: start transitions to ready', () async {
    final engine = FakeTorEngine();
    final manager = TorManager(engine: engine);

    final states = <TorState>[];
    final sub = manager.stateStream.listen(states.add);

    await manager.start();
    await Future<void>.delayed(Duration.zero);

    expect(manager.state, TorState.ready);
    expect(states, contains(TorState.bootstrapping));
    expect(states, contains(TorState.ready));

    await sub.cancel();
    await manager.dispose();
  });

  // T9.2 — SocksPort valid
  test('T9.2: socksPort is valid after start', () async {
    final engine = FakeTorEngine(port: 9150);
    final manager = TorManager(engine: engine);

    await manager.start();

    expect(manager.socksPort, 9150);
    expect(manager.socksPort, greaterThan(0));
    expect(manager.socksPort, lessThan(65536));

    await manager.dispose();
  });

  // T9.3 — Stop
  test('T9.3: stop transitions to stopped', () async {
    final engine = FakeTorEngine();
    final manager = TorManager(engine: engine);

    await manager.start();
    expect(manager.state, TorState.ready);

    await manager.stop();
    expect(manager.state, TorState.stopped);
    expect(manager.socksPort, 0);

    await manager.dispose();
  });

  // T9.4 — Bootstrap timeout
  test('T9.4: timeout transitions to error', () async {
    final engine = FakeTorEngine(
      startDelay: const Duration(seconds: 10),
    );
    final manager = TorManager(engine: engine);

    await manager.start(timeout: const Duration(milliseconds: 1));

    expect(manager.state, TorState.error);

    await manager.dispose();
  });

  // T9.5 — Double start is idempotent
  test('T9.5: double start is idempotent', () async {
    final engine = FakeTorEngine();
    final manager = TorManager(engine: engine);

    await manager.start();
    expect(manager.state, TorState.ready);

    // Second start should be a no-op.
    await manager.start();
    expect(manager.state, TorState.ready);

    await manager.dispose();
  });
}
