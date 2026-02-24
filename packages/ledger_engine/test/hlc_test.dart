import 'package:styx_ledger_engine/src/hlc.dart';
import 'package:test/test.dart';

void main() {
  group('HybridLogicalClock', () {
    // T5.1: HLC.now without previous
    test('T5.1 — now without previous has counter=0', () {
      final hlc = HybridLogicalClock.now(previous: null, nodeId: 'a1b2c3d4');
      expect(hlc.counter, 0);
      expect(hlc.nodeId, 'a1b2c3d4');
      // Timestamp should be close to now.
      final diff = DateTime.now().toUtc().difference(hlc.timestamp);
      expect(diff.inSeconds.abs(), lessThan(2));
    });

    // T5.2: HLC.now with previous at same timestamp
    test('T5.2 — now with same-ms previous increments counter', () {
      final prev = HybridLogicalClock(
        timestamp: DateTime.now().toUtc().add(const Duration(hours: 1)),
        counter: 5,
        nodeId: 'a1b2c3d4',
      );
      final hlc = HybridLogicalClock.now(
        previous: prev,
        nodeId: 'a1b2c3d4',
      );
      // Wall clock is behind previous, so counter should increment.
      expect(hlc.counter, 6);
      expect(hlc.timestamp, prev.timestamp);
    });

    // T5.3: HLC.now with previous in the past
    test('T5.3 — now with past previous resets counter', () {
      final prev = HybridLogicalClock(
        timestamp: DateTime.utc(2020),
        counter: 42,
        nodeId: 'a1b2c3d4',
      );
      final hlc = HybridLogicalClock.now(
        previous: prev,
        nodeId: 'a1b2c3d4',
      );
      expect(hlc.counter, 0);
      expect(
        hlc.timestamp.millisecondsSinceEpoch,
        greaterThan(prev.timestamp.millisecondsSinceEpoch),
      );
    });

    // T5.4: HLC.receive with clock drift (remote far in future)
    test('T5.4 — receive handles clock drift gracefully', () {
      final local = HybridLogicalClock(
        timestamp: DateTime.now().toUtc(),
        counter: 0,
        nodeId: 'localnode',
      );
      final remote = HybridLogicalClock(
        timestamp: DateTime.now().toUtc().add(const Duration(minutes: 10)),
        counter: 3,
        nodeId: 'remonode1',
      );

      final hlc = HybridLogicalClock.receive(
        local: local,
        remote: remote,
        nodeId: 'localnode',
      );

      // Should pick the remote timestamp (highest).
      expect(
        hlc.timestamp.millisecondsSinceEpoch,
        remote.timestamp.millisecondsSinceEpoch,
      );
      expect(hlc.counter, 4);
    });

    // T5.5: HLC.receive when local is ahead
    test('T5.5 — receive with local ahead keeps local timestamp', () {
      final local = HybridLogicalClock(
        timestamp: DateTime.now().toUtc().add(const Duration(hours: 1)),
        counter: 2,
        nodeId: 'localnode',
      );
      final remote = HybridLogicalClock(
        timestamp: DateTime.utc(2020),
        counter: 10,
        nodeId: 'remonode1',
      );

      final hlc = HybridLogicalClock.receive(
        local: local,
        remote: remote,
        nodeId: 'localnode',
      );

      expect(
        hlc.timestamp.millisecondsSinceEpoch,
        local.timestamp.millisecondsSinceEpoch,
      );
      expect(hlc.counter, 3);
    });

    // T5.6: Total ordering — no ties
    test('T5.6 — compareTo produces total ordering on 1000 HLCs', () {
      final hlcs = <HybridLogicalClock>[];
      final baseTime = DateTime.utc(2025);
      for (var i = 0; i < 1000; i++) {
        hlcs.add(
          HybridLogicalClock(
            timestamp: baseTime.add(Duration(milliseconds: i ~/ 10)),
            counter: i % 10,
            nodeId: 'node${(i % 3).toString().padLeft(4, '0')}',
          ),
        );
      }

      hlcs.sort();

      // No two adjacent elements should be equal after sorting.
      for (var i = 1; i < hlcs.length; i++) {
        expect(hlcs[i - 1].compareTo(hlcs[i]), isNegative);
      }
    });

    // T5.7: Serialization round-trip
    test('T5.7 — fromCanonical(toCanonical()) round-trips', () {
      final hlc = HybridLogicalClock(
        timestamp: DateTime.utc(2026, 2, 24, 12),
        counter: 42,
        nodeId: 'a1b2c3d4',
      );

      final canonical = hlc.toCanonical();
      final parsed = HybridLogicalClock.fromCanonical(canonical);

      expect(parsed.timestamp, hlc.timestamp);
      expect(parsed.counter, hlc.counter);
      expect(parsed.nodeId, hlc.nodeId);
      expect(parsed, hlc);
    });
  });
}
