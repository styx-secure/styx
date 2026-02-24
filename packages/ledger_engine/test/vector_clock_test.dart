import 'package:styx_ledger_engine/src/vector_clock.dart';
import 'package:test/test.dart';

void main() {
  group('VectorClock', () {
    // T5.8: Increment A
    test('T5.8 — increment A from zero', () {
      const vc = VectorClock(a: 0, b: 0);
      final incremented = vc.increment('A');
      expect(incremented, const VectorClock(a: 1, b: 0));
    });

    // T5.9: Merge
    test('T5.9 — merge takes component-wise max', () {
      const vc1 = VectorClock(a: 2, b: 1);
      const vc2 = VectorClock(a: 1, b: 3);
      final merged = vc1.merge(vc2);
      expect(merged, const VectorClock(a: 2, b: 3));
    });

    // T5.10: Causal BEFORE
    test('T5.10 — causal relation BEFORE', () {
      const vc1 = VectorClock(a: 1, b: 1);
      const vc2 = VectorClock(a: 2, b: 1);
      expect(vc1.causalRelation(vc2), CausalRelation.before);
    });

    // T5.11: Causal CONCURRENT
    test('T5.11 — causal relation CONCURRENT', () {
      const vc1 = VectorClock(a: 2, b: 1);
      const vc2 = VectorClock(a: 1, b: 2);
      expect(vc1.causalRelation(vc2), CausalRelation.concurrent);
    });

    // T5.12: Causal EQUAL
    test('T5.12 — causal relation EQUAL', () {
      const vc1 = VectorClock(a: 1, b: 1);
      const vc2 = VectorClock(a: 1, b: 1);
      expect(vc1.causalRelation(vc2), CausalRelation.equal);
    });

    // T5.13: Total
    test('T5.13 — total is sum of components', () {
      const vc = VectorClock(a: 3, b: 5);
      expect(vc.total, 8);
    });

    test('increment B works', () {
      const vc = VectorClock(a: 1, b: 2);
      expect(vc.increment('B'), const VectorClock(a: 1, b: 3));
    });

    test('increment invalid role throws', () {
      const vc = VectorClock.zero();
      expect(() => vc.increment('C'), throwsA(isA<ArgumentError>()));
    });

    test('toJson and fromJson round-trip', () {
      const vc = VectorClock(a: 7, b: 3);
      final json = vc.toJson();
      final parsed = VectorClock.fromJson(json);
      expect(parsed, vc);
    });

    test('toBytes produces 8 bytes', () {
      const vc = VectorClock(a: 1, b: 2);
      expect(vc.toBytes().length, 8);
    });
  });
}
