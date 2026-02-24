import 'package:styx_ledger_engine/src/conflict/causality_checker.dart';
import 'package:styx_ledger_engine/src/vector_clock.dart';
import 'package:test/test.dart';

void main() {
  final checker = CausalityChecker();

  group('CausalityChecker', () {
    // T6.1: {2,1} dominates {1,1}
    test('T6.1 — {2,1} is after {1,1}', () {
      expect(
        checker.compare(
          const VectorClock(a: 2, b: 1),
          const VectorClock(a: 1, b: 1),
        ),
        CausalRelation.after,
      );
    });

    // T6.2: {1,1} dominated by {2,1}
    test('T6.2 — {1,1} is before {2,1}', () {
      expect(
        checker.compare(
          const VectorClock(a: 1, b: 1),
          const VectorClock(a: 2, b: 1),
        ),
        CausalRelation.before,
      );
    });

    // T6.3: {2,1} vs {1,2} — concurrent
    test('T6.3 — {2,1} vs {1,2} is concurrent', () {
      expect(
        checker.compare(
          const VectorClock(a: 2, b: 1),
          const VectorClock(a: 1, b: 2),
        ),
        CausalRelation.concurrent,
      );
    });

    // T6.4: {3,3} vs {3,3} — equal
    test('T6.4 — {3,3} vs {3,3} is equal', () {
      expect(
        checker.compare(
          const VectorClock(a: 3, b: 3),
          const VectorClock(a: 3, b: 3),
        ),
        CausalRelation.equal,
      );
    });

    // T6.5: {0,0} vs {0,1} — before
    test('T6.5 — {0,0} vs {0,1} is before', () {
      expect(
        checker.compare(
          const VectorClock(a: 0, b: 0),
          const VectorClock(a: 0, b: 1),
        ),
        CausalRelation.before,
      );
    });

    test('isAfter returns true for after relation', () {
      expect(
        checker.isAfter(
          const VectorClock(a: 3, b: 1),
          const VectorClock(a: 2, b: 1),
        ),
        isTrue,
      );
    });

    test('isConcurrent returns true for concurrent', () {
      expect(
        checker.isConcurrent(
          const VectorClock(a: 2, b: 1),
          const VectorClock(a: 1, b: 2),
        ),
        isTrue,
      );
    });
  });
}
