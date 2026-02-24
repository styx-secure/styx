import 'package:styx_ledger_engine/src/vector_clock.dart';

/// Determines causal relationships between vector clocks.
class CausalityChecker {
  /// Compares the causal relationship between [a] and [b].
  CausalRelation compare(VectorClock a, VectorClock b) => a.causalRelation(b);

  /// Returns `true` if [event] is causally after [reference].
  bool isAfter(VectorClock event, VectorClock reference) =>
      event.causalRelation(reference) == CausalRelation.after;

  /// Returns `true` if [a] and [b] are concurrent (a fork).
  bool isConcurrent(VectorClock a, VectorClock b) =>
      a.causalRelation(b) == CausalRelation.concurrent;
}
