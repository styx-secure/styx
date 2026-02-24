import 'package:meta/meta.dart';
import 'package:styx_ledger_engine/src/conflict/fork_detector.dart';
import 'package:styx_ledger_engine/src/ledger_event.dart';
import 'package:styx_ledger_engine/src/vector_clock.dart';

/// Result of a deterministic merge operation.
@immutable
class MergeResult {
  /// Creates a [MergeResult].
  const MergeResult({
    required this.orderedEvents,
    required this.mergeEventNeeded,
  });

  /// The deterministically ordered event sequence.
  final List<LedgerEvent> orderedEvents;

  /// Whether a MERGE event should be appended.
  final bool mergeEventNeeded;
}

/// Performs deterministic merge of forked branches.
///
/// Both peers apply the same ordering rule, guaranteeing convergence
/// without additional communication.
class DeterministicMerge {
  /// Orders concurrent events deterministically.
  ///
  /// Rule:
  /// 1. Sort by vector clock total (ascending).
  /// 2. Tiebreak by sender pubkey (lexicographic).
  List<LedgerEvent> orderConcurrentEvents(List<LedgerEvent> events) {
    final sorted = List<LedgerEvent>.of(events)..sort(_compare);
    return sorted;
  }

  /// Merges a fork into a linear sequence.
  ///
  /// 1. Collects events from both branches.
  /// 2. Orders them deterministically.
  /// 3. Returns the ordered sequence + whether a MERGE event is needed.
  MergeResult merge({
    required Fork fork,
    required String localPeerRole,
  }) {
    final allEvents = [...fork.branchA, ...fork.branchB];
    final ordered = orderConcurrentEvents(allEvents);

    // Compute merged vector clock.
    var mergedVc = const VectorClock.zero();
    for (final event in ordered) {
      mergedVc = mergedVc.merge(event.vectorClock);
    }

    return MergeResult(
      orderedEvents: ordered,
      mergeEventNeeded: fork.branchA.isNotEmpty && fork.branchB.isNotEmpty,
    );
  }

  static int _compare(LedgerEvent a, LedgerEvent b) {
    final totalA = a.vectorClock.total;
    final totalB = b.vectorClock.total;
    if (totalA != totalB) return totalA.compareTo(totalB);
    return a.senderPubkey.compareTo(b.senderPubkey);
  }
}
