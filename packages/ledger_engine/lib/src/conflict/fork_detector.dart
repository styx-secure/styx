import 'package:meta/meta.dart';
import 'package:styx_ledger_engine/src/conflict/causality_checker.dart';
import 'package:styx_ledger_engine/src/ledger_event.dart';

/// A fork in the event chain where two branches diverge.
@immutable
class Fork {
  /// Creates a [Fork].
  const Fork({
    required this.commonAncestorHash,
    required this.branchA,
    required this.branchB,
  });

  /// Hash of the last common event before the fork.
  final String commonAncestorHash;

  /// Events on branch A (typically local).
  final List<LedgerEvent> branchA;

  /// Events on branch B (typically remote).
  final List<LedgerEvent> branchB;
}

/// Detects forks in the event chain.
class ForkDetector {
  /// Creates a [ForkDetector].
  ForkDetector({CausalityChecker? causalityChecker})
      : _causality = causalityChecker ?? CausalityChecker();

  final CausalityChecker _causality;

  /// Detects forks by finding events that share the same previousHash.
  List<Fork> detectForks(List<LedgerEvent> events) {
    // Group events by previousHash.
    final byPrevHash = <String, List<LedgerEvent>>{};
    for (final event in events) {
      final prev = event.previousHash;
      if (prev == null) continue;
      byPrevHash.putIfAbsent(prev, () => []).add(event);
    }

    final forks = <Fork>[];
    for (final entry in byPrevHash.entries) {
      if (entry.value.length < 2) continue;
      // A fork: multiple events reference the same previousHash.
      final branchA = [entry.value.first];
      final branchB = [entry.value.last];

      // Extend branches by following the chain.
      _extendBranch(branchA, events);
      _extendBranch(branchB, events);

      forks.add(
        Fork(
          commonAncestorHash: entry.key,
          branchA: branchA,
          branchB: branchB,
        ),
      );
    }

    return forks;
  }

  /// Detects if a remote event creates a fork with the local head.
  Fork? detectForkOnReceive({
    required LedgerEvent remoteEvent,
    required LedgerEvent localHead,
  }) {
    // If the remote event's previousHash matches the local head's
    // previousHash, they are siblings (fork).
    if (remoteEvent.previousHash == localHead.previousHash &&
        remoteEvent.eventId != localHead.eventId) {
      return Fork(
        commonAncestorHash: remoteEvent.previousHash ?? '',
        branchA: [localHead],
        branchB: [remoteEvent],
      );
    }

    // If the remote event has the same previousHash as the local head's
    // eventHash, it's a normal append (no fork).
    if (remoteEvent.previousHash == localHead.eventHash) return null;

    // Check for concurrency via vector clocks.
    if (_causality.isConcurrent(
      localHead.vectorClock,
      remoteEvent.vectorClock,
    )) {
      // Find common ancestor hash — use the earlier previousHash.
      final ancestorHash = remoteEvent.previousHash ?? '';
      return Fork(
        commonAncestorHash: ancestorHash,
        branchA: [localHead],
        branchB: [remoteEvent],
      );
    }

    return null;
  }

  void _extendBranch(List<LedgerEvent> branch, List<LedgerEvent> all) {
    final byPrev = <String, List<LedgerEvent>>{};
    for (final e in all) {
      if (e.previousHash != null) {
        byPrev.putIfAbsent(e.previousHash!, () => []).add(e);
      }
    }

    while (true) {
      final head = branch.last;
      final successors = byPrev[head.eventHash];
      if (successors == null || successors.length != 1) break;
      branch.add(successors.first);
    }
  }
}
