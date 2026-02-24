import 'dart:typed_data';

import 'package:meta/meta.dart';

/// Hybrid Logical Clock for causal ordering of events.
///
/// Format: `timestamp-counter-nodeId` where:
/// - timestamp: UTC wall-clock time
/// - counter: tiebreaker for events at the same millisecond
/// - nodeId: first 8 hex chars of the node's public key
@immutable
class HybridLogicalClock implements Comparable<HybridLogicalClock> {
  /// Creates an [HybridLogicalClock] with explicit values.
  const HybridLogicalClock({
    required this.timestamp,
    required this.counter,
    required this.nodeId,
  });

  /// Creates a new HLC for a local event.
  ///
  /// If the wall-clock has advanced past [previous], counter resets to 0.
  /// If the wall-clock is equal or behind [previous], counter increments.
  factory HybridLogicalClock.now({
    required HybridLogicalClock? previous,
    required String nodeId,
  }) {
    final now = DateTime.now().toUtc();

    if (previous == null) {
      return HybridLogicalClock(timestamp: now, counter: 0, nodeId: nodeId);
    }

    final prevMs = previous.timestamp.millisecondsSinceEpoch;
    final nowMs = now.millisecondsSinceEpoch;

    if (nowMs > prevMs) {
      return HybridLogicalClock(timestamp: now, counter: 0, nodeId: nodeId);
    }

    // Wall clock hasn't advanced: keep previous timestamp, bump counter.
    return HybridLogicalClock(
      timestamp: previous.timestamp,
      counter: previous.counter + 1,
      nodeId: nodeId,
    );
  }

  /// Updates the HLC upon receiving a remote event.
  ///
  /// Takes the max of local, remote, and wall-clock timestamps.
  factory HybridLogicalClock.receive({
    required HybridLogicalClock local,
    required HybridLogicalClock remote,
    required String nodeId,
  }) {
    final now = DateTime.now().toUtc();
    final localMs = local.timestamp.millisecondsSinceEpoch;
    final remoteMs = remote.timestamp.millisecondsSinceEpoch;
    final nowMs = now.millisecondsSinceEpoch;

    final maxMs = _max3(localMs, remoteMs, nowMs);

    int counter;
    if (maxMs == localMs && maxMs == remoteMs) {
      counter = _max2(local.counter, remote.counter) + 1;
    } else if (maxMs == localMs) {
      counter = local.counter + 1;
    } else if (maxMs == remoteMs) {
      counter = remote.counter + 1;
    } else {
      counter = 0;
    }

    return HybridLogicalClock(
      timestamp: DateTime.fromMillisecondsSinceEpoch(maxMs, isUtc: true),
      counter: counter,
      nodeId: nodeId,
    );
  }

  /// Parses a canonical HLC string.
  factory HybridLogicalClock.fromCanonical(String s) {
    // Format: ISO8601-COUNTER-NODEID
    // The ISO timestamp ends with 'Z', so split from the right.
    final lastDash = s.lastIndexOf('-');
    final nodeId = s.substring(lastDash + 1);

    final beforeNodeId = s.substring(0, lastDash);
    final secondLastDash = beforeNodeId.lastIndexOf('-');
    final counterStr = beforeNodeId.substring(secondLastDash + 1);
    final tsStr = beforeNodeId.substring(0, secondLastDash);

    return HybridLogicalClock(
      timestamp: DateTime.parse(tsStr),
      counter: int.parse(counterStr),
      nodeId: nodeId,
    );
  }

  /// UTC wall-clock time.
  final DateTime timestamp;

  /// Logical counter (tiebreaker within the same millisecond).
  final int counter;

  /// Node identifier (first 8 hex chars of pubkey).
  final String nodeId;

  /// Canonical string: `2026-02-24T12:00:00.000Z-0042-a1b2c3d4`
  String toCanonical() {
    final ts = timestamp.toIso8601String();
    final cnt = counter.toString().padLeft(4, '0');
    return '$ts-$cnt-$nodeId';
  }

  /// Serializes to bytes for inclusion in hash computations.
  Uint8List toBytes() {
    final canonical = toCanonical();
    return Uint8List.fromList(canonical.codeUnits);
  }

  @override
  int compareTo(HybridLogicalClock other) {
    final tsCmp = timestamp.compareTo(other.timestamp);
    if (tsCmp != 0) return tsCmp;

    final cntCmp = counter.compareTo(other.counter);
    if (cntCmp != 0) return cntCmp;

    return nodeId.compareTo(other.nodeId);
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is HybridLogicalClock &&
          timestamp == other.timestamp &&
          counter == other.counter &&
          nodeId == other.nodeId;

  @override
  int get hashCode => Object.hash(timestamp, counter, nodeId);

  @override
  String toString() => 'HLC(${toCanonical()})';

  static int _max2(int a, int b) => a > b ? a : b;
  static int _max3(int a, int b, int c) => _max2(_max2(a, b), c);
}
