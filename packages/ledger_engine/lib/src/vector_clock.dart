import 'dart:typed_data';

import 'package:meta/meta.dart';

/// Causal relationship between two vector clocks.
enum CausalRelation {
  /// This clock is causally before the other.
  before,

  /// This clock is causally after the other.
  after,

  /// The clocks are concurrent (no causal relationship).
  concurrent,

  /// The clocks are identical.
  equal,
}

/// A 2-element vector clock for the Styx 2-peer system.
@immutable
class VectorClock {
  /// Creates a [VectorClock] with components [a] and [b].
  const VectorClock({required this.a, required this.b});

  /// Creates a zero vector clock.
  const VectorClock.zero() : a = 0, b = 0;

  /// Deserializes from a JSON-compatible map.
  factory VectorClock.fromJson(Map<String, dynamic> json) {
    return VectorClock(a: json['a'] as int, b: json['b'] as int);
  }

  /// Counter for peer A.
  final int a;

  /// Counter for peer B.
  final int b;

  /// Increments the counter for [localPeerRole] ('A' or 'B').
  VectorClock increment(String localPeerRole) {
    return switch (localPeerRole) {
      'A' => VectorClock(a: a + 1, b: b),
      'B' => VectorClock(a: a, b: b + 1),
      _ => throw ArgumentError.value(
        localPeerRole,
        'localPeerRole',
        "Must be 'A' or 'B'",
      ),
    };
  }

  /// Merges with [other] by taking the component-wise maximum.
  VectorClock merge(VectorClock other) {
    return VectorClock(
      a: a > other.a ? a : other.a,
      b: b > other.b ? b : other.b,
    );
  }

  /// Sum of all counters (used for deterministic ordering).
  int get total => a + b;

  /// Compares the causal relationship with [other].
  CausalRelation causalRelation(VectorClock other) {
    if (a == other.a && b == other.b) return CausalRelation.equal;
    if (a <= other.a && b <= other.b) return CausalRelation.before;
    if (a >= other.a && b >= other.b) return CausalRelation.after;
    return CausalRelation.concurrent;
  }

  /// Serializes to a JSON-compatible map.
  Map<String, int> toJson() => {'a': a, 'b': b};

  /// Serializes to bytes (8 bytes: 4 for A, 4 for B, big-endian).
  Uint8List toBytes() {
    final data = ByteData(8)
      ..setInt32(0, a)
      ..setInt32(4, b);
    return data.buffer.asUint8List();
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is VectorClock && a == other.a && b == other.b;

  @override
  int get hashCode => Object.hash(a, b);

  @override
  String toString() => 'VectorClock(a: $a, b: $b)';
}
