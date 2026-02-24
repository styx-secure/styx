import 'dart:typed_data';

import 'package:meta/meta.dart';
import 'package:styx_ledger_engine/src/event_type.dart';
import 'package:styx_ledger_engine/src/hlc.dart';
import 'package:styx_ledger_engine/src/vector_clock.dart';

/// Immutable domain model for an event in the cryptographic chain.
@immutable
class LedgerEvent {
  /// Creates a [LedgerEvent].
  const LedgerEvent({
    required this.eventId,
    required this.eventType,
    required this.payload,
    required this.previousHash,
    required this.eventHash,
    required this.hlc,
    required this.vectorClock,
    required this.senderPubkey,
    required this.signature,
    required this.createdAt,
    this.isPruned = false,
  });

  /// Unique event identifier (UUID v4).
  final String eventId;

  /// Type of this event.
  final EventType eventType;

  /// Encrypted payload (null if pruned).
  final Uint8List? payload;

  /// Hash of the previous event (null only for genesis).
  final String? previousHash;

  /// SHA-256 hex hash of this event.
  final String eventHash;

  /// Hybrid logical clock for causal ordering.
  final HybridLogicalClock hlc;

  /// 2-element vector clock.
  final VectorClock vectorClock;

  /// Hex-encoded Ed25519 public key of the sender.
  final String senderPubkey;

  /// Ed25519 signature (64 bytes).
  final Uint8List signature;

  /// Timestamp of creation.
  final DateTime createdAt;

  /// Whether the payload has been pruned (GDPR).
  final bool isPruned;
}
