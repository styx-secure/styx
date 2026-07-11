import 'dart:convert';
import 'dart:typed_data';

import 'package:meta/meta.dart';

/// A message sent over the transport layer.
@immutable
class TransportMessage {
  /// Creates a [TransportMessage].
  const TransportMessage({
    required this.id,
    required this.senderPubkey,
    required this.recipientPubkey,
    required this.payload,
    required this.timestamp,
  });

  /// Deserializes from a JSON map.
  factory TransportMessage.fromJson(Map<String, dynamic> json) {
    return TransportMessage(
      id: json['id'] as String,
      senderPubkey: json['senderPubkey'] as String,
      recipientPubkey: json['recipientPubkey'] as String,
      payload: base64Decode(json['payload'] as String),
      timestamp: DateTime.parse(json['timestamp'] as String),
    );
  }

  /// Unique message identifier.
  final String id;

  /// Hex-encoded public key of the sender.
  final String senderPubkey;

  /// Hex-encoded public key of the recipient.
  final String recipientPubkey;

  /// Binary payload (encrypted ledger event data).
  final Uint8List payload;

  /// When this message was created.
  final DateTime timestamp;

  /// Serializes to a JSON map (payload as base64).
  Map<String, dynamic> toJson() => {
    'id': id,
    'senderPubkey': senderPubkey,
    'recipientPubkey': recipientPubkey,
    'payload': base64Encode(payload),
    'timestamp': timestamp.toUtc().toIso8601String(),
  };

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is TransportMessage &&
          id == other.id &&
          senderPubkey == other.senderPubkey &&
          recipientPubkey == other.recipientPubkey;

  @override
  int get hashCode => Object.hash(id, senderPubkey, recipientPubkey);

  @override
  String toString() => 'TransportMessage(id: $id, sender: $senderPubkey)';
}
