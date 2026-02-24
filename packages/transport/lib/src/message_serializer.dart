import 'dart:convert';
import 'dart:typed_data';

import 'package:styx_ledger_engine/styx_ledger_engine.dart';

/// Binary serializer for [LedgerEvent] instances.
///
/// Format: length-prefixed fields (4-byte big-endian length + data).
/// Fields: eventId, eventType, payload, previousHash, eventHash,
/// hlc (canonical), vectorClock (8 bytes), senderPubkey, signature,
/// createdAt (ISO 8601), isPruned (1 byte).
class MessageSerializer {
  /// Serializes a [LedgerEvent] to bytes.
  Uint8List serialize(LedgerEvent event) {
    final builder = BytesBuilder(copy: false);

    _writeString(builder, event.eventId);
    _writeString(builder, event.eventType.name);
    _writeBytes(builder, event.payload ?? Uint8List(0));
    _writeString(builder, event.previousHash ?? '');
    _writeString(builder, event.eventHash);
    _writeString(builder, event.hlc.toCanonical());
    _writeBytes(builder, event.vectorClock.toBytes());
    _writeString(builder, event.senderPubkey);
    _writeBytes(builder, event.signature);
    _writeString(builder, event.createdAt.toUtc().toIso8601String());
    builder.addByte(event.isPruned ? 1 : 0);

    return builder.toBytes();
  }

  /// Deserializes a [LedgerEvent] from bytes.
  LedgerEvent deserialize(Uint8List data) {
    var offset = 0;

    Uint8List readBytes() {
      final bd = ByteData.sublistView(data, offset, offset + 4);
      final length = bd.getInt32(0);
      offset += 4;
      final bytes = Uint8List.sublistView(data, offset, offset + length);
      offset += length;
      return bytes;
    }

    String readString() => utf8.decode(readBytes());

    final eventId = readString();
    final eventTypeName = readString();
    final payload = readBytes();
    final previousHashStr = readString();
    final eventHash = readString();
    final hlcCanonical = readString();
    final vcBytes = readBytes();
    final senderPubkey = readString();
    final signature = readBytes();
    final createdAtStr = readString();
    final isPruned = data[offset] == 1;

    final eventType = EventType.values.firstWhere(
      (e) => e.name == eventTypeName,
    );

    final vcData = ByteData.sublistView(vcBytes);
    final vectorClock = VectorClock(
      a: vcData.getInt32(0),
      b: vcData.getInt32(4),
    );

    return LedgerEvent(
      eventId: eventId,
      eventType: eventType,
      payload: payload.isEmpty && isPruned ? null : payload,
      previousHash: previousHashStr.isEmpty ? null : previousHashStr,
      eventHash: eventHash,
      hlc: HybridLogicalClock.fromCanonical(hlcCanonical),
      vectorClock: vectorClock,
      senderPubkey: senderPubkey,
      signature: Uint8List.fromList(signature),
      createdAt: DateTime.parse(createdAtStr),
      isPruned: isPruned,
    );
  }

  /// Serializes a batch of events.
  Uint8List serializeBatch(List<LedgerEvent> events) {
    final builder = BytesBuilder(copy: false)
      ..add((ByteData(4)..setInt32(0, events.length)).buffer.asUint8List());

    for (final event in events) {
      final serialized = serialize(event);
      final lenData = ByteData(4)..setInt32(0, serialized.length);
      builder
        ..add(lenData.buffer.asUint8List())
        ..add(serialized);
    }

    return builder.toBytes();
  }

  /// Deserializes a batch of events.
  List<LedgerEvent> deserializeBatch(Uint8List data) {
    var offset = 0;
    final countData = ByteData.sublistView(data, 0, 4);
    final count = countData.getInt32(0);
    offset = 4;

    final events = <LedgerEvent>[];
    for (var i = 0; i < count; i++) {
      final lenData = ByteData.sublistView(data, offset, offset + 4);
      final length = lenData.getInt32(0);
      offset += 4;
      final eventBytes = Uint8List.sublistView(data, offset, offset + length);
      events.add(deserialize(eventBytes));
      offset += length;
    }

    return events;
  }

  void _writeString(BytesBuilder builder, String value) {
    _writeBytes(builder, Uint8List.fromList(utf8.encode(value)));
  }

  void _writeBytes(BytesBuilder builder, Uint8List bytes) {
    builder
      ..add((ByteData(4)..setInt32(0, bytes.length)).buffer.asUint8List())
      ..add(bytes);
  }
}
