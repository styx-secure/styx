import 'dart:typed_data';

import 'package:styx_transport/styx_transport.dart';
import 'package:test/test.dart';

void main() {
  test('TransportMessage round-trip toJson/fromJson', () {
    final msg = TransportMessage(
      id: 'test-1',
      senderPubkey: 'sender-hex',
      recipientPubkey: 'recipient-hex',
      payload: Uint8List.fromList([1, 2, 3]),
      timestamp: DateTime.utc(2026, 2, 24),
    );

    final json = msg.toJson();
    final restored = TransportMessage.fromJson(json);

    expect(restored.id, msg.id);
    expect(restored.senderPubkey, msg.senderPubkey);
    expect(restored.recipientPubkey, msg.recipientPubkey);
    expect(restored.payload, equals(msg.payload));
  });

  test('TransportState has expected values', () {
    expect(TransportState.values, hasLength(3));
    expect(
      TransportState.values,
      containsAll([
        TransportState.disconnected,
        TransportState.connecting,
        TransportState.connected,
      ]),
    );
  });
}
