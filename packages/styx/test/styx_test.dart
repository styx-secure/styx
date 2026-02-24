import 'dart:typed_data';

import 'package:styx/styx.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:test/test.dart';

void main() {
  test('QrPairingData can be constructed and round-tripped', () {
    final key = StyxPublicKey.fromHex('aa' * 32);
    final nonce = Uint8List(16);
    final data = QrPairingData(
      publicKey: key,
      nonce: nonce,
    );

    final payload = data.toQrPayload();
    final restored = QrPairingData.fromQrPayload(payload);

    expect(restored.publicKey.toHex(), equals(key.toHex()));
    expect(restored.nonce, equals(nonce));
    expect(restored.relayHints, isNull);
  });
}
