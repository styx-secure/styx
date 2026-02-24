import 'dart:typed_data';

import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_transport/src/nostr/nostr_encryptor.dart';
import 'package:test/test.dart';

void main() {
  late X25519KeyPair aliceKeyPair;
  late X25519KeyPair bobKeyPair;
  late NostrEncryptor aliceEncryptor;
  late NostrEncryptor bobEncryptor;

  setUp(() async {
    final dh = DiffieHellman();
    aliceKeyPair = await dh.generateEphemeralKeyPair();
    bobKeyPair = await dh.generateEphemeralKeyPair();

    aliceEncryptor = NostrEncryptor(
      localPrivateKey: aliceKeyPair.privateKey,
      remotePublicKey: bobKeyPair.publicKey,
    );
    bobEncryptor = NostrEncryptor(
      localPrivateKey: bobKeyPair.privateKey,
      remotePublicKey: aliceKeyPair.publicKey,
    );

    await aliceEncryptor.initialize();
    await bobEncryptor.initialize();
  });

  // T7.1 — Round-trip encrypt/decrypt
  test('T7.1: round-trip encrypt/decrypt', () async {
    final plaintext = Uint8List.fromList(
      'Hello, Styx!'.codeUnits,
    );

    final encrypted = await aliceEncryptor.encrypt(plaintext);
    final decrypted = await bobEncryptor.decrypt(encrypted);

    expect(decrypted, equals(plaintext));
  });

  // T7.2 — Wrong key fails to decrypt
  test('T7.2: wrong key fails to decrypt', () async {
    final dh = DiffieHellman();
    final eveKeyPair = await dh.generateEphemeralKeyPair();

    final eveEncryptor = NostrEncryptor(
      localPrivateKey: eveKeyPair.privateKey,
      remotePublicKey: aliceKeyPair.publicKey,
    );
    await eveEncryptor.initialize();

    final plaintext = Uint8List.fromList('secret'.codeUnits);
    final encrypted = await aliceEncryptor.encrypt(plaintext);

    expect(
      () => eveEncryptor.decrypt(encrypted),
      throwsA(isA<Object>()),
    );
  });

  // T7.3 — Tampered ciphertext fails
  test('T7.3: tampered ciphertext is rejected', () async {
    final plaintext = Uint8List.fromList('integrity check'.codeUnits);
    final encrypted = await aliceEncryptor.encrypt(plaintext);

    // Flip a byte in the ciphertext (after nonce, before tag).
    encrypted[14] ^= 0xFF;

    expect(
      () => bobEncryptor.decrypt(encrypted),
      throwsA(isA<Object>()),
    );
  });

  // T7.4 — Nonce uniqueness
  test('T7.4: nonce is unique across encryptions', () async {
    final plaintext = Uint8List.fromList('same data'.codeUnits);

    final encrypted1 = await aliceEncryptor.encrypt(plaintext);
    final encrypted2 = await aliceEncryptor.encrypt(plaintext);

    // First 12 bytes are the nonce — they should differ.
    final nonce1 = encrypted1.sublist(0, 12);
    final nonce2 = encrypted2.sublist(0, 12);
    expect(nonce1, isNot(equals(nonce2)));
  });

  // T7.5 — Empty plaintext round-trip
  test('T7.5: empty plaintext round-trip', () async {
    final plaintext = Uint8List(0);

    final encrypted = await aliceEncryptor.encrypt(plaintext);
    final decrypted = await bobEncryptor.decrypt(encrypted);

    expect(decrypted, equals(plaintext));
  });

  // T7.6 — Large payload round-trip (64 KB)
  test('T7.6: large payload round-trip (64 KB)', () async {
    final plaintext = Uint8List(65536);
    for (var i = 0; i < plaintext.length; i++) {
      plaintext[i] = i & 0xFF;
    }

    final encrypted = await aliceEncryptor.encrypt(plaintext);
    final decrypted = await bobEncryptor.decrypt(encrypted);

    expect(decrypted, equals(plaintext));
  });
}
