// avoid_print: this is a CLI generator that reports progress on stdout by design.
// lines_longer_than_80_chars: the interop-diff reference table below holds long
// descriptive strings that are clearer kept on a single line than wrapped.
// ignore_for_file: avoid_print, lines_longer_than_80_chars
/// Generates interoperability test vectors from the Dart implementation.
///
/// Run: cd test_integration && dart run bin/generate_vectors.dart
/// Output: vectors/dart_vectors.json
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:styx/styx.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_ledger_engine/styx_ledger_engine.dart';

String _hex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

String _b64(Uint8List bytes) => base64Encode(bytes);

Uint8List _utf8(String s) => Uint8List.fromList(utf8.encode(s));

Future<void> main() async {
  final vectors = <String, dynamic>{};

  // --- 1. Identity ---
  final privateKeyBytes = Uint8List.fromList(List.generate(32, (i) => i + 1));
  final identityManager = IdentityManager();
  final keyPair = await identityManager.importPrivateKey(privateKeyBytes);
  final nodeId = keyPair.publicKey.toHex().substring(0, 8);

  vectors['identity'] = {
    'privateKeyHex': _hex(privateKeyBytes),
    'publicKeyHex': keyPair.publicKey.toHex(),
    'nodeId': nodeId,
  };

  // --- 2. Signing ---
  final signer = Signer();
  final verifier = Verifier();
  final payload = _utf8('Hello, Styx interop!');
  final signature = await signer.sign(payload, keyPair.privateKey);
  final isValid = await verifier.verify(
    payload: payload,
    signatureBytes: signature,
    publicKey: keyPair.publicKey,
  );

  vectors['signing'] = {
    'payload': _b64(payload),
    'payloadUtf8': 'Hello, Styx interop!',
    'signatureHex': _hex(signature),
    'signatureLength': signature.length,
    'valid': isValid,
  };

  // --- 3. Hashing ---
  final hasher = Hasher();
  final hashInput = _utf8('test data for hashing');
  final hashResult = hasher.hash(hashInput);

  final prevHash = hasher.hash(_utf8('previous'));
  final chainPayload = _utf8('chain payload');
  final chainResult = hasher.chainHash(
    previousHash: prevHash,
    payload: chainPayload,
  );
  final chainGenesisResult = hasher.chainHash(
    previousHash: null,
    payload: chainPayload,
  );

  final seg1 = _utf8('segment-one');
  final seg2 = _utf8('segment-two');
  final seg3 = _utf8('segment-three');
  final compositeResult = hasher.compositeHash([seg1, seg2, seg3]);

  vectors['hashing'] = {
    'input': _b64(hashInput),
    'inputUtf8': 'test data for hashing',
    'sha256': _hex(hashResult),
    'chainHash': {
      'previousHash': _b64(prevHash),
      'previousHashHex': _hex(prevHash),
      'payload': _b64(chainPayload),
      'result': _hex(chainResult),
    },
    'chainHashGenesis': {
      'payload': _b64(chainPayload),
      'result': _hex(chainGenesisResult),
    },
    'compositeHash': {
      'segments': [_b64(seg1), _b64(seg2), _b64(seg3)],
      'segmentsUtf8': ['segment-one', 'segment-two', 'segment-three'],
      'result': _hex(compositeResult),
    },
  };

  // --- 4. HLC ---
  final hlcTimestamp = DateTime.utc(2026, 1, 15, 10, 30);
  final hlc = HybridLogicalClock(
    timestamp: hlcTimestamp,
    counter: 42,
    nodeId: 'a1b2c3d4',
  );

  vectors['hlc'] = {
    'timestamp': hlcTimestamp.toIso8601String(),
    'counter': 42,
    'nodeId': 'a1b2c3d4',
    'canonical': hlc.toCanonical(),
    'bytes': _b64(hlc.toBytes()),
    'bytesHex': _hex(hlc.toBytes()),
  };

  // --- 5. Vector Clock ---
  const vc = VectorClock(a: 5, b: 3);
  vectors['vectorClock'] = {
    'a': 5,
    'b': 3,
    'total': vc.total,
    'bytes': _b64(vc.toBytes()),
    'bytesHex': _hex(vc.toBytes()),
    'json': vc.toJson(),
  };

  final vcIncrA = vc.increment('A');
  final vcIncrB = vc.increment('B');
  const vc2 = VectorClock(a: 3, b: 7);
  final vcMerged = vc.merge(vc2);

  vectors['vectorClockOps'] = {
    'incrementA': vcIncrA.toJson(),
    'incrementB': vcIncrB.toJson(),
    'mergeWith': vc2.toJson(),
    'mergeResult': vcMerged.toJson(),
  };

  // --- 6. Event Hash ---
  const eventPreviousHash =
      'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';
  const eventType = EventType.transaction;
  final eventPayload = _utf8('{"amount": 100}');
  final eventHlcBytes = hlc.toBytes();

  final eventHashSegments = <Uint8List>[
    _utf8(eventPreviousHash),
    _utf8(eventType.name),
    eventPayload,
    eventHlcBytes,
  ];
  final eventHashResult = hasher.compositeHash(eventHashSegments);

  vectors['eventHash'] = {
    'previousHash': eventPreviousHash,
    'eventType': eventType.name,
    'payload': _b64(eventPayload),
    'payloadUtf8': '{"amount": 100}',
    'hlcBytes': _b64(eventHlcBytes),
    'result': _hex(eventHashResult),
  };

  final genesisSegments = <Uint8List>[
    _utf8(eventType.name),
    eventPayload,
    eventHlcBytes,
  ];
  final genesisHashResult = hasher.compositeHash(genesisSegments);

  vectors['eventHashGenesis'] = {
    'eventType': eventType.name,
    'payload': _b64(eventPayload),
    'hlcBytes': _b64(eventHlcBytes),
    'result': _hex(genesisHashResult),
  };

  // --- 7. Shamir ---
  final secret = Uint8List.fromList([42, 137, 255, 0, 100, 200, 50, 75]);
  final splitter = ShamirSplitter();
  final shares = splitter.split(
    secret: secret,
  );

  final reconstructor = ShamirReconstructor();
  final reconstructed = reconstructor.reconstruct([shares[0], shares[2]]);

  vectors['shamir'] = {
    'secret': _b64(secret),
    'secretHex': _hex(secret),
    'threshold': 2,
    'totalShares': 3,
    'shares': shares
        .map(
          (s) => {
            'index': s.index,
            'data': _b64(s.data),
            'serialized': s.serialize(),
          },
        )
        .toList(),
    'reconstructedFromShares_0_2': _hex(reconstructed),
    'reconstructionMatches': _hex(reconstructed) == _hex(secret),
  };

  // --- 8. QR Pairing ---
  final qrData = QrPairingData(
    publicKey: keyPair.publicKey,
    nonce: Uint8List.fromList(List.generate(16, (i) => i * 10)),
    relayHints: const ['wss://relay.example.com'],
  );
  final qrPayload = qrData.toQrPayload();

  vectors['qrPairing'] = {
    'publicKeyHex': keyPair.publicKey.toHex(),
    'nonce': _b64(Uint8List.fromList(List.generate(16, (i) => i * 10))),
    'relayHints': ['wss://relay.example.com'],
    'payload': qrPayload,
    'format': 'json',
  };

  // --- 9. SPAKE2 ---
  final spake2 = Spake2Protocol();
  const mnemonic = 'abandon ability able about above absent';
  final spake2Password = spake2.mnemonicToPassword(mnemonic);

  vectors['spake2'] = {
    'mnemonic': mnemonic,
    'passwordHex': _hex(spake2Password),
    'passwordFormat': 'utf8(mnemonic.trim().toLowerCase())',
  };

  // --- 10. Mnemonic Seed ---
  final mnemonicGen = MnemonicGenerator();
  final seed = await mnemonicGen.mnemonicToSeed(mnemonic);

  vectors['mnemonicSeed'] = {
    'mnemonic': mnemonic,
    'seedHex': _hex(seed),
    'seedLength': seed.length,
    'params': {
      'hash': 'HMAC-SHA512',
      'iterations': 2048,
      'dkLenBytes': 64,
      'salt': 'mnemonic',
    },
  };

  // --- 11. Double Check ---
  final sessionKey = hasher.hash(_utf8('test-session-key'));
  final sessionVerifier = SessionVerifier();
  final doubleCheckCode = sessionVerifier.generateDoubleCheckCode(sessionKey);

  vectors['doubleCheck'] = {
    'sessionKeyHex': _hex(sessionKey),
    'code': doubleCheckCode,
    'codeLength': doubleCheckCode.length,
  };

  // --- Incompatibilities Summary ---
  vectors['_incompatibilities'] = {
    'hlcCounter': 'Dart=decimal padLeft(4,"0"), JS=hex padStart(4,"0")',
    'qrFormat': 'Dart=JSON, JS=binary base64',
    'shamirSerialization':
        'Dart=styx-share-v1:index:base64, JS=base64(indexByte||data)',
    'encryption':
        'Dart=ChaCha20-Poly1305 nonce=12, JS=XChaCha20-Poly1305 nonce=24',
    'spake2Password':
        'Dart=utf8(mnemonic), JS=sha256("SPAKE2-P256-password"||password)',
    'spake2MessageFormat':
        'Dart=uncompressed(65 bytes), JS=compressed(33 bytes)',
    'spake2Transcript':
        'Dart=SHA256(pA||pB||K), JS=SHA256(K||myPoint||peerPoint||password)',
    'spake2Confirmation':
        'Dart=HMAC(confirmKey, roleByte||ourMsg||peerMsg), JS=HMAC(sessionKey, tagString)',
    'mnemonicToSeed':
        'Dart=PBKDF2-SHA512 2048iter 64bytes salt=mnemonic, JS=PBKDF2-SHA256 100000iter 32bytes salt=styx-mnemonic-seed',
    'hkdfInfo': 'Dart=styx-transport-v1, JS=styx-send-a+orderedPubs',
  };

  // --- Meta ---
  vectors['_meta'] = {
    'generatedAt': DateTime.now().toUtc().toIso8601String(),
    'generator': 'Dart (styx_crypto_core + styx_ledger_engine + styx)',
    'dartSdkVersion': Platform.version.split(' ').first,
  };

  // --- Write output ---
  final outputFile = File('vectors/dart_vectors.json');
  const encoder = JsonEncoder.withIndent('  ');
  await outputFile.writeAsString(encoder.convert(vectors));
  print('Generated: ${outputFile.path}');
  print(
    'Vectors: ${vectors.keys.where((k) => !k.startsWith('_')).length} sections',
  );
}
