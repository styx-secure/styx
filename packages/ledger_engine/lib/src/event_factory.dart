import 'dart:convert';
import 'dart:typed_data';

import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_ledger_engine/src/event_type.dart';
import 'package:styx_ledger_engine/src/hlc.dart';
import 'package:styx_ledger_engine/src/ledger_event.dart';
import 'package:styx_ledger_engine/src/vector_clock.dart';
import 'package:uuid/uuid.dart';

const _uuid = Uuid();

/// Creates signed and hashed events for the ledger chain.
class EventFactory {
  /// Creates an [EventFactory] with the given [signer] and [hasher].
  EventFactory({required Signer signer, required Hasher hasher})
    : _signer = signer,
      _hasher = hasher;

  final Signer _signer;
  final Hasher _hasher;

  /// Creates a new event appended to the chain.
  ///
  /// 1. Generates a UUID v4 eventId.
  /// 2. Computes HLC from [previousEvent].
  /// 3. Increments [currentVectorClock] for [localPeerRole].
  /// 4. Computes eventHash = SHA-256(previousHash || eventType || payload
  ///    || hlc.toBytes()).
  /// 5. Signs with [privateKey].
  Future<LedgerEvent> createEvent({
    required EventType type,
    required Uint8List payload,
    required StyxPrivateKey privateKey,
    required StyxPublicKey publicKey,
    required LedgerEvent? previousEvent,
    required VectorClock currentVectorClock,
    required String localPeerRole,
  }) async {
    final eventId = _uuid.v4();
    final nodeId = publicKey.toHex().substring(0, 8);

    final hlc = HybridLogicalClock.now(
      previous: previousEvent?.hlc,
      nodeId: nodeId,
    );

    final vc = currentVectorClock.increment(localPeerRole);
    final previousHash = previousEvent?.eventHash;

    final hashBytes = _computeHashBytes(
      previousHash: previousHash,
      eventType: type,
      payload: payload,
      hlcBytes: hlc.toBytes(),
    );
    final eventHash = _hexEncode(hashBytes);

    // Sign the hash.
    final signature = await _signer.sign(hashBytes, privateKey);

    return LedgerEvent(
      eventId: eventId,
      eventType: type,
      payload: payload,
      previousHash: previousHash,
      eventHash: eventHash,
      hlc: hlc,
      vectorClock: vc,
      senderPubkey: publicKey.toHex(),
      signature: signature,
      createdAt: DateTime.now().toUtc(),
    );
  }

  /// Creates the genesis event (first event of the chain).
  Future<LedgerEvent> createGenesisEvent({
    required StyxPrivateKey privateKey,
    required StyxPublicKey publicKey,
    required String nodeId,
  }) async {
    final eventId = _uuid.v4();
    final payload = Uint8List.fromList(utf8.encode('genesis'));

    final hlc = HybridLogicalClock.now(previous: null, nodeId: nodeId);
    const vc = VectorClock(a: 1, b: 0);

    final hashBytes = _computeHashBytes(
      previousHash: null,
      eventType: EventType.config,
      payload: payload,
      hlcBytes: hlc.toBytes(),
    );
    final eventHash = _hexEncode(hashBytes);

    final signature = await _signer.sign(hashBytes, privateKey);

    return LedgerEvent(
      eventId: eventId,
      eventType: EventType.config,
      payload: payload,
      previousHash: null,
      eventHash: eventHash,
      hlc: hlc,
      vectorClock: vc,
      senderPubkey: publicKey.toHex(),
      signature: signature,
      createdAt: DateTime.now().toUtc(),
    );
  }

  /// Computes the event hash from its components.
  ///
  /// hash = SHA-256(previousHash || eventType || payload || hlcBytes)
  Uint8List computeHashBytes({
    required String? previousHash,
    required EventType eventType,
    required Uint8List? payload,
    required Uint8List hlcBytes,
  }) {
    return _computeHashBytes(
      previousHash: previousHash,
      eventType: eventType,
      payload: payload ?? Uint8List(0),
      hlcBytes: hlcBytes,
    );
  }

  Uint8List _computeHashBytes({
    required String? previousHash,
    required EventType eventType,
    required Uint8List payload,
    required Uint8List hlcBytes,
  }) {
    final segments = <Uint8List>[
      if (previousHash != null) Uint8List.fromList(utf8.encode(previousHash)),
      Uint8List.fromList(utf8.encode(eventType.name)),
      payload,
      hlcBytes,
    ];
    return _hasher.compositeHash(segments);
  }

  static String _hexEncode(Uint8List bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}
