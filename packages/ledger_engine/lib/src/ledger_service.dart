import 'dart:async';

import 'package:drift/drift.dart' hide isNotNull, isNull;
import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_ledger_engine/src/chain_validator.dart';
import 'package:styx_ledger_engine/src/event_factory.dart';
import 'package:styx_ledger_engine/src/event_type.dart';
import 'package:styx_ledger_engine/src/hlc.dart';
import 'package:styx_ledger_engine/src/ledger_event.dart';
import 'package:styx_ledger_engine/src/vector_clock.dart';
import 'package:styx_storage/styx_storage.dart';

/// Façade for ledger operations.
class LedgerService {
  /// Creates a [LedgerService].
  LedgerService({
    required EventFactory eventFactory,
    required ChainValidator chainValidator,
    required EventDao eventDao,
    required String localPeerRole,
  })  : _eventFactory = eventFactory,
        _chainValidator = chainValidator,
        _eventDao = eventDao,
        _localPeerRole = localPeerRole;

  final EventFactory _eventFactory;
  final ChainValidator _chainValidator;
  final EventDao _eventDao;
  final String _localPeerRole;

  VectorClock _currentVc = const VectorClock.zero();

  /// Appends a new event to the local chain.
  Future<LedgerEvent> appendEvent({
    required EventType type,
    required Uint8List payload,
    required StyxPrivateKey privateKey,
    required StyxPublicKey publicKey,
  }) async {
    final latestDb = await _eventDao.getLatestEvent();
    final previous = latestDb != null ? _dbEventToLedgerEvent(latestDb) : null;

    if (previous != null) {
      _currentVc = previous.vectorClock;
    }

    final event = await _eventFactory.createEvent(
      type: type,
      payload: payload,
      privateKey: privateKey,
      publicKey: publicKey,
      previousEvent: previous,
      currentVectorClock: _currentVc,
      localPeerRole: _localPeerRole,
    );

    _currentVc = event.vectorClock;

    await _eventDao.insertEvent(
      EventsCompanion.insert(
        eventId: event.eventId,
        eventType: event.eventType.name,
        payloadEncrypted: Value(event.payload),
        previousHash: Value(event.previousHash),
        eventHash: event.eventHash,
        hlcTimestamp: event.hlc.timestamp.toIso8601String(),
        hlcNodeId: event.hlc.nodeId,
        hlcCounter: event.hlc.counter,
        vectorClockA: Value(event.vectorClock.a),
        vectorClockB: Value(event.vectorClock.b),
        senderPubkey: event.senderPubkey,
        signature: event.signature,
        createdAt: event.createdAt,
      ),
    );

    return event;
  }

  /// Retrieves the full event history.
  Future<List<LedgerEvent>> getHistory() async {
    final dbEvents = await _eventDao.getAllEventsOrdered();
    return dbEvents.map(_dbEventToLedgerEvent).toList();
  }

  /// Validates the entire chain.
  Future<ChainValidationError?> validateChain() async {
    final history = await getHistory();
    return _chainValidator.validateFullChain(history);
  }

  /// Returns the latest event, or `null` if the chain is empty.
  Future<LedgerEvent?> getLatestEvent() async {
    final dbEvent = await _eventDao.getLatestEvent();
    if (dbEvent == null) return null;
    return _dbEventToLedgerEvent(dbEvent);
  }

  /// Reactive stream of new events.
  Stream<LedgerEvent> watchNewEvents() {
    var lastCount = 0;
    return _eventDao.watchEvents().expand((events) {
      final newEvents = events.skip(lastCount).toList();
      lastCount = events.length;
      return newEvents.map(_dbEventToLedgerEvent);
    });
  }

  static LedgerEvent _dbEventToLedgerEvent(Event dbEvent) {
    return LedgerEvent(
      eventId: dbEvent.eventId,
      eventType: EventType.values.byName(dbEvent.eventType),
      payload: dbEvent.payloadEncrypted,
      previousHash: dbEvent.previousHash,
      eventHash: dbEvent.eventHash,
      hlc: HybridLogicalClock(
        timestamp: DateTime.parse(dbEvent.hlcTimestamp),
        counter: dbEvent.hlcCounter,
        nodeId: dbEvent.hlcNodeId,
      ),
      vectorClock: VectorClock(
        a: dbEvent.vectorClockA,
        b: dbEvent.vectorClockB,
      ),
      senderPubkey: dbEvent.senderPubkey,
      signature: dbEvent.signature,
      createdAt: dbEvent.createdAt,
      isPruned: dbEvent.isPruned,
    );
  }
}
