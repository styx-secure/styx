// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'styx_database.dart';

// ignore_for_file: type=lint
class $EventsTable extends Events with TableInfo<$EventsTable, Event> {
  @override
  final GeneratedDatabase attachedDatabase;
  final String? _alias;
  $EventsTable(this.attachedDatabase, [this._alias]);
  static const VerificationMeta _idMeta = const VerificationMeta('id');
  @override
  late final GeneratedColumn<int> id = GeneratedColumn<int>(
    'id',
    aliasedName,
    false,
    hasAutoIncrement: true,
    type: DriftSqlType.int,
    requiredDuringInsert: false,
    defaultConstraints: GeneratedColumn.constraintIsAlways(
      'PRIMARY KEY AUTOINCREMENT',
    ),
  );
  static const VerificationMeta _eventIdMeta = const VerificationMeta(
    'eventId',
  );
  @override
  late final GeneratedColumn<String> eventId = GeneratedColumn<String>(
    'event_id',
    aliasedName,
    false,
    type: DriftSqlType.string,
    requiredDuringInsert: true,
    defaultConstraints: GeneratedColumn.constraintIsAlways('UNIQUE'),
  );
  static const VerificationMeta _eventTypeMeta = const VerificationMeta(
    'eventType',
  );
  @override
  late final GeneratedColumn<String> eventType = GeneratedColumn<String>(
    'event_type',
    aliasedName,
    false,
    type: DriftSqlType.string,
    requiredDuringInsert: true,
  );
  static const VerificationMeta _payloadEncryptedMeta = const VerificationMeta(
    'payloadEncrypted',
  );
  @override
  late final GeneratedColumn<Uint8List> payloadEncrypted =
      GeneratedColumn<Uint8List>(
        'payload_encrypted',
        aliasedName,
        true,
        type: DriftSqlType.blob,
        requiredDuringInsert: false,
      );
  static const VerificationMeta _previousHashMeta = const VerificationMeta(
    'previousHash',
  );
  @override
  late final GeneratedColumn<String> previousHash = GeneratedColumn<String>(
    'previous_hash',
    aliasedName,
    true,
    type: DriftSqlType.string,
    requiredDuringInsert: false,
  );
  static const VerificationMeta _eventHashMeta = const VerificationMeta(
    'eventHash',
  );
  @override
  late final GeneratedColumn<String> eventHash = GeneratedColumn<String>(
    'event_hash',
    aliasedName,
    false,
    type: DriftSqlType.string,
    requiredDuringInsert: true,
    defaultConstraints: GeneratedColumn.constraintIsAlways('UNIQUE'),
  );
  static const VerificationMeta _hlcTimestampMeta = const VerificationMeta(
    'hlcTimestamp',
  );
  @override
  late final GeneratedColumn<String> hlcTimestamp = GeneratedColumn<String>(
    'hlc_timestamp',
    aliasedName,
    false,
    type: DriftSqlType.string,
    requiredDuringInsert: true,
  );
  static const VerificationMeta _hlcNodeIdMeta = const VerificationMeta(
    'hlcNodeId',
  );
  @override
  late final GeneratedColumn<String> hlcNodeId = GeneratedColumn<String>(
    'hlc_node_id',
    aliasedName,
    false,
    type: DriftSqlType.string,
    requiredDuringInsert: true,
  );
  static const VerificationMeta _hlcCounterMeta = const VerificationMeta(
    'hlcCounter',
  );
  @override
  late final GeneratedColumn<int> hlcCounter = GeneratedColumn<int>(
    'hlc_counter',
    aliasedName,
    false,
    type: DriftSqlType.int,
    requiredDuringInsert: true,
  );
  static const VerificationMeta _vectorClockAMeta = const VerificationMeta(
    'vectorClockA',
  );
  @override
  late final GeneratedColumn<int> vectorClockA = GeneratedColumn<int>(
    'vector_clock_a',
    aliasedName,
    false,
    type: DriftSqlType.int,
    requiredDuringInsert: false,
    defaultValue: const Constant(0),
  );
  static const VerificationMeta _vectorClockBMeta = const VerificationMeta(
    'vectorClockB',
  );
  @override
  late final GeneratedColumn<int> vectorClockB = GeneratedColumn<int>(
    'vector_clock_b',
    aliasedName,
    false,
    type: DriftSqlType.int,
    requiredDuringInsert: false,
    defaultValue: const Constant(0),
  );
  static const VerificationMeta _senderPubkeyMeta = const VerificationMeta(
    'senderPubkey',
  );
  @override
  late final GeneratedColumn<String> senderPubkey = GeneratedColumn<String>(
    'sender_pubkey',
    aliasedName,
    false,
    type: DriftSqlType.string,
    requiredDuringInsert: true,
  );
  static const VerificationMeta _signatureMeta = const VerificationMeta(
    'signature',
  );
  @override
  late final GeneratedColumn<Uint8List> signature = GeneratedColumn<Uint8List>(
    'signature',
    aliasedName,
    false,
    type: DriftSqlType.blob,
    requiredDuringInsert: true,
  );
  static const VerificationMeta _createdAtMeta = const VerificationMeta(
    'createdAt',
  );
  @override
  late final GeneratedColumn<DateTime> createdAt = GeneratedColumn<DateTime>(
    'created_at',
    aliasedName,
    false,
    type: DriftSqlType.dateTime,
    requiredDuringInsert: true,
  );
  static const VerificationMeta _isPrunedMeta = const VerificationMeta(
    'isPruned',
  );
  @override
  late final GeneratedColumn<bool> isPruned = GeneratedColumn<bool>(
    'is_pruned',
    aliasedName,
    false,
    type: DriftSqlType.bool,
    requiredDuringInsert: false,
    defaultConstraints: GeneratedColumn.constraintIsAlways(
      'CHECK ("is_pruned" IN (0, 1))',
    ),
    defaultValue: const Constant(false),
  );
  @override
  List<GeneratedColumn> get $columns => [
    id,
    eventId,
    eventType,
    payloadEncrypted,
    previousHash,
    eventHash,
    hlcTimestamp,
    hlcNodeId,
    hlcCounter,
    vectorClockA,
    vectorClockB,
    senderPubkey,
    signature,
    createdAt,
    isPruned,
  ];
  @override
  String get aliasedName => _alias ?? actualTableName;
  @override
  String get actualTableName => $name;
  static const String $name = 'events';
  @override
  VerificationContext validateIntegrity(
    Insertable<Event> instance, {
    bool isInserting = false,
  }) {
    final context = VerificationContext();
    final data = instance.toColumns(true);
    if (data.containsKey('id')) {
      context.handle(_idMeta, id.isAcceptableOrUnknown(data['id']!, _idMeta));
    }
    if (data.containsKey('event_id')) {
      context.handle(
        _eventIdMeta,
        eventId.isAcceptableOrUnknown(data['event_id']!, _eventIdMeta),
      );
    } else if (isInserting) {
      context.missing(_eventIdMeta);
    }
    if (data.containsKey('event_type')) {
      context.handle(
        _eventTypeMeta,
        eventType.isAcceptableOrUnknown(data['event_type']!, _eventTypeMeta),
      );
    } else if (isInserting) {
      context.missing(_eventTypeMeta);
    }
    if (data.containsKey('payload_encrypted')) {
      context.handle(
        _payloadEncryptedMeta,
        payloadEncrypted.isAcceptableOrUnknown(
          data['payload_encrypted']!,
          _payloadEncryptedMeta,
        ),
      );
    }
    if (data.containsKey('previous_hash')) {
      context.handle(
        _previousHashMeta,
        previousHash.isAcceptableOrUnknown(
          data['previous_hash']!,
          _previousHashMeta,
        ),
      );
    }
    if (data.containsKey('event_hash')) {
      context.handle(
        _eventHashMeta,
        eventHash.isAcceptableOrUnknown(data['event_hash']!, _eventHashMeta),
      );
    } else if (isInserting) {
      context.missing(_eventHashMeta);
    }
    if (data.containsKey('hlc_timestamp')) {
      context.handle(
        _hlcTimestampMeta,
        hlcTimestamp.isAcceptableOrUnknown(
          data['hlc_timestamp']!,
          _hlcTimestampMeta,
        ),
      );
    } else if (isInserting) {
      context.missing(_hlcTimestampMeta);
    }
    if (data.containsKey('hlc_node_id')) {
      context.handle(
        _hlcNodeIdMeta,
        hlcNodeId.isAcceptableOrUnknown(data['hlc_node_id']!, _hlcNodeIdMeta),
      );
    } else if (isInserting) {
      context.missing(_hlcNodeIdMeta);
    }
    if (data.containsKey('hlc_counter')) {
      context.handle(
        _hlcCounterMeta,
        hlcCounter.isAcceptableOrUnknown(data['hlc_counter']!, _hlcCounterMeta),
      );
    } else if (isInserting) {
      context.missing(_hlcCounterMeta);
    }
    if (data.containsKey('vector_clock_a')) {
      context.handle(
        _vectorClockAMeta,
        vectorClockA.isAcceptableOrUnknown(
          data['vector_clock_a']!,
          _vectorClockAMeta,
        ),
      );
    }
    if (data.containsKey('vector_clock_b')) {
      context.handle(
        _vectorClockBMeta,
        vectorClockB.isAcceptableOrUnknown(
          data['vector_clock_b']!,
          _vectorClockBMeta,
        ),
      );
    }
    if (data.containsKey('sender_pubkey')) {
      context.handle(
        _senderPubkeyMeta,
        senderPubkey.isAcceptableOrUnknown(
          data['sender_pubkey']!,
          _senderPubkeyMeta,
        ),
      );
    } else if (isInserting) {
      context.missing(_senderPubkeyMeta);
    }
    if (data.containsKey('signature')) {
      context.handle(
        _signatureMeta,
        signature.isAcceptableOrUnknown(data['signature']!, _signatureMeta),
      );
    } else if (isInserting) {
      context.missing(_signatureMeta);
    }
    if (data.containsKey('created_at')) {
      context.handle(
        _createdAtMeta,
        createdAt.isAcceptableOrUnknown(data['created_at']!, _createdAtMeta),
      );
    } else if (isInserting) {
      context.missing(_createdAtMeta);
    }
    if (data.containsKey('is_pruned')) {
      context.handle(
        _isPrunedMeta,
        isPruned.isAcceptableOrUnknown(data['is_pruned']!, _isPrunedMeta),
      );
    }
    return context;
  }

  @override
  Set<GeneratedColumn> get $primaryKey => {id};
  @override
  Event map(Map<String, dynamic> data, {String? tablePrefix}) {
    final effectivePrefix = tablePrefix != null ? '$tablePrefix.' : '';
    return Event(
      id: attachedDatabase.typeMapping.read(
        DriftSqlType.int,
        data['${effectivePrefix}id'],
      )!,
      eventId: attachedDatabase.typeMapping.read(
        DriftSqlType.string,
        data['${effectivePrefix}event_id'],
      )!,
      eventType: attachedDatabase.typeMapping.read(
        DriftSqlType.string,
        data['${effectivePrefix}event_type'],
      )!,
      payloadEncrypted: attachedDatabase.typeMapping.read(
        DriftSqlType.blob,
        data['${effectivePrefix}payload_encrypted'],
      ),
      previousHash: attachedDatabase.typeMapping.read(
        DriftSqlType.string,
        data['${effectivePrefix}previous_hash'],
      ),
      eventHash: attachedDatabase.typeMapping.read(
        DriftSqlType.string,
        data['${effectivePrefix}event_hash'],
      )!,
      hlcTimestamp: attachedDatabase.typeMapping.read(
        DriftSqlType.string,
        data['${effectivePrefix}hlc_timestamp'],
      )!,
      hlcNodeId: attachedDatabase.typeMapping.read(
        DriftSqlType.string,
        data['${effectivePrefix}hlc_node_id'],
      )!,
      hlcCounter: attachedDatabase.typeMapping.read(
        DriftSqlType.int,
        data['${effectivePrefix}hlc_counter'],
      )!,
      vectorClockA: attachedDatabase.typeMapping.read(
        DriftSqlType.int,
        data['${effectivePrefix}vector_clock_a'],
      )!,
      vectorClockB: attachedDatabase.typeMapping.read(
        DriftSqlType.int,
        data['${effectivePrefix}vector_clock_b'],
      )!,
      senderPubkey: attachedDatabase.typeMapping.read(
        DriftSqlType.string,
        data['${effectivePrefix}sender_pubkey'],
      )!,
      signature: attachedDatabase.typeMapping.read(
        DriftSqlType.blob,
        data['${effectivePrefix}signature'],
      )!,
      createdAt: attachedDatabase.typeMapping.read(
        DriftSqlType.dateTime,
        data['${effectivePrefix}created_at'],
      )!,
      isPruned: attachedDatabase.typeMapping.read(
        DriftSqlType.bool,
        data['${effectivePrefix}is_pruned'],
      )!,
    );
  }

  @override
  $EventsTable createAlias(String alias) {
    return $EventsTable(attachedDatabase, alias);
  }
}

class Event extends DataClass implements Insertable<Event> {
  /// Auto-incrementing primary key.
  final int id;

  /// Unique event identifier (UUID).
  final String eventId;

  /// Event type: TRANSACTION, SOS, CONFIG, REKEY, MERGE,
  /// PRUNE_REQUEST, PRUNE_ACK, MESSAGE.
  final String eventType;

  /// Encrypted payload (null for pruned events).
  final Uint8List? payloadEncrypted;

  /// Hash of the previous event (null only for genesis).
  final String? previousHash;

  /// SHA-256 hash of this event.
  final String eventHash;

  /// HLC timestamp in ISO 8601 format with counter.
  final String hlcTimestamp;

  /// HLC node identifier.
  final String hlcNodeId;

  /// HLC logical counter.
  final int hlcCounter;

  /// Vector clock component for peer A.
  final int vectorClockA;

  /// Vector clock component for peer B.
  final int vectorClockB;

  /// Hex-encoded Ed25519 public key of sender.
  final String senderPubkey;

  /// Ed25519 signature (64 bytes).
  final Uint8List signature;

  /// Timestamp of insertion into local DB.
  final DateTime createdAt;

  /// Whether the payload has been pruned (GDPR).
  final bool isPruned;
  const Event({
    required this.id,
    required this.eventId,
    required this.eventType,
    this.payloadEncrypted,
    this.previousHash,
    required this.eventHash,
    required this.hlcTimestamp,
    required this.hlcNodeId,
    required this.hlcCounter,
    required this.vectorClockA,
    required this.vectorClockB,
    required this.senderPubkey,
    required this.signature,
    required this.createdAt,
    required this.isPruned,
  });
  @override
  Map<String, Expression> toColumns(bool nullToAbsent) {
    final map = <String, Expression>{};
    map['id'] = Variable<int>(id);
    map['event_id'] = Variable<String>(eventId);
    map['event_type'] = Variable<String>(eventType);
    if (!nullToAbsent || payloadEncrypted != null) {
      map['payload_encrypted'] = Variable<Uint8List>(payloadEncrypted);
    }
    if (!nullToAbsent || previousHash != null) {
      map['previous_hash'] = Variable<String>(previousHash);
    }
    map['event_hash'] = Variable<String>(eventHash);
    map['hlc_timestamp'] = Variable<String>(hlcTimestamp);
    map['hlc_node_id'] = Variable<String>(hlcNodeId);
    map['hlc_counter'] = Variable<int>(hlcCounter);
    map['vector_clock_a'] = Variable<int>(vectorClockA);
    map['vector_clock_b'] = Variable<int>(vectorClockB);
    map['sender_pubkey'] = Variable<String>(senderPubkey);
    map['signature'] = Variable<Uint8List>(signature);
    map['created_at'] = Variable<DateTime>(createdAt);
    map['is_pruned'] = Variable<bool>(isPruned);
    return map;
  }

  EventsCompanion toCompanion(bool nullToAbsent) {
    return EventsCompanion(
      id: Value(id),
      eventId: Value(eventId),
      eventType: Value(eventType),
      payloadEncrypted: payloadEncrypted == null && nullToAbsent
          ? const Value.absent()
          : Value(payloadEncrypted),
      previousHash: previousHash == null && nullToAbsent
          ? const Value.absent()
          : Value(previousHash),
      eventHash: Value(eventHash),
      hlcTimestamp: Value(hlcTimestamp),
      hlcNodeId: Value(hlcNodeId),
      hlcCounter: Value(hlcCounter),
      vectorClockA: Value(vectorClockA),
      vectorClockB: Value(vectorClockB),
      senderPubkey: Value(senderPubkey),
      signature: Value(signature),
      createdAt: Value(createdAt),
      isPruned: Value(isPruned),
    );
  }

  factory Event.fromJson(
    Map<String, dynamic> json, {
    ValueSerializer? serializer,
  }) {
    serializer ??= driftRuntimeOptions.defaultSerializer;
    return Event(
      id: serializer.fromJson<int>(json['id']),
      eventId: serializer.fromJson<String>(json['eventId']),
      eventType: serializer.fromJson<String>(json['eventType']),
      payloadEncrypted: serializer.fromJson<Uint8List?>(
        json['payloadEncrypted'],
      ),
      previousHash: serializer.fromJson<String?>(json['previousHash']),
      eventHash: serializer.fromJson<String>(json['eventHash']),
      hlcTimestamp: serializer.fromJson<String>(json['hlcTimestamp']),
      hlcNodeId: serializer.fromJson<String>(json['hlcNodeId']),
      hlcCounter: serializer.fromJson<int>(json['hlcCounter']),
      vectorClockA: serializer.fromJson<int>(json['vectorClockA']),
      vectorClockB: serializer.fromJson<int>(json['vectorClockB']),
      senderPubkey: serializer.fromJson<String>(json['senderPubkey']),
      signature: serializer.fromJson<Uint8List>(json['signature']),
      createdAt: serializer.fromJson<DateTime>(json['createdAt']),
      isPruned: serializer.fromJson<bool>(json['isPruned']),
    );
  }
  @override
  Map<String, dynamic> toJson({ValueSerializer? serializer}) {
    serializer ??= driftRuntimeOptions.defaultSerializer;
    return <String, dynamic>{
      'id': serializer.toJson<int>(id),
      'eventId': serializer.toJson<String>(eventId),
      'eventType': serializer.toJson<String>(eventType),
      'payloadEncrypted': serializer.toJson<Uint8List?>(payloadEncrypted),
      'previousHash': serializer.toJson<String?>(previousHash),
      'eventHash': serializer.toJson<String>(eventHash),
      'hlcTimestamp': serializer.toJson<String>(hlcTimestamp),
      'hlcNodeId': serializer.toJson<String>(hlcNodeId),
      'hlcCounter': serializer.toJson<int>(hlcCounter),
      'vectorClockA': serializer.toJson<int>(vectorClockA),
      'vectorClockB': serializer.toJson<int>(vectorClockB),
      'senderPubkey': serializer.toJson<String>(senderPubkey),
      'signature': serializer.toJson<Uint8List>(signature),
      'createdAt': serializer.toJson<DateTime>(createdAt),
      'isPruned': serializer.toJson<bool>(isPruned),
    };
  }

  Event copyWith({
    int? id,
    String? eventId,
    String? eventType,
    Value<Uint8List?> payloadEncrypted = const Value.absent(),
    Value<String?> previousHash = const Value.absent(),
    String? eventHash,
    String? hlcTimestamp,
    String? hlcNodeId,
    int? hlcCounter,
    int? vectorClockA,
    int? vectorClockB,
    String? senderPubkey,
    Uint8List? signature,
    DateTime? createdAt,
    bool? isPruned,
  }) => Event(
    id: id ?? this.id,
    eventId: eventId ?? this.eventId,
    eventType: eventType ?? this.eventType,
    payloadEncrypted: payloadEncrypted.present
        ? payloadEncrypted.value
        : this.payloadEncrypted,
    previousHash: previousHash.present ? previousHash.value : this.previousHash,
    eventHash: eventHash ?? this.eventHash,
    hlcTimestamp: hlcTimestamp ?? this.hlcTimestamp,
    hlcNodeId: hlcNodeId ?? this.hlcNodeId,
    hlcCounter: hlcCounter ?? this.hlcCounter,
    vectorClockA: vectorClockA ?? this.vectorClockA,
    vectorClockB: vectorClockB ?? this.vectorClockB,
    senderPubkey: senderPubkey ?? this.senderPubkey,
    signature: signature ?? this.signature,
    createdAt: createdAt ?? this.createdAt,
    isPruned: isPruned ?? this.isPruned,
  );
  Event copyWithCompanion(EventsCompanion data) {
    return Event(
      id: data.id.present ? data.id.value : this.id,
      eventId: data.eventId.present ? data.eventId.value : this.eventId,
      eventType: data.eventType.present ? data.eventType.value : this.eventType,
      payloadEncrypted: data.payloadEncrypted.present
          ? data.payloadEncrypted.value
          : this.payloadEncrypted,
      previousHash: data.previousHash.present
          ? data.previousHash.value
          : this.previousHash,
      eventHash: data.eventHash.present ? data.eventHash.value : this.eventHash,
      hlcTimestamp: data.hlcTimestamp.present
          ? data.hlcTimestamp.value
          : this.hlcTimestamp,
      hlcNodeId: data.hlcNodeId.present ? data.hlcNodeId.value : this.hlcNodeId,
      hlcCounter: data.hlcCounter.present
          ? data.hlcCounter.value
          : this.hlcCounter,
      vectorClockA: data.vectorClockA.present
          ? data.vectorClockA.value
          : this.vectorClockA,
      vectorClockB: data.vectorClockB.present
          ? data.vectorClockB.value
          : this.vectorClockB,
      senderPubkey: data.senderPubkey.present
          ? data.senderPubkey.value
          : this.senderPubkey,
      signature: data.signature.present ? data.signature.value : this.signature,
      createdAt: data.createdAt.present ? data.createdAt.value : this.createdAt,
      isPruned: data.isPruned.present ? data.isPruned.value : this.isPruned,
    );
  }

  @override
  String toString() {
    return (StringBuffer('Event(')
          ..write('id: $id, ')
          ..write('eventId: $eventId, ')
          ..write('eventType: $eventType, ')
          ..write('payloadEncrypted: $payloadEncrypted, ')
          ..write('previousHash: $previousHash, ')
          ..write('eventHash: $eventHash, ')
          ..write('hlcTimestamp: $hlcTimestamp, ')
          ..write('hlcNodeId: $hlcNodeId, ')
          ..write('hlcCounter: $hlcCounter, ')
          ..write('vectorClockA: $vectorClockA, ')
          ..write('vectorClockB: $vectorClockB, ')
          ..write('senderPubkey: $senderPubkey, ')
          ..write('signature: $signature, ')
          ..write('createdAt: $createdAt, ')
          ..write('isPruned: $isPruned')
          ..write(')'))
        .toString();
  }

  @override
  int get hashCode => Object.hash(
    id,
    eventId,
    eventType,
    $driftBlobEquality.hash(payloadEncrypted),
    previousHash,
    eventHash,
    hlcTimestamp,
    hlcNodeId,
    hlcCounter,
    vectorClockA,
    vectorClockB,
    senderPubkey,
    $driftBlobEquality.hash(signature),
    createdAt,
    isPruned,
  );
  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is Event &&
          other.id == this.id &&
          other.eventId == this.eventId &&
          other.eventType == this.eventType &&
          $driftBlobEquality.equals(
            other.payloadEncrypted,
            this.payloadEncrypted,
          ) &&
          other.previousHash == this.previousHash &&
          other.eventHash == this.eventHash &&
          other.hlcTimestamp == this.hlcTimestamp &&
          other.hlcNodeId == this.hlcNodeId &&
          other.hlcCounter == this.hlcCounter &&
          other.vectorClockA == this.vectorClockA &&
          other.vectorClockB == this.vectorClockB &&
          other.senderPubkey == this.senderPubkey &&
          $driftBlobEquality.equals(other.signature, this.signature) &&
          other.createdAt == this.createdAt &&
          other.isPruned == this.isPruned);
}

class EventsCompanion extends UpdateCompanion<Event> {
  final Value<int> id;
  final Value<String> eventId;
  final Value<String> eventType;
  final Value<Uint8List?> payloadEncrypted;
  final Value<String?> previousHash;
  final Value<String> eventHash;
  final Value<String> hlcTimestamp;
  final Value<String> hlcNodeId;
  final Value<int> hlcCounter;
  final Value<int> vectorClockA;
  final Value<int> vectorClockB;
  final Value<String> senderPubkey;
  final Value<Uint8List> signature;
  final Value<DateTime> createdAt;
  final Value<bool> isPruned;
  const EventsCompanion({
    this.id = const Value.absent(),
    this.eventId = const Value.absent(),
    this.eventType = const Value.absent(),
    this.payloadEncrypted = const Value.absent(),
    this.previousHash = const Value.absent(),
    this.eventHash = const Value.absent(),
    this.hlcTimestamp = const Value.absent(),
    this.hlcNodeId = const Value.absent(),
    this.hlcCounter = const Value.absent(),
    this.vectorClockA = const Value.absent(),
    this.vectorClockB = const Value.absent(),
    this.senderPubkey = const Value.absent(),
    this.signature = const Value.absent(),
    this.createdAt = const Value.absent(),
    this.isPruned = const Value.absent(),
  });
  EventsCompanion.insert({
    this.id = const Value.absent(),
    required String eventId,
    required String eventType,
    this.payloadEncrypted = const Value.absent(),
    this.previousHash = const Value.absent(),
    required String eventHash,
    required String hlcTimestamp,
    required String hlcNodeId,
    required int hlcCounter,
    this.vectorClockA = const Value.absent(),
    this.vectorClockB = const Value.absent(),
    required String senderPubkey,
    required Uint8List signature,
    required DateTime createdAt,
    this.isPruned = const Value.absent(),
  }) : eventId = Value(eventId),
       eventType = Value(eventType),
       eventHash = Value(eventHash),
       hlcTimestamp = Value(hlcTimestamp),
       hlcNodeId = Value(hlcNodeId),
       hlcCounter = Value(hlcCounter),
       senderPubkey = Value(senderPubkey),
       signature = Value(signature),
       createdAt = Value(createdAt);
  static Insertable<Event> custom({
    Expression<int>? id,
    Expression<String>? eventId,
    Expression<String>? eventType,
    Expression<Uint8List>? payloadEncrypted,
    Expression<String>? previousHash,
    Expression<String>? eventHash,
    Expression<String>? hlcTimestamp,
    Expression<String>? hlcNodeId,
    Expression<int>? hlcCounter,
    Expression<int>? vectorClockA,
    Expression<int>? vectorClockB,
    Expression<String>? senderPubkey,
    Expression<Uint8List>? signature,
    Expression<DateTime>? createdAt,
    Expression<bool>? isPruned,
  }) {
    return RawValuesInsertable({
      if (id != null) 'id': id,
      if (eventId != null) 'event_id': eventId,
      if (eventType != null) 'event_type': eventType,
      if (payloadEncrypted != null) 'payload_encrypted': payloadEncrypted,
      if (previousHash != null) 'previous_hash': previousHash,
      if (eventHash != null) 'event_hash': eventHash,
      if (hlcTimestamp != null) 'hlc_timestamp': hlcTimestamp,
      if (hlcNodeId != null) 'hlc_node_id': hlcNodeId,
      if (hlcCounter != null) 'hlc_counter': hlcCounter,
      if (vectorClockA != null) 'vector_clock_a': vectorClockA,
      if (vectorClockB != null) 'vector_clock_b': vectorClockB,
      if (senderPubkey != null) 'sender_pubkey': senderPubkey,
      if (signature != null) 'signature': signature,
      if (createdAt != null) 'created_at': createdAt,
      if (isPruned != null) 'is_pruned': isPruned,
    });
  }

  EventsCompanion copyWith({
    Value<int>? id,
    Value<String>? eventId,
    Value<String>? eventType,
    Value<Uint8List?>? payloadEncrypted,
    Value<String?>? previousHash,
    Value<String>? eventHash,
    Value<String>? hlcTimestamp,
    Value<String>? hlcNodeId,
    Value<int>? hlcCounter,
    Value<int>? vectorClockA,
    Value<int>? vectorClockB,
    Value<String>? senderPubkey,
    Value<Uint8List>? signature,
    Value<DateTime>? createdAt,
    Value<bool>? isPruned,
  }) {
    return EventsCompanion(
      id: id ?? this.id,
      eventId: eventId ?? this.eventId,
      eventType: eventType ?? this.eventType,
      payloadEncrypted: payloadEncrypted ?? this.payloadEncrypted,
      previousHash: previousHash ?? this.previousHash,
      eventHash: eventHash ?? this.eventHash,
      hlcTimestamp: hlcTimestamp ?? this.hlcTimestamp,
      hlcNodeId: hlcNodeId ?? this.hlcNodeId,
      hlcCounter: hlcCounter ?? this.hlcCounter,
      vectorClockA: vectorClockA ?? this.vectorClockA,
      vectorClockB: vectorClockB ?? this.vectorClockB,
      senderPubkey: senderPubkey ?? this.senderPubkey,
      signature: signature ?? this.signature,
      createdAt: createdAt ?? this.createdAt,
      isPruned: isPruned ?? this.isPruned,
    );
  }

  @override
  Map<String, Expression> toColumns(bool nullToAbsent) {
    final map = <String, Expression>{};
    if (id.present) {
      map['id'] = Variable<int>(id.value);
    }
    if (eventId.present) {
      map['event_id'] = Variable<String>(eventId.value);
    }
    if (eventType.present) {
      map['event_type'] = Variable<String>(eventType.value);
    }
    if (payloadEncrypted.present) {
      map['payload_encrypted'] = Variable<Uint8List>(payloadEncrypted.value);
    }
    if (previousHash.present) {
      map['previous_hash'] = Variable<String>(previousHash.value);
    }
    if (eventHash.present) {
      map['event_hash'] = Variable<String>(eventHash.value);
    }
    if (hlcTimestamp.present) {
      map['hlc_timestamp'] = Variable<String>(hlcTimestamp.value);
    }
    if (hlcNodeId.present) {
      map['hlc_node_id'] = Variable<String>(hlcNodeId.value);
    }
    if (hlcCounter.present) {
      map['hlc_counter'] = Variable<int>(hlcCounter.value);
    }
    if (vectorClockA.present) {
      map['vector_clock_a'] = Variable<int>(vectorClockA.value);
    }
    if (vectorClockB.present) {
      map['vector_clock_b'] = Variable<int>(vectorClockB.value);
    }
    if (senderPubkey.present) {
      map['sender_pubkey'] = Variable<String>(senderPubkey.value);
    }
    if (signature.present) {
      map['signature'] = Variable<Uint8List>(signature.value);
    }
    if (createdAt.present) {
      map['created_at'] = Variable<DateTime>(createdAt.value);
    }
    if (isPruned.present) {
      map['is_pruned'] = Variable<bool>(isPruned.value);
    }
    return map;
  }

  @override
  String toString() {
    return (StringBuffer('EventsCompanion(')
          ..write('id: $id, ')
          ..write('eventId: $eventId, ')
          ..write('eventType: $eventType, ')
          ..write('payloadEncrypted: $payloadEncrypted, ')
          ..write('previousHash: $previousHash, ')
          ..write('eventHash: $eventHash, ')
          ..write('hlcTimestamp: $hlcTimestamp, ')
          ..write('hlcNodeId: $hlcNodeId, ')
          ..write('hlcCounter: $hlcCounter, ')
          ..write('vectorClockA: $vectorClockA, ')
          ..write('vectorClockB: $vectorClockB, ')
          ..write('senderPubkey: $senderPubkey, ')
          ..write('signature: $signature, ')
          ..write('createdAt: $createdAt, ')
          ..write('isPruned: $isPruned')
          ..write(')'))
        .toString();
  }
}

class $PeersTable extends Peers with TableInfo<$PeersTable, Peer> {
  @override
  final GeneratedDatabase attachedDatabase;
  final String? _alias;
  $PeersTable(this.attachedDatabase, [this._alias]);
  static const VerificationMeta _idMeta = const VerificationMeta('id');
  @override
  late final GeneratedColumn<int> id = GeneratedColumn<int>(
    'id',
    aliasedName,
    false,
    hasAutoIncrement: true,
    type: DriftSqlType.int,
    requiredDuringInsert: false,
    defaultConstraints: GeneratedColumn.constraintIsAlways(
      'PRIMARY KEY AUTOINCREMENT',
    ),
  );
  static const VerificationMeta _pubkeyMeta = const VerificationMeta('pubkey');
  @override
  late final GeneratedColumn<String> pubkey = GeneratedColumn<String>(
    'pubkey',
    aliasedName,
    false,
    type: DriftSqlType.string,
    requiredDuringInsert: true,
    defaultConstraints: GeneratedColumn.constraintIsAlways('UNIQUE'),
  );
  static const VerificationMeta _aliasMeta = const VerificationMeta('alias');
  @override
  late final GeneratedColumn<String> alias = GeneratedColumn<String>(
    'alias',
    aliasedName,
    true,
    type: DriftSqlType.string,
    requiredDuringInsert: false,
  );
  static const VerificationMeta _pairedAtMeta = const VerificationMeta(
    'pairedAt',
  );
  @override
  late final GeneratedColumn<DateTime> pairedAt = GeneratedColumn<DateTime>(
    'paired_at',
    aliasedName,
    false,
    type: DriftSqlType.dateTime,
    requiredDuringInsert: true,
  );
  static const VerificationMeta _isActiveMeta = const VerificationMeta(
    'isActive',
  );
  @override
  late final GeneratedColumn<bool> isActive = GeneratedColumn<bool>(
    'is_active',
    aliasedName,
    false,
    type: DriftSqlType.bool,
    requiredDuringInsert: false,
    defaultConstraints: GeneratedColumn.constraintIsAlways(
      'CHECK ("is_active" IN (0, 1))',
    ),
    defaultValue: const Constant(true),
  );
  static const VerificationMeta _rekeyHistoryMeta = const VerificationMeta(
    'rekeyHistory',
  );
  @override
  late final GeneratedColumn<String> rekeyHistory = GeneratedColumn<String>(
    'rekey_history',
    aliasedName,
    false,
    type: DriftSqlType.string,
    requiredDuringInsert: false,
    defaultValue: const Constant('[]'),
  );
  @override
  List<GeneratedColumn> get $columns => [
    id,
    pubkey,
    alias,
    pairedAt,
    isActive,
    rekeyHistory,
  ];
  @override
  String get aliasedName => _alias ?? actualTableName;
  @override
  String get actualTableName => $name;
  static const String $name = 'peers';
  @override
  VerificationContext validateIntegrity(
    Insertable<Peer> instance, {
    bool isInserting = false,
  }) {
    final context = VerificationContext();
    final data = instance.toColumns(true);
    if (data.containsKey('id')) {
      context.handle(_idMeta, id.isAcceptableOrUnknown(data['id']!, _idMeta));
    }
    if (data.containsKey('pubkey')) {
      context.handle(
        _pubkeyMeta,
        pubkey.isAcceptableOrUnknown(data['pubkey']!, _pubkeyMeta),
      );
    } else if (isInserting) {
      context.missing(_pubkeyMeta);
    }
    if (data.containsKey('alias')) {
      context.handle(
        _aliasMeta,
        alias.isAcceptableOrUnknown(data['alias']!, _aliasMeta),
      );
    }
    if (data.containsKey('paired_at')) {
      context.handle(
        _pairedAtMeta,
        pairedAt.isAcceptableOrUnknown(data['paired_at']!, _pairedAtMeta),
      );
    } else if (isInserting) {
      context.missing(_pairedAtMeta);
    }
    if (data.containsKey('is_active')) {
      context.handle(
        _isActiveMeta,
        isActive.isAcceptableOrUnknown(data['is_active']!, _isActiveMeta),
      );
    }
    if (data.containsKey('rekey_history')) {
      context.handle(
        _rekeyHistoryMeta,
        rekeyHistory.isAcceptableOrUnknown(
          data['rekey_history']!,
          _rekeyHistoryMeta,
        ),
      );
    }
    return context;
  }

  @override
  Set<GeneratedColumn> get $primaryKey => {id};
  @override
  Peer map(Map<String, dynamic> data, {String? tablePrefix}) {
    final effectivePrefix = tablePrefix != null ? '$tablePrefix.' : '';
    return Peer(
      id: attachedDatabase.typeMapping.read(
        DriftSqlType.int,
        data['${effectivePrefix}id'],
      )!,
      pubkey: attachedDatabase.typeMapping.read(
        DriftSqlType.string,
        data['${effectivePrefix}pubkey'],
      )!,
      alias: attachedDatabase.typeMapping.read(
        DriftSqlType.string,
        data['${effectivePrefix}alias'],
      ),
      pairedAt: attachedDatabase.typeMapping.read(
        DriftSqlType.dateTime,
        data['${effectivePrefix}paired_at'],
      )!,
      isActive: attachedDatabase.typeMapping.read(
        DriftSqlType.bool,
        data['${effectivePrefix}is_active'],
      )!,
      rekeyHistory: attachedDatabase.typeMapping.read(
        DriftSqlType.string,
        data['${effectivePrefix}rekey_history'],
      )!,
    );
  }

  @override
  $PeersTable createAlias(String alias) {
    return $PeersTable(attachedDatabase, alias);
  }
}

class Peer extends DataClass implements Insertable<Peer> {
  /// Auto-incrementing primary key.
  final int id;

  /// Hex-encoded Ed25519 public key (unique).
  final String pubkey;

  /// Optional alias / username.
  final String? alias;

  /// When the peer was paired.
  final DateTime pairedAt;

  /// Whether the peer is currently active.
  final bool isActive;

  /// JSON array of rekey history entries.
  final String rekeyHistory;
  const Peer({
    required this.id,
    required this.pubkey,
    this.alias,
    required this.pairedAt,
    required this.isActive,
    required this.rekeyHistory,
  });
  @override
  Map<String, Expression> toColumns(bool nullToAbsent) {
    final map = <String, Expression>{};
    map['id'] = Variable<int>(id);
    map['pubkey'] = Variable<String>(pubkey);
    if (!nullToAbsent || alias != null) {
      map['alias'] = Variable<String>(alias);
    }
    map['paired_at'] = Variable<DateTime>(pairedAt);
    map['is_active'] = Variable<bool>(isActive);
    map['rekey_history'] = Variable<String>(rekeyHistory);
    return map;
  }

  PeersCompanion toCompanion(bool nullToAbsent) {
    return PeersCompanion(
      id: Value(id),
      pubkey: Value(pubkey),
      alias: alias == null && nullToAbsent
          ? const Value.absent()
          : Value(alias),
      pairedAt: Value(pairedAt),
      isActive: Value(isActive),
      rekeyHistory: Value(rekeyHistory),
    );
  }

  factory Peer.fromJson(
    Map<String, dynamic> json, {
    ValueSerializer? serializer,
  }) {
    serializer ??= driftRuntimeOptions.defaultSerializer;
    return Peer(
      id: serializer.fromJson<int>(json['id']),
      pubkey: serializer.fromJson<String>(json['pubkey']),
      alias: serializer.fromJson<String?>(json['alias']),
      pairedAt: serializer.fromJson<DateTime>(json['pairedAt']),
      isActive: serializer.fromJson<bool>(json['isActive']),
      rekeyHistory: serializer.fromJson<String>(json['rekeyHistory']),
    );
  }
  @override
  Map<String, dynamic> toJson({ValueSerializer? serializer}) {
    serializer ??= driftRuntimeOptions.defaultSerializer;
    return <String, dynamic>{
      'id': serializer.toJson<int>(id),
      'pubkey': serializer.toJson<String>(pubkey),
      'alias': serializer.toJson<String?>(alias),
      'pairedAt': serializer.toJson<DateTime>(pairedAt),
      'isActive': serializer.toJson<bool>(isActive),
      'rekeyHistory': serializer.toJson<String>(rekeyHistory),
    };
  }

  Peer copyWith({
    int? id,
    String? pubkey,
    Value<String?> alias = const Value.absent(),
    DateTime? pairedAt,
    bool? isActive,
    String? rekeyHistory,
  }) => Peer(
    id: id ?? this.id,
    pubkey: pubkey ?? this.pubkey,
    alias: alias.present ? alias.value : this.alias,
    pairedAt: pairedAt ?? this.pairedAt,
    isActive: isActive ?? this.isActive,
    rekeyHistory: rekeyHistory ?? this.rekeyHistory,
  );
  Peer copyWithCompanion(PeersCompanion data) {
    return Peer(
      id: data.id.present ? data.id.value : this.id,
      pubkey: data.pubkey.present ? data.pubkey.value : this.pubkey,
      alias: data.alias.present ? data.alias.value : this.alias,
      pairedAt: data.pairedAt.present ? data.pairedAt.value : this.pairedAt,
      isActive: data.isActive.present ? data.isActive.value : this.isActive,
      rekeyHistory: data.rekeyHistory.present
          ? data.rekeyHistory.value
          : this.rekeyHistory,
    );
  }

  @override
  String toString() {
    return (StringBuffer('Peer(')
          ..write('id: $id, ')
          ..write('pubkey: $pubkey, ')
          ..write('alias: $alias, ')
          ..write('pairedAt: $pairedAt, ')
          ..write('isActive: $isActive, ')
          ..write('rekeyHistory: $rekeyHistory')
          ..write(')'))
        .toString();
  }

  @override
  int get hashCode =>
      Object.hash(id, pubkey, alias, pairedAt, isActive, rekeyHistory);
  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is Peer &&
          other.id == this.id &&
          other.pubkey == this.pubkey &&
          other.alias == this.alias &&
          other.pairedAt == this.pairedAt &&
          other.isActive == this.isActive &&
          other.rekeyHistory == this.rekeyHistory);
}

class PeersCompanion extends UpdateCompanion<Peer> {
  final Value<int> id;
  final Value<String> pubkey;
  final Value<String?> alias;
  final Value<DateTime> pairedAt;
  final Value<bool> isActive;
  final Value<String> rekeyHistory;
  const PeersCompanion({
    this.id = const Value.absent(),
    this.pubkey = const Value.absent(),
    this.alias = const Value.absent(),
    this.pairedAt = const Value.absent(),
    this.isActive = const Value.absent(),
    this.rekeyHistory = const Value.absent(),
  });
  PeersCompanion.insert({
    this.id = const Value.absent(),
    required String pubkey,
    this.alias = const Value.absent(),
    required DateTime pairedAt,
    this.isActive = const Value.absent(),
    this.rekeyHistory = const Value.absent(),
  }) : pubkey = Value(pubkey),
       pairedAt = Value(pairedAt);
  static Insertable<Peer> custom({
    Expression<int>? id,
    Expression<String>? pubkey,
    Expression<String>? alias,
    Expression<DateTime>? pairedAt,
    Expression<bool>? isActive,
    Expression<String>? rekeyHistory,
  }) {
    return RawValuesInsertable({
      if (id != null) 'id': id,
      if (pubkey != null) 'pubkey': pubkey,
      if (alias != null) 'alias': alias,
      if (pairedAt != null) 'paired_at': pairedAt,
      if (isActive != null) 'is_active': isActive,
      if (rekeyHistory != null) 'rekey_history': rekeyHistory,
    });
  }

  PeersCompanion copyWith({
    Value<int>? id,
    Value<String>? pubkey,
    Value<String?>? alias,
    Value<DateTime>? pairedAt,
    Value<bool>? isActive,
    Value<String>? rekeyHistory,
  }) {
    return PeersCompanion(
      id: id ?? this.id,
      pubkey: pubkey ?? this.pubkey,
      alias: alias ?? this.alias,
      pairedAt: pairedAt ?? this.pairedAt,
      isActive: isActive ?? this.isActive,
      rekeyHistory: rekeyHistory ?? this.rekeyHistory,
    );
  }

  @override
  Map<String, Expression> toColumns(bool nullToAbsent) {
    final map = <String, Expression>{};
    if (id.present) {
      map['id'] = Variable<int>(id.value);
    }
    if (pubkey.present) {
      map['pubkey'] = Variable<String>(pubkey.value);
    }
    if (alias.present) {
      map['alias'] = Variable<String>(alias.value);
    }
    if (pairedAt.present) {
      map['paired_at'] = Variable<DateTime>(pairedAt.value);
    }
    if (isActive.present) {
      map['is_active'] = Variable<bool>(isActive.value);
    }
    if (rekeyHistory.present) {
      map['rekey_history'] = Variable<String>(rekeyHistory.value);
    }
    return map;
  }

  @override
  String toString() {
    return (StringBuffer('PeersCompanion(')
          ..write('id: $id, ')
          ..write('pubkey: $pubkey, ')
          ..write('alias: $alias, ')
          ..write('pairedAt: $pairedAt, ')
          ..write('isActive: $isActive, ')
          ..write('rekeyHistory: $rekeyHistory')
          ..write(')'))
        .toString();
  }
}

class $OutboxTable extends Outbox with TableInfo<$OutboxTable, OutboxData> {
  @override
  final GeneratedDatabase attachedDatabase;
  final String? _alias;
  $OutboxTable(this.attachedDatabase, [this._alias]);
  static const VerificationMeta _idMeta = const VerificationMeta('id');
  @override
  late final GeneratedColumn<int> id = GeneratedColumn<int>(
    'id',
    aliasedName,
    false,
    hasAutoIncrement: true,
    type: DriftSqlType.int,
    requiredDuringInsert: false,
    defaultConstraints: GeneratedColumn.constraintIsAlways(
      'PRIMARY KEY AUTOINCREMENT',
    ),
  );
  static const VerificationMeta _eventIdMeta = const VerificationMeta(
    'eventId',
  );
  @override
  late final GeneratedColumn<String> eventId = GeneratedColumn<String>(
    'event_id',
    aliasedName,
    false,
    type: DriftSqlType.string,
    requiredDuringInsert: true,
    defaultConstraints: GeneratedColumn.constraintIsAlways(
      'REFERENCES events (event_id)',
    ),
  );
  static const VerificationMeta _statusMeta = const VerificationMeta('status');
  @override
  late final GeneratedColumn<String> status = GeneratedColumn<String>(
    'status',
    aliasedName,
    false,
    type: DriftSqlType.string,
    requiredDuringInsert: false,
    defaultValue: const Constant('pending'),
  );
  static const VerificationMeta _transportUsedMeta = const VerificationMeta(
    'transportUsed',
  );
  @override
  late final GeneratedColumn<String> transportUsed = GeneratedColumn<String>(
    'transport_used',
    aliasedName,
    true,
    type: DriftSqlType.string,
    requiredDuringInsert: false,
  );
  static const VerificationMeta _retryCountMeta = const VerificationMeta(
    'retryCount',
  );
  @override
  late final GeneratedColumn<int> retryCount = GeneratedColumn<int>(
    'retry_count',
    aliasedName,
    false,
    type: DriftSqlType.int,
    requiredDuringInsert: false,
    defaultValue: const Constant(0),
  );
  static const VerificationMeta _nextRetryAtMeta = const VerificationMeta(
    'nextRetryAt',
  );
  @override
  late final GeneratedColumn<DateTime> nextRetryAt = GeneratedColumn<DateTime>(
    'next_retry_at',
    aliasedName,
    true,
    type: DriftSqlType.dateTime,
    requiredDuringInsert: false,
  );
  static const VerificationMeta _createdAtMeta = const VerificationMeta(
    'createdAt',
  );
  @override
  late final GeneratedColumn<DateTime> createdAt = GeneratedColumn<DateTime>(
    'created_at',
    aliasedName,
    false,
    type: DriftSqlType.dateTime,
    requiredDuringInsert: true,
  );
  static const VerificationMeta _sentAtMeta = const VerificationMeta('sentAt');
  @override
  late final GeneratedColumn<DateTime> sentAt = GeneratedColumn<DateTime>(
    'sent_at',
    aliasedName,
    true,
    type: DriftSqlType.dateTime,
    requiredDuringInsert: false,
  );
  @override
  List<GeneratedColumn> get $columns => [
    id,
    eventId,
    status,
    transportUsed,
    retryCount,
    nextRetryAt,
    createdAt,
    sentAt,
  ];
  @override
  String get aliasedName => _alias ?? actualTableName;
  @override
  String get actualTableName => $name;
  static const String $name = 'outbox';
  @override
  VerificationContext validateIntegrity(
    Insertable<OutboxData> instance, {
    bool isInserting = false,
  }) {
    final context = VerificationContext();
    final data = instance.toColumns(true);
    if (data.containsKey('id')) {
      context.handle(_idMeta, id.isAcceptableOrUnknown(data['id']!, _idMeta));
    }
    if (data.containsKey('event_id')) {
      context.handle(
        _eventIdMeta,
        eventId.isAcceptableOrUnknown(data['event_id']!, _eventIdMeta),
      );
    } else if (isInserting) {
      context.missing(_eventIdMeta);
    }
    if (data.containsKey('status')) {
      context.handle(
        _statusMeta,
        status.isAcceptableOrUnknown(data['status']!, _statusMeta),
      );
    }
    if (data.containsKey('transport_used')) {
      context.handle(
        _transportUsedMeta,
        transportUsed.isAcceptableOrUnknown(
          data['transport_used']!,
          _transportUsedMeta,
        ),
      );
    }
    if (data.containsKey('retry_count')) {
      context.handle(
        _retryCountMeta,
        retryCount.isAcceptableOrUnknown(data['retry_count']!, _retryCountMeta),
      );
    }
    if (data.containsKey('next_retry_at')) {
      context.handle(
        _nextRetryAtMeta,
        nextRetryAt.isAcceptableOrUnknown(
          data['next_retry_at']!,
          _nextRetryAtMeta,
        ),
      );
    }
    if (data.containsKey('created_at')) {
      context.handle(
        _createdAtMeta,
        createdAt.isAcceptableOrUnknown(data['created_at']!, _createdAtMeta),
      );
    } else if (isInserting) {
      context.missing(_createdAtMeta);
    }
    if (data.containsKey('sent_at')) {
      context.handle(
        _sentAtMeta,
        sentAt.isAcceptableOrUnknown(data['sent_at']!, _sentAtMeta),
      );
    }
    return context;
  }

  @override
  Set<GeneratedColumn> get $primaryKey => {id};
  @override
  OutboxData map(Map<String, dynamic> data, {String? tablePrefix}) {
    final effectivePrefix = tablePrefix != null ? '$tablePrefix.' : '';
    return OutboxData(
      id: attachedDatabase.typeMapping.read(
        DriftSqlType.int,
        data['${effectivePrefix}id'],
      )!,
      eventId: attachedDatabase.typeMapping.read(
        DriftSqlType.string,
        data['${effectivePrefix}event_id'],
      )!,
      status: attachedDatabase.typeMapping.read(
        DriftSqlType.string,
        data['${effectivePrefix}status'],
      )!,
      transportUsed: attachedDatabase.typeMapping.read(
        DriftSqlType.string,
        data['${effectivePrefix}transport_used'],
      ),
      retryCount: attachedDatabase.typeMapping.read(
        DriftSqlType.int,
        data['${effectivePrefix}retry_count'],
      )!,
      nextRetryAt: attachedDatabase.typeMapping.read(
        DriftSqlType.dateTime,
        data['${effectivePrefix}next_retry_at'],
      ),
      createdAt: attachedDatabase.typeMapping.read(
        DriftSqlType.dateTime,
        data['${effectivePrefix}created_at'],
      )!,
      sentAt: attachedDatabase.typeMapping.read(
        DriftSqlType.dateTime,
        data['${effectivePrefix}sent_at'],
      ),
    );
  }

  @override
  $OutboxTable createAlias(String alias) {
    return $OutboxTable(attachedDatabase, alias);
  }
}

class OutboxData extends DataClass implements Insertable<OutboxData> {
  /// Auto-incrementing primary key.
  final int id;

  /// References the event to send.
  final String eventId;

  /// Status: pending, sending, sent, failed, abandoned.
  final String status;

  /// Transport used: nostr, email, or null.
  final String? transportUsed;

  /// Number of send retries.
  final int retryCount;

  /// When to retry next (exponential backoff).
  final DateTime? nextRetryAt;

  /// When the outbox entry was created.
  final DateTime createdAt;

  /// When the event was successfully sent.
  final DateTime? sentAt;
  const OutboxData({
    required this.id,
    required this.eventId,
    required this.status,
    this.transportUsed,
    required this.retryCount,
    this.nextRetryAt,
    required this.createdAt,
    this.sentAt,
  });
  @override
  Map<String, Expression> toColumns(bool nullToAbsent) {
    final map = <String, Expression>{};
    map['id'] = Variable<int>(id);
    map['event_id'] = Variable<String>(eventId);
    map['status'] = Variable<String>(status);
    if (!nullToAbsent || transportUsed != null) {
      map['transport_used'] = Variable<String>(transportUsed);
    }
    map['retry_count'] = Variable<int>(retryCount);
    if (!nullToAbsent || nextRetryAt != null) {
      map['next_retry_at'] = Variable<DateTime>(nextRetryAt);
    }
    map['created_at'] = Variable<DateTime>(createdAt);
    if (!nullToAbsent || sentAt != null) {
      map['sent_at'] = Variable<DateTime>(sentAt);
    }
    return map;
  }

  OutboxCompanion toCompanion(bool nullToAbsent) {
    return OutboxCompanion(
      id: Value(id),
      eventId: Value(eventId),
      status: Value(status),
      transportUsed: transportUsed == null && nullToAbsent
          ? const Value.absent()
          : Value(transportUsed),
      retryCount: Value(retryCount),
      nextRetryAt: nextRetryAt == null && nullToAbsent
          ? const Value.absent()
          : Value(nextRetryAt),
      createdAt: Value(createdAt),
      sentAt: sentAt == null && nullToAbsent
          ? const Value.absent()
          : Value(sentAt),
    );
  }

  factory OutboxData.fromJson(
    Map<String, dynamic> json, {
    ValueSerializer? serializer,
  }) {
    serializer ??= driftRuntimeOptions.defaultSerializer;
    return OutboxData(
      id: serializer.fromJson<int>(json['id']),
      eventId: serializer.fromJson<String>(json['eventId']),
      status: serializer.fromJson<String>(json['status']),
      transportUsed: serializer.fromJson<String?>(json['transportUsed']),
      retryCount: serializer.fromJson<int>(json['retryCount']),
      nextRetryAt: serializer.fromJson<DateTime?>(json['nextRetryAt']),
      createdAt: serializer.fromJson<DateTime>(json['createdAt']),
      sentAt: serializer.fromJson<DateTime?>(json['sentAt']),
    );
  }
  @override
  Map<String, dynamic> toJson({ValueSerializer? serializer}) {
    serializer ??= driftRuntimeOptions.defaultSerializer;
    return <String, dynamic>{
      'id': serializer.toJson<int>(id),
      'eventId': serializer.toJson<String>(eventId),
      'status': serializer.toJson<String>(status),
      'transportUsed': serializer.toJson<String?>(transportUsed),
      'retryCount': serializer.toJson<int>(retryCount),
      'nextRetryAt': serializer.toJson<DateTime?>(nextRetryAt),
      'createdAt': serializer.toJson<DateTime>(createdAt),
      'sentAt': serializer.toJson<DateTime?>(sentAt),
    };
  }

  OutboxData copyWith({
    int? id,
    String? eventId,
    String? status,
    Value<String?> transportUsed = const Value.absent(),
    int? retryCount,
    Value<DateTime?> nextRetryAt = const Value.absent(),
    DateTime? createdAt,
    Value<DateTime?> sentAt = const Value.absent(),
  }) => OutboxData(
    id: id ?? this.id,
    eventId: eventId ?? this.eventId,
    status: status ?? this.status,
    transportUsed: transportUsed.present
        ? transportUsed.value
        : this.transportUsed,
    retryCount: retryCount ?? this.retryCount,
    nextRetryAt: nextRetryAt.present ? nextRetryAt.value : this.nextRetryAt,
    createdAt: createdAt ?? this.createdAt,
    sentAt: sentAt.present ? sentAt.value : this.sentAt,
  );
  OutboxData copyWithCompanion(OutboxCompanion data) {
    return OutboxData(
      id: data.id.present ? data.id.value : this.id,
      eventId: data.eventId.present ? data.eventId.value : this.eventId,
      status: data.status.present ? data.status.value : this.status,
      transportUsed: data.transportUsed.present
          ? data.transportUsed.value
          : this.transportUsed,
      retryCount: data.retryCount.present
          ? data.retryCount.value
          : this.retryCount,
      nextRetryAt: data.nextRetryAt.present
          ? data.nextRetryAt.value
          : this.nextRetryAt,
      createdAt: data.createdAt.present ? data.createdAt.value : this.createdAt,
      sentAt: data.sentAt.present ? data.sentAt.value : this.sentAt,
    );
  }

  @override
  String toString() {
    return (StringBuffer('OutboxData(')
          ..write('id: $id, ')
          ..write('eventId: $eventId, ')
          ..write('status: $status, ')
          ..write('transportUsed: $transportUsed, ')
          ..write('retryCount: $retryCount, ')
          ..write('nextRetryAt: $nextRetryAt, ')
          ..write('createdAt: $createdAt, ')
          ..write('sentAt: $sentAt')
          ..write(')'))
        .toString();
  }

  @override
  int get hashCode => Object.hash(
    id,
    eventId,
    status,
    transportUsed,
    retryCount,
    nextRetryAt,
    createdAt,
    sentAt,
  );
  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is OutboxData &&
          other.id == this.id &&
          other.eventId == this.eventId &&
          other.status == this.status &&
          other.transportUsed == this.transportUsed &&
          other.retryCount == this.retryCount &&
          other.nextRetryAt == this.nextRetryAt &&
          other.createdAt == this.createdAt &&
          other.sentAt == this.sentAt);
}

class OutboxCompanion extends UpdateCompanion<OutboxData> {
  final Value<int> id;
  final Value<String> eventId;
  final Value<String> status;
  final Value<String?> transportUsed;
  final Value<int> retryCount;
  final Value<DateTime?> nextRetryAt;
  final Value<DateTime> createdAt;
  final Value<DateTime?> sentAt;
  const OutboxCompanion({
    this.id = const Value.absent(),
    this.eventId = const Value.absent(),
    this.status = const Value.absent(),
    this.transportUsed = const Value.absent(),
    this.retryCount = const Value.absent(),
    this.nextRetryAt = const Value.absent(),
    this.createdAt = const Value.absent(),
    this.sentAt = const Value.absent(),
  });
  OutboxCompanion.insert({
    this.id = const Value.absent(),
    required String eventId,
    this.status = const Value.absent(),
    this.transportUsed = const Value.absent(),
    this.retryCount = const Value.absent(),
    this.nextRetryAt = const Value.absent(),
    required DateTime createdAt,
    this.sentAt = const Value.absent(),
  }) : eventId = Value(eventId),
       createdAt = Value(createdAt);
  static Insertable<OutboxData> custom({
    Expression<int>? id,
    Expression<String>? eventId,
    Expression<String>? status,
    Expression<String>? transportUsed,
    Expression<int>? retryCount,
    Expression<DateTime>? nextRetryAt,
    Expression<DateTime>? createdAt,
    Expression<DateTime>? sentAt,
  }) {
    return RawValuesInsertable({
      if (id != null) 'id': id,
      if (eventId != null) 'event_id': eventId,
      if (status != null) 'status': status,
      if (transportUsed != null) 'transport_used': transportUsed,
      if (retryCount != null) 'retry_count': retryCount,
      if (nextRetryAt != null) 'next_retry_at': nextRetryAt,
      if (createdAt != null) 'created_at': createdAt,
      if (sentAt != null) 'sent_at': sentAt,
    });
  }

  OutboxCompanion copyWith({
    Value<int>? id,
    Value<String>? eventId,
    Value<String>? status,
    Value<String?>? transportUsed,
    Value<int>? retryCount,
    Value<DateTime?>? nextRetryAt,
    Value<DateTime>? createdAt,
    Value<DateTime?>? sentAt,
  }) {
    return OutboxCompanion(
      id: id ?? this.id,
      eventId: eventId ?? this.eventId,
      status: status ?? this.status,
      transportUsed: transportUsed ?? this.transportUsed,
      retryCount: retryCount ?? this.retryCount,
      nextRetryAt: nextRetryAt ?? this.nextRetryAt,
      createdAt: createdAt ?? this.createdAt,
      sentAt: sentAt ?? this.sentAt,
    );
  }

  @override
  Map<String, Expression> toColumns(bool nullToAbsent) {
    final map = <String, Expression>{};
    if (id.present) {
      map['id'] = Variable<int>(id.value);
    }
    if (eventId.present) {
      map['event_id'] = Variable<String>(eventId.value);
    }
    if (status.present) {
      map['status'] = Variable<String>(status.value);
    }
    if (transportUsed.present) {
      map['transport_used'] = Variable<String>(transportUsed.value);
    }
    if (retryCount.present) {
      map['retry_count'] = Variable<int>(retryCount.value);
    }
    if (nextRetryAt.present) {
      map['next_retry_at'] = Variable<DateTime>(nextRetryAt.value);
    }
    if (createdAt.present) {
      map['created_at'] = Variable<DateTime>(createdAt.value);
    }
    if (sentAt.present) {
      map['sent_at'] = Variable<DateTime>(sentAt.value);
    }
    return map;
  }

  @override
  String toString() {
    return (StringBuffer('OutboxCompanion(')
          ..write('id: $id, ')
          ..write('eventId: $eventId, ')
          ..write('status: $status, ')
          ..write('transportUsed: $transportUsed, ')
          ..write('retryCount: $retryCount, ')
          ..write('nextRetryAt: $nextRetryAt, ')
          ..write('createdAt: $createdAt, ')
          ..write('sentAt: $sentAt')
          ..write(')'))
        .toString();
  }
}

class $ConfigTable extends Config with TableInfo<$ConfigTable, ConfigEntry> {
  @override
  final GeneratedDatabase attachedDatabase;
  final String? _alias;
  $ConfigTable(this.attachedDatabase, [this._alias]);
  static const VerificationMeta _keyMeta = const VerificationMeta('key');
  @override
  late final GeneratedColumn<String> key = GeneratedColumn<String>(
    'key',
    aliasedName,
    false,
    type: DriftSqlType.string,
    requiredDuringInsert: true,
  );
  static const VerificationMeta _valueMeta = const VerificationMeta('value');
  @override
  late final GeneratedColumn<String> value = GeneratedColumn<String>(
    'value',
    aliasedName,
    false,
    type: DriftSqlType.string,
    requiredDuringInsert: true,
  );
  @override
  List<GeneratedColumn> get $columns => [key, value];
  @override
  String get aliasedName => _alias ?? actualTableName;
  @override
  String get actualTableName => $name;
  static const String $name = 'config';
  @override
  VerificationContext validateIntegrity(
    Insertable<ConfigEntry> instance, {
    bool isInserting = false,
  }) {
    final context = VerificationContext();
    final data = instance.toColumns(true);
    if (data.containsKey('key')) {
      context.handle(
        _keyMeta,
        key.isAcceptableOrUnknown(data['key']!, _keyMeta),
      );
    } else if (isInserting) {
      context.missing(_keyMeta);
    }
    if (data.containsKey('value')) {
      context.handle(
        _valueMeta,
        value.isAcceptableOrUnknown(data['value']!, _valueMeta),
      );
    } else if (isInserting) {
      context.missing(_valueMeta);
    }
    return context;
  }

  @override
  Set<GeneratedColumn> get $primaryKey => {key};
  @override
  ConfigEntry map(Map<String, dynamic> data, {String? tablePrefix}) {
    final effectivePrefix = tablePrefix != null ? '$tablePrefix.' : '';
    return ConfigEntry(
      key: attachedDatabase.typeMapping.read(
        DriftSqlType.string,
        data['${effectivePrefix}key'],
      )!,
      value: attachedDatabase.typeMapping.read(
        DriftSqlType.string,
        data['${effectivePrefix}value'],
      )!,
    );
  }

  @override
  $ConfigTable createAlias(String alias) {
    return $ConfigTable(attachedDatabase, alias);
  }
}

class ConfigEntry extends DataClass implements Insertable<ConfigEntry> {
  /// Configuration key (primary key).
  final String key;

  /// Configuration value.
  final String value;
  const ConfigEntry({required this.key, required this.value});
  @override
  Map<String, Expression> toColumns(bool nullToAbsent) {
    final map = <String, Expression>{};
    map['key'] = Variable<String>(key);
    map['value'] = Variable<String>(value);
    return map;
  }

  ConfigCompanion toCompanion(bool nullToAbsent) {
    return ConfigCompanion(
      key: Value(key),
      value: Value(value),
    );
  }

  factory ConfigEntry.fromJson(
    Map<String, dynamic> json, {
    ValueSerializer? serializer,
  }) {
    serializer ??= driftRuntimeOptions.defaultSerializer;
    return ConfigEntry(
      key: serializer.fromJson<String>(json['key']),
      value: serializer.fromJson<String>(json['value']),
    );
  }
  @override
  Map<String, dynamic> toJson({ValueSerializer? serializer}) {
    serializer ??= driftRuntimeOptions.defaultSerializer;
    return <String, dynamic>{
      'key': serializer.toJson<String>(key),
      'value': serializer.toJson<String>(value),
    };
  }

  ConfigEntry copyWith({String? key, String? value}) => ConfigEntry(
    key: key ?? this.key,
    value: value ?? this.value,
  );
  ConfigEntry copyWithCompanion(ConfigCompanion data) {
    return ConfigEntry(
      key: data.key.present ? data.key.value : this.key,
      value: data.value.present ? data.value.value : this.value,
    );
  }

  @override
  String toString() {
    return (StringBuffer('ConfigEntry(')
          ..write('key: $key, ')
          ..write('value: $value')
          ..write(')'))
        .toString();
  }

  @override
  int get hashCode => Object.hash(key, value);
  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is ConfigEntry &&
          other.key == this.key &&
          other.value == this.value);
}

class ConfigCompanion extends UpdateCompanion<ConfigEntry> {
  final Value<String> key;
  final Value<String> value;
  final Value<int> rowid;
  const ConfigCompanion({
    this.key = const Value.absent(),
    this.value = const Value.absent(),
    this.rowid = const Value.absent(),
  });
  ConfigCompanion.insert({
    required String key,
    required String value,
    this.rowid = const Value.absent(),
  }) : key = Value(key),
       value = Value(value);
  static Insertable<ConfigEntry> custom({
    Expression<String>? key,
    Expression<String>? value,
    Expression<int>? rowid,
  }) {
    return RawValuesInsertable({
      if (key != null) 'key': key,
      if (value != null) 'value': value,
      if (rowid != null) 'rowid': rowid,
    });
  }

  ConfigCompanion copyWith({
    Value<String>? key,
    Value<String>? value,
    Value<int>? rowid,
  }) {
    return ConfigCompanion(
      key: key ?? this.key,
      value: value ?? this.value,
      rowid: rowid ?? this.rowid,
    );
  }

  @override
  Map<String, Expression> toColumns(bool nullToAbsent) {
    final map = <String, Expression>{};
    if (key.present) {
      map['key'] = Variable<String>(key.value);
    }
    if (value.present) {
      map['value'] = Variable<String>(value.value);
    }
    if (rowid.present) {
      map['rowid'] = Variable<int>(rowid.value);
    }
    return map;
  }

  @override
  String toString() {
    return (StringBuffer('ConfigCompanion(')
          ..write('key: $key, ')
          ..write('value: $value, ')
          ..write('rowid: $rowid')
          ..write(')'))
        .toString();
  }
}

abstract class _$StyxDatabase extends GeneratedDatabase {
  _$StyxDatabase(QueryExecutor e) : super(e);
  $StyxDatabaseManager get managers => $StyxDatabaseManager(this);
  late final $EventsTable events = $EventsTable(this);
  late final $PeersTable peers = $PeersTable(this);
  late final $OutboxTable outbox = $OutboxTable(this);
  late final $ConfigTable config = $ConfigTable(this);
  late final EventDao eventDao = EventDao(this as StyxDatabase);
  late final PeerDao peerDao = PeerDao(this as StyxDatabase);
  late final OutboxDao outboxDao = OutboxDao(this as StyxDatabase);
  late final ConfigDao configDao = ConfigDao(this as StyxDatabase);
  @override
  Iterable<TableInfo<Table, Object?>> get allTables =>
      allSchemaEntities.whereType<TableInfo<Table, Object?>>();
  @override
  List<DatabaseSchemaEntity> get allSchemaEntities => [
    events,
    peers,
    outbox,
    config,
  ];
}

typedef $$EventsTableCreateCompanionBuilder =
    EventsCompanion Function({
      Value<int> id,
      required String eventId,
      required String eventType,
      Value<Uint8List?> payloadEncrypted,
      Value<String?> previousHash,
      required String eventHash,
      required String hlcTimestamp,
      required String hlcNodeId,
      required int hlcCounter,
      Value<int> vectorClockA,
      Value<int> vectorClockB,
      required String senderPubkey,
      required Uint8List signature,
      required DateTime createdAt,
      Value<bool> isPruned,
    });
typedef $$EventsTableUpdateCompanionBuilder =
    EventsCompanion Function({
      Value<int> id,
      Value<String> eventId,
      Value<String> eventType,
      Value<Uint8List?> payloadEncrypted,
      Value<String?> previousHash,
      Value<String> eventHash,
      Value<String> hlcTimestamp,
      Value<String> hlcNodeId,
      Value<int> hlcCounter,
      Value<int> vectorClockA,
      Value<int> vectorClockB,
      Value<String> senderPubkey,
      Value<Uint8List> signature,
      Value<DateTime> createdAt,
      Value<bool> isPruned,
    });

final class $$EventsTableReferences
    extends BaseReferences<_$StyxDatabase, $EventsTable, Event> {
  $$EventsTableReferences(super.$_db, super.$_table, super.$_typedResult);

  static MultiTypedResultKey<$OutboxTable, List<OutboxData>> _outboxRefsTable(
    _$StyxDatabase db,
  ) => MultiTypedResultKey.fromTable(
    db.outbox,
    aliasName: $_aliasNameGenerator(db.events.eventId, db.outbox.eventId),
  );

  $$OutboxTableProcessedTableManager get outboxRefs {
    final manager = $$OutboxTableTableManager($_db, $_db.outbox).filter(
      (f) => f.eventId.eventId.sqlEquals($_itemColumn<String>('event_id')!),
    );

    final cache = $_typedResult.readTableOrNull(_outboxRefsTable($_db));
    return ProcessedTableManager(
      manager.$state.copyWith(prefetchedData: cache),
    );
  }
}

class $$EventsTableFilterComposer
    extends Composer<_$StyxDatabase, $EventsTable> {
  $$EventsTableFilterComposer({
    required super.$db,
    required super.$table,
    super.joinBuilder,
    super.$addJoinBuilderToRootComposer,
    super.$removeJoinBuilderFromRootComposer,
  });
  ColumnFilters<int> get id => $composableBuilder(
    column: $table.id,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<String> get eventId => $composableBuilder(
    column: $table.eventId,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<String> get eventType => $composableBuilder(
    column: $table.eventType,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<Uint8List> get payloadEncrypted => $composableBuilder(
    column: $table.payloadEncrypted,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<String> get previousHash => $composableBuilder(
    column: $table.previousHash,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<String> get eventHash => $composableBuilder(
    column: $table.eventHash,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<String> get hlcTimestamp => $composableBuilder(
    column: $table.hlcTimestamp,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<String> get hlcNodeId => $composableBuilder(
    column: $table.hlcNodeId,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<int> get hlcCounter => $composableBuilder(
    column: $table.hlcCounter,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<int> get vectorClockA => $composableBuilder(
    column: $table.vectorClockA,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<int> get vectorClockB => $composableBuilder(
    column: $table.vectorClockB,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<String> get senderPubkey => $composableBuilder(
    column: $table.senderPubkey,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<Uint8List> get signature => $composableBuilder(
    column: $table.signature,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<DateTime> get createdAt => $composableBuilder(
    column: $table.createdAt,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<bool> get isPruned => $composableBuilder(
    column: $table.isPruned,
    builder: (column) => ColumnFilters(column),
  );

  Expression<bool> outboxRefs(
    Expression<bool> Function($$OutboxTableFilterComposer f) f,
  ) {
    final $$OutboxTableFilterComposer composer = $composerBuilder(
      composer: this,
      getCurrentColumn: (t) => t.eventId,
      referencedTable: $db.outbox,
      getReferencedColumn: (t) => t.eventId,
      builder:
          (
            joinBuilder, {
            $addJoinBuilderToRootComposer,
            $removeJoinBuilderFromRootComposer,
          }) => $$OutboxTableFilterComposer(
            $db: $db,
            $table: $db.outbox,
            $addJoinBuilderToRootComposer: $addJoinBuilderToRootComposer,
            joinBuilder: joinBuilder,
            $removeJoinBuilderFromRootComposer:
                $removeJoinBuilderFromRootComposer,
          ),
    );
    return f(composer);
  }
}

class $$EventsTableOrderingComposer
    extends Composer<_$StyxDatabase, $EventsTable> {
  $$EventsTableOrderingComposer({
    required super.$db,
    required super.$table,
    super.joinBuilder,
    super.$addJoinBuilderToRootComposer,
    super.$removeJoinBuilderFromRootComposer,
  });
  ColumnOrderings<int> get id => $composableBuilder(
    column: $table.id,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<String> get eventId => $composableBuilder(
    column: $table.eventId,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<String> get eventType => $composableBuilder(
    column: $table.eventType,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<Uint8List> get payloadEncrypted => $composableBuilder(
    column: $table.payloadEncrypted,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<String> get previousHash => $composableBuilder(
    column: $table.previousHash,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<String> get eventHash => $composableBuilder(
    column: $table.eventHash,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<String> get hlcTimestamp => $composableBuilder(
    column: $table.hlcTimestamp,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<String> get hlcNodeId => $composableBuilder(
    column: $table.hlcNodeId,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<int> get hlcCounter => $composableBuilder(
    column: $table.hlcCounter,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<int> get vectorClockA => $composableBuilder(
    column: $table.vectorClockA,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<int> get vectorClockB => $composableBuilder(
    column: $table.vectorClockB,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<String> get senderPubkey => $composableBuilder(
    column: $table.senderPubkey,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<Uint8List> get signature => $composableBuilder(
    column: $table.signature,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<DateTime> get createdAt => $composableBuilder(
    column: $table.createdAt,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<bool> get isPruned => $composableBuilder(
    column: $table.isPruned,
    builder: (column) => ColumnOrderings(column),
  );
}

class $$EventsTableAnnotationComposer
    extends Composer<_$StyxDatabase, $EventsTable> {
  $$EventsTableAnnotationComposer({
    required super.$db,
    required super.$table,
    super.joinBuilder,
    super.$addJoinBuilderToRootComposer,
    super.$removeJoinBuilderFromRootComposer,
  });
  GeneratedColumn<int> get id =>
      $composableBuilder(column: $table.id, builder: (column) => column);

  GeneratedColumn<String> get eventId =>
      $composableBuilder(column: $table.eventId, builder: (column) => column);

  GeneratedColumn<String> get eventType =>
      $composableBuilder(column: $table.eventType, builder: (column) => column);

  GeneratedColumn<Uint8List> get payloadEncrypted => $composableBuilder(
    column: $table.payloadEncrypted,
    builder: (column) => column,
  );

  GeneratedColumn<String> get previousHash => $composableBuilder(
    column: $table.previousHash,
    builder: (column) => column,
  );

  GeneratedColumn<String> get eventHash =>
      $composableBuilder(column: $table.eventHash, builder: (column) => column);

  GeneratedColumn<String> get hlcTimestamp => $composableBuilder(
    column: $table.hlcTimestamp,
    builder: (column) => column,
  );

  GeneratedColumn<String> get hlcNodeId =>
      $composableBuilder(column: $table.hlcNodeId, builder: (column) => column);

  GeneratedColumn<int> get hlcCounter => $composableBuilder(
    column: $table.hlcCounter,
    builder: (column) => column,
  );

  GeneratedColumn<int> get vectorClockA => $composableBuilder(
    column: $table.vectorClockA,
    builder: (column) => column,
  );

  GeneratedColumn<int> get vectorClockB => $composableBuilder(
    column: $table.vectorClockB,
    builder: (column) => column,
  );

  GeneratedColumn<String> get senderPubkey => $composableBuilder(
    column: $table.senderPubkey,
    builder: (column) => column,
  );

  GeneratedColumn<Uint8List> get signature =>
      $composableBuilder(column: $table.signature, builder: (column) => column);

  GeneratedColumn<DateTime> get createdAt =>
      $composableBuilder(column: $table.createdAt, builder: (column) => column);

  GeneratedColumn<bool> get isPruned =>
      $composableBuilder(column: $table.isPruned, builder: (column) => column);

  Expression<T> outboxRefs<T extends Object>(
    Expression<T> Function($$OutboxTableAnnotationComposer a) f,
  ) {
    final $$OutboxTableAnnotationComposer composer = $composerBuilder(
      composer: this,
      getCurrentColumn: (t) => t.eventId,
      referencedTable: $db.outbox,
      getReferencedColumn: (t) => t.eventId,
      builder:
          (
            joinBuilder, {
            $addJoinBuilderToRootComposer,
            $removeJoinBuilderFromRootComposer,
          }) => $$OutboxTableAnnotationComposer(
            $db: $db,
            $table: $db.outbox,
            $addJoinBuilderToRootComposer: $addJoinBuilderToRootComposer,
            joinBuilder: joinBuilder,
            $removeJoinBuilderFromRootComposer:
                $removeJoinBuilderFromRootComposer,
          ),
    );
    return f(composer);
  }
}

class $$EventsTableTableManager
    extends
        RootTableManager<
          _$StyxDatabase,
          $EventsTable,
          Event,
          $$EventsTableFilterComposer,
          $$EventsTableOrderingComposer,
          $$EventsTableAnnotationComposer,
          $$EventsTableCreateCompanionBuilder,
          $$EventsTableUpdateCompanionBuilder,
          (Event, $$EventsTableReferences),
          Event,
          PrefetchHooks Function({bool outboxRefs})
        > {
  $$EventsTableTableManager(_$StyxDatabase db, $EventsTable table)
    : super(
        TableManagerState(
          db: db,
          table: table,
          createFilteringComposer: () =>
              $$EventsTableFilterComposer($db: db, $table: table),
          createOrderingComposer: () =>
              $$EventsTableOrderingComposer($db: db, $table: table),
          createComputedFieldComposer: () =>
              $$EventsTableAnnotationComposer($db: db, $table: table),
          updateCompanionCallback:
              ({
                Value<int> id = const Value.absent(),
                Value<String> eventId = const Value.absent(),
                Value<String> eventType = const Value.absent(),
                Value<Uint8List?> payloadEncrypted = const Value.absent(),
                Value<String?> previousHash = const Value.absent(),
                Value<String> eventHash = const Value.absent(),
                Value<String> hlcTimestamp = const Value.absent(),
                Value<String> hlcNodeId = const Value.absent(),
                Value<int> hlcCounter = const Value.absent(),
                Value<int> vectorClockA = const Value.absent(),
                Value<int> vectorClockB = const Value.absent(),
                Value<String> senderPubkey = const Value.absent(),
                Value<Uint8List> signature = const Value.absent(),
                Value<DateTime> createdAt = const Value.absent(),
                Value<bool> isPruned = const Value.absent(),
              }) => EventsCompanion(
                id: id,
                eventId: eventId,
                eventType: eventType,
                payloadEncrypted: payloadEncrypted,
                previousHash: previousHash,
                eventHash: eventHash,
                hlcTimestamp: hlcTimestamp,
                hlcNodeId: hlcNodeId,
                hlcCounter: hlcCounter,
                vectorClockA: vectorClockA,
                vectorClockB: vectorClockB,
                senderPubkey: senderPubkey,
                signature: signature,
                createdAt: createdAt,
                isPruned: isPruned,
              ),
          createCompanionCallback:
              ({
                Value<int> id = const Value.absent(),
                required String eventId,
                required String eventType,
                Value<Uint8List?> payloadEncrypted = const Value.absent(),
                Value<String?> previousHash = const Value.absent(),
                required String eventHash,
                required String hlcTimestamp,
                required String hlcNodeId,
                required int hlcCounter,
                Value<int> vectorClockA = const Value.absent(),
                Value<int> vectorClockB = const Value.absent(),
                required String senderPubkey,
                required Uint8List signature,
                required DateTime createdAt,
                Value<bool> isPruned = const Value.absent(),
              }) => EventsCompanion.insert(
                id: id,
                eventId: eventId,
                eventType: eventType,
                payloadEncrypted: payloadEncrypted,
                previousHash: previousHash,
                eventHash: eventHash,
                hlcTimestamp: hlcTimestamp,
                hlcNodeId: hlcNodeId,
                hlcCounter: hlcCounter,
                vectorClockA: vectorClockA,
                vectorClockB: vectorClockB,
                senderPubkey: senderPubkey,
                signature: signature,
                createdAt: createdAt,
                isPruned: isPruned,
              ),
          withReferenceMapper: (p0) => p0
              .map(
                (e) =>
                    (e.readTable(table), $$EventsTableReferences(db, table, e)),
              )
              .toList(),
          prefetchHooksCallback: ({outboxRefs = false}) {
            return PrefetchHooks(
              db: db,
              explicitlyWatchedTables: [if (outboxRefs) db.outbox],
              addJoins: null,
              getPrefetchedDataCallback: (items) async {
                return [
                  if (outboxRefs)
                    await $_getPrefetchedData<Event, $EventsTable, OutboxData>(
                      currentTable: table,
                      referencedTable: $$EventsTableReferences._outboxRefsTable(
                        db,
                      ),
                      managerFromTypedResult: (p0) =>
                          $$EventsTableReferences(db, table, p0).outboxRefs,
                      referencedItemsForCurrentItem: (item, referencedItems) =>
                          referencedItems.where(
                            (e) => e.eventId == item.eventId,
                          ),
                      typedResults: items,
                    ),
                ];
              },
            );
          },
        ),
      );
}

typedef $$EventsTableProcessedTableManager =
    ProcessedTableManager<
      _$StyxDatabase,
      $EventsTable,
      Event,
      $$EventsTableFilterComposer,
      $$EventsTableOrderingComposer,
      $$EventsTableAnnotationComposer,
      $$EventsTableCreateCompanionBuilder,
      $$EventsTableUpdateCompanionBuilder,
      (Event, $$EventsTableReferences),
      Event,
      PrefetchHooks Function({bool outboxRefs})
    >;
typedef $$PeersTableCreateCompanionBuilder =
    PeersCompanion Function({
      Value<int> id,
      required String pubkey,
      Value<String?> alias,
      required DateTime pairedAt,
      Value<bool> isActive,
      Value<String> rekeyHistory,
    });
typedef $$PeersTableUpdateCompanionBuilder =
    PeersCompanion Function({
      Value<int> id,
      Value<String> pubkey,
      Value<String?> alias,
      Value<DateTime> pairedAt,
      Value<bool> isActive,
      Value<String> rekeyHistory,
    });

class $$PeersTableFilterComposer extends Composer<_$StyxDatabase, $PeersTable> {
  $$PeersTableFilterComposer({
    required super.$db,
    required super.$table,
    super.joinBuilder,
    super.$addJoinBuilderToRootComposer,
    super.$removeJoinBuilderFromRootComposer,
  });
  ColumnFilters<int> get id => $composableBuilder(
    column: $table.id,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<String> get pubkey => $composableBuilder(
    column: $table.pubkey,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<String> get alias => $composableBuilder(
    column: $table.alias,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<DateTime> get pairedAt => $composableBuilder(
    column: $table.pairedAt,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<bool> get isActive => $composableBuilder(
    column: $table.isActive,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<String> get rekeyHistory => $composableBuilder(
    column: $table.rekeyHistory,
    builder: (column) => ColumnFilters(column),
  );
}

class $$PeersTableOrderingComposer
    extends Composer<_$StyxDatabase, $PeersTable> {
  $$PeersTableOrderingComposer({
    required super.$db,
    required super.$table,
    super.joinBuilder,
    super.$addJoinBuilderToRootComposer,
    super.$removeJoinBuilderFromRootComposer,
  });
  ColumnOrderings<int> get id => $composableBuilder(
    column: $table.id,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<String> get pubkey => $composableBuilder(
    column: $table.pubkey,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<String> get alias => $composableBuilder(
    column: $table.alias,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<DateTime> get pairedAt => $composableBuilder(
    column: $table.pairedAt,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<bool> get isActive => $composableBuilder(
    column: $table.isActive,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<String> get rekeyHistory => $composableBuilder(
    column: $table.rekeyHistory,
    builder: (column) => ColumnOrderings(column),
  );
}

class $$PeersTableAnnotationComposer
    extends Composer<_$StyxDatabase, $PeersTable> {
  $$PeersTableAnnotationComposer({
    required super.$db,
    required super.$table,
    super.joinBuilder,
    super.$addJoinBuilderToRootComposer,
    super.$removeJoinBuilderFromRootComposer,
  });
  GeneratedColumn<int> get id =>
      $composableBuilder(column: $table.id, builder: (column) => column);

  GeneratedColumn<String> get pubkey =>
      $composableBuilder(column: $table.pubkey, builder: (column) => column);

  GeneratedColumn<String> get alias =>
      $composableBuilder(column: $table.alias, builder: (column) => column);

  GeneratedColumn<DateTime> get pairedAt =>
      $composableBuilder(column: $table.pairedAt, builder: (column) => column);

  GeneratedColumn<bool> get isActive =>
      $composableBuilder(column: $table.isActive, builder: (column) => column);

  GeneratedColumn<String> get rekeyHistory => $composableBuilder(
    column: $table.rekeyHistory,
    builder: (column) => column,
  );
}

class $$PeersTableTableManager
    extends
        RootTableManager<
          _$StyxDatabase,
          $PeersTable,
          Peer,
          $$PeersTableFilterComposer,
          $$PeersTableOrderingComposer,
          $$PeersTableAnnotationComposer,
          $$PeersTableCreateCompanionBuilder,
          $$PeersTableUpdateCompanionBuilder,
          (Peer, BaseReferences<_$StyxDatabase, $PeersTable, Peer>),
          Peer,
          PrefetchHooks Function()
        > {
  $$PeersTableTableManager(_$StyxDatabase db, $PeersTable table)
    : super(
        TableManagerState(
          db: db,
          table: table,
          createFilteringComposer: () =>
              $$PeersTableFilterComposer($db: db, $table: table),
          createOrderingComposer: () =>
              $$PeersTableOrderingComposer($db: db, $table: table),
          createComputedFieldComposer: () =>
              $$PeersTableAnnotationComposer($db: db, $table: table),
          updateCompanionCallback:
              ({
                Value<int> id = const Value.absent(),
                Value<String> pubkey = const Value.absent(),
                Value<String?> alias = const Value.absent(),
                Value<DateTime> pairedAt = const Value.absent(),
                Value<bool> isActive = const Value.absent(),
                Value<String> rekeyHistory = const Value.absent(),
              }) => PeersCompanion(
                id: id,
                pubkey: pubkey,
                alias: alias,
                pairedAt: pairedAt,
                isActive: isActive,
                rekeyHistory: rekeyHistory,
              ),
          createCompanionCallback:
              ({
                Value<int> id = const Value.absent(),
                required String pubkey,
                Value<String?> alias = const Value.absent(),
                required DateTime pairedAt,
                Value<bool> isActive = const Value.absent(),
                Value<String> rekeyHistory = const Value.absent(),
              }) => PeersCompanion.insert(
                id: id,
                pubkey: pubkey,
                alias: alias,
                pairedAt: pairedAt,
                isActive: isActive,
                rekeyHistory: rekeyHistory,
              ),
          withReferenceMapper: (p0) => p0
              .map((e) => (e.readTable(table), BaseReferences(db, table, e)))
              .toList(),
          prefetchHooksCallback: null,
        ),
      );
}

typedef $$PeersTableProcessedTableManager =
    ProcessedTableManager<
      _$StyxDatabase,
      $PeersTable,
      Peer,
      $$PeersTableFilterComposer,
      $$PeersTableOrderingComposer,
      $$PeersTableAnnotationComposer,
      $$PeersTableCreateCompanionBuilder,
      $$PeersTableUpdateCompanionBuilder,
      (Peer, BaseReferences<_$StyxDatabase, $PeersTable, Peer>),
      Peer,
      PrefetchHooks Function()
    >;
typedef $$OutboxTableCreateCompanionBuilder =
    OutboxCompanion Function({
      Value<int> id,
      required String eventId,
      Value<String> status,
      Value<String?> transportUsed,
      Value<int> retryCount,
      Value<DateTime?> nextRetryAt,
      required DateTime createdAt,
      Value<DateTime?> sentAt,
    });
typedef $$OutboxTableUpdateCompanionBuilder =
    OutboxCompanion Function({
      Value<int> id,
      Value<String> eventId,
      Value<String> status,
      Value<String?> transportUsed,
      Value<int> retryCount,
      Value<DateTime?> nextRetryAt,
      Value<DateTime> createdAt,
      Value<DateTime?> sentAt,
    });

final class $$OutboxTableReferences
    extends BaseReferences<_$StyxDatabase, $OutboxTable, OutboxData> {
  $$OutboxTableReferences(super.$_db, super.$_table, super.$_typedResult);

  static $EventsTable _eventIdTable(_$StyxDatabase db) => db.events.createAlias(
    $_aliasNameGenerator(db.outbox.eventId, db.events.eventId),
  );

  $$EventsTableProcessedTableManager get eventId {
    final $_column = $_itemColumn<String>('event_id')!;

    final manager = $$EventsTableTableManager(
      $_db,
      $_db.events,
    ).filter((f) => f.eventId.sqlEquals($_column));
    final item = $_typedResult.readTableOrNull(_eventIdTable($_db));
    if (item == null) return manager;
    return ProcessedTableManager(
      manager.$state.copyWith(prefetchedData: [item]),
    );
  }
}

class $$OutboxTableFilterComposer
    extends Composer<_$StyxDatabase, $OutboxTable> {
  $$OutboxTableFilterComposer({
    required super.$db,
    required super.$table,
    super.joinBuilder,
    super.$addJoinBuilderToRootComposer,
    super.$removeJoinBuilderFromRootComposer,
  });
  ColumnFilters<int> get id => $composableBuilder(
    column: $table.id,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<String> get status => $composableBuilder(
    column: $table.status,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<String> get transportUsed => $composableBuilder(
    column: $table.transportUsed,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<int> get retryCount => $composableBuilder(
    column: $table.retryCount,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<DateTime> get nextRetryAt => $composableBuilder(
    column: $table.nextRetryAt,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<DateTime> get createdAt => $composableBuilder(
    column: $table.createdAt,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<DateTime> get sentAt => $composableBuilder(
    column: $table.sentAt,
    builder: (column) => ColumnFilters(column),
  );

  $$EventsTableFilterComposer get eventId {
    final $$EventsTableFilterComposer composer = $composerBuilder(
      composer: this,
      getCurrentColumn: (t) => t.eventId,
      referencedTable: $db.events,
      getReferencedColumn: (t) => t.eventId,
      builder:
          (
            joinBuilder, {
            $addJoinBuilderToRootComposer,
            $removeJoinBuilderFromRootComposer,
          }) => $$EventsTableFilterComposer(
            $db: $db,
            $table: $db.events,
            $addJoinBuilderToRootComposer: $addJoinBuilderToRootComposer,
            joinBuilder: joinBuilder,
            $removeJoinBuilderFromRootComposer:
                $removeJoinBuilderFromRootComposer,
          ),
    );
    return composer;
  }
}

class $$OutboxTableOrderingComposer
    extends Composer<_$StyxDatabase, $OutboxTable> {
  $$OutboxTableOrderingComposer({
    required super.$db,
    required super.$table,
    super.joinBuilder,
    super.$addJoinBuilderToRootComposer,
    super.$removeJoinBuilderFromRootComposer,
  });
  ColumnOrderings<int> get id => $composableBuilder(
    column: $table.id,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<String> get status => $composableBuilder(
    column: $table.status,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<String> get transportUsed => $composableBuilder(
    column: $table.transportUsed,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<int> get retryCount => $composableBuilder(
    column: $table.retryCount,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<DateTime> get nextRetryAt => $composableBuilder(
    column: $table.nextRetryAt,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<DateTime> get createdAt => $composableBuilder(
    column: $table.createdAt,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<DateTime> get sentAt => $composableBuilder(
    column: $table.sentAt,
    builder: (column) => ColumnOrderings(column),
  );

  $$EventsTableOrderingComposer get eventId {
    final $$EventsTableOrderingComposer composer = $composerBuilder(
      composer: this,
      getCurrentColumn: (t) => t.eventId,
      referencedTable: $db.events,
      getReferencedColumn: (t) => t.eventId,
      builder:
          (
            joinBuilder, {
            $addJoinBuilderToRootComposer,
            $removeJoinBuilderFromRootComposer,
          }) => $$EventsTableOrderingComposer(
            $db: $db,
            $table: $db.events,
            $addJoinBuilderToRootComposer: $addJoinBuilderToRootComposer,
            joinBuilder: joinBuilder,
            $removeJoinBuilderFromRootComposer:
                $removeJoinBuilderFromRootComposer,
          ),
    );
    return composer;
  }
}

class $$OutboxTableAnnotationComposer
    extends Composer<_$StyxDatabase, $OutboxTable> {
  $$OutboxTableAnnotationComposer({
    required super.$db,
    required super.$table,
    super.joinBuilder,
    super.$addJoinBuilderToRootComposer,
    super.$removeJoinBuilderFromRootComposer,
  });
  GeneratedColumn<int> get id =>
      $composableBuilder(column: $table.id, builder: (column) => column);

  GeneratedColumn<String> get status =>
      $composableBuilder(column: $table.status, builder: (column) => column);

  GeneratedColumn<String> get transportUsed => $composableBuilder(
    column: $table.transportUsed,
    builder: (column) => column,
  );

  GeneratedColumn<int> get retryCount => $composableBuilder(
    column: $table.retryCount,
    builder: (column) => column,
  );

  GeneratedColumn<DateTime> get nextRetryAt => $composableBuilder(
    column: $table.nextRetryAt,
    builder: (column) => column,
  );

  GeneratedColumn<DateTime> get createdAt =>
      $composableBuilder(column: $table.createdAt, builder: (column) => column);

  GeneratedColumn<DateTime> get sentAt =>
      $composableBuilder(column: $table.sentAt, builder: (column) => column);

  $$EventsTableAnnotationComposer get eventId {
    final $$EventsTableAnnotationComposer composer = $composerBuilder(
      composer: this,
      getCurrentColumn: (t) => t.eventId,
      referencedTable: $db.events,
      getReferencedColumn: (t) => t.eventId,
      builder:
          (
            joinBuilder, {
            $addJoinBuilderToRootComposer,
            $removeJoinBuilderFromRootComposer,
          }) => $$EventsTableAnnotationComposer(
            $db: $db,
            $table: $db.events,
            $addJoinBuilderToRootComposer: $addJoinBuilderToRootComposer,
            joinBuilder: joinBuilder,
            $removeJoinBuilderFromRootComposer:
                $removeJoinBuilderFromRootComposer,
          ),
    );
    return composer;
  }
}

class $$OutboxTableTableManager
    extends
        RootTableManager<
          _$StyxDatabase,
          $OutboxTable,
          OutboxData,
          $$OutboxTableFilterComposer,
          $$OutboxTableOrderingComposer,
          $$OutboxTableAnnotationComposer,
          $$OutboxTableCreateCompanionBuilder,
          $$OutboxTableUpdateCompanionBuilder,
          (OutboxData, $$OutboxTableReferences),
          OutboxData,
          PrefetchHooks Function({bool eventId})
        > {
  $$OutboxTableTableManager(_$StyxDatabase db, $OutboxTable table)
    : super(
        TableManagerState(
          db: db,
          table: table,
          createFilteringComposer: () =>
              $$OutboxTableFilterComposer($db: db, $table: table),
          createOrderingComposer: () =>
              $$OutboxTableOrderingComposer($db: db, $table: table),
          createComputedFieldComposer: () =>
              $$OutboxTableAnnotationComposer($db: db, $table: table),
          updateCompanionCallback:
              ({
                Value<int> id = const Value.absent(),
                Value<String> eventId = const Value.absent(),
                Value<String> status = const Value.absent(),
                Value<String?> transportUsed = const Value.absent(),
                Value<int> retryCount = const Value.absent(),
                Value<DateTime?> nextRetryAt = const Value.absent(),
                Value<DateTime> createdAt = const Value.absent(),
                Value<DateTime?> sentAt = const Value.absent(),
              }) => OutboxCompanion(
                id: id,
                eventId: eventId,
                status: status,
                transportUsed: transportUsed,
                retryCount: retryCount,
                nextRetryAt: nextRetryAt,
                createdAt: createdAt,
                sentAt: sentAt,
              ),
          createCompanionCallback:
              ({
                Value<int> id = const Value.absent(),
                required String eventId,
                Value<String> status = const Value.absent(),
                Value<String?> transportUsed = const Value.absent(),
                Value<int> retryCount = const Value.absent(),
                Value<DateTime?> nextRetryAt = const Value.absent(),
                required DateTime createdAt,
                Value<DateTime?> sentAt = const Value.absent(),
              }) => OutboxCompanion.insert(
                id: id,
                eventId: eventId,
                status: status,
                transportUsed: transportUsed,
                retryCount: retryCount,
                nextRetryAt: nextRetryAt,
                createdAt: createdAt,
                sentAt: sentAt,
              ),
          withReferenceMapper: (p0) => p0
              .map(
                (e) =>
                    (e.readTable(table), $$OutboxTableReferences(db, table, e)),
              )
              .toList(),
          prefetchHooksCallback: ({eventId = false}) {
            return PrefetchHooks(
              db: db,
              explicitlyWatchedTables: [],
              addJoins:
                  <
                    T extends TableManagerState<
                      dynamic,
                      dynamic,
                      dynamic,
                      dynamic,
                      dynamic,
                      dynamic,
                      dynamic,
                      dynamic,
                      dynamic,
                      dynamic,
                      dynamic
                    >
                  >(state) {
                    if (eventId) {
                      state =
                          state.withJoin(
                                currentTable: table,
                                currentColumn: table.eventId,
                                referencedTable: $$OutboxTableReferences
                                    ._eventIdTable(db),
                                referencedColumn: $$OutboxTableReferences
                                    ._eventIdTable(db)
                                    .eventId,
                              )
                              as T;
                    }

                    return state;
                  },
              getPrefetchedDataCallback: (items) async {
                return [];
              },
            );
          },
        ),
      );
}

typedef $$OutboxTableProcessedTableManager =
    ProcessedTableManager<
      _$StyxDatabase,
      $OutboxTable,
      OutboxData,
      $$OutboxTableFilterComposer,
      $$OutboxTableOrderingComposer,
      $$OutboxTableAnnotationComposer,
      $$OutboxTableCreateCompanionBuilder,
      $$OutboxTableUpdateCompanionBuilder,
      (OutboxData, $$OutboxTableReferences),
      OutboxData,
      PrefetchHooks Function({bool eventId})
    >;
typedef $$ConfigTableCreateCompanionBuilder =
    ConfigCompanion Function({
      required String key,
      required String value,
      Value<int> rowid,
    });
typedef $$ConfigTableUpdateCompanionBuilder =
    ConfigCompanion Function({
      Value<String> key,
      Value<String> value,
      Value<int> rowid,
    });

class $$ConfigTableFilterComposer
    extends Composer<_$StyxDatabase, $ConfigTable> {
  $$ConfigTableFilterComposer({
    required super.$db,
    required super.$table,
    super.joinBuilder,
    super.$addJoinBuilderToRootComposer,
    super.$removeJoinBuilderFromRootComposer,
  });
  ColumnFilters<String> get key => $composableBuilder(
    column: $table.key,
    builder: (column) => ColumnFilters(column),
  );

  ColumnFilters<String> get value => $composableBuilder(
    column: $table.value,
    builder: (column) => ColumnFilters(column),
  );
}

class $$ConfigTableOrderingComposer
    extends Composer<_$StyxDatabase, $ConfigTable> {
  $$ConfigTableOrderingComposer({
    required super.$db,
    required super.$table,
    super.joinBuilder,
    super.$addJoinBuilderToRootComposer,
    super.$removeJoinBuilderFromRootComposer,
  });
  ColumnOrderings<String> get key => $composableBuilder(
    column: $table.key,
    builder: (column) => ColumnOrderings(column),
  );

  ColumnOrderings<String> get value => $composableBuilder(
    column: $table.value,
    builder: (column) => ColumnOrderings(column),
  );
}

class $$ConfigTableAnnotationComposer
    extends Composer<_$StyxDatabase, $ConfigTable> {
  $$ConfigTableAnnotationComposer({
    required super.$db,
    required super.$table,
    super.joinBuilder,
    super.$addJoinBuilderToRootComposer,
    super.$removeJoinBuilderFromRootComposer,
  });
  GeneratedColumn<String> get key =>
      $composableBuilder(column: $table.key, builder: (column) => column);

  GeneratedColumn<String> get value =>
      $composableBuilder(column: $table.value, builder: (column) => column);
}

class $$ConfigTableTableManager
    extends
        RootTableManager<
          _$StyxDatabase,
          $ConfigTable,
          ConfigEntry,
          $$ConfigTableFilterComposer,
          $$ConfigTableOrderingComposer,
          $$ConfigTableAnnotationComposer,
          $$ConfigTableCreateCompanionBuilder,
          $$ConfigTableUpdateCompanionBuilder,
          (
            ConfigEntry,
            BaseReferences<_$StyxDatabase, $ConfigTable, ConfigEntry>,
          ),
          ConfigEntry,
          PrefetchHooks Function()
        > {
  $$ConfigTableTableManager(_$StyxDatabase db, $ConfigTable table)
    : super(
        TableManagerState(
          db: db,
          table: table,
          createFilteringComposer: () =>
              $$ConfigTableFilterComposer($db: db, $table: table),
          createOrderingComposer: () =>
              $$ConfigTableOrderingComposer($db: db, $table: table),
          createComputedFieldComposer: () =>
              $$ConfigTableAnnotationComposer($db: db, $table: table),
          updateCompanionCallback:
              ({
                Value<String> key = const Value.absent(),
                Value<String> value = const Value.absent(),
                Value<int> rowid = const Value.absent(),
              }) => ConfigCompanion(
                key: key,
                value: value,
                rowid: rowid,
              ),
          createCompanionCallback:
              ({
                required String key,
                required String value,
                Value<int> rowid = const Value.absent(),
              }) => ConfigCompanion.insert(
                key: key,
                value: value,
                rowid: rowid,
              ),
          withReferenceMapper: (p0) => p0
              .map((e) => (e.readTable(table), BaseReferences(db, table, e)))
              .toList(),
          prefetchHooksCallback: null,
        ),
      );
}

typedef $$ConfigTableProcessedTableManager =
    ProcessedTableManager<
      _$StyxDatabase,
      $ConfigTable,
      ConfigEntry,
      $$ConfigTableFilterComposer,
      $$ConfigTableOrderingComposer,
      $$ConfigTableAnnotationComposer,
      $$ConfigTableCreateCompanionBuilder,
      $$ConfigTableUpdateCompanionBuilder,
      (ConfigEntry, BaseReferences<_$StyxDatabase, $ConfigTable, ConfigEntry>),
      ConfigEntry,
      PrefetchHooks Function()
    >;

class $StyxDatabaseManager {
  final _$StyxDatabase _db;
  $StyxDatabaseManager(this._db);
  $$EventsTableTableManager get events =>
      $$EventsTableTableManager(_db, _db.events);
  $$PeersTableTableManager get peers =>
      $$PeersTableTableManager(_db, _db.peers);
  $$OutboxTableTableManager get outbox =>
      $$OutboxTableTableManager(_db, _db.outbox);
  $$ConfigTableTableManager get config =>
      $$ConfigTableTableManager(_db, _db.config);
}
