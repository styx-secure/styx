import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_ledger_engine/styx_ledger_engine.dart';

const _baseSha = 'f0f7c35fa030477f56ea3b29efa1381f0d2dc972';
const _schemaVersion = '1';

Object? _canonicalize(Object? value) {
  if (value is List<Object?>) return value.map(_canonicalize).toList();
  if (value is Map) {
    final result = SplayTreeMap<String, Object?>();
    for (final entry in value.entries) {
      result[entry.key as String] = _canonicalize(entry.value);
    }
    return result;
  }
  return value;
}

String canonicalJson(Object? value) => '${jsonEncode(_canonicalize(value))}\n';

Object? _resolveReference(Map<String, dynamic> root, String reference) {
  if (!reference.startsWith('#/')) {
    throw StateError('SCHEMA_EXTERNAL_REF:$reference');
  }
  Object? value = root;
  for (final component in reference.substring(2).split('/')) {
    value = (value! as Map<String, dynamic>)[component];
  }
  return value;
}

bool _matchesType(Object? value, String type) => switch (type) {
  'null' => value == null,
  'array' => value is List,
  'object' => value is Map,
  'string' => value is String,
  'boolean' => value is bool,
  _ => false,
};

void _validateNode(
  Object? value,
  Map<String, dynamic> schema,
  Map<String, dynamic> root,
  String path,
) {
  final reference = schema[r'$ref'];
  if (reference is String) {
    _validateNode(
      value,
      _resolveReference(root, reference)! as Map<String, dynamic>,
      root,
      path,
    );
    return;
  }
  final oneOf = schema['oneOf'];
  if (oneOf is List) {
    var matches = 0;
    for (final candidate in oneOf) {
      try {
        _validateNode(value, candidate as Map<String, dynamic>, root, path);
        matches += 1;
      } on Object {
        // A failing oneOf candidate is expected and not diagnostic by itself.
      }
    }
    if (matches != 1) throw StateError('SCHEMA_ONE_OF:$path');
    return;
  }
  if (schema.containsKey('const') && value != schema['const']) {
    throw StateError('SCHEMA_CONST:$path');
  }
  final allowed = schema['enum'];
  if (allowed is List && !allowed.contains(value)) {
    throw StateError('SCHEMA_ENUM:$path');
  }
  final type = schema['type'];
  if (type is String && !_matchesType(value, type)) {
    throw StateError('SCHEMA_TYPE:$path:$type');
  }
  final pattern = schema['pattern'];
  if (pattern is String && !RegExp(pattern).hasMatch(value! as String)) {
    throw StateError('SCHEMA_PATTERN:$path');
  }
  if (type == 'array') {
    final array = value! as List;
    final itemSchema = schema['items']! as Map<String, dynamic>;
    for (var index = 0; index < array.length; index += 1) {
      _validateNode(array[index], itemSchema, root, '$path[$index]');
    }
  }
  if (type == 'object') {
    final object = value! as Map;
    for (final required in (schema['required'] as List<dynamic>? ?? const [])) {
      if (!object.containsKey(required)) {
        throw StateError('SCHEMA_REQUIRED:$path.$required');
      }
    }
    final properties = schema['properties'] as Map<String, dynamic>?;
    for (final entry in object.entries) {
      final key = entry.key as String;
      if (properties?[key] case final Map<String, dynamic> child) {
        _validateNode(entry.value, child, root, '$path.$key');
      } else if (schema['additionalProperties'] == false) {
        throw StateError('SCHEMA_EXTRA:$path.$key');
      } else if (schema['additionalProperties']
          case final Map<String, dynamic> child) {
        _validateNode(entry.value, child, root, '$path.$key');
      }
    }
  }
}

// Imported by the isolated Dart test; the executable entry point does not call
// it.
// ignore: unreachable_from_main
void validateEnvelope(
  Map<String, Object?> envelope,
  Map<String, dynamic> schema,
) => _validateNode(envelope, schema, schema, r'$');

Uint8List _hexToBytes(String hex) {
  if (hex.length.isOdd) throw const FormatException('odd hex length');
  return Uint8List.fromList([
    for (var index = 0; index < hex.length; index += 2)
      int.parse(hex.substring(index, index + 2), radix: 16),
  ]);
}

String _bytesToHex(List<int> bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

String _repeat(String value, int count) => List.filled(count, value).join();

Map<String, Object?> _observed(
  String caseId,
  Object? value,
  String observedToken, [
  String? reasonCode,
]) => {
  'caseId': caseId,
  'status': 'OBSERVED',
  'value': value,
  'reasonCode': reasonCode,
  'observedToken': observedToken,
};

Map<String, Object?> _unsupported(
  String caseId,
  String reasonCode,
  String observedToken,
) => {
  'caseId': caseId,
  'status': 'UNSUPPORTED',
  'value': null,
  'reasonCode': reasonCode,
  'observedToken': observedToken,
};

Map<String, Object?> _clockValue(HybridLogicalClock clock) => {
  'kind': 'clock',
  'canonical': clock.toCanonical(),
  'epochMicros': clock.timestamp.microsecondsSinceEpoch.toString(),
  'counter': clock.counter.toString(),
  'nodeId': clock.nodeId,
};

Map<String, Object?> _vectorValue(VectorClock clock) => {
  'a': clock.a.toString(),
  'b': clock.b.toString(),
  'total': clock.total.toString(),
};

LedgerEvent _orderingEvent(Map<String, dynamic> input) => LedgerEvent(
  eventId: input['id'] as String,
  eventType: EventType.transaction,
  payload: Uint8List(0),
  previousHash: null,
  eventHash: input['id'] as String,
  hlc: HybridLogicalClock.fromCanonical(
    '2026-02-24T12:00:00.123Z-0042-a1b2c3d4',
  ),
  vectorClock: VectorClock(
    a: int.parse(input['a'] as String),
    b: int.parse(input['b'] as String),
  ),
  senderPubkey: input['sender'] as String,
  signature: Uint8List(64),
  createdAt: DateTime.parse('2026-02-24T12:00:00.123Z'),
);

LedgerEvent _chainEvent({
  required String id,
  required String senderPublicKeyHex,
  String? previousHash,
  String? eventHash,
  Uint8List? signature,
}) => LedgerEvent(
  eventId: id,
  eventType: EventType.transaction,
  payload: Uint8List.fromList([1]),
  previousHash: previousHash,
  eventHash: eventHash ?? _repeat('00', 32),
  hlc: HybridLogicalClock.fromCanonical(
    '2026-02-24T12:00:00.123Z-0042-a1b2c3d4',
  ),
  vectorClock: const VectorClock(a: 1, b: 0),
  senderPubkey: senderPublicKeyHex,
  signature: signature ?? Uint8List(64),
  createdAt: DateTime.parse('2026-02-24T12:00:00.123Z'),
);

String _chainErrorCode(ChainValidationError? error) =>
    switch (error?.errorType) {
      null => 'CHAIN_VALID',
      ChainErrorType.hashMismatch => 'CHAIN_HASH_MISMATCH',
      ChainErrorType.signatureInvalid => 'CHAIN_SIGNATURE_INVALID',
      ChainErrorType.previousHashMissing => 'CHAIN_PREVIOUS_HASH_MISMATCH',
      ChainErrorType.hlcViolation => 'CHAIN_HLC_VIOLATION',
      ChainErrorType.genesisViolation => 'CHAIN_GENESIS_VIOLATION',
    };

Future<Map<String, Object?>> _runCase(Map<String, dynamic> testCase) async {
  final id = testCase['id'] as String;
  final category = testCase['category'] as String;
  final operation = testCase['operation'] as String;
  final input = testCase['input'] as Map<String, dynamic>;
  final hasher = Hasher();

  if (category == 'hlc') {
    try {
      if (operation == 'parse-render') {
        return _observed(
          id,
          _clockValue(
            HybridLogicalClock.fromCanonical(input['canonical'] as String),
          ),
          'HybridLogicalClock.fromCanonical:return',
        );
      }
      if (operation == 'bytes') {
        final clock = HybridLogicalClock.fromCanonical(
          input['canonical'] as String,
        );
        return _observed(
          id,
          {'kind': 'bytes', 'hex': _bytesToHex(clock.toBytes())},
          'HybridLogicalClock.toBytes:return',
        );
      }
      if (operation == 'compare') {
        final left = HybridLogicalClock.fromCanonical(input['left'] as String);
        final right = HybridLogicalClock.fromCanonical(
          input['right'] as String,
        );
        return _observed(
          id,
          {'kind': 'comparison', 'relation': left.compareTo(right).toString()},
          'HybridLogicalClock.compareTo:return',
        );
      }
    } on Object {
      return _observed(
        id,
        {'kind': 'error', 'code': 'HLC_PARSE_ERROR'},
        'HybridLogicalClock.fromCanonical:throw',
        'HLC_PARSE_ERROR',
      );
    }
  }

  if (category == 'vector-clock') {
    if (operation == 'three-party-topology') {
      return _unsupported(
        id,
        'VECTOR_TOPOLOGY_TWO_PARTY_ONLY',
        'VectorClock.constructor:two-components',
      );
    }
    if (operation == 'merge-relation') {
      final leftInput = input['left'] as Map<String, dynamic>;
      final rightInput = input['right'] as Map<String, dynamic>;
      final left = VectorClock(
        a: int.parse(leftInput['a'] as String),
        b: int.parse(leftInput['b'] as String),
      );
      final right = VectorClock(
        a: int.parse(rightInput['a'] as String),
        b: int.parse(rightInput['b'] as String),
      );
      return _observed(
        id,
        {
          'kind': 'merge-relation',
          'merged': _vectorValue(left.merge(right)),
          'relation': left.causalRelation(right).name,
        },
        'VectorClock.merge.causalRelation:return',
      );
    }
    final clock = VectorClock(
      a: int.parse(input['a'] as String),
      b: int.parse(input['b'] as String),
    );
    if (operation == 'project') {
      return _observed(
        id,
        {..._vectorValue(clock), 'bytesHex': _bytesToHex(clock.toBytes())},
        'VectorClock.project:return',
      );
    }
    if (operation == 'bytes') {
      try {
        return _observed(
          id,
          {'kind': 'bytes', 'hex': _bytesToHex(clock.toBytes())},
          'VectorClock.toBytes:return',
        );
      } on Object {
        return _observed(
          id,
          {'kind': 'error', 'code': 'VECTOR_BYTES_RANGE'},
          'VectorClock.toBytes:throw',
          'VECTOR_BYTES_RANGE',
        );
      }
    }
    if (operation == 'increment') {
      try {
        return _observed(
          id,
          {
            'kind': 'vector',
            ..._vectorValue(clock.increment(input['role'] as String)),
          },
          'VectorClock.increment:return',
        );
      } on Object {
        return _observed(
          id,
          {'kind': 'error', 'code': 'VECTOR_ROLE_INVALID'},
          'VectorClock.increment:throw',
          'VECTOR_ROLE_INVALID',
        );
      }
    }
  }

  if (category == 'hashing') {
    if (operation == 'sha256') {
      return _observed(
        id,
        {
          'kind': 'hash',
          'hex': _bytesToHex(
            hasher.hash(_hexToBytes(input['dataHex'] as String)),
          ),
        },
        'Hasher.hash:return',
      );
    }
    if (operation == 'chain-hash') {
      final previousHex = input['previousHex'] as String?;
      return _observed(
        id,
        {
          'kind': 'hash',
          'hex': _bytesToHex(
            hasher.chainHash(
              previousHash: previousHex == null
                  ? null
                  : _hexToBytes(previousHex),
              payload: _hexToBytes(input['payloadHex'] as String),
            ),
          ),
        },
        'Hasher.chainHash:return',
      );
    }
    if (operation == 'composite-hash') {
      return _observed(
        id,
        {
          'kind': 'hash',
          'hex': _bytesToHex(
            hasher.compositeHash(
              (input['segmentsHex'] as List<dynamic>)
                  .cast<String>()
                  .map(_hexToBytes)
                  .toList(),
            ),
          ),
        },
        'Hasher.compositeHash:return',
      );
    }
    if (operation == 'segmentation-witness') {
      String digest(String key) => _bytesToHex(
        hasher.compositeHash(
          (input[key] as List<dynamic>)
              .cast<String>()
              .map(_hexToBytes)
              .toList(),
        ),
      );
      final left = digest('leftSegmentsHex');
      final right = digest('rightSegmentsHex');
      return _observed(
        id,
        {
          'kind': 'segmentation-witness',
          'leftHex': left,
          'rightHex': right,
          'equal': left == right,
        },
        'Hasher.compositeHash:segment-boundaries-erased',
      );
    }
  }

  if (category == 'event-hash') {
    final factory = EventFactory(signer: Signer(), hasher: hasher);
    if (operation == 'fixed-preimage') {
      return _observed(
        id,
        {
          'kind': 'event-hash',
          'hex': _bytesToHex(
            factory.computeHashBytes(
              previousHash: input['previousHash'] as String,
              eventType: EventType.values.byName(input['eventType'] as String),
              payload: _hexToBytes(input['payloadHex'] as String),
              hlcBytes: _hexToBytes(input['hlcBytesHex'] as String),
            ),
          ),
        },
        'EventFactory.computeHashBytes:return',
      );
    }
    if (operation == 'genesis-projection') {
      final event = await factory.createGenesisEvent(
        privateKey: StyxPrivateKey(
          _hexToBytes(input['privateSeedHex'] as String),
        ),
        publicKey: StyxPublicKey.fromHex(input['publicKeyHex'] as String),
        nodeId: input['nodeId'] as String,
      );
      return _observed(
        id,
        {
          'kind': 'genesis-projection',
          'eventType': event.eventType.name,
          'payloadHex': _bytesToHex(event.payload!),
          'previousHash': event.previousHash,
          'vectorClock': _vectorValue(event.vectorClock),
        },
        'EventFactory.createGenesisEvent:deterministic-fields',
      );
    }
    if (operation == 'deterministic-genesis-hash') {
      return _unsupported(
        id,
        'GENESIS_CLOCK_NOT_INJECTABLE',
        'EventFactory.createGenesisEvent:wall-clock-bound',
      );
    }
  }

  if (category == 'ordering') {
    final events = (input['events'] as List<dynamic>)
        .cast<Map<String, dynamic>>()
        .map(_orderingEvent)
        .toList();
    final ordered = DeterministicMerge()
        .orderConcurrentEvents(events)
        .map((event) => event.eventId)
        .toList();
    return _observed(
      id,
      {'kind': 'ordered-event-ids', 'ids': ordered},
      'DeterministicMerge.orderConcurrentEvents:return',
    );
  }

  if (category == 'chain-validation') {
    final validator = ChainValidator(hasher: hasher, verifier: Verifier());
    if (operation == 'empty-chain') {
      final code = _chainErrorCode(await validator.validateFullChain([]));
      return _observed(
        id,
        {'kind': 'chain-result', 'code': code},
        'ChainValidator.validateFullChain:return',
      );
    }
    final sender = input['senderPublicKeyHex'] as String;
    if (operation == 'genesis-previous-hash') {
      final code = _chainErrorCode(
        await validator.validateFullChain([
          _chainEvent(
            id: id,
            previousHash: input['previousHash'] as String,
            senderPublicKeyHex: sender,
          ),
        ]),
      );
      return _observed(
        id,
        {'kind': 'chain-result', 'code': code},
        'ChainValidator.validateFullChain:return',
        code,
      );
    }
    if (operation == 'hash-mismatch') {
      final code = _chainErrorCode(
        await validator.validateFullChain([
          _chainEvent(id: id, senderPublicKeyHex: sender),
        ]),
      );
      return _observed(
        id,
        {'kind': 'chain-result', 'code': code},
        'ChainValidator.validateFullChain:return',
        code,
      );
    }
    if (operation == 'signature-invalid') {
      final hlc = HybridLogicalClock.fromCanonical(
        '2026-02-24T12:00:00.123Z-0042-a1b2c3d4',
      );
      final factory = EventFactory(signer: Signer(), hasher: hasher);
      final eventHash = _bytesToHex(
        factory.computeHashBytes(
          previousHash: null,
          eventType: EventType.transaction,
          payload: Uint8List.fromList([1]),
          hlcBytes: hlc.toBytes(),
        ),
      );
      final code = _chainErrorCode(
        await validator.validateFullChain([
          _chainEvent(
            id: id,
            eventHash: eventHash,
            senderPublicKeyHex: sender,
          ),
        ]),
      );
      return _observed(
        id,
        {'kind': 'chain-result', 'code': code},
        'ChainValidator.validateFullChain:return',
        code,
      );
    }
    if (operation == 'previous-hash-mismatch') {
      final previous = _chainEvent(
        id: 'previous',
        eventHash: _repeat('11', 32),
        senderPublicKeyHex: sender,
      );
      final event = _chainEvent(
        id: id,
        previousHash: _repeat('22', 32),
        senderPublicKeyHex: sender,
      );
      final code = _chainErrorCode(
        await validator.validateEvent(
          event: event,
          previousEvent: previous,
          senderPublicKey: StyxPublicKey.fromHex(sender),
        ),
      );
      return _observed(
        id,
        {'kind': 'chain-result', 'code': code},
        'ChainValidator.validateEvent:return',
        code,
      );
    }
  }

  throw StateError('HARNESS_UNKNOWN_CASE:$id');
}

Future<Map<String, Object?>> runCharacterization(String corpusPath) async {
  final raw = await File(corpusPath).readAsBytes();
  final corpus = jsonDecode(utf8.decode(raw)) as Map<String, dynamic>;
  if (corpus['schemaVersion'] != _schemaVersion ||
      corpus['baseSha'] != _baseSha) {
    throw StateError('HARNESS_CORPUS_IDENTITY');
  }
  final observations = <Map<String, Object?>>[];
  for (final testCase in (corpus['cases'] as List<dynamic>)) {
    observations.add(await _runCase(testCase as Map<String, dynamic>));
  }
  return {
    'schemaVersion': _schemaVersion,
    'runtime': 'dart',
    'baseSha': _baseSha,
    'casesSha256': crypto.sha256.convert(raw).toString(),
    'observations': observations,
  };
}

Future<void> main(List<String> arguments) async {
  if (arguments.length != 1) {
    stderr.writeln(
      'C0_RUNNER_FAILED:USAGE:c0_characterization.dart <cases.json>',
    );
    exitCode = 1;
    return;
  }
  try {
    stdout.write(canonicalJson(await runCharacterization(arguments.single)));
  } on Object catch (error) {
    stderr.writeln('C0_RUNNER_FAILED:$error');
    exitCode = 1;
  }
}
