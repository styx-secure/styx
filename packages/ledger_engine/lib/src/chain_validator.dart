import 'package:meta/meta.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_ledger_engine/src/event_factory.dart';
import 'package:styx_ledger_engine/src/ledger_event.dart';

/// Type of chain validation error.
enum ChainErrorType {
  /// The computed hash does not match the stored hash.
  hashMismatch,

  /// The Ed25519 signature is invalid.
  signatureInvalid,

  /// The previousHash field does not match the preceding event's hash.
  previousHashMissing,

  /// The HLC is not monotonically increasing.
  hlcViolation,

  /// The first event is not a valid genesis.
  genesisViolation,
}

/// Describes a chain validation error.
@immutable
class ChainValidationError {
  /// Creates a [ChainValidationError].
  const ChainValidationError({
    required this.eventId,
    required this.errorType,
    required this.message,
  });

  /// The event where the error was found.
  final String eventId;

  /// The type of error.
  final ChainErrorType errorType;

  /// Human-readable description.
  final String message;

  @override
  String toString() => 'ChainValidationError($errorType on $eventId)';
}

/// Validates the integrity of the ledger chain.
class ChainValidator {
  /// Creates a [ChainValidator].
  ChainValidator({
    required Hasher hasher,
    required Verifier verifier,
  }) : _eventFactory = EventFactory(signer: Signer(), hasher: hasher),
       _verifier = verifier;

  final EventFactory _eventFactory;
  final Verifier _verifier;

  /// Validates the full chain from start to end.
  ///
  /// Returns the first error found, or `null` if the chain is valid.
  Future<ChainValidationError?> validateFullChain(
    List<LedgerEvent> events,
  ) async {
    if (events.isEmpty) return null;

    // First event must be genesis (no previousHash).
    final genesis = events.first;
    if (genesis.previousHash != null) {
      return ChainValidationError(
        eventId: genesis.eventId,
        errorType: ChainErrorType.genesisViolation,
        message: 'First event must have null previousHash',
      );
    }

    for (var i = 0; i < events.length; i++) {
      final event = events[i];
      final previous = i > 0 ? events[i - 1] : null;
      final senderKey = StyxPublicKey.fromHex(event.senderPubkey);

      final error = await validateEvent(
        event: event,
        previousEvent: previous,
        senderPublicKey: senderKey,
      );
      if (error != null) return error;
    }

    return null;
  }

  /// Validates a single event against its predecessor.
  Future<ChainValidationError?> validateEvent({
    required LedgerEvent event,
    required LedgerEvent? previousEvent,
    required StyxPublicKey senderPublicKey,
  }) async {
    // Check previousHash linkage.
    if (previousEvent != null) {
      if (event.previousHash != previousEvent.eventHash) {
        return ChainValidationError(
          eventId: event.eventId,
          errorType: ChainErrorType.previousHashMissing,
          message: 'previousHash does not match preceding event hash',
        );
      }
    }

    // Verify hash.
    if (!await verifyEventHash(event, event.previousHash)) {
      return ChainValidationError(
        eventId: event.eventId,
        errorType: ChainErrorType.hashMismatch,
        message: 'Computed hash does not match eventHash',
      );
    }

    // Verify signature.
    if (!await verifyEventSignature(event, senderPublicKey)) {
      return ChainValidationError(
        eventId: event.eventId,
        errorType: ChainErrorType.signatureInvalid,
        message: 'Ed25519 signature is invalid',
      );
    }

    // Check HLC monotonicity.
    if (previousEvent != null) {
      if (event.hlc.compareTo(previousEvent.hlc) <= 0) {
        return ChainValidationError(
          eventId: event.eventId,
          errorType: ChainErrorType.hlcViolation,
          message: 'HLC is not monotonically increasing',
        );
      }
    }

    return null;
  }

  /// Verifies that the event's hash matches the computed hash.
  Future<bool> verifyEventHash(
    LedgerEvent event,
    String? previousHash,
  ) async {
    final computed = _eventFactory.computeHashBytes(
      previousHash: previousHash,
      eventType: event.eventType,
      payload: event.payload,
      hlcBytes: event.hlc.toBytes(),
    );
    final computedHex = computed
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
    return computedHex == event.eventHash;
  }

  /// Verifies the Ed25519 signature on the event.
  Future<bool> verifyEventSignature(
    LedgerEvent event,
    StyxPublicKey publicKey,
  ) async {
    final hashBytes = _eventFactory.computeHashBytes(
      previousHash: event.previousHash,
      eventType: event.eventType,
      payload: event.payload,
      hlcBytes: event.hlc.toBytes(),
    );
    return _verifier.verify(
      payload: hashBytes,
      signatureBytes: event.signature,
      publicKey: publicKey,
    );
  }
}
