/// Types of events in the Styx ledger.
enum EventType {
  /// Financial transaction.
  transaction,

  /// Emergency signal.
  sos,

  /// Configuration change.
  config,

  /// Device migration (rekey).
  rekey,

  /// Fork resolution.
  merge,

  /// GDPR deletion request.
  pruneRequest,

  /// GDPR deletion acknowledgement.
  pruneAck,

  /// Generic message.
  message,
}
