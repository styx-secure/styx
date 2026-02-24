/// State of the Styx library.
enum StyxState {
  /// Not yet initialized.
  uninitialized,

  /// Initialization in progress.
  initializing,

  /// Ready but no peer paired.
  unpaired,

  /// Ready with a paired peer, transport connected.
  ready,

  /// Connected but with transport issues.
  degraded,

  /// Pairing in progress.
  pairing,

  /// Device migration in progress.
  migrating,

  /// Critical error (corrupted database, lost key).
  error,

  /// Shutdown in progress.
  shuttingDown,
}
