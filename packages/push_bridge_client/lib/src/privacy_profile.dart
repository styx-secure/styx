/// Privacy profile for push notification behavior.
enum PrivacyProfile {
  /// No dummy notifications. Push only for real events.
  ///
  /// Pro: zero extra battery consumption.
  /// Con: push provider knows communication timing.
  balanced,

  /// Dummy notifications at Poisson intervals (~4-6/day).
  ///
  /// The app wakes, checks the dummy flag, and goes back to sleep
  /// without any network I/O.
  ///
  /// Pro: temporal patterns masked.
  /// Con: minimal CPU wake-ups.
  private,

  /// High-frequency dummies with real relay connections.
  ///
  /// The app connects to the relay on every push (including dummies),
  /// making traffic patterns completely indistinguishable.
  ///
  /// Pro: traffic patterns fully masked.
  /// Con: measurable battery consumption.
  paranoid;

  /// Parses a profile from its string name.
  static PrivacyProfile fromString(String value) {
    return PrivacyProfile.values.firstWhere(
      (p) => p.name == value,
      orElse: () => PrivacyProfile.balanced,
    );
  }
}
