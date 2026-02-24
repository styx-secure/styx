/// Determines whether a push notification is a dummy or a real wake-up.
///
/// The push bridge inserts `"d": "1"` in dummy notifications for
/// Private and Paranoid profiles. The detector checks this field.
class DummyDetector {
  /// Creates a [DummyDetector].
  const DummyDetector();

  /// Returns `true` if the push data represents a dummy notification.
  ///
  /// Dummy notifications contain `{"d": "1"}` in their data payload.
  bool isDummy(Map<String, dynamic> data) {
    return data['d'] == '1';
  }
}
