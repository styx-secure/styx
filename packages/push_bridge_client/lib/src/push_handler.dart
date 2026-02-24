import 'package:styx_push_bridge_client/src/dummy_detector.dart';
import 'package:styx_push_bridge_client/src/privacy_profile.dart';

/// Abstract interface for push messaging services.
///
/// In production, this wraps `firebase_messaging`. For testing, use a fake.
abstract class PushMessagingService {
  /// Returns the current FCM/APNs token.
  Future<String?> getToken();

  /// Stream of token refreshes.
  Stream<String> get onTokenRefresh;
}

/// Callback type for wake-up handling.
typedef WakeUpCallback = Future<void> Function();

/// Callback type for token refresh handling.
typedef TokenRefreshCallback = Future<void> Function(String newToken);

/// Handles incoming push notifications.
///
/// Determines whether a push is real or dummy, and acts according to
/// the configured [PrivacyProfile].
class PushHandler {
  /// Creates a [PushHandler].
  PushHandler({
    required this.profile,
    required WakeUpCallback onWakeUp,
    required WakeUpCallback onConnectRelay,
    TokenRefreshCallback? onTokenRefresh,
    DummyDetector? detector,
  })  : _onWakeUp = onWakeUp,
        _onConnectRelay = onConnectRelay,
        _onTokenRefresh = onTokenRefresh,
        _detector = detector ?? const DummyDetector();

  /// The active privacy profile.
  final PrivacyProfile profile;

  final WakeUpCallback _onWakeUp;
  final WakeUpCallback _onConnectRelay;
  final TokenRefreshCallback? _onTokenRefresh;
  final DummyDetector _detector;

  int _realCount = 0;
  int _dummyCount = 0;
  int _connectCount = 0;

  /// Number of real wake-ups processed.
  int get realCount => _realCount;

  /// Number of dummy notifications detected.
  int get dummyCount => _dummyCount;

  /// Number of relay connections made (real + paranoid dummy).
  int get connectCount => _connectCount;

  /// Handles an incoming push notification data payload.
  ///
  /// Behavior depends on [profile]:
  /// - **Balanced:** Only real pushes trigger wake-up.
  /// - **Private:** Dummy pushes are silently dropped (zero network I/O).
  /// - **Paranoid:** Dummy pushes still connect to the relay.
  Future<void> handleMessage(Map<String, dynamic> data) async {
    final isDummy = _detector.isDummy(data);

    if (isDummy) {
      _dummyCount++;
      if (profile == PrivacyProfile.paranoid) {
        // Paranoid: connect to relay even for dummies.
        _connectCount++;
        await _onConnectRelay();
      }
      return;
    }

    // Real push — always wake up.
    _realCount++;
    _connectCount++;
    await _onWakeUp();
  }

  /// Handles a token refresh event.
  Future<void> handleTokenRefresh(String newToken) async {
    await _onTokenRefresh?.call(newToken);
  }
}
