import 'package:styx_push_bridge_client/src/privacy_profile.dart';

/// Abstract HTTP client for communicating with the Push Bridge server.
///
/// Implementations should use `dart:io` HttpClient or `package:http`.
/// This abstraction enables testing without a real HTTP stack.
abstract class BridgeHttpClient {
  /// Sends a POST request and returns the status code.
  Future<int> post(String path, Map<String, dynamic> body);

  /// Sends a GET request and returns the response body.
  Future<String> get(String path);
}

/// Client for registering/unregistering with the Push Bridge server.
class PushBridgeClient {
  /// Creates a [PushBridgeClient].
  PushBridgeClient({
    required String bridgeUrl,
    required BridgeHttpClient httpClient,
  })  : _bridgeUrl = bridgeUrl,
        _httpClient = httpClient;

  final String _bridgeUrl;
  final BridgeHttpClient _httpClient;

  /// The configured bridge URL.
  String get bridgeUrl => _bridgeUrl;

  /// Registers the device with the Push Bridge.
  Future<void> register({
    required String fcmToken,
    required String nostrPubkey,
    required PrivacyProfile profile,
    String platform = 'android',
  }) async {
    await _httpClient.post('/register', {
      'fcm_token': fcmToken,
      'nostr_pubkey': nostrPubkey,
      'platform': platform,
      'privacy_profile': profile.name,
    });
  }

  /// Unregisters the device from the Push Bridge.
  Future<void> unregister({required String fcmToken}) async {
    await _httpClient.post('/unregister', {
      'fcm_token': fcmToken,
    });
  }

  /// Updates the privacy profile by re-registering.
  Future<void> updateProfile({
    required String fcmToken,
    required String nostrPubkey,
    required PrivacyProfile profile,
    String platform = 'android',
  }) async {
    await register(
      fcmToken: fcmToken,
      nostrPubkey: nostrPubkey,
      profile: profile,
      platform: platform,
    );
  }
}
