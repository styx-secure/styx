import 'dart:convert';

/// Abstraction for sending private survey answers via Styx E2E encryption.
///
/// The actual Styx `sendTransaction()` is injected as a callback to avoid
/// coupling this package directly to the Styx library.
class SurveyStyxBridge {
  SurveyStyxBridge({required this.sendTransaction});

  /// Callback that sends encrypted data via Styx.
  /// Parameters: (eventType, payload JSON string, recipientPublicKey)
  final Future<void> Function(
    String eventType,
    String payload,
    String recipientPublicKey,
  ) sendTransaction;

  /// Encrypts and sends private survey answers via Styx.
  Future<void> sendPrivateAnswers({
    required String surveyId,
    required int version,
    required Map<String, dynamic> privateAnswers,
    required String recipientPublicKey,
  }) async {
    if (privateAnswers.isEmpty) return;

    final payload = jsonEncode({
      'surveyId': surveyId,
      'version': version,
      'answers': privateAnswers,
    });

    await sendTransaction(
      'survey_private_response',
      payload,
      recipientPublicKey,
    );
  }
}
