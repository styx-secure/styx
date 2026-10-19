import 'package:meta/meta.dart';

/// The result of splitting survey answers into public and private buckets.
@immutable
class SurveySubmission {
  const SurveySubmission({
    required this.surveyId,
    required this.version,
    required this.publicAnswers,
    required this.privateAnswers,
  });

  final String surveyId;
  final int version;

  /// Answers to public questions — sent to the server.
  final Map<String, dynamic> publicAnswers;

  /// Answers to private questions — encrypted E2E via Styx.
  final Map<String, dynamic> privateAnswers;

  bool get hasPrivateAnswers => privateAnswers.isNotEmpty;
}
