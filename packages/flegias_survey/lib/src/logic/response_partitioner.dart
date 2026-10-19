import '../models/survey_schema.dart';
import '../models/survey_submission.dart';

/// Splits survey answers into public and private buckets based on
/// each question's `private` flag.
class ResponsePartitioner {
  /// Partitions [answers] into a [SurveySubmission] with public and private buckets.
  ///
  /// Public answers are sent to the server. Private answers are encrypted
  /// E2E via Styx and never touch the server.
  SurveySubmission partition({
    required String surveyId,
    required int version,
    required SurveySchema schema,
    required Map<String, dynamic> answers,
  }) {
    final privateIds = <String>{};
    for (final q in schema.questions) {
      if (q.private) privateIds.add(q.id);
    }

    final publicAnswers = <String, dynamic>{};
    final privateAnswers = <String, dynamic>{};

    for (final entry in answers.entries) {
      if (privateIds.contains(entry.key)) {
        privateAnswers[entry.key] = entry.value;
      } else {
        publicAnswers[entry.key] = entry.value;
      }
    }

    return SurveySubmission(
      surveyId: surveyId,
      version: version,
      publicAnswers: publicAnswers,
      privateAnswers: privateAnswers,
    );
  }
}
