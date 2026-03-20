import '../models/survey_schema.dart';

/// Validates that all required visible fields have answers.
class SurveyValidator {
  /// Returns a list of validation errors. Empty list means valid.
  List<ValidationError> validate({
    required SurveySchema schema,
    required Map<String, dynamic> answers,
    required Set<String> visibleQuestionIds,
  }) {
    final errors = <ValidationError>[];

    for (final question in schema.questions) {
      if (!visibleQuestionIds.contains(question.id)) continue;
      if (!question.required) continue;

      final answer = answers[question.id];
      if (_isEmpty(answer)) {
        errors.add(ValidationError(
          questionId: question.id,
          label: question.label,
          message: 'This field is required',
        ));
      }
    }

    return errors;
  }

  bool _isEmpty(dynamic value) {
    if (value == null) return true;
    if (value is String) return value.trim().isEmpty;
    if (value is List) return value.isEmpty;
    if (value is Map) return value.isEmpty;
    return false;
  }
}

class ValidationError {
  const ValidationError({
    required this.questionId,
    required this.label,
    required this.message,
  });

  final String questionId;
  final String label;
  final String message;

  @override
  String toString() => '$label: $message';
}
