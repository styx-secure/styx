import '../models/branch_condition.dart';
import '../models/survey_question.dart';
import '../models/survey_schema.dart';

/// Evaluates branch conditions to determine which questions are visible
/// given the current set of answers.
class BranchEvaluator {
  /// Returns the set of visible question IDs given the current answers.
  ///
  /// Handles cascading: if Q2 depends on Q1, and Q1 is hidden,
  /// then Q2 is also hidden regardless of its own condition.
  Set<String> visibleQuestionIds(
    SurveySchema schema,
    Map<String, dynamic> answers,
  ) {
    final visible = <String>{};
    final questionMap = {for (final q in schema.questions) q.id: q};

    for (final question in schema.questions) {
      if (_isVisible(question, answers, questionMap, visible, <String>{})) {
        visible.add(question.id);
      }
    }
    return visible;
  }

  /// Returns answers with hidden question keys removed.
  Map<String, dynamic> cleanHiddenAnswers(
    SurveySchema schema,
    Map<String, dynamic> answers,
  ) {
    final visible = visibleQuestionIds(schema, answers);
    return Map.fromEntries(
      answers.entries.where((e) => visible.contains(e.key)),
    );
  }

  bool _isVisible(
    SurveyQuestion question,
    Map<String, dynamic> answers,
    Map<String, SurveyQuestion> questionMap,
    Set<String> knownVisible,
    Set<String> visiting,
  ) {
    // Cycle detection
    if (visiting.contains(question.id)) return false;

    // No condition means always visible
    if (question.showIf == null) return true;

    // Check cascading: if condition references a field that is itself hidden
    final condition = question.showIf!;
    if (condition.isSimple && condition.field != null) {
      final depQuestion = questionMap[condition.field!];
      if (depQuestion != null && depQuestion.showIf != null) {
        final depVisible = _isVisible(
          depQuestion,
          answers,
          questionMap,
          knownVisible,
          {...visiting, question.id},
        );
        if (!depVisible) return false;
      }
    }

    return evaluate(condition, answers);
  }

  /// Evaluates a single condition against the current answers.
  bool evaluate(BranchCondition condition, Map<String, dynamic> answers) {
    if (condition.all != null) {
      return condition.all!.every((c) => evaluate(c, answers));
    }
    if (condition.any != null) {
      return condition.any!.any((c) => evaluate(c, answers));
    }
    if (!condition.isSimple) return true;

    final actual = answers[condition.field];
    final expected = condition.value;

    return _evaluateOp(condition.op!, actual, expected);
  }

  bool _evaluateOp(String op, dynamic actual, dynamic expected) {
    switch (op) {
      case 'eq':
        return actual == expected;
      case 'neq':
        return actual != expected;
      case 'gt':
        return _compare(actual, expected) > 0;
      case 'lt':
        return _compare(actual, expected) < 0;
      case 'gte':
        return _compare(actual, expected) >= 0;
      case 'lte':
        return _compare(actual, expected) <= 0;
      case 'in':
        if (expected is List) return expected.contains(actual);
        return false;
      case 'contains':
        if (actual is List) return actual.contains(expected);
        if (actual is String && expected is String) {
          return actual.contains(expected);
        }
        return false;
      default:
        return true;
    }
  }

  int _compare(dynamic a, dynamic b) {
    if (a is num && b is num) return a.compareTo(b);
    return a.toString().compareTo(b.toString());
  }
}
