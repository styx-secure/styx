import 'package:flutter_test/flutter_test.dart';
import 'package:themis_survey/themis_survey.dart';

void main() {
  late SurveyValidator validator;

  setUp(() {
    validator = SurveyValidator();
  });

  test('passes when all required fields answered', () {
    final schema = SurveySchema(
      title: 'Test',
      questions: [
        SurveyQuestion(
            id: 'q1',
            type: QuestionType.choice,
            label: 'Q1',
            required: true),
        SurveyQuestion(id: 'q2', type: QuestionType.text, label: 'Q2'),
      ],
    );

    final errors = validator.validate(
      schema: schema,
      answers: {'q1': 'A'},
      visibleQuestionIds: {'q1', 'q2'},
    );
    expect(errors, isEmpty);
  });

  test('fails when required field is missing', () {
    final schema = SurveySchema(
      title: 'Test',
      questions: [
        SurveyQuestion(
            id: 'q1',
            type: QuestionType.choice,
            label: 'Q1',
            required: true),
      ],
    );

    final errors = validator.validate(
      schema: schema,
      answers: {},
      visibleQuestionIds: {'q1'},
    );
    expect(errors.length, equals(1));
    expect(errors.first.questionId, equals('q1'));
  });

  test('skips hidden required fields', () {
    final schema = SurveySchema(
      title: 'Test',
      questions: [
        SurveyQuestion(
            id: 'q1',
            type: QuestionType.choice,
            label: 'Q1',
            required: true),
        SurveyQuestion(
            id: 'q2',
            type: QuestionType.text,
            label: 'Q2',
            required: true),
      ],
    );

    // q2 is not visible, so it shouldn't fail
    final errors = validator.validate(
      schema: schema,
      answers: {'q1': 'A'},
      visibleQuestionIds: {'q1'},
    );
    expect(errors, isEmpty);
  });

  test('empty string fails required', () {
    final schema = SurveySchema(
      title: 'Test',
      questions: [
        SurveyQuestion(
            id: 'q1',
            type: QuestionType.text,
            label: 'Q1',
            required: true),
      ],
    );

    final errors = validator.validate(
      schema: schema,
      answers: {'q1': '  '},
      visibleQuestionIds: {'q1'},
    );
    expect(errors.length, equals(1));
  });

  test('empty list fails required', () {
    final schema = SurveySchema(
      title: 'Test',
      questions: [
        SurveyQuestion(
            id: 'q1',
            type: QuestionType.multiChoice,
            label: 'Q1',
            required: true),
      ],
    );

    final errors = validator.validate(
      schema: schema,
      answers: {'q1': <String>[]},
      visibleQuestionIds: {'q1'},
    );
    expect(errors.length, equals(1));
  });
}
