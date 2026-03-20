import 'package:flutter_test/flutter_test.dart';
import 'package:themis_survey/themis_survey.dart';

void main() {
  late ResponsePartitioner partitioner;

  setUp(() {
    partitioner = ResponsePartitioner();
  });

  test('splits public and private answers', () {
    final schema = SurveySchema(
      title: 'Test',
      questions: [
        SurveyQuestion(id: 'q1', type: QuestionType.choice, label: 'Q1'),
        SurveyQuestion(
            id: 'q2', type: QuestionType.text, label: 'Q2', private: true),
        SurveyQuestion(id: 'q3', type: QuestionType.rating, label: 'Q3'),
        SurveyQuestion(
            id: 'q4',
            type: QuestionType.longText,
            label: 'Q4',
            private: true),
      ],
    );

    final submission = partitioner.partition(
      surveyId: 'survey-1',
      version: 1,
      schema: schema,
      answers: {
        'q1': 'A',
        'q2': 'private text',
        'q3': 8,
        'q4': 'more private text',
      },
    );

    expect(submission.publicAnswers, equals({'q1': 'A', 'q3': 8}));
    expect(
      submission.privateAnswers,
      equals({'q2': 'private text', 'q4': 'more private text'}),
    );
    expect(submission.hasPrivateAnswers, isTrue);
  });

  test('all public answers', () {
    final schema = SurveySchema(
      title: 'Test',
      questions: [
        SurveyQuestion(id: 'q1', type: QuestionType.choice, label: 'Q1'),
        SurveyQuestion(id: 'q2', type: QuestionType.rating, label: 'Q2'),
      ],
    );

    final submission = partitioner.partition(
      surveyId: 'survey-1',
      version: 1,
      schema: schema,
      answers: {'q1': 'A', 'q2': 5},
    );

    expect(submission.publicAnswers, equals({'q1': 'A', 'q2': 5}));
    expect(submission.privateAnswers, isEmpty);
    expect(submission.hasPrivateAnswers, isFalse);
  });
}
