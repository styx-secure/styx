import 'package:flutter_test/flutter_test.dart';
import 'package:themis_survey/themis_survey.dart';

void main() {
  late BranchEvaluator evaluator;

  setUp(() {
    evaluator = BranchEvaluator();
  });

  group('evaluate - simple operators', () {
    test('eq', () {
      final cond = BranchCondition(field: 'q1', op: 'eq', value: 'Yes');
      expect(evaluator.evaluate(cond, {'q1': 'Yes'}), isTrue);
      expect(evaluator.evaluate(cond, {'q1': 'No'}), isFalse);
    });

    test('neq', () {
      final cond = BranchCondition(field: 'q1', op: 'neq', value: 'Yes');
      expect(evaluator.evaluate(cond, {'q1': 'No'}), isTrue);
      expect(evaluator.evaluate(cond, {'q1': 'Yes'}), isFalse);
    });

    test('gt', () {
      final cond = BranchCondition(field: 'q1', op: 'gt', value: 5);
      expect(evaluator.evaluate(cond, {'q1': 7}), isTrue);
      expect(evaluator.evaluate(cond, {'q1': 5}), isFalse);
      expect(evaluator.evaluate(cond, {'q1': 3}), isFalse);
    });

    test('lt', () {
      final cond = BranchCondition(field: 'q1', op: 'lt', value: 5);
      expect(evaluator.evaluate(cond, {'q1': 3}), isTrue);
      expect(evaluator.evaluate(cond, {'q1': 5}), isFalse);
    });

    test('gte', () {
      final cond = BranchCondition(field: 'q1', op: 'gte', value: 5);
      expect(evaluator.evaluate(cond, {'q1': 5}), isTrue);
      expect(evaluator.evaluate(cond, {'q1': 6}), isTrue);
      expect(evaluator.evaluate(cond, {'q1': 4}), isFalse);
    });

    test('lte', () {
      final cond = BranchCondition(field: 'q1', op: 'lte', value: 5);
      expect(evaluator.evaluate(cond, {'q1': 5}), isTrue);
      expect(evaluator.evaluate(cond, {'q1': 4}), isTrue);
      expect(evaluator.evaluate(cond, {'q1': 6}), isFalse);
    });

    test('in', () {
      final cond = BranchCondition(field: 'q1', op: 'in', value: ['A', 'B']);
      expect(evaluator.evaluate(cond, {'q1': 'A'}), isTrue);
      expect(evaluator.evaluate(cond, {'q1': 'C'}), isFalse);
    });

    test('contains (list)', () {
      final cond = BranchCondition(field: 'q1', op: 'contains', value: 'X');
      expect(evaluator.evaluate(cond, {'q1': ['X', 'Y']}), isTrue);
      expect(evaluator.evaluate(cond, {'q1': ['Y', 'Z']}), isFalse);
    });

    test('contains (string)', () {
      final cond = BranchCondition(field: 'q1', op: 'contains', value: 'foo');
      expect(evaluator.evaluate(cond, {'q1': 'foobar'}), isTrue);
      expect(evaluator.evaluate(cond, {'q1': 'baz'}), isFalse);
    });
  });

  group('evaluate - composite conditions', () {
    test('all (AND)', () {
      final cond = BranchCondition(all: [
        BranchCondition(field: 'q1', op: 'eq', value: 'Yes'),
        BranchCondition(field: 'q2', op: 'gt', value: 3),
      ]);
      expect(evaluator.evaluate(cond, {'q1': 'Yes', 'q2': 5}), isTrue);
      expect(evaluator.evaluate(cond, {'q1': 'Yes', 'q2': 2}), isFalse);
      expect(evaluator.evaluate(cond, {'q1': 'No', 'q2': 5}), isFalse);
    });

    test('any (OR)', () {
      final cond = BranchCondition(any: [
        BranchCondition(field: 'q1', op: 'eq', value: 'Yes'),
        BranchCondition(field: 'q2', op: 'gt', value: 3),
      ]);
      expect(evaluator.evaluate(cond, {'q1': 'Yes', 'q2': 1}), isTrue);
      expect(evaluator.evaluate(cond, {'q1': 'No', 'q2': 5}), isTrue);
      expect(evaluator.evaluate(cond, {'q1': 'No', 'q2': 1}), isFalse);
    });

    test('nested composite', () {
      final cond = BranchCondition(all: [
        BranchCondition(field: 'q1', op: 'eq', value: 'Yes'),
        BranchCondition(any: [
          BranchCondition(field: 'q2', op: 'gt', value: 5),
          BranchCondition(field: 'q3', op: 'eq', value: 'High'),
        ]),
      ]);
      expect(
        evaluator.evaluate(cond, {'q1': 'Yes', 'q2': 7, 'q3': 'Low'}),
        isTrue,
      );
      expect(
        evaluator.evaluate(cond, {'q1': 'Yes', 'q2': 3, 'q3': 'High'}),
        isTrue,
      );
      expect(
        evaluator.evaluate(cond, {'q1': 'Yes', 'q2': 3, 'q3': 'Low'}),
        isFalse,
      );
    });
  });

  group('visibleQuestionIds', () {
    test('unconditional questions are always visible', () {
      final schema = SurveySchema(
        title: 'Test',
        questions: [
          SurveyQuestion(id: 'q1', type: QuestionType.choice, label: 'Q1'),
          SurveyQuestion(id: 'q2', type: QuestionType.text, label: 'Q2'),
        ],
      );
      final visible = evaluator.visibleQuestionIds(schema, {});
      expect(visible, containsAll(['q1', 'q2']));
    });

    test('conditional question hidden when condition not met', () {
      final schema = SurveySchema(
        title: 'Test',
        questions: [
          SurveyQuestion(
            id: 'q1',
            type: QuestionType.choice,
            label: 'Q1',
            options: ['Yes', 'No'],
          ),
          SurveyQuestion(
            id: 'q2',
            type: QuestionType.text,
            label: 'Q2',
            showIf: BranchCondition(field: 'q1', op: 'eq', value: 'Yes'),
          ),
        ],
      );

      expect(
        evaluator.visibleQuestionIds(schema, {'q1': 'No'}),
        isNot(contains('q2')),
      );
      expect(
        evaluator.visibleQuestionIds(schema, {'q1': 'Yes'}),
        contains('q2'),
      );
    });

    test('cascading visibility', () {
      final schema = SurveySchema(
        title: 'Test',
        questions: [
          SurveyQuestion(
            id: 'q1',
            type: QuestionType.choice,
            label: 'Q1',
            options: ['Yes', 'No'],
          ),
          SurveyQuestion(
            id: 'q2',
            type: QuestionType.choice,
            label: 'Q2',
            options: ['A', 'B'],
            showIf: BranchCondition(field: 'q1', op: 'eq', value: 'Yes'),
          ),
          SurveyQuestion(
            id: 'q3',
            type: QuestionType.text,
            label: 'Q3',
            showIf: BranchCondition(field: 'q2', op: 'eq', value: 'A'),
          ),
        ],
      );

      // Q1=No → Q2 hidden → Q3 also hidden (cascade)
      final hidden = evaluator.visibleQuestionIds(schema, {'q1': 'No', 'q2': 'A'});
      expect(hidden, contains('q1'));
      expect(hidden, isNot(contains('q2')));
      expect(hidden, isNot(contains('q3')));

      // Q1=Yes, Q2=A → all visible
      final allVisible = evaluator.visibleQuestionIds(schema, {'q1': 'Yes', 'q2': 'A'});
      expect(allVisible, containsAll(['q1', 'q2', 'q3']));
    });
  });

  group('cleanHiddenAnswers', () {
    test('removes answers for hidden questions', () {
      final schema = SurveySchema(
        title: 'Test',
        questions: [
          SurveyQuestion(
            id: 'q1',
            type: QuestionType.choice,
            label: 'Q1',
            options: ['Yes', 'No'],
          ),
          SurveyQuestion(
            id: 'q2',
            type: QuestionType.text,
            label: 'Q2',
            showIf: BranchCondition(field: 'q1', op: 'eq', value: 'Yes'),
          ),
        ],
      );
      final cleaned = evaluator.cleanHiddenAnswers(
        schema,
        {'q1': 'No', 'q2': 'should be removed'},
      );
      expect(cleaned, equals({'q1': 'No'}));
    });
  });
}
