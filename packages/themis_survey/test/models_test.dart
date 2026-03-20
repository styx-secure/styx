import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:themis_survey/themis_survey.dart';

void main() {
  group('QuestionType', () {
    test('round-trip serialization', () {
      for (final type in QuestionType.values) {
        final json = type.toJson();
        final parsed = QuestionType.fromJson(json);
        expect(parsed, equals(type));
      }
    });
  });

  group('BranchCondition', () {
    test('simple condition round-trip', () {
      final condition = BranchCondition(
        field: 'q1',
        op: 'eq',
        value: 'Yes',
      );
      final json = condition.toJson();
      final parsed = BranchCondition.fromJson(json);
      expect(parsed.field, equals('q1'));
      expect(parsed.op, equals('eq'));
      expect(parsed.value, equals('Yes'));
    });

    test('composite condition round-trip', () {
      final condition = BranchCondition(
        all: [
          BranchCondition(field: 'q1', op: 'eq', value: 'Yes'),
          BranchCondition(field: 'q2', op: 'gt', value: 5),
        ],
      );
      final json = condition.toJson();
      final parsed = BranchCondition.fromJson(json);
      expect(parsed.isComposite, isTrue);
      expect(parsed.all!.length, equals(2));
    });
  });

  group('SurveyQuestion', () {
    test('round-trip with all fields', () {
      final question = SurveyQuestion(
        id: 'q1',
        type: QuestionType.choice,
        label: 'Favorite color?',
        description: 'Pick one',
        required: true,
        private: false,
        options: ['Red', 'Blue', 'Green'],
        showIf: BranchCondition(field: 'q0', op: 'eq', value: 'Yes'),
      );
      final json = question.toJson();
      final parsed = SurveyQuestion.fromJson(json);
      expect(parsed.id, equals('q1'));
      expect(parsed.type, equals(QuestionType.choice));
      expect(parsed.label, equals('Favorite color?'));
      expect(parsed.required, isTrue);
      expect(parsed.options, equals(['Red', 'Blue', 'Green']));
      expect(parsed.showIf, isNotNull);
      expect(parsed.showIf!.field, equals('q0'));
    });

    test('round-trip likert question', () {
      final question = SurveyQuestion(
        id: 'q2',
        type: QuestionType.likert,
        label: 'Rate these',
        statements: ['Fair pay', 'Good culture'],
      );
      final json = question.toJson();
      final parsed = SurveyQuestion.fromJson(json);
      expect(parsed.type, equals(QuestionType.likert));
      expect(parsed.statements, equals(['Fair pay', 'Good culture']));
    });
  });

  group('SurveySchema', () {
    test('round-trip full schema', () {
      final schema = SurveySchema(
        title: 'Test Survey',
        description: 'A test',
        questions: [
          SurveyQuestion(
            id: 'q1',
            type: QuestionType.choice,
            label: 'Q1',
            options: ['A', 'B'],
          ),
          SurveyQuestion(
            id: 'q2',
            type: QuestionType.text,
            label: 'Q2',
            private: true,
          ),
        ],
      );
      final jsonStr = jsonEncode(schema.toJson());
      final parsed =
          SurveySchema.fromJson(jsonDecode(jsonStr) as Map<String, dynamic>);
      expect(parsed.title, equals('Test Survey'));
      expect(parsed.questions.length, equals(2));
      expect(parsed.questions[1].private, isTrue);
    });
  });
}
