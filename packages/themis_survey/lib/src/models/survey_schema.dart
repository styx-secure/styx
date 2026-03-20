import 'package:meta/meta.dart';

import 'survey_question.dart';

@immutable
class SurveySchema {
  const SurveySchema({
    required this.title,
    this.description,
    required this.questions,
  });

  factory SurveySchema.fromJson(Map<String, dynamic> json) {
    return SurveySchema(
      title: json['title'] as String,
      description: json['description'] as String?,
      questions: (json['questions'] as List<dynamic>)
          .map((e) => SurveyQuestion.fromJson(e as Map<String, dynamic>))
          .toList(),
    );
  }

  final String title;
  final String? description;
  final List<SurveyQuestion> questions;

  Map<String, dynamic> toJson() => {
        'title': title,
        if (description != null) 'description': description,
        'questions': questions.map((q) => q.toJson()).toList(),
      };
}
