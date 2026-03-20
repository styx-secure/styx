import 'package:meta/meta.dart';

import 'branch_condition.dart';
import 'question_type.dart';

@immutable
class SurveyQuestion {
  const SurveyQuestion({
    required this.id,
    required this.type,
    required this.label,
    this.description,
    this.required = false,
    this.private = false,
    this.options,
    this.statements,
    this.min,
    this.max,
    this.minLabel,
    this.maxLabel,
    this.showIf,
  });

  factory SurveyQuestion.fromJson(Map<String, dynamic> json) {
    return SurveyQuestion(
      id: json['id'] as String,
      type: QuestionType.fromJson(json['type'] as String),
      label: json['label'] as String,
      description: json['description'] as String?,
      required: json['required'] as bool? ?? false,
      private: json['private'] as bool? ?? false,
      options:
          (json['options'] as List<dynamic>?)?.map((e) => e as String).toList(),
      statements: (json['statements'] as List<dynamic>?)
          ?.map((e) => e as String)
          .toList(),
      min: (json['min'] as num?)?.toInt(),
      max: (json['max'] as num?)?.toInt(),
      minLabel: json['minLabel'] as String?,
      maxLabel: json['maxLabel'] as String?,
      showIf: json['showIf'] != null
          ? BranchCondition.fromJson(json['showIf'] as Map<String, dynamic>)
          : null,
    );
  }

  final String id;
  final QuestionType type;
  final String label;
  final String? description;
  final bool required;
  final bool private;
  final List<String>? options;
  final List<String>? statements;
  final int? min;
  final int? max;
  final String? minLabel;
  final String? maxLabel;
  final BranchCondition? showIf;

  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{
      'id': id,
      'type': type.toJson(),
      'label': label,
    };
    if (description != null) json['description'] = description;
    if (required) json['required'] = required;
    if (private) json['private'] = private;
    if (options != null) json['options'] = options;
    if (statements != null) json['statements'] = statements;
    if (min != null) json['min'] = min;
    if (max != null) json['max'] = max;
    if (minLabel != null) json['minLabel'] = minLabel;
    if (maxLabel != null) json['maxLabel'] = maxLabel;
    if (showIf != null) json['showIf'] = showIf!.toJson();
    return json;
  }
}
