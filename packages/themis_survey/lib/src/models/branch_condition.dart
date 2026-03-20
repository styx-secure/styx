import 'package:meta/meta.dart';

/// A condition that controls question visibility via branching logic.
///
/// Simple conditions reference a field with an operator and value.
/// Composite conditions combine multiple conditions with `all` (AND) or `any` (OR).
@immutable
class BranchCondition {
  const BranchCondition({
    this.field,
    this.op,
    this.value,
    this.all,
    this.any,
  });

  factory BranchCondition.fromJson(Map<String, dynamic> json) {
    return BranchCondition(
      field: json['field'] as String?,
      op: json['op'] as String?,
      value: json['value'],
      all: (json['all'] as List<dynamic>?)
          ?.map((e) => BranchCondition.fromJson(e as Map<String, dynamic>))
          .toList(),
      any: (json['any'] as List<dynamic>?)
          ?.map((e) => BranchCondition.fromJson(e as Map<String, dynamic>))
          .toList(),
    );
  }

  final String? field;
  final String? op;
  final dynamic value;
  final List<BranchCondition>? all;
  final List<BranchCondition>? any;

  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{};
    if (field != null) json['field'] = field;
    if (op != null) json['op'] = op;
    if (value != null) json['value'] = value;
    if (all != null) json['all'] = all!.map((c) => c.toJson()).toList();
    if (any != null) json['any'] = any!.map((c) => c.toJson()).toList();
    return json;
  }

  bool get isComposite => all != null || any != null;
  bool get isSimple => field != null && op != null;
}
