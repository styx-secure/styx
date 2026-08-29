import 'package:flutter/material.dart';

import '../models/survey_question.dart';

// ── Choice (single select) ──────────────────────────────────────────────

class ChoiceQuestionWidget extends StatelessWidget {
  const ChoiceQuestionWidget({
    super.key,
    required this.question,
    required this.value,
    required this.onChanged,
  });

  final SurveyQuestion question;
  final String? value;
  final ValueChanged<dynamic> onChanged;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        for (final option in question.options ?? [])
          RadioListTile<String>(
            title: Text(option),
            value: option,
            // ignore: deprecated_member_use
            groupValue: value,
            // ignore: deprecated_member_use
            onChanged: (v) => onChanged(v),
            dense: true,
          ),
      ],
    );
  }
}

// ── Multi Choice ────────────────────────────────────────────────────────

class MultiChoiceQuestionWidget extends StatelessWidget {
  const MultiChoiceQuestionWidget({
    super.key,
    required this.question,
    required this.value,
    required this.onChanged,
  });

  final SurveyQuestion question;
  final List<String> value;
  final ValueChanged<dynamic> onChanged;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        for (final option in question.options ?? [])
          CheckboxListTile(
            title: Text(option),
            value: value.contains(option),
            onChanged: (checked) {
              final updated = List<String>.from(value);
              if (checked == true) {
                updated.add(option);
              } else {
                updated.remove(option);
              }
              onChanged(updated);
            },
            dense: true,
          ),
      ],
    );
  }
}

// ── Text ────────────────────────────────────────────────────────────────

class TextQuestionWidget extends StatelessWidget {
  const TextQuestionWidget({
    super.key,
    required this.question,
    required this.value,
    required this.onChanged,
    this.maxLines = 1,
  });

  final SurveyQuestion question;
  final String? value;
  final ValueChanged<dynamic> onChanged;
  final int maxLines;

  @override
  Widget build(BuildContext context) {
    return TextFormField(
      initialValue: value,
      maxLines: maxLines,
      decoration: InputDecoration(
        hintText: question.description ?? 'Enter your answer',
        border: const OutlineInputBorder(),
      ),
      onChanged: (v) => onChanged(v),
    );
  }
}

// ── Rating ──────────────────────────────────────────────────────────────

class RatingQuestionWidget extends StatelessWidget {
  const RatingQuestionWidget({
    super.key,
    required this.question,
    required this.value,
    required this.onChanged,
  });

  final SurveyQuestion question;
  final int? value;
  final ValueChanged<dynamic> onChanged;

  @override
  Widget build(BuildContext context) {
    final min = question.min ?? 1;
    final max = question.max ?? 10;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (question.minLabel != null || question.maxLabel != null)
          Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                if (question.minLabel != null)
                  Text(
                    question.minLabel!,
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                if (question.maxLabel != null)
                  Text(
                    question.maxLabel!,
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
              ],
            ),
          ),
        Slider(
          min: min.toDouble(),
          max: max.toDouble(),
          divisions: max - min,
          value: (value ?? min).toDouble(),
          label: '${value ?? min}',
          onChanged: (v) => onChanged(v.round()),
        ),
        Center(
          child: Text(
            '${value ?? min}',
            style: Theme.of(context).textTheme.headlineSmall,
          ),
        ),
      ],
    );
  }
}

// ── NPS ─────────────────────────────────────────────────────────────────

class NpsQuestionWidget extends StatelessWidget {
  const NpsQuestionWidget({
    super.key,
    required this.question,
    required this.value,
    required this.onChanged,
  });

  final SurveyQuestion question;
  final int? value;
  final ValueChanged<dynamic> onChanged;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text('Not likely', style: Theme.of(context).textTheme.bodySmall),
            Text('Very likely', style: Theme.of(context).textTheme.bodySmall),
          ],
        ),
        const SizedBox(height: 8),
        Wrap(
          spacing: 4,
          children: List.generate(11, (i) {
            final isSelected = value == i;
            return ChoiceChip(
              label: Text('$i'),
              selected: isSelected,
              onSelected: (_) => onChanged(i),
            );
          }),
        ),
      ],
    );
  }
}

// ── Likert ──────────────────────────────────────────────────────────────

class LikertQuestionWidget extends StatelessWidget {
  const LikertQuestionWidget({
    super.key,
    required this.question,
    required this.value,
    required this.onChanged,
  });

  final SurveyQuestion question;
  final Map<String, dynamic> value;
  final ValueChanged<dynamic> onChanged;

  static const _likertScale = [1, 2, 3, 4, 5];

  @override
  Widget build(BuildContext context) {
    final statements = question.statements ?? [];

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Header row
        Row(
          children: [
            const Expanded(flex: 3, child: SizedBox.shrink()),
            for (final level in _likertScale)
              Expanded(child: Center(child: Text('$level'))),
          ],
        ),
        const Divider(),
        for (final stmt in statements)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 4),
            child: Row(
              children: [
                Expanded(
                  flex: 3,
                  child: Text(stmt, style: Theme.of(context).textTheme.bodyMedium),
                ),
                for (final level in _likertScale)
                  Expanded(
                    child: Radio<int>(
                      value: level,
                      // ignore: deprecated_member_use
                      groupValue: value[stmt] as int?,
                      // ignore: deprecated_member_use
                      onChanged: (v) {
                        final updated = Map<String, dynamic>.from(value);
                        updated[stmt] = v;
                        onChanged(updated);
                      },
                    ),
                  ),
              ],
            ),
          ),
      ],
    );
  }
}

// ── Date ────────────────────────────────────────────────────────────────

class DateQuestionWidget extends StatelessWidget {
  const DateQuestionWidget({
    super.key,
    required this.question,
    required this.value,
    required this.onChanged,
  });

  final SurveyQuestion question;
  final String? value;
  final ValueChanged<dynamic> onChanged;

  @override
  Widget build(BuildContext context) {
    return OutlinedButton.icon(
      icon: const Icon(Icons.calendar_today),
      label: Text(value ?? 'Select date'),
      onPressed: () async {
        final date = await showDatePicker(
          context: context,
          initialDate: DateTime.now(),
          firstDate: DateTime(2000),
          lastDate: DateTime(2100),
        );
        if (date != null) {
          onChanged(date.toIso8601String().split('T').first);
        }
      },
    );
  }
}

// ── Ranking ─────────────────────────────────────────────────────────────

class RankingQuestionWidget extends StatefulWidget {
  const RankingQuestionWidget({
    super.key,
    required this.question,
    required this.value,
    required this.onChanged,
  });

  final SurveyQuestion question;
  final List<String> value;
  final ValueChanged<dynamic> onChanged;

  @override
  State<RankingQuestionWidget> createState() => _RankingQuestionWidgetState();
}

class _RankingQuestionWidgetState extends State<RankingQuestionWidget> {
  @override
  Widget build(BuildContext context) {
    final items = widget.value.isNotEmpty
        ? widget.value
        : List<String>.from(widget.question.options ?? []);

    return ReorderableListView.builder(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      itemCount: items.length,
      onReorder: (oldIndex, newIndex) {
        final updated = List<String>.from(items);
        if (newIndex > oldIndex) newIndex--;
        final item = updated.removeAt(oldIndex);
        updated.insert(newIndex, item);
        widget.onChanged(updated);
      },
      itemBuilder: (context, index) {
        return ListTile(
          key: ValueKey(items[index]),
          leading: CircleAvatar(
            radius: 14,
            child: Text('${index + 1}'),
          ),
          title: Text(items[index]),
          trailing: const Icon(Icons.drag_handle),
        );
      },
    );
  }
}

// ── Section Header ──────────────────────────────────────────────────────

class SectionWidget extends StatelessWidget {
  const SectionWidget({
    super.key,
    required this.question,
  });

  final SurveyQuestion question;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Divider(height: 32),
        Text(
          question.label,
          style: Theme.of(context).textTheme.titleLarge,
        ),
        if (question.description != null)
          Padding(
            padding: const EdgeInsets.only(top: 4),
            child: Text(
              question.description!,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
            ),
          ),
      ],
    );
  }
}
