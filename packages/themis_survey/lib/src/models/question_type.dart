enum QuestionType {
  choice,
  multiChoice,
  text,
  longText,
  rating,
  likert,
  date,
  nps,
  ranking,
  section;

  static QuestionType fromJson(String value) {
    switch (value) {
      case 'choice':
        return QuestionType.choice;
      case 'multi_choice':
        return QuestionType.multiChoice;
      case 'text':
        return QuestionType.text;
      case 'long_text':
        return QuestionType.longText;
      case 'rating':
        return QuestionType.rating;
      case 'likert':
        return QuestionType.likert;
      case 'date':
        return QuestionType.date;
      case 'nps':
        return QuestionType.nps;
      case 'ranking':
        return QuestionType.ranking;
      case 'section':
        return QuestionType.section;
      default:
        throw ArgumentError('Unknown question type: $value');
    }
  }

  String toJson() {
    switch (this) {
      case QuestionType.choice:
        return 'choice';
      case QuestionType.multiChoice:
        return 'multi_choice';
      case QuestionType.text:
        return 'text';
      case QuestionType.longText:
        return 'long_text';
      case QuestionType.rating:
        return 'rating';
      case QuestionType.likert:
        return 'likert';
      case QuestionType.date:
        return 'date';
      case QuestionType.nps:
        return 'nps';
      case QuestionType.ranking:
        return 'ranking';
      case QuestionType.section:
        return 'section';
    }
  }
}
