import 'dart:convert';

import 'package:http/http.dart' as http;

import '../models/survey_schema.dart';

/// Fetches survey schemas from the server and submits public answers.
class SurveyApiClient {
  SurveyApiClient({required this.baseUrl, http.Client? client})
      : _client = client ?? http.Client();

  final String baseUrl;
  final http.Client _client;

  /// Fetches survey schema by ID (no auth required).
  Future<SurveyFetchResult> fetchSurvey(String surveyId) async {
    final response = await _client.get(
      Uri.parse('$baseUrl/surveys/$surveyId'),
      headers: {'Content-Type': 'application/json'},
    );

    if (response.statusCode != 200) {
      throw Exception('Failed to fetch survey: ${response.body}');
    }

    final json = jsonDecode(response.body) as Map<String, dynamic>;
    return SurveyFetchResult(
      id: json['id'] as String,
      title: json['title'] as String,
      version: json['version'] as int,
      status: json['status'] as String,
      schema: SurveySchema.fromJson(json['schema'] as Map<String, dynamic>),
    );
  }

  /// Lists active surveys for an organization (no auth required for listing).
  Future<List<SurveyListItem>> listActiveSurveys(String orgId) async {
    final response = await _client.get(
      Uri.parse('$baseUrl/surveys?org_id=$orgId&status=ACTIVE'),
      headers: {'Content-Type': 'application/json'},
    );

    if (response.statusCode != 200) {
      throw Exception('Failed to list surveys: ${response.body}');
    }

    final list = jsonDecode(response.body) as List<dynamic>;
    return list
        .map((e) => SurveyListItem.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// Submits public answers to the server (no auth, anonymous).
  Future<void> submitPublicAnswers({
    required String surveyId,
    required Map<String, dynamic> answers,
  }) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/surveys/$surveyId/responses'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'answers': answers}),
    );

    if (response.statusCode != 201) {
      throw Exception('Failed to submit response: ${response.body}');
    }
  }

  void dispose() => _client.close();
}

class SurveyFetchResult {
  const SurveyFetchResult({
    required this.id,
    required this.title,
    required this.version,
    required this.status,
    required this.schema,
  });

  final String id;
  final String title;
  final int version;
  final String status;
  final SurveySchema schema;
}

class SurveyListItem {
  const SurveyListItem({
    required this.id,
    required this.title,
    this.description,
    required this.status,
  });

  factory SurveyListItem.fromJson(Map<String, dynamic> json) {
    return SurveyListItem(
      id: json['id'] as String,
      title: json['title'] as String,
      description: json['description'] as String?,
      status: json['status'] as String,
    );
  }

  final String id;
  final String title;
  final String? description;
  final String status;
}
