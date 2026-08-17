import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

import '../bin/c0_characterization.dart';

void main() {
  test('regenerates the exact committed Dart envelope', () async {
    const directory = '../conformance/application-protocol/c0-characterization';
    final report =
        jsonDecode(
              File('$directory/report.json').readAsStringSync(),
            )
            as Map<String, dynamic>;
    final schema =
        jsonDecode(
              File('$directory/schema.json').readAsStringSync(),
            )
            as Map<String, dynamic>;
    final envelope = await runCharacterization('$directory/cases.json');

    validateEnvelope(envelope, schema);
    expect(
      canonicalJson(envelope),
      canonicalJson(
        (report['runtimeEnvelopes'] as Map<String, dynamic>)['dart'],
      ),
    );
  });
}
