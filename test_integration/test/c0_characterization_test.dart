import 'dart:convert';
import 'dart:io';
import 'dart:isolate';

import 'package:test/test.dart';

import '../bin/c0_characterization.dart';

void main() {
  test('regenerates the exact committed Dart envelope', () async {
    final libraryUri = await Isolate.resolvePackageUri(
      Uri.parse('package:styx_test_integration/styx_test_integration.dart'),
    );
    if (libraryUri == null) {
      fail('Unable to resolve the styx_test_integration package root.');
    }
    final packageRoot = Directory.fromUri(libraryUri.resolve('..'));
    final directory = Directory.fromUri(
      packageRoot.parent.uri.resolve(
        'conformance/application-protocol/c0-characterization/',
      ),
    ).path;
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
