import 'package:styx_test_integration/styx_test_integration.dart';
import 'package:test/test.dart';

void main() {
  test('package name is correct', () {
    expect(packageName(), 'styx_test_integration');
  });
}
