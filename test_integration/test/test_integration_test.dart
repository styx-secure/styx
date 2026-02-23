import 'package:test/test.dart';
import 'package:test_integration/test_integration.dart';

void main() {
  test('package name is correct', () {
    expect(packageName(), 'test_integration');
  });
}
