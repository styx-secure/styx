import 'package:test/test.dart';
import 'package:transport/transport.dart';

void main() {
  test('package name is correct', () {
    expect(packageName(), 'transport');
  });
}
