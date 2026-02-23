import 'package:styx/styx.dart';
import 'package:test/test.dart';

void main() {
  test('package name is correct', () {
    expect(packageName(), 'styx');
  });
}
