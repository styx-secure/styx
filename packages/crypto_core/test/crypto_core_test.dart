import 'package:crypto_core/crypto_core.dart';
import 'package:test/test.dart';

void main() {
  test('package name is correct', () {
    expect(packageName(), 'crypto_core');
  });
}
