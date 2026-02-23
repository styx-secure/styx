import 'package:storage/storage.dart';
import 'package:test/test.dart';

void main() {
  test('package name is correct', () {
    expect(packageName(), 'storage');
  });
}
