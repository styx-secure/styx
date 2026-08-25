// Exact Dart runtime adapter for O-14 evidence. Never imported by product code.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';

Uint8List hexBytes(String value) {
  if (value.length.isOdd) {
    throw const FormatException('invalid hex');
  }
  final result = Uint8List(value.length ~/ 2);
  for (var i = 0; i < result.length; i++) {
    result[i] = int.parse(value.substring(2 * i, 2 * i + 2), radix: 16);
  }
  return result;
}

Future<Map<String, Object?>> capture(Future<bool> Function() operation) async {
  try {
    return {'result': await operation(), 'error': null};
  } catch (error) {
    return {'result': false, 'error': error.runtimeType.toString()};
  }
}

Future<void> main(List<String> arguments) async {
  if (arguments.length != 1) {
    throw ArgumentError('usage: dart_adapter.dart VECTORS');
  }
  final vectors = jsonDecode(await File(arguments.single).readAsString()) as List<dynamic>;
  final algorithm = DartEd25519();
  final results = <Map<String, Object?>>[];
  for (final raw in vectors) {
    final vector = raw as Map<String, dynamic>;
    final key = hexBytes(vector['public_key_hex'] as String);
    final signature = hexBytes(vector['signature_hex'] as String);
    final message = hexBytes(vector['message_hex'] as String);
    final observed = await capture(() async {
      final publicKey = SimplePublicKey(key, type: KeyPairType.ed25519);
      return algorithm.verify(
        message,
        signature: Signature(signature, publicKey: publicKey),
      );
    });
    results.add({
      'id': vector['id'],
      'expected_selected': vector['expected_selected'],
      'dart_cryptography_raw': observed,
    });
  }
  stdout.write(jsonEncode({'results': results}));
}
