import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart' as cryptography;
import 'package:styx_crypto_core/src/bip39_english.dart';

/// The set of word counts that follow standard BIP-39 encoding
/// (entropy + checksum in multiples of 33 bits / 3 words).
const _standardWordCounts = {12, 15, 18, 21, 24};

/// BIP-39 mnemonic code generation for remote pairing.
///
/// Supports standard BIP-39 word counts (12, 15, 18, 21, 24) with
/// checksum verification, and non-standard counts (6, 8) that select
/// random words from the wordlist without BIP-39 checksum.
class MnemonicGenerator {
  final Random _random = Random.secure();

  /// Generates a BIP-39 mnemonic code with [wordCount] words.
  ///
  /// Standard BIP-39 (12, 15, 18, 21, 24 words) includes checksum.
  /// Non-standard (6, 8 words) selects random wordlist entries without
  /// checksum — sufficient for SPAKE2 where offline brute-force is
  /// infeasible.
  String generate({int wordCount = 6}) {
    if (_standardWordCounts.contains(wordCount)) {
      return _generateStandard(wordCount);
    }
    return _generateRandom(wordCount);
  }

  /// Validates syntactic correctness of [mnemonic].
  ///
  /// For standard BIP-39 (12–24 words): verifies words are in
  /// wordlist and checksum is valid.
  /// For non-standard (6, 8 words): verifies words are in wordlist.
  bool validate(String mnemonic) {
    final words = mnemonic.trim().split(RegExp(r'\s+'));
    if (words.isEmpty) return false;

    // Check all words are in the wordlist.
    final wordSet = bip39English.toSet();
    for (final word in words) {
      if (!wordSet.contains(word)) return false;
    }

    if (_standardWordCounts.contains(words.length)) {
      return _validateChecksum(words);
    }

    return true;
  }

  /// Converts [mnemonic] to a seed for SPAKE2 password use.
  ///
  /// Uses PBKDF2-SHA512 with 2048 iterations and empty passphrase
  /// per BIP-39 specification.
  Future<Uint8List> mnemonicToSeed(String mnemonic) async {
    final pbkdf2 = cryptography.Pbkdf2(
      macAlgorithm: cryptography.Hmac.sha512(),
      iterations: 2048,
      bits: 512,
    );

    final secretKey = cryptography.SecretKey(
      mnemonic.codeUnits,
    );

    final derived = await pbkdf2.deriveKey(
      secretKey: secretKey,
      nonce: 'mnemonic'.codeUnits,
    );

    return Uint8List.fromList(await derived.extractBytes());
  }

  /// Supported languages (currently English only).
  List<String> get supportedLanguages => const ['english'];

  // -------------------------------------------------------------------------
  // Standard BIP-39 generation (with checksum)
  // -------------------------------------------------------------------------

  String _generateStandard(int wordCount) {
    // wordCount = (entropyBits + checksumBits) / 11
    // entropyBits = wordCount * 11 - wordCount / 3
    // Simplified: entropyBits = wordCount * 32 / 3
    final entropyBits = wordCount * 32 ~/ 3;
    final entropyBytes = entropyBits ~/ 8;

    final entropy = Uint8List(entropyBytes);
    for (var i = 0; i < entropyBytes; i++) {
      entropy[i] = _random.nextInt(256);
    }

    return _entropyToMnemonic(entropy);
  }

  String _entropyToMnemonic(Uint8List entropy) {
    final checksumBits = entropy.length ~/ 4; // 1 bit per 32 bits of entropy
    final hash = crypto.sha256.convert(entropy);

    // Build bit string: entropy bits + checksum bits
    final bits = StringBuffer();
    for (final byte in entropy) {
      bits.write(byte.toRadixString(2).padLeft(8, '0'));
    }
    for (var i = 0; i < checksumBits; i++) {
      final byteIndex = i ~/ 8;
      final bitIndex = 7 - (i % 8);
      bits.write((hash.bytes[byteIndex] >> bitIndex) & 1);
    }

    final bitString = bits.toString();
    final words = <String>[];
    for (var i = 0; i < bitString.length; i += 11) {
      final index = int.parse(bitString.substring(i, i + 11), radix: 2);
      words.add(bip39English[index]);
    }

    return words.join(' ');
  }

  // -------------------------------------------------------------------------
  // Non-standard generation (random wordlist selection)
  // -------------------------------------------------------------------------

  String _generateRandom(int wordCount) {
    final words = <String>[];
    for (var i = 0; i < wordCount; i++) {
      words.add(bip39English[_random.nextInt(bip39English.length)]);
    }
    return words.join(' ');
  }

  // -------------------------------------------------------------------------
  // Checksum validation
  // -------------------------------------------------------------------------

  bool _validateChecksum(List<String> words) {
    final wordMap = <String, int>{};
    for (var i = 0; i < bip39English.length; i++) {
      wordMap[bip39English[i]] = i;
    }

    // Convert words to bit string
    final bits = StringBuffer();
    for (final word in words) {
      final index = wordMap[word];
      if (index == null) return false;
      bits.write(index.toRadixString(2).padLeft(11, '0'));
    }

    final bitString = bits.toString();
    final totalBits = bitString.length;
    final checksumBits = totalBits ~/ 33; // CS = ENT / 32
    final entropyBits = totalBits - checksumBits;

    // Extract entropy bytes
    final entropyBytes = Uint8List(entropyBits ~/ 8);
    for (var i = 0; i < entropyBytes.length; i++) {
      entropyBytes[i] = int.parse(
        bitString.substring(i * 8, i * 8 + 8),
        radix: 2,
      );
    }

    // Compute expected checksum
    final hash = crypto.sha256.convert(entropyBytes);
    final expectedBits = StringBuffer();
    for (var i = 0; i < checksumBits; i++) {
      final byteIndex = i ~/ 8;
      final bitIndex = 7 - (i % 8);
      expectedBits.write((hash.bytes[byteIndex] >> bitIndex) & 1);
    }

    final actualChecksum = bitString.substring(entropyBits);
    return actualChecksum == expectedBits.toString();
  }
}
