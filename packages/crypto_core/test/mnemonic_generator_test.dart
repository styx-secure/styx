import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:test/test.dart';

void main() {
  final gen = MnemonicGenerator();

  group('MnemonicGenerator', () {
    test('T3.10 — Generate 6 words', () {
      final mnemonic = gen.generate();
      final words = mnemonic.split(' ');
      expect(words.length, 6);
    });

    test('T3.11 — Generate 8 words', () {
      final mnemonic = gen.generate(wordCount: 8);
      final words = mnemonic.split(' ');
      expect(words.length, 8);
    });

    test('T3.12 — Words in BIP-39 English wordlist', () {
      final mnemonic = gen.generate(wordCount: 12);
      final words = mnemonic.split(' ');
      final wordSet = bip39English.toSet();
      for (final word in words) {
        expect(
          wordSet.contains(word),
          isTrue,
          reason: '"$word" not in wordlist',
        );
      }
    });

    test('T3.13 — Uniqueness: 1000 mnemonics all different', () {
      final mnemonics = <String>{};
      for (var i = 0; i < 1000; i++) {
        mnemonics.add(gen.generate());
      }
      expect(mnemonics.length, 1000);
    });

    test('T3.14 — Validate correct mnemonic', () {
      // 12-word standard BIP-39 with checksum
      final mnemonic = gen.generate(wordCount: 12);
      expect(gen.validate(mnemonic), isTrue);
    });

    test('T3.15 — Validate altered word returns false', () {
      final mnemonic = gen.generate(wordCount: 12);
      final words = mnemonic.split(' ');
      words[2] = 'zzzzz'; // Not in wordlist
      expect(gen.validate(words.join(' ')), isFalse);
    });

    test('T3.16 — MnemonicToSeed deterministic', () async {
      final mnemonic = gen.generate(wordCount: 12);
      final seed1 = await gen.mnemonicToSeed(mnemonic);
      final seed2 = await gen.mnemonicToSeed(mnemonic);
      expect(seed1, equals(seed2));
    });

    test('T3.17 — MnemonicToSeed different mnemonics → different seeds',
        () async {
      final m1 = gen.generate(wordCount: 12);
      final m2 = gen.generate(wordCount: 12);
      final seed1 = await gen.mnemonicToSeed(m1);
      final seed2 = await gen.mnemonicToSeed(m2);
      expect(seed1, isNot(equals(seed2)));
    });

    test('T3.18 — 12-word mnemonic: standard BIP-39 validation OK', () {
      final mnemonic = gen.generate(wordCount: 12);
      final words = mnemonic.split(' ');
      expect(words.length, 12);
      expect(gen.validate(mnemonic), isTrue);
    });

    test('validate non-standard 6-word mnemonic', () {
      final mnemonic = gen.generate();
      expect(gen.validate(mnemonic), isTrue);
    });

    test('supportedLanguages contains english', () {
      expect(gen.supportedLanguages, contains('english'));
    });
  });
}
