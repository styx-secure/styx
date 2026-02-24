import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:test/test.dart';

void main() {
  final manager = IdentityManager();
  final backup = KeyBackup(
    splitter: ShamirSplitter(),
    reconstructor: ShamirReconstructor(),
  );

  group('KeyBackup', () {
    test('T3.31 — Backup + restore: identical keypair', () async {
      final original = await manager.generate();
      final shares = backup.backupPrivateKey(privateKey: original.privateKey);

      // Use first 2 shares (threshold=2 default)
      final restored = await backup.restoreFromShares(
        [shares[0], shares[1]],
      );

      expect(
        restored.publicKey.bytes,
        equals(original.publicKey.bytes),
      );
      expect(
        restored.privateKey.bytes,
        equals(original.privateKey.bytes),
      );
    });

    test('T3.32 — Restore insufficient shares: wrong result', () async {
      final original = await manager.generate();
      final shares = backup.backupPrivateKey(privateKey: original.privateKey);

      // Only 1 share when threshold=2 → wrong private key
      final restored = await backup.restoreFromShares([shares[0]]);
      expect(
        restored.privateKey.bytes,
        isNot(equals(original.privateKey.bytes)),
      );
    });

    test('T3.33 — Backup produces N shares', () async {
      final kp = await manager.generate();
      final shares = backup.backupPrivateKey(
        privateKey: kp.privateKey,
      );
      expect(shares.length, 3);
    });

    test('T3.34 — Each share has unique index', () async {
      final kp = await manager.generate();
      final shares = backup.backupPrivateKey(
        privateKey: kp.privateKey,
        threshold: 3,
        totalShares: 5,
      );
      final indices = shares.map((s) => s.index).toSet();
      expect(indices, equals({1, 2, 3, 4, 5}));
    });
  });
}
