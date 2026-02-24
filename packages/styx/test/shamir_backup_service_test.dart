import 'package:styx/styx.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:test/test.dart';

void main() {
  late KeyBackup keyBackup;
  late InMemoryKeyStore keyStore;
  late ShamirBackupService backupService;
  late IdentityManager identityManager;

  setUp(() {
    keyBackup = KeyBackup(
      splitter: ShamirSplitter(),
      reconstructor: ShamirReconstructor(),
    );
    keyStore = InMemoryKeyStore();
    backupService = ShamirBackupService(
      keyBackup: keyBackup,
      secureKeyStore: keyStore,
    );
    identityManager = IdentityManager();
  });

  group('ShamirBackupService', () {
    // T11.33: CreateBackup produces N shares -
    //         threshold=2, total=3 -> 3 serialized strings.
    test(
      'T11.33: createBackup produces the correct number '
      'of shares',
      () async {
        final kp = await identityManager.generate();

        final shares = backupService.createBackup(
          privateKey: kp.privateKey,
        );

        expect(shares, hasLength(3));
        for (final share in shares) {
          expect(share, startsWith('styx-share-v1:'));
        }
      },
    );

    // T11.34: RestoreFromBackup round-trip - create ->
    //         restore -> identical keypair.
    test(
      'T11.34: restoreFromBackup round-trip produces '
      'identical keypair',
      () async {
        final kp = await identityManager.generate();

        final shares = backupService.createBackup(
          privateKey: kp.privateKey,
        );

        // Restore using 2 of 3 shares.
        final restoredKp = await backupService.restoreFromBackup(
          serializedShares: shares.sublist(0, 2),
          keyId: 'test-key',
        );

        expect(
          restoredKp.publicKey,
          equals(kp.publicKey),
        );

        // Verify the key was stored.
        final storedKp = await keyStore.retrieveKeyPair('test-key');
        expect(storedKp, isNotNull);
        expect(
          storedKp!.publicKey,
          equals(kp.publicKey),
        );
      },
    );

    // T11.35: VerifyShares valid -
    //         2 correct shares -> true.
    test(
      'T11.35: verifyShares returns true for valid shares',
      () async {
        final kp = await identityManager.generate();

        final shares = backupService.createBackup(
          privateKey: kp.privateKey,
        );

        final valid = await backupService.verifyShares(
          shares.sublist(0, 2),
        );

        expect(valid, isTrue);
      },
    );

    // T11.36: VerifyShares invalid -
    //         1 corrupted share -> false.
    test(
      'T11.36: verifyShares returns false for corrupted '
      'shares',
      () async {
        final kp = await identityManager.generate();

        final shares = backupService.createBackup(
          privateKey: kp.privateKey,
        );

        // Corrupt one share by replacing it with an
        // invalid serialized string.
        final corruptedShares = [
          shares[0],
          'styx-share-v1:2:INVALIDBASE64!!!',
        ];

        final valid = await backupService.verifyShares(
          corruptedShares,
        );

        expect(valid, isFalse);
      },
    );
  });
}
