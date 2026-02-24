import 'package:styx/styx.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:test/test.dart';

void main() {
  late InMemoryPeerStore peerStore;
  late TrustStoreManager trustStore;

  setUp(() {
    peerStore = InMemoryPeerStore();
    trustStore = TrustStoreManager(peerStore: peerStore);
  });

  group('TrustStoreManager', () {
    // T11.17: AddTrustedPeer + isTrusted -> true
    test(
      'T11.17: addTrustedPeer makes the peer trusted',
      () async {
        final key = StyxPublicKey.fromHex('aa' * 32);

        await trustStore.addTrustedPeer(
          peerPublicKey: key,
          alias: 'Alice',
        );

        expect(await trustStore.isTrusted(key), isTrue);
      },
    );

    // T11.18: RevokePeer -> isTrusted == false
    test(
      'T11.18: revokePeer makes the peer untrusted',
      () async {
        final key = StyxPublicKey.fromHex('bb' * 32);

        await trustStore.addTrustedPeer(
          peerPublicKey: key,
          alias: 'Bob',
        );
        expect(await trustStore.isTrusted(key), isTrue);

        await trustStore.revokePeer(key);
        expect(await trustStore.isTrusted(key), isFalse);
      },
    );

    // T11.19: GetActivePeer with 1 active peer -> returns peer
    test(
      'T11.19: getActivePeer returns the active peer',
      () async {
        final key = StyxPublicKey.fromHex('cc' * 32);

        await trustStore.addTrustedPeer(
          peerPublicKey: key,
          alias: 'Carol',
        );

        final peer = await trustStore.getActivePeer();
        expect(peer, isNotNull);
        expect(peer!.publicKey, equals(key));
        expect(peer.alias, equals('Carol'));
        expect(peer.isActive, isTrue);
      },
    );

    // T11.20: GetActivePeer no peers -> null
    test(
      'T11.20: getActivePeer returns null when no peers',
      () async {
        final peer = await trustStore.getActivePeer();
        expect(peer, isNull);
      },
    );

    // T11.21: UpdatePeerKey -> isTrusted(newKey)==true,
    //         isTrusted(oldKey)==false
    test(
      'T11.21: updatePeerKey transfers trust to new key',
      () async {
        final oldKey = StyxPublicKey.fromHex('dd' * 32);
        final newKey = StyxPublicKey.fromHex('ee' * 32);

        await trustStore.addTrustedPeer(
          peerPublicKey: oldKey,
          alias: 'Dave',
        );
        expect(await trustStore.isTrusted(oldKey), isTrue);

        await trustStore.updatePeerKey(
          oldKey: oldKey,
          newKey: newKey,
        );

        expect(await trustStore.isTrusted(newKey), isTrue);
        expect(await trustStore.isTrusted(oldKey), isFalse);
      },
    );

    // T11.22: RekeyHistory -> 2 successive re-keys -> list
    //         with 2 records chronologically
    test(
      'T11.22: getRekeyHistory returns chronological records',
      () async {
        final key1 = StyxPublicKey.fromHex('11' * 32);
        final key2 = StyxPublicKey.fromHex('22' * 32);
        final key3 = StyxPublicKey.fromHex('33' * 32);

        await trustStore.addTrustedPeer(
          peerPublicKey: key1,
          alias: 'Eve',
        );

        // First re-key: key1 -> key2
        await trustStore.updatePeerKey(
          oldKey: key1,
          newKey: key2,
        );

        // Second re-key: key2 -> key3
        await trustStore.updatePeerKey(
          oldKey: key2,
          newKey: key3,
        );

        final history = await trustStore.getRekeyHistory(key3);

        expect(history, hasLength(2));
        expect(history[0].oldKey, equals(key1.toHex()));
        expect(history[0].newKey, equals(key2.toHex()));
        expect(history[1].oldKey, equals(key2.toHex()));
        expect(history[1].newKey, equals(key3.toHex()));

        // Chronological order: first record before second.
        expect(
          history[0].timestamp.isBefore(
                    history[1].timestamp,
                  ) ||
              history[0].timestamp.isAtSameMomentAs(
                    history[1].timestamp,
                  ),
          isTrue,
        );
      },
    );
  });
}
