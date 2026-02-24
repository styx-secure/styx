import 'package:styx_storage/src/styx_database.dart';
import 'package:test/test.dart';

void main() {
  late StyxDatabase db;

  setUp(() {
    db = StyxDatabase.inMemory();
  });

  tearDown(() => db.close());

  group('PeerDao', () {
    // T4.24: AddPeer + getPeerByPubkey
    test('T4.24 — add and retrieve peer by pubkey', () async {
      await db.peerDao.addPeer(
        PeersCompanion.insert(
          pubkey: 'pk-alice',
          pairedAt: DateTime(2025),
        ),
      );

      final peer = await db.peerDao.getPeerByPubkey('pk-alice');
      expect(peer, isNotNull);
      expect(peer!.pubkey, 'pk-alice');
      expect(peer.isActive, isTrue);
      expect(peer.rekeyHistory, '[]');
    });

    // T4.25: GetActivePeers
    test('T4.25 — getActivePeers returns only active', () async {
      for (var i = 0; i < 5; i++) {
        await db.peerDao.addPeer(
          PeersCompanion.insert(
            pubkey: 'pk-$i',
            pairedAt: DateTime(2025),
          ),
        );
      }
      // Deactivate 2 peers.
      await db.peerDao.deactivatePeer('pk-3');
      await db.peerDao.deactivatePeer('pk-4');

      final active = await db.peerDao.getActivePeers();
      expect(active.length, 3);
      expect(active.every((p) => p.isActive), isTrue);
    });

    // T4.26: DeactivatePeer
    test('T4.26 — deactivatePeer sets isActive to false', () async {
      await db.peerDao.addPeer(
        PeersCompanion.insert(
          pubkey: 'pk-deact',
          pairedAt: DateTime(2025),
        ),
      );

      await db.peerDao.deactivatePeer('pk-deact');
      final peer = await db.peerDao.getPeerByPubkey('pk-deact');
      expect(peer!.isActive, isFalse);
    });

    // T4.27: UpdatePeerKey (rekey)
    test('T4.27 — updatePeerKey makes peer findable by new key', () async {
      await db.peerDao.addPeer(
        PeersCompanion.insert(
          pubkey: 'pk-old',
          pairedAt: DateTime(2025),
        ),
      );

      await db.peerDao.updatePeerKey(
        oldPubkey: 'pk-old',
        newPubkey: 'pk-new',
      );

      final byOld = await db.peerDao.getPeerByPubkey('pk-old');
      final byNew = await db.peerDao.getPeerByPubkey('pk-new');

      expect(byOld, isNull);
      expect(byNew, isNotNull);
      expect(byNew!.pubkey, 'pk-new');
    });

    // T4.28: Peer duplicate pubkey
    test('T4.28 — duplicate pubkey throws', () async {
      await db.peerDao.addPeer(
        PeersCompanion.insert(
          pubkey: 'pk-dup',
          pairedAt: DateTime(2025),
        ),
      );

      expect(
        () => db.peerDao.addPeer(
          PeersCompanion.insert(
            pubkey: 'pk-dup',
            pairedAt: DateTime(2025),
          ),
        ),
        throwsA(isA<Exception>()),
      );
    });

    // AddRekeyEntry
    test('addRekeyEntry appends to rekey history', () async {
      await db.peerDao.addPeer(
        PeersCompanion.insert(
          pubkey: 'pk-rekey',
          pairedAt: DateTime(2025),
        ),
      );

      await db.peerDao.addRekeyEntry(
        pubkey: 'pk-rekey',
        oldKey: 'old-1',
        newKey: 'new-1',
      );

      final peer = await db.peerDao.getPeerByPubkey('pk-rekey');
      expect(peer!.rekeyHistory, contains('old-1'));
      expect(peer.rekeyHistory, contains('new-1'));
    });
  });
}
