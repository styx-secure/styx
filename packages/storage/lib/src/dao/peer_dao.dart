import 'dart:convert';

import 'package:drift/drift.dart';
import 'package:styx_storage/src/styx_database.dart';
import 'package:styx_storage/src/tables/peers.dart';

part 'peer_dao.g.dart';

/// Data access object for the peer trust store.
@DriftAccessor(tables: [Peers])
class PeerDao extends DatabaseAccessor<StyxDatabase> with _$PeerDaoMixin {
  /// Creates a [PeerDao] attached to [db].
  PeerDao(super.attachedDatabase);

  /// Adds a new peer.
  Future<int> addPeer(PeersCompanion peer) => into(peers).insert(peer);

  /// Retrieves a peer by public key.
  Future<Peer?> getPeerByPubkey(String pubkey) =>
      (select(peers)..where((p) => p.pubkey.equals(pubkey))).getSingleOrNull();

  /// Returns all active peers.
  Future<List<Peer>> getActivePeers() =>
      (select(peers)..where((p) => p.isActive.equals(true))).get();

  /// Deactivates a peer.
  Future<int> deactivatePeer(String pubkey) =>
      (update(peers)..where((p) => p.pubkey.equals(pubkey)))
          .write(const PeersCompanion(isActive: Value(false)));

  /// Updates a peer's public key during rekey.
  Future<void> updatePeerKey({
    required String oldPubkey,
    required String newPubkey,
  }) async {
    await (update(peers)..where((p) => p.pubkey.equals(oldPubkey)))
        .write(PeersCompanion(pubkey: Value(newPubkey)));
  }

  /// Adds a rekey history entry to a peer.
  Future<void> addRekeyEntry({
    required String pubkey,
    required String oldKey,
    required String newKey,
  }) async {
    final peer = await getPeerByPubkey(pubkey);
    if (peer == null) return;

    final history =
        (jsonDecode(peer.rekeyHistory) as List<dynamic>).cast<Object>()
          ..add({
            'oldKey': oldKey,
            'newKey': newKey,
            'timestamp': DateTime.now().toIso8601String(),
          });

    await (update(peers)..where((p) => p.pubkey.equals(pubkey)))
        .write(PeersCompanion(rekeyHistory: Value(jsonEncode(history))));
  }
}
