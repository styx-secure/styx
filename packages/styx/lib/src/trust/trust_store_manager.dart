import 'package:meta/meta.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';

/// A trusted peer entry.
@immutable
class TrustedPeer {
  /// Creates a [TrustedPeer].
  const TrustedPeer({
    required this.publicKey,
    required this.alias,
    required this.pairedAt,
    required this.isActive,
  });

  /// The peer's Ed25519 public key.
  final StyxPublicKey publicKey;

  /// Optional human-readable alias.
  final String? alias;

  /// When the pairing was established.
  final DateTime pairedAt;

  /// Whether the peer is currently active.
  final bool isActive;
}

/// A record of a re-keying event.
@immutable
class RekeyRecord {
  /// Creates a [RekeyRecord].
  const RekeyRecord({
    required this.oldKey,
    required this.newKey,
    required this.timestamp,
  });

  /// Hex-encoded old public key.
  final String oldKey;

  /// Hex-encoded new public key.
  final String newKey;

  /// When the re-key occurred.
  final DateTime timestamp;
}

/// Abstract interface for peer storage operations.
///
/// In production this wraps PeerDao from styx_storage.
/// For testing, use [InMemoryPeerStore].
abstract class PeerStore {
  /// Adds a peer.
  Future<void> addPeer({
    required String pubkey,
    required String? alias,
    required DateTime pairedAt,
  });

  /// Retrieves a peer by public key.
  Future<TrustedPeer?> getPeerByPubkey(String pubkey);

  /// Returns all active peers.
  Future<List<TrustedPeer>> getActivePeers();

  /// Deactivates a peer.
  Future<void> deactivatePeer(String pubkey);

  /// Updates a peer's public key.
  Future<void> updatePeerKey({
    required String oldPubkey,
    required String newPubkey,
  });

  /// Adds a re-key history entry.
  Future<void> addRekeyEntry({
    required String pubkey,
    required String oldKey,
    required String newKey,
  });

  /// Returns re-key history for a peer.
  Future<List<RekeyRecord>> getRekeyHistory(String pubkey);
}

/// Manages the trust store of paired peers.
class TrustStoreManager {
  /// Creates a [TrustStoreManager].
  TrustStoreManager({required PeerStore peerStore}) : _peerStore = peerStore;

  final PeerStore _peerStore;

  /// Adds a trusted peer after pairing.
  Future<void> addTrustedPeer({
    required StyxPublicKey peerPublicKey,
    required String? alias,
  }) async {
    await _peerStore.addPeer(
      pubkey: peerPublicKey.toHex(),
      alias: alias,
      pairedAt: DateTime.now().toUtc(),
    );
  }

  /// Revokes trust for a peer.
  Future<void> revokePeer(StyxPublicKey peerPublicKey) async {
    await _peerStore.deactivatePeer(peerPublicKey.toHex());
  }

  /// Checks if a public key is trusted (active).
  Future<bool> isTrusted(StyxPublicKey publicKey) async {
    final peer = await _peerStore.getPeerByPubkey(publicKey.toHex());
    return peer != null && peer.isActive;
  }

  /// Returns the active peer (at most one in the 2-peer system).
  Future<TrustedPeer?> getActivePeer() async {
    final peers = await _peerStore.getActivePeers();
    return peers.isEmpty ? null : peers.first;
  }

  /// Updates a peer's public key after re-keying.
  Future<void> updatePeerKey({
    required StyxPublicKey oldKey,
    required StyxPublicKey newKey,
  }) async {
    await _peerStore.addRekeyEntry(
      pubkey: oldKey.toHex(),
      oldKey: oldKey.toHex(),
      newKey: newKey.toHex(),
    );
    await _peerStore.updatePeerKey(
      oldPubkey: oldKey.toHex(),
      newPubkey: newKey.toHex(),
    );
  }

  /// Returns the re-key history for a peer.
  Future<List<RekeyRecord>> getRekeyHistory(
    StyxPublicKey currentKey,
  ) async {
    return _peerStore.getRekeyHistory(currentKey.toHex());
  }
}

/// In-memory implementation of [PeerStore] for testing.
class InMemoryPeerStore implements PeerStore {
  final _peers = <String, TrustedPeer>{};
  final _rekeyHistory = <String, List<RekeyRecord>>{};

  @override
  Future<void> addPeer({
    required String pubkey,
    required String? alias,
    required DateTime pairedAt,
  }) async {
    _peers[pubkey] = TrustedPeer(
      publicKey: StyxPublicKey.fromHex(pubkey),
      alias: alias,
      pairedAt: pairedAt,
      isActive: true,
    );
  }

  @override
  Future<TrustedPeer?> getPeerByPubkey(String pubkey) async => _peers[pubkey];

  @override
  Future<List<TrustedPeer>> getActivePeers() async =>
      _peers.values.where((p) => p.isActive).toList();

  @override
  Future<void> deactivatePeer(String pubkey) async {
    final peer = _peers[pubkey];
    if (peer != null) {
      _peers[pubkey] = TrustedPeer(
        publicKey: peer.publicKey,
        alias: peer.alias,
        pairedAt: peer.pairedAt,
        isActive: false,
      );
    }
  }

  @override
  Future<void> updatePeerKey({
    required String oldPubkey,
    required String newPubkey,
  }) async {
    final peer = _peers.remove(oldPubkey);
    if (peer != null) {
      _peers[newPubkey] = TrustedPeer(
        publicKey: StyxPublicKey.fromHex(newPubkey),
        alias: peer.alias,
        pairedAt: peer.pairedAt,
        isActive: peer.isActive,
      );
      // Move history to new key.
      final history = _rekeyHistory.remove(oldPubkey);
      if (history != null) {
        _rekeyHistory[newPubkey] = history;
      }
    }
  }

  @override
  Future<void> addRekeyEntry({
    required String pubkey,
    required String oldKey,
    required String newKey,
  }) async {
    _rekeyHistory
        .putIfAbsent(pubkey, () => [])
        .add(
          RekeyRecord(
            oldKey: oldKey,
            newKey: newKey,
            timestamp: DateTime.now().toUtc(),
          ),
        );
  }

  @override
  Future<List<RekeyRecord>> getRekeyHistory(String pubkey) async =>
      _rekeyHistory[pubkey] ?? [];
}
