# Task 6 — Ledger Engine: Conflict Resolution + Pruning

**Stato:** Da iniziare
**Durata stimata:** 4-5 giorni
**Dipendenze:** Task 5
**Package:** `packages/ledger_engine/` (estensione)
**Coverage target:** ≥ 95%

---

## Obiettivo

Gestione dei fork nella catena quando entrambi i peer creano eventi offline contemporaneamente. Merge deterministico che garantisce convergenza identica su entrambi i peer senza comunicazione aggiuntiva. Protocollo di pruning bilaterale per conformità GDPR.

---

## Componenti da Implementare

### 1. `CausalityChecker` — `lib/src/conflict/causality_checker.dart`

```dart
class CausalityChecker {
  /// Determina la relazione causale tra due vector clock
  CausalRelation compare(VectorClock a, VectorClock b);

  /// Verifica se un evento è causalmente successivo a un altro
  bool isAfter(VectorClock event, VectorClock reference);

  /// Verifica se due eventi sono concorrenti (fork)
  bool isConcurrent(VectorClock a, VectorClock b);
}
```

### 2. `ForkDetector` — `lib/src/conflict/fork_detector.dart`

```dart
class ForkDetector {
  /// Analizza un set di eventi e rileva eventuali fork
  /// Un fork si verifica quando due eventi hanno lo stesso previousHash
  /// o quando i loro vector clock indicano concorrenza
  List<Fork> detectForks(List<LedgerEvent> events);

  /// Verifica se un evento remoto crea un fork rispetto alla catena locale
  Fork? detectForkOnReceive({
    required LedgerEvent remoteEvent,
    required LedgerEvent localHead,
  });
}

@immutable
class Fork {
  const Fork({
    required this.commonAncestorHash,
    required this.branchA,
    required this.branchB,
  });

  final String commonAncestorHash;     // Hash dell'ultimo evento comune
  final List<LedgerEvent> branchA;      // Eventi sul branch A (locale)
  final List<LedgerEvent> branchB;      // Eventi sul branch B (remoto)
}
```

### 3. `DeterministicMerge` — `lib/src/conflict/deterministic_merge.dart`

```dart
class DeterministicMerge {
  /// Ordina eventi concorrenti in modo deterministico
  /// Regola: (1) somma contatori VC crescente, (2) a parità → pubkey lessicografica
  /// 
  /// Entrambi i peer applicano la stessa regola → convergono sulla stessa sequenza
  List<LedgerEvent> orderConcurrentEvents(List<LedgerEvent> events);

  /// Esegue il merge completo di un fork
  /// 1. Identifica l'ancestor comune
  /// 2. Raccoglie eventi su entrambi i branch
  /// 3. Ordina deterministicamente
  /// 4. Ricostruisce la sequenza lineare
  MergeResult merge({
    required Fork fork,
    required String localPeerRole,
  });
}

@immutable
class MergeResult {
  const MergeResult({
    required this.orderedEvents,
    required this.mergeEventNeeded,
  });

  final List<LedgerEvent> orderedEvents;  // Sequenza finale ordinata
  final bool mergeEventNeeded;             // Se serve un evento MERGE
}
```

**Regola di ordinamento deterministico:**
```
sort(events, (a, b) {
  // 1. Ordinare per somma totale del vector clock (crescente)
  final totalA = a.vectorClock.total;
  final totalB = b.vectorClock.total;
  if (totalA != totalB) return totalA.compareTo(totalB);

  // 2. A parità, ordinare per pubkey del mittente (lessicografico)
  return a.senderPubkey.compareTo(b.senderPubkey);
});
```

### 4. `MergeEventFactory` — `lib/src/conflict/merge_event_factory.dart`

```dart
class MergeEventFactory {
  MergeEventFactory({required EventFactory eventFactory});

  /// Crea un evento MERGE che referenzia entrambe le punte del fork
  /// Il payload del MERGE contiene gli hash di entrambe le punte
  Future<LedgerEvent> createMergeEvent({
    required String branchAHeadHash,
    required String branchBHeadHash,
    required LedgerEvent newPreviousEvent,  // L'ultimo evento dopo l'ordinamento
    required StyxPrivateKey privateKey,
    required StyxPublicKey publicKey,
    required VectorClock mergedVectorClock,
    required String localPeerRole,
  });
}
```

**Payload del MERGE event:**
```json
{
  "type": "merge",
  "branch_a_head": "<hash>",
  "branch_b_head": "<hash>",
  "ancestor": "<hash>"
}
```

### 5. `PruneProtocol` — `lib/src/pruning/prune_protocol.dart`

```dart
enum PruneState { idle, requestSent, waitingAck, pruned, unilateralPruned }
enum PruneReason { retentionExpired, userRequest, gdprArticle17 }

class PruneProtocol {
  /// Avvia una richiesta di pruning bilaterale
  Future<LedgerEvent> requestPrune({
    required String targetEventId,
    required PruneReason reason,
    required StyxPrivateKey privateKey,
    required StyxPublicKey publicKey,
    required LedgerEvent? previousEvent,
    required VectorClock currentVectorClock,
    required String localPeerRole,
  });

  /// Gestisce la ricezione di un PRUNE_REQUEST
  /// Restituisce il PRUNE_ACK da inviare
  Future<LedgerEvent> acknowledgePrune({
    required LedgerEvent pruneRequest,
    required StyxPrivateKey privateKey,
    required StyxPublicKey publicKey,
    required LedgerEvent? previousEvent,
    required VectorClock currentVectorClock,
    required String localPeerRole,
  });

  /// Esegue il pruning locale dopo ACK bilaterale
  Future<void> executeBilateralPrune({
    required String targetEventId,
    required EventDao eventDao,
  });

  /// Esegue il pruning unilaterale (Art. 17 GDPR)
  /// Il peer locale elimina il proprio payload senza attendere ACK
  Future<void> executeUnilateralPrune({
    required String targetEventId,
    required EventDao eventDao,
  });
}
```

**Payload del PRUNE_REQUEST:**
```json
{
  "target_event_id": "<eventId>",
  "target_event_hash": "<hash>",
  "reason": "gdpr_article_17"
}
```

**Payload del PRUNE_ACK:**
```json
{
  "request_event_id": "<eventId del PRUNE_REQUEST>",
  "target_event_id": "<eventId dell'evento da prunare>",
  "acknowledged": true
}
```

### 6. `RetentionManager` — `lib/src/pruning/retention_manager.dart`

```dart
class RetentionManager {
  /// Verifica quali eventi hanno superato la retention policy
  Future<List<LedgerEvent>> getExpiredEvents({
    required Duration retentionPeriod,
    required List<EventType> applicableTypes,
  });

  /// Avvia il pruning automatico per tutti gli eventi scaduti
  Future<List<LedgerEvent>> autoprune({
    required Duration retentionPeriod,
    required PruneProtocol pruneProtocol,
    required StyxPrivateKey privateKey,
    required StyxPublicKey publicKey,
  });
}
```

---

## Test Specification

### Unit Test: `test/causality_checker_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T6.1 | `{2,1}` domina `{1,1}` | Due VC | `after` |
| T6.2 | `{1,1}` dominato da `{2,1}` | Due VC | `before` |
| T6.3 | `{2,1}` vs `{1,2}` | Due VC | `concurrent` |
| T6.4 | `{3,3}` vs `{3,3}` | Due VC | `equal` |
| T6.5 | `{0,0}` vs `{0,1}` | Due VC | `before` |

### Unit Test: `test/fork_detector_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T6.6 | Nessun fork | Catena lineare 10 eventi | `detectForks() = []` |
| T6.7 | Fork semplice | 2 eventi con stesso previousHash | 1 fork rilevato |
| T6.8 | Fork + branch multipli | 3 + 2 eventi sui branch | Branches corretti |
| T6.9 | Fork su receive | Evento remoto concorrente con head locale | Fork rilevato |
| T6.10 | No fork su receive | Evento remoto causalmente successivo | `null` |

### Unit Test: `test/deterministic_merge_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T6.11 | Ordine per VC total | VC totals [5, 3, 7] | Ordinati [3, 5, 7] |
| T6.12 | Tiebreak per pubkey | VC totals uguali, pubkeys diverse | Ordine lessicografico |
| T6.13 | Commutatività | merge(A,B) vs merge(B,A) | Risultato identico |
| T6.14 | 1000 fork randomici | Fork generati con dati casuali | Entrambi i "peer simulati" convergono |
| T6.15 | Merge produce catena lineare | Fork con 3+2 eventi | Sequenza lineare di 5 eventi ordinati |
| T6.16 | MERGE event creato | Dopo merge | Evento MERGE referenzia entrambe le punte |

### Unit Test: `test/prune_protocol_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T6.17 | PRUNE_REQUEST creato | Target event + reason | Evento con tipo PRUNE_REQUEST, payload corretto |
| T6.18 | PRUNE_ACK creato | PRUNE_REQUEST ricevuto | Evento con tipo PRUNE_ACK, references REQUEST |
| T6.19 | Bilateral prune | REQUEST → ACK → execute | Payload rimosso, hash preservato, isPruned = true |
| T6.20 | Chain integrity post-prune | Prune 3 eventi su 10 | `validateChain() == null` |
| T6.21 | Unilateral prune (Art. 17) | REQUEST senza ACK | Payload locale rimosso, hash preservato |
| T6.22 | Prune evento già pruned | Stesso evento × 2 | Nessun errore, idempotente |
| T6.23 | Prune genesis | Tentativo prune del genesis | Errore (genesis non prunabile) |

### Unit Test: `test/retention_manager_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T6.24 | GetExpired con retention 30 giorni | 5 eventi di 45 giorni fa + 5 recenti | 5 scaduti |
| T6.25 | GetExpired filtra per tipo | Solo TRANSACTION applicabile | Solo transazioni vecchie |
| T6.26 | Nessun scaduto | Tutti recenti | Lista vuota |

### Property-Based Test: `test/property_merge_test.dart`

| # | Test | Proprietà |
|---|------|-----------|
| T6.27 | Commutatività merge | `∀ fork: merge(A,B) == merge(B,A)` (stessa sequenza) |
| T6.28 | Idempotenza | `∀ catena: merge(chain, chain) == chain` |
| T6.29 | Chain integrity post-merge | `∀ fork → merge: validateChain() == null` |
| T6.30 | Chain integrity post-prune | `∀ catena, ∀ evento prunato: validateChain() == null` |
| T6.31 | Merge 10.000 scenari | Fork random con branch 1-50 eventi | Convergenza al 100% |

---

## Note di Implementazione

### Merge Workflow Completo

1. Peer A riceve eventi da Peer B
2. `ForkDetector.detectForkOnReceive()` → Fork rilevato
3. `DeterministicMerge.merge(fork)` → Sequenza ordinata
4. Riassegna `previousHash` nella sequenza ordinata (ricalcola hash chain)
5. `MergeEventFactory.createMergeEvent()` → Evento MERGE in coda alla sequenza
6. Persisti tutti gli eventi nel DB nell'ordine corretto
7. Il peer B fa la stessa operazione e ottiene la stessa sequenza (determinismo)

### Hash Chain Post-Merge

Dopo il merge, la hash chain deve essere ricalcolata per la parte ordinata. Questo significa che gli `eventHash` degli eventi riordinati cambiano. Per mantenere la verificabilità:
- Conservare l'`eventHash` originale come `originalHash` nel MERGE event
- Il nuovo `eventHash` nella catena lineare è calcolato con il nuovo `previousHash`

**Alternativa (più semplice):** Non ricalcolare gli hash. Il MERGE event referenzia le due punte e si collega all'ultimo evento della sequenza ordinata. Gli eventi nei branch mantengono i loro hash originali. La validazione della catena deve essere "merge-aware" e seguire i due branch fino all'ancestor comune.

### Pruning e Integrità

Quando un evento viene prunato:
- `payloadEncrypted` → `null`
- `isPruned` → `true`
- `eventHash` rimane invariato (calcolato quando il payload era presente)
- La chain validation per un evento prunato salta la verifica del payload ma verifica che l'`eventHash` colleghi correttamente all'evento precedente e successivo

---

## Criteri di Completamento

- [ ] Tutti i test T6.1–T6.31 passano
- [ ] Coverage ≥ 95%
- [ ] `melos run test:all` include Task 0-6, tutto green
- [ ] Merge deterministico verificato su 10.000 scenari random
- [ ] Pruning preserva integrità catena
- [ ] Chain validation è merge-aware
