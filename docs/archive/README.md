# Archivio — documenti storici, non normativi

I documenti in questa cartella descrivono **lavoro concluso** o **direzioni superate**. Sono conservati per tracciabilità: non vanno usati come specifica per nuovo lavoro, e il loro contenuto **non è garantito allineato al codice**.

Per la direzione corrente del progetto vedi, nell'ordine:

1. `docs/security/2026-07-11-fattibilita-piano-utente.md` — valutazione di fattibilità e roadmap in 5 blocchi (documento normativo)
2. `docs/security/2026-07-10-styx-chat-security-report.md` — audit e vulnerabilità aperte
3. `docs/superpowers/plans/` — piani di implementazione attivi

## Contenuto

| Documento | Cos'era | Perché è archiviato |
|---|---|---|
| `tasks/TASK_00..12.md` | Piano bottom-up del layer Dart, un task per package | Il lavoro è **fatto** (107 file Dart di produzione, 60 di test), ma ogni file dichiara ancora "Stato: Da iniziare". La fonte di verità è il codice in `packages/` e i suoi test. |
| `ROADMAP.md` | Piano task-by-task del ledger Dart (la sorgente dei TASK_*) | Stesso corpus dei TASK_*, stessa condizione. |
| `Sovereign_P2P_Ledger_Blueprint_v2.md` | Manifesto tecnico originale del ledger P2P | Design fondativo del layer Dart, precedente alla direzione PWA/MLS. Utile come contesto storico, non come specifica. |

**Non archiviati** (restano in `docs/`, documentano codice vivo e testato): `API_REFERENCE.md`, `API_REFERENCE_IT.md`, `APPLICATION_EXAMPLES.md`.
