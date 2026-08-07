<!-- styx-translation:v1 canonical="docs/platform/README.md" sha256="070b481cfd8de78bd7300764ffd91a4c09d3da45ce6328626d40556a3a1b5d45" -->
# Styx come piattaforma applicativa

[English canonical version](README.md)

> **Stato:** proposta esplorativa, non normativa
> **Snapshot del codice:** `main @ d90931a3f59ce89c1594cad64ce385d58857b305`
> **Issue:** [#110](https://github.com/styx-secure/styx/issues/110)
> **Lingua:** italiano; gli identificatori tecnici restano in inglese.

Questa cartella descrive come Styx potrebbe evolvere da prodotto di
messaggistica a piattaforma riutilizzabile per applicazioni che condividono tre
esigenze:

1. dati leggibili soltanto dagli endpoint autorizzati;
2. funzionamento locale e asincrono, senza dipendere da un unico gestore;
3. proprietà di sicurezza dichiarate rispetto a un modello di minaccia, senza
   promesse assolute.

I documenti non autorizzano modifiche al codice e non sostituiscono specifiche,
ADR, Issue contrattuali, audit o consulenze legali. In caso di conflitto
prevalgono `AGENTS.md`, le Issue approvate e le fonti normative del repository.

## Documenti

| Documento | Scopo |
|---|---|
| [Modello delle capacità](application-capability-model.md) | Definisce le capacità applicative generali, i confini di fiducia, i profili di identità e i livelli di garanzia. |
| [Roadmap di integrazione](integration-roadmap.md) | Confronta i requisiti con lo stack JavaScript attivo e lo stack Dart di riferimento, indicando lacune e possibili incrementi. |
| [Dialogo anonimo bidirezionale](use-cases/anonymous-dialogue.md) | Applica il modello a segnalazioni che devono ricevere risposte senza richiedere recapiti personali. |

## Idea architetturale

La direzione proposta non è aggiungere tutte le funzioni alla chat. È separare
quattro livelli:

```text
Applicazioni
  chat | contabilità condivisa | segnalazioni | casework | sondaggi
       │
Profili e policy applicative
  identità | ruoli | retention | schema dati | threat model
       │
Styx Application Core
  oggetti E2EE | sessioni | sync | affidabilità | vault | recovery
       │
Adattatori infrastrutturali
  relay Nostr | onion service | push | storage locale | client nativo
```

L'applicazione decide il significato dei dati. Il core fornisce primitive
verificabili. Gli adattatori trasportano blob e segnali senza diventare
autorità sull'identità o sul contenuto. Un profilo di sicurezza combina le
primitive, ma non può promettere più di quanto provino implementazione, test e
operatività.

## Famiglie di applicazioni candidate

### Comunicazione privata

Chat individuali o di piccoli gruppi, coordinamento di associazioni e scambio
di documenti. È il caso più vicino al prodotto JavaScript attuale, ma richiede
ancora la chiusura dei blocker di storage e metadati prima di un uso sensibile.

### Registri condivisi senza gestore centrale

Contabilità familiare, cassa di un gruppo di amici, inventari, turni, decisioni
e spese comuni. Gli eventi devono essere autenticati, sincronizzati offline,
idempotenti e risolti secondo regole applicative esplicite. Una catena
tamper-evident può aiutare a rilevare modifiche, ma non rende vero un dato
falso inserito da un partecipante.

### Dialogo anonimo o pseudonimo

Segnalazioni di abusi, whistleblowing quando applicabile, sportelli di ascolto,
fonti giornalistiche e richieste di aiuto. Richiede identità monouso per caso,
nessun account obbligatorio, capacità di ritorno, protezione della rete e una
procedura organizzativa competente. La cifratura del contenuto, da sola, non
fornisce anonimato.

### Casework riservato

Relazione tra assistito e ONG, avvocato, sindacato o operatore. Può richiedere
assegnazione dei casi, separazione dei ruoli, escalation, custodia condivisa
delle chiavi, esportazioni controllate e conservazione limitata.

### Raccolta dati e sondaggi

Questionari privati, rilevazioni sul campo e consultazioni. Occorre distinguere
segretezza della risposta, autenticazione dell'avente diritto, unicità del voto
e anonimato: proprietà diverse che possono essere in tensione. Styx non deve
presentarsi come sistema di voto verificabile senza un processo dedicato.

### Evidenze e attestazioni

Raccolta di dichiarazioni, fotografie o documenti con provenienza e cronologia
verificabili. Firma e hash possono provare l'integrità di byte osservati, non
l'autenticità materiale dell'evento rappresentato né una catena di custodia
legale completa.

## Regole per le affermazioni di sicurezza

Questa area adotta alcune regole lessicali:

- **E2EE** significa che il contenuto è cifrato tra endpoint autorizzati; non
  implica anonimato, disponibilità o sicurezza dell'endpoint.
- **Riservato** non significa **anonimo**.
- **Pseudonimo** non significa **non identificabile**.
- **Tamper-evident** non significa immutabile, vero o giuridicamente
  non ripudiabile.
- **Federato** non significa privo di server.
- **Tor-capable** non significa che tutto il traffico sia passato attraverso
  Tor o che la correlazione globale sia impossibile.
- **Cancellato logicamente** non significa fisicamente irrecuperabile da ogni
  supporto, replica o backup.
- Nessuna configurazione va descritta come universalmente anonima, priva di
  metadati, incapace di apprendere qualsiasi informazione o pronta per la
  produzione senza un'evidenza specifica e corrente.

## Come usare questa documentazione

Una nuova applicazione dovrebbe:

1. selezionare gli asset e gli avversari rilevanti;
2. scegliere un profilo di identità e un profilo di garanzia;
3. dichiarare quali metadati restano visibili a relay, operatori e peer;
4. mappare ogni requisito sulle capacità del core;
5. trattare le capacità mancanti come dipendenze bloccanti;
6. aprire Issue separate per decisioni crittografiche, formati persistenti,
   migrazioni e cambiamenti al vault;
7. eseguire test e review indipendenti sul prodotto completo, non soltanto
   sulle primitive.

## Stato rispetto al prodotto corrente

Lo stack canonico resta Rust/OpenMLS attraverso WASM, con PWA JavaScript,
secondo `docs/architecture/decisions/ADR-0001-canonical-product-stack.md`. Lo
stack Dart resta una reference implementation secondo ADR-0003 e non diventa
un secondo core di prodotto. Le idee presenti nel Dart possono diventare
requisiti e test, non essere importate implicitamente nel prodotto attivo.

Al presente snapshot:

- la chat 1:1 MLS e il trasporto Nostr forniscono primitive utili;
- il vault IndexedDB è ancora canary-only e non contiene dati di prodotto;
- il trasporto della chat non attende un ACK di consegna reale;
- le identità di trasporto sono durevoli e correlabili;
- relay e osservatori vedono metadati strutturali e di rete;
- pairing remoto, gruppi di prodotto e multi-device non sono completati;
- manca un contratto SDK applicativo indipendente dalla chat.

La [roadmap](integration-roadmap.md) trasforma queste differenze in possibili
incrementi senza anticiparne le decisioni sensibili.
