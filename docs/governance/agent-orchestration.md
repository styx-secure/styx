# Orchestrazione multi-persona e multi-agente

**Stato:** Proposed  
**Ambito:** governance del processo di sviluppo  
**Repository:** `styx-secure/styx`  
**Fonte di verità:** GitHub Issues, Projects, pull request e Actions

Questo documento definisce il sistema tool-neutral con cui persone, Claude Code,
Codex e agenti futuri collaborano sul repository. Non autorizza modifiche al
prodotto, non modifica decisioni crittografiche e non avvia PR tecniche della
roadmap Styx.

## 1. Principi vincolanti

1. GitHub è l'unica fonte di verità operativa.
2. Ogni unità eseguibile è una Issue atomica con contratto completo.
3. Le dipendenze sono relazioni native GitHub `blocked by` / `blocking`.
4. Ogni esecuzione usa branch e worktree isolati.
5. Tutti i file modificabili devono essere dichiarati prima dell'avvio.
6. I path vietati prevalgono sempre sui path consentiti.
7. Due task paralleli non possono modificare lo stesso file senza una deroga
   umana esplicita e registrata.
8. L'agente che implementa non può effettuare la review indipendente.
9. Nessun agente può approvare o mergiare il proprio lavoro.
10. Nessun agente può modificare direttamente `main`.
11. Ogni automazione fallisce in chiuso: dati mancanti, ambigui o non
    verificabili bloccano il flusso.
12. Formati persistiti, crittografia, dipendenze runtime, workflow CI,
    configurazione GitHub e architettura del vault richiedono gate umano.

## 2. Separazione dei piani

Il sistema distingue quattro piani.

### 2.1 Control plane — GitHub

Contiene stato, dipendenze, responsabilità e audit trail:

- Issues e sub-issues;
- issue dependencies;
- Project;
- pull request;
- review;
- status check;
- Merge Queue;
- cronologia di label, assegnazioni e commenti.

Nessuna memoria di chat sostituisce questi dati.

### 2.2 Execution plane — worktree

Ogni task ha un worktree e un branch dedicati. L'esecutore riceve solo:

- checkout del task;
- contratto dell'Issue;
- documenti e file esplicitamente necessari;
- comandi di test consentiti;
- capacità di produrre commit e aggiornare una Draft PR.

L'esecutore non riceve capacità di merge, amministrazione repository o modifica
ruleset.

### 2.3 Verification plane — CI e reviewer indipendenti

La verifica è separata dall'implementazione:

- validazione del contratto;
- scope guard;
- rilevazione overlap;
- test e controlli esistenti;
- reviewer agentici in sola lettura e con contesto pulito;
- approvazione umana finale.

I reviewer agentici possono produrre finding e review, ma non commit sul branch
esaminato.

### 2.4 Authorization plane — umano

Solo una persona autorizzata può:

- approvare eccezioni di scope;
- approvare modifiche ad aree ad alto rischio;
- dichiarare risolti finding bloccanti;
- rendere Ready una PR dopo i gate;
- inserire la PR nella Merge Queue;
- cambiare ruleset, CODEOWNERS o configurazione del Project.

## 3. Identità e credenziali

Gli agenti non devono possedere credenziali GitHub generiche o persistenti.
L'architettura prevista per la Fase 2 usa un broker/orchestratore che espone
operazioni ristrette e validate:

- leggere Issue e PR;
- creare o aggiornare un branch di task;
- creare o aggiornare una Draft PR;
- pubblicare report e commenti;
- caricare evidenze di test.

Il broker rifiuta sempre operazioni di merge, approvazione, modifica ruleset,
modifica CODEOWNERS e applicazione di autorizzazioni umane. Anche quando il token
tecnico sottostante avesse permessi più ampi, tali capacità non vengono esposte
al processo agente.

## 4. Modello di lavoro

```text
Epic approvata
  -> task atomici
  -> dipendenze native
  -> contratto valido
  -> Ready
  -> assegnazione
  -> worktree + branch
  -> Draft PR
  -> scope guard
  -> CI
  -> review indipendente
  -> gate umano
  -> Merge Queue
  -> Done
```

### 4.1 Stati del Project

| Stato | Significato | Condizione d'uscita |
|---|---|---|
| `Inbox` | elemento acquisito ma non triagiato | owner e tipo definiti |
| `Needs contract` | contratto incompleto o task non atomico | contratto completo |
| `Blocked` | almeno una dipendenza o decisione è aperta | blocchi chiusi |
| `Ready` | eseguibile senza ulteriori decisioni | assegnazione |
| `In progress` | worktree attivo | Draft PR aperta |
| `In review` | implementazione completata, verifiche in corso | finding chiusi |
| `Human gate` | tutte le verifiche automatiche sono verdi | approvazione umana |
| `Merge queue` | autorizzata e accodata | merge o espulsione |
| `Done` | Issue chiusa e PR mergiata oppure gate completato | stato terminale |
| `Cancelled` | lavoro esplicitamente annullato | stato terminale |

`Blocked` non è una label di stato: deriva dalle dipendenze native e viene
rappresentato anche nel campo `Status` del Project.

### 4.2 Campi del Project

| Campo | Tipo | Valori / uso |
|---|---|---|
| `Status` | single select | stati della tabella precedente |
| `Type` | single select | Epic, Task, Gate, Bug, Review, Chore, Research |
| `Priority` | single select | P0, P1, P2, P3 |
| `Risk` | single select | Low, Medium, High, Crypto-critical |
| `Phase` | single select | Governance, Agent harness, Orchestration, Product |
| `Executor kind` | single select | Human, Agent, Pair, Unassigned |
| `Executor` | text | login GitHub o identificatore dell'esecutore |
| `Agent/tool` | single select | None, Claude Code, Codex, Other |
| `Persona` | single select | Implementer, Test author, Security reviewer, Spec reviewer, CI debugger, Maintainer |
| `Estimate` | number | giorni-persona ideali |
| `Start date` | date | data pianificata o reale di avvio |
| `Target date` | date | data prevista di completamento |
| `Confidence` | single select | High, Medium, Low |
| `Execution ID` | text | identificatore immutabile del tentativo |

I path consentiti, i path vietati e i criteri di accettazione restano nel corpo
dell'Issue: sono dati versionati e revisionabili, non semplici campi di
visualizzazione.

### 4.3 Viste minime

1. **Intake** — tabella filtrata su `Inbox` e `Needs contract`.
2. **Execution board** — board raggruppata per `Status`, con limiti WIP.
3. **Dependency queue** — `Blocked` e `Ready`, ordinata per priorità.
4. **Human gates** — `Risk:High,Crypto-critical` o `Status:Human gate`.
5. **Roadmap** — layout roadmap con `Start date` e `Target date`.
6. **Agent performance** — raggruppata per `Agent/tool` ed `Executor`.

## 5. Tassonomia delle label

Le label descrivono proprietà stabili; non duplicano lo stato del Project.

### Tipo

- `type:epic`
- `type:task`
- `type:gate`
- `type:bug`
- `type:review`
- `type:chore`
- `type:research`

### Rischio

- `risk:low`
- `risk:medium`
- `risk:high`
- `risk:crypto-critical`

### Origine ed esecuzione

- `origin:human`
- `origin:agent`
- `executor:human`
- `executor:agent`
- `executor:pair`

### Gate

- `gate:human-required`
- `gate:security-review`
- `gate:architecture-review`
- `gate:manual-test`

### Area

- `area:governance`
- `area:ci`
- `area:docs`
- `area:styx-js`
- `area:dart`
- `area:crypto`
- `area:storage`
- `area:wasm`
- `area:vault`

Nuove label devono appartenere a una famiglia documentata. Label di stato come
`in-progress` o `blocked` sono vietate per evitare drift con il Project.

## 6. Contratto atomico del task

Un task può passare a `Ready` solo se contiene tutte le sezioni seguenti:

1. risultato osservabile;
2. non-obiettivi;
3. path consentiti, uno per riga;
4. path vietati, uno per riga;
5. dipendenze native già impostate;
6. interfacce condivise congelate;
7. criteri di accettazione verificabili;
8. test obbligatori con comandi esatti;
9. classe e procedura di rollback;
10. rischio residuo;
11. tipo di esecutore e persona richiesta;
12. reviewer indipendenti richiesti;
13. gate umano applicabile.

Il marker canonico del contratto è:

```html
<!-- styx-task-contract:v1 -->
```

L'Issue Form usa intestazioni stabili. La Fase 2 introdurrà un parser che rifiuta
Issue mancanti, sezioni duplicate, glob non validi o riferimenti ambigui.

## 7. Semantica dello scope

- I path sono relativi alla root del repository.
- Ogni file aggiunto, modificato, rinominato o eliminato deve corrispondere ad
  almeno un pattern consentito.
- Per un rename devono essere consentiti sia il vecchio sia il nuovo path.
- I pattern vietati prevalgono sui consentiti.
- Submodule, symlink, file binari e lockfile sono rifiutati salvo autorizzazione
  esplicita.
- `.github/workflows/**`, `.github/CODEOWNERS`, manifest/lockfile, codice
  crittografico, formati persistiti e artefatti WASM implicano sempre
  `gate:human-required`.
- Un task non può ampliare autonomamente il proprio scope. Serve modifica
  dell'Issue e nuova approvazione umana prima di continuare.

## 8. Parallelizzazione

Due task sono parallelizzabili solo quando:

1. nessuno dipende dall'altro;
2. gli insiemi di file sono disgiunti;
3. le interfacce condivise sono già congelate;
4. non condividono migrazioni, lockfile o fixture normative;
5. esiste un criterio di integrazione esplicito.

Se l'overlap è inevitabile, le alternative ammesse sono:

- serializzare i task;
- estrarre prima un task di interfaccia;
- usare stacked PR con dipendenze dichiarate;
- registrare una deroga umana con owner unico del file.

L'overlap detector della Fase 3 usa i path dichiarati e i diff reali. In caso di
incertezza considera i task non parallelizzabili.

## 9. Branch, worktree e commit

Convenzioni:

```text
task/<issue>-<slug>
agent/<issue>-<slug>
review/<pr>-<persona>
```

Ogni branch nasce dal SHA dichiarato nel task. Il worktree locale è dedicato a
un solo tentativo. Un branch non viene riutilizzato per task diversi.

I commit devono essere piccoli, coerenti e reversibili. Il messaggio usa inglese
e include `Refs #<issue>` quando applicabile. È vietato riscrivere la storia dopo
l'inizio della review senza motivazione registrata.

## 10. Pull request e review

La PR viene aperta in Draft appena esiste il primo commit utile. Deve collegare
una sola Issue atomica, salvo stacked PR esplicitamente autorizzate.

Prima di `Ready for review` devono risultare:

- contratto valido;
- dipendenze chiuse;
- diff entro scope;
- test obbligatori eseguiti;
- rollback descritto;
- nessun finding bloccante noto.

Il reviewer indipendente:

- non è l'implementatore;
- non usa la memoria o il worktree dell'implementatore;
- riceve base SHA, head SHA, contratto e diff;
- opera in sola lettura;
- produce finding con severità, evidenza e criterio di chiusura.

Una review agentica non sostituisce l'approvazione umana.

## 11. Protezione di `main`

Il ruleset definitivo deve avere:

- target esatto `refs/heads/main`;
- pull request obbligatoria;
- almeno una approvazione umana;
- dismiss delle approvazioni stale dopo nuovi commit;
- approvazione dell'ultimo push da persona diversa dall'autore del push;
- review CODEOWNERS per i path critici;
- conversazioni risolte;
- status check obbligatori e sempre presenti;
- cronologia lineare;
- force-push e cancellazione vietati;
- Merge Queue obbligatoria;
- nessun bypass actor permanente.

Il break-glass non è un bypass configurato: richiede modifica temporanea del
ruleset da parte di un amministratore, Issue di incidente, motivazione,
approvazione e ripristino immediato.

## 12. Merge Queue

Configurazione iniziale conservativa:

- metodo: squash;
- build concurrency: 1;
- gruppo minimo: 1;
- gruppo massimo: 1;
- merge solo di PR non fallite;
- nessun salto di coda ordinario;
- inserimento in coda esclusivamente umano.

Tutti i workflow richiesti devono reagire anche a `merge_group`. Un required
check che non viene pubblicato sul merge group blocca correttamente la coda.

## 13. Project e Gantt

Il Project è la pianificazione canonica. La roadmap usa `Start date` e
`Target date`; le Issue dependencies rappresentano il critical path.

Il file Excel è un artefatto generato:

```text
GitHub Project -> export normalizzato -> workbook Gantt
```

Non sono ammesse modifiche manuali al Gantt che non siano prima rappresentate in
GitHub. Ogni export conserva timestamp, Project number e SHA del generatore.
L'automazione completa appartiene alla Fase 3.

## 14. Automazioni della Fase 1

Usare subito le automazioni native del Project:

- auto-add di Issue e PR di `styx-secure/styx`;
- nuovo elemento -> `Inbox`;
- Issue chiusa o PR mergiata -> `Done`;
- riapertura -> stato non terminale;
- archiviazione solo dopo una finestra definita.

Le transizioni che richiedono verifica semantica restano manuali fino ai gate
della Fase 2.

## 15. Rollout

### Fase 1A — repository

- rendere `AGENTS.md` canonico;
- trasformare `CLAUDE.md` in adapter;
- aggiungere Issue Forms, PR template e CODEOWNERS;
- rendere i required workflow compatibili con `merge_group`.

### Fase 1B — impostazioni GitHub

- creare label e Project;
- creare campi, viste e automazioni native;
- importare/aggiornare il ruleset;
- attivare Merge Queue solo dopo un test su PR innocua.

### Fase 2 — enforcement

- parser del task contract;
- scope guard;
- report JSON;
- profili agentici;
- review indipendente;
- check di gate umano.

### Fase 3 — orchestrazione

- dependency resolver;
- overlap detector;
- assegnazione automatica;
- sincronizzazione Project/Gantt;
- metriche e recovery.

## 16. Rollback della governance

Ogni componente è reversibile separatamente:

1. disabilitare Merge Queue senza rimuovere la protezione PR;
2. ripristinare il precedente ruleset da export JSON;
3. disattivare automazioni Project mantenendo i dati;
4. revert dei commit di template e documentazione;
5. mantenere tutte le Issue e PR come audit trail.

La governance non deve mai essere rimossa per sbloccare una PR tecnica. I
problemi del processo si risolvono nel processo, non bypassandolo.