# Fase 1B — rapporto di evidenza

**Issue:** [#43](https://github.com/styx-secure/styx/issues/43)
**PR di validazione:** [#44](https://github.com/styx-secure/styx/pull/44)
**Periodo di applicazione:** 2026-07-12
**Fonte di verità:** GitHub; questo documento è una fotografia revisionata dello
stato amministrativo applicato. Le evidenze verificabili via API sono registrate
nei commenti di audit dell'Issue #43; le impostazioni non esposte dalle API
pubbliche sono qualificate come attestazioni manuali dell'amministratore umano.

## 1. Label

Le 29 label della tassonomia (`type:*` 7, `risk:*` 4, `origin:*` 2,
`executor:*` 3, `gate:*` 4, `area:*` 9) sono state create o aggiornate in modo
idempotente con i colori e le descrizioni documentati. Nessuna label eliminata;
nessuna label di stato vietata (`blocked`, `ready`, `in-progress`, `status:*`)
presente nel repository.

## 2. Project organizzativo

- Nome: **Styx Secure Delivery**; numero `1`;
  URL: <https://github.com/orgs/styx-secure/projects/1>.
- Visibilità: private; collegato a `styx-secure/styx`.
- Campi custom creati: Priority, Risk, Phase, Executor kind, Agent/tool,
  Persona, Confidence (single select); Executor, Execution ID (text);
  Estimate (number); Start date, Target date (date).
- Campo `Status` nativo aggiornato alle dieci opzioni documentate, nell'ordine:
  Inbox, Needs contract, Blocked, Ready, In progress, In review, Human gate,
  Merge queue, Done, Cancelled.

## 3. Campo Type e organization issue types

Il campo custom `Type` non è realizzabile: il nome è riservato da GitHub
Projects. Il campo nativo `Type` è alimentato dagli organization issue types di
`styx-secure`, configurati via REST API ufficiale:

| Tipo | Colore | Stato |
|---|---|---|
| Epic | purple | abilitato |
| Task | blue | abilitato |
| Gate | red | abilitato |
| Bug | red | abilitato |
| Review | yellow | abilitato |
| Chore | gray | abilitato |
| Research | green | abilitato |
| Feature | blue | **disabilitato**, non eliminato |

L'Issue #43 è di tipo `Task`.

## 4. Viste del Project

Viste effettive (oltre alla `View 1` di default, invariata):

| Vista | Layout | Filtro |
|---|---|---|
| Intake | table | `status:Inbox,"Needs contract"` |
| Execution board | board | `-status:Done,Cancelled` |
| Dependency queue | table | `status:Blocked,Ready` |
| Roadmap | roadmap | `-status:Cancelled` |
| Agent performance | table | `"executor kind":Agent,Pair` |
| Human gates — Status | table | `status:"Human gate"` |
| Human gates — Risk | table | `risk:High,"Crypto-critical"` |

La vista unica `Human gates` prevista in origine è stata divisa nelle due viste
complementari perché GitHub Projects non supporta filtri OR tra campi
differenti.

Limiti WIP della Execution board: `In progress` 3, `In review` 3,
`Human gate` 5, `Merge queue` 1. I limiti WIP non sono esposti dalle API
pubbliche utilizzate per l'audit: questi valori sono attestati dall'amministratore
umano dopo verifica visiva nell'interfaccia GitHub Projects.

## 5. Automazioni attive

- Auto-add delle Issue e PR aperte di `styx-secure/styx`.
- Auto-add delle sub-issue.
- Elemento aggiunto -> `Inbox`.
- Elemento riaperto -> `Needs contract`.
- PR collegata a una Issue -> `In progress`.
- PR mergiata -> `Done`.
- Elemento chiuso -> `Done`.

La configurazione dei workflow nativi del Project è attestata
dall'amministratore umano dopo verifica visiva nell'interfaccia. Le API pubbliche
usate nell'audit non espongono integralmente questa configurazione; l'auto-add e
alcune transizioni sono inoltre corroborati dagli effetti osservabili nel
Project.

Transizioni manuali in Fase 1: `Ready`, `In review`, `Human gate`,
`Merge queue`, `Cancelled` (per le Issue chiuse come not planned).

## 6. Ruleset `main` — Passaggio A

Ruleset **`main branch protection`**, ID `18814814`, enforcement `active`:

- target esatto `refs/heads/main`;
- bypass list vuota;
- pull request obbligatoria (0 approvazioni richieste in Fase 1);
- conversazioni risolte;
- cronologia lineare;
- force-push e cancellazione vietati;
- branch aggiornato prima del merge (strict status checks);
- squash merge soltanto;
- quattro required check associati all'app **GitHub Actions**
  (`integration_id` `15368`):
  - `Dart reference stack gate`;
  - `styx-js web gate`;
  - `WASM integrity gate`;
  - `Analyze (javascript-typescript)`.

L'aggiornamento del ruleset (target esplicito e binding dei check all'app) è
stato applicato il 2026-07-12 previa autorizzazione umana esplicita, verifica
TOCTOU e diff semantico limitato alle cinque modifiche autorizzate.

## 7. Validazione su PR innocua

La PR #44, limitata a `docs/governance/**`, ha pubblicato e completato con
successo tutti e quattro i required check sull'evento `pull_request`. I job
pesanti non pertinenti sono stati green-skippati solo dopo change detection
riuscita, come previsto da `AGENTS.md`.

## 8. Rinvii espliciti

- Il run `merge_group` **non è ancora stato validato**: la validazione della
  Merge Queue richiede un'autorizzazione umana separata.
- La Merge Queue permanente e il **Passaggio B** (approvazione distinta,
  dismiss stale approvals, approvazione dell'ultimo push, review CODEOWNERS)
  restano rinviati finché non esiste un secondo CODEOWNER umano idoneo.
- Nessuna approvazione distinta o review CODEOWNERS è oggi obbligatoria.

## 9. Audit trail

Le evidenze API primarie (export JSON, timestamp, diff semantici ed esiti dei
check) sono registrate nei commenti di audit dell'Issue #43. I limiti WIP e la
configurazione completa delle automazioni, non integralmente leggibili tramite
le API pubbliche utilizzate, sono attestati dall'amministratore umano sulla base
della verifica visiva eseguita durante il rollout.
