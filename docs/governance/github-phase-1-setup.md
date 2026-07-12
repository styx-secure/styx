# GitHub Fase 1 — configurazione amministrativa

Applicare questa configurazione solo dopo il merge della PR governance e dopo
aver verificato i gate su `main`. GitHub resta la fonte di verità; il Gantt Excel
è un'esportazione derivata.

## 1. Project

Creare un Project organizzativo chiamato **Styx Secure Delivery** e collegare il
repository `styx-secure/styx`.

Campi:

| Campo | Tipo | Valori |
|---|---|---|
| Status | single select | Inbox, Needs contract, Blocked, Ready, In progress, In review, Human gate, Merge queue, Done, Cancelled |
| Type | single select | Epic, Task, Gate, Bug, Review, Chore, Research |
| Priority | single select | P0, P1, P2, P3 |
| Risk | single select | Low, Medium, High, Crypto-critical |
| Phase | single select | Governance, Agent harness, Orchestration, Product |
| Executor kind | single select | Human, Agent, Pair, Unassigned |
| Executor | text | login o identificatore |
| Agent/tool | single select | None, Claude Code, Codex, Other |
| Persona | single select | Implementer, Test author, Security reviewer, Spec reviewer, CI debugger, Maintainer |
| Estimate | number | giorni ideali |
| Start date | date | pianificata/reale |
| Target date | date | pianificata |
| Confidence | single select | High, Medium, Low |
| Execution ID | text | identificatore immutabile del tentativo |

Viste minime: Intake, Execution board, Dependency queue, Human gates, Roadmap,
Agent performance. Lo stato vive nel Project; non creare label di stato.

Automazioni iniziali:

- nuovo elemento -> `Inbox`;
- Issue riaperta -> `Needs contract`;
- PR collegata aperta -> `In progress`;
- PR pronta per review -> `In review`;
- PR mergiata -> `Done`;
- Issue chiusa come not planned -> `Cancelled`.

Le transizioni `Ready`, `Human gate` e `Merge queue` restano manuali in Fase 1.

## 2. Label

Creare le famiglie documentate in `agent-orchestration.md`:

- `type:*`: epic, task, gate, bug, review, chore, research;
- `risk:*`: low, medium, high, crypto-critical;
- `origin:*`: human, agent;
- `executor:*`: human, agent, pair;
- `gate:*`: human-required, security-review, architecture-review, manual-test;
- `area:*`: governance, ci, docs, styx-js, dart, crypto, storage, wasm, vault.

Non usare label `blocked`, `ready`, `in-progress` o equivalenti.

## 3. Dipendenze

Usare esclusivamente le relazioni native GitHub `blocked by` / `blocking`.
Riferimenti testuali nel corpo sono ridondanza validabile, non la fonte dello
stato. Un task non passa a `Ready` finché ogni dipendenza nativa è chiusa.

## 4. Ruleset `main`

Applicare in due passaggi per non bloccare la stessa PR che introduce i gate.

### Passaggio A — subito dopo il merge governance

- target branch esatto: `main`;
- pull request obbligatoria;
- conversazioni risolte;
- cronologia lineare;
- force-push e cancellazione vietati;
- branch aggiornato prima del merge;
- squash merge soltanto;
- required checks:
  - `Dart reference stack / Dart reference stack gate`;
  - `styx-js web / styx-js web gate`;
  - `WASM integrity / WASM integrity gate`;
  - `CodeQL / Analyze (javascript-typescript)`;
- nessun bypass permanente.

Verificare una PR di prova non-prodotto e un run `merge_group` prima del
Passaggio B.

### Passaggio B — enforcement umano

- almeno una approvazione;
- dismiss stale approvals;
- approvazione del push più recente da persona diversa dall'autore;
- review CODEOWNERS richiesta;
- Merge Queue richiesta;
- metodo della queue: squash;
- concorrenza iniziale: 1 PR;
- accodamento consentito solo da umano autorizzato.

Con un solo maintainer, una PR umana richiede l'onboarding di un secondo reviewer
prima di rendere obbligatoria l'approvazione distinta. Le PR prodotte da una
GitHub App agente possono essere approvate dall'umano, ma l'App non deve avere
permessi di merge o approval.

## 5. Break-glass

Non configurare attori in bypass permanente. Un'emergenza richiede:

1. Issue `Manual gate` con motivo, durata e owner;
2. modifica amministrativa temporanea del ruleset da parte umana;
3. ripristino immediato delle regole;
4. audit post-evento collegato all'Issue.

## 6. Gantt

Il Project è autorevole per stato e date. L'Excel viene rigenerato o aggiornato
solo da dati Project/Issue. Un'importazione dall'Excel verso GitHub è vietata,
salvo bootstrap umano esplicitamente revisionato.
