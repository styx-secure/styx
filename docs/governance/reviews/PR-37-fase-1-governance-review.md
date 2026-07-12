# Review indipendente — PR #37 · Fase 1 Governance

**Modalità:** sola lettura, contesto pulito, nessuna modifica al branch.
**Repository:** `styx-secure/styx` · **PR:** #37 (Draft, `Closes #36`) · **Autore:** maverde73
**Base verificata:** `9344985a41a4f2d51b6a6d8159654d2fa4e621b1` (antenato diretto di `main`; il diff base→head è esattamente il contenuto della PR)
**Head esaminato:** `16ab3d18a137e9247740db8d34ade34f8b3f89ae`
**Ambito:** esclusivamente Fase 1 Governance. Nessuna valutazione del prodotto.

## Metodo

Fetch di base e head, diff `--name-status`, lettura integrale al head di ogni file toccato, validazione dei tre Issue Form e del `config.yml` contro gli schemi SchemaStore (`github-issue-forms`, `github-issue-config`) con `Draft7Validator`, parsing YAML dei quattro workflow per derivare i nomi reali dei check-run, verifica di ascendenza `base→main` e assenza di file fuori scope. Superficie modificata: 14 file, tutti in `.github/`, `docs/governance/`, `AGENTS.md`, `CLAUDE.md`.

## Esito punto per punto

| # | Controllo | Esito |
|---|---|---|
| 1 | Validità Issue Form vs schema GitHub | **PASS** — i 3 form + `config.yml` validano; `render: shell` è nell'enum ammesso; nessun `id` duplicato |
| 2 | Coerenza AGENTS.md / CLAUDE.md / governance | **PASS** — `CLAUDE.md` è adapter subordinato ad `AGENTS.md`; tassonomia label/stati identica fra `agent-orchestration.md` e `github-phase-1-setup.md` |
| 3 | Compatibilità workflow con `pull_request`, `push`, `merge_group` | **PASS** — tutti e 4 i workflow reagiscono a tutti e tre gli eventi |
| 4 | Fail-closed della change detection | **PASS** — base non disponibile → suite completa; `changes` non-`success` → gate `exit 1`; output vuoti trattati come fallimento |
| 5 | Nomi stabili dei required check | **PASS con condizione** — i nomi dei job sono stabili e univoci; il setup doc li elenca però con prefisso `Workflow /` (vedi IMPORTANTE-1) |
| 6 | Correttezza e completezza CODEOWNERS | **PASS con note** — sintassi valida, routing solo umano; verifiche in MINORE-2/3 |
| 7 | Impossibilità per un agente di approvare/mergiare/soddisfare gate | **PASS a livello di policy** — documentato; l'enforcement è configurazione amministrativa esterna alla PR (MINORE-5) |
| 8 | Separazione stato Project vs label | **PASS** — lo stato vive nel Project; label di stato vietate; le famiglie di label non sono di stato |
| 9 | Ruleset e Merge Queue con un solo maintainer | **PASS** — applicazione in due passaggi che evita l'auto-blocco; approvazione distinta rinviata al secondo reviewer; coda conservativa (concurrency 1) |
| 10 | Assenza di modifiche al prodotto / attività PR-3 | **PASS** — diff strettamente governance; `PR-3` compare solo come divieto; corpo PR "without modifying Styx product code or starting PR-3" |

Nessun finding **Blocking**.

---

## Findings

### IMPORTANTE-1 — I required check potrebbero essere trascritti con un prefisso di workflow che non corrisponde al context reale

- **Severità:** Important
- **File e linea:** `docs/governance/github-phase-1-setup.md:77-81`
- **Evidenza:** i required check sono elencati come `Dart reference stack / Dart reference stack gate`, `styx-js web / styx-js web gate`, `WASM integrity / WASM integrity gate`, `CodeQL / Analyze (javascript-typescript)`. Il context reale del check-run di GitHub Actions è il **solo nome del job**: `Dart reference stack gate`, `styx-js web gate`, `WASM integrity gate`, `Analyze (javascript-typescript)` (derivati dal parsing dei workflow). Il nome del workflow non fa parte del context che un ruleset confronta.
- **Rischio:** se le stringhe `Workflow / job` vengono inserite verbatim come nome del required check nel ruleset, nessun check prodotto le soddisfa; restano in stato "Expected/pending" e **ogni PR verso `main` e ogni `merge_group` si bloccano in modo permanente**. Il fallimento è sicuro (blocca, non bypassa), ma è uno stallo operativo.
- **Correzione richiesta:** nel ruleset selezionare i check dal picker dei check osservati (o memorizzare esattamente `Dart reference stack gate`, `styx-js web gate`, `WASM integrity gate`, `Analyze (javascript-typescript)`), scopandoli sull'app GitHub Actions. In alternativa annotare nel doc che il prefisso `Workflow /` è descrittivo e non è il context memorizzato.
- **Criterio di verifica:** sulla PR di prova del Passaggio A e su un run `merge_group`, ciascun required check risulta **Successful** (non "Expected") esattamente sotto quei quattro nomi, prima di abilitare il Passaggio B.

### MINORE-1 — `ci.yml` si attiva su un branch `develop` inesistente; gli altri tre gate sono solo `main`

- **Severità:** Minor
- **File e linea:** `.github/workflows/ci.yml:7` e `:11` (`branches: [main, develop]`)
- **Evidenza:** `develop` non esiste come branch remoto (verificato via `ls-remote`). `codeql.yml`, `styx-js-web.yml`, `wasm-integrity.yml` si attivano solo su `main`. `AGENTS.md:130` e `CLAUDE.md:90` descrivono i gate per "pull request a `main`".
- **Rischio:** configurazione morta oggi; se in futuro nascesse un branch di integrazione `develop`, riceverebbe solo il gate Dart (niente web/WASM/CodeQL), cioè CI parziale, in contrasto con il modello a singolo `main` protetto documentato.
- **Correzione richiesta:** rimuovere `develop` da `ci.yml` (allineamento al modello Fase 1 solo-`main`) oppure, se `develop` è pianificato, aggiungerlo in modo coerente agli altri tre workflow e documentarne lo stato di protezione.
- **Criterio di verifica:** `on.pull_request.branches` e `on.push.branches` identici fra i quattro workflow gate, oppure il doc dichiara `develop` intenzionalmente non protetto.

### MINORE-2 — Voci CODEOWNERS ignorate in silenzio se il proprietario non ha write access; `*` copre già tutto

- **Severità:** Minor
- **File e linea:** `.github/CODEOWNERS:3-35`
- **Evidenza:** `* @maverde73` assegna già la proprietà a ogni path; le voci specifiche successive sono forward-looking (utili con i team) ma ridondanti per la copertura. GitHub ignora silenziosamente qualsiasi riga CODEOWNERS il cui owner non abbia write access.
- **Rischio:** se `@maverde73` (o un futuro team) non avesse write access, "Require review from Code Owners" diventerebbe vacuo o insoddisfacibile senza alcun avviso.
- **Correzione richiesta:** confermare che `@maverde73` abbia accesso write/maintain (come owner del repo/org dovrebbe valere); introducendo team usare `@styx-secure/<team>` e riverificare. Nessuna modifica al codice ora.
- **Criterio di verifica:** l'editor CODEOWNERS di GitHub non mostra warning "Unknown owner / not enough permissions"; una PR di prova del Passaggio B mostra la review dei Code Owners richiesta.

### MINORE-3 — Con un solo code owner, "Require CODEOWNERS review" è insoddisfacibile per PR auto-firmate finché non esiste un secondo owner

- **Severità:** Minor
- **File e linea:** `docs/governance/github-phase-1-setup.md:92` e `:98-100`; `.github/CODEOWNERS:3`
- **Evidenza:** con `* @maverde73` e `@maverde73` unico maintainer, una PR firmata da `@maverde73` non può ricevere un'approvazione Code Owners (l'autore non può essere reviewer richiesto di sé stesso). Il doc rinvia l'"approvazione distinta" all'onboarding di un secondo reviewer (righe 98-100) ma non nomina esplicitamente la review CODEOWNERS fra i requisiti rinviati alla riga 92.
- **Rischio:** se il Passaggio B venisse abilitato ancora in regime single-owner, le PR auto-firmate verso `main` diventerebbero non-mergeabili se non via break-glass.
- **Correzione richiesta:** elencare esplicitamente "review CODEOWNERS richiesta" fra i requisiti rinviati fino all'esistenza di un secondo owner, in parallelo alla nota sull'approvazione distinta.
- **Criterio di verifica:** il Passaggio B viene abilitato solo dopo l'esistenza di una seconda identità idonea come CODEOWNERS, oppure il doc lega esplicitamente la review CODEOWNERS a quell'onboarding.

### MINORE-4 — Il marker di contratto dipende da un input precompilato editabile; l'enforcement è rinviato al parser (Fase 2)

- **Severità:** Minor
- **File e linea:** `.github/ISSUE_TEMPLATE/agent-task.yml:8-15`
- **Evidenza:** `contract_version` è un `input` obbligatorio precompilato con `<!-- styx-task-contract:v1 -->`; la description dichiara che il validator fallisce in chiuso se cambiato, ma in Fase 1 non gira alcun validator (`agent-orchestration.md:249-250` assegna il parser alla Fase 2). Un compilatore può sovrascrivere il valore e creare comunque la Issue.
- **Rischio:** nella finestra Fase 1 è possibile creare Issue prive del marker canonico; l'automazione a valle che cerca il marker le tratterebbe come non-contratto (comportamento fail-closed accettabile) ma non esiste ancora un check attivo.
- **Correzione richiesta:** nessuna per la Fase 1 (già documentato come Fase 2). Facoltativo: annotare nel form che il marker viene verificato solo con l'arrivo del parser Fase 2.
- **Criterio di verifica:** il parser di contratto Fase 2 rifiuta le Issue il cui corpo grezzo non contiene `styx-task-contract:v1`; tracciato come task Fase 2.

### MINORE-5 — Il divieto di approvazione/merge da parte dell'agente è documentato ma applicato solo dalla configurazione App/token esterna alla PR

- **Severità:** Minor
- **File e linea:** `docs/governance/agent-orchestration.md:88-103`; `docs/governance/github-phase-1-setup.md:99-101`; `AGENTS.md:26-37`
- **Evidenza:** il divieto per gli agenti di mergiare/approvare/soddisfare gate è testo di policy. Il suo enforcement tecnico dipende da (a) l'App/token agente privo di scope di write/merge/approval e (b) l'assenza di bypass actor nel ruleset — entrambe impostazioni amministrative non contenute nella PR.
- **Rischio:** documenti corretti con un'App mal-scopata consentirebbero comunque a un agente di approvare/mergiare. La PR non può da sola garantire l'enforcement.
- **Correzione richiesta:** nessuna al branch. Al Passaggio A/B verificare che l'App/token agente non abbia permessi di merge/approve/administration e non compaia in alcuna bypass list.
- **Criterio di verifica:** le impostazioni App di org/repo mostrano l'identità agente senza write-su-branch-protetto, PR-approve o ruleset-bypass; la "Bypass list" del ruleset è vuota.

---

## Osservazioni positive (non richiedono azione)

- Change detection **fail-closed** solida e uniforme nei tre workflow path-aware: base indisponibile → esecuzione completa; job `changes` non-`success` → il gate esce con errore; timeout/silenzio/output vuoti trattati come fallimento (`ci.yml:51-55,125-128`, `styx-js-web.yml:50-53,121-124`, `.github/scripts/wasm-integrity-gate.sh:17-20`, pre-esistente ed eseguibile).
- Il gate finale di ogni workflow gira sempre (`if: always()`), quindi il required check è presente su ogni PR e ogni commit di merge-group anche quando i job pesanti fanno green-skip legittimo.
- Bootstrap del ruleset gestito correttamente in due passaggi (`github-phase-1-setup.md:64-101`): i required check vengono resi obbligatori **dopo** il merge governance, evitando l'auto-blocco della PR che li introduce.
- Separazione stato/label esplicita e coerente fra i due documenti (`agent-orchestration.md:139,176,222-223`; `github-phase-1-setup.md:32,56`).
- Isolamento di scope confermato: nessun file di prodotto toccato, `PR-3` presente solo come divieto (`AGENTS.md:143`, `CLAUDE.md:100-102`).

---

## Verdetto

**GO WITH CONDITIONS**

Il contenuto del branch è coerente, fail-closed e strettamente entro l'ambito Fase 1 Governance, senza alcuna modifica al prodotto o attività PR-3. Non emergono finding bloccanti. Il merge può procedere a condizione che, **prima di rendere obbligatori i required check e la Merge Queue (Passaggio A/B)**, vengano soddisfatte:

1. **IMPORTANTE-1** — configurare/verificare i required check con i context esatti (`Dart reference stack gate`, `styx-js web gate`, `WASM integrity gate`, `Analyze (javascript-typescript)`) su una PR di prova e un run `merge_group`.
2. **MINORE-1** — allineare o documentare i trigger `develop`.
3. **MINORE-2/3** — confermare il write access di `@maverde73` e rinviare esplicitamente la review CODEOWNERS all'onboarding di un secondo owner.
4. **MINORE-5** — verificare, al momento della configurazione, che l'identità agente non abbia permessi di merge/approve e non sia in bypass list.

Le condizioni sono di configurazione amministrativa e documentazione, non richiedono modifiche al prodotto Styx.
