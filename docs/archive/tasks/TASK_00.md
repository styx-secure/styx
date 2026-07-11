# Task 0 — Scaffolding del Monorepo

**Stato:** Da iniziare
**Durata stimata:** 1 giorno
**Dipendenze:** Nessuna
**Package coinvolti:** Root workspace, tutti i package (struttura vuota)

---

## Obiettivo

Creare l'infrastruttura completa del progetto Styx: monorepo con Pub Workspaces, 6 package Dart, CI/CD con GitHub Actions, linting rigoroso, coverage gate al 90%, e script melos per l'automazione dei test di regressione.

Al completamento di questo task, `melos bootstrap` e `melos run test:all` devono eseguire senza errori su un'infrastruttura placeholder.

---

## Struttura Finale

```
styx/
├── .github/
│   └── workflows/
│       └── ci.yml                    # GitHub Actions pipeline
├── .gitignore
├── README.md                         # Branding Styx + istruzioni sviluppo
├── ROADMAP.md                        # Piano di sviluppo task-by-task
├── analysis_options.yaml             # Root lint rules (very_good_analysis)
├── melos.yaml                        # Monorepo orchestration
├── pubspec.yaml                      # Pub Workspace root
├── docs/
│   └── tasks/                        # Specifiche tecniche per task
│       ├── TASK_00.md
│       ├── TASK_01.md
│       └── ...
├── packages/
│   ├── crypto_core/                  # Primitivi crittografici
│   │   ├── analysis_options.yaml
│   │   ├── pubspec.yaml
│   │   ├── lib/
│   │   │   ├── styx_crypto_core.dart # Barrel export
│   │   │   └── src/                  # Implementazioni
│   │   └── test/
│   │       └── styx_crypto_core_test.dart
│   ├── storage/                      # Database cifrato
│   ├── ledger_engine/                # Event sourcing + hash chain
│   ├── transport/                    # Nostr, Email, Tor
│   ├── push_bridge_client/           # FCM/APNs client
│   └── styx/                         # Façade pubblica
├── push_bridge_server/               # Go microservice (Task 10)
└── test_integration/                 # Test cross-package (Task 12)
```

---

## Componenti da Configurare

### 1. Pub Workspace Root (`pubspec.yaml`)

- `name: styx_workspace`
- `publish_to: none`
- `sdk: ^3.6.0`
- Sezione `workspace:` che elenca tutti i 6 package

### 2. Melos (`melos.yaml`)

Script richiesti:

| Script | Descrizione | Comando |
|--------|-------------|---------|
| `test:all` | Esegue tutti i test con coverage | `melos exec --fail-fast -- "dart test --coverage=coverage"` |
| `test:unit` | Solo test unitari (tag `unit`) | `melos exec --fail-fast -- "dart test --tags=unit"` |
| `test:integration` | Solo test integrazione (tag `integration`) | `melos exec --fail-fast -- "dart test --tags=integration"` |
| `coverage:check` | Verifica soglia 90% | Parsing lcov con awk |
| `analyze` | Analisi statica | `dart analyze --fatal-infos --fatal-warnings` |
| `format:check` | Verifica formatting | `dart format --set-exit-if-changed .` |
| `format:fix` | Auto-format | `dart format .` |
| `ci` | Pipeline completa locale | analyze → format → test → coverage |
| `clean` | Pulizia artefatti | Rimuove `.dart_tool`, `build`, `coverage` |
| `deps:check` | Dipendenze obsolete | `dart pub outdated` |

### 3. Lint Rules (`analysis_options.yaml`)

Base: `very_good_analysis` (ultimo stable).

Override aggiuntivi:
- `strict-casts: true`
- `strict-inference: true`
- `strict-raw-types: true`
- `avoid_dynamic_calls: true`
- `prefer_const_constructors: true`
- `prefer_final_locals: true`
- `unawaited_futures: true`

Esclusioni: `*.g.dart`, `*.freezed.dart`, `*.mocks.dart`

### 4. GitHub Actions (`ci.yml`)

**Job 1 — Analyze & Format:**
- Checkout, setup Dart SDK stable, install melos, bootstrap
- `melos run analyze`
- `melos run format:check`

**Job 2 — Test (matrix per package):**
- Matrix: `[crypto_core, storage, ledger_engine, transport, push_bridge_client, styx]`
- Installa `lcov`, `libsqlcipher-dev`
- `dart test --coverage=coverage`
- Formattazione coverage con `coverage:format_coverage`
- Verifica soglia 90%
- Upload artefatto coverage

**Job 3 — Coverage Merge:**
- Scarica tutti gli artefatti coverage
- Merge con `lcov -a`
- Summary globale

**Job 4 — Full Regression:**
- `melos run test:all` — esegue TUTTI i test di TUTTI i package
- Questo job è la garanzia anti-regressione

**Trigger:** push su `main`/`develop`, PR verso `main`/`develop`
**Concurrency:** cancel-in-progress per branch

### 5. Package Placeholder

Ogni package deve avere:
- `pubspec.yaml` con `resolution: workspace`, dipendenze corrette, `publish_to: none`
- `analysis_options.yaml` che include `very_good_analysis`
- `lib/<package_name>.dart` — barrel file con solo la dichiarazione `library`
- `lib/src/` — directory vuota per le implementazioni future
- `test/<package_name>_test.dart` — test placeholder con un singolo `expect(true, isTrue)`

### 6. Naming Convention

| Package dir | Package name | Library name | Import |
|-------------|-------------|--------------|--------|
| `crypto_core` | `styx_crypto_core` | `styx_crypto_core` | `package:styx_crypto_core/styx_crypto_core.dart` |
| `storage` | `styx_storage` | `styx_storage` | `package:styx_storage/styx_storage.dart` |
| `ledger_engine` | `styx_ledger_engine` | `styx_ledger_engine` | `package:styx_ledger_engine/styx_ledger_engine.dart` |
| `transport` | `styx_transport` | `styx_transport` | `package:styx_transport/styx_transport.dart` |
| `push_bridge_client` | `styx_push_bridge_client` | `styx_push_bridge_client` | `package:styx_push_bridge_client/styx_push_bridge_client.dart` |
| `styx` | `styx` | `styx` | `package:styx/styx.dart` |

---

## Test

| # | Test | Aspettativa |
|---|------|-------------|
| T0.1 | `melos bootstrap` | Exit code 0, nessun errore |
| T0.2 | `melos run analyze` | Zero warning, zero errori |
| T0.3 | `melos run format:check` | Nessun file da formattare |
| T0.4 | `melos run test:all` | Tutti i placeholder test passano |
| T0.5 | `melos run ci` | Pipeline completa green |
| T0.6 | Git push → GitHub Actions | Tutti i job green |

---

## Criteri di Completamento

- [ ] `melos bootstrap` esegue senza errori
- [ ] `melos run test:all` — 6 test passano (1 per package)
- [ ] `melos run analyze` — zero warning
- [ ] `melos run format:check` — zero diff
- [ ] CI GitHub Actions green su tutti e 4 i job
- [ ] Coverage gate attivo (placeholder test = 100%)
- [ ] `.gitignore` copre tutti gli artefatti generati
- [ ] README.md con istruzioni di setup
