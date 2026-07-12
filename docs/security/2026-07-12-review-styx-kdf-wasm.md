# Review — styx-kdf-wasm (Blocco 3, PR‑1)

Oggetto: il crate `styx-js/vendor/styx-kdf-wasm/` (artefatto Argon2id separato),
il validatore di policy `styx-js/src/crypto/kdf-bounds.js`, le suite di test
KAT/bounds e l'estensione dei gate CI — i 5 commit di `feat/vault-kdf-wasm`.
Review condotta da un revisore **indipendente dalla stesura** (agente separato,
contesto pulito) con verifiche attive: riesecuzione della suite jest,
`sha256sum -c` sugli artefatti, **ri-derivazione indipendente di tutti e 5 i
vettori KAT con hash-wasm 4.12.0** (5/5 byte-identici), probe dei boundary
esatti sull'artefatto WASM reale e probe avversariali sul validatore JS.

## 1. Tabella di verifica (checklist §16 del mandato)

| # | Voce | Verdetto | Sintesi |
|---|---|---|---|
| 1 | Separazione da OpenMLS | **OK** | Crate con lockfile/digest/lifecycle propri; `vendor/openmls-wasm` non toccato; digest KDF ≠ digest OpenMLS imposto da test jest e da step CI; stessa immagine pinnata e stesso wasm-pack sha-verificato del crate canonico (pin identici byte-a-byte). |
| 2 | API minima | **OK** | Un solo export derive-only su byte array; output copiato fuori e memoria interna liberata; nessun oggetto Argon2, handle, memoria grezza o altro algoritmo (il glue wasm-bindgen standard espone `memory`/`malloc`: inevitabile per il target, registrato). |
| 3 | Bounds JS | **OK** | Validatore unico, puro, zero dipendenze: algoritmo/versione/salt/outLen/memoria/iterazioni/parallelismo/profilo/combinazioni/campi sconosciuti e mancanti/non-interi; floor 19456 accettato esatto, 262145 rifiutato esatto (verificato). Lookup del profilo indurito contro la prototype chain (K2, applicato). |
| 4 | Hard bounds Rust | **OK** | Limiti assoluti distinti e più larghi della policy, documentati come safety net e non come copia; boundary probati sull'artefatto reale (1023/262145 rifiutati, 1024/262144 accettati, t=17 rifiutato); multi-GiB irraggiungibile; wrap u32 al confine ABI pinnato da test e documentato (K1, applicato). |
| 5 | No allocazioni pre-validazione | **OK** | Validazione prima istruzione di `derive_impl`; blocchi via `try_reserve_exact` → `KDF_MEMORY_UNAVAILABLE` tipizzato; anti-allocation dimostrata su spy, su wrapper contatore del vero `argon2id_derive` (0 chiamate) e nel browser (3 GiB → errore tipizzato, mai trap). |
| 6 | KAT | **OK** | Le tre ancore dello spike + due vettori nuovi, tutti ri-derivati indipendentemente con hash-wasm in questa review (5/5 MATCH), byte-identici su Node, Chromium e Firefox e tra build pulite. RFC 9106 §5.3 non API-compatibile (richiede secret key + associated data non esposti): deviazione motivata e documentata in fixture, lib.rs e PROVENANCE. |
| 7 | Riproducibilità | **OK** | Immagine per digest, wasm-pack sha-verificato, build da copia pulita dei soli sorgenti committati, `--locked` + drift guard; `verify.sh`: doppia build byte-identica tra sé e vs `pkg/` committato, `SHA256SUMS -c`, controllo file inattesi. Esecuzione reale registrata in PROVENANCE (4 file `REPRODUCIBLE`). |
| 8 | Provenance | **OK** | Completa per il mandato §11 (sorgente, dipendenze+checksum via lockfile, toolchain, digest immagine, wasm-pack, comando, data, digest artefatto, commit, doppia build, rapporti audit/deny, licenze, separazione da OpenMLS); nessun path locale o dato personale. Due imprecisioni testuali corrette (K5). |
| 9 | Licenze | **OK** | Tutte permissive (MIT/Apache-2.0, BSD-3-Clause, Unicode-3.0), allowlist in `deny.toml` coerente con l'albero reale. |
| 10 | Advisory | **OK** | `cargo audit` 0.22.2 e `cargo deny` 0.20.2 come binari release sha256-verificati nell'immagine pinnata: 0 vulnerabilità; advisories/bans/licenses/sources ok; rieseguiti in CI dal job hermetic. |
| 11 | No build cache | **OK** | Solo i 15 file attesi tracciati; `.gitignore` su target/archivi/file rigenerati; step CI che fallisce su qualunque `target/` o tarball tracciato nel repo. |
| 12 | Assenza dal bundle | **OK** | Nessun import dal runtime di prodotto (grep verificato su src/, apps/chat/src, push_bridge); `kdf-bounds` non esportato dall'indice; gate web esteso: `styx_kdf_wasm`/`argon2id_derive` in `dist/` → fail. |
| 13 | Errori non sensibili | **OK** | Codici stabili; l'errore argon2 interno è scartato; test su entrambi i layer che i messaggi non echeggiano password/salt/output. |
| 14 | Nessuna integrazione anticipata | **OK** | Nessun vault/RSK/wrapper/IndexedDB/worker/flag/UI/factory reset/localStorage nel diff; OpenMLS intatto; README dichiara "Not yet integrated". |
| — | CI wiring e green-skip | **OK** | Nuovi job con `if` sui rispettivi output; aggregatore rosso se un tier needed non è `success`; green-skip preservato su PR estranee; actions a SHA pieno, `contents: read`, timeout sugli hermetic. |
| — | Correttezza dei test | **OK** | 41/41 al momento della review (42/42 dopo K1); asseriscono ciò che dichiarano; boundary esatti coperti; spec browser esclusi da jest e dal config Playwright di default. |

## 2. Finding e risoluzioni

| ID | Severità | Dove | Finding | Risoluzione |
|---|---|---|---|---|
| K1 | Minor | `lib.rs` / `kdf-wasm.test.js` | I numeri JS ≥ 2³² vengono ridotti modulo 2³² dall'ABI u32 prima dei bound assoluti: un chiamante diretto con mKib "enorme" degrada silenziosamente a un costo piccolo invece di essere rifiutato (la policy JS, unico percorso sancito, lo blocca prima). | **Applicato**: test che pinna `2^32+1024 ≡ 1024` + nota ABI nel README ("integer enforcement SOLO nel layer JS"). |
| K2 | Minor | `kdf-bounds.js` | `KDF_PROFILES[params.profile]` con `'__proto__'`/`'constructor'` risolveva via prototype chain e superava il check "unknown profile" (il fail-closed reggeva solo grazie al check di combinazione successivo). | **Applicato**: lookup con `Object.hasOwn` + 3 casi di test (`__proto__`, `constructor`, `toString`). |
| K3 | Minor | `wasm-integrity.yml` | Il tier KDF non verificava la coerenza dei pin (build.sh ↔ PROVENANCE ↔ crate canonico): una PR futura poteva far divergere silenziosamente l'immagine o wasm-pack. | **Applicato**: step "Pin coherence" nel job `kdf-light` (digest immagine e sha wasm-pack estratti da build.sh, grep in PROVENANCE e nel build.sh canonico, fail su mismatch). |
| K4 | Minor | `kdf-bounds.js` vs piano B3.0.4 | `passwordMinLen: 1` (byte) senza spiegare il rapporto col vincolo utente 8–1024 char del piano. | **Applicato**: commento in `KDF_POLICY` — bound del layer KDF in byte UTF-8; il vincolo utente sarà imposto dal chiamante vault (PR‑2/3). |
| K5 | Minor | `PROVENANCE.md` | (a) "three known-answer anchors" nella suite nativa (è 1 ancora spike + 2 vettori nuovi); (b) "27 crates, all from crates.io" (il 27º è il crate root locale). | **Applicato**: entrambe le frasi riformulate. |
| K6 | Minor | `playwright.kdf.config.js` | Fallback locale a un Chromium in cache non pinnato (inerte in CI, commento onesto); può mascherare differenze di engine in locale. | **Accettato** come caveat d'ambiente (stesso pattern degli spike); da rimuovere quando l'ambiente locale supporterà i browser Playwright nativi. |

## 3. Rischi residui registrati (accettabili)

1. **Gate verde se il job `changes` fallisce** (pattern PRE-esistente su `main`
   in `wasm-integrity.yml` e `styx-js-web.yml`, non introdotto da questa PR):
   con `changes` in failure gli output sono vuoti e il gate prende il ramo
   "nulla è cambiato". Da sistemare in un intervento CI dedicato
   (`needs.changes.result == 'success'` come precondizione dei gate).
2. **Vettori RFC 9106 letterali assenti** per scelta di superficie API:
   compensati da 5 vettori cross-validati su due implementazioni indipendenti
   e tre engine, ri-verificati indipendentemente in questa review; il rischio
   di bug correlato tra RustCrypto e hash-wasm è remoto ma non nullo.
3. **`SHA256SUMS` aggiornato a mano dopo un rebuild** (build.sh non lo
   rigenera): ogni divergenza è bloccata da verify.sh, dal test jest
   anti-drift e dalla CI — attrito di processo, non rischio di integrità.
4. **Glue wasm-bindgen espone `memory`/`malloc`** nell'init output: inevitabile
   per il target; irrilevante quando l'artefatto vivrà nel worker dedicato
   (PR‑3, invariante B3.0.5.9).
5. **Profili mobile provvisori fino a M5** — dichiarato nel codice e coerente
   col piano manuale.

## 4. Verdetto

```text
GO
```

Nessun finding Important o Critical; i sei Minor sono stati applicati (K1–K5)
o registrati (K6) in questa stessa PR. La PR‑1 rispetta il mandato: artefatto
KDF separato e riproducibile, doppio layer di bounds con boundary verificati,
KAT cross-validati su tre engine, supply chain pinnata e pulita, nessuna
integrazione anticipata del vault. Il merge resta una decisione dell'utente;
PR‑2 non è autorizzata da questo documento.
