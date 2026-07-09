# OpenMLS-WASM (vendored)

Motore crittografico **MLS (RFC 9420)** per Styx Chat: [OpenMLS](https://github.com/openmls/openmls)
compilato in WebAssembly. È l'**unica libreria MLS con audit indipendente** (SRLabs) e in
produzione (XMTP). Fornisce forward secrecy e post-compromise security per il caso 1:1
(gruppo a 2 membri).

## Provenienza (riproducibile)

- **Sorgente:** `github.com/openmls/openmls`, crate `openmls-wasm`
- **Commit:** `09e92777dba0528d3d29e2e5e681b7e91637c7be` (2026-07-08)
- **Licenza:** MIT
- **Ciphersuite:** `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (MTI di OpenMLS)
- **Toolchain:** `rust:latest` in Docker + `wasm-pack build --target web`
- **Dimensione:** `openmls_wasm_bg.wasm` ≈ 1.8 MB raw / **≈ 655 KB gzip** (ok per PWA/Capacitor)

Rigenera con `./build.sh` (richiede Docker). L'artefatto è vendorizzato deliberatamente perché
OpenMLS non pubblica un pacchetto npm.

**Patch Styx:** oltre all'esempio ufficiale, applichiamo `patch/lib.rs` (via `build.sh`) che
aggiunge i metodi di persistenza: `Provider.serialize_state()/restore_state()`,
`Group.load(provider, groupId)`, `Identity.public_key()/load(...)`. Servono a salvare lo stato
MLS (gruppi + chiavi) su IndexedDB/localStorage e ricaricare le sessioni dopo un refresh della
pagina — senza, ricaricando si perderebbero le sessioni.

## API esposta (vedi `openmls_wasm.d.ts`)

`Provider` (crypto+storage per-peer) · `Identity(provider, name)` + `key_package()` ·
`Group.create_new` · `Group.join(provider, welcome, ratchetTree)` · `propose_and_commit_add` →
`{ proposal, commit, welcome }` · `merge_pending_commit` · `create_message` / `process_message`
· `export_ratchet_tree` · `KeyPackage`/`RatchetTree` `to_bytes`/`from_bytes`.

Verificato con un round-trip 1:1 in Node: KeyPackage → gruppo 2-membri → Welcome → join →
messaggi applicativi bidirezionali decifrati (vedi `roundtrip.mjs`).

## Persistenza (risolta)

Lo stato del gruppo era **in memoria**; ora la patch espone serialize/restore dello storage del
`Provider` + `Group.load`/`Identity.load`, e `StyxChat` li usa per persistere su localStorage e
ricaricare le sessioni dopo un refresh. Verificato da `test/chat/styx-chat-assembly.test.js`
(«a peer survives a reload…»). *Nota:* è persistenza whole-storage after-each-op; per volumi
elevati si passerà a un `StorageProvider` backato direttamente su IndexedDB.
