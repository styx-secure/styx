# OpenMLS-WASM (vendored)

Motore crittografico **MLS (RFC 9420)** per Styx Chat: [OpenMLS](https://github.com/openmls/openmls)
compilato in WebAssembly. È l'**unica libreria MLS con audit indipendente** (SRLabs) e in
produzione (XMTP). Fornisce forward secrecy e post-compromise security per il caso 1:1
(gruppo a 2 membri).

## Provenienza (riproducibile)

Il dettaglio completo — posizione del pin rispetto alle release, verifica dei fix dell'audit,
hash dell'artefatto, rischi residui — sta in **[`PROVENANCE.md`](./PROVENANCE.md)**. In sintesi:

- **Sorgente:** `github.com/openmls/openmls`, crate `openmls-wasm`
- **Commit:** `09e92777dba0528d3d29e2e5e681b7e91637c7be` (2026-07-08) — discendente del tag
  `openmls-v0.8.1`, quindi **porta i fix dell'audit SRLabs** (verificato nel sorgente).
  ⚠️ È un commit di `main` **non rilasciato**: vedi i rischi residui in `PROVENANCE.md`.
- **Licenza:** MIT
- **Ciphersuite:** `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` — X25519 HPKE,
  ChaCha20-Poly1305, SHA-256, Ed25519 (fissata in `patch/lib.rs`)
- **Provider crypto:** `openmls_rust_crypto` (RustCrypto)
- **Toolchain:** `rust:1.96.1` pinnata **per digest** + `wasm-pack` 0.15.0 con **sha256
  verificato**, `Cargo.lock` vendorizzato e build `-- --locked`
- **Dimensione:** `openmls_wasm_bg.wasm` = 1 813 110 byte raw / **≈ 644 KiB gzip** (ok per PWA/Capacitor)

Rigenera con `./build.sh` (richiede Docker). Verifica la riproducibilità con `./verify.sh`: due
build dai medesimi pin devono essere byte-identiche tra loro e uguali all'artefatto committato.
L'artefatto è vendorizzato deliberatamente perché OpenMLS non pubblica un pacchetto npm.

**Patch Styx** (`patch/lib.rs`, applicata da `build.sh` — *non* coperta dall'audit upstream):

- **persistenza:** `Provider.serialize_state()/restore_state()`, `Group.load(provider, groupId)`,
  `Identity.public_key()/load(...)` — servono a salvare lo stato MLS e ricaricare le sessioni
  dopo un refresh della pagina;
- **binding d'identità:** `Group.member_identities()` — espone le credenziali dei membri, così
  l'app può rifiutare un gruppo il cui peer non è chi lo ha inviato;
- **niente panic da rete:** `process_message` restituisce errori invece di trappare il WASM su
  input malformato. Un trap avvelenerebbe l'istanza, che è condivisa da tutte le sessioni.

## API esposta (vedi `openmls_wasm.d.ts`)

`Provider` (crypto+storage per-peer) · `Identity(provider, name)` + `key_package()` ·
`Group.create_new` · `Group.join(provider, welcome, ratchetTree)` · `propose_and_commit_add` →
`{ proposal, commit, welcome }` · `merge_pending_commit` · `create_message` / `process_message`
· `export_ratchet_tree` · `export_key` · `member_identities` ·
`KeyPackage`/`RatchetTree` `to_bytes`/`from_bytes`.

Verificato con un round-trip 1:1 in Node: KeyPackage → gruppo 2-membri → Welcome → join →
messaggi applicativi bidirezionali decifrati (vedi `roundtrip.mjs`).

## Limiti noti

- **Persistenza whole-storage.** Lo stato è serializzato per intero dopo *ogni* operazione
  (`serialize_state`), con riscritture O(stato totale) per messaggio. Verificato da
  `test/chat/styx-chat-assembly.test.js` («a peer survives a reload…»). Il passo successivo è
  uno `StorageProvider` granulare su IndexedDB, che abilita anche la cancellazione delle chiavi
  per epoca.
- **Commit non subordinati agli ACK.** `merge_pending_commit` è esposto, `clear_pending_commit`
  no, e `process_message` fonde i commit in ingresso dentro il WASM: non c'è modo di annullare
  un commit non confermato. Irrilevante oggi (in 1:1 i commit non attraversano il filo), da
  risolvere prima del multi-device.
- **Nessuna fork detection.** Epoch, tree hash e group context non sono esposti; l'unico valore
  confrontabile tra i peer è il secret esportato usato per il safety number.
