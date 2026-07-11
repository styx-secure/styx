# Task 2 — Crypto Core: Key Exchange (X25519 + SPAKE2)

**Stato:** Da iniziare
**Durata stimata:** 5-7 giorni
**Dipendenze:** Task 1
**Package:** `packages/crypto_core/` (estensione)
**Coverage target:** ≥ 95%

---

## Obiettivo

Implementare il Diffie-Hellman X25519 per lo scambio di chiavi simmetriche tra peer, il protocollo SPAKE2 per il pairing remoto basato su codice mnemonico, la derivazione di chiavi simmetriche via HKDF, e la generazione del codice di verifica Double Check.

**SPAKE2 è il rischio tecnico principale del progetto.** Nessun package Dart cross-platform esiste. Questo task include la scelta e l'implementazione della strategia.

---

## Dipendenze Esterne Aggiuntive

```yaml
dependencies:
  # Nessuna nuova dipendenza se SPAKE2 è pure-Dart
  # Altrimenti:
  # ffi: ^2.1.0          # Se FFI verso C/Rust
```

---

## Componenti da Implementare

### 1. `DiffieHellman` — `lib/src/diffie_hellman.dart`

Scambio di chiavi X25519 per generare un shared secret.

```dart
class DiffieHellman {
  /// Genera un keypair X25519 effimero per una sessione DH
  Future<X25519KeyPair> generateEphemeralKeyPair();

  /// Calcola il shared secret da chiave privata locale + chiave pubblica remota
  /// Il risultato è un segreto condiviso di 32 bytes
  Future<Uint8List> computeSharedSecret({
    required Uint8List localPrivateKey,
    required Uint8List remotePublicKey,
  });
}

@immutable
class X25519KeyPair {
  const X25519KeyPair({
    required this.publicKey,
    required this.privateKey,
  });

  final Uint8List publicKey;   // 32 bytes
  final Uint8List privateKey;  // 32 bytes

  void destroy();
}
```

**Note implementative:**
- Usa `X25519().newKeyPair()` e `X25519().sharedSecretKey()` da `cryptography`
- Il shared secret X25519 raw NON deve essere usato direttamente come chiave — passare sempre attraverso HKDF
- I keypair effimeri devono essere distrutti dopo l'uso

### 2. `KeyDerivation` — `lib/src/key_derivation.dart`

Derivazione di chiavi simmetriche dal shared secret via HKDF-SHA256.

```dart
class KeyDerivation {
  /// Deriva una chiave simmetrica dal shared secret DH
  /// 
  /// [sharedSecret] — output del DH (32 bytes)
  /// [salt] — sale opzionale (null = HKDF senza sale)
  /// [info] — contesto applicativo (es. "styx-session-v1")
  /// [outputLength] — lunghezza chiave in bytes (default: 32 per AES-256)
  Future<Uint8List> deriveKey({
    required Uint8List sharedSecret,
    Uint8List? salt,
    required Uint8List info,
    int outputLength = 32,
  });

  /// Deriva una coppia di chiavi direzionali (A→B e B→A)
  /// per cifratura bidirezionale su un singolo shared secret
  Future<DirectionalKeys> deriveDirectionalKeys({
    required Uint8List sharedSecret,
    required Uint8List localPubKey,
    required Uint8List remotePubKey,
  });
}

@immutable
class DirectionalKeys {
  const DirectionalKeys({
    required this.sendKey,
    required this.receiveKey,
  });

  final Uint8List sendKey;     // 32 bytes — chiave per cifrare messaggi in uscita
  final Uint8List receiveKey;  // 32 bytes — chiave per decifrare messaggi in entrata

  void destroy();
}
```

**Note implementative:**
- Usa `Hkdf(hmac: Hmac(Sha256()), outputLength: outputLength)` da `cryptography`
- Per `deriveDirectionalKeys`: ordina le pubkey lessicograficamente, usa `info = "styx-send-" + orderedKeys[0]` e `info = "styx-recv-" + orderedKeys[1]` per garantire che entrambi i peer derivino le stesse chiavi ma nei ruoli corretti
- Ogni derivazione deve produrre chiavi indipendenti (non derivare receive da send)

### 3. `Spake2Session` — `lib/src/spake2/spake2_session.dart`

Stato della sessione SPAKE2.

```dart
enum Spake2Role { initiator, responder }
enum Spake2State { init, messageSent, completed, failed }

class Spake2Session {
  Spake2Session({
    required this.role,
    required Uint8List password,
  });

  final Spake2Role role;
  Spake2State get state;

  /// Genera il messaggio da inviare al peer (pA o pB)
  /// SPAKE2 step 1: calcola T = pw*M + x*G (initiator) o T = pw*N + y*G (responder)
  Uint8List generateMessage();

  /// Processa il messaggio ricevuto dal peer
  /// SPAKE2 step 2: calcola il shared secret K
  /// Restituisce true se il processing è andato a buon fine
  bool processMessage(Uint8List peerMessage);

  /// Ottiene la chiave di sessione derivata (disponibile solo dopo processMessage)
  /// Throws se lo stato non è [completed]
  Uint8List getSessionKey();

  /// Ottiene il confirmation code per la verifica reciproca
  /// Entrambi i peer devono ottenere lo stesso valore
  Uint8List getConfirmation();

  /// Verifica il confirmation code ricevuto dal peer
  bool verifyConfirmation(Uint8List peerConfirmation);

  /// Distrugge tutti i dati sensibili della sessione
  void destroy();
}
```

### 4. `Spake2Protocol` — `lib/src/spake2/spake2_protocol.dart`

Orchestrazione del protocollo SPAKE2 a due messaggi.

```dart
class Spake2Protocol {
  /// Crea una sessione SPAKE2 come initiator
  /// [password] — il codice mnemonico convertito in bytes
  Spake2Session createInitiatorSession(Uint8List password);

  /// Crea una sessione SPAKE2 come responder
  Spake2Session createResponderSession(Uint8List password);

  /// Converte un codice mnemonico BIP-39 in bytes per SPAKE2
  Uint8List mnemonicToPassword(String mnemonic);
}
```

### 5. Strategia di Implementazione SPAKE2

**Opzione A — Pure Dart su P-256 (RACCOMANDATA per l'inizio):**

Implementare SPAKE2 (RFC 9382) usando le primitive EC P-256 di `cryptography`:
- M e N sono punti fissi definiti nell'RFC (hash-to-curve)
- Le operazioni EC (addizione, moltiplicazione scalare) sono disponibili via `EcKeyPairData` e `Ecdh`
- Pro: zero FFI, cross-platform nativo, testabile ovunque
- Contro: P-256 non è ideale (Ed25519/Ristretto255 sarebbe più coerente con il resto), performance leggermente inferiori

**Opzione B — FFI verso libspake2 (Rust):**

Wrap della crate Rust `spake2` via `dart:ffi`:
- Compilare per Android (NDK), iOS (Xcode), Linux, macOS
- Usare `package_ffi` template (Flutter 3.38+) con `hook/build.dart`
- Pro: performance native, implementazione auditata
- Contro: complessità build significativa, 4+ target di compilazione

**Opzione C — OPAQUE o SRP come alternativa:**

Se SPAKE2 risulta troppo complesso, valutare:
- SRP-6a (Secure Remote Password): più diffuso, più librerie disponibili
- OPAQUE: più moderno, ma ancora più complesso da implementare

**Decisione:** Partire con Opzione A. Se le performance sono insufficienti o la P-256 crea problemi di sicurezza percepiti, migrare a Opzione B.

### 6. `SessionVerifier` — `lib/src/session_verifier.dart`

Generazione del codice Double Check per verifica MITM.

```dart
class SessionVerifier {
  /// Genera un codice di verifica a 6 cifre dalla chiave di sessione
  /// Entrambi i peer derivano lo stesso codice e lo verificano fuori banda
  String generateDoubleCheckCode(Uint8List sessionKey);
}
```

**Note implementative:**
- `doubleCheckCode = SHA-256(sessionKey || "styx-double-check-v1")` troncato ai primi 3 bytes
- Conversione 3 bytes → numero 0-999999 → zero-padded a 6 cifre
- Il codice deve essere stabile: stessa sessionKey → stesso codice sempre

---

## Test Specification

### Unit Test: `test/diffie_hellman_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T2.1 | DH round-trip | KeyA, KeyB | `sharedSecret(A.priv, B.pub) == sharedSecret(B.priv, A.pub)` |
| T2.2 | DH commutatività | 100 keypair random | Proprietà commutativa vale per tutti |
| T2.3 | DH unicità | 100 coppie diverse | Shared secret diverso per ogni coppia |
| T2.4 | DH con se stessi | Stessa keypair | Shared secret valido (non zero, non errore) |
| T2.5 | Keypair effimero unicità | Genera 100 | Tutti diversi |
| T2.6 | Keypair effimero dimensioni | — | pubkey=32 bytes, privkey=32 bytes |

### Unit Test: `test/key_derivation_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T2.7 | HKDF vettori RFC 5869 | Test Case 1 | Output match esatto |
| T2.8 | HKDF vettori RFC 5869 | Test Case 2 | Output match esatto |
| T2.9 | HKDF vettori RFC 5869 | Test Case 3 | Output match esatto |
| T2.10 | HKDF deterministico | Stesso input × 2 | Stesso output |
| T2.11 | HKDF info diverso | Stesso secret, info diverso | Output diverso |
| T2.12 | HKDF salt diverso | Stesso secret, salt diverso | Output diverso |
| T2.13 | Directional keys asimmetria | A.pub < B.pub | A.sendKey == B.receiveKey && A.receiveKey == B.sendKey |
| T2.14 | Directional keys determinismo | Stessi input, ordine pubkey invertito | Stesse chiavi (ordinate internamente) |

### Unit Test: `test/spake2_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T2.15 | SPAKE2 round-trip | Stessa password | Entrambi ottengono la stessa session key |
| T2.16 | SPAKE2 password sbagliata | Password diversa su A e B | Session key diverse OPPURE confirmation fallisce |
| T2.17 | SPAKE2 confirmation match | Stessa password | `A.getConfirmation() == B.getConfirmation()` (o cross-verify) |
| T2.18 | SPAKE2 confirmation mismatch | Password diverse | `verifyConfirmation() == false` |
| T2.19 | SPAKE2 non riutilizzabile | Sessione completata → `generateMessage()` | Eccezione o errore di stato |
| T2.20 | SPAKE2 ruoli distinti | Init+Init o Resp+Resp | Protocollo fallisce (ruoli diversi obbligatori) |
| T2.21 | SPAKE2 100 sessioni | 100 password random | Tutti i round-trip funzionano |
| T2.22 | SPAKE2 password corta | 1 byte | Funziona (la sicurezza dipende da SPAKE2, non dalla lunghezza) |
| T2.23 | SPAKE2 password lunga | 1 KB | Funziona |
| T2.24 | SPAKE2 messaggio alterato | Flip 1 bit nel messaggio in transito | Confirmation fallisce |

### Unit Test: `test/session_verifier_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T2.25 | Double Check formato | Session key qualsiasi | Stringa di 6 cifre, zero-padded |
| T2.26 | Double Check determinismo | Stessa session key × 2 | Stesso codice |
| T2.27 | Double Check diversità | Session key diverse | Codici diversi |
| T2.28 | Double Check distribuzione | 10.000 session key random | Distribuzione approssimativamente uniforme su [000000, 999999] |

### Property-Based Test: `test/property_key_exchange_test.dart`

| # | Test | Proprietà |
|---|------|-----------|
| T2.29 | DH commutatività | `∀ keyA, keyB: dh(A.priv, B.pub) == dh(B.priv, A.pub)` |
| T2.30 | HKDF determinismo | `∀ secret, salt, info: derive(s, sa, i) == derive(s, sa, i)` |
| T2.31 | SPAKE2 correttezza | `∀ password: spake2_roundtrip(password) → same_session_key` |

---

## Note di Implementazione

### SPAKE2 Deep Dive

Il protocollo SPAKE2 (RFC 9382) funziona così:

1. **Setup:** Entrambi i peer hanno la stessa password `pw` (il codice mnemonico)
2. **Initiator (A):** Genera scalare random `x`, calcola `pA = x*G + pw*M`, invia `pA`
3. **Responder (B):** Genera scalare random `y`, calcola `pB = y*G + pw*N`, invia `pB`
4. **A calcola:** `K_A = x * (pB - pw*N)` = `x*y*G`
5. **B calcola:** `K_B = y * (pA - pw*M)` = `x*y*G`
6. **Entrambi:** Derivano `sessionKey = Hash(transcript || K)`

M e N sono punti "nothing-up-my-sleeve" generati tramite hash-to-curve. Sono fissi per curva e definiti nell'RFC.

La sicurezza risiede nel fatto che un attaccante che osserva `pA` e `pB` non può separare il contributo di `pw` da quello del random (`x` o `y`) senza conoscere `pw`. Un dizionario attack offline è impossibile.

### Gestione del Timing

- Le operazioni EC devono essere constant-time per prevenire timing attacks
- Il package `cryptography` usa implementazioni constant-time per P-256
- Se si implementa in pure Dart su un'altra curva, verificare che non ci siano early-return nelle moltiplicazioni scalari

### Distruzione dei Segreti

- `Spake2Session.destroy()` deve azzerare: scalare random, shared secret K, session key
- I keypair effimeri DH devono essere distrutti dopo `computeSharedSecret()`

---

## Criteri di Completamento

- [ ] Tutti i test T2.1–T2.31 passano
- [ ] Coverage ≥ 95%
- [ ] `melos run test:all` include Task 0 + 1 + 2, tutto green
- [ ] SPAKE2 funziona su Android e iOS (test su emulatore)
- [ ] Nessun segreto esposto come `String`
- [ ] `destroy()` implementato su tutti gli oggetti con dati sensibili
- [ ] Documentazione della strategia SPAKE2 scelta (A, B, o C)
