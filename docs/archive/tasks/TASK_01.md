# Task 1 — Crypto Core: Chiavi e Firme

**Stato:** Da iniziare
**Durata stimata:** 2-3 giorni
**Dipendenze:** Task 0
**Package:** `packages/crypto_core/`
**Coverage target:** ≥ 95%

---

## Obiettivo

Implementare le primitive crittografiche fondamentali: generazione keypair Ed25519/X25519, firma digitale, verifica, hashing SHA-256 con supporto per hash chain, e conversione Ed25519 → X25519.

Questo task è il fondamento di tutta la libreria Styx. Ogni layer superiore dipende da questi componenti.

---

## Dipendenze Esterne

```yaml
dependencies:
  cryptography: ^2.9.0          # Ed25519, X25519, SHA-256, AES, HKDF
  cryptography_flutter: ^2.3.4  # Delegazione a CryptoKit/javax.crypto
  crypto: ^3.0.7                # Hashing standalone (Dart team)
  meta: ^1.16.0                 # Annotazioni @immutable, @visibleForTesting

dev_dependencies:
  test: ^1.25.0
  mocktail: ^1.0.4
  glados: ^1.1.7                # Property-based testing
  very_good_analysis: ^7.0.0
```

---

## Componenti da Implementare

### 1. `StyxKeyPair` — `lib/src/styx_key_pair.dart`

Wrapper tipizzato e immutabile per un keypair Ed25519.

```dart
@immutable
class StyxKeyPair {
  const StyxKeyPair({
    required this.publicKey,
    required this.privateKey,
  });

  /// Chiave pubblica Ed25519 (32 bytes)
  final StyxPublicKey publicKey;

  /// Chiave privata Ed25519 (32 bytes seed)
  final StyxPrivateKey privateKey;
}

@immutable
class StyxPublicKey {
  const StyxPublicKey(this.bytes);

  /// Raw bytes della chiave pubblica (32 bytes)
  final Uint8List bytes;

  /// Hex encoding per serializzazione/display
  String toHex();

  /// Ricostruzione da hex
  factory StyxPublicKey.fromHex(String hex);

  /// Equality basato sui bytes (non reference)
  @override
  bool operator ==(Object other);

  @override
  int get hashCode;
}

@immutable
class StyxPrivateKey {
  const StyxPrivateKey(this.bytes);

  /// Raw bytes della chiave privata (32 bytes seed)
  final Uint8List bytes;

  /// Azzera i bytes in memoria (best-effort su Dart GC)
  void destroy();
}
```

**Note implementative:**
- `StyxPublicKey` e `StyxPrivateKey` usano `Uint8List`, mai `String` (le stringhe Dart sono immutabili e non azzerabili)
- `destroy()` su `StyxPrivateKey` sovrascrive i bytes con zeri. Non è una garanzia assoluta (il GC potrebbe aver copiato) ma è il best-effort su Dart
- Equality su `StyxPublicKey` deve usare `ListEquality` o confronto byte-a-byte costante-nel-tempo per prevenire timing attacks

### 2. `IdentityManager` — `lib/src/identity_manager.dart`

Genera e gestisce le identità crittografiche.

```dart
class IdentityManager {
  /// Genera un nuovo keypair Ed25519 usando CSPRNG
  Future<StyxKeyPair> generateKeyPair();

  /// Esporta la chiave pubblica come bytes
  Uint8List exportPublicKey(StyxPublicKey key);

  /// Importa una chiave pubblica da bytes
  StyxPublicKey importPublicKey(Uint8List bytes);

  /// Esporta la chiave privata come bytes (per backup)
  Uint8List exportPrivateKey(StyxPrivateKey key);

  /// Importa una chiave privata da bytes (per restore)
  Future<StyxKeyPair> importPrivateKey(Uint8List bytes);
}
```

**Note implementative:**
- `generateKeyPair()` usa `Ed25519().newKeyPair()` da `cryptography`
- L'import della chiave privata ricostruisce il keypair completo (pubkey derivata dalla privkey)
- `cryptography_flutter` delega automaticamente alle API native quando disponibile

### 3. `Signer` — `lib/src/signer.dart`

Firma digitale con Ed25519.

```dart
class Signer {
  /// Firma un payload binario con la chiave privata
  /// Restituisce la firma (64 bytes)
  Future<Uint8List> sign({
    required Uint8List payload,
    required StyxPrivateKey privateKey,
  });
}
```

**Note implementative:**
- Usa `Ed25519().sign(payload, keyPair: keyPair)` da `cryptography`
- La firma Ed25519 produce sempre 64 bytes
- Il payload non ha limiti di dimensione (Ed25519 firma l'hash internamente)

### 4. `Verifier` — `lib/src/verifier.dart`

Verifica delle firme digitali.

```dart
class Verifier {
  /// Verifica che la firma sia valida per il payload dato e la chiave pubblica
  Future<bool> verify({
    required Uint8List payload,
    required Uint8List signature,
    required StyxPublicKey publicKey,
  });
}
```

**Note implementative:**
- Usa `Ed25519().verify(payload, signature: Signature(signature, publicKey: publicKey))`
- Non deve mai lanciare eccezioni per firme invalide — restituisce `false`
- Deve gestire gracefully: firma di lunghezza sbagliata, chiave pubblica di lunghezza sbagliata

### 5. `Hasher` — `lib/src/hasher.dart`

Hashing SHA-256 con supporto per hash chain.

```dart
class Hasher {
  /// SHA-256 di un singolo payload
  /// Restituisce il digest (32 bytes)
  Future<Uint8List> hash(Uint8List data);

  /// SHA-256 della concatenazione di un hash precedente + payload
  /// Usato per costruire la hash chain del ledger
  /// Se previousHash è null (genesis event), hash solo il payload
  Future<Uint8List> chainHash({
    required Uint8List? previousHash,
    required Uint8List payload,
  });

  /// SHA-256 di una lista di segmenti concatenati
  /// Usato per costruire l'hash completo di un evento
  /// (previousHash || eventType || payload || hlcTimestamp)
  Future<Uint8List> compositeHash(List<Uint8List> segments);
}
```

**Note implementative:**
- Usa `Sha256()` da `cryptography` (più veloce di `crypto` in VM, ~100× più veloce in browser via WebCrypto)
- `chainHash` con `previousHash == null` è il caso del genesis event
- `compositeHash` concatena i segmenti in ordine e applica SHA-256 una sola volta sulla concatenazione
- I segmenti vuoti sono permessi (producono un hash deterministico)

### 6. `KeyConverter` — `lib/src/key_converter.dart`

Conversione Ed25519 → X25519 per Diffie-Hellman.

```dart
class KeyConverter {
  /// Converte una chiave pubblica Ed25519 in X25519
  /// Necessario per il key agreement DH
  Future<Uint8List> ed25519PublicToX25519(StyxPublicKey ed25519Key);

  /// Converte una chiave privata Ed25519 in X25519
  Future<Uint8List> ed25519PrivateToX25519(StyxPrivateKey ed25519Key);
}
```

**Note implementative:**
- La conversione Ed25519 → X25519 è una operazione matematica ben definita (RFC 7748 §6, birational equivalence delle curve)
- Il package `cryptography` potrebbe non esporre direttamente questa conversione — valutare se usare `pinenacl` o implementare la conversione manualmente (clamping del seed + moltiplicazione scalare sulla curva Montgomery)
- Se non disponibile nativamente, generare keypair X25519 separati e memorizzarli insieme all'Ed25519

---

## Barrel Export — `lib/styx_crypto_core.dart`

```dart
library styx_crypto_core;

export 'src/styx_key_pair.dart';
export 'src/identity_manager.dart';
export 'src/signer.dart';
export 'src/verifier.dart';
export 'src/hasher.dart';
export 'src/key_converter.dart';
```

---

## Test Specification

### Unit Test: `test/identity_manager_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T1.1 | Generazione keypair | — | `publicKey.bytes.length == 32`, `privateKey.bytes.length == 32` |
| T1.2 | Keypair unicità | Genera 100 keypair | Tutte le chiavi pubbliche diverse |
| T1.3 | PublicKey ≠ PrivateKey | Keypair generato | `publicKey.bytes != privateKey.bytes` |
| T1.4 | Export/Import pubkey round-trip | Keypair generato | Export → Import → bytes identici |
| T1.5 | Export/Import privkey round-trip | Keypair generato | Export → Import → pubkey derivata identica |
| T1.6 | Import pubkey invalida | 31 bytes | Eccezione appropriata |
| T1.7 | Import pubkey vuota | 0 bytes | Eccezione appropriata |

### Unit Test: `test/signer_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T1.8 | Firma lunghezza | Qualsiasi payload + keypair | Firma = 64 bytes |
| T1.9 | Firma deterministica | Stesso payload + stessa chiave × 2 | Stessa firma |
| T1.10 | Firma su payload vuoto | `Uint8List(0)` | Firma valida di 64 bytes |
| T1.11 | Firma su payload grande | 10 MB di dati random | Firma valida di 64 bytes, nessun OOM |

### Unit Test: `test/verifier_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T1.12 | Sign+Verify round-trip | Payload qualsiasi | `verify() == true` |
| T1.13 | Payload alterato | Firma valida + payload con 1 bit flippato | `verify() == false` |
| T1.14 | Firma alterata | Payload valido + firma con 1 byte modificato | `verify() == false` |
| T1.15 | Chiave pubblica sbagliata | Firma con keyA, verify con keyB | `verify() == false` |
| T1.16 | Firma lunghezza sbagliata | Firma di 63 bytes | `verify() == false` (no eccezione) |
| T1.17 | Chiave pubblica vuota | 0 bytes | `verify() == false` (no eccezione) |
| T1.18 | RFC 8032 test vectors | Vettori ufficiali Ed25519 | Tutti passano |

### Unit Test: `test/hasher_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T1.19 | SHA-256 vettore noto | `""` (empty) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| T1.20 | SHA-256 vettore noto | `"abc"` | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` |
| T1.21 | SHA-256 deterministico | Stesso input × 2 | Stesso output |
| T1.22 | SHA-256 avalanche | Input differisce di 1 bit | Output totalmente diverso |
| T1.23 | Chain hash con previous | `previousHash + payload` | Hash deterministico |
| T1.24 | Chain hash genesis | `previousHash = null` | Hash valido del solo payload |
| T1.25 | Composite hash | 3 segmenti | Hash della concatenazione |
| T1.26 | Composite hash ordine | Segmenti in ordine diverso | Hash diverso |
| T1.27 | Composite hash segmento vuoto | Segmento vuoto nella lista | Hash deterministico, nessun errore |

### Unit Test: `test/key_converter_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T1.28 | Conversione pubkey Ed→X | Pubkey Ed25519 | X25519 pubkey di 32 bytes |
| T1.29 | Conversione privkey Ed→X | Privkey Ed25519 | X25519 privkey di 32 bytes |
| T1.30 | DH agreement cross-key | A(Ed) → A(X), B(Ed) → B(X), DH(A,B) | Shared secret identico da entrambi i lati |

### Property-Based Test: `test/property_test.dart`

| # | Test | Proprietà |
|---|------|-----------|
| T1.31 | Sign+Verify universale | `∀ payload, ∀ keypair: sign(payload, key) → verify(payload, sig, pubkey) == true` |
| T1.32 | Hash collision resistance | `∀ a ≠ b: hash(a) ≠ hash(b)` (su campione di 10.000 coppie random) |
| T1.33 | Firma non trasferibile | `∀ payload, ∀ keyA ≠ keyB: verify(payload, sign(payload, keyA), keyB.pub) == false` |
| T1.34 | Hash determinismo | `∀ data: hash(data) == hash(data)` |

---

## Note di Implementazione

### Sicurezza della memoria

- **Mai usare `String` per chiavi o segreti.** Le stringhe Dart sono immutabili e risiedono nel garbage collector. Usare sempre `Uint8List`.
- **`destroy()` è best-effort.** Dart non offre `mlock()` o `sodium_malloc()`. L'overwrite con zeri è il meglio che si può fare senza FFI. Documentare questa limitazione.
- **Constant-time comparison** per `StyxPublicKey.operator==`. Non usare `ListEquality` (potrebbe short-circuit). Implementare un confronto che esegue sempre tutti i 32 confronti.

### Performance

- `cryptography_flutter` delega automaticamente a:
  - **Android:** javax.crypto (hardware-backed quando disponibile)
  - **iOS:** CryptoKit (Secure Enclave per operazioni supportate)
  - **Web:** WebCrypto API
- In test (VM Dart), le operazioni sono in software puro: ~200 sign/sec, ~500 verify/sec, ~50K hash/sec

### Conversione Ed25519 → X25519

La conversione è definita in RFC 7748 §6. Se `cryptography` non espone una API diretta:
1. **Opzione A:** Generare keypair X25519 separati e memorizzarli come campo aggiuntivo del `StyxKeyPair`
2. **Opzione B:** Usare `pinenacl` per la conversione (pure Dart, TweetNaCl)
3. **Opzione C:** Implementare la conversione: per la privkey basta il clamping del seed a 32 bytes; per la pubkey serve la conversione dalla curva Edwards a Montgomery

L'opzione A è la più sicura e semplice. L'opzione B è la più fedele al manifesto.

---

## Criteri di Completamento

- [ ] Tutti i test T1.1–T1.34 passano
- [ ] Coverage ≥ 95%
- [ ] `melos run test:all` include Task 0 + Task 1, tutto green
- [ ] `melos run analyze` — zero warning
- [ ] Nessuna `String` usata per dati sensibili (audit manuale)
- [ ] `destroy()` implementato su `StyxPrivateKey`
- [ ] Vettori di test RFC 8032 inclusi come golden file
