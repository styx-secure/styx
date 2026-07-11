# Task 3 — Crypto Core: Key Storage, BIP-39, Shamir

**Stato:** Da iniziare
**Durata stimata:** 3-4 giorni
**Dipendenze:** Task 1, Task 2
**Package:** `packages/crypto_core/` (estensione)
**Coverage target:** ≥ 95%

---

## Obiettivo

Persistenza sicura delle chiavi private tramite hardware-backed storage, generazione di codici mnemonici BIP-39 per il pairing remoto, e implementazione di Shamir's Secret Sharing per il backup delle chiavi con threshold scheme.

---

## Dipendenze Esterne Aggiuntive

```yaml
dependencies:
  flutter_secure_storage: ^10.0.0  # Keychain/Keystore wrapper
  bip39_mnemonic: <latest>         # BIP-39 mnemonic generation
```

---

## Componenti da Implementare

### 1. `SecureKeyStore` — `lib/src/secure_key_store.dart`

Wrapper attorno a flutter_secure_storage per la persistenza hardware-backed delle chiavi.

```dart
abstract class SecureKeyStore {
  /// Salva un keypair Ed25519 nel secure storage
  /// La chiave privata viene cifrata con AES-256-GCM usando una chiave
  /// derivata dal Keystore/Keychain hardware
  Future<void> storeKeyPair({
    required String keyId,
    required StyxKeyPair keyPair,
  });

  /// Recupera un keypair dal secure storage
  /// Restituisce null se il keyId non esiste
  Future<StyxKeyPair?> retrieveKeyPair(String keyId);

  /// Elimina un keypair dal secure storage
  Future<void> deleteKeyPair(String keyId);

  /// Verifica se un keypair esiste
  Future<bool> hasKeyPair(String keyId);

  /// Salva un valore binario generico (es. shared secret, session key)
  Future<void> storeSecret({
    required String key,
    required Uint8List value,
  });

  /// Recupera un valore binario
  Future<Uint8List?> retrieveSecret(String key);

  /// Elimina un valore binario
  Future<void> deleteSecret(String key);

  /// Elimina tutto il secure storage (factory reset)
  Future<void> deleteAll();
}
```

**Implementazione concreta:** `FlutterSecureKeyStore`

```dart
class FlutterSecureKeyStore implements SecureKeyStore {
  FlutterSecureKeyStore({FlutterSecureStorage? storage})
    : _storage = storage ?? const FlutterSecureStorage(
        aOptions: AndroidOptions(encryptedSharedPreferences: true),
        iOptions: IOSOptions(
          accessibility: KeychainAccessibility.first_unlock_this_device,
        ),
      );
}
```

**Note implementative:**
- **Android:** `EncryptedSharedPreferences` usa Tink (AES-256-SIV per chiavi, AES-256-GCM per valori). Il master key è protetto dal Keystore hardware.
- **iOS:** Keychain con `kSecAttrAccessibleAfterFirstUnlockThisDevice` — accessibile dopo il primo sblocco, non migra a nuovi device (sicuro per chiavi device-bound).
- **Limitazione hardware:** Né Android Keystore né iOS Secure Enclave supportano Ed25519. Le chiavi Ed25519 sono cifrate in software e lo storage hardware protegge solo la chiave di cifratura.
- **Serializzazione:** Le chiavi sono serializzate come Base64 per la compatibilità con flutter_secure_storage (che accetta solo stringhe). La conversione `Uint8List → Base64 String → storage → Base64 String → Uint8List` deve essere testata per round-trip.

### 2. `MnemonicGenerator` — `lib/src/mnemonic_generator.dart`

Generazione di codici mnemonici BIP-39 per il pairing remoto.

```dart
class MnemonicGenerator {
  /// Genera un codice mnemonico BIP-39 con il numero di parole specificato
  /// 
  /// [wordCount] — 6 (66 bit), 8 (88 bit), 12 (128 bit), 24 (256 bit)
  /// Default: 6 per pairing (sufficiente per SPAKE2)
  /// 
  /// [language] — lingua della wordlist (default: english)
  String generate({int wordCount = 6, String language = 'english'});

  /// Valida che un mnemonic sia sintatticamente corretto
  /// Verifica: parole nella wordlist, checksum valido, numero parole corretto
  bool validate(String mnemonic, {String language = 'english'});

  /// Converte un mnemonic in bytes (seed) per l'uso come password SPAKE2
  Uint8List mnemonicToSeed(String mnemonic);

  /// Lista delle lingue supportate
  List<String> get supportedLanguages;
}
```

**Note implementative:**
- BIP-39 standard: entropia → SHA-256 checksum → concatenazione → split ogni 11 bit → indice wordlist
- 6 parole = 66 bit (6 × 11) di cui 2 bit di checksum = 64 bit di entropia effettiva
- 8 parole = 88 bit (8 × 11) di cui ~3 bit di checksum = ~85 bit di entropia effettiva
- Per il pairing SPAKE2, 6 parole (64 bit) sono sufficienti perché SPAKE2 è resistente a brute-force offline
- `mnemonicToSeed` usa PBKDF2-SHA512 con 2048 iterazioni come da BIP-39 spec (passphrase vuota)
- **Attenzione:** BIP-39 standard prevede solo wordcount multipli di 3 (12, 15, 18, 21, 24). Per 6 e 8 parole si usa una variante non-standard con checksum ridotto, oppure si selezionano semplicemente N parole random dalla wordlist senza checksum BIP-39. Documentare la scelta.

### 3. `ShamirSplitter` — `lib/src/shamir/shamir_splitter.dart`

Implementazione di Shamir's Secret Sharing su GF(256).

```dart
class ShamirSplitter {
  /// Divide un secret in [n] shares, di cui [threshold] sono necessari per ricostruire
  /// 
  /// [secret] — il segreto da dividere (chiave privata Ed25519, 32 bytes)
  /// [threshold] — numero minimo di share necessari (default: 2)
  /// [totalShares] — numero totale di share da generare (default: 3)
  /// 
  /// Restituisce una lista di share, ciascuno con un indice (1..n) e i bytes
  List<ShamirShare> split({
    required Uint8List secret,
    int threshold = 2,
    int totalShares = 3,
  });
}

@immutable
class ShamirShare {
  const ShamirShare({
    required this.index,
    required this.data,
  });

  /// Indice dello share (1..n, mai 0)
  final int index;

  /// Bytes dello share (stessa lunghezza del secret originale)
  final Uint8List data;

  /// Serializza lo share per export (es. QR code o testo)
  /// Formato: "styx-share-v1:{index}:{base64data}"
  String serialize();

  /// Deserializza uno share da stringa
  factory ShamirShare.deserialize(String encoded);
}
```

### 4. `ShamirReconstructor` — `lib/src/shamir/shamir_reconstructor.dart`

```dart
class ShamirReconstructor {
  /// Ricostruisce il secret da [threshold] share
  /// 
  /// [shares] — almeno [threshold] share validi
  /// 
  /// Throws [InsufficientSharesException] se shares.length < threshold originale
  /// Throws [InvalidShareException] se gli share sono corrotti
  Uint8List reconstruct(List<ShamirShare> shares);
}
```

**Note implementative per Shamir su GF(256):**

L'implementazione opera byte per byte. Per ogni byte del secret:
1. **Split:** Genera un polinomio random di grado `threshold - 1` dove il coefficiente costante è il byte del secret. Valuta il polinomio in `totalShares` punti (x = 1, 2, ..., n). Ogni valutazione è un byte dello share.
2. **Reconstruct:** Usa l'interpolazione di Lagrange su GF(256) per ricostruire il coefficiente costante da `threshold` punti.

Tutte le operazioni (addizione, moltiplicazione, divisione) avvengono in GF(256) con il polinomio irriducibile `x^8 + x^4 + x^3 + x + 1` (0x11B, usato da AES).

L'implementazione è ~150-200 righe di Dart puro. Tabelle di lookup per moltiplicazione/inversione in GF(256) accelerano le performance.

### 5. `KeyBackup` — `lib/src/key_backup.dart`

Orchestrazione del backup e restore delle chiavi.

```dart
class KeyBackup {
  KeyBackup({
    required ShamirSplitter splitter,
    required ShamirReconstructor reconstructor,
  });

  /// Crea un backup della chiave privata come share Shamir
  /// Default: 2-of-3 (2 share bastano per ricostruire, ne servono almeno 3)
  List<ShamirShare> backupPrivateKey({
    required StyxPrivateKey privateKey,
    int threshold = 2,
    int totalShares = 3,
  });

  /// Ripristina la chiave privata da un set di share
  /// Ricostruisce il keypair completo (privkey → pubkey derivata)
  Future<StyxKeyPair> restoreFromShares(List<ShamirShare> shares);
}
```

---

## Barrel Export Aggiornato — `lib/styx_crypto_core.dart`

```dart
library styx_crypto_core;

// Task 1
export 'src/styx_key_pair.dart';
export 'src/identity_manager.dart';
export 'src/signer.dart';
export 'src/verifier.dart';
export 'src/hasher.dart';
export 'src/key_converter.dart';

// Task 2
export 'src/diffie_hellman.dart';
export 'src/key_derivation.dart';
export 'src/spake2/spake2_session.dart';
export 'src/spake2/spake2_protocol.dart';
export 'src/session_verifier.dart';

// Task 3
export 'src/secure_key_store.dart';
export 'src/mnemonic_generator.dart';
export 'src/shamir/shamir_splitter.dart';
export 'src/shamir/shamir_reconstructor.dart';
export 'src/key_backup.dart';
```

---

## Test Specification

### Unit Test: `test/secure_key_store_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T3.1 | Store + retrieve keypair | Keypair generato | Keypair recuperato identico |
| T3.2 | Retrieve inesistente | keyId mai usato | Restituisce `null` |
| T3.3 | Delete + retrieve | Store → delete → retrieve | `null` |
| T3.4 | Overwrite | Store(id, keyA) → Store(id, keyB) → retrieve | keyB |
| T3.5 | HasKeyPair true | Dopo store | `true` |
| T3.6 | HasKeyPair false | keyId mai usato | `false` |
| T3.7 | Store/retrieve secret binario | 64 bytes random | Round-trip perfetto |
| T3.8 | DeleteAll | Store 3 keypair → deleteAll → retrieve tutti | Tutti `null` |
| T3.9 | Caratteri speciali nel keyId | `"styx/key:main-01"` | Funziona senza errori |

### Unit Test: `test/mnemonic_generator_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T3.10 | Genera 6 parole | `wordCount: 6` | 6 parole separate da spazio |
| T3.11 | Genera 8 parole | `wordCount: 8` | 8 parole separate da spazio |
| T3.12 | Parole nella wordlist | Mnemonic generato | Tutte le parole presenti nella BIP-39 english wordlist |
| T3.13 | Unicità | Genera 1000 mnemonic | Tutti diversi |
| T3.14 | Validate corretto | Mnemonic appena generato | `true` |
| T3.15 | Validate parola alterata | Sostituisci 1 parola con "zzzzz" | `false` |
| T3.16 | MnemonicToSeed deterministico | Stesso mnemonic × 2 | Stesso seed |
| T3.17 | MnemonicToSeed diverso | Mnemonic diversi | Seed diversi |
| T3.18 | Mnemonic 12 parole | `wordCount: 12` | 12 parole, validazione BIP-39 standard OK |

### Unit Test: `test/shamir_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T3.19 | 2-of-3 ricostruzione (share 1,2) | Secret 32 bytes | Ricostruzione = originale |
| T3.20 | 2-of-3 ricostruzione (share 1,3) | Secret 32 bytes | Ricostruzione = originale |
| T3.21 | 2-of-3 ricostruzione (share 2,3) | Secret 32 bytes | Ricostruzione = originale |
| T3.22 | 2-of-3 con 1 solo share | Secret 32 bytes | Eccezione |
| T3.23 | 3-of-5 tutte le combinazioni | Secret 32 bytes | Tutte le C(5,3)=10 combinazioni → originale |
| T3.24 | 3-of-5 con 2 share | Secret 32 bytes | Eccezione o risultato sbagliato |
| T3.25 | Secret 1 byte | `[0x42]` | Round-trip corretto |
| T3.26 | Secret 64 bytes | 64 bytes random | Round-trip corretto |
| T3.27 | Secret tutti zeri | `Uint8List(32)` | Round-trip corretto |
| T3.28 | Secret tutti 0xFF | 32 bytes di 0xFF | Round-trip corretto |
| T3.29 | Share serialize/deserialize | Share generato | `ShamirShare.deserialize(share.serialize()) == share` |
| T3.30 | Share corrotto | Flip 1 byte in share.data | Ricostruzione produce risultato sbagliato ≠ originale |

### Unit Test: `test/key_backup_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T3.31 | Backup + restore | Keypair → backup → restore | Keypair identico (pubkey e privkey) |
| T3.32 | Restore con share insufficienti | 1 share su threshold 2 | Eccezione |
| T3.33 | Backup produce N share | threshold=2, total=3 | Esattamente 3 share |
| T3.34 | Ogni share ha indice unico | 5 share | Indici {1, 2, 3, 4, 5} |

### Property-Based Test: `test/property_shamir_test.dart`

| # | Test | Proprietà |
|---|------|-----------|
| T3.35 | Ricostruzione universale | `∀ secret random (1-64 bytes), ∀ combinazione valida di T share su N: reconstruct == secret` |
| T3.36 | Shamir informazione teorica | `∀ secret, T-1 share: reconstruct ≠ secret` (con alta probabilità) |
| T3.37 | Share indipendenza | `∀ secret: share[i] è uniformemente distribuito` (chi-square test su campione) |

---

## Note di Implementazione

### GF(256) Lookup Tables

Per performance, pre-calcolare:
- `EXP_TABLE[256]` — potenze di α (generatore, tipicamente 0x03)
- `LOG_TABLE[256]` — logaritmi discreti

Moltiplicazione: `a * b = EXP_TABLE[(LOG_TABLE[a] + LOG_TABLE[b]) % 255]`
Inversione: `a^-1 = EXP_TABLE[255 - LOG_TABLE[a]]`

Le tabelle sono costanti e possono essere `const` in Dart.

### flutter_secure_storage Pitfalls

- **Android backup:** `EncryptedSharedPreferences` può essere incluso nel backup cloud di Android. Se il master key non viene migrato, i dati diventano illeggibili sul nuovo device. Questo va bene per chiavi device-bound, ma va documentato.
- **iOS Keychain sharing:** Con `kSecAttrAccessibleAfterFirstUnlockThisDevice` i dati NON vengono sincronizzati su iCloud Keychain. Questo è il comportamento desiderato.
- **First boot:** Su Android, dopo un factory reset, il Keystore potrebbe non essere immediatamente disponibile. Implementare retry con backoff.

---

## Criteri di Completamento

- [ ] Tutti i test T3.1–T3.37 passano
- [ ] Coverage ≥ 95%
- [ ] `melos run test:all` include Task 0 + 1 + 2 + 3, tutto green
- [ ] SecureKeyStore testato su emulatore Android
- [ ] SecureKeyStore testato su simulatore iOS
- [ ] Shamir implementato in pure Dart senza dipendenze esterne
- [ ] Share serializzabili come stringa per QR/testo
