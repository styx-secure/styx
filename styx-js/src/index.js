// styx-js/src/index.js
// Main entry point for the Styx JS library

// === Facade (primary API) ===
export { SovereignLedger, LedgerConfig, StyxState, LogLevel } from './facade/sovereign-ledger.js';

// === Crypto ===
export {
  StyxPublicKey, StyxPrivateKey, StyxKeyPair, IdentityManager,
  Hasher,
  Signer, Verifier,
  KeyConverter, X25519KeyPair, DiffieHellman,
  KeyDerivation, DirectionalKeys,
  StyxEncryptor,
  Spake2Protocol, Spake2Session, Spake2Role, Spake2State,
  ShamirSplitter, ShamirReconstructor, ShamirShare, KeyBackup,
  InsufficientSharesException, InvalidShareException,
  MnemonicGenerator, SessionVerifier, DoubleCheckVerifier,
  setBip39Wordlist, getBip39Wordlist,
} from './crypto/index.js';

// === Ledger ===
export {
  LedgerEvent, EventType, PruneReason, ChainErrorType, ChainValidationError,
  VectorClock, CausalRelation, CausalityChecker,
  HybridLogicalClock,
  EventFactory,
  ChainValidator,
  Fork, ForkDetector, MergeResult, DeterministicMerge, MergeEventFactory,
  PruneProtocol, PruneState, RetentionManager,
  LedgerService,
} from './ledger/index.js';

// === Storage ===
export {
  LedgerStore, PeerStore, OutboxStore, SecureKeyStore,
  MemoryLedgerStore, MemoryPeerStore, MemoryOutboxStore, MemoryKeyStore,
  IndexedDBLedgerStore, IndexedDBPeerStore, IndexedDBKeyStore,
} from './storage/index.js';

// === Transport ===
export {
  TransportInterface, TransportState, TransportMessage,
  WebRTCTransport,
  NostrTransport, RelayPool,
  TransportFailover, TransportPriority, TransportFailoverException, OutboxWorker,
} from './transport/index.js';

// === Pairing ===
export {
  TrustStoreManager,
  QrPairingData, QrPairingService,
  RemotePairingService, RemotePairingState,
} from './pairing/trust-store.js';

// === Utils (selected) ===
export {
  bytesToHex, hexToBytes, bytesToBase64, base64ToBytes,
  utf8Encode, utf8Decode, randomBytes, uuidv4,
} from './utils.js';
