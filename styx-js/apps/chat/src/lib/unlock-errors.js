// unlock-errors.js — single choke point between unlock failures and the user.
// Maps stable MLS_STATE_* codes (MLS state envelope) and the key store's
// stable wrong-password error to fixed Italian messages. The user-facing text
// is NEVER composed from err.message or err.details: those stay in
// development logs only. US-001 — residual item 3 of
// docs/security/2026-07-12-review-mls-state-envelope.md.

// Recovery actions for MLS_STATE_OPENMLS_INCOMPATIBLE, least destructive
// first (mirrors the library's details.actions, which stays authoritative in
// dev logs — the UI shows this fixed Italian rendering).
const OPENMLS_INCOMPATIBLE_ACTIONS = Object.freeze([
  'Riapri con la versione dell’app che ha scritto questo stato.',
  'Attendi una versione dell’app in grado di migrare questo stato.',
  'Come ultima risorsa, esegui un factory reset esplicito (elimina la sessione).',
]);

// No VAULT_* codes in this map, deliberately: the runtime unlock path uses
// EncryptedKeyStore, which throws plain Errors without a code, and the coded
// vault modules are not runtime-integrated — the Blocco 3 CI gate forbids
// their identifiers in the production bundle. The PR that wires the vault in
// (and revises that gate) will extend this map to the vault codes.
const STATE_DAMAGED =
  'Lo stato cifrato delle conversazioni risulta danneggiato o non leggibile. Riprova a sbloccare.';
const STATE_FROM_OTHER_BUILD =
  'Lo stato delle conversazioni è stato salvato da una versione dell’app diversa e non è utilizzabile da questa build.';
const MESSAGES = Object.freeze({
  // MLS state envelope (fail-closed unlock path)
  MLS_STATE_INVALID: STATE_DAMAGED,
  MLS_STATE_CORRUPTED: STATE_DAMAGED,
  MLS_STATE_VERSION_UNSUPPORTED: STATE_FROM_OTHER_BUILD,
  MLS_STATE_SCHEMA_UNSUPPORTED: STATE_FROM_OTHER_BUILD,
  MLS_STATE_OPENMLS_INCOMPATIBLE:
    'Lo stato delle conversazioni è stato scritto da una versione incompatibile del motore crittografico. Nessun dato è andato perso.',
  MLS_STATE_CIPHERSUITE_MISMATCH:
    'Lo stato delle conversazioni è stato creato con una configurazione crittografica diversa da quella di questa build.',
  MLS_STATE_MIGRATION_FAILED:
    'L’aggiornamento dello stato delle conversazioni non è riuscito. Riprova a sbloccare.',
  MLS_STATE_RESTORE_FAILED:
    'Il ripristino dello stato precedente delle conversazioni non è riuscito. Riprova a sbloccare.',
});

// EncryptedKeyStore (the runtime key store) throws plain Errors: the stable
// library message is the dispatch key (exact match, never displayed).
const MESSAGES_BY_EXACT_RAW = Object.freeze({
  'Invalid password': 'Password errata. Riprova.',
});

const GENERIC_MESSAGE =
  'Impossibile sbloccare. Riprova; se l’errore persiste, riavvia l’app.';

const NO_ACTIONS = Object.freeze([]);

// Statically foldable exactly like styx-adapter.js: Vite replaces
// `import.meta.env.DEV`, so the log call is dead-code eliminated from
// production bundles; under Jest/Node import.meta.env is undefined and the
// guard short-circuits.
function devLog(err) {
  if (import.meta.env && import.meta.env.DEV) {
    console.debug('[unlock] error', err?.code, err?.details, err);
  }
}

/**
 * Describe an unlock failure for the user.
 * Returns `{ message, actions }`: a fixed safe message (never derived from
 * `err.message`/`err.details`) and an ordered, possibly empty, list of
 * recovery actions.
 */
export function describeUnlockError(err) {
  devLog(err);
  const code = typeof err?.code === 'string' ? err.code : undefined;
  const rawMessage = typeof err?.message === 'string' ? err.message : undefined;
  const message = (code && MESSAGES[code])
    || (rawMessage && MESSAGES_BY_EXACT_RAW[rawMessage])
    || GENERIC_MESSAGE;
  const actions = code === 'MLS_STATE_OPENMLS_INCOMPATIBLE'
    ? OPENMLS_INCOMPATIBLE_ACTIONS
    : NO_ACTIONS;
  return { message, actions };
}
