// vault-stage.js — the `styx.vault.stage` build flag (plan §B3.0.6).
//
// Blocco 3 lands the vault behind a developer-only flag: while it is off, the
// vault chain (vault.js → vault-db.js, vault-worker, the KDF) must not reach
// the production bundle at all. The flag is a STATICALLY FOLDABLE token —
// Vite replaces `import.meta.env.VITE_VAULT_STAGE` with a literal at build
// time, so the guarded dynamic import below is dead-code eliminated when the
// flag is off (same mechanism as VITE_DEMO in styx-adapter.js). The
// `import.meta.env &&` guard short-circuits in runtimes where the object is
// absent (jest) without hiding the token from Vite.
//
// Stages (plan §B3.0.6, ordered): off → developer-only → test-profile →
// opt-in → limited-alpha → … Only `developer-only` is honored by this story;
// anything else is treated as off.

export const VAULT_STAGE_DEVELOPER_ONLY = 'developer-only';

/**
 * True only when the build was produced with VITE_VAULT_STAGE=developer-only.
 * Keep the `import.meta.env.VITE_VAULT_STAGE` token EXACT and literal so the
 * bundler can fold it — do not read it through a variable.
 */
export function vaultStageEnabled() {
  return Boolean(import.meta.env) && import.meta.env.VITE_VAULT_STAGE === VAULT_STAGE_DEVELOPER_ONLY;
}

/**
 * The single flag-guarded entry into the vault lifecycle. When the flag is off
 * (production default) this returns null AND the guarded `import()` folds out,
 * so no vault module reaches the bundle — the anti-bundle CI step proves the
 * flag-off exclusion, and this function proves the flag actually gates access.
 * When the flag is on, it loads the lifecycle module dynamically.
 * @returns {Promise<null | typeof import('../storage/vault.js')>}
 */
export async function loadVaultLifecycle() {
  if (!vaultStageEnabled()) return null;
  return import('../storage/vault.js');
}
