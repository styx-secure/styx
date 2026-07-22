// vault-stage.js — the `styx.vault.stage` build flag (plan §B3.0.6).
//
// Blocco 3 lands the vault behind a developer-only flag: while it is off, the
// vault chain (vault.js → vault-db.js, vault-worker, the KDF) must not reach
// the production bundle at all. The flag is a STATICALLY FOLDABLE token —
// Vite replaces `import.meta.env.VITE_VAULT_STAGE` with a literal at build
// time, so a `vaultStageEnabled()`-guarded dynamic import is dead-code
// eliminated when the flag is off (same mechanism as VITE_DEMO in
// styx-adapter.js). The `import.meta.env &&` guard short-circuits in runtimes
// where the object is absent (jest) without hiding the token from Vite.
//
// Stages (plan §B3.0.6): 'off' (default — no vault code ships), 'developer'
// (vault reachable behind the flag for dev/testing, no product data yet),
// and future stages that migrate real namespaces. Only 'developer' is honored
// by this story; anything else is treated as 'off'.

export const VAULT_STAGE_DEVELOPER = 'developer';

/**
 * True only when the build was produced with VITE_VAULT_STAGE=developer.
 * Keep the `import.meta.env.VITE_VAULT_STAGE` token EXACT and literal so the
 * bundler can fold it — do not read it through a variable.
 */
export function vaultStageEnabled() {
  return Boolean(import.meta.env) && import.meta.env.VITE_VAULT_STAGE === VAULT_STAGE_DEVELOPER;
}
