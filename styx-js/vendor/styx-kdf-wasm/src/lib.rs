//! styx-kdf-wasm — bounded Argon2id derivation for the Styx vault (Blocco 3, PR-1).
//!
//! A deliberately SEPARATE WASM artifact from `openmls-wasm`: the MLS state
//! envelope pins that artifact's digest, so the KDF must never share its binary
//! (spec §2.1). This crate knows nothing about MLS, the envelope, ciphersuites
//! or the wire protocol.
//!
//! Surface: one derive-only function. No internal Argon2 objects, no persistent
//! handles, no raw memory, no other algorithms.
//!
//! Two validation layers exist by design:
//!   * JS policy (styx-js/src/crypto/kdf-bounds.js): profiles, OWASP floor,
//!     exact production shapes. THE policy source of truth.
//!   * The ABSOLUTE bounds below: a component-level safety net against direct
//!     or future mis-integrations. They are intentionally wider than the JS
//!     policy and are NOT a second copy of it. No input may request arbitrary
//!     allocations (e.g. multi-GiB) regardless of what the caller does.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use wasm_bindgen::prelude::*;

/// Absolute component bounds (see module docs; the JS policy is stricter).
pub const MIN_PASSWORD_LEN: usize = 1;
pub const MAX_PASSWORD_LEN: usize = 4096;
pub const MIN_SALT_LEN: usize = 8;
pub const MAX_SALT_LEN: usize = 64;
pub const MIN_OUT_LEN: u32 = 16;
pub const MAX_OUT_LEN: u32 = 64;
/// 1 MiB absolute minimum (the JS policy floor is 19456 KiB).
pub const MIN_M_KIB: u32 = 1024;
/// 256 MiB absolute maximum: multi-GiB allocations are unreachable.
pub const MAX_M_KIB: u32 = 262_144;
pub const MIN_T: u32 = 1;
pub const MAX_T: u32 = 16;
pub const MIN_P: u32 = 1;
/// >1 is computed sequentially in WASM (no threads); kept for cross-vector
/// compatibility with the validated spike test vectors.
pub const MAX_P: u32 = 4;

/// Stable error codes. Messages never include the password, the salt, derived
/// output, or any buffer contents.
const ERR_PARAMS: &str = "KDF_PARAMS_INVALID";
const ERR_MEMORY: &str = "KDF_MEMORY_UNAVAILABLE";
const ERR_DERIVE: &str = "KDF_DERIVATION_FAILED";

/// Absolute-bounds check. Pure; also exercised natively by `cargo test`.
fn validate_absolute_bounds(
    password_len: usize,
    salt_len: usize,
    m_kib: u32,
    t_cost: u32,
    p_lanes: u32,
    out_len: u32,
) -> Result<(), String> {
    if !(MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&password_len) {
        return Err(format!("{ERR_PARAMS}: password length out of absolute bounds"));
    }
    if !(MIN_SALT_LEN..=MAX_SALT_LEN).contains(&salt_len) {
        return Err(format!("{ERR_PARAMS}: salt length out of absolute bounds"));
    }
    if !(MIN_M_KIB..=MAX_M_KIB).contains(&m_kib) {
        return Err(format!("{ERR_PARAMS}: memory cost out of absolute bounds"));
    }
    if !(MIN_T..=MAX_T).contains(&t_cost) {
        return Err(format!("{ERR_PARAMS}: iteration count out of absolute bounds"));
    }
    if !(MIN_P..=MAX_P).contains(&p_lanes) {
        return Err(format!("{ERR_PARAMS}: parallelism out of absolute bounds"));
    }
    if !(MIN_OUT_LEN..=MAX_OUT_LEN).contains(&out_len) {
        return Err(format!("{ERR_PARAMS}: output length out of absolute bounds"));
    }
    // Argon2 requires at least 8 KiB per lane; unreachable given MIN_M_KIB and
    // MAX_P, kept as an explicit invariant against future constant changes.
    if m_kib < 8 * p_lanes {
        return Err(format!("{ERR_PARAMS}: memory cost below 8 KiB per lane"));
    }
    Ok(())
}

/// Shared derivation path (wasm export and native tests use the same code).
/// Memory for the Argon2 blocks is reserved with `try_reserve_exact` so an
/// environment that cannot satisfy the (already bounded) memory cost fails
/// with a typed error instead of aborting, and no partial output ever escapes.
fn derive_impl(
    password: &[u8],
    salt: &[u8],
    m_kib: u32,
    t_cost: u32,
    p_lanes: u32,
    out_len: u32,
) -> Result<Vec<u8>, String> {
    validate_absolute_bounds(password.len(), salt.len(), m_kib, t_cost, p_lanes, out_len)?;

    let params = Params::new(m_kib, t_cost, p_lanes, Some(out_len as usize))
        .map_err(|_| format!("{ERR_PARAMS}: rejected by argon2 parameter builder"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // One 1-KiB Block per KiB of memory cost.
    let blocks_needed = m_kib as usize;
    let mut blocks: Vec<Block> = Vec::new();
    if blocks.try_reserve_exact(blocks_needed).is_err() {
        return Err(format!("{ERR_MEMORY}: cannot allocate the requested memory cost"));
    }
    blocks.resize(blocks_needed, Block::default());

    let mut out = vec![0u8; out_len as usize];
    argon2
        .hash_password_into_with_memory(password, salt, &mut out, &mut blocks[..])
        .map_err(|_| ERR_DERIVE.to_string())?;
    Ok(out)
}

/// Derive `out_len` bytes with Argon2id (v0x13) from password and salt bytes.
/// Byte arrays only — no string/encoding ambiguity. Production callers use
/// out_len = 32 (enforced by the JS policy layer, not here).
#[wasm_bindgen]
pub fn argon2id_derive(
    password: &[u8],
    salt: &[u8],
    m_kib: u32,
    t_cost: u32,
    p_lanes: u32,
    out_len: u32,
) -> Result<Vec<u8>, JsError> {
    derive_impl(password, salt, m_kib, t_cost, p_lanes, out_len).map_err(|e| JsError::new(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // Known-answer vectors, cross-validated between two independent
    // implementations (this crate's RustCrypto path and hash-wasm 4.12.0) and
    // stable across Chromium/Firefox in the Argon2id spike. RFC 9106 §5.3
    // literal vectors are NOT API-compatible (they require the secret-key and
    // associated-data inputs this minimal surface deliberately does not
    // expose); these anchors serve the same regression purpose.
    #[test]
    fn kat_spike_anchor_1() {
        let salt: Vec<u8> = (0..16u8).map(|i| i * 7 + 3).collect();
        let out = derive_impl(b"synthetic-test-password", &salt, 19_456, 2, 1, 32).unwrap();
        assert_eq!(
            hex(&out),
            "743669d50cc2010f3ac408895f013d176b7e53a4f114cf6c12f42981e1837a7e"
        );
    }

    #[test]
    fn kat_zero_salt() {
        let out = derive_impl(b"styx-kdf-wasm-kat", &[0u8; 16], 19_456, 2, 1, 32).unwrap();
        assert_eq!(
            hex(&out),
            "b3a27916fb1e0e5ff9f461b7721cf2d5cc5fb50dab51b68f0f8ca2b25818bc7a"
        );
    }

    #[test]
    fn kat_min_bounds() {
        let salt: Vec<u8> = (0..8u8).collect();
        let out = derive_impl(b"k", &salt, 1024, 1, 1, 16).unwrap();
        assert_eq!(hex(&out), "7a6ebb2e8257e4c8ea88b5d3bf7c5a95");
    }

    // Absolute bounds are rejected BEFORE any Argon2 execution or block
    // allocation (validate_absolute_bounds runs first in derive_impl).
    #[test]
    fn absolute_bounds_rejected() {
        let cases: &[(usize, usize, u32, u32, u32, u32)] = &[
            (0, 16, 19_456, 2, 1, 32),          // empty password
            (4097, 16, 19_456, 2, 1, 32),       // oversized password
            (8, 7, 19_456, 2, 1, 32),           // salt too short
            (8, 65, 19_456, 2, 1, 32),          // salt too long
            (8, 16, 1023, 2, 1, 32),            // memory below absolute floor
            (8, 16, 262_145, 2, 1, 32),         // memory above absolute max (multi-GiB unreachable)
            (8, 16, 19_456, 0, 1, 32),          // zero iterations
            (8, 16, 19_456, 17, 1, 32),         // iterations above max
            (8, 16, 19_456, 2, 0, 32),          // zero lanes
            (8, 16, 19_456, 2, 5, 32),          // parallelism above max
            (8, 16, 19_456, 2, 1, 15),          // output too short
            (8, 16, 19_456, 2, 1, 65),          // output too long
        ];
        for &(pw_len, salt_len, m, t, p, out) in cases {
            let pw = vec![b'x'; pw_len];
            let salt_buf = vec![7u8; salt_len];
            let err = derive_impl(&pw, &salt_buf, m, t, p, out)
                .expect_err("out-of-bounds input must be rejected");
            assert!(err.starts_with("KDF_PARAMS_INVALID"), "unexpected error: {err}");
            assert!(!err.contains('x'), "error must not echo input bytes");
        }
    }

    // A failed derivation must not poison the instance: a valid derivation
    // afterwards still succeeds and no partial output is returned on failure.
    #[test]
    fn failure_then_recovery() {
        let salt = [7u8; 16];
        assert!(derive_impl(b"pw", &salt, 999, 2, 1, 32).is_err());
        let out = derive_impl(b"pw", &salt, 1024, 1, 1, 32).unwrap();
        assert_eq!(out.len(), 32);
    }
}
