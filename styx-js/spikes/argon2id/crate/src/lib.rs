// STYX_SPIKE_PROTOTYPE — Argon2id candidate A: the RustCrypto `argon2` crate
// compiled to WASM with the project-pinned toolchain. API kept minimal on
// purpose: derive-only, fail-closed on bad parameters.
use argon2::{Algorithm, Argon2, Params, Version};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn argon2id_derive(
    password: &[u8],
    salt: &[u8],
    m_kib: u32,
    t_cost: u32,
    p_lanes: u32,
    out_len: usize,
) -> Result<Vec<u8>, JsError> {
    let params = Params::new(m_kib, t_cost, p_lanes, Some(out_len))
        .map_err(|e| JsError::new(&format!("bad params: {e}")))?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; out_len];
    a.hash_password_into(password, salt, &mut out)
        .map_err(|e| JsError::new(&format!("derive failed: {e}")))?;
    Ok(out)
}
