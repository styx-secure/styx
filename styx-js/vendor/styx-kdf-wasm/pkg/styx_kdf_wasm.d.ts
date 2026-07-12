/* tslint:disable */
/* eslint-disable */

/**
 * Derive `out_len` bytes with Argon2id (v0x13) from password and salt bytes.
 * Byte arrays only — no string/encoding ambiguity. Production callers use
 * out_len = 32 (enforced by the JS policy layer, not here).
 *
 * Validation order (K7/K8 — nothing is converted, copied or allocated first):
 *   1. password/salt really are Uint8Array; lengths read WITHOUT copying
 *   2. every number is a finite, integral, in-range u32 (no mod-2³² wrap)
 *   3. absolute component bounds
 *   4. only now: the two small byte copies, then the Argon2 block memory
 */
export function argon2id_derive(password: any, salt: any, m_kib: number, t_cost: number, p_lanes: number, out_len: number): Uint8Array;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly argon2id_derive: (a: any, b: any, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
