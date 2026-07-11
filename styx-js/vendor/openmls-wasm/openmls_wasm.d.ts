/* tslint:disable */
/* eslint-disable */

export class AddMessages {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly commit: Uint8Array;
    readonly proposal: Uint8Array;
    readonly welcome: Uint8Array;
}

export class Group {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    create_message(provider: Provider, sender: Identity, msg: Uint8Array): Uint8Array;
    static create_new(provider: Provider, founder: Identity, group_id: string): Group;
    export_key(provider: Provider, label: string, context: Uint8Array, key_length: number): Uint8Array;
    export_ratchet_tree(): RatchetTree;
    static join(provider: Provider, welcome: Uint8Array, ratchet_tree: RatchetTree): Group;
    /**
     * Reload a group previously persisted in the provider's storage.
     * Returns undefined if no group with that id exists.
     */
    static load(provider: Provider, group_id: string): Group | undefined;
    /**
     * The identity string of every current group member — the BasicCredential's
     * serialized identity, which Styx sets to the member's Nostr pubkey hex.
     *
     * This is what lets the app bind an MLS member to a transport identity: a peer
     * who hands us a group built for somebody else can be detected and rejected.
     */
    member_identities(): string[];
    merge_pending_commit(provider: Provider): void;
    process_message(provider: Provider, msg: Uint8Array): Uint8Array;
    propose_and_commit_add(provider: Provider, sender: Identity, new_member: KeyPackage): AddMessages;
}

export class Identity {
    free(): void;
    [Symbol.dispose](): void;
    key_package(provider: Provider): KeyPackage;
    /**
     * Reload an identity whose signature keypair was previously persisted in
     * the provider storage (restored via `Provider.restore_state`).
     */
    static load(provider: Provider, name: string, public_key: Uint8Array): Identity | undefined;
    constructor(provider: Provider, name: string);
    /**
     * The MLS signature public key, to be persisted so the identity can be
     * reloaded after a page refresh via `Identity.load`.
     */
    public_key(): Uint8Array;
}

export class KeyPackage {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Deserialize a KeyPackage from bytes
     */
    static from_bytes(bytes: Uint8Array): KeyPackage;
    /**
     * Serialize this KeyPackage to bytes
     */
    to_bytes(): Uint8Array;
}

export class NoWelcomeError {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
}

export class Provider {
    free(): void;
    [Symbol.dispose](): void;
    constructor();
    /**
     * Restore storage previously produced by `serialize_state`.
     *
     * Every length is read from the input and MUST be treated as hostile: this blob
     * can be a corrupted or attacker-supplied `mls:state`. All offset arithmetic is
     * therefore checked. A naive `i + kl + vl > bytes.len()` wraps on wasm32 (usize
     * is 32-bit) and would let a crafted length slip past the bound into an
     * out-of-range slice — a panic, i.e. a trap that poisons the shared instance at
     * init. Checked arithmetic turns every such case into a returned error.
     */
    restore_state(bytes: Uint8Array): void;
    /**
     * Serialize the whole storage (all MLS group/key state) to bytes so it can
     * be persisted (e.g. in IndexedDB) and survive a page reload.
     * Format: u64 count, then per entry: u64 key_len, u64 val_len, key, val.
     */
    serialize_state(): Uint8Array;
}

export class RatchetTree {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Deserialize a RatchetTree from bytes
     */
    static from_bytes(bytes: Uint8Array): RatchetTree;
    /**
     * Serialize this RatchetTree to bytes
     */
    to_bytes(): Uint8Array;
}

export function greet(): void;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_addmessages_free: (a: number, b: number) => void;
    readonly __wbg_group_free: (a: number, b: number) => void;
    readonly __wbg_identity_free: (a: number, b: number) => void;
    readonly __wbg_keypackage_free: (a: number, b: number) => void;
    readonly __wbg_nowelcomeerror_free: (a: number, b: number) => void;
    readonly __wbg_provider_free: (a: number, b: number) => void;
    readonly __wbg_ratchettree_free: (a: number, b: number) => void;
    readonly addmessages_commit: (a: number) => any;
    readonly addmessages_proposal: (a: number) => any;
    readonly addmessages_welcome: (a: number) => any;
    readonly group_create_message: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly group_create_new: (a: number, b: number, c: number, d: number) => number;
    readonly group_export_key: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly group_export_ratchet_tree: (a: number) => number;
    readonly group_join: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly group_load: (a: number, b: number, c: number) => [number, number, number];
    readonly group_member_identities: (a: number) => [number, number];
    readonly group_merge_pending_commit: (a: number, b: number) => [number, number];
    readonly group_process_message: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly group_propose_and_commit_add: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly identity_key_package: (a: number, b: number) => number;
    readonly identity_load: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly identity_new: (a: number, b: number, c: number) => [number, number, number];
    readonly identity_public_key: (a: number) => [number, number];
    readonly keypackage_from_bytes: (a: number, b: number) => [number, number, number];
    readonly keypackage_to_bytes: (a: number) => [number, number];
    readonly provider_new: () => number;
    readonly provider_restore_state: (a: number, b: number, c: number) => [number, number];
    readonly provider_serialize_state: (a: number) => [number, number];
    readonly ratchettree_from_bytes: (a: number, b: number) => [number, number, number];
    readonly ratchettree_to_bytes: (a: number) => [number, number];
    readonly greet: () => void;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_drop_slice: (a: number, b: number) => void;
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
