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

/**
 * Closed, non-secret projection of a staged Commit. It deliberately exposes
 * only bounded proposal counts and public member metadata.
 */
export class PhaseB1CommitProjection {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    add_count(): number;
    added_component_ids(index: number): Uint16Array;
    added_credential_identity(index: number): Uint8Array;
    added_leaf_signature_key(index: number): Uint8Array;
    added_member_count(): number;
    added_supported_component_ids(index: number): Uint16Array;
    app_data_update_count(): number;
    app_ephemeral_count(): number;
    external_init_count(): number;
    group_context_extensions_count(): number;
    next_epoch(): bigint;
    prior_epoch(): bigint;
    psk_count(): number;
    reinit_count(): number;
    remove_count(): number;
    self_remove_count(): number;
    update_count(): number;
}

/**
 * Isolated Phase B1 group wrapper. No method on this type silently merges a
 * locally pending or remotely staged Commit.
 */
export class PhaseB1Group {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    confirm_pending_add(provider: Provider, pending: PhaseB1PendingAdd): void;
    create_application_message(provider: Provider, sender: PhaseB1Identity, plaintext: Uint8Array): Uint8Array;
    static create_new(provider: Provider, founder: PhaseB1Identity, group_id: Uint8Array, founder_proof: Uint8Array): PhaseB1Group;
    discard_pending_add(provider: Provider, pending: PhaseB1PendingAdd): void;
    discard_staged_commit(provider: Provider, staged: PhaseB1StagedCommit): void;
    epoch(): bigint;
    export_ratchet_tree(): PhaseB1RatchetTree;
    static join(provider: Provider, welcome_bytes: Uint8Array, ratchet_tree: PhaseB1RatchetTree): PhaseB1Group;
    member_count(): number;
    member_identity(index: number): Uint8Array;
    merge_staged_commit(provider: Provider, staged: PhaseB1StagedCommit): void;
    process_application_message(provider: Provider, bytes: Uint8Array): Uint8Array;
    propose_and_commit_add(provider: Provider, sender: PhaseB1Identity, new_member: PhaseB1KeyPackage): PhaseB1PendingAdd;
    stage_inbound_commit(provider: Provider, bytes: Uint8Array): PhaseB1StagedCommit;
}

/**
 * A non-product Phase B1 identity. Its 32-byte Nostr account identity is a
 * BasicCredential value; its Ed25519 MLS signing key remains independent.
 */
export class PhaseB1Identity {
    free(): void;
    [Symbol.dispose](): void;
    account_public_key(): Uint8Array;
    key_package(provider: Provider, proof: Uint8Array): PhaseB1KeyPackage;
    leaf_signature_key(): Uint8Array;
    constructor(provider: Provider, account_public_key: Uint8Array);
}

/**
 * A strictly validated, non-last-resort Phase B1 KeyPackage.
 */
export class PhaseB1KeyPackage {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    ciphersuite_id(): number;
    component_ids(): Uint16Array;
    credential_identity(): Uint8Array;
    static from_framed_bytes(bytes: Uint8Array): PhaseB1KeyPackage;
    identity_proof(): Uint8Array;
    is_last_resort(): boolean;
    leaf_signature_key(): Uint8Array;
    lifetime_seconds(): bigint;
    supported_component_ids(): Uint16Array;
    to_framed_bytes(): Uint8Array;
}

/**
 * Local Add output and single-use token for the still-pending local Commit.
 */
export class PhaseB1PendingAdd {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    commit(): Uint8Array;
    is_consumed(): boolean;
    welcome(): Uint8Array;
}

export class PhaseB1RatchetTree {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    static from_bytes(bytes: Uint8Array): PhaseB1RatchetTree;
    to_bytes(): Uint8Array;
}

/**
 * WASM-owned, opaque and single-use inbound staged Commit handle.
 */
export class PhaseB1StagedCommit {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    is_consumed(): boolean;
    projection(): PhaseB1CommitProjection;
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
    readonly __wbg_phaseb1commitprojection_free: (a: number, b: number) => void;
    readonly __wbg_phaseb1group_free: (a: number, b: number) => void;
    readonly __wbg_phaseb1identity_free: (a: number, b: number) => void;
    readonly __wbg_phaseb1keypackage_free: (a: number, b: number) => void;
    readonly __wbg_phaseb1pendingadd_free: (a: number, b: number) => void;
    readonly __wbg_phaseb1ratchettree_free: (a: number, b: number) => void;
    readonly __wbg_phaseb1stagedcommit_free: (a: number, b: number) => void;
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
    readonly phaseb1commitprojection_add_count: (a: number) => number;
    readonly phaseb1commitprojection_added_component_ids: (a: number, b: number) => [number, number, number, number];
    readonly phaseb1commitprojection_added_credential_identity: (a: number, b: number) => [number, number, number, number];
    readonly phaseb1commitprojection_added_leaf_signature_key: (a: number, b: number) => [number, number, number, number];
    readonly phaseb1commitprojection_added_member_count: (a: number) => number;
    readonly phaseb1commitprojection_added_supported_component_ids: (a: number, b: number) => [number, number, number, number];
    readonly phaseb1commitprojection_app_data_update_count: (a: number) => number;
    readonly phaseb1commitprojection_app_ephemeral_count: (a: number) => number;
    readonly phaseb1commitprojection_external_init_count: (a: number) => number;
    readonly phaseb1commitprojection_group_context_extensions_count: (a: number) => number;
    readonly phaseb1commitprojection_next_epoch: (a: number) => bigint;
    readonly phaseb1commitprojection_prior_epoch: (a: number) => bigint;
    readonly phaseb1commitprojection_psk_count: (a: number) => number;
    readonly phaseb1commitprojection_reinit_count: (a: number) => number;
    readonly phaseb1commitprojection_remove_count: (a: number) => number;
    readonly phaseb1commitprojection_self_remove_count: (a: number) => number;
    readonly phaseb1commitprojection_update_count: (a: number) => number;
    readonly phaseb1group_confirm_pending_add: (a: number, b: number, c: number) => [number, number];
    readonly phaseb1group_create_application_message: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly phaseb1group_create_new: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly phaseb1group_discard_pending_add: (a: number, b: number, c: number) => [number, number];
    readonly phaseb1group_discard_staged_commit: (a: number, b: number, c: number) => [number, number];
    readonly phaseb1group_export_ratchet_tree: (a: number) => number;
    readonly phaseb1group_join: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly phaseb1group_member_count: (a: number) => number;
    readonly phaseb1group_member_identity: (a: number, b: number) => [number, number, number, number];
    readonly phaseb1group_merge_staged_commit: (a: number, b: number, c: number) => [number, number];
    readonly phaseb1group_process_application_message: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly phaseb1group_propose_and_commit_add: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly phaseb1group_stage_inbound_commit: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly phaseb1identity_account_public_key: (a: number) => [number, number];
    readonly phaseb1identity_key_package: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly phaseb1identity_leaf_signature_key: (a: number) => [number, number];
    readonly phaseb1identity_new: (a: number, b: number, c: number) => [number, number, number];
    readonly phaseb1keypackage_ciphersuite_id: (a: number) => number;
    readonly phaseb1keypackage_component_ids: (a: number) => [number, number];
    readonly phaseb1keypackage_credential_identity: (a: number) => [number, number];
    readonly phaseb1keypackage_from_framed_bytes: (a: number, b: number) => [number, number, number];
    readonly phaseb1keypackage_identity_proof: (a: number) => [number, number];
    readonly phaseb1keypackage_is_last_resort: (a: number) => number;
    readonly phaseb1keypackage_leaf_signature_key: (a: number) => [number, number];
    readonly phaseb1keypackage_lifetime_seconds: (a: number) => bigint;
    readonly phaseb1keypackage_supported_component_ids: (a: number) => [number, number];
    readonly phaseb1keypackage_to_framed_bytes: (a: number) => [number, number, number, number];
    readonly phaseb1pendingadd_commit: (a: number) => [number, number];
    readonly phaseb1pendingadd_is_consumed: (a: number) => number;
    readonly phaseb1pendingadd_welcome: (a: number) => [number, number];
    readonly phaseb1ratchettree_from_bytes: (a: number, b: number) => [number, number, number];
    readonly phaseb1ratchettree_to_bytes: (a: number) => [number, number, number, number];
    readonly phaseb1stagedcommit_is_consumed: (a: number) => number;
    readonly phaseb1stagedcommit_projection: (a: number) => number;
    readonly provider_new: () => number;
    readonly provider_restore_state: (a: number, b: number, c: number) => [number, number];
    readonly provider_serialize_state: (a: number) => [number, number];
    readonly ratchettree_from_bytes: (a: number, b: number) => [number, number, number];
    readonly ratchettree_to_bytes: (a: number) => [number, number];
    readonly phaseb1group_epoch: (a: number) => bigint;
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
