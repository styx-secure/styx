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
    clear_pending_commit(provider: Provider, expected_prior_epoch: bigint): void;
    confirm_pending_add(provider: Provider, pending: PhaseB1PendingAdd): void;
    confirm_pending_commit(provider: Provider, expected_prior_epoch: bigint): void;
    create_application_message(provider: Provider, sender: PhaseB1Identity, plaintext: Uint8Array): Uint8Array;
    static create_new(provider: Provider, founder: PhaseB1Identity, group_id: Uint8Array, founder_proof: Uint8Array): PhaseB1Group;
    discard_pending_add(provider: Provider, pending: PhaseB1PendingAdd): void;
    discard_staged_commit(provider: Provider, staged: PhaseB1StagedCommit): void;
    epoch(): bigint;
    export_ratchet_tree(): PhaseB1RatchetTree;
    group_id(): Uint8Array;
    has_pending_commit(provider: Provider): boolean;
    static join(provider: Provider, welcome_bytes: Uint8Array, ratchet_tree: PhaseB1RatchetTree): PhaseB1Group;
    static load(provider: Provider, group_id: Uint8Array): PhaseB1Group | undefined;
    matches_own_identity(account_public_key: Uint8Array, leaf_signature_key: Uint8Array): boolean;
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
    static load(provider: Provider, account_public_key: Uint8Array, leaf_signature_key: Uint8Array): PhaseB1Identity | undefined;
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

export class PhaseB2CommitProjection {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    administrator_policy(): Uint8Array;
    candidate_component_ids(index: number): Uint16Array;
    candidate_epoch(): bigint;
    candidate_group_context_sha256(): Uint8Array;
    candidate_group_context_tls(): Uint8Array;
    candidate_identity(index: number): Uint8Array;
    candidate_identity_proof(index: number): Uint8Array;
    candidate_leaf_index(index: number): number;
    candidate_member_count(): number;
    candidate_signature_key(index: number): Uint8Array;
    candidate_supported_component_ids(index: number): Uint16Array;
    committer_identity(): Uint8Array;
    committer_leaf_index(): number;
    committer_signature_key(): Uint8Array;
    committer_source(): string;
    has_update_path(): boolean;
    lifecycle(): Uint8Array;
    prior_epoch(): bigint;
    proposal_added_component_ids(index: number): Uint16Array | undefined;
    proposal_added_identity(index: number): Uint8Array | undefined;
    proposal_added_identity_proof(index: number): Uint8Array | undefined;
    proposal_added_leaf_index(index: number): number | undefined;
    proposal_added_signature_key(index: number): Uint8Array | undefined;
    proposal_added_supported_component_ids(index: number): Uint16Array | undefined;
    proposal_count(): number;
    proposal_kind(index: number): string;
    proposal_removed_identity(index: number): Uint8Array | undefined;
    proposal_removed_identity_proof(index: number): Uint8Array | undefined;
    proposal_removed_parent_leaf_index(index: number): number | undefined;
    proposal_removed_signature_key(index: number): Uint8Array | undefined;
    proposal_sender_leaf_index(index: number): number;
    proposal_sender_source(index: number): string;
    proposal_source(index: number): string;
    required_component_ids(): Uint16Array;
    update_path_component_ids(): Uint16Array | undefined;
    update_path_identity(): Uint8Array | undefined;
    update_path_identity_proof(): Uint8Array | undefined;
    update_path_leaf_index(): number | undefined;
    update_path_signature_key(): Uint8Array | undefined;
    update_path_supported_component_ids(): Uint16Array | undefined;
    verified_leaf_digest(): Uint8Array;
}

export class PhaseB2Group {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    administrator_policy(): Uint8Array;
    clear_pending_commit(provider: Provider, expected_prior_epoch: bigint, account_public_key: Uint8Array, leaf_signature_key: Uint8Array): void;
    confirm_pending(provider: Provider, pending: PhaseB2PendingCommit, verified_leaf_digest: Uint8Array): void;
    confirm_pending_commit(provider: Provider, expected_prior_epoch: bigint, account_public_key: Uint8Array, leaf_signature_key: Uint8Array, verified_leaf_digest: Uint8Array): void;
    create_application_message(provider: Provider, sender: PhaseB2Identity, plaintext: Uint8Array): Uint8Array;
    static create_new(provider: Provider, founder: PhaseB2Identity, group_id: Uint8Array, founder_proof: Uint8Array): PhaseB2Group;
    discard_pending(provider: Provider, pending: PhaseB2PendingCommit): void;
    discard_staged_commit(provider: Provider, staged: PhaseB2StagedCommit): void;
    epoch(): bigint;
    export_ratchet_tree(): PhaseB2RatchetTree;
    group_context_sha256(provider: Provider): Uint8Array;
    group_context_tls(): Uint8Array;
    group_id(): Uint8Array;
    has_pending_commit(provider: Provider): boolean;
    static join(provider: Provider, welcome_bytes: Uint8Array, ratchet_tree: PhaseB2RatchetTree): PhaseB2Group;
    lifecycle(): Uint8Array;
    static load(provider: Provider, group_id: Uint8Array): PhaseB2Group | undefined;
    matches_own_identity(account_public_key: Uint8Array, leaf_signature_key: Uint8Array): boolean;
    member_count(): number;
    member_identity(index: number): Uint8Array;
    member_identity_proof(index: number): Uint8Array;
    member_leaf_index(index: number): number;
    member_signature_key(index: number): Uint8Array;
    merge_staged_commit(provider: Provider, staged: PhaseB2StagedCommit, verified_leaf_digest: Uint8Array): void;
    pending_projection(provider: Provider): PhaseB2CommitProjection | undefined;
    prepare_add(provider: Provider, sender: PhaseB2Identity, new_member: PhaseB2KeyPackage): PhaseB2PendingCommit;
    prepare_remove(provider: Provider, sender: PhaseB2Identity, removed_leaf_index: number): PhaseB2PendingCommit;
    prepare_self_update(provider: Provider, sender: PhaseB2Identity): PhaseB2PendingCommit;
    /**
     * Legacy sender-discarding receive API. B2.7 and later must use
     * `receive_application_message` so authenticated sender evidence is not
     * lost before the durable boundary.
     */
    process_application_message(provider: Provider, bytes: Uint8Array): Uint8Array;
    receive_application_message(provider: Provider, bytes: Uint8Array): PhaseB2ReceivedApplicationMessage;
    required_component_ids(): Uint16Array;
    stage_inbound_commit(provider: Provider, bytes: Uint8Array): PhaseB2StagedCommit;
}

/**
 * Current-profile identity with an independent Ed25519 MLS signing key.
 */
export class PhaseB2Identity {
    free(): void;
    [Symbol.dispose](): void;
    account_public_key(): Uint8Array;
    b3_1_key_package(provider: Provider, proof: Uint8Array): PhaseB31KeyPackage;
    b3_2a_key_package(provider: Provider, proof: Uint8Array): PhaseB32aKeyPackage;
    key_package(provider: Provider, proof: Uint8Array): PhaseB2KeyPackage;
    leaf_signature_key(): Uint8Array;
    static load(provider: Provider, account_public_key: Uint8Array, leaf_signature_key: Uint8Array): PhaseB2Identity | undefined;
    constructor(provider: Provider, account_public_key: Uint8Array);
}

export class PhaseB2KeyPackage {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    ciphersuite_id(): number;
    component_ids(): Uint16Array;
    credential_identity(): Uint8Array;
    static from_framed_bytes(bytes: Uint8Array): PhaseB2KeyPackage;
    identity_proof(): Uint8Array;
    is_last_resort(): boolean;
    leaf_signature_key(): Uint8Array;
    supported_component_ids(): Uint16Array;
    to_framed_bytes(): Uint8Array;
}

export class PhaseB2PendingCommit {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    commit(): Uint8Array;
    is_consumed(): boolean;
    projection(): PhaseB2CommitProjection;
    welcome(): Uint8Array | undefined;
}

export class PhaseB2RatchetTree {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    static from_bytes(bytes: Uint8Array): PhaseB2RatchetTree;
    to_bytes(): Uint8Array;
}

/**
 * Closed result of the Phase B2 current-epoch application receive boundary.
 *
 * The sender fields come from the authenticated OpenMLS `ProcessedMessage`
 * and the profile-valid leaf in the same loaded group instance. They are not
 * inferred from application payload bytes.
 */
export class PhaseB2ReceivedApplicationMessage {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    epoch(): bigint;
    group_id(): Uint8Array;
    plaintext(): Uint8Array;
    sender_credential_identity(): Uint8Array;
    sender_leaf_index(): number;
    sender_signature_key(): Uint8Array;
}

export class PhaseB2StagedCommit {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    is_consumed(): boolean;
    projection(): PhaseB2CommitProjection;
}

/**
 * Isolated B3.1 proof wrapper. Product code must not reference this surface.
 */
export class PhaseB31KeyPackage {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    ciphersuite_id(): number;
    component_ids(): Uint16Array;
    credential_identity(): Uint8Array;
    static from_framed_bytes(bytes: Uint8Array): PhaseB31KeyPackage;
    identity_proof(): Uint8Array;
    is_last_resort(): boolean;
    leaf_signature_key(): Uint8Array;
    supported_component_ids(): Uint16Array;
    to_framed_bytes(): Uint8Array;
}

/**
 * Load-only B3.2 group. The experiment intentionally exposes no create, join,
 * message, Commit or update operation through this type.
 */
export class PhaseB32Group {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    epoch(): bigint;
    group_id(): Uint8Array;
    static load(provider: Provider, group_id: Uint8Array): PhaseB32Group | undefined;
    projection(provider: Provider, welcome_sender_leaf_index: number, expected_author: Uint8Array, welcome_sha256: Uint8Array, expected_key_package_sha256: Uint8Array, predecessor_state_sha256: Uint8Array, candidate_state_sha256: Uint8Array): PhaseB32JoinProjection;
}

/**
 * Canonical, immutable description of one fully validated B3.2 join candidate.
 *
 * Provider snapshot digests are deliberately instance-scoped commitments to
 * exact bytes within this operation. They are not canonical logical-state
 * identities across unrelated restores (the storage map has no stable order).
 */
export class PhaseB32JoinProjection {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    administrator_policy(): Uint8Array;
    candidate_state_sha256(): Uint8Array;
    ciphersuite_id(): number;
    domain(): string;
    epoch(): bigint;
    expected_key_package_sha256(): Uint8Array;
    group_context_sha256(): Uint8Array;
    group_context_tls(): Uint8Array;
    group_id(): Uint8Array;
    group_profile_description(): Uint8Array;
    group_profile_name(): Uint8Array;
    lifecycle(): Uint8Array;
    member_component_ids(index: number): Uint16Array;
    member_count(): number;
    member_identity(index: number): Uint8Array;
    member_identity_proof(index: number): Uint8Array;
    member_leaf_index(index: number): number;
    member_signature_key(index: number): Uint8Array;
    member_supported_component_ids(index: number): Uint16Array;
    own_leaf_index(): number;
    predecessor_state_sha256(): Uint8Array;
    projection_sha256(): Uint8Array;
    required_component_ids(): Uint16Array;
    verified_leaf_digest(): Uint8Array;
    version(): number;
    welcome_sender_identity(): Uint8Array;
    welcome_sender_leaf_index(): number;
    welcome_sender_signature_key(): Uint8Array;
    welcome_sha256(): Uint8Array;
}

/**
 * One-use capability holding exact candidate provider bytes. It never owns or
 * mutates the predecessor provider.
 */
export class PhaseB32PendingWelcome {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    discard(provider: Provider): void;
    is_consumed(): boolean;
    static prepare(provider: Provider, identity: PhaseB2Identity, welcome_bytes: Uint8Array, expected_key_package_bytes: Uint8Array, expected_author: Uint8Array): PhaseB32PendingWelcome;
    projection(): PhaseB32JoinProjection;
    release_candidate_state(provider: Provider, projection_sha256: Uint8Array, expected_author: Uint8Array): Uint8Array;
}

/**
 * Load-only B3.2a group whose Provider is private and operation-scoped.
 */
export class PhaseB32aGroup {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    canonical_state(): Uint8Array;
    epoch(): bigint;
    group_id(): Uint8Array;
    static load_canonical_state(candidate_state: Uint8Array, group_id: Uint8Array): PhaseB32aGroup | undefined;
    projection(welcome_sender_leaf_index: number, expected_author: Uint8Array, expected_own_identity: Uint8Array, expected_own_signature_key: Uint8Array, welcome_sha256: Uint8Array, expected_key_package_sha256: Uint8Array, predecessor_state_sha256: Uint8Array, candidate_state_sha256: Uint8Array): PhaseB32aJoinProjection;
}

export class PhaseB32aJoinProjection {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    administrator_policy(): Uint8Array;
    candidate_state_sha256(): Uint8Array;
    ciphersuite_id(): number;
    domain(): string;
    epoch(): bigint;
    expected_key_package_sha256(): Uint8Array;
    group_context_sha256(): Uint8Array;
    group_context_tls(): Uint8Array;
    group_id(): Uint8Array;
    group_profile_description(): Uint8Array;
    group_profile_name(): Uint8Array;
    lifecycle(): Uint8Array;
    member_component_ids(index: number): Uint16Array;
    member_count(): number;
    member_emits_empty_safe_aad(index: number): boolean;
    member_identity(index: number): Uint8Array;
    member_identity_proof(index: number): Uint8Array;
    member_leaf_index(index: number): number;
    member_lists_default_required_capabilities(index: number): boolean;
    member_profile(index: number): string;
    member_profile_sha256(index: number): Uint8Array;
    member_signature_key(index: number): Uint8Array;
    member_supported_component_ids(index: number): Uint16Array;
    own_leaf_index(): number;
    predecessor_state_sha256(): Uint8Array;
    projection_sha256(): Uint8Array;
    provider_format(): string;
    required_component_ids(): Uint16Array;
    verified_leaf_digest(): Uint8Array;
    version(): number;
    welcome_sender_identity(): Uint8Array;
    welcome_sender_leaf_index(): number;
    welcome_sender_signature_key(): Uint8Array;
    welcome_sha256(): Uint8Array;
}

/**
 * Exact Styx B3.2a KeyPackage. It is additive and does not relabel B3.1 bytes.
 */
export class PhaseB32aKeyPackage {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    capability_extension_ids(): Uint16Array;
    capability_proposal_ids(): Uint16Array;
    ciphersuite_id(): number;
    component_ids(): Uint16Array;
    credential_identity(): Uint8Array;
    static from_framed_bytes(bytes: Uint8Array): PhaseB32aKeyPackage;
    identity_proof(): Uint8Array;
    is_last_resort(): boolean;
    leaf_signature_key(): Uint8Array;
    supported_component_ids(): Uint16Array;
    to_framed_bytes(): Uint8Array;
}

/**
 * One-use B3.2a candidate. It owns no live Provider or identity handle.
 */
export class PhaseB32aPendingWelcome {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    differing_storage_key(): Uint8Array;
    discard(): void;
    is_consumed(): boolean;
    preparation_classification(): string;
    static prepare_from_durable_state(predecessor_state: Uint8Array, expected_predecessor_sha256: Uint8Array, account_identity: Uint8Array, leaf_signature_key: Uint8Array, welcome_bytes: Uint8Array, expected_key_package_bytes: Uint8Array, expected_author: Uint8Array): PhaseB32aPendingWelcome;
    projection(): PhaseB32aJoinProjection;
    release_candidate_state(projection_sha256: Uint8Array, expected_author: Uint8Array): Uint8Array;
    second_candidate_state_sha256(): Uint8Array;
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
    readonly __wbg_phaseb2commitprojection_free: (a: number, b: number) => void;
    readonly __wbg_phaseb2group_free: (a: number, b: number) => void;
    readonly __wbg_phaseb2identity_free: (a: number, b: number) => void;
    readonly __wbg_phaseb2keypackage_free: (a: number, b: number) => void;
    readonly __wbg_phaseb2pendingcommit_free: (a: number, b: number) => void;
    readonly __wbg_phaseb2ratchettree_free: (a: number, b: number) => void;
    readonly __wbg_phaseb2receivedapplicationmessage_free: (a: number, b: number) => void;
    readonly __wbg_phaseb2stagedcommit_free: (a: number, b: number) => void;
    readonly __wbg_phaseb31keypackage_free: (a: number, b: number) => void;
    readonly __wbg_phaseb32agroup_free: (a: number, b: number) => void;
    readonly __wbg_phaseb32ajoinprojection_free: (a: number, b: number) => void;
    readonly __wbg_phaseb32akeypackage_free: (a: number, b: number) => void;
    readonly __wbg_phaseb32apendingwelcome_free: (a: number, b: number) => void;
    readonly __wbg_phaseb32group_free: (a: number, b: number) => void;
    readonly __wbg_phaseb32joinprojection_free: (a: number, b: number) => void;
    readonly __wbg_phaseb32pendingwelcome_free: (a: number, b: number) => void;
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
    readonly phaseb1group_clear_pending_commit: (a: number, b: number, c: bigint) => [number, number];
    readonly phaseb1group_confirm_pending_add: (a: number, b: number, c: number) => [number, number];
    readonly phaseb1group_confirm_pending_commit: (a: number, b: number, c: bigint) => [number, number];
    readonly phaseb1group_create_application_message: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly phaseb1group_create_new: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly phaseb1group_discard_pending_add: (a: number, b: number, c: number) => [number, number];
    readonly phaseb1group_discard_staged_commit: (a: number, b: number, c: number) => [number, number];
    readonly phaseb1group_export_ratchet_tree: (a: number) => number;
    readonly phaseb1group_group_id: (a: number) => [number, number];
    readonly phaseb1group_has_pending_commit: (a: number, b: number) => [number, number, number];
    readonly phaseb1group_join: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly phaseb1group_load: (a: number, b: number, c: number) => [number, number, number];
    readonly phaseb1group_matches_own_identity: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly phaseb1group_member_count: (a: number) => number;
    readonly phaseb1group_member_identity: (a: number, b: number) => [number, number, number, number];
    readonly phaseb1group_merge_staged_commit: (a: number, b: number, c: number) => [number, number];
    readonly phaseb1group_process_application_message: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly phaseb1group_propose_and_commit_add: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly phaseb1group_stage_inbound_commit: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly phaseb1identity_account_public_key: (a: number) => [number, number];
    readonly phaseb1identity_key_package: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly phaseb1identity_leaf_signature_key: (a: number) => [number, number];
    readonly phaseb1identity_load: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
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
    readonly phaseb2commitprojection_administrator_policy: (a: number) => [number, number];
    readonly phaseb2commitprojection_candidate_component_ids: (a: number, b: number) => [number, number, number, number];
    readonly phaseb2commitprojection_candidate_epoch: (a: number) => bigint;
    readonly phaseb2commitprojection_candidate_group_context_sha256: (a: number) => [number, number];
    readonly phaseb2commitprojection_candidate_group_context_tls: (a: number) => [number, number];
    readonly phaseb2commitprojection_candidate_identity: (a: number, b: number) => [number, number, number, number];
    readonly phaseb2commitprojection_candidate_identity_proof: (a: number, b: number) => [number, number, number, number];
    readonly phaseb2commitprojection_candidate_leaf_index: (a: number, b: number) => [number, number, number];
    readonly phaseb2commitprojection_candidate_member_count: (a: number) => number;
    readonly phaseb2commitprojection_candidate_signature_key: (a: number, b: number) => [number, number, number, number];
    readonly phaseb2commitprojection_candidate_supported_component_ids: (a: number, b: number) => [number, number, number, number];
    readonly phaseb2commitprojection_committer_identity: (a: number) => [number, number];
    readonly phaseb2commitprojection_committer_leaf_index: (a: number) => number;
    readonly phaseb2commitprojection_committer_signature_key: (a: number) => [number, number];
    readonly phaseb2commitprojection_committer_source: (a: number) => [number, number];
    readonly phaseb2commitprojection_has_update_path: (a: number) => number;
    readonly phaseb2commitprojection_lifecycle: (a: number) => [number, number];
    readonly phaseb2commitprojection_prior_epoch: (a: number) => bigint;
    readonly phaseb2commitprojection_proposal_added_component_ids: (a: number, b: number) => [number, number, number, number];
    readonly phaseb2commitprojection_proposal_added_identity: (a: number, b: number) => [number, number, number, number];
    readonly phaseb2commitprojection_proposal_added_identity_proof: (a: number, b: number) => [number, number, number, number];
    readonly phaseb2commitprojection_proposal_added_leaf_index: (a: number, b: number) => [number, number, number];
    readonly phaseb2commitprojection_proposal_added_signature_key: (a: number, b: number) => [number, number, number, number];
    readonly phaseb2commitprojection_proposal_added_supported_component_ids: (a: number, b: number) => [number, number, number, number];
    readonly phaseb2commitprojection_proposal_count: (a: number) => number;
    readonly phaseb2commitprojection_proposal_kind: (a: number, b: number) => [number, number, number, number];
    readonly phaseb2commitprojection_proposal_removed_identity: (a: number, b: number) => [number, number, number, number];
    readonly phaseb2commitprojection_proposal_removed_identity_proof: (a: number, b: number) => [number, number, number, number];
    readonly phaseb2commitprojection_proposal_removed_parent_leaf_index: (a: number, b: number) => [number, number, number];
    readonly phaseb2commitprojection_proposal_removed_signature_key: (a: number, b: number) => [number, number, number, number];
    readonly phaseb2commitprojection_proposal_sender_leaf_index: (a: number, b: number) => [number, number, number];
    readonly phaseb2commitprojection_proposal_sender_source: (a: number, b: number) => [number, number, number, number];
    readonly phaseb2commitprojection_proposal_source: (a: number, b: number) => [number, number, number, number];
    readonly phaseb2commitprojection_required_component_ids: (a: number) => [number, number];
    readonly phaseb2commitprojection_update_path_component_ids: (a: number) => [number, number];
    readonly phaseb2commitprojection_update_path_identity: (a: number) => [number, number];
    readonly phaseb2commitprojection_update_path_identity_proof: (a: number) => [number, number];
    readonly phaseb2commitprojection_update_path_leaf_index: (a: number) => number;
    readonly phaseb2commitprojection_update_path_signature_key: (a: number) => [number, number];
    readonly phaseb2commitprojection_update_path_supported_component_ids: (a: number) => [number, number];
    readonly phaseb2commitprojection_verified_leaf_digest: (a: number) => [number, number];
    readonly phaseb2group_administrator_policy: (a: number) => [number, number, number, number];
    readonly phaseb2group_clear_pending_commit: (a: number, b: number, c: bigint, d: number, e: number, f: number, g: number) => [number, number];
    readonly phaseb2group_confirm_pending: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly phaseb2group_confirm_pending_commit: (a: number, b: number, c: bigint, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number];
    readonly phaseb2group_create_application_message: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly phaseb2group_create_new: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly phaseb2group_discard_pending: (a: number, b: number, c: number) => [number, number];
    readonly phaseb2group_discard_staged_commit: (a: number, b: number, c: number) => [number, number];
    readonly phaseb2group_export_ratchet_tree: (a: number) => number;
    readonly phaseb2group_group_context_sha256: (a: number, b: number) => [number, number, number, number];
    readonly phaseb2group_group_context_tls: (a: number) => [number, number, number, number];
    readonly phaseb2group_group_id: (a: number) => [number, number];
    readonly phaseb2group_has_pending_commit: (a: number, b: number) => [number, number, number];
    readonly phaseb2group_join: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly phaseb2group_lifecycle: (a: number) => [number, number, number, number];
    readonly phaseb2group_load: (a: number, b: number, c: number) => [number, number, number];
    readonly phaseb2group_matches_own_identity: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly phaseb2group_member_count: (a: number) => number;
    readonly phaseb2group_member_identity: (a: number, b: number) => [number, number, number, number];
    readonly phaseb2group_member_identity_proof: (a: number, b: number) => [number, number, number, number];
    readonly phaseb2group_member_leaf_index: (a: number, b: number) => [number, number, number];
    readonly phaseb2group_member_signature_key: (a: number, b: number) => [number, number, number, number];
    readonly phaseb2group_merge_staged_commit: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly phaseb2group_pending_projection: (a: number, b: number) => [number, number, number];
    readonly phaseb2group_prepare_add: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly phaseb2group_prepare_remove: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly phaseb2group_prepare_self_update: (a: number, b: number, c: number) => [number, number, number];
    readonly phaseb2group_process_application_message: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly phaseb2group_receive_application_message: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly phaseb2group_required_component_ids: (a: number) => [number, number, number, number];
    readonly phaseb2group_stage_inbound_commit: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly phaseb2identity_account_public_key: (a: number) => [number, number];
    readonly phaseb2identity_b3_1_key_package: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly phaseb2identity_b3_2a_key_package: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly phaseb2identity_key_package: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly phaseb2identity_leaf_signature_key: (a: number) => [number, number];
    readonly phaseb2identity_load: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly phaseb2identity_new: (a: number, b: number, c: number) => [number, number, number];
    readonly phaseb2keypackage_component_ids: (a: number) => [number, number];
    readonly phaseb2keypackage_credential_identity: (a: number) => [number, number];
    readonly phaseb2keypackage_from_framed_bytes: (a: number, b: number) => [number, number, number];
    readonly phaseb2keypackage_identity_proof: (a: number) => [number, number];
    readonly phaseb2keypackage_is_last_resort: (a: number) => number;
    readonly phaseb2keypackage_leaf_signature_key: (a: number) => [number, number];
    readonly phaseb2keypackage_supported_component_ids: (a: number) => [number, number];
    readonly phaseb2keypackage_to_framed_bytes: (a: number) => [number, number, number, number];
    readonly phaseb2pendingcommit_commit: (a: number) => [number, number];
    readonly phaseb2pendingcommit_is_consumed: (a: number) => number;
    readonly phaseb2pendingcommit_projection: (a: number) => number;
    readonly phaseb2pendingcommit_welcome: (a: number) => [number, number];
    readonly phaseb2ratchettree_from_bytes: (a: number, b: number) => [number, number, number];
    readonly phaseb2ratchettree_to_bytes: (a: number) => [number, number, number, number];
    readonly phaseb2receivedapplicationmessage_group_id: (a: number) => [number, number];
    readonly phaseb2receivedapplicationmessage_plaintext: (a: number) => [number, number];
    readonly phaseb2receivedapplicationmessage_sender_credential_identity: (a: number) => [number, number];
    readonly phaseb2receivedapplicationmessage_sender_leaf_index: (a: number) => number;
    readonly phaseb2receivedapplicationmessage_sender_signature_key: (a: number) => [number, number];
    readonly phaseb2stagedcommit_projection: (a: number) => number;
    readonly phaseb31keypackage_component_ids: (a: number) => [number, number];
    readonly phaseb31keypackage_credential_identity: (a: number) => [number, number];
    readonly phaseb31keypackage_from_framed_bytes: (a: number, b: number) => [number, number, number];
    readonly phaseb31keypackage_identity_proof: (a: number) => [number, number];
    readonly phaseb31keypackage_is_last_resort: (a: number) => number;
    readonly phaseb31keypackage_leaf_signature_key: (a: number) => [number, number];
    readonly phaseb31keypackage_supported_component_ids: (a: number) => [number, number, number, number];
    readonly phaseb31keypackage_to_framed_bytes: (a: number) => [number, number, number, number];
    readonly phaseb32agroup_canonical_state: (a: number) => [number, number, number, number];
    readonly phaseb32agroup_epoch: (a: number) => bigint;
    readonly phaseb32agroup_group_id: (a: number) => [number, number];
    readonly phaseb32agroup_load_canonical_state: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly phaseb32agroup_projection: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number) => [number, number, number];
    readonly phaseb32ajoinprojection_administrator_policy: (a: number) => [number, number];
    readonly phaseb32ajoinprojection_candidate_state_sha256: (a: number) => [number, number];
    readonly phaseb32ajoinprojection_ciphersuite_id: (a: number) => number;
    readonly phaseb32ajoinprojection_domain: (a: number) => [number, number];
    readonly phaseb32ajoinprojection_expected_key_package_sha256: (a: number) => [number, number];
    readonly phaseb32ajoinprojection_group_context_sha256: (a: number) => [number, number];
    readonly phaseb32ajoinprojection_group_context_tls: (a: number) => [number, number];
    readonly phaseb32ajoinprojection_group_id: (a: number) => [number, number];
    readonly phaseb32ajoinprojection_group_profile_description: (a: number) => [number, number];
    readonly phaseb32ajoinprojection_group_profile_name: (a: number) => [number, number];
    readonly phaseb32ajoinprojection_lifecycle: (a: number) => [number, number];
    readonly phaseb32ajoinprojection_member_component_ids: (a: number, b: number) => [number, number, number, number];
    readonly phaseb32ajoinprojection_member_count: (a: number) => number;
    readonly phaseb32ajoinprojection_member_emits_empty_safe_aad: (a: number, b: number) => [number, number, number];
    readonly phaseb32ajoinprojection_member_identity: (a: number, b: number) => [number, number, number, number];
    readonly phaseb32ajoinprojection_member_identity_proof: (a: number, b: number) => [number, number, number, number];
    readonly phaseb32ajoinprojection_member_leaf_index: (a: number, b: number) => [number, number, number];
    readonly phaseb32ajoinprojection_member_lists_default_required_capabilities: (a: number, b: number) => [number, number, number];
    readonly phaseb32ajoinprojection_member_profile: (a: number, b: number) => [number, number, number, number];
    readonly phaseb32ajoinprojection_member_profile_sha256: (a: number, b: number) => [number, number, number, number];
    readonly phaseb32ajoinprojection_member_signature_key: (a: number, b: number) => [number, number, number, number];
    readonly phaseb32ajoinprojection_member_supported_component_ids: (a: number, b: number) => [number, number, number, number];
    readonly phaseb32ajoinprojection_own_leaf_index: (a: number) => number;
    readonly phaseb32ajoinprojection_predecessor_state_sha256: (a: number) => [number, number];
    readonly phaseb32ajoinprojection_projection_sha256: (a: number) => [number, number];
    readonly phaseb32ajoinprojection_provider_format: (a: number) => [number, number];
    readonly phaseb32ajoinprojection_required_component_ids: (a: number) => [number, number];
    readonly phaseb32ajoinprojection_verified_leaf_digest: (a: number) => [number, number];
    readonly phaseb32ajoinprojection_version: (a: number) => number;
    readonly phaseb32ajoinprojection_welcome_sender_identity: (a: number) => [number, number];
    readonly phaseb32ajoinprojection_welcome_sender_leaf_index: (a: number) => number;
    readonly phaseb32ajoinprojection_welcome_sender_signature_key: (a: number) => [number, number];
    readonly phaseb32ajoinprojection_welcome_sha256: (a: number) => [number, number];
    readonly phaseb32akeypackage_capability_extension_ids: (a: number) => [number, number];
    readonly phaseb32akeypackage_capability_proposal_ids: (a: number) => [number, number];
    readonly phaseb32akeypackage_component_ids: (a: number) => [number, number];
    readonly phaseb32akeypackage_credential_identity: (a: number) => [number, number];
    readonly phaseb32akeypackage_from_framed_bytes: (a: number, b: number) => [number, number, number];
    readonly phaseb32akeypackage_identity_proof: (a: number) => [number, number];
    readonly phaseb32akeypackage_is_last_resort: (a: number) => number;
    readonly phaseb32akeypackage_leaf_signature_key: (a: number) => [number, number];
    readonly phaseb32akeypackage_supported_component_ids: (a: number) => [number, number, number, number];
    readonly phaseb32akeypackage_to_framed_bytes: (a: number) => [number, number, number, number];
    readonly phaseb32apendingwelcome_differing_storage_key: (a: number) => [number, number];
    readonly phaseb32apendingwelcome_discard: (a: number) => [number, number];
    readonly phaseb32apendingwelcome_is_consumed: (a: number) => number;
    readonly phaseb32apendingwelcome_preparation_classification: (a: number) => [number, number];
    readonly phaseb32apendingwelcome_prepare_from_durable_state: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number) => [number, number, number];
    readonly phaseb32apendingwelcome_projection: (a: number) => number;
    readonly phaseb32apendingwelcome_release_candidate_state: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly phaseb32apendingwelcome_second_candidate_state_sha256: (a: number) => [number, number];
    readonly phaseb32group_group_id: (a: number) => [number, number];
    readonly phaseb32group_load: (a: number, b: number, c: number) => [number, number, number];
    readonly phaseb32group_projection: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number) => [number, number, number];
    readonly phaseb32joinprojection_administrator_policy: (a: number) => [number, number];
    readonly phaseb32joinprojection_candidate_state_sha256: (a: number) => [number, number];
    readonly phaseb32joinprojection_domain: (a: number) => [number, number];
    readonly phaseb32joinprojection_expected_key_package_sha256: (a: number) => [number, number];
    readonly phaseb32joinprojection_group_context_sha256: (a: number) => [number, number];
    readonly phaseb32joinprojection_group_context_tls: (a: number) => [number, number];
    readonly phaseb32joinprojection_group_id: (a: number) => [number, number];
    readonly phaseb32joinprojection_group_profile_description: (a: number) => [number, number];
    readonly phaseb32joinprojection_group_profile_name: (a: number) => [number, number];
    readonly phaseb32joinprojection_lifecycle: (a: number) => [number, number];
    readonly phaseb32joinprojection_member_component_ids: (a: number, b: number) => [number, number, number, number];
    readonly phaseb32joinprojection_member_count: (a: number) => number;
    readonly phaseb32joinprojection_member_identity: (a: number, b: number) => [number, number, number, number];
    readonly phaseb32joinprojection_member_identity_proof: (a: number, b: number) => [number, number, number, number];
    readonly phaseb32joinprojection_member_leaf_index: (a: number, b: number) => [number, number, number];
    readonly phaseb32joinprojection_member_signature_key: (a: number, b: number) => [number, number, number, number];
    readonly phaseb32joinprojection_member_supported_component_ids: (a: number, b: number) => [number, number, number, number];
    readonly phaseb32joinprojection_predecessor_state_sha256: (a: number) => [number, number];
    readonly phaseb32joinprojection_projection_sha256: (a: number) => [number, number];
    readonly phaseb32joinprojection_required_component_ids: (a: number) => [number, number];
    readonly phaseb32joinprojection_verified_leaf_digest: (a: number) => [number, number];
    readonly phaseb32joinprojection_welcome_sender_identity: (a: number) => [number, number];
    readonly phaseb32joinprojection_welcome_sender_signature_key: (a: number) => [number, number];
    readonly phaseb32joinprojection_welcome_sha256: (a: number) => [number, number];
    readonly phaseb32pendingwelcome_discard: (a: number, b: number) => [number, number];
    readonly phaseb32pendingwelcome_is_consumed: (a: number) => number;
    readonly phaseb32pendingwelcome_prepare: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly phaseb32pendingwelcome_projection: (a: number) => number;
    readonly phaseb32pendingwelcome_release_candidate_state: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly provider_new: () => number;
    readonly provider_restore_state: (a: number, b: number, c: number) => [number, number];
    readonly provider_serialize_state: (a: number) => [number, number];
    readonly ratchettree_from_bytes: (a: number, b: number) => [number, number, number];
    readonly ratchettree_to_bytes: (a: number) => [number, number];
    readonly phaseb1group_epoch: (a: number) => bigint;
    readonly phaseb2group_epoch: (a: number) => bigint;
    readonly phaseb2receivedapplicationmessage_epoch: (a: number) => bigint;
    readonly phaseb32ajoinprojection_epoch: (a: number) => bigint;
    readonly phaseb32group_epoch: (a: number) => bigint;
    readonly phaseb32joinprojection_epoch: (a: number) => bigint;
    readonly phaseb32joinprojection_own_leaf_index: (a: number) => number;
    readonly phaseb32joinprojection_welcome_sender_leaf_index: (a: number) => number;
    readonly phaseb32joinprojection_version: (a: number) => number;
    readonly phaseb2stagedcommit_is_consumed: (a: number) => number;
    readonly phaseb2keypackage_ciphersuite_id: (a: number) => number;
    readonly phaseb31keypackage_ciphersuite_id: (a: number) => number;
    readonly phaseb32akeypackage_ciphersuite_id: (a: number) => number;
    readonly phaseb32joinprojection_ciphersuite_id: (a: number) => number;
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
