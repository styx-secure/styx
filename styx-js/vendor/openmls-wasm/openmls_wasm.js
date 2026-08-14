/* @ts-self-types="./openmls_wasm.d.ts" */

export class AddMessages {
    static __wrap(ptr) {
        const obj = Object.create(AddMessages.prototype);
        obj.__wbg_ptr = ptr;
        AddMessagesFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        AddMessagesFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_addmessages_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    get commit() {
        const ret = wasm.addmessages_commit(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Uint8Array}
     */
    get proposal() {
        const ret = wasm.addmessages_proposal(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Uint8Array}
     */
    get welcome() {
        const ret = wasm.addmessages_welcome(this.__wbg_ptr);
        return ret;
    }
}
if (Symbol.dispose) AddMessages.prototype[Symbol.dispose] = AddMessages.prototype.free;

export class Group {
    static __wrap(ptr) {
        const obj = Object.create(Group.prototype);
        obj.__wbg_ptr = ptr;
        GroupFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        GroupFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_group_free(ptr, 0);
    }
    /**
     * @param {Provider} provider
     * @param {Identity} sender
     * @param {Uint8Array} msg
     * @returns {Uint8Array}
     */
    create_message(provider, sender, msg) {
        _assertClass(provider, Provider);
        _assertClass(sender, Identity);
        const ptr0 = passArray8ToWasm0(msg, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.group_create_message(this.__wbg_ptr, provider.__wbg_ptr, sender.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * @param {Provider} provider
     * @param {Identity} founder
     * @param {string} group_id
     * @returns {Group}
     */
    static create_new(provider, founder, group_id) {
        _assertClass(provider, Provider);
        _assertClass(founder, Identity);
        const ptr0 = passStringToWasm0(group_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.group_create_new(provider.__wbg_ptr, founder.__wbg_ptr, ptr0, len0);
        return Group.__wrap(ret);
    }
    /**
     * @param {Provider} provider
     * @param {string} label
     * @param {Uint8Array} context
     * @param {number} key_length
     * @returns {Uint8Array}
     */
    export_key(provider, label, context, key_length) {
        _assertClass(provider, Provider);
        const ptr0 = passStringToWasm0(label, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.group_export_key(this.__wbg_ptr, provider.__wbg_ptr, ptr0, len0, ptr1, len1, key_length);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v3;
    }
    /**
     * @returns {RatchetTree}
     */
    export_ratchet_tree() {
        const ret = wasm.group_export_ratchet_tree(this.__wbg_ptr);
        return RatchetTree.__wrap(ret);
    }
    /**
     * @param {Provider} provider
     * @param {Uint8Array} welcome
     * @param {RatchetTree} ratchet_tree
     * @returns {Group}
     */
    static join(provider, welcome, ratchet_tree) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(welcome, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        _assertClass(ratchet_tree, RatchetTree);
        var ptr1 = ratchet_tree.__destroy_into_raw();
        const ret = wasm.group_join(provider.__wbg_ptr, ptr0, len0, ptr1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Group.__wrap(ret[0]);
    }
    /**
     * Reload a group previously persisted in the provider's storage.
     * Returns undefined if no group with that id exists.
     * @param {Provider} provider
     * @param {string} group_id
     * @returns {Group | undefined}
     */
    static load(provider, group_id) {
        _assertClass(provider, Provider);
        const ptr0 = passStringToWasm0(group_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.group_load(provider.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] === 0 ? undefined : Group.__wrap(ret[0]);
    }
    /**
     * The identity string of every current group member — the BasicCredential's
     * serialized identity, which Styx sets to the member's Nostr pubkey hex.
     *
     * This is what lets the app bind an MLS member to a transport identity: a peer
     * who hands us a group built for somebody else can be detected and rejected.
     * @returns {string[]}
     */
    member_identities() {
        const ret = wasm.group_member_identities(this.__wbg_ptr);
        var v1 = getArrayJsValueFromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
        return v1;
    }
    /**
     * @param {Provider} provider
     */
    merge_pending_commit(provider) {
        _assertClass(provider, Provider);
        const ret = wasm.group_merge_pending_commit(this.__wbg_ptr, provider.__wbg_ptr);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {Provider} provider
     * @param {Uint8Array} msg
     * @returns {Uint8Array}
     */
    process_message(provider, msg) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(msg, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.group_process_message(this.__wbg_ptr, provider.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * @param {Provider} provider
     * @param {Identity} sender
     * @param {KeyPackage} new_member
     * @returns {AddMessages}
     */
    propose_and_commit_add(provider, sender, new_member) {
        _assertClass(provider, Provider);
        _assertClass(sender, Identity);
        _assertClass(new_member, KeyPackage);
        const ret = wasm.group_propose_and_commit_add(this.__wbg_ptr, provider.__wbg_ptr, sender.__wbg_ptr, new_member.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return AddMessages.__wrap(ret[0]);
    }
}
if (Symbol.dispose) Group.prototype[Symbol.dispose] = Group.prototype.free;

export class Identity {
    static __wrap(ptr) {
        const obj = Object.create(Identity.prototype);
        obj.__wbg_ptr = ptr;
        IdentityFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        IdentityFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_identity_free(ptr, 0);
    }
    /**
     * @param {Provider} provider
     * @returns {KeyPackage}
     */
    key_package(provider) {
        _assertClass(provider, Provider);
        const ret = wasm.identity_key_package(this.__wbg_ptr, provider.__wbg_ptr);
        return KeyPackage.__wrap(ret);
    }
    /**
     * Reload an identity whose signature keypair was previously persisted in
     * the provider storage (restored via `Provider.restore_state`).
     * @param {Provider} provider
     * @param {string} name
     * @param {Uint8Array} public_key
     * @returns {Identity | undefined}
     */
    static load(provider, name, public_key) {
        _assertClass(provider, Provider);
        const ptr0 = passStringToWasm0(name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(public_key, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.identity_load(provider.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] === 0 ? undefined : Identity.__wrap(ret[0]);
    }
    /**
     * @param {Provider} provider
     * @param {string} name
     */
    constructor(provider, name) {
        _assertClass(provider, Provider);
        const ptr0 = passStringToWasm0(name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.identity_new(provider.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0];
        IdentityFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * The MLS signature public key, to be persisted so the identity can be
     * reloaded after a page refresh via `Identity.load`.
     * @returns {Uint8Array}
     */
    public_key() {
        const ret = wasm.identity_public_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) Identity.prototype[Symbol.dispose] = Identity.prototype.free;

export class KeyPackage {
    static __wrap(ptr) {
        const obj = Object.create(KeyPackage.prototype);
        obj.__wbg_ptr = ptr;
        KeyPackageFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        KeyPackageFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_keypackage_free(ptr, 0);
    }
    /**
     * Deserialize a KeyPackage from bytes
     * @param {Uint8Array} bytes
     * @returns {KeyPackage}
     */
    static from_bytes(bytes) {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.keypackage_from_bytes(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return KeyPackage.__wrap(ret[0]);
    }
    /**
     * Serialize this KeyPackage to bytes
     * @returns {Uint8Array}
     */
    to_bytes() {
        const ret = wasm.keypackage_to_bytes(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) KeyPackage.prototype[Symbol.dispose] = KeyPackage.prototype.free;

export class NoWelcomeError {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        NoWelcomeErrorFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_nowelcomeerror_free(ptr, 0);
    }
}
if (Symbol.dispose) NoWelcomeError.prototype[Symbol.dispose] = NoWelcomeError.prototype.free;

/**
 * Closed, non-secret projection of a staged Commit. It deliberately exposes
 * only bounded proposal counts and public member metadata.
 */
export class PhaseB1CommitProjection {
    static __wrap(ptr) {
        const obj = Object.create(PhaseB1CommitProjection.prototype);
        obj.__wbg_ptr = ptr;
        PhaseB1CommitProjectionFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PhaseB1CommitProjectionFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_phaseb1commitprojection_free(ptr, 0);
    }
    /**
     * @returns {number}
     */
    add_count() {
        const ret = wasm.phaseb1commitprojection_add_count(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @param {number} index
     * @returns {Uint16Array}
     */
    added_component_ids(index) {
        const ret = wasm.phaseb1commitprojection_added_component_ids(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU16FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 2, 2);
        return v1;
    }
    /**
     * @param {number} index
     * @returns {Uint8Array}
     */
    added_credential_identity(index) {
        const ret = wasm.phaseb1commitprojection_added_credential_identity(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {number} index
     * @returns {Uint8Array}
     */
    added_leaf_signature_key(index) {
        const ret = wasm.phaseb1commitprojection_added_leaf_signature_key(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {number}
     */
    added_member_count() {
        const ret = wasm.phaseb1commitprojection_added_member_count(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @param {number} index
     * @returns {Uint16Array}
     */
    added_supported_component_ids(index) {
        const ret = wasm.phaseb1commitprojection_added_supported_component_ids(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU16FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 2, 2);
        return v1;
    }
    /**
     * @returns {number}
     */
    app_data_update_count() {
        const ret = wasm.phaseb1commitprojection_app_data_update_count(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {number}
     */
    app_ephemeral_count() {
        const ret = wasm.phaseb1commitprojection_app_ephemeral_count(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {number}
     */
    external_init_count() {
        const ret = wasm.phaseb1commitprojection_external_init_count(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {number}
     */
    group_context_extensions_count() {
        const ret = wasm.phaseb1commitprojection_group_context_extensions_count(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {bigint}
     */
    next_epoch() {
        const ret = wasm.phaseb1commitprojection_next_epoch(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * @returns {bigint}
     */
    prior_epoch() {
        const ret = wasm.phaseb1commitprojection_prior_epoch(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * @returns {number}
     */
    psk_count() {
        const ret = wasm.phaseb1commitprojection_psk_count(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {number}
     */
    reinit_count() {
        const ret = wasm.phaseb1commitprojection_reinit_count(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {number}
     */
    remove_count() {
        const ret = wasm.phaseb1commitprojection_remove_count(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {number}
     */
    self_remove_count() {
        const ret = wasm.phaseb1commitprojection_self_remove_count(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {number}
     */
    update_count() {
        const ret = wasm.phaseb1commitprojection_update_count(this.__wbg_ptr);
        return ret >>> 0;
    }
}
if (Symbol.dispose) PhaseB1CommitProjection.prototype[Symbol.dispose] = PhaseB1CommitProjection.prototype.free;

/**
 * Isolated Phase B1 group wrapper. No method on this type silently merges a
 * locally pending or remotely staged Commit.
 */
export class PhaseB1Group {
    static __wrap(ptr) {
        const obj = Object.create(PhaseB1Group.prototype);
        obj.__wbg_ptr = ptr;
        PhaseB1GroupFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PhaseB1GroupFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_phaseb1group_free(ptr, 0);
    }
    /**
     * @param {Provider} provider
     * @param {bigint} expected_prior_epoch
     */
    clear_pending_commit(provider, expected_prior_epoch) {
        _assertClass(provider, Provider);
        const ret = wasm.phaseb1group_clear_pending_commit(this.__wbg_ptr, provider.__wbg_ptr, expected_prior_epoch);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {Provider} provider
     * @param {PhaseB1PendingAdd} pending
     */
    confirm_pending_add(provider, pending) {
        _assertClass(provider, Provider);
        _assertClass(pending, PhaseB1PendingAdd);
        const ret = wasm.phaseb1group_confirm_pending_add(this.__wbg_ptr, provider.__wbg_ptr, pending.__wbg_ptr);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {Provider} provider
     * @param {bigint} expected_prior_epoch
     */
    confirm_pending_commit(provider, expected_prior_epoch) {
        _assertClass(provider, Provider);
        const ret = wasm.phaseb1group_confirm_pending_commit(this.__wbg_ptr, provider.__wbg_ptr, expected_prior_epoch);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {Provider} provider
     * @param {PhaseB1Identity} sender
     * @param {Uint8Array} plaintext
     * @returns {Uint8Array}
     */
    create_application_message(provider, sender, plaintext) {
        _assertClass(provider, Provider);
        _assertClass(sender, PhaseB1Identity);
        const ptr0 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb1group_create_application_message(this.__wbg_ptr, provider.__wbg_ptr, sender.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * @param {Provider} provider
     * @param {PhaseB1Identity} founder
     * @param {Uint8Array} group_id
     * @param {Uint8Array} founder_proof
     * @returns {PhaseB1Group}
     */
    static create_new(provider, founder, group_id, founder_proof) {
        _assertClass(provider, Provider);
        _assertClass(founder, PhaseB1Identity);
        const ptr0 = passArray8ToWasm0(group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(founder_proof, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb1group_create_new(provider.__wbg_ptr, founder.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PhaseB1Group.__wrap(ret[0]);
    }
    /**
     * @param {Provider} provider
     * @param {PhaseB1PendingAdd} pending
     */
    discard_pending_add(provider, pending) {
        _assertClass(provider, Provider);
        _assertClass(pending, PhaseB1PendingAdd);
        const ret = wasm.phaseb1group_discard_pending_add(this.__wbg_ptr, provider.__wbg_ptr, pending.__wbg_ptr);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {Provider} provider
     * @param {PhaseB1StagedCommit} staged
     */
    discard_staged_commit(provider, staged) {
        _assertClass(provider, Provider);
        _assertClass(staged, PhaseB1StagedCommit);
        const ret = wasm.phaseb1group_discard_staged_commit(this.__wbg_ptr, provider.__wbg_ptr, staged.__wbg_ptr);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @returns {bigint}
     */
    epoch() {
        const ret = wasm.phaseb1group_epoch(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * @returns {PhaseB1RatchetTree}
     */
    export_ratchet_tree() {
        const ret = wasm.phaseb1group_export_ratchet_tree(this.__wbg_ptr);
        return PhaseB1RatchetTree.__wrap(ret);
    }
    /**
     * @returns {Uint8Array}
     */
    group_id() {
        const ret = wasm.phaseb1group_group_id(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Provider} provider
     * @returns {boolean}
     */
    has_pending_commit(provider) {
        _assertClass(provider, Provider);
        const ret = wasm.phaseb1group_has_pending_commit(this.__wbg_ptr, provider.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * @param {Provider} provider
     * @param {Uint8Array} welcome_bytes
     * @param {PhaseB1RatchetTree} ratchet_tree
     * @returns {PhaseB1Group}
     */
    static join(provider, welcome_bytes, ratchet_tree) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(welcome_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        _assertClass(ratchet_tree, PhaseB1RatchetTree);
        var ptr1 = ratchet_tree.__destroy_into_raw();
        const ret = wasm.phaseb1group_join(provider.__wbg_ptr, ptr0, len0, ptr1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PhaseB1Group.__wrap(ret[0]);
    }
    /**
     * @param {Provider} provider
     * @param {Uint8Array} group_id
     * @returns {PhaseB1Group | undefined}
     */
    static load(provider, group_id) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb1group_load(provider.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] === 0 ? undefined : PhaseB1Group.__wrap(ret[0]);
    }
    /**
     * @param {Uint8Array} account_public_key
     * @param {Uint8Array} leaf_signature_key
     * @returns {boolean}
     */
    matches_own_identity(account_public_key, leaf_signature_key) {
        const ptr0 = passArray8ToWasm0(account_public_key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(leaf_signature_key, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb1group_matches_own_identity(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * @returns {number}
     */
    member_count() {
        const ret = wasm.phaseb1group_member_count(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @param {number} index
     * @returns {Uint8Array}
     */
    member_identity(index) {
        const ret = wasm.phaseb1group_member_identity(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Provider} provider
     * @param {PhaseB1StagedCommit} staged
     */
    merge_staged_commit(provider, staged) {
        _assertClass(provider, Provider);
        _assertClass(staged, PhaseB1StagedCommit);
        const ret = wasm.phaseb1group_merge_staged_commit(this.__wbg_ptr, provider.__wbg_ptr, staged.__wbg_ptr);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {Provider} provider
     * @param {Uint8Array} bytes
     * @returns {Uint8Array}
     */
    process_application_message(provider, bytes) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb1group_process_application_message(this.__wbg_ptr, provider.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * @param {Provider} provider
     * @param {PhaseB1Identity} sender
     * @param {PhaseB1KeyPackage} new_member
     * @returns {PhaseB1PendingAdd}
     */
    propose_and_commit_add(provider, sender, new_member) {
        _assertClass(provider, Provider);
        _assertClass(sender, PhaseB1Identity);
        _assertClass(new_member, PhaseB1KeyPackage);
        const ret = wasm.phaseb1group_propose_and_commit_add(this.__wbg_ptr, provider.__wbg_ptr, sender.__wbg_ptr, new_member.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PhaseB1PendingAdd.__wrap(ret[0]);
    }
    /**
     * @param {Provider} provider
     * @param {Uint8Array} bytes
     * @returns {PhaseB1StagedCommit}
     */
    stage_inbound_commit(provider, bytes) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb1group_stage_inbound_commit(this.__wbg_ptr, provider.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PhaseB1StagedCommit.__wrap(ret[0]);
    }
}
if (Symbol.dispose) PhaseB1Group.prototype[Symbol.dispose] = PhaseB1Group.prototype.free;

/**
 * A non-product Phase B1 identity. Its 32-byte Nostr account identity is a
 * BasicCredential value; its Ed25519 MLS signing key remains independent.
 */
export class PhaseB1Identity {
    static __wrap(ptr) {
        const obj = Object.create(PhaseB1Identity.prototype);
        obj.__wbg_ptr = ptr;
        PhaseB1IdentityFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PhaseB1IdentityFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_phaseb1identity_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    account_public_key() {
        const ret = wasm.phaseb1identity_account_public_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Provider} provider
     * @param {Uint8Array} proof
     * @returns {PhaseB1KeyPackage}
     */
    key_package(provider, proof) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(proof, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb1identity_key_package(this.__wbg_ptr, provider.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PhaseB1KeyPackage.__wrap(ret[0]);
    }
    /**
     * @returns {Uint8Array}
     */
    leaf_signature_key() {
        const ret = wasm.phaseb1identity_leaf_signature_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Provider} provider
     * @param {Uint8Array} account_public_key
     * @param {Uint8Array} leaf_signature_key
     * @returns {PhaseB1Identity | undefined}
     */
    static load(provider, account_public_key, leaf_signature_key) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(account_public_key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(leaf_signature_key, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb1identity_load(provider.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] === 0 ? undefined : PhaseB1Identity.__wrap(ret[0]);
    }
    /**
     * @param {Provider} provider
     * @param {Uint8Array} account_public_key
     */
    constructor(provider, account_public_key) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(account_public_key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb1identity_new(provider.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0];
        PhaseB1IdentityFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
}
if (Symbol.dispose) PhaseB1Identity.prototype[Symbol.dispose] = PhaseB1Identity.prototype.free;

/**
 * A strictly validated, non-last-resort Phase B1 KeyPackage.
 */
export class PhaseB1KeyPackage {
    static __wrap(ptr) {
        const obj = Object.create(PhaseB1KeyPackage.prototype);
        obj.__wbg_ptr = ptr;
        PhaseB1KeyPackageFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PhaseB1KeyPackageFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_phaseb1keypackage_free(ptr, 0);
    }
    /**
     * @returns {number}
     */
    ciphersuite_id() {
        const ret = wasm.phaseb1keypackage_ciphersuite_id(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Uint16Array}
     */
    component_ids() {
        const ret = wasm.phaseb1keypackage_component_ids(this.__wbg_ptr);
        var v1 = getArrayU16FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 2, 2);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    credential_identity() {
        const ret = wasm.phaseb1keypackage_credential_identity(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Uint8Array} bytes
     * @returns {PhaseB1KeyPackage}
     */
    static from_framed_bytes(bytes) {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb1keypackage_from_framed_bytes(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PhaseB1KeyPackage.__wrap(ret[0]);
    }
    /**
     * @returns {Uint8Array}
     */
    identity_proof() {
        const ret = wasm.phaseb1keypackage_identity_proof(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {boolean}
     */
    is_last_resort() {
        const ret = wasm.phaseb1keypackage_is_last_resort(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * @returns {Uint8Array}
     */
    leaf_signature_key() {
        const ret = wasm.phaseb1keypackage_leaf_signature_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {bigint}
     */
    lifetime_seconds() {
        const ret = wasm.phaseb1keypackage_lifetime_seconds(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * @returns {Uint16Array}
     */
    supported_component_ids() {
        const ret = wasm.phaseb1keypackage_supported_component_ids(this.__wbg_ptr);
        var v1 = getArrayU16FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 2, 2);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    to_framed_bytes() {
        const ret = wasm.phaseb1keypackage_to_framed_bytes(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) PhaseB1KeyPackage.prototype[Symbol.dispose] = PhaseB1KeyPackage.prototype.free;

/**
 * Local Add output and single-use token for the still-pending local Commit.
 */
export class PhaseB1PendingAdd {
    static __wrap(ptr) {
        const obj = Object.create(PhaseB1PendingAdd.prototype);
        obj.__wbg_ptr = ptr;
        PhaseB1PendingAddFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PhaseB1PendingAddFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_phaseb1pendingadd_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    commit() {
        const ret = wasm.phaseb1pendingadd_commit(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {boolean}
     */
    is_consumed() {
        const ret = wasm.phaseb1pendingadd_is_consumed(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * @returns {Uint8Array}
     */
    welcome() {
        const ret = wasm.phaseb1pendingadd_welcome(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) PhaseB1PendingAdd.prototype[Symbol.dispose] = PhaseB1PendingAdd.prototype.free;

export class PhaseB1RatchetTree {
    static __wrap(ptr) {
        const obj = Object.create(PhaseB1RatchetTree.prototype);
        obj.__wbg_ptr = ptr;
        PhaseB1RatchetTreeFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PhaseB1RatchetTreeFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_phaseb1ratchettree_free(ptr, 0);
    }
    /**
     * @param {Uint8Array} bytes
     * @returns {PhaseB1RatchetTree}
     */
    static from_bytes(bytes) {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb1ratchettree_from_bytes(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PhaseB1RatchetTree.__wrap(ret[0]);
    }
    /**
     * @returns {Uint8Array}
     */
    to_bytes() {
        const ret = wasm.phaseb1ratchettree_to_bytes(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) PhaseB1RatchetTree.prototype[Symbol.dispose] = PhaseB1RatchetTree.prototype.free;

/**
 * WASM-owned, opaque and single-use inbound staged Commit handle.
 */
export class PhaseB1StagedCommit {
    static __wrap(ptr) {
        const obj = Object.create(PhaseB1StagedCommit.prototype);
        obj.__wbg_ptr = ptr;
        PhaseB1StagedCommitFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PhaseB1StagedCommitFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_phaseb1stagedcommit_free(ptr, 0);
    }
    /**
     * @returns {boolean}
     */
    is_consumed() {
        const ret = wasm.phaseb1stagedcommit_is_consumed(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * @returns {PhaseB1CommitProjection}
     */
    projection() {
        const ret = wasm.phaseb1stagedcommit_projection(this.__wbg_ptr);
        return PhaseB1CommitProjection.__wrap(ret);
    }
}
if (Symbol.dispose) PhaseB1StagedCommit.prototype[Symbol.dispose] = PhaseB1StagedCommit.prototype.free;

export class PhaseB2CommitProjection {
    static __wrap(ptr) {
        const obj = Object.create(PhaseB2CommitProjection.prototype);
        obj.__wbg_ptr = ptr;
        PhaseB2CommitProjectionFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PhaseB2CommitProjectionFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_phaseb2commitprojection_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    administrator_policy() {
        const ret = wasm.phaseb2commitprojection_administrator_policy(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {number} index
     * @returns {Uint16Array}
     */
    candidate_component_ids(index) {
        const ret = wasm.phaseb2commitprojection_candidate_component_ids(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU16FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 2, 2);
        return v1;
    }
    /**
     * @returns {bigint}
     */
    candidate_epoch() {
        const ret = wasm.phaseb2commitprojection_candidate_epoch(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * @returns {Uint8Array}
     */
    candidate_group_context_sha256() {
        const ret = wasm.phaseb2commitprojection_candidate_group_context_sha256(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    candidate_group_context_tls() {
        const ret = wasm.phaseb2commitprojection_candidate_group_context_tls(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {number} index
     * @returns {Uint8Array}
     */
    candidate_identity(index) {
        const ret = wasm.phaseb2commitprojection_candidate_identity(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {number} index
     * @returns {Uint8Array}
     */
    candidate_identity_proof(index) {
        const ret = wasm.phaseb2commitprojection_candidate_identity_proof(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {number} index
     * @returns {number}
     */
    candidate_leaf_index(index) {
        const ret = wasm.phaseb2commitprojection_candidate_leaf_index(this.__wbg_ptr, index);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] >>> 0;
    }
    /**
     * @returns {number}
     */
    candidate_member_count() {
        const ret = wasm.phaseb2commitprojection_candidate_member_count(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @param {number} index
     * @returns {Uint8Array}
     */
    candidate_signature_key(index) {
        const ret = wasm.phaseb2commitprojection_candidate_signature_key(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {number} index
     * @returns {Uint16Array}
     */
    candidate_supported_component_ids(index) {
        const ret = wasm.phaseb2commitprojection_candidate_supported_component_ids(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU16FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 2, 2);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    committer_identity() {
        const ret = wasm.phaseb2commitprojection_committer_identity(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {number}
     */
    committer_leaf_index() {
        const ret = wasm.phaseb2commitprojection_committer_leaf_index(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {Uint8Array}
     */
    committer_signature_key() {
        const ret = wasm.phaseb2commitprojection_committer_signature_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {string}
     */
    committer_source() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.phaseb2commitprojection_committer_source(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {boolean}
     */
    has_update_path() {
        const ret = wasm.phaseb2commitprojection_has_update_path(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * @returns {Uint8Array}
     */
    lifecycle() {
        const ret = wasm.phaseb2commitprojection_lifecycle(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {bigint}
     */
    prior_epoch() {
        const ret = wasm.phaseb2commitprojection_prior_epoch(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * @param {number} index
     * @returns {Uint16Array | undefined}
     */
    proposal_added_component_ids(index) {
        const ret = wasm.phaseb2commitprojection_proposal_added_component_ids(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU16FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 2, 2);
        }
        return v1;
    }
    /**
     * @param {number} index
     * @returns {Uint8Array | undefined}
     */
    proposal_added_identity(index) {
        const ret = wasm.phaseb2commitprojection_proposal_added_identity(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * @param {number} index
     * @returns {Uint8Array | undefined}
     */
    proposal_added_identity_proof(index) {
        const ret = wasm.phaseb2commitprojection_proposal_added_identity_proof(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * @param {number} index
     * @returns {number | undefined}
     */
    proposal_added_leaf_index(index) {
        const ret = wasm.phaseb2commitprojection_proposal_added_leaf_index(this.__wbg_ptr, index);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] === Number.MAX_SAFE_INTEGER ? undefined : ret[0];
    }
    /**
     * @param {number} index
     * @returns {Uint8Array | undefined}
     */
    proposal_added_signature_key(index) {
        const ret = wasm.phaseb2commitprojection_proposal_added_signature_key(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * @param {number} index
     * @returns {Uint16Array | undefined}
     */
    proposal_added_supported_component_ids(index) {
        const ret = wasm.phaseb2commitprojection_proposal_added_supported_component_ids(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU16FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 2, 2);
        }
        return v1;
    }
    /**
     * @returns {number}
     */
    proposal_count() {
        const ret = wasm.phaseb2commitprojection_proposal_count(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @param {number} index
     * @returns {string}
     */
    proposal_kind(index) {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.phaseb2commitprojection_proposal_kind(this.__wbg_ptr, index);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * @param {number} index
     * @returns {Uint8Array | undefined}
     */
    proposal_removed_identity(index) {
        const ret = wasm.phaseb2commitprojection_proposal_removed_identity(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * @param {number} index
     * @returns {Uint8Array | undefined}
     */
    proposal_removed_identity_proof(index) {
        const ret = wasm.phaseb2commitprojection_proposal_removed_identity_proof(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * @param {number} index
     * @returns {number | undefined}
     */
    proposal_removed_parent_leaf_index(index) {
        const ret = wasm.phaseb2commitprojection_proposal_removed_parent_leaf_index(this.__wbg_ptr, index);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] === Number.MAX_SAFE_INTEGER ? undefined : ret[0];
    }
    /**
     * @param {number} index
     * @returns {Uint8Array | undefined}
     */
    proposal_removed_signature_key(index) {
        const ret = wasm.phaseb2commitprojection_proposal_removed_signature_key(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * @param {number} index
     * @returns {number}
     */
    proposal_sender_leaf_index(index) {
        const ret = wasm.phaseb2commitprojection_proposal_sender_leaf_index(this.__wbg_ptr, index);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] >>> 0;
    }
    /**
     * @param {number} index
     * @returns {string}
     */
    proposal_sender_source(index) {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.phaseb2commitprojection_proposal_sender_source(this.__wbg_ptr, index);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * @param {number} index
     * @returns {string}
     */
    proposal_source(index) {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.phaseb2commitprojection_proposal_source(this.__wbg_ptr, index);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * @returns {Uint16Array}
     */
    required_component_ids() {
        const ret = wasm.phaseb2commitprojection_required_component_ids(this.__wbg_ptr);
        var v1 = getArrayU16FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 2, 2);
        return v1;
    }
    /**
     * @returns {Uint16Array | undefined}
     */
    update_path_component_ids() {
        const ret = wasm.phaseb2commitprojection_update_path_component_ids(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU16FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 2, 2);
        }
        return v1;
    }
    /**
     * @returns {Uint8Array | undefined}
     */
    update_path_identity() {
        const ret = wasm.phaseb2commitprojection_update_path_identity(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * @returns {Uint8Array | undefined}
     */
    update_path_identity_proof() {
        const ret = wasm.phaseb2commitprojection_update_path_identity_proof(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * @returns {number | undefined}
     */
    update_path_leaf_index() {
        const ret = wasm.phaseb2commitprojection_update_path_leaf_index(this.__wbg_ptr);
        return ret === Number.MAX_SAFE_INTEGER ? undefined : ret;
    }
    /**
     * @returns {Uint8Array | undefined}
     */
    update_path_signature_key() {
        const ret = wasm.phaseb2commitprojection_update_path_signature_key(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * @returns {Uint16Array | undefined}
     */
    update_path_supported_component_ids() {
        const ret = wasm.phaseb2commitprojection_update_path_supported_component_ids(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU16FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 2, 2);
        }
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    verified_leaf_digest() {
        const ret = wasm.phaseb2commitprojection_verified_leaf_digest(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) PhaseB2CommitProjection.prototype[Symbol.dispose] = PhaseB2CommitProjection.prototype.free;

export class PhaseB2Group {
    static __wrap(ptr) {
        const obj = Object.create(PhaseB2Group.prototype);
        obj.__wbg_ptr = ptr;
        PhaseB2GroupFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PhaseB2GroupFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_phaseb2group_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    administrator_policy() {
        const ret = wasm.phaseb2group_administrator_policy(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Provider} provider
     * @param {bigint} expected_prior_epoch
     * @param {Uint8Array} account_public_key
     * @param {Uint8Array} leaf_signature_key
     */
    clear_pending_commit(provider, expected_prior_epoch, account_public_key, leaf_signature_key) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(account_public_key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(leaf_signature_key, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb2group_clear_pending_commit(this.__wbg_ptr, provider.__wbg_ptr, expected_prior_epoch, ptr0, len0, ptr1, len1);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {Provider} provider
     * @param {PhaseB2PendingCommit} pending
     * @param {Uint8Array} verified_leaf_digest
     */
    confirm_pending(provider, pending, verified_leaf_digest) {
        _assertClass(provider, Provider);
        _assertClass(pending, PhaseB2PendingCommit);
        const ptr0 = passArray8ToWasm0(verified_leaf_digest, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb2group_confirm_pending(this.__wbg_ptr, provider.__wbg_ptr, pending.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {Provider} provider
     * @param {bigint} expected_prior_epoch
     * @param {Uint8Array} account_public_key
     * @param {Uint8Array} leaf_signature_key
     * @param {Uint8Array} verified_leaf_digest
     */
    confirm_pending_commit(provider, expected_prior_epoch, account_public_key, leaf_signature_key, verified_leaf_digest) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(account_public_key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(leaf_signature_key, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(verified_leaf_digest, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb2group_confirm_pending_commit(this.__wbg_ptr, provider.__wbg_ptr, expected_prior_epoch, ptr0, len0, ptr1, len1, ptr2, len2);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {Provider} provider
     * @param {PhaseB2Identity} sender
     * @param {Uint8Array} plaintext
     * @returns {Uint8Array}
     */
    create_application_message(provider, sender, plaintext) {
        _assertClass(provider, Provider);
        _assertClass(sender, PhaseB2Identity);
        const ptr0 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb2group_create_application_message(this.__wbg_ptr, provider.__wbg_ptr, sender.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * @param {Provider} provider
     * @param {PhaseB2Identity} founder
     * @param {Uint8Array} group_id
     * @param {Uint8Array} founder_proof
     * @returns {PhaseB2Group}
     */
    static create_new(provider, founder, group_id, founder_proof) {
        _assertClass(provider, Provider);
        _assertClass(founder, PhaseB2Identity);
        const ptr0 = passArray8ToWasm0(group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(founder_proof, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb2group_create_new(provider.__wbg_ptr, founder.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PhaseB2Group.__wrap(ret[0]);
    }
    /**
     * @param {Provider} provider
     * @param {PhaseB2PendingCommit} pending
     */
    discard_pending(provider, pending) {
        _assertClass(provider, Provider);
        _assertClass(pending, PhaseB2PendingCommit);
        const ret = wasm.phaseb2group_discard_pending(this.__wbg_ptr, provider.__wbg_ptr, pending.__wbg_ptr);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {Provider} provider
     * @param {PhaseB2StagedCommit} staged
     */
    discard_staged_commit(provider, staged) {
        _assertClass(provider, Provider);
        _assertClass(staged, PhaseB2StagedCommit);
        const ret = wasm.phaseb2group_discard_staged_commit(this.__wbg_ptr, provider.__wbg_ptr, staged.__wbg_ptr);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @returns {bigint}
     */
    epoch() {
        const ret = wasm.phaseb2group_epoch(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * @returns {PhaseB2RatchetTree}
     */
    export_ratchet_tree() {
        const ret = wasm.phaseb2group_export_ratchet_tree(this.__wbg_ptr);
        return PhaseB2RatchetTree.__wrap(ret);
    }
    /**
     * @param {Provider} provider
     * @returns {Uint8Array}
     */
    group_context_sha256(provider) {
        _assertClass(provider, Provider);
        const ret = wasm.phaseb2group_group_context_sha256(this.__wbg_ptr, provider.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    group_context_tls() {
        const ret = wasm.phaseb2group_group_context_tls(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    group_id() {
        const ret = wasm.phaseb2group_group_id(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Provider} provider
     * @returns {boolean}
     */
    has_pending_commit(provider) {
        _assertClass(provider, Provider);
        const ret = wasm.phaseb2group_has_pending_commit(this.__wbg_ptr, provider.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * @param {Provider} provider
     * @param {Uint8Array} welcome_bytes
     * @param {PhaseB2RatchetTree} ratchet_tree
     * @returns {PhaseB2Group}
     */
    static join(provider, welcome_bytes, ratchet_tree) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(welcome_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        _assertClass(ratchet_tree, PhaseB2RatchetTree);
        var ptr1 = ratchet_tree.__destroy_into_raw();
        const ret = wasm.phaseb2group_join(provider.__wbg_ptr, ptr0, len0, ptr1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PhaseB2Group.__wrap(ret[0]);
    }
    /**
     * @returns {Uint8Array}
     */
    lifecycle() {
        const ret = wasm.phaseb2group_lifecycle(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Provider} provider
     * @param {Uint8Array} group_id
     * @returns {PhaseB2Group | undefined}
     */
    static load(provider, group_id) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb2group_load(provider.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] === 0 ? undefined : PhaseB2Group.__wrap(ret[0]);
    }
    /**
     * @param {Uint8Array} account_public_key
     * @param {Uint8Array} leaf_signature_key
     * @returns {boolean}
     */
    matches_own_identity(account_public_key, leaf_signature_key) {
        const ptr0 = passArray8ToWasm0(account_public_key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(leaf_signature_key, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb2group_matches_own_identity(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * @returns {number}
     */
    member_count() {
        const ret = wasm.phaseb2group_member_count(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @param {number} index
     * @returns {Uint8Array}
     */
    member_identity(index) {
        const ret = wasm.phaseb2group_member_identity(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {number} index
     * @returns {Uint8Array}
     */
    member_identity_proof(index) {
        const ret = wasm.phaseb2group_member_identity_proof(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {number} index
     * @returns {number}
     */
    member_leaf_index(index) {
        const ret = wasm.phaseb2group_member_leaf_index(this.__wbg_ptr, index);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] >>> 0;
    }
    /**
     * @param {number} index
     * @returns {Uint8Array}
     */
    member_signature_key(index) {
        const ret = wasm.phaseb2group_member_signature_key(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Provider} provider
     * @param {PhaseB2StagedCommit} staged
     * @param {Uint8Array} verified_leaf_digest
     */
    merge_staged_commit(provider, staged, verified_leaf_digest) {
        _assertClass(provider, Provider);
        _assertClass(staged, PhaseB2StagedCommit);
        const ptr0 = passArray8ToWasm0(verified_leaf_digest, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb2group_merge_staged_commit(this.__wbg_ptr, provider.__wbg_ptr, staged.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {Provider} provider
     * @returns {PhaseB2CommitProjection | undefined}
     */
    pending_projection(provider) {
        _assertClass(provider, Provider);
        const ret = wasm.phaseb2group_pending_projection(this.__wbg_ptr, provider.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] === 0 ? undefined : PhaseB2CommitProjection.__wrap(ret[0]);
    }
    /**
     * @param {Provider} provider
     * @param {PhaseB2Identity} sender
     * @param {PhaseB2KeyPackage} new_member
     * @returns {PhaseB2PendingCommit}
     */
    prepare_add(provider, sender, new_member) {
        _assertClass(provider, Provider);
        _assertClass(sender, PhaseB2Identity);
        _assertClass(new_member, PhaseB2KeyPackage);
        const ret = wasm.phaseb2group_prepare_add(this.__wbg_ptr, provider.__wbg_ptr, sender.__wbg_ptr, new_member.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PhaseB2PendingCommit.__wrap(ret[0]);
    }
    /**
     * @param {Provider} provider
     * @param {PhaseB2Identity} sender
     * @param {number} removed_leaf_index
     * @returns {PhaseB2PendingCommit}
     */
    prepare_remove(provider, sender, removed_leaf_index) {
        _assertClass(provider, Provider);
        _assertClass(sender, PhaseB2Identity);
        const ret = wasm.phaseb2group_prepare_remove(this.__wbg_ptr, provider.__wbg_ptr, sender.__wbg_ptr, removed_leaf_index);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PhaseB2PendingCommit.__wrap(ret[0]);
    }
    /**
     * @param {Provider} provider
     * @param {PhaseB2Identity} sender
     * @returns {PhaseB2PendingCommit}
     */
    prepare_self_update(provider, sender) {
        _assertClass(provider, Provider);
        _assertClass(sender, PhaseB2Identity);
        const ret = wasm.phaseb2group_prepare_self_update(this.__wbg_ptr, provider.__wbg_ptr, sender.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PhaseB2PendingCommit.__wrap(ret[0]);
    }
    /**
     * Legacy sender-discarding receive API. B2.7 and later must use
     * `receive_application_message` so authenticated sender evidence is not
     * lost before the durable boundary.
     * @param {Provider} provider
     * @param {Uint8Array} bytes
     * @returns {Uint8Array}
     */
    process_application_message(provider, bytes) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb2group_process_application_message(this.__wbg_ptr, provider.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * @param {Provider} provider
     * @param {Uint8Array} bytes
     * @returns {PhaseB2ReceivedApplicationMessage}
     */
    receive_application_message(provider, bytes) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb2group_receive_application_message(this.__wbg_ptr, provider.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PhaseB2ReceivedApplicationMessage.__wrap(ret[0]);
    }
    /**
     * @returns {Uint16Array}
     */
    required_component_ids() {
        const ret = wasm.phaseb2group_required_component_ids(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU16FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 2, 2);
        return v1;
    }
    /**
     * @param {Provider} provider
     * @param {Uint8Array} bytes
     * @returns {PhaseB2StagedCommit}
     */
    stage_inbound_commit(provider, bytes) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb2group_stage_inbound_commit(this.__wbg_ptr, provider.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PhaseB2StagedCommit.__wrap(ret[0]);
    }
}
if (Symbol.dispose) PhaseB2Group.prototype[Symbol.dispose] = PhaseB2Group.prototype.free;

/**
 * Current-profile identity with an independent Ed25519 MLS signing key.
 */
export class PhaseB2Identity {
    static __wrap(ptr) {
        const obj = Object.create(PhaseB2Identity.prototype);
        obj.__wbg_ptr = ptr;
        PhaseB2IdentityFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PhaseB2IdentityFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_phaseb2identity_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    account_public_key() {
        const ret = wasm.phaseb2identity_account_public_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Provider} provider
     * @param {Uint8Array} proof
     * @returns {PhaseB31KeyPackage}
     */
    b3_1_key_package(provider, proof) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(proof, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb2identity_b3_1_key_package(this.__wbg_ptr, provider.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PhaseB31KeyPackage.__wrap(ret[0]);
    }
    /**
     * @param {Provider} provider
     * @param {Uint8Array} proof
     * @returns {PhaseB2KeyPackage}
     */
    key_package(provider, proof) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(proof, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb2identity_key_package(this.__wbg_ptr, provider.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PhaseB2KeyPackage.__wrap(ret[0]);
    }
    /**
     * @returns {Uint8Array}
     */
    leaf_signature_key() {
        const ret = wasm.phaseb2identity_leaf_signature_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Provider} provider
     * @param {Uint8Array} account_public_key
     * @param {Uint8Array} leaf_signature_key
     * @returns {PhaseB2Identity | undefined}
     */
    static load(provider, account_public_key, leaf_signature_key) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(account_public_key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(leaf_signature_key, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb2identity_load(provider.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] === 0 ? undefined : PhaseB2Identity.__wrap(ret[0]);
    }
    /**
     * @param {Provider} provider
     * @param {Uint8Array} account_public_key
     */
    constructor(provider, account_public_key) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(account_public_key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb2identity_new(provider.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0];
        PhaseB2IdentityFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
}
if (Symbol.dispose) PhaseB2Identity.prototype[Symbol.dispose] = PhaseB2Identity.prototype.free;

export class PhaseB2KeyPackage {
    static __wrap(ptr) {
        const obj = Object.create(PhaseB2KeyPackage.prototype);
        obj.__wbg_ptr = ptr;
        PhaseB2KeyPackageFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PhaseB2KeyPackageFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_phaseb2keypackage_free(ptr, 0);
    }
    /**
     * @returns {number}
     */
    ciphersuite_id() {
        const ret = wasm.phaseb2keypackage_ciphersuite_id(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Uint16Array}
     */
    component_ids() {
        const ret = wasm.phaseb2keypackage_component_ids(this.__wbg_ptr);
        var v1 = getArrayU16FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 2, 2);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    credential_identity() {
        const ret = wasm.phaseb2keypackage_credential_identity(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Uint8Array} bytes
     * @returns {PhaseB2KeyPackage}
     */
    static from_framed_bytes(bytes) {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb2keypackage_from_framed_bytes(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PhaseB2KeyPackage.__wrap(ret[0]);
    }
    /**
     * @returns {Uint8Array}
     */
    identity_proof() {
        const ret = wasm.phaseb2keypackage_identity_proof(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {boolean}
     */
    is_last_resort() {
        const ret = wasm.phaseb2keypackage_is_last_resort(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * @returns {Uint8Array}
     */
    leaf_signature_key() {
        const ret = wasm.phaseb2keypackage_leaf_signature_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint16Array}
     */
    supported_component_ids() {
        const ret = wasm.phaseb2keypackage_supported_component_ids(this.__wbg_ptr);
        var v1 = getArrayU16FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 2, 2);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    to_framed_bytes() {
        const ret = wasm.phaseb2keypackage_to_framed_bytes(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) PhaseB2KeyPackage.prototype[Symbol.dispose] = PhaseB2KeyPackage.prototype.free;

export class PhaseB2PendingCommit {
    static __wrap(ptr) {
        const obj = Object.create(PhaseB2PendingCommit.prototype);
        obj.__wbg_ptr = ptr;
        PhaseB2PendingCommitFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PhaseB2PendingCommitFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_phaseb2pendingcommit_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    commit() {
        const ret = wasm.phaseb2pendingcommit_commit(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {boolean}
     */
    is_consumed() {
        const ret = wasm.phaseb2pendingcommit_is_consumed(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * @returns {PhaseB2CommitProjection}
     */
    projection() {
        const ret = wasm.phaseb2pendingcommit_projection(this.__wbg_ptr);
        return PhaseB2CommitProjection.__wrap(ret);
    }
    /**
     * @returns {Uint8Array | undefined}
     */
    welcome() {
        const ret = wasm.phaseb2pendingcommit_welcome(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
}
if (Symbol.dispose) PhaseB2PendingCommit.prototype[Symbol.dispose] = PhaseB2PendingCommit.prototype.free;

export class PhaseB2RatchetTree {
    static __wrap(ptr) {
        const obj = Object.create(PhaseB2RatchetTree.prototype);
        obj.__wbg_ptr = ptr;
        PhaseB2RatchetTreeFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PhaseB2RatchetTreeFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_phaseb2ratchettree_free(ptr, 0);
    }
    /**
     * @param {Uint8Array} bytes
     * @returns {PhaseB2RatchetTree}
     */
    static from_bytes(bytes) {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb2ratchettree_from_bytes(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PhaseB2RatchetTree.__wrap(ret[0]);
    }
    /**
     * @returns {Uint8Array}
     */
    to_bytes() {
        const ret = wasm.phaseb2ratchettree_to_bytes(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) PhaseB2RatchetTree.prototype[Symbol.dispose] = PhaseB2RatchetTree.prototype.free;

/**
 * Closed result of the Phase B2 current-epoch application receive boundary.
 *
 * The sender fields come from the authenticated OpenMLS `ProcessedMessage`
 * and the profile-valid leaf in the same loaded group instance. They are not
 * inferred from application payload bytes.
 */
export class PhaseB2ReceivedApplicationMessage {
    static __wrap(ptr) {
        const obj = Object.create(PhaseB2ReceivedApplicationMessage.prototype);
        obj.__wbg_ptr = ptr;
        PhaseB2ReceivedApplicationMessageFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PhaseB2ReceivedApplicationMessageFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_phaseb2receivedapplicationmessage_free(ptr, 0);
    }
    /**
     * @returns {bigint}
     */
    epoch() {
        const ret = wasm.phaseb2receivedapplicationmessage_epoch(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * @returns {Uint8Array}
     */
    group_id() {
        const ret = wasm.phaseb2receivedapplicationmessage_group_id(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    plaintext() {
        const ret = wasm.phaseb2receivedapplicationmessage_plaintext(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    sender_credential_identity() {
        const ret = wasm.phaseb2receivedapplicationmessage_sender_credential_identity(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {number}
     */
    sender_leaf_index() {
        const ret = wasm.phaseb2receivedapplicationmessage_sender_leaf_index(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {Uint8Array}
     */
    sender_signature_key() {
        const ret = wasm.phaseb2receivedapplicationmessage_sender_signature_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) PhaseB2ReceivedApplicationMessage.prototype[Symbol.dispose] = PhaseB2ReceivedApplicationMessage.prototype.free;

export class PhaseB2StagedCommit {
    static __wrap(ptr) {
        const obj = Object.create(PhaseB2StagedCommit.prototype);
        obj.__wbg_ptr = ptr;
        PhaseB2StagedCommitFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PhaseB2StagedCommitFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_phaseb2stagedcommit_free(ptr, 0);
    }
    /**
     * @returns {boolean}
     */
    is_consumed() {
        const ret = wasm.phaseb2stagedcommit_is_consumed(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * @returns {PhaseB2CommitProjection}
     */
    projection() {
        const ret = wasm.phaseb2stagedcommit_projection(this.__wbg_ptr);
        return PhaseB2CommitProjection.__wrap(ret);
    }
}
if (Symbol.dispose) PhaseB2StagedCommit.prototype[Symbol.dispose] = PhaseB2StagedCommit.prototype.free;

/**
 * Isolated B3.1 proof wrapper. Product code must not reference this surface.
 */
export class PhaseB31KeyPackage {
    static __wrap(ptr) {
        const obj = Object.create(PhaseB31KeyPackage.prototype);
        obj.__wbg_ptr = ptr;
        PhaseB31KeyPackageFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PhaseB31KeyPackageFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_phaseb31keypackage_free(ptr, 0);
    }
    /**
     * @returns {number}
     */
    ciphersuite_id() {
        const ret = wasm.phaseb31keypackage_ciphersuite_id(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Uint16Array}
     */
    component_ids() {
        const ret = wasm.phaseb31keypackage_component_ids(this.__wbg_ptr);
        var v1 = getArrayU16FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 2, 2);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    credential_identity() {
        const ret = wasm.phaseb31keypackage_credential_identity(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Uint8Array} bytes
     * @returns {PhaseB31KeyPackage}
     */
    static from_framed_bytes(bytes) {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb31keypackage_from_framed_bytes(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PhaseB31KeyPackage.__wrap(ret[0]);
    }
    /**
     * @returns {Uint8Array}
     */
    identity_proof() {
        const ret = wasm.phaseb31keypackage_identity_proof(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {boolean}
     */
    is_last_resort() {
        const ret = wasm.phaseb31keypackage_is_last_resort(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * @returns {Uint8Array}
     */
    leaf_signature_key() {
        const ret = wasm.phaseb31keypackage_leaf_signature_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint16Array}
     */
    supported_component_ids() {
        const ret = wasm.phaseb31keypackage_supported_component_ids(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU16FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 2, 2);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    to_framed_bytes() {
        const ret = wasm.phaseb31keypackage_to_framed_bytes(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) PhaseB31KeyPackage.prototype[Symbol.dispose] = PhaseB31KeyPackage.prototype.free;

/**
 * Load-only B3.2 group. The experiment intentionally exposes no create, join,
 * message, Commit or update operation through this type.
 */
export class PhaseB32Group {
    static __wrap(ptr) {
        const obj = Object.create(PhaseB32Group.prototype);
        obj.__wbg_ptr = ptr;
        PhaseB32GroupFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PhaseB32GroupFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_phaseb32group_free(ptr, 0);
    }
    /**
     * @returns {bigint}
     */
    epoch() {
        const ret = wasm.phaseb32group_epoch(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * @returns {Uint8Array}
     */
    group_id() {
        const ret = wasm.phaseb32group_group_id(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Provider} provider
     * @param {Uint8Array} group_id
     * @returns {PhaseB32Group | undefined}
     */
    static load(provider, group_id) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb32group_load(provider.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] === 0 ? undefined : PhaseB32Group.__wrap(ret[0]);
    }
    /**
     * @param {Provider} provider
     * @param {number} welcome_sender_leaf_index
     * @param {Uint8Array} expected_author
     * @param {Uint8Array} welcome_sha256
     * @param {Uint8Array} expected_key_package_sha256
     * @param {Uint8Array} predecessor_state_sha256
     * @param {Uint8Array} candidate_state_sha256
     * @returns {PhaseB32JoinProjection}
     */
    projection(provider, welcome_sender_leaf_index, expected_author, welcome_sha256, expected_key_package_sha256, predecessor_state_sha256, candidate_state_sha256) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(expected_author, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(welcome_sha256, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(expected_key_package_sha256, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(predecessor_state_sha256, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passArray8ToWasm0(candidate_state_sha256, wasm.__wbindgen_malloc);
        const len4 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb32group_projection(this.__wbg_ptr, provider.__wbg_ptr, welcome_sender_leaf_index, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PhaseB32JoinProjection.__wrap(ret[0]);
    }
}
if (Symbol.dispose) PhaseB32Group.prototype[Symbol.dispose] = PhaseB32Group.prototype.free;

/**
 * Canonical, immutable description of one fully validated B3.2 join candidate.
 *
 * Provider snapshot digests are deliberately instance-scoped commitments to
 * exact bytes within this operation. They are not canonical logical-state
 * identities across unrelated restores (the storage map has no stable order).
 */
export class PhaseB32JoinProjection {
    static __wrap(ptr) {
        const obj = Object.create(PhaseB32JoinProjection.prototype);
        obj.__wbg_ptr = ptr;
        PhaseB32JoinProjectionFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PhaseB32JoinProjectionFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_phaseb32joinprojection_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    administrator_policy() {
        const ret = wasm.phaseb32joinprojection_administrator_policy(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    candidate_state_sha256() {
        const ret = wasm.phaseb32joinprojection_candidate_state_sha256(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {number}
     */
    ciphersuite_id() {
        const ret = wasm.phaseb32joinprojection_ciphersuite_id(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {string}
     */
    domain() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.phaseb32joinprojection_domain(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {bigint}
     */
    epoch() {
        const ret = wasm.phaseb32joinprojection_epoch(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * @returns {Uint8Array}
     */
    expected_key_package_sha256() {
        const ret = wasm.phaseb32joinprojection_expected_key_package_sha256(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    group_context_sha256() {
        const ret = wasm.phaseb32joinprojection_group_context_sha256(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    group_context_tls() {
        const ret = wasm.phaseb32joinprojection_group_context_tls(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    group_id() {
        const ret = wasm.phaseb32joinprojection_group_id(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    group_profile_description() {
        const ret = wasm.phaseb32joinprojection_group_profile_description(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    group_profile_name() {
        const ret = wasm.phaseb32joinprojection_group_profile_name(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    lifecycle() {
        const ret = wasm.phaseb32joinprojection_lifecycle(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {number} index
     * @returns {Uint16Array}
     */
    member_component_ids(index) {
        const ret = wasm.phaseb32joinprojection_member_component_ids(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU16FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 2, 2);
        return v1;
    }
    /**
     * @returns {number}
     */
    member_count() {
        const ret = wasm.phaseb32joinprojection_member_count(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @param {number} index
     * @returns {Uint8Array}
     */
    member_identity(index) {
        const ret = wasm.phaseb32joinprojection_member_identity(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {number} index
     * @returns {Uint8Array}
     */
    member_identity_proof(index) {
        const ret = wasm.phaseb32joinprojection_member_identity_proof(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {number} index
     * @returns {number}
     */
    member_leaf_index(index) {
        const ret = wasm.phaseb32joinprojection_member_leaf_index(this.__wbg_ptr, index);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] >>> 0;
    }
    /**
     * @param {number} index
     * @returns {Uint8Array}
     */
    member_signature_key(index) {
        const ret = wasm.phaseb32joinprojection_member_signature_key(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {number} index
     * @returns {Uint16Array}
     */
    member_supported_component_ids(index) {
        const ret = wasm.phaseb32joinprojection_member_supported_component_ids(this.__wbg_ptr, index);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU16FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 2, 2);
        return v1;
    }
    /**
     * @returns {number}
     */
    own_leaf_index() {
        const ret = wasm.phaseb32joinprojection_own_leaf_index(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {Uint8Array}
     */
    predecessor_state_sha256() {
        const ret = wasm.phaseb32joinprojection_predecessor_state_sha256(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    projection_sha256() {
        const ret = wasm.phaseb32joinprojection_projection_sha256(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint16Array}
     */
    required_component_ids() {
        const ret = wasm.phaseb32joinprojection_required_component_ids(this.__wbg_ptr);
        var v1 = getArrayU16FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 2, 2);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    verified_leaf_digest() {
        const ret = wasm.phaseb32joinprojection_verified_leaf_digest(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {number}
     */
    version() {
        const ret = wasm.phaseb32joinprojection_version(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Uint8Array}
     */
    welcome_sender_identity() {
        const ret = wasm.phaseb32joinprojection_welcome_sender_identity(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {number}
     */
    welcome_sender_leaf_index() {
        const ret = wasm.phaseb32joinprojection_welcome_sender_leaf_index(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {Uint8Array}
     */
    welcome_sender_signature_key() {
        const ret = wasm.phaseb32joinprojection_welcome_sender_signature_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    welcome_sha256() {
        const ret = wasm.phaseb32joinprojection_welcome_sha256(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) PhaseB32JoinProjection.prototype[Symbol.dispose] = PhaseB32JoinProjection.prototype.free;

/**
 * One-use capability holding exact candidate provider bytes. It never owns or
 * mutates the predecessor provider.
 */
export class PhaseB32PendingWelcome {
    static __wrap(ptr) {
        const obj = Object.create(PhaseB32PendingWelcome.prototype);
        obj.__wbg_ptr = ptr;
        PhaseB32PendingWelcomeFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PhaseB32PendingWelcomeFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_phaseb32pendingwelcome_free(ptr, 0);
    }
    /**
     * @param {Provider} provider
     */
    discard(provider) {
        _assertClass(provider, Provider);
        const ret = wasm.phaseb32pendingwelcome_discard(this.__wbg_ptr, provider.__wbg_ptr);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @returns {boolean}
     */
    is_consumed() {
        const ret = wasm.phaseb32pendingwelcome_is_consumed(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * @param {Provider} provider
     * @param {PhaseB2Identity} identity
     * @param {Uint8Array} welcome_bytes
     * @param {Uint8Array} expected_key_package_bytes
     * @param {Uint8Array} expected_author
     * @returns {PhaseB32PendingWelcome}
     */
    static prepare(provider, identity, welcome_bytes, expected_key_package_bytes, expected_author) {
        _assertClass(provider, Provider);
        _assertClass(identity, PhaseB2Identity);
        const ptr0 = passArray8ToWasm0(welcome_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(expected_key_package_bytes, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(expected_author, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb32pendingwelcome_prepare(provider.__wbg_ptr, identity.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PhaseB32PendingWelcome.__wrap(ret[0]);
    }
    /**
     * @returns {PhaseB32JoinProjection}
     */
    projection() {
        const ret = wasm.phaseb32pendingwelcome_projection(this.__wbg_ptr);
        return PhaseB32JoinProjection.__wrap(ret);
    }
    /**
     * @param {Provider} provider
     * @param {Uint8Array} projection_sha256
     * @param {Uint8Array} expected_author
     * @returns {Uint8Array}
     */
    release_candidate_state(provider, projection_sha256, expected_author) {
        _assertClass(provider, Provider);
        const ptr0 = passArray8ToWasm0(projection_sha256, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(expected_author, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.phaseb32pendingwelcome_release_candidate_state(this.__wbg_ptr, provider.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v3;
    }
}
if (Symbol.dispose) PhaseB32PendingWelcome.prototype[Symbol.dispose] = PhaseB32PendingWelcome.prototype.free;

export class Provider {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        ProviderFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_provider_free(ptr, 0);
    }
    constructor() {
        const ret = wasm.provider_new();
        this.__wbg_ptr = ret;
        ProviderFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Restore storage previously produced by `serialize_state`.
     *
     * Every length is read from the input and MUST be treated as hostile: this blob
     * can be a corrupted or attacker-supplied `mls:state`. All offset arithmetic is
     * therefore checked. A naive `i + kl + vl > bytes.len()` wraps on wasm32 (usize
     * is 32-bit) and would let a crafted length slip past the bound into an
     * out-of-range slice — a panic, i.e. a trap that poisons the shared instance at
     * init. Checked arithmetic turns every such case into a returned error.
     * @param {Uint8Array} bytes
     */
    restore_state(bytes) {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.provider_restore_state(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Serialize the whole storage (all MLS group/key state) to bytes so it can
     * be persisted (e.g. in IndexedDB) and survive a page reload.
     * Format: u64 count, then per entry: u64 key_len, u64 val_len, key, val.
     * @returns {Uint8Array}
     */
    serialize_state() {
        const ret = wasm.provider_serialize_state(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) Provider.prototype[Symbol.dispose] = Provider.prototype.free;

export class RatchetTree {
    static __wrap(ptr) {
        const obj = Object.create(RatchetTree.prototype);
        obj.__wbg_ptr = ptr;
        RatchetTreeFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        RatchetTreeFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_ratchettree_free(ptr, 0);
    }
    /**
     * Deserialize a RatchetTree from bytes
     * @param {Uint8Array} bytes
     * @returns {RatchetTree}
     */
    static from_bytes(bytes) {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.ratchettree_from_bytes(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return RatchetTree.__wrap(ret[0]);
    }
    /**
     * Serialize this RatchetTree to bytes
     * @returns {Uint8Array}
     */
    to_bytes() {
        const ret = wasm.ratchettree_to_bytes(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) RatchetTree.prototype[Symbol.dispose] = RatchetTree.prototype.free;

export function greet() {
    wasm.greet();
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_92b29b0548f8b746: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg___wbindgen_is_function_1ff95bcc5517c252: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_object_a27215656b807791: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_ea5e6cc2e4141dfe: function(arg0) {
            const ret = typeof(arg0) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_c05833b95a3cf397: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_throw_344f42d3211c4765: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_alert_df37d024dc4ede3b: function(arg0, arg1) {
            alert(getStringFromWasm0(arg0, arg1));
        },
        __wbg_call_a6e5c5dce5018821: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_crypto_38df2bab126b63dc: function(arg0) {
            const ret = arg0.crypto;
            return ret;
        },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_length_1f0964f4a5e2c6d8: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_msCrypto_bd5a034af96bcba6: function(arg0) {
            const ret = arg0.msCrypto;
            return ret;
        },
        __wbg_new_cd45aabdf6073e84: function(arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        },
        __wbg_new_with_length_e6785c33c8e4cce8: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        },
        __wbg_node_84ea875411254db1: function(arg0) {
            const ret = arg0.node;
            return ret;
        },
        __wbg_now_86c0d4ba3fa605b8: function() {
            const ret = Date.now();
            return ret;
        },
        __wbg_process_44c7a14e11e9f69e: function(arg0) {
            const ret = arg0.process;
            return ret;
        },
        __wbg_prototypesetcall_4770620bbe4688a0: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_static_accessor_GLOBAL_4ef717fb391d88b7: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_THIS_8d1badc68b5a74f4: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_146583524fe1469b: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_f2829a2234d7819e: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_subarray_3ed232c8a6baee09: function(arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        },
        __wbg_versions_276b2795b1c6a219: function(arg0) {
            const ret = arg0.versions;
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./openmls_wasm_bg.js": import0,
    };
}

const AddMessagesFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_addmessages_free(ptr, 1));
const GroupFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_group_free(ptr, 1));
const IdentityFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_identity_free(ptr, 1));
const KeyPackageFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_keypackage_free(ptr, 1));
const NoWelcomeErrorFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_nowelcomeerror_free(ptr, 1));
const PhaseB1CommitProjectionFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_phaseb1commitprojection_free(ptr, 1));
const PhaseB1GroupFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_phaseb1group_free(ptr, 1));
const PhaseB1IdentityFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_phaseb1identity_free(ptr, 1));
const PhaseB1KeyPackageFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_phaseb1keypackage_free(ptr, 1));
const PhaseB1PendingAddFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_phaseb1pendingadd_free(ptr, 1));
const PhaseB1RatchetTreeFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_phaseb1ratchettree_free(ptr, 1));
const PhaseB1StagedCommitFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_phaseb1stagedcommit_free(ptr, 1));
const PhaseB2CommitProjectionFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_phaseb2commitprojection_free(ptr, 1));
const PhaseB2GroupFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_phaseb2group_free(ptr, 1));
const PhaseB2IdentityFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_phaseb2identity_free(ptr, 1));
const PhaseB2KeyPackageFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_phaseb2keypackage_free(ptr, 1));
const PhaseB2PendingCommitFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_phaseb2pendingcommit_free(ptr, 1));
const PhaseB2RatchetTreeFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_phaseb2ratchettree_free(ptr, 1));
const PhaseB2ReceivedApplicationMessageFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_phaseb2receivedapplicationmessage_free(ptr, 1));
const PhaseB2StagedCommitFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_phaseb2stagedcommit_free(ptr, 1));
const PhaseB31KeyPackageFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_phaseb31keypackage_free(ptr, 1));
const PhaseB32GroupFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_phaseb32group_free(ptr, 1));
const PhaseB32JoinProjectionFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_phaseb32joinprojection_free(ptr, 1));
const PhaseB32PendingWelcomeFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_phaseb32pendingwelcome_free(ptr, 1));
const ProviderFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_provider_free(ptr, 1));
const RatchetTreeFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_ratchettree_free(ptr, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
}

function getArrayJsValueFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    const mem = getDataViewMemory0();
    const result = [];
    for (let i = ptr; i < ptr + 4 * len; i += 4) {
        result.push(wasm.__wbindgen_externrefs.get(mem.getUint32(i, true)));
    }
    wasm.__externref_drop_slice(ptr, len);
    return result;
}

function getArrayU16FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint16ArrayMemory0().subarray(ptr / 2, ptr / 2 + len);
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    return decodeText(ptr >>> 0, len);
}

let cachedUint16ArrayMemory0 = null;
function getUint16ArrayMemory0() {
    if (cachedUint16ArrayMemory0 === null || cachedUint16ArrayMemory0.byteLength === 0) {
        cachedUint16ArrayMemory0 = new Uint16Array(wasm.memory.buffer);
    }
    return cachedUint16ArrayMemory0;
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module) {
    wasmInstance = instance;
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint16ArrayMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('openmls_wasm_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
