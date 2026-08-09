mod utils;

use std::cell::Cell;

use js_sys::Uint8Array;
use openmls::{
    credentials::{BasicCredential, CredentialWithKey},
    framing::{MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProtocolMessage},
    group::{GroupId, MlsGroup, MlsGroupJoinConfig, StagedWelcome},
    key_packages::KeyPackage as OpenMlsKeyPackage,
    prelude::SignatureScheme,
    treesync::RatchetTreeIn,
};
#[cfg(feature = "extensions-draft")]
use openmls::{
    component::ComponentId,
    extensions::{
        AppDataDictionary, AppDataDictionaryExtension, Extension, ExtensionType, Extensions,
    },
    group::StagedCommit,
    key_packages::Lifetime,
    messages::proposals::{Proposal, ProposalType},
    prelude::{Capabilities, LeafNode},
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{types::Ciphersuite, OpenMlsProvider};
use tls_codec::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);

    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

/// The ciphersuite used here. Fixed in order to reduce the binary size.
static CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

#[cfg(feature = "extensions-draft")]
static PROBE_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
#[cfg(feature = "extensions-draft")]
const ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID: ComponentId = 0x8009;
#[cfg(feature = "extensions-draft")]
const ACCOUNT_IDENTITY_PROOF_V2_LENGTH: usize = 104;
#[cfg(feature = "extensions-draft")]
const PROBE_KEY_PACKAGE_LIFETIME_SECONDS: u64 = 7 * 24 * 60 * 60;

thread_local! {
    static NEXT_PROVIDER_INSTANCE_ID: Cell<u32> = const { Cell::new(1) };
    static NEXT_GROUP_INSTANCE_ID: Cell<u32> = const { Cell::new(1) };
}

fn next_provider_instance_id() -> u32 {
    NEXT_PROVIDER_INSTANCE_ID.with(|next| {
        let id = next.get();
        next.set(id.checked_add(1).expect("provider instance id exhausted"));
        id
    })
}

#[cfg(feature = "extensions-draft")]
fn next_group_instance_id() -> u32 {
    NEXT_GROUP_INSTANCE_ID.with(|next| {
        let id = next.get();
        next.set(id.checked_add(1).expect("group instance id exhausted"));
        id
    })
}

#[wasm_bindgen]
pub struct Provider {
    inner: OpenMlsRustCrypto,
    instance_id: u32,
    restore_generation: Cell<u32>,
}

impl Default for Provider {
    fn default() -> Self {
        Self {
            inner: OpenMlsRustCrypto::default(),
            instance_id: next_provider_instance_id(),
            restore_generation: Cell::new(0),
        }
    }
}

impl AsRef<OpenMlsRustCrypto> for Provider {
    fn as_ref(&self) -> &OpenMlsRustCrypto {
        &self.inner
    }
}

impl AsMut<OpenMlsRustCrypto> for Provider {
    fn as_mut(&mut self) -> &mut OpenMlsRustCrypto {
        &mut self.inner
    }
}

#[wasm_bindgen]
impl Provider {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Serialize the whole storage (all MLS group/key state) to bytes so it can
    /// be persisted (e.g. in IndexedDB) and survive a page reload.
    /// Format: u64 count, then per entry: u64 key_len, u64 val_len, key, val.
    pub fn serialize_state(&self) -> Vec<u8> {
        let values = self.inner.storage().values.read().unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&(values.len() as u64).to_be_bytes());
        for (k, v) in values.iter() {
            out.extend_from_slice(&(k.len() as u64).to_be_bytes());
            out.extend_from_slice(&(v.len() as u64).to_be_bytes());
            out.extend_from_slice(k);
            out.extend_from_slice(v);
        }
        out
    }

    /// Restore storage previously produced by `serialize_state`.
    ///
    /// Every length is read from the input and MUST be treated as hostile: this blob
    /// can be a corrupted or attacker-supplied `mls:state`. All offset arithmetic is
    /// therefore checked. A naive `i + kl + vl > bytes.len()` wraps on wasm32 (usize
    /// is 32-bit) and would let a crafted length slip past the bound into an
    /// out-of-range slice — a panic, i.e. a trap that poisons the shared instance at
    /// init. Checked arithmetic turns every such case into a returned error.
    pub fn restore_state(&self, bytes: &[u8]) -> Result<(), JsError> {
        fn err(_: &str) -> JsError {
            // Deliberately generic: the message must not echo attacker-controlled
            // offsets or bytes into logs.
            JsError::new("restore_state: malformed state blob")
        }
        fn read_u64(bytes: &[u8], i: &mut usize) -> Result<u64, JsError> {
            let end = i.checked_add(8).filter(|&e| e <= bytes.len()).ok_or_else(|| err("len"))?;
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[*i..end]);
            *i = end;
            Ok(u64::from_be_bytes(b))
        }
        // A length that does not fit in usize (32-bit on wasm32) can never index this
        // buffer, so reject it up front rather than truncating it.
        fn as_len(n: u64) -> Result<usize, JsError> {
            usize::try_from(n).map_err(|_| err("size"))
        }
        let mut map = std::collections::HashMap::new();
        let mut i = 0usize;
        let count = read_u64(bytes, &mut i)?;
        for _ in 0..count {
            let kl = as_len(read_u64(bytes, &mut i)?)?;
            let vl = as_len(read_u64(bytes, &mut i)?)?;
            let k_end = i.checked_add(kl).filter(|&e| e <= bytes.len()).ok_or_else(|| err("k"))?;
            let k = bytes[i..k_end].to_vec();
            i = k_end;
            let v_end = i.checked_add(vl).filter(|&e| e <= bytes.len()).ok_or_else(|| err("v"))?;
            let v = bytes[i..v_end].to_vec();
            i = v_end;
            map.insert(k, v);
        }
        *self.inner.storage().values.write().unwrap() = map;
        self.restore_generation.set(
            self.restore_generation
                .get()
                .checked_add(1)
                .ok_or_else(|| JsError::new("restore_state: restore generation exhausted"))?,
        );
        Ok(())
    }
}

#[wasm_bindgen]
pub fn greet() {
    alert("Hello, openmls!");
}

#[wasm_bindgen]
pub struct Identity {
    credential_with_key: CredentialWithKey,
    keypair: openmls_basic_credential::SignatureKeyPair,
}

#[wasm_bindgen]
impl Identity {
    #[wasm_bindgen(constructor)]
    pub fn new(provider: &Provider, name: &str) -> Result<Identity, JsError> {
        let signature_scheme = SignatureScheme::ED25519;
        let identity = name.bytes().collect();
        let credential = BasicCredential::new(identity);
        let keypair = SignatureKeyPair::new(signature_scheme)?;

        keypair.store(provider.inner.storage())?;

        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: keypair.public().into(),
        };

        Ok(Identity {
            credential_with_key,
            keypair,
        })
    }

    /// The MLS signature public key, to be persisted so the identity can be
    /// reloaded after a page refresh via `Identity.load`.
    pub fn public_key(&self) -> Vec<u8> {
        self.keypair.public().to_vec()
    }

    /// Reload an identity whose signature keypair was previously persisted in
    /// the provider storage (restored via `Provider.restore_state`).
    pub fn load(
        provider: &Provider,
        name: &str,
        public_key: &[u8],
    ) -> Result<Option<Identity>, JsError> {
        match SignatureKeyPair::read(provider.inner.storage(), public_key, SignatureScheme::ED25519) {
            Some(keypair) => {
                let credential = BasicCredential::new(name.bytes().collect());
                let credential_with_key = CredentialWithKey {
                    credential: credential.into(),
                    signature_key: keypair.public().into(),
                };
                Ok(Some(Identity {
                    credential_with_key,
                    keypair,
                }))
            }
            None => Ok(None),
        }
    }

    pub fn key_package(&self, provider: &Provider) -> KeyPackage {
        KeyPackage(
            OpenMlsKeyPackage::builder()
                .build(
                    CIPHERSUITE,
                    &provider.inner,
                    &self.keypair,
                    self.credential_with_key.clone(),
                )
                .unwrap()
                .key_package()
                .clone(),
        )
    }
}

#[cfg(feature = "extensions-draft")]
#[derive(Clone)]
struct HandleBinding {
    provider_instance_id: u32,
    provider_restore_generation: u32,
    group_instance_id: u32,
    group_id: Vec<u8>,
    prior_epoch: u64,
}

#[cfg(feature = "extensions-draft")]
impl HandleBinding {
    fn validate(&self, provider: &Provider, group: &PhaseB1Group) -> Result<(), JsError> {
        if self.provider_instance_id != provider.instance_id {
            return Err(JsError::new("phase-b1 handle: wrong provider"));
        }
        if self.provider_restore_generation != provider.restore_generation.get() {
            return Err(JsError::new("phase-b1 handle: invalidated by provider restore"));
        }
        if self.group_instance_id != group.instance_id
            || self.group_id != group.mls_group.group_id().as_slice()
        {
            return Err(JsError::new("phase-b1 handle: wrong group"));
        }
        if self.prior_epoch != group.mls_group.epoch().as_u64() {
            return Err(JsError::new("phase-b1 handle: stale epoch"));
        }
        Ok(())
    }
}

#[cfg(feature = "extensions-draft")]
fn validate_probe_identity_and_proof(
    account_public_key: &[u8],
    proof: &[u8],
) -> Result<(), JsError> {
    if account_public_key.len() != 32 {
        return Err(JsError::new(
            "phase-b1 identity: account public key must be exactly 32 bytes",
        ));
    }
    if proof.len() != ACCOUNT_IDENTITY_PROOF_V2_LENGTH {
        return Err(JsError::new(
            "phase-b1 identity: proof must be exactly 104 bytes",
        ));
    }
    if proof[..32] != *account_public_key {
        return Err(JsError::new(
            "phase-b1 identity: proof signer does not match the credential identity",
        ));
    }
    Ok(())
}

#[cfg(feature = "extensions-draft")]
fn probe_capabilities() -> Capabilities {
    Capabilities::builder()
        .ciphersuites(vec![PROBE_CIPHERSUITE])
        .extensions(vec![ExtensionType::AppDataDictionary])
        .proposals(vec![ProposalType::AppDataUpdate])
        .build()
}

#[cfg(feature = "extensions-draft")]
fn probe_leaf_extensions(proof: &[u8]) -> Result<Extensions<LeafNode>, JsError> {
    if proof.len() != ACCOUNT_IDENTITY_PROOF_V2_LENGTH {
        return Err(JsError::new(
            "phase-b1 identity: proof must be exactly 104 bytes",
        ));
    }
    let app_components = vec![ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID]
        .tls_serialize_detached()
        .map_err(|_| JsError::new("phase-b1 identity: component capability encoding failed"))?;
    let mut dictionary = AppDataDictionary::new();
    dictionary.insert(1, app_components);
    dictionary.insert(ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID, proof.to_vec());
    let extension = Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary));
    Extensions::single(extension)
        .map_err(|_| JsError::new("phase-b1 identity: leaf extension construction failed"))
}

#[cfg(feature = "extensions-draft")]
fn inspect_probe_key_package(key_package: &OpenMlsKeyPackage) -> Result<(), JsError> {
    if key_package.ciphersuite() != PROBE_CIPHERSUITE {
        return Err(JsError::new("phase-b1 key package: unexpected ciphersuite"));
    }
    if key_package.last_resort() {
        return Err(JsError::new(
            "phase-b1 key package: last-resort packages are outside B1",
        ));
    }
    let leaf = key_package.leaf_node();
    let identity = leaf.credential().serialized_content();
    if identity.len() != 32 {
        return Err(JsError::new(
            "phase-b1 key package: credential identity must be exactly 32 bytes",
        ));
    }
    if leaf.signature_key().as_slice().len() != 32 {
        return Err(JsError::new(
            "phase-b1 key package: leaf signature key must be exactly 32 bytes",
        ));
    }
    if !leaf
        .capabilities()
        .extensions()
        .contains(&ExtensionType::AppDataDictionary)
        || !leaf
            .capabilities()
            .proposals()
            .contains(&ProposalType::AppDataUpdate)
    {
        return Err(JsError::new(
            "phase-b1 key package: required extension/proposal capability missing",
        ));
    }
    let dictionary = leaf
        .extensions()
        .app_data_dictionary()
        .ok_or_else(|| JsError::new("phase-b1 key package: app-data dictionary missing"))?
        .dictionary();
    if dictionary.len() != 2 {
        return Err(JsError::new(
            "phase-b1 key package: app-data dictionary must have exactly two entries",
        ));
    }
    let proof = dictionary
        .get(&ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID)
        .ok_or_else(|| JsError::new("phase-b1 key package: identity proof missing"))?;
    validate_probe_identity_and_proof(identity, proof)?;
    let app_components = dictionary
        .get(&1)
        .ok_or_else(|| JsError::new("phase-b1 key package: component capability list missing"))?;
    let supported = Vec::<u16>::tls_deserialize_exact(app_components)
        .map_err(|_| JsError::new("phase-b1 key package: malformed component capability list"))?;
    if supported != [ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID] {
        return Err(JsError::new(
            "phase-b1 key package: unexpected component capability list",
        ));
    }
    let lifetime = key_package.life_time();
    if !lifetime.has_acceptable_range()
        || lifetime.not_after().saturating_sub(lifetime.not_before())
            > PROBE_KEY_PACKAGE_LIFETIME_SECONDS + 60 * 60
    {
        return Err(JsError::new(
            "phase-b1 key package: lifetime exceeds the bounded profile",
        ));
    }
    Ok(())
}

/// A non-product Phase B1 identity. Its 32-byte Nostr account identity is a
/// BasicCredential value; its Ed25519 MLS signing key remains independent.
#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
pub struct PhaseB1Identity {
    account_public_key: Vec<u8>,
    credential_with_key: CredentialWithKey,
    keypair: SignatureKeyPair,
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB1Identity {
    #[wasm_bindgen(constructor)]
    pub fn new(provider: &Provider, account_public_key: &[u8]) -> Result<PhaseB1Identity, JsError> {
        if account_public_key.len() != 32 {
            return Err(JsError::new(
                "phase-b1 identity: account public key must be exactly 32 bytes",
            ));
        }
        let keypair = SignatureKeyPair::new(SignatureScheme::ED25519)?;
        keypair.store(provider.inner.storage())?;
        let credential = BasicCredential::new(account_public_key.to_vec());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: keypair.public().into(),
        };
        Ok(Self {
            account_public_key: account_public_key.to_vec(),
            credential_with_key,
            keypair,
        })
    }

    pub fn account_public_key(&self) -> Vec<u8> {
        self.account_public_key.clone()
    }

    pub fn leaf_signature_key(&self) -> Vec<u8> {
        self.keypair.public().to_vec()
    }

    pub fn key_package(
        &self,
        provider: &Provider,
        proof: &[u8],
    ) -> Result<PhaseB1KeyPackage, JsError> {
        validate_probe_identity_and_proof(&self.account_public_key, proof)?;
        let key_package = OpenMlsKeyPackage::builder()
            .key_package_lifetime(Lifetime::new(PROBE_KEY_PACKAGE_LIFETIME_SECONDS))
            .leaf_node_capabilities(probe_capabilities())
            .leaf_node_extensions(probe_leaf_extensions(proof)?)
            .build(
                PROBE_CIPHERSUITE,
                &provider.inner,
                &self.keypair,
                self.credential_with_key.clone(),
            )?
            .key_package()
            .clone();
        inspect_probe_key_package(&key_package)?;
        Ok(PhaseB1KeyPackage(key_package))
    }
}

/// A strictly validated, non-last-resort Phase B1 KeyPackage.
#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
pub struct PhaseB1KeyPackage(OpenMlsKeyPackage);

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB1KeyPackage {
    pub fn to_framed_bytes(&self) -> Result<Vec<u8>, JsError> {
        let framed = MlsMessageOut::from(self.0.clone());
        framed
            .tls_serialize_detached()
            .map_err(|_| JsError::new("phase-b1 key package: framing failed"))
    }

    pub fn from_framed_bytes(bytes: &[u8]) -> Result<PhaseB1KeyPackage, JsError> {
        let message = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(|_| JsError::new("phase-b1 key package: malformed MLSMessage framing"))?;
        let key_package_in = match message.extract() {
            MlsMessageBodyIn::KeyPackage(key_package) => key_package,
            _ => {
                return Err(JsError::new(
                    "phase-b1 key package: MLSMessage does not contain a KeyPackage",
                ));
            }
        };
        let key_package = key_package_in
            .validate(
                &openmls_rust_crypto::RustCrypto::default(),
                openmls::prelude::ProtocolVersion::Mls10,
            )
            .map_err(|_| JsError::new("phase-b1 key package: validation failed"))?;
        inspect_probe_key_package(&key_package)?;
        Ok(Self(key_package))
    }

    pub fn ciphersuite_id(&self) -> u16 {
        self.0.ciphersuite().into()
    }

    pub fn credential_identity(&self) -> Vec<u8> {
        self.0
            .leaf_node()
            .credential()
            .serialized_content()
            .to_vec()
    }

    pub fn leaf_signature_key(&self) -> Vec<u8> {
        self.0.leaf_node().signature_key().as_slice().to_vec()
    }

    pub fn identity_proof(&self) -> Vec<u8> {
        self.0
            .leaf_node()
            .extensions()
            .app_data_dictionary()
            .expect("validated Phase B1 KeyPackage")
            .dictionary()
            .get(&ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID)
            .expect("validated Phase B1 KeyPackage")
            .to_vec()
    }

    pub fn component_ids(&self) -> Vec<u16> {
        self.0
            .leaf_node()
            .extensions()
            .app_data_dictionary()
            .expect("validated Phase B1 KeyPackage")
            .dictionary()
            .entries()
            .map(|entry| entry.id())
            .collect()
    }

    pub fn supported_component_ids(&self) -> Vec<u16> {
        let body = self
            .0
            .leaf_node()
            .extensions()
            .app_data_dictionary()
            .expect("validated Phase B1 KeyPackage")
            .dictionary()
            .get(&1)
            .expect("validated Phase B1 KeyPackage");
        Vec::<u16>::tls_deserialize_exact(body).expect("validated Phase B1 KeyPackage")
    }

    pub fn lifetime_seconds(&self) -> u64 {
        let lifetime = self.0.life_time();
        lifetime.not_after().saturating_sub(lifetime.not_before())
    }

    pub fn is_last_resort(&self) -> bool {
        self.0.last_resort()
    }
}

#[wasm_bindgen]
pub struct Group {
    mls_group: MlsGroup,
}

#[wasm_bindgen]
pub struct AddMessages {
    proposal: Uint8Array,
    commit: Uint8Array,
    welcome: Uint8Array,
}

#[cfg(test)]
#[allow(dead_code)]
struct NativeAddMessages {
    proposal: Vec<u8>,
    commit: Vec<u8>,
    welcome: Vec<u8>,
}

#[wasm_bindgen]
impl AddMessages {
    #[wasm_bindgen(getter)]
    pub fn proposal(&self) -> Uint8Array {
        self.proposal.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Uint8Array {
        self.commit.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Uint8Array {
        self.welcome.clone()
    }
}

#[wasm_bindgen]
impl Group {
    /// Reload a group previously persisted in the provider's storage.
    /// Returns undefined if no group with that id exists.
    pub fn load(provider: &Provider, group_id: &str) -> Result<Option<Group>, JsError> {
        let group_id_bytes = group_id.bytes().collect::<Vec<_>>();
        let gid = GroupId::from_slice(&group_id_bytes);
        match MlsGroup::load(provider.inner.storage(), &gid) {
            Ok(Some(mls_group)) => Ok(Some(Group { mls_group })),
            Ok(None) => Ok(None),
            Err(e) => Err(JsError::new(&format!("Group::load failed: {e:?}"))),
        }
    }

    pub fn create_new(provider: &Provider, founder: &Identity, group_id: &str) -> Group {
        let group_id_bytes = group_id.bytes().collect::<Vec<_>>();

        let mls_group = MlsGroup::builder()
            .ciphersuite(CIPHERSUITE)
            .with_group_id(GroupId::from_slice(&group_id_bytes))
            .build(
                &provider.inner,
                &founder.keypair,
                founder.credential_with_key.clone(),
            )
            .unwrap();

        Group { mls_group }
    }
    pub fn join(
        provider: &Provider,
        mut welcome: &[u8],
        ratchet_tree: RatchetTree,
    ) -> Result<Group, JsError> {
        let welcome = match MlsMessageIn::tls_deserialize(&mut welcome)?.extract() {
            MlsMessageBodyIn::Welcome(welcome) => Ok(welcome),
            other => Err(openmls::error::ErrorString::from(format!(
                "expected a message of type welcome, got {other:?}",
            ))),
        }?;
        let config = MlsGroupJoinConfig::builder().build();
        let mls_group =
            StagedWelcome::new_from_welcome(&provider.inner, &config, welcome, Some(ratchet_tree.0))?
                .into_group(&provider.inner)?;

        Ok(Group { mls_group })
    }

    pub fn export_ratchet_tree(&self) -> RatchetTree {
        RatchetTree(self.mls_group.export_ratchet_tree().into())
    }

    pub fn propose_and_commit_add(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        new_member: &KeyPackage,
    ) -> Result<AddMessages, JsError> {
        let (proposal_msg, _proposal_ref) =
            self.mls_group
                .propose_add_member(provider.as_ref(), &sender.keypair, &new_member.0)?;

        let (commit_msg, welcome_msg, _group_info) = self
            .mls_group
            .commit_to_pending_proposals(&provider.inner, &sender.keypair)?;

        let welcome_msg = welcome_msg.ok_or(NoWelcomeError)?;

        let proposal = mls_message_to_uint8array(&proposal_msg);
        let commit = mls_message_to_uint8array(&commit_msg);
        let welcome = mls_message_to_uint8array(&welcome_msg);

        Ok(AddMessages {
            proposal,
            commit,
            welcome,
        })
    }

    pub fn merge_pending_commit(&mut self, provider: &mut Provider) -> Result<(), JsError> {
        self.mls_group
            .merge_pending_commit(provider.as_mut())
            .map_err(|e| e.into())
    }

    pub fn create_message(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        msg: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let msg_out = &self
            .mls_group
            .create_message(provider.as_ref(), &sender.keypair, msg)?;
        let mut serialized = vec![];
        msg_out.tls_serialize(&mut serialized)?;
        Ok(serialized)
    }

    pub fn process_message(
        &mut self,
        provider: &mut Provider,
        mut msg: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        // These bytes come straight off the relay: an attacker controls them. Every
        // failure here must be a returned error, never a panic — a panic traps the
        // WASM instance, and the instance (and its Provider) is shared by every
        // session in the app.
        let msg = MlsMessageIn::tls_deserialize(&mut msg)
            .map_err(|e| JsError::new(&format!("process_message: malformed MLS message: {e:?}")))?;

        let msg = match msg.extract() {
            openmls::framing::MlsMessageBodyIn::PublicMessage(msg) => {
                self.mls_group.process_message(provider.as_ref(), msg)?
            }

            openmls::framing::MlsMessageBodyIn::PrivateMessage(msg) => {
                self.mls_group.process_message(provider.as_ref(), msg)?
            }
            // Welcome / GroupInfo / KeyPackage arrive through their own entry points,
            // never through process_message. Seeing one here means the peer is
            // confused or hostile: reject it, do not trap. The body is deliberately
            // NOT formatted into the error — it would put attacker-chosen bytes into
            // logs.
            _ => {
                return Err(JsError::new(
                    "process_message: unsupported message body over the wire",
                ));
            }
        };

        match msg.into_content() {
            openmls::framing::ProcessedMessageContent::ApplicationMessage(app_msg) => {
                Ok(app_msg.into_bytes())
            }
            openmls::framing::ProcessedMessageContent::ProposalMessage(proposal)
            | openmls::framing::ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                self.mls_group
                    .store_pending_proposal(provider.inner.storage(), *proposal)?;
                Ok(vec![])
            }
            openmls::framing::ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                self.mls_group
                    .merge_staged_commit(provider.as_mut(), *staged_commit)?;
                Ok(vec![])
            }
            openmls::framing::ProcessedMessageContent::OwnPendingCommit => {
                self.mls_group.merge_pending_commit(provider.as_mut())?;
                Ok(vec![])
            }
            // Own PrivateMessages echoed by the DS cannot be decrypted, so skip
            // them.
            openmls::framing::ProcessedMessageContent::OwnPrivateMessage => Ok(vec![]),
            // Also wire-driven: a peer can send one. Reject, do not panic.
            #[cfg(feature = "extensions-draft")]
            openmls::framing::ProcessedMessageContent::UnresolvedAppDataCommit(_) => Err(
                JsError::new("process_message: AppDataUpdate proposals are not supported"),
            ),
        }
    }

    pub fn export_key(
        &self,
        provider: &Provider,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>, JsError> {
        self.mls_group
            .export_secret(provider.as_ref().crypto(), label, context, key_length)
            .map_err(|e| {
                println!("export key error: {e}");
                e.into()
            })
    }

    /// The identity string of every current group member — the BasicCredential's
    /// serialized identity, which Styx sets to the member's Nostr pubkey hex.
    ///
    /// This is what lets the app bind an MLS member to a transport identity: a peer
    /// who hands us a group built for somebody else can be detected and rejected.
    pub fn member_identities(&self) -> Vec<String> {
        self.mls_group
            .members()
            .map(|m| String::from_utf8_lossy(m.credential.serialized_content()).into_owned())
            .collect()
    }
}

#[cfg(feature = "extensions-draft")]
#[derive(Clone)]
struct ProjectedMember {
    credential_identity: Vec<u8>,
    leaf_signature_key: Vec<u8>,
    component_ids: Vec<u16>,
    supported_component_ids: Vec<u16>,
}

#[cfg(feature = "extensions-draft")]
fn project_probe_member(key_package: &OpenMlsKeyPackage) -> Result<ProjectedMember, JsError> {
    inspect_probe_key_package(key_package)?;
    let leaf = key_package.leaf_node();
    let dictionary = leaf
        .extensions()
        .app_data_dictionary()
        .expect("validated Phase B1 KeyPackage")
        .dictionary();
    let component_ids = dictionary.entries().map(|entry| entry.id()).collect();
    let supported_component_ids = Vec::<u16>::tls_deserialize_exact(
        dictionary
            .get(&1)
            .expect("validated Phase B1 KeyPackage"),
    )
    .expect("validated Phase B1 KeyPackage");
    Ok(ProjectedMember {
        credential_identity: leaf.credential().serialized_content().to_vec(),
        leaf_signature_key: leaf.signature_key().as_slice().to_vec(),
        component_ids,
        supported_component_ids,
    })
}

/// Closed, non-secret projection of a staged Commit. It deliberately exposes
/// only bounded proposal counts and public member metadata.
#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
#[derive(Clone)]
pub struct PhaseB1CommitProjection {
    prior_epoch: u64,
    next_epoch: u64,
    add_count: u32,
    update_count: u32,
    remove_count: u32,
    psk_count: u32,
    reinit_count: u32,
    external_init_count: u32,
    group_context_extensions_count: u32,
    app_data_update_count: u32,
    self_remove_count: u32,
    app_ephemeral_count: u32,
    added_members: Vec<ProjectedMember>,
}

#[cfg(feature = "extensions-draft")]
impl PhaseB1CommitProjection {
    fn from_staged(prior_epoch: u64, staged: &StagedCommit) -> Result<Self, JsError> {
        const MAX_PROJECTED_PROPOSALS: usize = 32;
        const MAX_PROJECTED_ADDS: usize = 8;

        let queued: Vec<_> = staged.queued_proposals().collect();
        if queued.len() > MAX_PROJECTED_PROPOSALS {
            return Err(JsError::new(
                "phase-b1 staged commit: proposal projection limit exceeded",
            ));
        }
        let mut projection = Self {
            prior_epoch,
            next_epoch: staged.epoch().as_u64(),
            add_count: 0,
            update_count: 0,
            remove_count: 0,
            psk_count: 0,
            reinit_count: 0,
            external_init_count: 0,
            group_context_extensions_count: 0,
            app_data_update_count: 0,
            self_remove_count: 0,
            app_ephemeral_count: 0,
            added_members: Vec::new(),
        };
        if projection.next_epoch != prior_epoch.saturating_add(1) {
            return Err(JsError::new(
                "phase-b1 staged commit: unexpected epoch transition",
            ));
        }
        for queued_proposal in queued {
            match queued_proposal.proposal() {
                Proposal::Add(add) => {
                    projection.add_count += 1;
                    if projection.added_members.len() >= MAX_PROJECTED_ADDS {
                        return Err(JsError::new(
                            "phase-b1 staged commit: added-member projection limit exceeded",
                        ));
                    }
                    projection
                        .added_members
                        .push(project_probe_member(add.key_package())?);
                }
                Proposal::Update(_) => projection.update_count += 1,
                Proposal::Remove(_) => projection.remove_count += 1,
                Proposal::PreSharedKey(_) => projection.psk_count += 1,
                Proposal::ReInit(_) => projection.reinit_count += 1,
                Proposal::ExternalInit(_) => projection.external_init_count += 1,
                Proposal::GroupContextExtensions(_) => {
                    projection.group_context_extensions_count += 1
                }
                Proposal::AppDataUpdate(_) => projection.app_data_update_count += 1,
                Proposal::SelfRemove => projection.self_remove_count += 1,
                Proposal::AppEphemeral(_) => projection.app_ephemeral_count += 1,
                Proposal::Custom(_) => {
                    return Err(JsError::new(
                        "phase-b1 staged commit: custom proposal cannot be projected",
                    ));
                }
            }
        }
        Ok(projection)
    }
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB1CommitProjection {
    pub fn prior_epoch(&self) -> u64 {
        self.prior_epoch
    }
    pub fn next_epoch(&self) -> u64 {
        self.next_epoch
    }
    pub fn add_count(&self) -> u32 {
        self.add_count
    }
    pub fn update_count(&self) -> u32 {
        self.update_count
    }
    pub fn remove_count(&self) -> u32 {
        self.remove_count
    }
    pub fn psk_count(&self) -> u32 {
        self.psk_count
    }
    pub fn reinit_count(&self) -> u32 {
        self.reinit_count
    }
    pub fn external_init_count(&self) -> u32 {
        self.external_init_count
    }
    pub fn group_context_extensions_count(&self) -> u32 {
        self.group_context_extensions_count
    }
    pub fn app_data_update_count(&self) -> u32 {
        self.app_data_update_count
    }
    pub fn self_remove_count(&self) -> u32 {
        self.self_remove_count
    }
    pub fn app_ephemeral_count(&self) -> u32 {
        self.app_ephemeral_count
    }
    pub fn added_member_count(&self) -> u32 {
        self.added_members.len() as u32
    }
    pub fn added_credential_identity(&self, index: usize) -> Result<Vec<u8>, JsError> {
        self.added_members
            .get(index)
            .map(|member| member.credential_identity.clone())
            .ok_or_else(|| JsError::new("phase-b1 projection: added member index out of range"))
    }
    pub fn added_leaf_signature_key(&self, index: usize) -> Result<Vec<u8>, JsError> {
        self.added_members
            .get(index)
            .map(|member| member.leaf_signature_key.clone())
            .ok_or_else(|| JsError::new("phase-b1 projection: added member index out of range"))
    }
    pub fn added_component_ids(&self, index: usize) -> Result<Vec<u16>, JsError> {
        self.added_members
            .get(index)
            .map(|member| member.component_ids.clone())
            .ok_or_else(|| JsError::new("phase-b1 projection: added member index out of range"))
    }
    pub fn added_supported_component_ids(&self, index: usize) -> Result<Vec<u16>, JsError> {
        self.added_members
            .get(index)
            .map(|member| member.supported_component_ids.clone())
            .ok_or_else(|| JsError::new("phase-b1 projection: added member index out of range"))
    }
}

/// WASM-owned, opaque and single-use inbound staged Commit handle.
#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
pub struct PhaseB1StagedCommit {
    binding: Option<HandleBinding>,
    staged_commit: Option<StagedCommit>,
    projection: PhaseB1CommitProjection,
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB1StagedCommit {
    pub fn projection(&self) -> PhaseB1CommitProjection {
        self.projection.clone()
    }

    pub fn is_consumed(&self) -> bool {
        self.staged_commit.is_none()
    }
}

/// Local Add output and single-use token for the still-pending local Commit.
#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
pub struct PhaseB1PendingAdd {
    binding: Option<HandleBinding>,
    commit: Vec<u8>,
    welcome: Vec<u8>,
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB1PendingAdd {
    pub fn commit(&self) -> Vec<u8> {
        self.commit.clone()
    }
    pub fn welcome(&self) -> Vec<u8> {
        self.welcome.clone()
    }
    pub fn is_consumed(&self) -> bool {
        self.binding.is_none()
    }
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
pub struct PhaseB1RatchetTree(RatchetTreeIn);

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB1RatchetTree {
    pub fn to_bytes(&self) -> Result<Vec<u8>, JsError> {
        self.0
            .tls_serialize_detached()
            .map_err(|_| JsError::new("phase-b1 ratchet tree: serialization failed"))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<PhaseB1RatchetTree, JsError> {
        let tree = RatchetTreeIn::tls_deserialize_exact(bytes)
            .map_err(|_| JsError::new("phase-b1 ratchet tree: malformed input"))?;
        Ok(Self(tree))
    }
}

/// Isolated Phase B1 group wrapper. No method on this type silently merges a
/// locally pending or remotely staged Commit.
#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
pub struct PhaseB1Group {
    mls_group: MlsGroup,
    instance_id: u32,
}

#[cfg(feature = "extensions-draft")]
impl PhaseB1Group {
    fn handle_binding(&self, provider: &Provider) -> HandleBinding {
        HandleBinding {
            provider_instance_id: provider.instance_id,
            provider_restore_generation: provider.restore_generation.get(),
            group_instance_id: self.instance_id,
            group_id: self.mls_group.group_id().to_vec(),
            prior_epoch: self.mls_group.epoch().as_u64(),
        }
    }
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB1Group {
    pub fn create_new(
        provider: &Provider,
        founder: &PhaseB1Identity,
        group_id: &[u8],
        founder_proof: &[u8],
    ) -> Result<PhaseB1Group, JsError> {
        if group_id.is_empty() || group_id.len() > 64 {
            return Err(JsError::new(
                "phase-b1 group: group id must contain 1..64 bytes",
            ));
        }
        validate_probe_identity_and_proof(&founder.account_public_key, founder_proof)?;
        let builder = MlsGroup::builder()
            .ciphersuite(PROBE_CIPHERSUITE)
            .with_group_id(GroupId::from_slice(group_id))
            .with_capabilities(probe_capabilities())
            .with_leaf_node_extensions(probe_leaf_extensions(founder_proof)?)?;
        let mls_group = builder.build(
            &provider.inner,
            &founder.keypair,
            founder.credential_with_key.clone(),
        )?;
        Ok(Self {
            mls_group,
            instance_id: next_group_instance_id(),
        })
    }

    pub fn join(
        provider: &Provider,
        welcome_bytes: &[u8],
        ratchet_tree: PhaseB1RatchetTree,
    ) -> Result<PhaseB1Group, JsError> {
        let message = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|_| JsError::new("phase-b1 group: malformed Welcome framing"))?;
        let welcome = match message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(JsError::new("phase-b1 group: MLSMessage is not a Welcome")),
        };
        let config = MlsGroupJoinConfig::builder().build();
        let mls_group = StagedWelcome::new_from_welcome(
            &provider.inner,
            &config,
            welcome,
            Some(ratchet_tree.0),
        )?
        .into_group(&provider.inner)?;
        if mls_group.ciphersuite() != PROBE_CIPHERSUITE {
            return Err(JsError::new("phase-b1 group: unexpected ciphersuite"));
        }
        Ok(Self {
            mls_group,
            instance_id: next_group_instance_id(),
        })
    }

    pub fn export_ratchet_tree(&self) -> PhaseB1RatchetTree {
        PhaseB1RatchetTree(self.mls_group.export_ratchet_tree().into())
    }

    pub fn epoch(&self) -> u64 {
        self.mls_group.epoch().as_u64()
    }

    pub fn member_count(&self) -> u32 {
        self.mls_group.members().count() as u32
    }

    pub fn member_identity(&self, index: usize) -> Result<Vec<u8>, JsError> {
        self.mls_group
            .members()
            .nth(index)
            .map(|member| member.credential.serialized_content().to_vec())
            .ok_or_else(|| JsError::new("phase-b1 group: member index out of range"))
    }

    pub fn propose_and_commit_add(
        &mut self,
        provider: &Provider,
        sender: &PhaseB1Identity,
        new_member: &PhaseB1KeyPackage,
    ) -> Result<PhaseB1PendingAdd, JsError> {
        inspect_probe_key_package(&new_member.0)?;
        if self.mls_group.pending_commit().is_some() {
            return Err(JsError::new(
                "phase-b1 local commit: another pending commit already exists",
            ));
        }
        let (commit, welcome, _) = self
            .mls_group
            .add_members(provider.as_ref(), &sender.keypair, &[new_member.0.clone()])?;
        if self.mls_group.pending_commit().is_none() {
            return Err(JsError::new(
                "phase-b1 local commit: OpenMLS did not retain pending state",
            ));
        }
        Ok(PhaseB1PendingAdd {
            binding: Some(self.handle_binding(provider)),
            commit: commit.tls_serialize_detached()?,
            welcome: welcome.tls_serialize_detached()?,
        })
    }

    pub fn confirm_pending_add(
        &mut self,
        provider: &mut Provider,
        pending: &mut PhaseB1PendingAdd,
    ) -> Result<(), JsError> {
        let binding = pending
            .binding
            .as_ref()
            .ok_or_else(|| JsError::new("phase-b1 local commit: handle already consumed"))?;
        binding.validate(provider, self)?;
        if self.mls_group.pending_commit().is_none() {
            return Err(JsError::new("phase-b1 local commit: pending state is absent"));
        }
        pending.binding.take();
        self.mls_group.merge_pending_commit(provider.as_mut())?;
        Ok(())
    }

    pub fn discard_pending_add(
        &mut self,
        provider: &Provider,
        pending: &mut PhaseB1PendingAdd,
    ) -> Result<(), JsError> {
        let binding = pending
            .binding
            .as_ref()
            .ok_or_else(|| JsError::new("phase-b1 local commit: handle already consumed"))?;
        binding.validate(provider, self)?;
        if self.mls_group.pending_commit().is_none() {
            return Err(JsError::new("phase-b1 local commit: pending state is absent"));
        }
        pending.binding.take();
        self.mls_group.clear_pending_commit(provider.inner.storage())?;
        Ok(())
    }

    pub fn stage_inbound_commit(
        &mut self,
        provider: &Provider,
        bytes: &[u8],
    ) -> Result<PhaseB1StagedCommit, JsError> {
        let message = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(|_| JsError::new("phase-b1 staged commit: malformed MLSMessage"))?;
        let protocol_message: ProtocolMessage = match message.extract() {
            MlsMessageBodyIn::PublicMessage(message) => message.into(),
            MlsMessageBodyIn::PrivateMessage(message) => message.into(),
            _ => {
                return Err(JsError::new(
                    "phase-b1 staged commit: unsupported MLSMessage body",
                ));
            }
        };
        let prior_epoch = self.mls_group.epoch().as_u64();
        let processed = self
            .mls_group
            .process_message(provider.as_ref(), protocol_message)?;
        let staged_commit = match processed.into_content() {
            openmls::framing::ProcessedMessageContent::StagedCommitMessage(commit) => *commit,
            _ => {
                return Err(JsError::new(
                    "phase-b1 staged commit: message is not an inbound Commit",
                ));
            }
        };
        let projection = PhaseB1CommitProjection::from_staged(prior_epoch, &staged_commit)?;
        Ok(PhaseB1StagedCommit {
            binding: Some(self.handle_binding(provider)),
            staged_commit: Some(staged_commit),
            projection,
        })
    }

    pub fn merge_staged_commit(
        &mut self,
        provider: &mut Provider,
        staged: &mut PhaseB1StagedCommit,
    ) -> Result<(), JsError> {
        let binding = staged
            .binding
            .as_ref()
            .ok_or_else(|| JsError::new("phase-b1 staged commit: handle already consumed"))?;
        binding.validate(provider, self)?;
        let commit = staged
            .staged_commit
            .take()
            .ok_or_else(|| JsError::new("phase-b1 staged commit: handle already consumed"))?;
        staged.binding.take();
        self.mls_group.merge_staged_commit(provider.as_mut(), commit)?;
        Ok(())
    }

    pub fn discard_staged_commit(
        &mut self,
        provider: &Provider,
        staged: &mut PhaseB1StagedCommit,
    ) -> Result<(), JsError> {
        let binding = staged
            .binding
            .as_ref()
            .ok_or_else(|| JsError::new("phase-b1 staged commit: handle already consumed"))?;
        binding.validate(provider, self)?;
        staged
            .staged_commit
            .take()
            .ok_or_else(|| JsError::new("phase-b1 staged commit: handle already consumed"))?;
        staged.binding.take();
        Ok(())
    }

    pub fn create_application_message(
        &mut self,
        provider: &Provider,
        sender: &PhaseB1Identity,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        if plaintext.is_empty() {
            return Err(JsError::new("phase-b1 application: plaintext must not be empty"));
        }
        let message = self
            .mls_group
            .create_message(provider.as_ref(), &sender.keypair, plaintext)?;
        Ok(message.tls_serialize_detached()?)
    }

    pub fn process_application_message(
        &mut self,
        provider: &Provider,
        bytes: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let message = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(|_| JsError::new("phase-b1 application: malformed MLSMessage"))?;
        let protocol_message: ProtocolMessage = match message.extract() {
            MlsMessageBodyIn::PublicMessage(message) => message.into(),
            MlsMessageBodyIn::PrivateMessage(message) => message.into(),
            _ => {
                return Err(JsError::new(
                    "phase-b1 application: unsupported MLSMessage body",
                ));
            }
        };
        let processed = self
            .mls_group
            .process_message(provider.as_ref(), protocol_message)?;
        match processed.into_content() {
            openmls::framing::ProcessedMessageContent::ApplicationMessage(message) => {
                Ok(message.into_bytes())
            }
            _ => Err(JsError::new(
                "phase-b1 application: message is not application data",
            )),
        }
    }
}

#[cfg(test)]
impl Group {
    fn native_propose_and_commit_add(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        new_member: &KeyPackage,
    ) -> Result<NativeAddMessages, JsError> {
        let (proposal_msg, _proposal_ref) =
            self.mls_group
                .propose_add_member(provider.as_ref(), &sender.keypair, &new_member.0)?;

        let (commit_msg, welcome_msg, _group_info) = self
            .mls_group
            .commit_to_pending_proposals(provider.as_ref(), &sender.keypair)?;

        let welcome_msg = welcome_msg.ok_or(NoWelcomeError)?;

        let proposal = mls_message_to_u8vec(&proposal_msg);
        let commit = mls_message_to_u8vec(&commit_msg);
        let welcome = mls_message_to_u8vec(&welcome_msg);

        Ok(NativeAddMessages {
            proposal,
            commit,
            welcome,
        })
    }

    fn native_join(provider: &Provider, mut welcome: &[u8], ratchet_tree: RatchetTree) -> Group {
        let welcome = match MlsMessageIn::tls_deserialize(&mut welcome)
            .unwrap()
            .extract()
        {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => panic!("expected a message of type welcome"),
        };
        let config = MlsGroupJoinConfig::builder().build();
        let mls_group = StagedWelcome::new_from_welcome(
            provider.as_ref(),
            &config,
            welcome,
            Some(ratchet_tree.0),
        )
        .unwrap()
        .into_group(provider.as_ref())
        .unwrap();

        Group { mls_group }
    }
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct NoWelcomeError;

impl std::fmt::Display for NoWelcomeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no welcome")
    }
}

impl std::error::Error for NoWelcomeError {}

#[wasm_bindgen]
pub struct KeyPackage(OpenMlsKeyPackage);

#[wasm_bindgen]
impl KeyPackage {
    /// Serialize this KeyPackage to bytes
    #[wasm_bindgen]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.tls_serialize_detached().unwrap()
    }

    /// Deserialize a KeyPackage from bytes
    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Result<KeyPackage, JsError> {
        let mut s = bytes;
        let kp_in = openmls::key_packages::KeyPackageIn::tls_deserialize(&mut s)
            .map_err(|e| JsError::new(&format!("KeyPackage deserialization error: {e}")))?;
        let kp = kp_in
            .validate(
                &openmls_rust_crypto::RustCrypto::default(),
                openmls::prelude::ProtocolVersion::Mls10,
            )
            .map_err(|e| JsError::new(&format!("KeyPackage validation error: {e}")))?;
        Ok(KeyPackage(kp))
    }
}

#[wasm_bindgen]
pub struct RatchetTree(RatchetTreeIn);

#[wasm_bindgen]
impl RatchetTree {
    /// Serialize this RatchetTree to bytes
    #[wasm_bindgen]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.tls_serialize_detached().unwrap()
    }

    /// Deserialize a RatchetTree from bytes
    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Result<RatchetTree, JsError> {
        let mut s = bytes;
        let tree = RatchetTreeIn::tls_deserialize(&mut s)
            .map_err(|e| JsError::new(&format!("RatchetTree deserialization error: {e}")))?;
        Ok(RatchetTree(tree))
    }
}

fn mls_message_to_uint8array(msg: &MlsMessageOut) -> Uint8Array {
    // see https://github.com/rustwasm/wasm-bindgen/issues/1619#issuecomment-505065294

    let mut serialized = vec![];
    msg.tls_serialize(&mut serialized).unwrap();

    unsafe { Uint8Array::new(&Uint8Array::view(&serialized)) }
}

#[cfg(test)]
fn mls_message_to_u8vec(msg: &MlsMessageOut) -> Vec<u8> {
    // see https://github.com/rustwasm/wasm-bindgen/issues/1619#issuecomment-505065294

    let mut serialized = vec![];
    msg.tls_serialize(&mut serialized).unwrap();
    serialized
}

#[cfg(test)]
mod tests {
    use super::*;

    fn js_error_to_string(e: JsError) -> String {
        let v: JsValue = e.into();
        v.as_string().unwrap()
    }

    fn create_group_alice_and_bob() -> (Provider, Identity, Group, Provider, Identity, Group) {
        let mut alice_provider = Provider::new();
        let bob_provider = Provider::new();

        let alice = Identity::new(&alice_provider, "alice")
            .map_err(js_error_to_string)
            .unwrap();
        let bob = Identity::new(&bob_provider, "bob")
            .map_err(js_error_to_string)
            .unwrap();

        let mut chess_club_alice = Group::create_new(&alice_provider, &alice, "chess club");

        let bob_key_pkg = bob.key_package(&bob_provider);

        let add_msgs = chess_club_alice
            .native_propose_and_commit_add(&alice_provider, &alice, &bob_key_pkg)
            .map_err(js_error_to_string)
            .unwrap();

        chess_club_alice
            .merge_pending_commit(&mut alice_provider)
            .map_err(js_error_to_string)
            .unwrap();

        let ratchet_tree = chess_club_alice.export_ratchet_tree();

        let chess_club_bob = Group::native_join(&bob_provider, &add_msgs.welcome, ratchet_tree);

        (
            alice_provider,
            alice,
            chess_club_alice,
            bob_provider,
            bob,
            chess_club_bob,
        )
    }

    #[test]
    fn basic() {
        let (alice_provider, _, chess_club_alice, bob_provider, _, chess_club_bob) =
            create_group_alice_and_bob();

        let bob_exported_key = chess_club_bob
            .export_key(&bob_provider, "chess_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();
        let alice_exported_key = chess_club_alice
            .export_key(&alice_provider, "chess_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();

        assert_eq!(bob_exported_key, alice_exported_key);
    }

    #[test]
    fn create_message() {
        let (alice_provider, alice, mut chess_club_alice, mut bob_provider, _, mut chess_club_bob) =
            create_group_alice_and_bob();

        let alice_msg = "hello, bob!".as_bytes();
        let msg_out = chess_club_alice
            .create_message(&alice_provider, &alice, alice_msg)
            .map_err(js_error_to_string)
            .unwrap();

        let bob_msg = chess_club_bob
            .process_message(&mut bob_provider, &msg_out)
            .map_err(js_error_to_string)
            .unwrap();

        assert_eq!(alice_msg, bob_msg);
    }

    #[cfg(feature = "extensions-draft")]
    fn probe_identity(
        provider: &Provider,
        account_byte: u8,
    ) -> (PhaseB1Identity, Vec<u8>, PhaseB1KeyPackage) {
        let account = vec![account_byte; 32];
        let identity = PhaseB1Identity::new(provider, &account)
            .map_err(js_error_to_string)
            .unwrap();
        // Rust verifies the structural binding. The independent JavaScript
        // harness verifies the real NIP-01/BIP340 proof.
        let mut proof = vec![0u8; ACCOUNT_IDENTITY_PROOF_V2_LENGTH];
        proof[..32].copy_from_slice(&account);
        let key_package = identity
            .key_package(provider, &proof)
            .map_err(js_error_to_string)
            .unwrap();
        (identity, proof, key_package)
    }

    #[cfg(feature = "extensions-draft")]
    #[test]
    fn phase_b1_profile_and_explicit_staging() {
        let mut alice_provider = Provider::new();
        let mut bob_provider = Provider::new();
        let charlie_provider = Provider::new();
        let (alice, alice_proof, _) = probe_identity(&alice_provider, 1);
        let (bob, _, bob_key_package) = probe_identity(&bob_provider, 2);
        let (_, _, charlie_key_package) = probe_identity(&charlie_provider, 3);

        let framed = bob_key_package.to_framed_bytes().unwrap();
        let parsed = PhaseB1KeyPackage::from_framed_bytes(&framed)
            .map_err(js_error_to_string)
            .unwrap();
        assert_eq!(parsed.ciphersuite_id(), 0x0001);
        assert_eq!(parsed.credential_identity(), vec![2; 32]);
        assert_eq!(parsed.identity_proof().len(), 104);
        assert_eq!(parsed.component_ids(), vec![1, 0x8009]);
        assert_eq!(parsed.supported_component_ids(), vec![0x8009]);
        assert!(!parsed.is_last_resort());

        let mut alice_group = PhaseB1Group::create_new(
            &alice_provider,
            &alice,
            b"phase-b1-native",
            &alice_proof,
        )
        .map_err(js_error_to_string)
        .unwrap();
        let mut first_add = alice_group
            .propose_and_commit_add(&alice_provider, &alice, &parsed)
            .map_err(js_error_to_string)
            .unwrap();
        assert_eq!(alice_group.epoch(), 0);
        alice_group
            .confirm_pending_add(&mut alice_provider, &mut first_add)
            .map_err(js_error_to_string)
            .unwrap();
        assert_eq!(alice_group.epoch(), 1);

        let tree = PhaseB1RatchetTree::from_bytes(
            &alice_group.export_ratchet_tree().to_bytes().unwrap(),
        )
        .map_err(js_error_to_string)
        .unwrap();
        let mut bob_group = PhaseB1Group::join(&bob_provider, &first_add.welcome(), tree)
            .map_err(js_error_to_string)
            .unwrap();

        let mut second_add = bob_group
            .propose_and_commit_add(&bob_provider, &bob, &charlie_key_package)
            .map_err(js_error_to_string)
            .unwrap();
        let mut staged = alice_group
            .stage_inbound_commit(&alice_provider, &second_add.commit())
            .map_err(js_error_to_string)
            .unwrap();
        let projection = staged.projection();
        assert_eq!(projection.prior_epoch(), 1);
        assert_eq!(projection.next_epoch(), 2);
        assert_eq!(projection.add_count(), 1);
        assert_eq!(projection.added_credential_identity(0).unwrap(), vec![3; 32]);
        assert_eq!(alice_group.epoch(), 1);
        assert_eq!(alice_group.member_count(), 2);

        alice_group
            .merge_staged_commit(&mut alice_provider, &mut staged)
            .map_err(js_error_to_string)
            .unwrap();
        bob_group
            .confirm_pending_add(&mut bob_provider, &mut second_add)
            .map_err(js_error_to_string)
            .unwrap();
        assert_eq!(alice_group.epoch(), 2);
        assert_eq!(alice_group.member_count(), 3);
        assert!(staged.is_consumed());
    }

    #[cfg(feature = "extensions-draft")]
    mod phase_b2_restore_probes {
        use super::*;
        use openmls::{
            component::ComponentData,
            extensions::RequiredCapabilitiesExtension,
            group::{
                GroupContext, MlsGroupJoinConfig, StagedCommit,
                PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
            },
            prelude::LeafNodeParameters,
        };
        use openmls_traits::crypto::OpenMlsCrypto;
        use std::collections::BTreeMap;

        const ADMIN_POLICY_V1_COMPONENT_ID: ComponentId = 0x8003;
        const GROUP_LIFECYCLE_V1_COMPONENT_ID: ComponentId = 0x800c;
        const CURRENT_COMPONENTS: [ComponentId; 3] = [
            ADMIN_POLICY_V1_COMPONENT_ID,
            ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID,
            GROUP_LIFECYCLE_V1_COMPONENT_ID,
        ];

        fn unwrap_js<T>(result: Result<T, JsError>) -> T {
            result.map_err(js_error_to_string).unwrap()
        }

        fn synthetic_proof(account: &[u8]) -> Vec<u8> {
            assert_eq!(account.len(), 32);
            let mut proof = vec![0u8; ACCOUNT_IDENTITY_PROOF_V2_LENGTH];
            proof[..32].copy_from_slice(account);
            proof
        }

        fn current_capabilities() -> Capabilities {
            Capabilities::builder()
                .ciphersuites(vec![PROBE_CIPHERSUITE])
                .extensions(vec![ExtensionType::AppDataDictionary])
                .proposals(vec![ProposalType::AppDataUpdate])
                .build()
        }

        fn current_leaf_extensions(account: &[u8]) -> Extensions<LeafNode> {
            let supported = CURRENT_COMPONENTS
                .to_vec()
                .tls_serialize_detached()
                .unwrap();
            let mut dictionary = AppDataDictionary::new();
            dictionary.insert(1, supported);
            dictionary.insert(
                ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID,
                synthetic_proof(account),
            );
            Extensions::single(Extension::AppDataDictionary(
                AppDataDictionaryExtension::new(dictionary),
            ))
            .unwrap()
        }

        fn current_group_context_extensions(
            founder_account: &[u8],
            require_app_data_update: bool,
        ) -> Extensions<GroupContext> {
            assert_eq!(founder_account.len(), 32);
            let mut dictionary = AppDataDictionary::new();
            dictionary.insert(
                1,
                CURRENT_COMPONENTS
                    .to_vec()
                    .tls_serialize_detached()
                    .unwrap(),
            );

            // Marmot's one-admin initial state is a QUIC-varint byte length
            // followed by one fixed-width 32-byte account key. 32 has the
            // canonical one-byte QUIC prefix 0x20.
            let mut admin_policy = vec![0x20];
            admin_policy.extend_from_slice(founder_account);
            dictionary.insert(ADMIN_POLICY_V1_COMPONENT_ID, admin_policy);
            dictionary.insert(GROUP_LIFECYCLE_V1_COMPONENT_ID, vec![0x00]);

            let proposal_types = if require_app_data_update {
                vec![ProposalType::AppDataUpdate]
            } else {
                vec![]
            };
            Extensions::from_vec(vec![
                Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
                    &[ExtensionType::AppDataDictionary],
                    &proposal_types,
                    &[],
                )),
                Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary)),
            ])
            .unwrap()
        }

        fn new_identity(provider: &Provider, account_byte: u8) -> PhaseB1Identity {
            unwrap_js(PhaseB1Identity::new(provider, &[account_byte; 32]))
        }

        fn reload_identity(
            provider: &Provider,
            account: &[u8],
            signature_public_key: &[u8],
        ) -> PhaseB1Identity {
            let keypair = SignatureKeyPair::read(
                provider.inner.storage(),
                signature_public_key,
                SignatureScheme::ED25519,
            )
            .expect("restored provider must contain the exact MLS signing key");
            let credential = BasicCredential::new(account.to_vec());
            PhaseB1Identity {
                account_public_key: account.to_vec(),
                credential_with_key: CredentialWithKey {
                    credential: credential.into(),
                    signature_key: keypair.public().into(),
                },
                keypair,
            }
        }

        fn current_key_package(
            provider: &Provider,
            identity: &PhaseB1Identity,
        ) -> OpenMlsKeyPackage {
            OpenMlsKeyPackage::builder()
                .key_package_lifetime(Lifetime::new(PROBE_KEY_PACKAGE_LIFETIME_SECONDS))
                .leaf_node_capabilities(current_capabilities())
                .leaf_node_extensions(current_leaf_extensions(&identity.account_public_key))
                .build(
                    PROBE_CIPHERSUITE,
                    provider.as_ref(),
                    &identity.keypair,
                    identity.credential_with_key.clone(),
                )
                .unwrap()
                .key_package()
                .clone()
        }

        fn create_current_group(
            provider: &Provider,
            founder: &PhaseB1Identity,
            group_id: &[u8],
        ) -> MlsGroup {
            MlsGroup::builder()
                .ciphersuite(PROBE_CIPHERSUITE)
                .with_group_id(GroupId::from_slice(group_id))
                .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                .with_group_context_extensions(current_group_context_extensions(
                    &founder.account_public_key,
                    true,
                ))
                .with_capabilities(current_capabilities())
                .with_leaf_node_extensions(current_leaf_extensions(
                    &founder.account_public_key,
                ))
                .unwrap()
                .build(
                    provider.as_ref(),
                    &founder.keypair,
                    founder.credential_with_key.clone(),
                )
                .unwrap()
        }

        fn join_current_group(
            provider: &Provider,
            welcome_bytes: &[u8],
            tree: RatchetTreeIn,
        ) -> MlsGroup {
            let message = MlsMessageIn::tls_deserialize_exact(welcome_bytes).unwrap();
            let welcome = match message.extract() {
                MlsMessageBodyIn::Welcome(welcome) => welcome,
                _ => panic!("expected Welcome"),
            };
            let config = MlsGroupJoinConfig::builder()
                .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                .build();
            StagedWelcome::new_from_welcome(provider.as_ref(), &config, welcome, Some(tree))
                .unwrap()
                .into_group(provider.as_ref())
                .unwrap()
        }

        fn restore_provider(snapshot: &[u8]) -> Provider {
            let provider = Provider::new();
            unwrap_js(provider.restore_state(snapshot));
            provider
        }

        fn load_group(provider: &Provider, group_id: &[u8]) -> MlsGroup {
            MlsGroup::load(
                provider.inner.storage(),
                &GroupId::from_slice(group_id),
            )
            .unwrap()
            .expect("restored provider must contain the exact MLS group")
        }

        fn snapshot_map(snapshot: &[u8]) -> BTreeMap<Vec<u8>, Vec<u8>> {
            fn read_u64(snapshot: &[u8], offset: &mut usize) -> u64 {
                let end = offset.checked_add(8).unwrap();
                assert!(end <= snapshot.len());
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&snapshot[*offset..end]);
                *offset = end;
                u64::from_be_bytes(bytes)
            }

            let mut offset = 0usize;
            let count = usize::try_from(read_u64(snapshot, &mut offset)).unwrap();
            let mut map = BTreeMap::new();
            for _ in 0..count {
                let key_len = usize::try_from(read_u64(snapshot, &mut offset)).unwrap();
                let value_len = usize::try_from(read_u64(snapshot, &mut offset)).unwrap();
                let key_end = offset.checked_add(key_len).unwrap();
                assert!(key_end <= snapshot.len());
                let key = snapshot[offset..key_end].to_vec();
                offset = key_end;
                let value_end = offset.checked_add(value_len).unwrap();
                assert!(value_end <= snapshot.len());
                let value = snapshot[offset..value_end].to_vec();
                offset = value_end;
                assert!(map.insert(key, value).is_none(), "duplicate provider key");
            }
            assert_eq!(offset, snapshot.len(), "trailing provider snapshot bytes");
            map
        }

        fn snapshot_sha256(provider: &Provider, snapshot: &[u8]) -> String {
            provider
                .as_ref()
                .crypto()
                .hash(PROBE_CIPHERSUITE.hash_algorithm(), snapshot)
                .unwrap()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        }

        fn stage_public_commit(
            group: &mut MlsGroup,
            provider: &Provider,
            commit_bytes: &[u8],
        ) -> StagedCommit {
            let message = MlsMessageIn::tls_deserialize_exact(commit_bytes).unwrap();
            let protocol: ProtocolMessage = match message.extract() {
                MlsMessageBodyIn::PublicMessage(message) => message.into(),
                _ => panic!("B2 inbound probe requires PublicMessage Commit framing"),
            };
            let processed = group.process_message(provider.as_ref(), protocol).unwrap();
            match processed.into_content() {
                openmls::framing::ProcessedMessageContent::StagedCommitMessage(commit) => *commit,
                _ => panic!("expected staged Commit"),
            }
        }

        fn assert_public_commit(commit_bytes: &[u8]) {
            let message = MlsMessageIn::tls_deserialize_exact(commit_bytes).unwrap();
            assert!(matches!(
                message.extract(),
                MlsMessageBodyIn::PublicMessage(_)
            ));
        }

        fn process_application(
            group: &mut MlsGroup,
            provider: &Provider,
            message_bytes: &[u8],
        ) -> Vec<u8> {
            let message = MlsMessageIn::tls_deserialize_exact(message_bytes).unwrap();
            let protocol: ProtocolMessage = match message.extract() {
                MlsMessageBodyIn::PublicMessage(message) => message.into(),
                MlsMessageBodyIn::PrivateMessage(message) => message.into(),
                _ => panic!("expected MLS application message"),
            };
            match group
                .process_message(provider.as_ref(), protocol)
                .unwrap()
                .into_content()
            {
                openmls::framing::ProcessedMessageContent::ApplicationMessage(message) => {
                    message.into_bytes()
                }
                _ => panic!("expected application data"),
            }
        }

        fn assert_bidirectional_liveness(
            left_group: &mut MlsGroup,
            left_provider: &Provider,
            left_identity: &PhaseB1Identity,
            right_group: &mut MlsGroup,
            right_provider: &Provider,
            right_identity: &PhaseB1Identity,
        ) {
            let left_plaintext = b"phase-b2-left-to-right";
            let left_message = left_group
                .create_message(
                    left_provider.as_ref(),
                    &left_identity.keypair,
                    left_plaintext,
                )
                .unwrap()
                .tls_serialize_detached()
                .unwrap();
            assert_eq!(
                process_application(right_group, right_provider, &left_message),
                left_plaintext
            );

            let right_plaintext = b"phase-b2-right-to-left";
            let right_message = right_group
                .create_message(
                    right_provider.as_ref(),
                    &right_identity.keypair,
                    right_plaintext,
                )
                .unwrap()
                .tls_serialize_detached()
                .unwrap();
            assert_eq!(
                process_application(left_group, left_provider, &right_message),
                right_plaintext
            );
        }

        fn assert_current_group_context(
            extensions: &Extensions<GroupContext>,
            founder_account: &[u8],
        ) -> Result<(), String> {
            let required = extensions
                .required_capabilities()
                .ok_or("required_capabilities missing")?;
            if !required
                .extension_types()
                .contains(&ExtensionType::AppDataDictionary)
            {
                return Err("app_data_dictionary extension capability missing".into());
            }
            if !required
                .proposal_types()
                .contains(&ProposalType::AppDataUpdate)
            {
                return Err("test-only exact profile decoder: app_data_update missing".into());
            }
            let dictionary = extensions
                .app_data_dictionary()
                .ok_or("GroupContext app_data_dictionary missing")?
                .dictionary();
            let component_ids: Vec<_> = dictionary.entries().map(|entry| entry.id()).collect();
            if component_ids != [1, ADMIN_POLICY_V1_COMPONENT_ID, GROUP_LIFECYCLE_V1_COMPONENT_ID]
            {
                return Err("unexpected GroupContext component locations".into());
            }
            let required_components = Vec::<u16>::tls_deserialize_exact(
                dictionary.get(&1).ok_or("app_components missing")?,
            )
            .map_err(|_| "app_components malformed")?;
            if required_components != CURRENT_COMPONENTS {
                return Err("required component set mismatch".into());
            }
            let admin_policy = dictionary
                .get(&ADMIN_POLICY_V1_COMPONENT_ID)
                .ok_or("admin policy missing")?;
            if admin_policy.len() != 33
                || admin_policy[0] != 0x20
                || &admin_policy[1..] != founder_account
            {
                return Err("initial founder admin policy malformed".into());
            }
            if dictionary
                .get(&GROUP_LIFECYCLE_V1_COMPONENT_ID)
                .ok_or("lifecycle missing")?
                != [0x00]
            {
                return Err("initial lifecycle is not active".into());
            }
            Ok(())
        }

        fn assert_current_profile(group: &MlsGroup, founder_account: &[u8]) -> Result<(), String> {
            if group.ciphersuite() != PROBE_CIPHERSUITE {
                return Err("unexpected ciphersuite".into());
            }
            assert_current_group_context(group.extensions(), founder_account)?;

            for member in group.members() {
                let leaf = group
                    .public_group()
                    .leaf(member.index)
                    .ok_or("member leaf missing")?;
                if !leaf
                    .capabilities()
                    .proposals()
                    .contains(&ProposalType::AppDataUpdate)
                {
                    return Err("member proposal capability missing".into());
                }
                let leaf_dictionary = leaf
                    .extensions()
                    .app_data_dictionary()
                    .ok_or("member app_data_dictionary missing")?
                    .dictionary();
                let leaf_ids: Vec<_> = leaf_dictionary.entries().map(|entry| entry.id()).collect();
                if leaf_ids != [1, ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID] {
                    return Err("member component placement mismatch".into());
                }
                let supported = Vec::<u16>::tls_deserialize_exact(
                    leaf_dictionary.get(&1).ok_or("member app_components missing")?,
                )
                .map_err(|_| "member app_components malformed")?;
                if supported != CURRENT_COMPONENTS {
                    return Err("member component support mismatch".into());
                }
                let proof = leaf_dictionary
                    .get(&ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID)
                    .ok_or("member account proof missing")?;
                if proof.len() != ACCOUNT_IDENTITY_PROOF_V2_LENGTH
                    || proof[..32] != *member.credential.serialized_content()
                {
                    return Err("member account proof structurally invalid".into());
                }
            }
            Ok(())
        }

        fn setup_stable_pair(
            group_id: &[u8],
        ) -> (
            Provider,
            PhaseB1Identity,
            MlsGroup,
            Provider,
            PhaseB1Identity,
            MlsGroup,
        ) {
            let mut alice_provider = Provider::new();
            let bob_provider = Provider::new();
            let alice = new_identity(&alice_provider, 0x11);
            let bob = new_identity(&bob_provider, 0x22);
            let bob_key_package = current_key_package(&bob_provider, &bob);
            let mut alice_group = create_current_group(&alice_provider, &alice, group_id);
            let (_commit, welcome, _) = alice_group
                .add_members(
                    alice_provider.as_ref(),
                    &alice.keypair,
                    &[bob_key_package],
                )
                .unwrap();
            alice_group
                .merge_pending_commit(alice_provider.as_mut())
                .unwrap();
            let bob_group = join_current_group(
                &bob_provider,
                &welcome.tls_serialize_detached().unwrap(),
                alice_group.export_ratchet_tree().into(),
            );
            (
                alice_provider,
                alice,
                alice_group,
                bob_provider,
                bob,
                bob_group,
            )
        }

        #[test]
        fn local_pending_commits_survive_restore_for_merge_and_clear() {
            let group_id = b"phase-b2-local-add";
            let alice_provider = Provider::new();
            let bob_seed_provider = Provider::new();
            let alice = new_identity(&alice_provider, 0x31);
            let bob_seed = new_identity(&bob_seed_provider, 0x32);
            let alice_signature_key = alice.leaf_signature_key();
            let bob_signature_key = bob_seed.leaf_signature_key();
            let bob_account = bob_seed.account_public_key.clone();
            let bob_key_package = current_key_package(&bob_seed_provider, &bob_seed);
            let bob_seed_snapshot = bob_seed_provider.serialize_state();
            let mut alice_group = create_current_group(&alice_provider, &alice, group_id);
            let (commit, welcome, _) = alice_group
                .add_members(
                    alice_provider.as_ref(),
                    &alice.keypair,
                    &[bob_key_package.clone()],
                )
                .unwrap();
            let commit_bytes = commit.tls_serialize_detached().unwrap();
            assert_public_commit(&commit_bytes);
            assert_eq!(alice_group.epoch().as_u64(), 0);
            assert!(alice_group.pending_commit().is_some());
            let add_snapshot = alice_provider.serialize_state();
            println!(
                "B2 local founding Add snapshot: bytes={} sha256={}",
                add_snapshot.len(),
                snapshot_sha256(&alice_provider, &add_snapshot)
            );

            let mut merge_provider = restore_provider(&add_snapshot);
            let merge_identity = reload_identity(
                &merge_provider,
                &alice.account_public_key,
                &alice_signature_key,
            );
            let mut merge_group = load_group(&merge_provider, group_id);
            assert!(merge_group.pending_commit().is_some());
            merge_group
                .merge_pending_commit(merge_provider.as_mut())
                .unwrap();
            assert_eq!(merge_group.epoch().as_u64(), 1);
            assert_eq!(merge_group.members().count(), 2);
            let epoch_after_first_merge = merge_group.epoch();
            let members_after_first_merge = merge_group.members().count();
            let second_merge = merge_group.merge_pending_commit(merge_provider.as_mut());
            println!(
                "B2 local founding Add second merge outcome: {}",
                if second_merge.is_ok() { "no-op success" } else { "error" }
            );
            assert_eq!(merge_group.epoch(), epoch_after_first_merge);
            assert_eq!(merge_group.members().count(), members_after_first_merge);
            let bob_merge_provider = restore_provider(&bob_seed_snapshot);
            let bob_merge_identity = reload_identity(
                &bob_merge_provider,
                &bob_account,
                &bob_signature_key,
            );
            let mut bob_merge_group = join_current_group(
                &bob_merge_provider,
                &welcome.tls_serialize_detached().unwrap(),
                merge_group.export_ratchet_tree().into(),
            );
            assert_current_profile(&merge_group, &alice.account_public_key).unwrap();
            assert_current_profile(&bob_merge_group, &alice.account_public_key).unwrap();
            assert_bidirectional_liveness(
                &mut merge_group,
                &merge_provider,
                &merge_identity,
                &mut bob_merge_group,
                &bob_merge_provider,
                &bob_merge_identity,
            );

            let clear_provider = restore_provider(&add_snapshot);
            let clear_identity = reload_identity(
                &clear_provider,
                &alice.account_public_key,
                &alice_signature_key,
            );
            let mut clear_group = load_group(&clear_provider, group_id);
            assert!(clear_group.pending_commit().is_some());
            clear_group
                .clear_pending_commit(clear_provider.inner.storage())
                .unwrap();
            assert_eq!(clear_group.epoch().as_u64(), 0);
            assert_eq!(clear_group.members().count(), 1);
            assert!(clear_group.pending_commit().is_none());
            let cleared_snapshot = clear_provider.serialize_state();
            let mut recovered_provider = restore_provider(&cleared_snapshot);
            let recovered_identity = reload_identity(
                &recovered_provider,
                &clear_identity.account_public_key,
                &alice_signature_key,
            );
            let mut recovered_group = load_group(&recovered_provider, group_id);
            assert!(recovered_group.pending_commit().is_none());
            assert_eq!(recovered_group.epoch().as_u64(), 0);
            let (_fresh_commit, fresh_welcome, _) = recovered_group
                .add_members(
                    recovered_provider.as_ref(),
                    &recovered_identity.keypair,
                    &[bob_key_package],
                )
                .unwrap();
            recovered_group
                .merge_pending_commit(recovered_provider.as_mut())
                .unwrap();
            assert_eq!(recovered_group.epoch().as_u64(), 1);
            let bob_clear_provider = restore_provider(&bob_seed_snapshot);
            let bob_clear_identity = reload_identity(
                &bob_clear_provider,
                &bob_account,
                &bob_signature_key,
            );
            let mut bob_clear_group = join_current_group(
                &bob_clear_provider,
                &fresh_welcome.tls_serialize_detached().unwrap(),
                recovered_group.export_ratchet_tree().into(),
            );
            assert_bidirectional_liveness(
                &mut recovered_group,
                &recovered_provider,
                &recovered_identity,
                &mut bob_clear_group,
                &bob_clear_provider,
                &bob_clear_identity,
            );

            let self_update_group_id = b"phase-b2-local-self-update";
            let (
                alice_provider,
                alice,
                mut alice_group,
                bob_provider,
                bob,
                bob_group,
            ) = setup_stable_pair(self_update_group_id);
            assert_eq!(alice_group.epoch().as_u64(), 1);
            let alice_signature_key = alice.leaf_signature_key();
            let bob_signature_key = bob.leaf_signature_key();
            let bob_snapshot = bob_provider.serialize_state();
            let self_update = alice_group
                .self_update(
                    alice_provider.as_ref(),
                    &alice.keypair,
                    LeafNodeParameters::default(),
                )
                .unwrap();
            let self_update_commit = self_update.commit().tls_serialize_detached().unwrap();
            assert_public_commit(&self_update_commit);
            assert!(alice_group.pending_commit().is_some());
            let self_update_snapshot = alice_provider.serialize_state();
            println!(
                "B2 local epoch-1 self-update snapshot: bytes={} sha256={}",
                self_update_snapshot.len(),
                snapshot_sha256(&alice_provider, &self_update_snapshot)
            );

            let mut update_merge_provider = restore_provider(&self_update_snapshot);
            let update_merge_identity = reload_identity(
                &update_merge_provider,
                &alice.account_public_key,
                &alice_signature_key,
            );
            let mut update_merge_group = load_group(&update_merge_provider, self_update_group_id);
            update_merge_group
                .merge_pending_commit(update_merge_provider.as_mut())
                .unwrap();
            assert_eq!(update_merge_group.epoch().as_u64(), 2);
            assert_eq!(update_merge_group.members().count(), 2);
            let epoch_after_update_merge = update_merge_group.epoch();
            let members_after_update_merge = update_merge_group.members().count();
            let second_update_merge =
                update_merge_group.merge_pending_commit(update_merge_provider.as_mut());
            println!(
                "B2 local epoch-1 self-update second merge outcome: {}",
                if second_update_merge.is_ok() {
                    "no-op success"
                } else {
                    "error"
                }
            );
            assert_eq!(update_merge_group.epoch(), epoch_after_update_merge);
            assert_eq!(
                update_merge_group.members().count(),
                members_after_update_merge
            );
            let mut bob_merge_provider = restore_provider(&bob_snapshot);
            let bob_merge_identity = reload_identity(
                &bob_merge_provider,
                &bob.account_public_key,
                &bob_signature_key,
            );
            let mut bob_merge_group = load_group(&bob_merge_provider, self_update_group_id);
            let staged = stage_public_commit(
                &mut bob_merge_group,
                &bob_merge_provider,
                &self_update_commit,
            );
            bob_merge_group
                .merge_staged_commit(bob_merge_provider.as_mut(), staged)
                .unwrap();
            assert_bidirectional_liveness(
                &mut update_merge_group,
                &update_merge_provider,
                &update_merge_identity,
                &mut bob_merge_group,
                &bob_merge_provider,
                &bob_merge_identity,
            );

            let clear_update_provider = restore_provider(&self_update_snapshot);
            let clear_update_identity = reload_identity(
                &clear_update_provider,
                &alice.account_public_key,
                &alice_signature_key,
            );
            let mut clear_update_group =
                load_group(&clear_update_provider, self_update_group_id);
            clear_update_group
                .clear_pending_commit(clear_update_provider.inner.storage())
                .unwrap();
            let clear_update_snapshot = clear_update_provider.serialize_state();
            let mut recovered_update_provider = restore_provider(&clear_update_snapshot);
            let recovered_update_identity = reload_identity(
                &recovered_update_provider,
                &clear_update_identity.account_public_key,
                &alice_signature_key,
            );
            let mut recovered_update_group =
                load_group(&recovered_update_provider, self_update_group_id);
            assert!(recovered_update_group.pending_commit().is_none());
            assert_eq!(recovered_update_group.epoch().as_u64(), 1);
            let fresh_update = recovered_update_group
                .self_update(
                    recovered_update_provider.as_ref(),
                    &recovered_update_identity.keypair,
                    LeafNodeParameters::default(),
                )
                .unwrap();
            let fresh_update_commit = fresh_update.commit().tls_serialize_detached().unwrap();
            recovered_update_group
                .merge_pending_commit(recovered_update_provider.as_mut())
                .unwrap();
            let mut bob_clear_provider = restore_provider(&bob_snapshot);
            let bob_clear_identity = reload_identity(
                &bob_clear_provider,
                &bob.account_public_key,
                &bob_signature_key,
            );
            let mut bob_clear_group = load_group(&bob_clear_provider, self_update_group_id);
            let staged = stage_public_commit(
                &mut bob_clear_group,
                &bob_clear_provider,
                &fresh_update_commit,
            );
            bob_clear_group
                .merge_staged_commit(bob_clear_provider.as_mut(), staged)
                .unwrap();
            assert_bidirectional_liveness(
                &mut recovered_update_group,
                &recovered_update_provider,
                &recovered_update_identity,
                &mut bob_clear_group,
                &bob_clear_provider,
                &bob_clear_identity,
            );

            // The original in-memory Bob group is deliberately unused after its
            // durable snapshot is taken: recovery must use a fresh provider.
            drop(bob_group);
        }

        #[test]
        fn inbound_public_commit_can_be_restaged_after_restore() {
            let group_id = b"phase-b2-inbound-restage";
            let (
                alice_provider,
                alice,
                mut alice_group,
                mut bob_provider,
                bob,
                mut bob_group,
            ) = setup_stable_pair(group_id);
            let charlie_provider = Provider::new();
            let charlie = new_identity(&charlie_provider, 0x43);
            let charlie_key_package = current_key_package(&charlie_provider, &charlie);

            let (commit, _welcome, _) = bob_group
                .add_members(
                    bob_provider.as_ref(),
                    &bob.keypair,
                    &[charlie_key_package],
                )
                .unwrap();
            let commit_bytes = commit.tls_serialize_detached().unwrap();
            assert_public_commit(&commit_bytes);
            println!("B2 inbound explicit PublicMessage policy required: true");

            let alice_signature_key = alice.leaf_signature_key();
            let pre_stage = alice_provider.serialize_state();
            let staged_once = stage_public_commit(&mut alice_group, &alice_provider, &commit_bytes);
            let post_stage = alice_provider.serialize_state();
            let raw_equal = pre_stage == post_stage;
            let decoded_equal = snapshot_map(&pre_stage) == snapshot_map(&post_stage);
            println!(
                "B2 inbound staging: pre_bytes={} pre_sha256={} post_bytes={} post_sha256={} raw_equal={} decoded_maps_equal={}",
                pre_stage.len(),
                snapshot_sha256(&alice_provider, &pre_stage),
                post_stage.len(),
                snapshot_sha256(&alice_provider, &post_stage),
                raw_equal,
                decoded_equal
            );
            assert!(decoded_equal, "staging unexpectedly mutated provider storage");
            drop(staged_once);
            drop(alice_group);

            let mut restored_provider = restore_provider(&pre_stage);
            let restored_identity = reload_identity(
                &restored_provider,
                &alice.account_public_key,
                &alice_signature_key,
            );
            let mut restored_group = load_group(&restored_provider, group_id);
            let staged = stage_public_commit(&mut restored_group, &restored_provider, &commit_bytes);
            restored_group
                .merge_staged_commit(restored_provider.as_mut(), staged)
                .unwrap();
            bob_group
                .merge_pending_commit(bob_provider.as_mut())
                .unwrap();
            assert_eq!(restored_group.epoch().as_u64(), 2);
            assert_eq!(restored_group.members().count(), 3);
            assert_eq!(bob_group.epoch().as_u64(), 2);
            assert_eq!(bob_group.members().count(), 3);

            let replay_message = MlsMessageIn::tls_deserialize_exact(&commit_bytes).unwrap();
            let replay_protocol: ProtocolMessage = match replay_message.extract() {
                MlsMessageBodyIn::PublicMessage(message) => message.into(),
                _ => panic!("expected PublicMessage replay"),
            };
            let epoch_before_replay = restored_group.epoch();
            assert!(restored_group
                .process_message(restored_provider.as_ref(), replay_protocol)
                .is_err());
            assert_eq!(restored_group.epoch(), epoch_before_replay);
            assert_bidirectional_liveness(
                &mut restored_group,
                &restored_provider,
                &restored_identity,
                &mut bob_group,
                &bob_provider,
                &bob,
            );
        }

        #[test]
        fn current_profile_structure_and_exact_negative_decoders() {
            let provider = Provider::new();
            let founder = new_identity(&provider, 0x51);
            let group = create_current_group(&provider, &founder, b"phase-b2-profile");
            assert_current_profile(&group, &founder.account_public_key).unwrap();

            let missing_proposal =
                current_group_context_extensions(&founder.account_public_key, false);
            let missing_result =
                assert_current_group_context(&missing_proposal, &founder.account_public_key);
            assert_eq!(
                missing_result.unwrap_err(),
                "test-only exact profile decoder: app_data_update missing"
            );

            let duplicate_entries = vec![
                ComponentData::from_parts(ADMIN_POLICY_V1_COMPONENT_ID, vec![0].into()),
                ComponentData::from_parts(ADMIN_POLICY_V1_COMPONENT_ID, vec![1].into()),
            ]
            .tls_serialize_detached()
            .unwrap();
            assert!(AppDataDictionary::tls_deserialize_exact(&duplicate_entries).is_err());

            let valid_dictionary = current_group_context_extensions(
                &founder.account_public_key,
                true,
            )
            .app_data_dictionary()
            .unwrap()
            .dictionary()
            .tls_serialize_detached()
            .unwrap();
            let mut malformed = valid_dictionary.clone();
            malformed.pop();
            assert!(AppDataDictionary::tls_deserialize_exact(&malformed).is_err());
            let mut trailing = valid_dictionary;
            trailing.push(0);
            assert!(AppDataDictionary::tls_deserialize_exact(&trailing).is_err());
        }
    }
}
