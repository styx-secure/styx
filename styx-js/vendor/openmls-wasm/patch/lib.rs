mod utils;

use std::cell::Cell;

use js_sys::Uint8Array;
#[cfg(feature = "extensions-draft")]
use openmls::{
    component::ComponentId,
    extensions::{
        AppDataDictionary, AppDataDictionaryExtension, Extension, ExtensionType, Extensions,
        RequiredCapabilitiesExtension,
    },
    group::{GroupContext, StagedCommit, PURE_PLAINTEXT_WIRE_FORMAT_POLICY},
    key_packages::Lifetime,
    messages::proposals::{Proposal, ProposalOrRefType, ProposalType},
    prelude::{Capabilities, LeafNode, LeafNodeParameters},
};
use openmls::{
    credentials::{BasicCredential, CredentialWithKey},
    framing::{MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProtocolMessage, Sender},
    group::{GroupId, MlsGroup, MlsGroupJoinConfig, StagedWelcome},
    key_packages::KeyPackage as OpenMlsKeyPackage,
    prelude::SignatureScheme,
    treesync::RatchetTreeIn,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, VerifiableCiphersuite},
    OpenMlsProvider,
};
use tls_codec::{Deserialize, Serialize, Size};
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
static PROBE_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
#[cfg(feature = "extensions-draft")]
const ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID: ComponentId = 0x8009;
#[cfg(feature = "extensions-draft")]
const ACCOUNT_IDENTITY_PROOF_V2_LENGTH: usize = 104;
#[cfg(feature = "extensions-draft")]
const PROBE_KEY_PACKAGE_LIFETIME_SECONDS: u64 = 7 * 24 * 60 * 60;
#[cfg(feature = "extensions-draft")]
const ADMIN_POLICY_V1_COMPONENT_ID: ComponentId = 0x8003;
#[cfg(feature = "extensions-draft")]
const GROUP_LIFECYCLE_V1_COMPONENT_ID: ComponentId = 0x800c;
#[cfg(feature = "extensions-draft")]
const PHASE_B2_COMPONENTS: [ComponentId; 3] = [
    ADMIN_POLICY_V1_COMPONENT_ID,
    ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID,
    GROUP_LIFECYCLE_V1_COMPONENT_ID,
];
#[cfg(feature = "extensions-draft")]
const PHASE_B2_MAX_PROPOSALS: usize = 32;
#[cfg(feature = "extensions-draft")]
const PHASE_B2_MAX_ADDS: usize = 8;
#[cfg(feature = "extensions-draft")]
const PHASE_B2_MAX_MEMBERS: usize = 4096;
#[cfg(feature = "extensions-draft")]
const PHASE_B2_MAX_COMPONENTS: usize = 64;
#[cfg(feature = "extensions-draft")]
const PHASE_B2_MAX_GROUP_CONTEXT_BYTES: usize = 1_048_576;
#[cfg(feature = "extensions-draft")]
const PHASE_B2_DIGEST_DOMAIN: &[u8; 26] = b"STYX-B2-VERIFIED-LEAVES-v1";

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
            let end = i
                .checked_add(8)
                .filter(|&e| e <= bytes.len())
                .ok_or_else(|| err("len"))?;
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
            let k_end = i
                .checked_add(kl)
                .filter(|&e| e <= bytes.len())
                .ok_or_else(|| err("k"))?;
            let k = bytes[i..k_end].to_vec();
            i = k_end;
            let v_end = i
                .checked_add(vl)
                .filter(|&e| e <= bytes.len())
                .ok_or_else(|| err("v"))?;
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
        match SignatureKeyPair::read(
            provider.inner.storage(),
            public_key,
            SignatureScheme::ED25519,
        ) {
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
            return Err(JsError::new(
                "phase-b1 handle: invalidated by provider restore",
            ));
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
impl PhaseB1Identity {
    fn load_recovery(
        provider: &Provider,
        account_public_key: &[u8],
        leaf_signature_key: &[u8],
    ) -> Result<Option<PhaseB1Identity>, &'static str> {
        if account_public_key.len() != 32 {
            return Err("phase-b1 identity: account public key must be exactly 32 bytes");
        }
        if leaf_signature_key.len() != 32 {
            return Err("phase-b1 identity: leaf signature key must be exactly 32 bytes");
        }
        let Some(keypair) = SignatureKeyPair::read(
            provider.inner.storage(),
            leaf_signature_key,
            SignatureScheme::ED25519,
        ) else {
            return Ok(None);
        };
        if keypair.public() != leaf_signature_key {
            return Err("phase-b1 identity: loaded signing key does not match");
        }
        let credential = BasicCredential::new(account_public_key.to_vec());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: keypair.public().into(),
        };
        Ok(Some(Self {
            account_public_key: account_public_key.to_vec(),
            credential_with_key,
            keypair,
        }))
    }
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

    pub fn load(
        provider: &Provider,
        account_public_key: &[u8],
        leaf_signature_key: &[u8],
    ) -> Result<Option<PhaseB1Identity>, JsError> {
        Self::load_recovery(provider, account_public_key, leaf_signature_key).map_err(JsError::new)
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
        let mls_group = StagedWelcome::new_from_welcome(
            &provider.inner,
            &config,
            welcome,
            Some(ratchet_tree.0),
        )?
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
fn phase_b2_capabilities() -> Capabilities {
    Capabilities::builder()
        .ciphersuites(vec![PROBE_CIPHERSUITE])
        .extensions(vec![ExtensionType::AppDataDictionary])
        .proposals(vec![ProposalType::AppDataUpdate])
        .build()
}

#[cfg(feature = "extensions-draft")]
fn phase_b2_check_identity_proof(
    account_public_key: &[u8],
    proof: &[u8],
) -> Result<(), &'static str> {
    if account_public_key.len() != 32 {
        return Err("phase-b2 identity: account key must be exactly 32 bytes");
    }
    if proof.len() != ACCOUNT_IDENTITY_PROOF_V2_LENGTH {
        return Err("phase-b2 identity: proof must be exactly 104 bytes");
    }
    if proof[..32] != *account_public_key {
        return Err("phase-b2 identity: proof signer does not match credential identity");
    }
    Ok(())
}

#[cfg(feature = "extensions-draft")]
fn phase_b2_check_component_profile(
    component_ids: &[u16],
    supported_component_ids: &[u16],
) -> Result<(), &'static str> {
    if component_ids.len() > PHASE_B2_MAX_COMPONENTS
        || supported_component_ids.len() > PHASE_B2_MAX_COMPONENTS
    {
        return Err("PHASE_B2_COMPONENT_LIMIT");
    }
    if component_ids != [1, ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID] {
        return Err("phase-b2 leaf: unexpected component locations");
    }
    if supported_component_ids != PHASE_B2_COMPONENTS {
        return Err("phase-b2 leaf: unexpected supported components");
    }
    Ok(())
}

#[cfg(feature = "extensions-draft")]
fn phase_b2_check_leaf_capabilities(capabilities: &Capabilities) -> Result<(), &'static str> {
    if capabilities != &phase_b2_capabilities() {
        return Err("phase-b2 leaf: unexpected capabilities");
    }
    Ok(())
}

#[cfg(feature = "extensions-draft")]
fn phase_b2_check_key_package_metadata(
    ciphersuite: Ciphersuite,
    last_resort: bool,
    acceptable_lifetime: bool,
    lifetime_seconds: u64,
) -> Result<(), &'static str> {
    if ciphersuite != PROBE_CIPHERSUITE {
        return Err("phase-b2 key package: unexpected ciphersuite");
    }
    if last_resort {
        return Err("phase-b2 key package: last-resort package is not accepted");
    }
    if !acceptable_lifetime || lifetime_seconds > PROBE_KEY_PACKAGE_LIFETIME_SECONDS + 60 * 60 {
        return Err("phase-b2 key package: lifetime exceeds bounded profile");
    }
    Ok(())
}

#[cfg(feature = "extensions-draft")]
fn phase_b2_check_required_profile(
    extension_types: &[ExtensionType],
    proposal_types: &[ProposalType],
    credential_count: usize,
    required_components: &[u16],
) -> Result<(), &'static str> {
    if extension_types != [ExtensionType::AppDataDictionary]
        || proposal_types != [ProposalType::AppDataUpdate]
        || credential_count != 0
    {
        return Err("phase-b2 group: unexpected required capabilities");
    }
    if required_components != PHASE_B2_COMPONENTS {
        return Err("phase-b2 group: unexpected required components");
    }
    Ok(())
}

#[cfg(feature = "extensions-draft")]
fn phase_b2_leaf_extensions(proof: &[u8]) -> Result<Extensions<LeafNode>, JsError> {
    if proof.len() != ACCOUNT_IDENTITY_PROOF_V2_LENGTH {
        return Err(JsError::new(
            "phase-b2 identity: proof must be exactly 104 bytes",
        ));
    }
    let supported = PHASE_B2_COMPONENTS
        .to_vec()
        .tls_serialize_detached()
        .map_err(|_| JsError::new("phase-b2 identity: component encoding failed"))?;
    let mut dictionary = AppDataDictionary::new();
    dictionary.insert(1, supported);
    dictionary.insert(ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID, proof.to_vec());
    Extensions::single(Extension::AppDataDictionary(
        AppDataDictionaryExtension::new(dictionary),
    ))
    .map_err(|_| JsError::new("phase-b2 identity: leaf extension construction failed"))
}

#[cfg(feature = "extensions-draft")]
fn phase_b2_group_context_extensions(
    founder_account: &[u8],
) -> Result<Extensions<GroupContext>, JsError> {
    if founder_account.len() != 32 {
        return Err(JsError::new(
            "phase-b2 group: founder account key must be exactly 32 bytes",
        ));
    }
    let mut dictionary = AppDataDictionary::new();
    dictionary.insert(
        1,
        PHASE_B2_COMPONENTS
            .to_vec()
            .tls_serialize_detached()
            .map_err(|_| JsError::new("phase-b2 group: component encoding failed"))?,
    );
    let mut admin_policy = vec![0x20];
    admin_policy.extend_from_slice(founder_account);
    dictionary.insert(ADMIN_POLICY_V1_COMPONENT_ID, admin_policy);
    dictionary.insert(GROUP_LIFECYCLE_V1_COMPONENT_ID, vec![0x00]);
    Extensions::from_vec(vec![
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::AppDataDictionary],
            &[ProposalType::AppDataUpdate],
            &[],
        )),
        Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary)),
    ])
    .map_err(|_| JsError::new("phase-b2 group: GroupContext extension construction failed"))
}

#[cfg(feature = "extensions-draft")]
fn phase_b2_decode_admin_policy_recovery(bytes: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    let first = *bytes
        .first()
        .ok_or("phase-b2 group: administrator policy is empty")?;
    let prefix_len = match first >> 6 {
        0 => 1usize,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };
    if bytes.len() < prefix_len {
        return Err("phase-b2 group: malformed administrator policy length");
    }
    let mut declared = u64::from(first & 0x3f);
    for byte in &bytes[1..prefix_len] {
        declared = (declared << 8) | u64::from(*byte);
    }
    let canonical = match prefix_len {
        1 => true,
        2 => declared >= (1 << 6),
        4 => declared >= (1 << 14),
        8 => declared >= (1 << 30),
        _ => false,
    };
    if !canonical
        || usize::try_from(declared).ok() != Some(bytes.len() - prefix_len)
        || declared == 0
        || declared % 32 != 0
    {
        return Err("phase-b2 group: malformed administrator policy length");
    }
    let admins: Vec<Vec<u8>> = bytes[prefix_len..]
        .chunks_exact(32)
        .map(|chunk| chunk.to_vec())
        .collect();
    if admins.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("phase-b2 group: administrator policy must be sorted and unique");
    }
    Ok(admins)
}

#[cfg(feature = "extensions-draft")]
fn phase_b2_validate_leaf(leaf: &LeafNode) -> Result<PhaseB2Member, JsError> {
    let identity = leaf.credential().serialized_content();
    if identity.len() != 32 || leaf.signature_key().as_slice().len() != 32 {
        return Err(JsError::new(
            "phase-b2 leaf: identity and signature key must be exactly 32 bytes",
        ));
    }
    phase_b2_check_leaf_capabilities(leaf.capabilities()).map_err(JsError::new)?;
    let dictionary = leaf
        .extensions()
        .app_data_dictionary()
        .ok_or_else(|| JsError::new("phase-b2 leaf: app-data dictionary missing"))?
        .dictionary();
    if dictionary.len() != 2 {
        return Err(JsError::new(
            "phase-b2 leaf: app-data dictionary must have exactly two entries",
        ));
    }
    let component_ids: Vec<u16> = dictionary.entries().map(|entry| entry.id()).collect();
    let supported_bytes = dictionary
        .get(&1)
        .ok_or_else(|| JsError::new("phase-b2 leaf: supported components missing"))?;
    if supported_bytes.len() > 2 + PHASE_B2_MAX_COMPONENTS * 2 {
        return Err(JsError::new("PHASE_B2_COMPONENT_LIMIT"));
    }
    let supported_component_ids = Vec::<u16>::tls_deserialize_exact(supported_bytes)
        .map_err(|_| JsError::new("phase-b2 leaf: malformed supported components"))?;
    phase_b2_check_component_profile(&component_ids, &supported_component_ids)
        .map_err(JsError::new)?;
    let proof = dictionary
        .get(&ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID)
        .ok_or_else(|| JsError::new("phase-b2 leaf: identity proof missing"))?;
    phase_b2_check_identity_proof(identity, proof).map_err(JsError::new)?;
    Ok(PhaseB2Member {
        leaf_index: 0,
        credential_identity: identity.to_vec(),
        leaf_signature_key: leaf.signature_key().as_slice().to_vec(),
        identity_proof: proof.to_vec(),
        component_ids,
        supported_component_ids,
    })
}

#[cfg(feature = "extensions-draft")]
fn phase_b2_validate_group_context(
    context: &GroupContext,
    member_identities: &[Vec<u8>],
) -> Result<PhaseB2GroupContext, JsError> {
    let serialized_len = context.tls_serialized_len();
    if serialized_len > PHASE_B2_MAX_GROUP_CONTEXT_BYTES {
        return Err(JsError::new("PHASE_B2_GROUP_CONTEXT_LIMIT"));
    }
    let required = context
        .required_capabilities()
        .ok_or_else(|| JsError::new("phase-b2 group: required capabilities missing"))?;
    let dictionary = context
        .extensions()
        .app_data_dictionary()
        .ok_or_else(|| JsError::new("phase-b2 group: app-data dictionary missing"))?
        .dictionary();
    let ids: Vec<u16> = dictionary.entries().map(|entry| entry.id()).collect();
    if ids
        != [
            1,
            ADMIN_POLICY_V1_COMPONENT_ID,
            GROUP_LIFECYCLE_V1_COMPONENT_ID,
        ]
    {
        return Err(JsError::new(
            "phase-b2 group: unexpected GroupContext components",
        ));
    }
    let required_components = Vec::<u16>::tls_deserialize_exact(
        dictionary
            .get(&1)
            .ok_or_else(|| JsError::new("phase-b2 group: required components missing"))?,
    )
    .map_err(|_| JsError::new("phase-b2 group: malformed required components"))?;
    phase_b2_check_required_profile(
        required.extension_types(),
        required.proposal_types(),
        required.credential_types().len(),
        &required_components,
    )
    .map_err(JsError::new)?;
    let administrator_policy = dictionary
        .get(&ADMIN_POLICY_V1_COMPONENT_ID)
        .ok_or_else(|| JsError::new("phase-b2 group: administrator policy missing"))?
        .to_vec();
    let admins =
        phase_b2_decode_admin_policy_recovery(&administrator_policy).map_err(JsError::new)?;
    if admins
        .iter()
        .any(|admin| !member_identities.iter().any(|member| member == admin))
    {
        return Err(JsError::new(
            "phase-b2 group: administrator is not a candidate member",
        ));
    }
    let lifecycle = dictionary
        .get(&GROUP_LIFECYCLE_V1_COMPONENT_ID)
        .ok_or_else(|| JsError::new("phase-b2 group: lifecycle missing"))?
        .to_vec();
    if lifecycle != [0x00] {
        return Err(JsError::new("phase-b2 group: lifecycle is not active"));
    }
    let tls = context
        .tls_serialize_detached()
        .map_err(|_| JsError::new("phase-b2 group: GroupContext serialization failed"))?;
    Ok(PhaseB2GroupContext {
        tls,
        required_components,
        administrator_policy,
        lifecycle,
    })
}

/// Current-profile identity with an independent Ed25519 MLS signing key.
#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
pub struct PhaseB2Identity {
    account_public_key: Vec<u8>,
    credential_with_key: CredentialWithKey,
    keypair: SignatureKeyPair,
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB2Identity {
    #[wasm_bindgen(constructor)]
    pub fn new(provider: &Provider, account_public_key: &[u8]) -> Result<PhaseB2Identity, JsError> {
        if account_public_key.len() != 32 {
            return Err(JsError::new(
                "phase-b2 identity: account public key must be exactly 32 bytes",
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

    pub fn load(
        provider: &Provider,
        account_public_key: &[u8],
        leaf_signature_key: &[u8],
    ) -> Result<Option<PhaseB2Identity>, JsError> {
        if account_public_key.len() != 32 || leaf_signature_key.len() != 32 {
            return Err(JsError::new(
                "phase-b2 identity: identity inputs must be exactly 32 bytes",
            ));
        }
        let Some(keypair) = SignatureKeyPair::read(
            provider.inner.storage(),
            leaf_signature_key,
            SignatureScheme::ED25519,
        ) else {
            return Ok(None);
        };
        if keypair.public() != leaf_signature_key {
            return Err(JsError::new("phase-b2 identity: loaded key does not match"));
        }
        let credential = BasicCredential::new(account_public_key.to_vec());
        Ok(Some(Self {
            account_public_key: account_public_key.to_vec(),
            credential_with_key: CredentialWithKey {
                credential: credential.into(),
                signature_key: keypair.public().into(),
            },
            keypair,
        }))
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
    ) -> Result<PhaseB2KeyPackage, JsError> {
        phase_b2_check_identity_proof(&self.account_public_key, proof).map_err(JsError::new)?;
        let key_package = OpenMlsKeyPackage::builder()
            .key_package_lifetime(Lifetime::new(PROBE_KEY_PACKAGE_LIFETIME_SECONDS))
            .leaf_node_capabilities(phase_b2_capabilities())
            .leaf_node_extensions(phase_b2_leaf_extensions(proof)?)
            .build(
                PROBE_CIPHERSUITE,
                &provider.inner,
                &self.keypair,
                self.credential_with_key.clone(),
            )?
            .key_package()
            .clone();
        phase_b2_inspect_key_package(&key_package)?;
        Ok(PhaseB2KeyPackage(key_package))
    }
}

#[cfg(feature = "extensions-draft")]
fn phase_b2_inspect_key_package(key_package: &OpenMlsKeyPackage) -> Result<PhaseB2Member, JsError> {
    let lifetime = key_package.life_time();
    phase_b2_check_key_package_metadata(
        key_package.ciphersuite(),
        key_package.last_resort(),
        lifetime.has_acceptable_range(),
        lifetime.not_after().saturating_sub(lifetime.not_before()),
    )
    .map_err(JsError::new)?;
    phase_b2_validate_leaf(key_package.leaf_node())
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
pub struct PhaseB2KeyPackage(OpenMlsKeyPackage);

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB2KeyPackage {
    pub fn to_framed_bytes(&self) -> Result<Vec<u8>, JsError> {
        MlsMessageOut::from(self.0.clone())
            .tls_serialize_detached()
            .map_err(|_| JsError::new("phase-b2 key package: framing failed"))
    }

    pub fn from_framed_bytes(bytes: &[u8]) -> Result<PhaseB2KeyPackage, JsError> {
        let message = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(|_| JsError::new("phase-b2 key package: malformed MLSMessage framing"))?;
        let input = match message.extract() {
            MlsMessageBodyIn::KeyPackage(key_package) => key_package,
            _ => {
                return Err(JsError::new(
                    "phase-b2 key package: MLSMessage does not contain a KeyPackage",
                ));
            }
        };
        let key_package = input
            .validate(
                &openmls_rust_crypto::RustCrypto::default(),
                openmls::prelude::ProtocolVersion::Mls10,
            )
            .map_err(|_| JsError::new("phase-b2 key package: validation failed"))?;
        phase_b2_inspect_key_package(&key_package)?;
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
            .expect("validated Phase B2 KeyPackage")
            .dictionary()
            .get(&ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID)
            .expect("validated Phase B2 KeyPackage")
            .to_vec()
    }

    pub fn component_ids(&self) -> Vec<u16> {
        self.0
            .leaf_node()
            .extensions()
            .app_data_dictionary()
            .expect("validated Phase B2 KeyPackage")
            .dictionary()
            .entries()
            .map(|entry| entry.id())
            .collect()
    }

    pub fn supported_component_ids(&self) -> Vec<u16> {
        PHASE_B2_COMPONENTS.to_vec()
    }

    pub fn is_last_resort(&self) -> bool {
        self.0.last_resort()
    }
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
pub struct PhaseB2RatchetTree(RatchetTreeIn);

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB2RatchetTree {
    pub fn to_bytes(&self) -> Result<Vec<u8>, JsError> {
        self.0
            .tls_serialize_detached()
            .map_err(|_| JsError::new("phase-b2 ratchet tree: serialization failed"))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<PhaseB2RatchetTree, JsError> {
        let tree = RatchetTreeIn::tls_deserialize_exact(bytes)
            .map_err(|_| JsError::new("phase-b2 ratchet tree: malformed input"))?;
        Ok(Self(tree))
    }
}

#[cfg(feature = "extensions-draft")]
#[derive(Clone, PartialEq, Eq)]
struct PhaseB2Member {
    leaf_index: u32,
    credential_identity: Vec<u8>,
    leaf_signature_key: Vec<u8>,
    identity_proof: Vec<u8>,
    component_ids: Vec<u16>,
    supported_component_ids: Vec<u16>,
}

#[cfg(feature = "extensions-draft")]
#[derive(Clone, PartialEq, Eq)]
struct PhaseB2GroupContext {
    tls: Vec<u8>,
    required_components: Vec<u16>,
    administrator_policy: Vec<u8>,
    lifecycle: Vec<u8>,
}

#[cfg(feature = "extensions-draft")]
#[derive(Clone, PartialEq, Eq)]
struct PhaseB2ProposalProjection {
    kind: &'static str,
    sender_leaf_index: u32,
    added_member: Option<PhaseB2Member>,
    removed_parent_leaf_index: Option<u32>,
    removed_member: Option<PhaseB2Member>,
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
#[derive(Clone, PartialEq, Eq)]
pub struct PhaseB2CommitProjection {
    prior_epoch: u64,
    candidate_epoch: u64,
    committer_leaf_index: u32,
    committer_identity: Vec<u8>,
    committer_signature_key: Vec<u8>,
    proposals: Vec<PhaseB2ProposalProjection>,
    update_path_leaf: Option<PhaseB2Member>,
    candidate_members: Vec<PhaseB2Member>,
    group_context: PhaseB2GroupContext,
    group_context_sha256: Vec<u8>,
    verified_leaf_digest: Vec<u8>,
}

#[cfg(feature = "extensions-draft")]
fn phase_b2_member_at(group: &MlsGroup, leaf_index: u32) -> Result<PhaseB2Member, JsError> {
    let index = openmls::prelude::LeafNodeIndex::new(leaf_index);
    let member = group
        .members()
        .find(|member| member.index == index)
        .ok_or_else(|| JsError::new("phase-b2 projection: member leaf index is absent"))?;
    let leaf = group
        .public_group()
        .leaf(index)
        .ok_or_else(|| JsError::new("phase-b2 projection: member leaf is absent"))?;
    let mut projected = phase_b2_validate_leaf(leaf)?;
    if projected.credential_identity != member.credential.serialized_content()
        || projected.leaf_signature_key != member.signature_key
    {
        return Err(JsError::new(
            "phase-b2 projection: member metadata disagrees with leaf",
        ));
    }
    projected.leaf_index = leaf_index;
    Ok(projected)
}

#[cfg(feature = "extensions-draft")]
fn phase_b2_group_projection(
    group: &MlsGroup,
) -> Result<(Vec<PhaseB2Member>, PhaseB2GroupContext), JsError> {
    if group.ciphersuite() != PROBE_CIPHERSUITE
        || !group.is_active()
        || group.own_leaf_node().is_none()
        || group.group_id().as_slice().is_empty()
        || group.group_id().as_slice().len() > 64
    {
        return Err(JsError::new("phase-b2 group: unexpected profile"));
    }
    let count = group.members().count();
    if count > PHASE_B2_MAX_MEMBERS {
        return Err(JsError::new("PHASE_B2_MEMBER_LIMIT"));
    }
    if count == 0 {
        return Err(JsError::new("phase-b2 group: no occupied member leaf"));
    }
    let mut members = Vec::with_capacity(count);
    for member in group.members() {
        members.push(phase_b2_member_at(group, member.index.u32())?);
    }
    members.sort_by_key(|member| member.leaf_index);
    let identities: Vec<Vec<u8>> = members
        .iter()
        .map(|member| member.credential_identity.clone())
        .collect();
    let context =
        phase_b2_validate_group_context(group.public_group().group_context(), &identities)?;
    Ok((members, context))
}

#[cfg(feature = "extensions-draft")]
fn phase_b2_verified_leaf_digest(
    crypto: &impl OpenMlsCrypto,
    members: &[PhaseB2Member],
) -> Result<Vec<u8>, JsError> {
    if members.len() > PHASE_B2_MAX_MEMBERS {
        return Err(JsError::new("PHASE_B2_MEMBER_LIMIT"));
    }
    let payload_len = 27usize
        .checked_add(4)
        .and_then(|len| len.checked_add(172usize.checked_mul(members.len())?))
        .ok_or_else(|| JsError::new("PHASE_B2_MEMBER_LIMIT"))?;
    let mut payload = Vec::with_capacity(payload_len);
    payload.extend_from_slice(PHASE_B2_DIGEST_DOMAIN);
    payload.push(0);
    payload.extend_from_slice(&(members.len() as u32).to_be_bytes());
    for member in members {
        if member.credential_identity.len() != 32
            || member.leaf_signature_key.len() != 32
            || member.identity_proof.len() != ACCOUNT_IDENTITY_PROOF_V2_LENGTH
        {
            return Err(JsError::new(
                "phase-b2 digest: candidate member has malformed fields",
            ));
        }
        payload.extend_from_slice(&member.leaf_index.to_be_bytes());
        payload.extend_from_slice(&member.credential_identity);
        payload.extend_from_slice(&member.leaf_signature_key);
        payload.extend_from_slice(&member.identity_proof);
    }
    if payload.len() != payload_len {
        return Err(JsError::new("phase-b2 digest: internal length mismatch"));
    }
    crypto
        .hash(PROBE_CIPHERSUITE.hash_algorithm(), &payload)
        .map_err(|_| JsError::new("phase-b2 digest: SHA-256 failed"))
}

#[cfg(feature = "extensions-draft")]
fn phase_b2_check_verified_leaf_digest(
    supplied: &[u8],
    expected: &[u8],
) -> Result<(), &'static str> {
    if supplied.len() != 32 || supplied != expected {
        return Err("phase-b2 commit: verified-leaf digest mismatch");
    }
    Ok(())
}

#[cfg(feature = "extensions-draft")]
fn phase_b2_check_projection_bounds(
    proposal_count: usize,
    add_count: usize,
    member_count: usize,
    group_context_bytes: usize,
) -> Result<(), &'static str> {
    if proposal_count > PHASE_B2_MAX_PROPOSALS {
        return Err("PHASE_B2_PROPOSAL_LIMIT");
    }
    if add_count > PHASE_B2_MAX_ADDS {
        return Err("PHASE_B2_ADD_LIMIT");
    }
    if member_count > PHASE_B2_MAX_MEMBERS {
        return Err("PHASE_B2_MEMBER_LIMIT");
    }
    if group_context_bytes > PHASE_B2_MAX_GROUP_CONTEXT_BYTES {
        return Err("PHASE_B2_GROUP_CONTEXT_LIMIT");
    }
    Ok(())
}

#[cfg(feature = "extensions-draft")]
fn phase_b2_member_sender(sender: &Sender, error: &'static str) -> Result<u32, JsError> {
    match sender {
        Sender::Member(index) => Ok(index.u32()),
        Sender::External(_) | Sender::NewMemberProposal | Sender::NewMemberCommit => {
            Err(JsError::new(error))
        }
    }
}

#[cfg(feature = "extensions-draft")]
#[derive(Clone, Copy)]
enum PhaseB2ProposalKind {
    Add,
    Remove,
    Update,
    AppDataUpdate,
    Custom,
    Other,
}

#[cfg(feature = "extensions-draft")]
fn phase_b2_proposal_kind(proposal: &Proposal) -> PhaseB2ProposalKind {
    match proposal {
        Proposal::Add(_) => PhaseB2ProposalKind::Add,
        Proposal::Remove(_) => PhaseB2ProposalKind::Remove,
        Proposal::Update(_) => PhaseB2ProposalKind::Update,
        Proposal::AppDataUpdate(_) => PhaseB2ProposalKind::AppDataUpdate,
        Proposal::Custom(_) => PhaseB2ProposalKind::Custom,
        Proposal::PreSharedKey(_)
        | Proposal::ReInit(_)
        | Proposal::ExternalInit(_)
        | Proposal::GroupContextExtensions(_)
        | Proposal::SelfRemove
        | Proposal::AppEphemeral(_) => PhaseB2ProposalKind::Other,
    }
}

#[cfg(feature = "extensions-draft")]
fn phase_b2_check_proposal_policy(
    source: ProposalOrRefType,
    kind: PhaseB2ProposalKind,
) -> Result<(), &'static str> {
    if source != ProposalOrRefType::Proposal {
        return Err("PHASE_B2_REFERENCED_PROPOSAL_UNSUPPORTED");
    }
    match kind {
        PhaseB2ProposalKind::Add | PhaseB2ProposalKind::Remove => Ok(()),
        PhaseB2ProposalKind::Update => Err("PHASE_B2_PROPOSAL_UPDATE_UNSUPPORTED"),
        PhaseB2ProposalKind::AppDataUpdate => Err("PHASE_B2_APP_DATA_UPDATE_UNSUPPORTED"),
        PhaseB2ProposalKind::Custom => Err("PHASE_B2_CUSTOM_PROPOSAL_UNSUPPORTED"),
        PhaseB2ProposalKind::Other => Err("PHASE_B2_PROPOSAL_KIND_UNSUPPORTED"),
    }
}

#[cfg(feature = "extensions-draft")]
fn phase_b2_projection(
    crypto: &impl OpenMlsCrypto,
    parent: &MlsGroup,
    staged: &StagedCommit,
    candidate: &MlsGroup,
    committer_leaf_index: u32,
) -> Result<PhaseB2CommitProjection, JsError> {
    let prior_epoch = parent.epoch().as_u64();
    let candidate_epoch = staged.epoch().as_u64();
    if candidate_epoch != prior_epoch.saturating_add(1)
        || candidate.epoch().as_u64() != candidate_epoch
    {
        return Err(JsError::new(
            "phase-b2 projection: unexpected epoch transition",
        ));
    }
    let committer = phase_b2_member_at(parent, committer_leaf_index)
        .map_err(|_| JsError::new("phase-b2 projection: committer is not a parent member"))?;
    let proposal_count = staged.queued_proposals().count();
    let add_count = staged
        .queued_proposals()
        .filter(|queued| matches!(queued.proposal(), Proposal::Add(_)))
        .count();
    phase_b2_check_projection_bounds(proposal_count, add_count, 0, 0)
        .map_err(JsError::new)?;
    let mut proposals = Vec::with_capacity(proposal_count);
    for queued in staged.queued_proposals() {
        phase_b2_check_proposal_policy(
            queued.proposal_or_ref_type(),
            phase_b2_proposal_kind(queued.proposal()),
        )
        .map_err(JsError::new)?;
        let sender_leaf_index =
            phase_b2_member_sender(queued.sender(), "PHASE_B2_PROPOSAL_KIND_UNSUPPORTED")?;
        match queued.proposal() {
            Proposal::Add(add) => {
                let mut added = phase_b2_inspect_key_package(add.key_package())?;
                let candidate_match = candidate
                    .members()
                    .filter_map(|member| {
                        let leaf = candidate.public_group().leaf(member.index)?;
                        if leaf.credential().serialized_content() == added.credential_identity
                            && leaf.signature_key().as_slice() == added.leaf_signature_key
                        {
                            Some(member.index.u32())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                if candidate_match.len() != 1 {
                    return Err(JsError::new(
                        "phase-b2 projection: added member is ambiguous in candidate tree",
                    ));
                }
                added.leaf_index = candidate_match[0];
                proposals.push(PhaseB2ProposalProjection {
                    kind: "add",
                    sender_leaf_index,
                    added_member: Some(added),
                    removed_parent_leaf_index: None,
                    removed_member: None,
                });
            }
            Proposal::Remove(remove) => {
                let removed_index = remove.removed().u32();
                proposals.push(PhaseB2ProposalProjection {
                    kind: "remove",
                    sender_leaf_index,
                    added_member: None,
                    removed_parent_leaf_index: Some(removed_index),
                    removed_member: Some(phase_b2_member_at(parent, removed_index)?),
                });
            }
            Proposal::Update(_) | Proposal::AppDataUpdate(_) | Proposal::Custom(_) => {
                unreachable!("unsupported proposal was rejected by the policy check")
            }
            Proposal::PreSharedKey(_)
            | Proposal::ReInit(_)
            | Proposal::ExternalInit(_)
            | Proposal::GroupContextExtensions(_)
            | Proposal::SelfRemove
            | Proposal::AppEphemeral(_) => {
                unreachable!("unsupported proposal was rejected by the policy check")
            }
        }
    }
    let update_path_leaf = staged
        .update_path_leaf_node()
        .map(phase_b2_validate_leaf)
        .transpose()?
        .map(|mut member| {
            member.leaf_index = committer_leaf_index;
            member
        });
    if let Some(update_leaf) = &update_path_leaf {
        let candidate_committer = phase_b2_member_at(candidate, committer_leaf_index)?;
        if update_leaf != &candidate_committer {
            return Err(JsError::new(
                "phase-b2 projection: update-path leaf disagrees with candidate tree",
            ));
        }
    }
    let (candidate_members, group_context) = phase_b2_group_projection(candidate)?;
    let staged_context_tls = staged
        .group_context()
        .tls_serialize_detached()
        .map_err(|_| JsError::new("phase-b2 projection: GroupContext serialization failed"))?;
    if staged_context_tls != group_context.tls {
        return Err(JsError::new(
            "phase-b2 projection: staged and candidate GroupContext disagree",
        ));
    }
    let group_context_sha256 = crypto
        .hash(PROBE_CIPHERSUITE.hash_algorithm(), &group_context.tls)
        .map_err(|_| JsError::new("phase-b2 projection: GroupContext hash failed"))?;
    let verified_leaf_digest = phase_b2_verified_leaf_digest(crypto, &candidate_members)?;
    Ok(PhaseB2CommitProjection {
        prior_epoch,
        candidate_epoch,
        committer_leaf_index,
        committer_identity: committer.credential_identity,
        committer_signature_key: committer.leaf_signature_key,
        proposals,
        update_path_leaf,
        candidate_members,
        group_context,
        group_context_sha256,
        verified_leaf_digest,
    })
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB2CommitProjection {
    pub fn prior_epoch(&self) -> u64 {
        self.prior_epoch
    }
    pub fn candidate_epoch(&self) -> u64 {
        self.candidate_epoch
    }
    pub fn committer_source(&self) -> String {
        "member".into()
    }
    pub fn committer_leaf_index(&self) -> u32 {
        self.committer_leaf_index
    }
    pub fn committer_identity(&self) -> Vec<u8> {
        self.committer_identity.clone()
    }
    pub fn committer_signature_key(&self) -> Vec<u8> {
        self.committer_signature_key.clone()
    }
    pub fn proposal_count(&self) -> u32 {
        self.proposals.len() as u32
    }
    pub fn proposal_kind(&self, index: usize) -> Result<String, JsError> {
        self.proposals
            .get(index)
            .map(|proposal| proposal.kind.into())
            .ok_or_else(|| JsError::new("phase-b2 projection: proposal index out of range"))
    }
    pub fn proposal_source(&self, index: usize) -> Result<String, JsError> {
        self.proposals
            .get(index)
            .map(|_| "inline".into())
            .ok_or_else(|| JsError::new("phase-b2 projection: proposal index out of range"))
    }
    pub fn proposal_sender_source(&self, index: usize) -> Result<String, JsError> {
        self.proposals
            .get(index)
            .map(|_| "member".into())
            .ok_or_else(|| JsError::new("phase-b2 projection: proposal index out of range"))
    }
    pub fn proposal_sender_leaf_index(&self, index: usize) -> Result<u32, JsError> {
        self.proposals
            .get(index)
            .map(|proposal| proposal.sender_leaf_index)
            .ok_or_else(|| JsError::new("phase-b2 projection: proposal index out of range"))
    }
    pub fn proposal_added_leaf_index(&self, index: usize) -> Result<Option<u32>, JsError> {
        self.proposals
            .get(index)
            .map(|proposal| {
                proposal
                    .added_member
                    .as_ref()
                    .map(|member| member.leaf_index)
            })
            .ok_or_else(|| JsError::new("phase-b2 projection: proposal index out of range"))
    }
    pub fn proposal_added_identity(&self, index: usize) -> Result<Option<Vec<u8>>, JsError> {
        self.proposals
            .get(index)
            .map(|proposal| {
                proposal
                    .added_member
                    .as_ref()
                    .map(|member| member.credential_identity.clone())
            })
            .ok_or_else(|| JsError::new("phase-b2 projection: proposal index out of range"))
    }
    pub fn proposal_added_signature_key(&self, index: usize) -> Result<Option<Vec<u8>>, JsError> {
        self.proposals
            .get(index)
            .map(|proposal| {
                proposal
                    .added_member
                    .as_ref()
                    .map(|member| member.leaf_signature_key.clone())
            })
            .ok_or_else(|| JsError::new("phase-b2 projection: proposal index out of range"))
    }
    pub fn proposal_added_identity_proof(&self, index: usize) -> Result<Option<Vec<u8>>, JsError> {
        self.proposals
            .get(index)
            .map(|proposal| {
                proposal
                    .added_member
                    .as_ref()
                    .map(|member| member.identity_proof.clone())
            })
            .ok_or_else(|| JsError::new("phase-b2 projection: proposal index out of range"))
    }
    pub fn proposal_added_component_ids(&self, index: usize) -> Result<Option<Vec<u16>>, JsError> {
        self.proposals
            .get(index)
            .map(|proposal| {
                proposal
                    .added_member
                    .as_ref()
                    .map(|member| member.component_ids.clone())
            })
            .ok_or_else(|| JsError::new("phase-b2 projection: proposal index out of range"))
    }
    pub fn proposal_added_supported_component_ids(
        &self,
        index: usize,
    ) -> Result<Option<Vec<u16>>, JsError> {
        self.proposals
            .get(index)
            .map(|proposal| {
                proposal
                    .added_member
                    .as_ref()
                    .map(|member| member.supported_component_ids.clone())
            })
            .ok_or_else(|| JsError::new("phase-b2 projection: proposal index out of range"))
    }
    pub fn proposal_removed_parent_leaf_index(&self, index: usize) -> Result<Option<u32>, JsError> {
        self.proposals
            .get(index)
            .map(|proposal| proposal.removed_parent_leaf_index)
            .ok_or_else(|| JsError::new("phase-b2 projection: proposal index out of range"))
    }
    pub fn proposal_removed_identity(&self, index: usize) -> Result<Option<Vec<u8>>, JsError> {
        self.proposals
            .get(index)
            .map(|proposal| {
                proposal
                    .removed_member
                    .as_ref()
                    .map(|member| member.credential_identity.clone())
            })
            .ok_or_else(|| JsError::new("phase-b2 projection: proposal index out of range"))
    }
    pub fn proposal_removed_signature_key(&self, index: usize) -> Result<Option<Vec<u8>>, JsError> {
        self.proposals
            .get(index)
            .map(|proposal| {
                proposal
                    .removed_member
                    .as_ref()
                    .map(|member| member.leaf_signature_key.clone())
            })
            .ok_or_else(|| JsError::new("phase-b2 projection: proposal index out of range"))
    }
    pub fn proposal_removed_identity_proof(
        &self,
        index: usize,
    ) -> Result<Option<Vec<u8>>, JsError> {
        self.proposals
            .get(index)
            .map(|proposal| {
                proposal
                    .removed_member
                    .as_ref()
                    .map(|member| member.identity_proof.clone())
            })
            .ok_or_else(|| JsError::new("phase-b2 projection: proposal index out of range"))
    }
    pub fn has_update_path(&self) -> bool {
        self.update_path_leaf.is_some()
    }
    pub fn update_path_leaf_index(&self) -> Option<u32> {
        self.update_path_leaf
            .as_ref()
            .map(|member| member.leaf_index)
    }
    pub fn update_path_identity(&self) -> Option<Vec<u8>> {
        self.update_path_leaf
            .as_ref()
            .map(|member| member.credential_identity.clone())
    }
    pub fn update_path_signature_key(&self) -> Option<Vec<u8>> {
        self.update_path_leaf
            .as_ref()
            .map(|member| member.leaf_signature_key.clone())
    }
    pub fn update_path_identity_proof(&self) -> Option<Vec<u8>> {
        self.update_path_leaf
            .as_ref()
            .map(|member| member.identity_proof.clone())
    }
    pub fn update_path_component_ids(&self) -> Option<Vec<u16>> {
        self.update_path_leaf
            .as_ref()
            .map(|member| member.component_ids.clone())
    }
    pub fn update_path_supported_component_ids(&self) -> Option<Vec<u16>> {
        self.update_path_leaf
            .as_ref()
            .map(|member| member.supported_component_ids.clone())
    }
    pub fn candidate_member_count(&self) -> u32 {
        self.candidate_members.len() as u32
    }
    pub fn candidate_leaf_index(&self, index: usize) -> Result<u32, JsError> {
        self.candidate_member(index).map(|member| member.leaf_index)
    }
    pub fn candidate_identity(&self, index: usize) -> Result<Vec<u8>, JsError> {
        self.candidate_member(index)
            .map(|member| member.credential_identity.clone())
    }
    pub fn candidate_signature_key(&self, index: usize) -> Result<Vec<u8>, JsError> {
        self.candidate_member(index)
            .map(|member| member.leaf_signature_key.clone())
    }
    pub fn candidate_identity_proof(&self, index: usize) -> Result<Vec<u8>, JsError> {
        self.candidate_member(index)
            .map(|member| member.identity_proof.clone())
    }
    pub fn candidate_component_ids(&self, index: usize) -> Result<Vec<u16>, JsError> {
        self.candidate_member(index)
            .map(|member| member.component_ids.clone())
    }
    pub fn candidate_supported_component_ids(&self, index: usize) -> Result<Vec<u16>, JsError> {
        self.candidate_member(index)
            .map(|member| member.supported_component_ids.clone())
    }
    pub fn candidate_group_context_tls(&self) -> Vec<u8> {
        self.group_context.tls.clone()
    }
    pub fn candidate_group_context_sha256(&self) -> Vec<u8> {
        self.group_context_sha256.clone()
    }
    pub fn required_component_ids(&self) -> Vec<u16> {
        self.group_context.required_components.clone()
    }
    pub fn administrator_policy(&self) -> Vec<u8> {
        self.group_context.administrator_policy.clone()
    }
    pub fn lifecycle(&self) -> Vec<u8> {
        self.group_context.lifecycle.clone()
    }
    pub fn verified_leaf_digest(&self) -> Vec<u8> {
        self.verified_leaf_digest.clone()
    }
}

#[cfg(feature = "extensions-draft")]
impl PhaseB2CommitProjection {
    fn candidate_member(&self, index: usize) -> Result<&PhaseB2Member, JsError> {
        self.candidate_members
            .get(index)
            .ok_or_else(|| JsError::new("phase-b2 projection: candidate member index out of range"))
    }
}

#[cfg(feature = "extensions-draft")]
#[derive(Clone)]
struct PhaseB2HandleBinding {
    provider_instance_id: u32,
    provider_restore_generation: u32,
    group_instance_id: u32,
    group_id: Vec<u8>,
    prior_epoch: u64,
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
pub struct PhaseB2PendingCommit {
    binding: Option<PhaseB2HandleBinding>,
    commit: Vec<u8>,
    welcome: Option<Vec<u8>>,
    projection: PhaseB2CommitProjection,
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB2PendingCommit {
    pub fn commit(&self) -> Vec<u8> {
        self.commit.clone()
    }
    pub fn welcome(&self) -> Option<Vec<u8>> {
        self.welcome.clone()
    }
    pub fn projection(&self) -> PhaseB2CommitProjection {
        self.projection.clone()
    }
    pub fn is_consumed(&self) -> bool {
        self.binding.is_none()
    }
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
pub struct PhaseB2StagedCommit {
    binding: Option<PhaseB2HandleBinding>,
    staged_commit: Option<StagedCommit>,
    projection: PhaseB2CommitProjection,
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB2StagedCommit {
    pub fn projection(&self) -> PhaseB2CommitProjection {
        self.projection.clone()
    }
    pub fn is_consumed(&self) -> bool {
        self.staged_commit.is_none()
    }
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
pub struct PhaseB2Group {
    mls_group: MlsGroup,
    instance_id: u32,
    provider_instance_id: u32,
    provider_restore_generation: u32,
}

#[cfg(feature = "extensions-draft")]
impl PhaseB2Group {
    fn from_bound_group(provider: &Provider, mls_group: MlsGroup) -> Self {
        Self {
            mls_group,
            instance_id: next_group_instance_id(),
            provider_instance_id: provider.instance_id,
            provider_restore_generation: provider.restore_generation.get(),
        }
    }

    fn validate_provider(&self, provider: &Provider) -> Result<(), JsError> {
        if self.provider_instance_id != provider.instance_id {
            return Err(JsError::new("phase-b2 handle: wrong provider"));
        }
        if self.provider_restore_generation != provider.restore_generation.get() {
            return Err(JsError::new(
                "phase-b2 handle: invalidated by provider restore",
            ));
        }
        Ok(())
    }

    fn validate_binding_recovery(
        &self,
        provider: &Provider,
        binding: &PhaseB2HandleBinding,
    ) -> Result<(), &'static str> {
        if self.provider_instance_id != provider.instance_id
            || binding.provider_instance_id != provider.instance_id
        {
            return Err("phase-b2 handle: wrong provider");
        }
        if self.provider_restore_generation != provider.restore_generation.get()
            || binding.provider_restore_generation != provider.restore_generation.get()
        {
            return Err("phase-b2 handle: invalidated by provider restore");
        }
        if binding.group_instance_id != self.instance_id
            || binding.group_id != self.mls_group.group_id().as_slice()
        {
            return Err("phase-b2 handle: wrong group");
        }
        if binding.prior_epoch != self.mls_group.epoch().as_u64() {
            return Err("phase-b2 handle: stale epoch");
        }
        Ok(())
    }

    fn binding(&self, provider: &Provider) -> PhaseB2HandleBinding {
        PhaseB2HandleBinding {
            provider_instance_id: provider.instance_id,
            provider_restore_generation: provider.restore_generation.get(),
            group_instance_id: self.instance_id,
            group_id: self.mls_group.group_id().to_vec(),
            prior_epoch: self.mls_group.epoch().as_u64(),
        }
    }

    fn validate_binding(
        &self,
        provider: &Provider,
        binding: &PhaseB2HandleBinding,
    ) -> Result<(), JsError> {
        self.validate_binding_recovery(provider, binding)
            .map_err(JsError::new)
    }

    fn validate_own_identity(&self, identity: &PhaseB2Identity) -> Result<(), JsError> {
        let own = self
            .mls_group
            .own_leaf_node()
            .ok_or_else(|| JsError::new("phase-b2 group: own leaf is absent"))?;
        if own.credential().serialized_content() != identity.account_public_key
            || own.signature_key().as_slice() != identity.keypair.public()
        {
            return Err(JsError::new(
                "phase-b2 group: signer is not the bound own identity",
            ));
        }
        Ok(())
    }

    fn clone_provider(provider: &Provider) -> Result<Provider, JsError> {
        let clone = Provider::new();
        clone.restore_state(&provider.serialize_state())?;
        Ok(clone)
    }

    fn candidate_from_pending(&self, provider: &Provider) -> Result<MlsGroup, JsError> {
        let mut clone = Self::clone_provider(provider)?;
        let mut candidate = MlsGroup::load(clone.inner.storage(), self.mls_group.group_id())?
            .ok_or_else(|| JsError::new("phase-b2 projection: cloned group is absent"))?;
        candidate.merge_pending_commit(clone.as_mut())?;
        Ok(candidate)
    }

    fn projection_from_pending(
        &self,
        provider: &Provider,
    ) -> Result<PhaseB2CommitProjection, JsError> {
        let staged = self
            .mls_group
            .pending_commit()
            .ok_or_else(|| JsError::new("phase-b2 local commit: pending state is absent"))?;
        let candidate = self.candidate_from_pending(provider)?;
        phase_b2_projection(
            provider.as_ref().crypto(),
            &self.mls_group,
            staged,
            &candidate,
            self.mls_group.own_leaf_index().u32(),
        )
    }

    fn verify_digest(&self, supplied: &[u8], expected: &[u8]) -> Result<(), JsError> {
        phase_b2_check_verified_leaf_digest(supplied, expected).map_err(JsError::new)
    }

    fn durable_matches_memory(&self, provider: &Provider) -> Result<(), JsError> {
        self.validate_provider(provider)?;
        let durable = MlsGroup::load(provider.inner.storage(), self.mls_group.group_id())?
            .ok_or_else(|| JsError::new("phase-b2 recovery: durable group is absent"))?;
        let (memory_members, memory_context) = phase_b2_group_projection(&self.mls_group)?;
        let (durable_members, durable_context) = phase_b2_group_projection(&durable)?;
        if durable.epoch() != self.mls_group.epoch()
            || durable.group_id() != self.mls_group.group_id()
            || memory_members != durable_members
            || memory_context != durable_context
            || durable.pending_commit().is_some() != self.mls_group.pending_commit().is_some()
        {
            return Err(JsError::new(
                "phase-b2 recovery: durable state disagrees with memory",
            ));
        }
        Ok(())
    }

    fn pending_result(
        &self,
        provider: &Provider,
        commit: MlsMessageOut,
        welcome: Option<MlsMessageOut>,
    ) -> Result<PhaseB2PendingCommit, JsError> {
        let commit = commit.tls_serialize_detached()?;
        let parsed = MlsMessageIn::tls_deserialize_exact(&commit)
            .map_err(|_| JsError::new("phase-b2 local commit: malformed generated Commit"))?;
        if !matches!(parsed.extract(), MlsMessageBodyIn::PublicMessage(_)) {
            return Err(JsError::new(
                "phase-b2 local commit: Commit is not PublicMessage",
            ));
        }
        let projection = self.projection_from_pending(provider)?;
        Ok(PhaseB2PendingCommit {
            binding: Some(self.binding(provider)),
            commit,
            welcome: welcome
                .map(|message| message.tls_serialize_detached())
                .transpose()?,
            projection,
        })
    }
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB2Group {
    pub fn create_new(
        provider: &Provider,
        founder: &PhaseB2Identity,
        group_id: &[u8],
        founder_proof: &[u8],
    ) -> Result<PhaseB2Group, JsError> {
        if group_id.is_empty() || group_id.len() > 64 {
            return Err(JsError::new(
                "phase-b2 group: group id must contain 1..64 bytes",
            ));
        }
        phase_b2_check_identity_proof(&founder.account_public_key, founder_proof)
            .map_err(JsError::new)?;
        let group = MlsGroup::builder()
            .ciphersuite(PROBE_CIPHERSUITE)
            .with_group_id(GroupId::from_slice(group_id))
            .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .with_group_context_extensions(phase_b2_group_context_extensions(
                &founder.account_public_key,
            )?)
            .with_capabilities(phase_b2_capabilities())
            .with_leaf_node_extensions(phase_b2_leaf_extensions(founder_proof)?)?
            .build(
                &provider.inner,
                &founder.keypair,
                founder.credential_with_key.clone(),
            )?;
        phase_b2_group_projection(&group)?;
        Ok(Self::from_bound_group(provider, group))
    }

    pub fn join(
        provider: &Provider,
        welcome_bytes: &[u8],
        ratchet_tree: PhaseB2RatchetTree,
    ) -> Result<PhaseB2Group, JsError> {
        let message = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|_| JsError::new("phase-b2 group: malformed Welcome framing"))?;
        let welcome = match message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(JsError::new("phase-b2 group: MLSMessage is not a Welcome")),
        };
        let config = MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .build();
        let group = StagedWelcome::new_from_welcome(
            &provider.inner,
            &config,
            welcome,
            Some(ratchet_tree.0),
        )?
        .into_group(&provider.inner)?;
        phase_b2_group_projection(&group)?;
        Ok(Self::from_bound_group(provider, group))
    }

    pub fn load(provider: &Provider, group_id: &[u8]) -> Result<Option<PhaseB2Group>, JsError> {
        if group_id.is_empty() || group_id.len() > 64 {
            return Err(JsError::new(
                "phase-b2 group: group id must contain 1..64 bytes",
            ));
        }
        let requested = GroupId::from_slice(group_id);
        let Some(group) = MlsGroup::load(provider.inner.storage(), &requested)? else {
            return Ok(None);
        };
        if group.group_id() != &requested {
            return Err(JsError::new("phase-b2 group: loaded group id mismatch"));
        }
        phase_b2_group_projection(&group)?;
        Ok(Some(Self::from_bound_group(provider, group)))
    }

    pub fn group_id(&self) -> Vec<u8> {
        self.mls_group.group_id().to_vec()
    }
    pub fn epoch(&self) -> u64 {
        self.mls_group.epoch().as_u64()
    }
    pub fn member_count(&self) -> u32 {
        self.mls_group.members().count() as u32
    }
    pub fn export_ratchet_tree(&self) -> PhaseB2RatchetTree {
        PhaseB2RatchetTree(self.mls_group.export_ratchet_tree().into())
    }
    pub fn member_leaf_index(&self, index: usize) -> Result<u32, JsError> {
        phase_b2_group_projection(&self.mls_group)?
            .0
            .get(index)
            .map(|member| member.leaf_index)
            .ok_or_else(|| JsError::new("phase-b2 group: member index out of range"))
    }
    pub fn member_identity(&self, index: usize) -> Result<Vec<u8>, JsError> {
        phase_b2_group_projection(&self.mls_group)?
            .0
            .get(index)
            .map(|member| member.credential_identity.clone())
            .ok_or_else(|| JsError::new("phase-b2 group: member index out of range"))
    }
    pub fn member_signature_key(&self, index: usize) -> Result<Vec<u8>, JsError> {
        phase_b2_group_projection(&self.mls_group)?
            .0
            .get(index)
            .map(|member| member.leaf_signature_key.clone())
            .ok_or_else(|| JsError::new("phase-b2 group: member index out of range"))
    }
    pub fn member_identity_proof(&self, index: usize) -> Result<Vec<u8>, JsError> {
        phase_b2_group_projection(&self.mls_group)?
            .0
            .get(index)
            .map(|member| member.identity_proof.clone())
            .ok_or_else(|| JsError::new("phase-b2 group: member index out of range"))
    }
    pub fn group_context_tls(&self) -> Result<Vec<u8>, JsError> {
        Ok(phase_b2_group_projection(&self.mls_group)?.1.tls)
    }
    pub fn group_context_sha256(&self, provider: &Provider) -> Result<Vec<u8>, JsError> {
        self.validate_provider(provider)?;
        let context = phase_b2_group_projection(&self.mls_group)?.1;
        provider
            .as_ref()
            .crypto()
            .hash(PROBE_CIPHERSUITE.hash_algorithm(), &context.tls)
            .map_err(|_| JsError::new("phase-b2 group: GroupContext hash failed"))
    }
    pub fn required_component_ids(&self) -> Result<Vec<u16>, JsError> {
        Ok(phase_b2_group_projection(&self.mls_group)?
            .1
            .required_components)
    }
    pub fn administrator_policy(&self) -> Result<Vec<u8>, JsError> {
        Ok(phase_b2_group_projection(&self.mls_group)?
            .1
            .administrator_policy)
    }
    pub fn lifecycle(&self) -> Result<Vec<u8>, JsError> {
        Ok(phase_b2_group_projection(&self.mls_group)?.1.lifecycle)
    }
    pub fn matches_own_identity(
        &self,
        account_public_key: &[u8],
        leaf_signature_key: &[u8],
    ) -> Result<bool, JsError> {
        if account_public_key.len() != 32 || leaf_signature_key.len() != 32 {
            return Err(JsError::new(
                "phase-b2 group: identity inputs must be exactly 32 bytes",
            ));
        }
        let own = self
            .mls_group
            .own_leaf_node()
            .ok_or_else(|| JsError::new("phase-b2 group: own leaf is absent"))?;
        Ok(own.credential().serialized_content() == account_public_key
            && own.signature_key().as_slice() == leaf_signature_key)
    }

    pub fn prepare_add(
        &mut self,
        provider: &Provider,
        sender: &PhaseB2Identity,
        new_member: &PhaseB2KeyPackage,
    ) -> Result<PhaseB2PendingCommit, JsError> {
        self.validate_provider(provider)?;
        self.validate_own_identity(sender)?;
        phase_b2_inspect_key_package(&new_member.0)?;
        if self.mls_group.pending_commit().is_some() {
            return Err(JsError::new(
                "phase-b2 local commit: pending state already exists",
            ));
        }
        let (commit, welcome, _) = self.mls_group.add_members(
            provider.as_ref(),
            &sender.keypair,
            &[new_member.0.clone()],
        )?;
        match self.pending_result(provider, commit, Some(welcome)) {
            Ok(pending) => Ok(pending),
            Err(error) => {
                let _ = self
                    .mls_group
                    .clear_pending_commit(provider.inner.storage());
                Err(error)
            }
        }
    }

    pub fn prepare_remove(
        &mut self,
        provider: &Provider,
        sender: &PhaseB2Identity,
        removed_leaf_index: u32,
    ) -> Result<PhaseB2PendingCommit, JsError> {
        self.validate_provider(provider)?;
        self.validate_own_identity(sender)?;
        if self.mls_group.pending_commit().is_some() {
            return Err(JsError::new(
                "phase-b2 local commit: pending state already exists",
            ));
        }
        phase_b2_member_at(&self.mls_group, removed_leaf_index)?;
        let (commit, welcome, _) = self.mls_group.remove_members(
            provider.as_ref(),
            &sender.keypair,
            &[openmls::prelude::LeafNodeIndex::new(removed_leaf_index)],
        )?;
        match self.pending_result(provider, commit, welcome) {
            Ok(pending) => Ok(pending),
            Err(error) => {
                let _ = self
                    .mls_group
                    .clear_pending_commit(provider.inner.storage());
                Err(error)
            }
        }
    }

    pub fn prepare_self_update(
        &mut self,
        provider: &Provider,
        sender: &PhaseB2Identity,
    ) -> Result<PhaseB2PendingCommit, JsError> {
        self.validate_provider(provider)?;
        self.validate_own_identity(sender)?;
        if self.mls_group.pending_commit().is_some() {
            return Err(JsError::new(
                "phase-b2 local commit: pending state already exists",
            ));
        }
        let bundle = self.mls_group.self_update(
            provider.as_ref(),
            &sender.keypair,
            LeafNodeParameters::default(),
        )?;
        let commit = bundle.commit().clone();
        let welcome = bundle.to_welcome_msg();
        match self.pending_result(provider, commit, welcome) {
            Ok(pending) => Ok(pending),
            Err(error) => {
                let _ = self
                    .mls_group
                    .clear_pending_commit(provider.inner.storage());
                Err(error)
            }
        }
    }

    pub fn confirm_pending(
        &mut self,
        provider: &mut Provider,
        pending: &mut PhaseB2PendingCommit,
        verified_leaf_digest: &[u8],
    ) -> Result<(), JsError> {
        let binding = pending
            .binding
            .as_ref()
            .ok_or_else(|| JsError::new("phase-b2 local commit: handle already consumed"))?;
        self.validate_binding(provider, binding)?;
        let current = self.projection_from_pending(provider)?;
        if current != pending.projection {
            return Err(JsError::new(
                "phase-b2 local commit: candidate state changed",
            ));
        }
        self.verify_digest(verified_leaf_digest, &current.verified_leaf_digest)?;
        self.mls_group.merge_pending_commit(provider.as_mut())?;
        pending.binding.take();
        Ok(())
    }

    pub fn discard_pending(
        &mut self,
        provider: &Provider,
        pending: &mut PhaseB2PendingCommit,
    ) -> Result<(), JsError> {
        let binding = pending
            .binding
            .as_ref()
            .ok_or_else(|| JsError::new("phase-b2 local commit: handle already consumed"))?;
        self.validate_binding(provider, binding)?;
        if self.mls_group.pending_commit().is_none() {
            return Err(JsError::new(
                "phase-b2 local commit: pending state is absent",
            ));
        }
        self.mls_group
            .clear_pending_commit(provider.inner.storage())?;
        pending.binding.take();
        Ok(())
    }

    pub fn has_pending_commit(&self, provider: &Provider) -> Result<bool, JsError> {
        self.durable_matches_memory(provider)?;
        Ok(self.mls_group.pending_commit().is_some())
    }

    pub fn pending_projection(
        &self,
        provider: &Provider,
    ) -> Result<Option<PhaseB2CommitProjection>, JsError> {
        self.durable_matches_memory(provider)?;
        self.mls_group
            .pending_commit()
            .map(|_| self.projection_from_pending(provider))
            .transpose()
    }

    pub fn confirm_pending_commit(
        &mut self,
        provider: &mut Provider,
        expected_prior_epoch: u64,
        account_public_key: &[u8],
        leaf_signature_key: &[u8],
        verified_leaf_digest: &[u8],
    ) -> Result<(), JsError> {
        self.durable_matches_memory(provider)?;
        if self.epoch() != expected_prior_epoch
            || !self.matches_own_identity(account_public_key, leaf_signature_key)?
        {
            return Err(JsError::new(
                "phase-b2 recovery: stale epoch or wrong identity",
            ));
        }
        let projection = self.projection_from_pending(provider)?;
        self.verify_digest(verified_leaf_digest, &projection.verified_leaf_digest)?;
        self.mls_group.merge_pending_commit(provider.as_mut())?;
        Ok(())
    }

    pub fn clear_pending_commit(
        &mut self,
        provider: &Provider,
        expected_prior_epoch: u64,
        account_public_key: &[u8],
        leaf_signature_key: &[u8],
    ) -> Result<(), JsError> {
        self.durable_matches_memory(provider)?;
        if self.epoch() != expected_prior_epoch
            || !self.matches_own_identity(account_public_key, leaf_signature_key)?
        {
            return Err(JsError::new(
                "phase-b2 recovery: stale epoch or wrong identity",
            ));
        }
        if self.mls_group.pending_commit().is_none() {
            return Err(JsError::new("phase-b2 recovery: pending state is absent"));
        }
        self.mls_group
            .clear_pending_commit(provider.inner.storage())?;
        Ok(())
    }

    pub fn stage_inbound_commit(
        &mut self,
        provider: &Provider,
        bytes: &[u8],
    ) -> Result<PhaseB2StagedCommit, JsError> {
        self.validate_provider(provider)?;
        let message = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(|_| JsError::new("phase-b2 staged commit: malformed MLSMessage"))?;
        let public = match message.extract() {
            MlsMessageBodyIn::PublicMessage(message) => message,
            MlsMessageBodyIn::PrivateMessage(_) => {
                return Err(JsError::new(
                    "phase-b2 staged commit: PrivateMessage Commit rejected",
                ));
            }
            _ => {
                return Err(JsError::new(
                    "phase-b2 staged commit: unsupported MLSMessage body",
                ))
            }
        };
        let processed = self.mls_group.process_message(provider.as_ref(), public)?;
        let committer_leaf_index = phase_b2_member_sender(
            processed.sender(),
            "phase-b2 staged commit: non-member committer rejected",
        )?;
        let staged_commit = match processed.into_content() {
            openmls::framing::ProcessedMessageContent::StagedCommitMessage(commit) => *commit,
            openmls::framing::ProcessedMessageContent::UnresolvedAppDataCommit(_) => {
                return Err(JsError::new("PHASE_B2_APP_DATA_UPDATE_UNSUPPORTED"));
            }
            _ => {
                return Err(JsError::new(
                    "phase-b2 staged commit: message is not a Commit",
                ))
            }
        };

        let mut clone = Self::clone_provider(provider)?;
        let mut candidate = MlsGroup::load(clone.inner.storage(), self.mls_group.group_id())?
            .ok_or_else(|| JsError::new("phase-b2 projection: cloned group is absent"))?;
        let candidate_message = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(|_| JsError::new("phase-b2 staged commit: malformed MLSMessage"))?;
        let candidate_public = match candidate_message.extract() {
            MlsMessageBodyIn::PublicMessage(message) => message,
            _ => {
                return Err(JsError::new(
                    "phase-b2 staged commit: PublicMessage required",
                ))
            }
        };
        let candidate_processed = candidate.process_message(clone.as_ref(), candidate_public)?;
        let candidate_staged = match candidate_processed.into_content() {
            openmls::framing::ProcessedMessageContent::StagedCommitMessage(commit) => *commit,
            openmls::framing::ProcessedMessageContent::UnresolvedAppDataCommit(_) => {
                return Err(JsError::new("PHASE_B2_APP_DATA_UPDATE_UNSUPPORTED"));
            }
            _ => {
                return Err(JsError::new(
                    "phase-b2 staged commit: message is not a Commit",
                ))
            }
        };
        candidate.merge_staged_commit(clone.as_mut(), candidate_staged)?;
        let projection = phase_b2_projection(
            provider.as_ref().crypto(),
            &self.mls_group,
            &staged_commit,
            &candidate,
            committer_leaf_index,
        )?;
        Ok(PhaseB2StagedCommit {
            binding: Some(self.binding(provider)),
            staged_commit: Some(staged_commit),
            projection,
        })
    }

    pub fn merge_staged_commit(
        &mut self,
        provider: &mut Provider,
        staged: &mut PhaseB2StagedCommit,
        verified_leaf_digest: &[u8],
    ) -> Result<(), JsError> {
        let binding = staged
            .binding
            .as_ref()
            .ok_or_else(|| JsError::new("phase-b2 staged commit: handle already consumed"))?;
        self.validate_binding(provider, binding)?;
        self.verify_digest(
            verified_leaf_digest,
            &staged.projection.verified_leaf_digest,
        )?;
        let commit = staged
            .staged_commit
            .take()
            .ok_or_else(|| JsError::new("phase-b2 staged commit: handle already consumed"))?;
        self.mls_group
            .merge_staged_commit(provider.as_mut(), commit)?;
        staged.binding.take();
        Ok(())
    }

    pub fn discard_staged_commit(
        &mut self,
        provider: &Provider,
        staged: &mut PhaseB2StagedCommit,
    ) -> Result<(), JsError> {
        let binding = staged
            .binding
            .as_ref()
            .ok_or_else(|| JsError::new("phase-b2 staged commit: handle already consumed"))?;
        self.validate_binding(provider, binding)?;
        staged
            .staged_commit
            .as_ref()
            .ok_or_else(|| JsError::new("phase-b2 staged commit: handle already consumed"))?;
        staged.staged_commit.take();
        staged.binding.take();
        Ok(())
    }

    pub fn create_application_message(
        &mut self,
        provider: &Provider,
        sender: &PhaseB2Identity,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        self.validate_provider(provider)?;
        self.validate_own_identity(sender)?;
        if plaintext.is_empty() {
            return Err(JsError::new(
                "phase-b2 application: plaintext must not be empty",
            ));
        }
        Ok(self
            .mls_group
            .create_message(provider.as_ref(), &sender.keypair, plaintext)?
            .tls_serialize_detached()?)
    }

    pub fn process_application_message(
        &mut self,
        provider: &Provider,
        bytes: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        self.validate_provider(provider)?;
        let message = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(|_| JsError::new("phase-b2 application: malformed MLSMessage"))?;
        let protocol: ProtocolMessage = match message.extract() {
            MlsMessageBodyIn::PublicMessage(message) => message.into(),
            MlsMessageBodyIn::PrivateMessage(message) => message.into(),
            _ => {
                return Err(JsError::new(
                    "phase-b2 application: unsupported MLSMessage body",
                ))
            }
        };
        match self
            .mls_group
            .process_message(provider.as_ref(), protocol)?
            .into_content()
        {
            openmls::framing::ProcessedMessageContent::ApplicationMessage(message) => {
                Ok(message.into_bytes())
            }
            _ => Err(JsError::new(
                "phase-b2 application: message is not application data",
            )),
        }
    }
}

#[cfg(feature = "extensions-draft")]
#[derive(Clone, PartialEq, Eq)]
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
        dictionary.get(&1).expect("validated Phase B1 KeyPackage"),
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
#[derive(Clone, PartialEq, Eq)]
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
    provider_instance_id: u32,
    provider_restore_generation: u32,
}

#[cfg(feature = "extensions-draft")]
impl PhaseB1Group {
    fn from_bound_group(provider: &Provider, mls_group: MlsGroup) -> Self {
        Self {
            mls_group,
            instance_id: next_group_instance_id(),
            provider_instance_id: provider.instance_id,
            provider_restore_generation: provider.restore_generation.get(),
        }
    }

    fn validate_provider_binding_recovery(&self, provider: &Provider) -> Result<(), &'static str> {
        if self.provider_instance_id != provider.instance_id {
            return Err("phase-b1 handle: wrong provider");
        }
        if self.provider_restore_generation != provider.restore_generation.get() {
            return Err("phase-b1 handle: invalidated by provider restore");
        }
        Ok(())
    }

    fn validate_provider_binding(&self, provider: &Provider) -> Result<(), JsError> {
        self.validate_provider_binding_recovery(provider)
            .map_err(JsError::new)
    }

    fn handle_binding(&self, provider: &Provider) -> HandleBinding {
        HandleBinding {
            provider_instance_id: provider.instance_id,
            provider_restore_generation: provider.restore_generation.get(),
            group_instance_id: self.instance_id,
            group_id: self.mls_group.group_id().to_vec(),
            prior_epoch: self.mls_group.epoch().as_u64(),
        }
    }

    fn validate_durable_recovery_state_recovery(
        &self,
        provider: &Provider,
    ) -> Result<(), &'static str> {
        self.validate_provider_binding_recovery(provider)?;
        validate_phase_b1_group_profile_recovery(&self.mls_group)?;
        let durable_group = MlsGroup::load(provider.inner.storage(), self.mls_group.group_id())
            .map_err(|_| "phase-b1 recovery: durable group load failed")?
            .ok_or("phase-b1 recovery: durable group is absent")?;
        validate_phase_b1_group_profile_recovery(&durable_group)?;

        let current_pending = phase_b1_pending_projection(&self.mls_group)
            .map_err(|_| "phase-b1 recovery: pending projection failed")?;
        let durable_pending = phase_b1_pending_projection(&durable_group)
            .map_err(|_| "phase-b1 recovery: pending projection failed")?;
        if self.mls_group.group_id() != durable_group.group_id()
            || self.mls_group.ciphersuite() != durable_group.ciphersuite()
            || self.mls_group.epoch() != durable_group.epoch()
            || phase_b1_member_bindings(&self.mls_group) != phase_b1_member_bindings(&durable_group)
            || current_pending != durable_pending
        {
            return Err("phase-b1 recovery: durable group disagrees with memory");
        }
        Ok(())
    }

    fn validate_durable_recovery_state(&self, provider: &Provider) -> Result<(), JsError> {
        self.validate_durable_recovery_state_recovery(provider)
            .map_err(JsError::new)
    }

    fn validate_pending_recovery(
        &self,
        provider: &Provider,
        expected_prior_epoch: u64,
    ) -> Result<(), &'static str> {
        self.validate_durable_recovery_state_recovery(provider)?;
        if self.mls_group.epoch().as_u64() != expected_prior_epoch {
            return Err("phase-b1 recovery: stale epoch");
        }
        if self.mls_group.pending_commit().is_none() {
            return Err("phase-b1 recovery: pending state is absent");
        }
        Ok(())
    }

    fn load_recovery(
        provider: &Provider,
        group_id: &[u8],
    ) -> Result<Option<PhaseB1Group>, &'static str> {
        if group_id.is_empty() || group_id.len() > 64 {
            return Err("phase-b1 group: group id must contain 1..64 bytes");
        }
        let requested_group_id = GroupId::from_slice(group_id);
        let Some(mls_group) = MlsGroup::load(provider.inner.storage(), &requested_group_id)
            .map_err(|_| "phase-b1 recovery: durable group load failed")?
        else {
            return Ok(None);
        };
        if mls_group.group_id() != &requested_group_id {
            return Err("phase-b1 group: unexpected profile");
        }
        validate_phase_b1_group_profile_recovery(&mls_group)?;
        Ok(Some(Self::from_bound_group(provider, mls_group)))
    }

    fn matches_own_identity_recovery(
        &self,
        account_public_key: &[u8],
        leaf_signature_key: &[u8],
    ) -> Result<bool, &'static str> {
        if account_public_key.len() != 32 || leaf_signature_key.len() != 32 {
            return Err("phase-b1 recovery: identity inputs must be exactly 32 bytes");
        }
        let own_leaf = self
            .mls_group
            .own_leaf_node()
            .ok_or("phase-b1 recovery: own leaf is absent")?;
        Ok(
            own_leaf.credential().serialized_content() == account_public_key
                && own_leaf.signature_key().as_slice() == leaf_signature_key,
        )
    }
}

#[cfg(feature = "extensions-draft")]
fn phase_b1_member_bindings(group: &MlsGroup) -> Vec<(u32, Vec<u8>, Vec<u8>, Vec<u8>)> {
    group
        .members()
        .map(|member| {
            (
                member.index.u32(),
                member.credential.serialized_content().to_vec(),
                member.signature_key,
                member.encryption_key,
            )
        })
        .collect()
}

#[cfg(feature = "extensions-draft")]
fn phase_b1_pending_projection(
    group: &MlsGroup,
) -> Result<Option<PhaseB1CommitProjection>, JsError> {
    group
        .pending_commit()
        .map(|pending| PhaseB1CommitProjection::from_staged(group.epoch().as_u64(), pending))
        .transpose()
}

#[cfg(feature = "extensions-draft")]
fn validate_phase_b1_group_profile_recovery(group: &MlsGroup) -> Result<(), &'static str> {
    if group.ciphersuite() != PROBE_CIPHERSUITE {
        return Err("phase-b1 group: unexpected ciphersuite");
    }
    if group.group_id().as_slice().is_empty() || group.group_id().as_slice().len() > 64 {
        return Err("phase-b1 group: unexpected profile");
    }
    if !group.is_active() || group.own_leaf_node().is_none() {
        return Err("phase-b1 group: unexpected profile");
    }

    let mut member_count = 0usize;
    for member in group.members() {
        member_count += 1;
        if member.credential.serialized_content().len() != 32 || member.signature_key.len() != 32 {
            return Err("phase-b1 group: unexpected profile");
        }
        let leaf = group
            .public_group()
            .leaf(member.index)
            .ok_or("phase-b1 group: unexpected profile")?;
        if !leaf
            .capabilities()
            .ciphersuites()
            .contains(&VerifiableCiphersuite::from(PROBE_CIPHERSUITE))
            || !leaf
                .capabilities()
                .extensions()
                .contains(&ExtensionType::AppDataDictionary)
            || !leaf
                .capabilities()
                .proposals()
                .contains(&ProposalType::AppDataUpdate)
        {
            return Err("phase-b1 group: unexpected profile");
        }
        let dictionary = leaf
            .extensions()
            .app_data_dictionary()
            .ok_or("phase-b1 group: unexpected profile")?
            .dictionary();
        let component_ids: Vec<_> = dictionary.entries().map(|entry| entry.id()).collect();
        if component_ids != [1, ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID] {
            return Err("phase-b1 group: unexpected profile");
        }
        let supported = Vec::<u16>::tls_deserialize_exact(
            dictionary
                .get(&1)
                .ok_or("phase-b1 group: unexpected profile")?,
        )
        .map_err(|_| "phase-b1 group: unexpected profile")?;
        if supported != [ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID] {
            return Err("phase-b1 group: unexpected profile");
        }
        let proof = dictionary
            .get(&ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID)
            .ok_or("phase-b1 group: unexpected profile")?;
        validate_probe_identity_and_proof(member.credential.serialized_content(), proof)
            .map_err(|_| "phase-b1 group: unexpected profile")?;
    }
    if member_count == 0 {
        return Err("phase-b1 group: unexpected profile");
    }
    Ok(())
}

#[cfg(feature = "extensions-draft")]
fn validate_phase_b1_group_profile(group: &MlsGroup) -> Result<(), JsError> {
    validate_phase_b1_group_profile_recovery(group).map_err(JsError::new)
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB1Group {
    pub fn load(provider: &Provider, group_id: &[u8]) -> Result<Option<PhaseB1Group>, JsError> {
        Self::load_recovery(provider, group_id).map_err(JsError::new)
    }

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
        Ok(Self::from_bound_group(provider, mls_group))
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
        validate_phase_b1_group_profile(&mls_group)?;
        Ok(Self::from_bound_group(provider, mls_group))
    }

    pub fn group_id(&self) -> Vec<u8> {
        self.mls_group.group_id().to_vec()
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

    pub fn matches_own_identity(
        &self,
        account_public_key: &[u8],
        leaf_signature_key: &[u8],
    ) -> Result<bool, JsError> {
        self.matches_own_identity_recovery(account_public_key, leaf_signature_key)
            .map_err(JsError::new)
    }

    pub fn has_pending_commit(&self, provider: &Provider) -> Result<bool, JsError> {
        self.validate_durable_recovery_state(provider)?;
        Ok(self.mls_group.pending_commit().is_some())
    }

    pub fn confirm_pending_commit(
        &mut self,
        provider: &mut Provider,
        expected_prior_epoch: u64,
    ) -> Result<(), JsError> {
        self.validate_pending_recovery(provider, expected_prior_epoch)
            .map_err(JsError::new)?;
        self.mls_group.merge_pending_commit(provider.as_mut())?;
        Ok(())
    }

    pub fn clear_pending_commit(
        &mut self,
        provider: &Provider,
        expected_prior_epoch: u64,
    ) -> Result<(), JsError> {
        self.validate_pending_recovery(provider, expected_prior_epoch)
            .map_err(JsError::new)?;
        self.mls_group
            .clear_pending_commit(provider.inner.storage())?;
        Ok(())
    }

    pub fn propose_and_commit_add(
        &mut self,
        provider: &Provider,
        sender: &PhaseB1Identity,
        new_member: &PhaseB1KeyPackage,
    ) -> Result<PhaseB1PendingAdd, JsError> {
        self.validate_provider_binding(provider)?;
        inspect_probe_key_package(&new_member.0)?;
        if self.mls_group.pending_commit().is_some() {
            return Err(JsError::new(
                "phase-b1 local commit: another pending commit already exists",
            ));
        }
        let (commit, welcome, _) = self.mls_group.add_members(
            provider.as_ref(),
            &sender.keypair,
            &[new_member.0.clone()],
        )?;
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
        self.validate_provider_binding(provider)?;
        let binding = pending
            .binding
            .as_ref()
            .ok_or_else(|| JsError::new("phase-b1 local commit: handle already consumed"))?;
        binding.validate(provider, self)?;
        if self.mls_group.pending_commit().is_none() {
            return Err(JsError::new(
                "phase-b1 local commit: pending state is absent",
            ));
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
        self.validate_provider_binding(provider)?;
        let binding = pending
            .binding
            .as_ref()
            .ok_or_else(|| JsError::new("phase-b1 local commit: handle already consumed"))?;
        binding.validate(provider, self)?;
        if self.mls_group.pending_commit().is_none() {
            return Err(JsError::new(
                "phase-b1 local commit: pending state is absent",
            ));
        }
        pending.binding.take();
        self.mls_group
            .clear_pending_commit(provider.inner.storage())?;
        Ok(())
    }

    pub fn stage_inbound_commit(
        &mut self,
        provider: &Provider,
        bytes: &[u8],
    ) -> Result<PhaseB1StagedCommit, JsError> {
        self.validate_provider_binding(provider)?;
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
        self.validate_provider_binding(provider)?;
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
        self.mls_group
            .merge_staged_commit(provider.as_mut(), commit)?;
        Ok(())
    }

    pub fn discard_staged_commit(
        &mut self,
        provider: &Provider,
        staged: &mut PhaseB1StagedCommit,
    ) -> Result<(), JsError> {
        self.validate_provider_binding(provider)?;
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
        self.validate_provider_binding(provider)?;
        if plaintext.is_empty() {
            return Err(JsError::new(
                "phase-b1 application: plaintext must not be empty",
            ));
        }
        let message =
            self.mls_group
                .create_message(provider.as_ref(), &sender.keypair, plaintext)?;
        Ok(message.tls_serialize_detached()?)
    }

    pub fn process_application_message(
        &mut self,
        provider: &Provider,
        bytes: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        self.validate_provider_binding(provider)?;
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

    // Native wasm-bindgen tests cannot construct JsError on a non-WASM target.
    // Keep these exact pure predicates test-only, while the generated-JavaScript
    // probe exercises the exported boundary and authenticated OpenMLS objects
    // exercise the production policy inputs below.
    #[cfg(feature = "extensions-draft")]
    macro_rules! phase_b2_group_context_components_match {
        ($ids:expr) => {
            $ids == [
                1,
                ADMIN_POLICY_V1_COMPONENT_ID,
                GROUP_LIFECYCLE_V1_COMPONENT_ID,
            ]
        };
    }

    #[cfg(feature = "extensions-draft")]
    macro_rules! phase_b2_group_lifecycle_is_active {
        ($lifecycle:expr) => {
            $lifecycle == [0x00]
        };
    }

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

        let mut alice_group =
            PhaseB1Group::create_new(&alice_provider, &alice, b"phase-b1-native", &alice_proof)
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

        let tree =
            PhaseB1RatchetTree::from_bytes(&alice_group.export_ratchet_tree().to_bytes().unwrap())
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
        assert_eq!(
            projection.added_credential_identity(0).unwrap(),
            vec![3; 32]
        );
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
    fn phase_b2_identity(
        provider: &Provider,
        account_byte: u8,
    ) -> (PhaseB2Identity, Vec<u8>, PhaseB2KeyPackage) {
        let account = vec![account_byte; 32];
        let identity = PhaseB2Identity::new(provider, &account)
            .map_err(js_error_to_string)
            .unwrap();
        let mut proof = vec![0u8; ACCOUNT_IDENTITY_PROOF_V2_LENGTH];
        proof[..32].copy_from_slice(&account);
        let key_package = identity
            .key_package(provider, &proof)
            .map_err(js_error_to_string)
            .unwrap();
        (identity, proof, key_package)
    }

    #[cfg(feature = "extensions-draft")]
    fn phase_b2_stable_pair(
        group_id: &[u8],
        alice_byte: u8,
        bob_byte: u8,
    ) -> (
        Provider,
        PhaseB2Identity,
        PhaseB2Group,
        Provider,
        PhaseB2Identity,
        PhaseB2Group,
    ) {
        let mut alice_provider = Provider::new();
        let bob_provider = Provider::new();
        let (alice, alice_proof, _) = phase_b2_identity(&alice_provider, alice_byte);
        let (bob, _, bob_key_package) = phase_b2_identity(&bob_provider, bob_byte);
        let mut alice_group = PhaseB2Group::create_new(
            &alice_provider,
            &alice,
            group_id,
            &alice_proof,
        )
        .map_err(js_error_to_string)
        .unwrap();
        let mut add_bob = alice_group
            .prepare_add(&alice_provider, &alice, &bob_key_package)
            .map_err(js_error_to_string)
            .unwrap();
        let projection = add_bob.projection();
        alice_group
            .confirm_pending(
                &mut alice_provider,
                &mut add_bob,
                &projection.verified_leaf_digest(),
            )
            .map_err(js_error_to_string)
            .unwrap();
        let tree = PhaseB2RatchetTree::from_bytes(
            &alice_group.export_ratchet_tree().to_bytes().unwrap(),
        )
        .map_err(js_error_to_string)
        .unwrap();
        let bob_group = PhaseB2Group::join(
            &bob_provider,
            &add_bob.welcome().unwrap(),
            tree,
        )
        .map_err(js_error_to_string)
        .unwrap();
        (
            alice_provider,
            alice,
            alice_group,
            bob_provider,
            bob,
            bob_group,
        )
    }

    #[cfg(feature = "extensions-draft")]
    fn phase_b2_assert_exported_inline_self_update_accepts(
        group_id: &[u8],
        alice_byte: u8,
        bob_byte: u8,
    ) {
        let (
            alice_provider,
            alice,
            mut alice_group,
            bob_provider,
            _,
            mut bob_group,
        ) = phase_b2_stable_pair(group_id, alice_byte, bob_byte);
        let self_update = alice_group
            .prepare_self_update(&alice_provider, &alice)
            .map_err(js_error_to_string)
            .unwrap();
        let accepted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            bob_group.stage_inbound_commit(&bob_provider, &self_update.commit())
        }));
        assert!(
            accepted.is_ok(),
            "an admitted inline self-update must not trap at the exported staging boundary"
        );
        let mut staged = accepted
            .unwrap()
            .map_err(js_error_to_string)
            .unwrap();
        bob_group
            .discard_staged_commit(&bob_provider, &mut staged)
            .map_err(js_error_to_string)
            .unwrap();
    }

    #[cfg(feature = "extensions-draft")]
    fn phase_b2_provider_entries(snapshot: &[u8]) -> std::collections::BTreeMap<Vec<u8>, Vec<u8>> {
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
        let mut entries = std::collections::BTreeMap::new();
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
            assert!(entries.insert(key, value).is_none());
        }
        assert_eq!(offset, snapshot.len());
        entries
    }

    #[cfg(feature = "extensions-draft")]
    #[test]
    fn phase_b2_current_profile_projection_and_explicit_commit_lifecycle() {
        let mut alice_provider = Provider::new();
        let mut bob_provider = Provider::new();
        let charlie_provider = Provider::new();
        let (alice, alice_proof, _) = phase_b2_identity(&alice_provider, 0x41);
        let (bob, _, bob_key_package) = phase_b2_identity(&bob_provider, 0x42);
        let (_, _, charlie_key_package) = phase_b2_identity(&charlie_provider, 0x43);

        let framed = bob_key_package.to_framed_bytes().unwrap();
        let parsed = PhaseB2KeyPackage::from_framed_bytes(&framed)
            .map_err(js_error_to_string)
            .unwrap();
        assert_eq!(parsed.ciphersuite_id(), 0x0001);
        assert_eq!(parsed.credential_identity(), vec![0x42; 32]);
        assert_eq!(parsed.identity_proof().len(), 104);
        assert_eq!(parsed.component_ids(), vec![1, 0x8009]);
        assert_eq!(
            parsed.supported_component_ids(),
            vec![0x8003, 0x8009, 0x800c]
        );
        assert!(!parsed.is_last_resort());

        let mut alice_group = PhaseB2Group::create_new(
            &alice_provider,
            &alice,
            b"phase-b2-explicit-lifecycle",
            &alice_proof,
        )
        .map_err(js_error_to_string)
        .unwrap();
        assert_eq!(
            alice_group.required_component_ids().unwrap(),
            PHASE_B2_COMPONENTS
        );
        assert_eq!(alice_group.lifecycle().unwrap(), vec![0x00]);
        let mut add_bob = alice_group
            .prepare_add(&alice_provider, &alice, &parsed)
            .map_err(js_error_to_string)
            .unwrap();
        let add_projection = add_bob.projection();
        assert_eq!(add_projection.prior_epoch(), 0);
        assert_eq!(add_projection.candidate_epoch(), 1);
        assert_eq!(add_projection.committer_source(), "member");
        assert_eq!(add_projection.committer_leaf_index(), 0);
        assert_eq!(add_projection.proposal_count(), 1);
        assert_eq!(add_projection.proposal_kind(0).unwrap(), "add");
        assert_eq!(add_projection.proposal_source(0).unwrap(), "inline");
        assert_eq!(add_projection.proposal_sender_leaf_index(0).unwrap(), 0);
        assert_eq!(add_projection.candidate_member_count(), 2);
        assert_eq!(add_projection.required_component_ids(), PHASE_B2_COMPONENTS);
        assert_eq!(add_projection.verified_leaf_digest().len(), 32);
        assert!(matches!(
            MlsMessageIn::tls_deserialize_exact(&add_bob.commit())
                .unwrap()
                .extract(),
            MlsMessageBodyIn::PublicMessage(_)
        ));

        let wrong_digest = vec![0u8; 32];
        assert_eq!(
            phase_b2_check_verified_leaf_digest(
                &wrong_digest,
                &add_projection.verified_leaf_digest(),
            )
            .unwrap_err(),
            "phase-b2 commit: verified-leaf digest mismatch"
        );
        assert!(!add_bob.is_consumed());
        assert_eq!(alice_group.epoch(), 0);
        assert!(alice_group.has_pending_commit(&alice_provider).unwrap());

        assert_eq!(
            alice_group
                .validate_binding_recovery(&bob_provider, add_bob.binding.as_ref().unwrap())
                .unwrap_err(),
            "phase-b2 handle: wrong provider"
        );
        alice_group
            .confirm_pending(
                &mut alice_provider,
                &mut add_bob,
                &add_projection.verified_leaf_digest(),
            )
            .map_err(js_error_to_string)
            .unwrap();
        assert!(add_bob.is_consumed());
        assert_eq!(alice_group.epoch(), 1);

        let tree =
            PhaseB2RatchetTree::from_bytes(&alice_group.export_ratchet_tree().to_bytes().unwrap())
                .map_err(js_error_to_string)
                .unwrap();
        let mut bob_group = PhaseB2Group::join(&bob_provider, &add_bob.welcome().unwrap(), tree)
            .map_err(js_error_to_string)
            .unwrap();

        let mut self_update = alice_group
            .prepare_self_update(&alice_provider, &alice)
            .map_err(js_error_to_string)
            .unwrap();
        let self_projection = self_update.projection();
        assert_eq!(self_projection.proposal_count(), 0);
        assert!(self_projection.has_update_path());
        assert_eq!(self_projection.update_path_leaf_index(), Some(0));
        let bob_before = phase_b2_provider_entries(&bob_provider.serialize_state());
        let mut staged_update = bob_group
            .stage_inbound_commit(&bob_provider, &self_update.commit())
            .map_err(js_error_to_string)
            .unwrap();
        let bob_after = phase_b2_provider_entries(&bob_provider.serialize_state());
        assert_eq!(
            bob_before, bob_after,
            "inbound self-update staging wrote provider state"
        );
        let staged_projection = staged_update.projection();
        assert_eq!(staged_projection.committer_leaf_index(), 0);
        assert!(staged_projection.has_update_path());
        assert_eq!(
            phase_b2_check_verified_leaf_digest(
                &wrong_digest,
                &staged_projection.verified_leaf_digest(),
            )
            .unwrap_err(),
            "phase-b2 commit: verified-leaf digest mismatch"
        );
        assert!(!staged_update.is_consumed());
        bob_group
            .discard_staged_commit(&bob_provider, &mut staged_update)
            .map_err(js_error_to_string)
            .unwrap();
        let mut staged_update = bob_group
            .stage_inbound_commit(&bob_provider, &self_update.commit())
            .map_err(js_error_to_string)
            .unwrap();
        bob_group
            .merge_staged_commit(
                &mut bob_provider,
                &mut staged_update,
                &staged_projection.verified_leaf_digest(),
            )
            .map_err(js_error_to_string)
            .unwrap();
        alice_group
            .confirm_pending(
                &mut alice_provider,
                &mut self_update,
                &self_projection.verified_leaf_digest(),
            )
            .map_err(js_error_to_string)
            .unwrap();
        assert_eq!(alice_group.epoch(), 2);
        assert_eq!(bob_group.epoch(), 2);

        let mut add_charlie = alice_group
            .prepare_add(&alice_provider, &alice, &charlie_key_package)
            .map_err(js_error_to_string)
            .unwrap();
        let add_charlie_projection = add_charlie.projection();
        let mut bob_staged_add = bob_group
            .stage_inbound_commit(&bob_provider, &add_charlie.commit())
            .map_err(js_error_to_string)
            .unwrap();
        bob_group
            .merge_staged_commit(
                &mut bob_provider,
                &mut bob_staged_add,
                &add_charlie_projection.verified_leaf_digest(),
            )
            .map_err(js_error_to_string)
            .unwrap();
        alice_group
            .confirm_pending(
                &mut alice_provider,
                &mut add_charlie,
                &add_charlie_projection.verified_leaf_digest(),
            )
            .map_err(js_error_to_string)
            .unwrap();
        let charlie_leaf_index = add_charlie_projection
            .proposal_added_leaf_index(0)
            .unwrap()
            .unwrap();

        let mut remove_charlie = bob_group
            .prepare_remove(&bob_provider, &bob, charlie_leaf_index)
            .map_err(js_error_to_string)
            .unwrap();
        let remove_projection = remove_charlie.projection();
        assert_eq!(remove_projection.proposal_kind(0).unwrap(), "remove");
        assert_eq!(
            remove_projection
                .proposal_removed_parent_leaf_index(0)
                .unwrap(),
            Some(charlie_leaf_index)
        );
        assert_eq!(remove_projection.candidate_member_count(), 2);
        let alice_before = phase_b2_provider_entries(&alice_provider.serialize_state());
        let mut alice_staged_remove = alice_group
            .stage_inbound_commit(&alice_provider, &remove_charlie.commit())
            .map_err(js_error_to_string)
            .unwrap();
        let alice_after = phase_b2_provider_entries(&alice_provider.serialize_state());
        assert_eq!(
            alice_before, alice_after,
            "inbound Remove staging wrote provider state"
        );
        alice_group
            .merge_staged_commit(
                &mut alice_provider,
                &mut alice_staged_remove,
                &remove_projection.verified_leaf_digest(),
            )
            .map_err(js_error_to_string)
            .unwrap();
        bob_group
            .confirm_pending(
                &mut bob_provider,
                &mut remove_charlie,
                &remove_projection.verified_leaf_digest(),
            )
            .map_err(js_error_to_string)
            .unwrap();

        let plaintext = b"phase-b2-after-add-update-remove";
        let message = alice_group
            .create_application_message(&alice_provider, &alice, plaintext)
            .map_err(js_error_to_string)
            .unwrap();
        assert_eq!(
            bob_group
                .process_application_message(&bob_provider, &message)
                .map_err(js_error_to_string)
                .unwrap(),
            plaintext
        );
    }

    #[cfg(feature = "extensions-draft")]
    #[test]
    fn phase_b2_authenticated_hostile_inputs_reach_fail_closed_policy() {
        phase_b2_assert_exported_inline_self_update_accepts(
            b"phase-b2-referenced-add-positive-control",
            0x6d,
            0x6e,
        );
        let (
            alice_provider,
            alice,
            mut alice_group,
            bob_provider,
            _,
            mut bob_group,
        ) = phase_b2_stable_pair(b"phase-b2-referenced-add-policy", 0x71, 0x72);
        let charlie_provider = Provider::new();
        let (_, _, charlie_key_package) = phase_b2_identity(&charlie_provider, 0x73);
        let (proposal_message, _) = alice_group
            .mls_group
            .propose_add_member(
                alice_provider.as_ref(),
                &alice.keypair,
                &charlie_key_package.0,
            )
            .unwrap();
        let proposal_message = MlsMessageIn::tls_deserialize_exact(
            &proposal_message.tls_serialize_detached().unwrap(),
        )
        .unwrap();
        let proposal_public = match proposal_message.extract() {
            MlsMessageBodyIn::PublicMessage(message) => message,
            _ => panic!("expected referenced Add proposal to use PublicMessage framing"),
        };
        let processed = bob_group
            .mls_group
            .process_message(bob_provider.as_ref(), proposal_public)
            .unwrap();
        let queued = match processed.into_content() {
            openmls::framing::ProcessedMessageContent::ProposalMessage(proposal) => *proposal,
            _ => panic!("expected an authenticated referenced Add proposal"),
        };
        bob_group
            .mls_group
            .store_pending_proposal(bob_provider.inner.storage(), queued)
            .unwrap();
        let (referenced_commit, _, _) = alice_group
            .mls_group
            .commit_to_pending_proposals(alice_provider.as_ref(), &alice.keypair)
            .unwrap();
        let referenced_commit_bytes = referenced_commit.tls_serialize_detached().unwrap();
        let referenced_commit = MlsMessageIn::tls_deserialize_exact(
            &referenced_commit_bytes,
        )
        .unwrap();
        let referenced_public = match referenced_commit.extract() {
            MlsMessageBodyIn::PublicMessage(message) => message,
            _ => panic!("expected referenced Commit to use PublicMessage framing"),
        };
        let processed = bob_group
            .mls_group
            .process_message(bob_provider.as_ref(), referenced_public)
            .unwrap();
        let staged = match processed.into_content() {
            openmls::framing::ProcessedMessageContent::StagedCommitMessage(commit) => *commit,
            _ => panic!("expected a staged referenced Add Commit"),
        };
        let referenced = staged
            .queued_proposals()
            .next()
            .expect("referenced Add Commit must retain one queued proposal");
        assert!(matches!(referenced.proposal(), Proposal::Add(_)));
        assert_eq!(referenced.proposal_or_ref_type(), ProposalOrRefType::Reference);
        assert_eq!(
            phase_b2_check_proposal_policy(
                referenced.proposal_or_ref_type(),
                phase_b2_proposal_kind(referenced.proposal()),
            )
            .unwrap_err(),
            "PHASE_B2_REFERENCED_PROPOSAL_UNSUPPORTED"
        );
        let bob_before_referenced_rejection =
            phase_b2_provider_entries(&bob_provider.serialize_state());
        // JsError construction itself panics on a native non-WASM target. Catch
        // that test-environment boundary only after all other uses of this group;
        // the exact stable policy code was asserted from the same authenticated
        // staged proposal immediately above.
        let referenced_boundary_rejection = std::panic::catch_unwind(
            std::panic::AssertUnwindSafe(|| {
                bob_group.stage_inbound_commit(&bob_provider, &referenced_commit_bytes)
            }),
        );
        assert!(referenced_boundary_rejection.is_err());
        assert_eq!(
            phase_b2_provider_entries(&bob_provider.serialize_state()),
            bob_before_referenced_rejection,
            "exported referenced-proposal rejection must not write provider state"
        );

        let (
            alice_provider,
            alice,
            mut alice_group,
            bob_provider,
            _,
            mut bob_group,
        ) = phase_b2_stable_pair(b"phase-b2-update-proposal-policy", 0x74, 0x75);
        let (update_message, _) = alice_group
            .mls_group
            .propose_self_update(
                alice_provider.as_ref(),
                &alice.keypair,
                LeafNodeParameters::default(),
            )
            .unwrap();
        let update_message = MlsMessageIn::tls_deserialize_exact(
            &update_message.tls_serialize_detached().unwrap(),
        )
        .unwrap();
        let update_public = match update_message.extract() {
            MlsMessageBodyIn::PublicMessage(message) => message,
            _ => panic!("expected Update proposal to use PublicMessage framing"),
        };
        let processed = bob_group
            .mls_group
            .process_message(bob_provider.as_ref(), update_public)
            .unwrap();
        let update = match processed.into_content() {
            openmls::framing::ProcessedMessageContent::ProposalMessage(proposal) => *proposal,
            _ => panic!("expected an authenticated Update proposal"),
        };
        assert!(matches!(update.proposal(), Proposal::Update(_)));
        assert_eq!(update.proposal_or_ref_type(), ProposalOrRefType::Reference);
        assert_eq!(
            phase_b2_check_proposal_policy(
                update.proposal_or_ref_type(),
                phase_b2_proposal_kind(update.proposal()),
            )
            .unwrap_err(),
            "PHASE_B2_REFERENCED_PROPOSAL_UNSUPPORTED"
        );
        assert_eq!(
            phase_b2_check_proposal_policy(
                ProposalOrRefType::Proposal,
                phase_b2_proposal_kind(update.proposal()),
            )
            .unwrap_err(),
            "PHASE_B2_PROPOSAL_UPDATE_UNSUPPORTED"
        );

        phase_b2_assert_exported_inline_self_update_accepts(
            b"phase-b2-app-data-positive-control",
            0x6f,
            0x70,
        );
        let (
            alice_provider,
            alice,
            mut alice_group,
            bob_provider,
            _,
            mut bob_group,
        ) = phase_b2_stable_pair(b"phase-b2-app-data-policy", 0x76, 0x77);
        let mut stage = alice_group
            .mls_group
            .commit_builder()
            .add_proposal(Proposal::AppDataUpdate(Box::new(
                openmls::messages::proposals::AppDataUpdateProposal::update(
                    ADMIN_POLICY_V1_COMPONENT_ID,
                    b"opaque-policy-diff",
                ),
            )))
            .load_psks(alice_provider.inner.storage())
            .unwrap();
        let mut updater = stage.app_data_dictionary_updater();
        let mut unchanged_policy = vec![0x20];
        unchanged_policy.extend_from_slice(&alice.account_public_key());
        updater.set(openmls::component::ComponentData::from_parts(
            ADMIN_POLICY_V1_COMPONENT_ID,
            unchanged_policy.into(),
        ));
        stage.with_app_data_dictionary_updates(updater.changes());
        let app_data_bundle = stage
            .build(
                alice_provider.inner.rand(),
                alice_provider.inner.crypto(),
                &alice.keypair,
                |_| true,
            )
            .unwrap()
            .stage_commit(alice_provider.as_ref())
            .unwrap();
        let (app_data_commit, _, _) = app_data_bundle.into_contents();
        let app_data_commit_bytes = app_data_commit.tls_serialize_detached().unwrap();
        let app_data_commit = MlsMessageIn::tls_deserialize_exact(
            &app_data_commit_bytes,
        )
        .unwrap();
        let app_data_public = match app_data_commit.extract() {
            MlsMessageBodyIn::PublicMessage(message) => message,
            _ => panic!("expected AppDataUpdate Commit to use PublicMessage framing"),
        };
        let processed = bob_group
            .mls_group
            .process_message(bob_provider.as_ref(), app_data_public)
            .unwrap();
        let unresolved = match processed.into_content() {
            openmls::framing::ProcessedMessageContent::UnresolvedAppDataCommit(commit) => commit,
            _ => panic!("expected an unresolved AppDataUpdate Commit"),
        };
        assert_eq!(unresolved.app_data_update_proposals().count(), 1);
        assert_eq!(
            phase_b2_check_proposal_policy(
                ProposalOrRefType::Proposal,
                PhaseB2ProposalKind::AppDataUpdate,
            )
            .unwrap_err(),
            "PHASE_B2_APP_DATA_UPDATE_UNSUPPORTED"
        );
        let bob_before_app_data_rejection =
            phase_b2_provider_entries(&bob_provider.serialize_state());
        let app_data_boundary_rejection = std::panic::catch_unwind(
            std::panic::AssertUnwindSafe(|| {
                bob_group.stage_inbound_commit(&bob_provider, &app_data_commit_bytes)
            }),
        );
        assert!(app_data_boundary_rejection.is_err());
        assert_eq!(
            phase_b2_provider_entries(&bob_provider.serialize_state()),
            bob_before_app_data_rejection,
            "exported AppDataUpdate rejection must not write provider state"
        );
    }

    #[cfg(feature = "extensions-draft")]
    #[test]
    fn phase_b2_pending_recovery_is_explicit_and_bound() {
        let alice_provider = Provider::new();
        let bob_provider = Provider::new();
        let (alice, alice_proof, _) = phase_b2_identity(&alice_provider, 0x51);
        let (_, _, bob_key_package) = phase_b2_identity(&bob_provider, 0x52);
        let alice_account = alice.account_public_key();
        let alice_signature_key = alice.leaf_signature_key();
        let mut alice_group = PhaseB2Group::create_new(
            &alice_provider,
            &alice,
            b"phase-b2-pending-recovery",
            &alice_proof,
        )
        .map_err(js_error_to_string)
        .unwrap();
        let pending = alice_group
            .prepare_add(&alice_provider, &alice, &bob_key_package)
            .map_err(js_error_to_string)
            .unwrap();
        let pending_binding = pending.binding.as_ref().unwrap().clone();
        let snapshot = alice_provider.serialize_state();

        let mut merge_provider = Provider::new();
        merge_provider.restore_state(&snapshot).unwrap();
        let mut merge_group = PhaseB2Group::load(&merge_provider, b"phase-b2-pending-recovery")
            .map_err(js_error_to_string)
            .unwrap()
            .unwrap();
        let merge_identity =
            PhaseB2Identity::load(&merge_provider, &alice_account, &alice_signature_key)
                .map_err(js_error_to_string)
                .unwrap()
                .unwrap();
        assert_eq!(merge_identity.account_public_key(), alice_account);
        assert!(merge_group.has_pending_commit(&merge_provider).unwrap());
        let projection = merge_group
            .pending_projection(&merge_provider)
            .map_err(js_error_to_string)
            .unwrap()
            .unwrap();
        merge_group
            .confirm_pending_commit(
                &mut merge_provider,
                0,
                &alice_account,
                &alice_signature_key,
                &projection.verified_leaf_digest(),
            )
            .map_err(js_error_to_string)
            .unwrap();
        assert_eq!(merge_group.epoch(), 1);
        assert_eq!(merge_group.member_count(), 2);
        assert_eq!(
            merge_group
                .validate_binding_recovery(&merge_provider, &pending_binding)
                .unwrap_err(),
            "phase-b2 handle: wrong provider"
        );

        let clear_provider = Provider::new();
        clear_provider.restore_state(&snapshot).unwrap();
        let mut clear_group = PhaseB2Group::load(&clear_provider, b"phase-b2-pending-recovery")
            .map_err(js_error_to_string)
            .unwrap()
            .unwrap();
        clear_group
            .clear_pending_commit(&clear_provider, 0, &alice_account, &alice_signature_key)
            .map_err(js_error_to_string)
            .unwrap();
        assert!(!clear_group.has_pending_commit(&clear_provider).unwrap());
        assert_eq!(clear_group.epoch(), 0);

        let restored_snapshot = clear_provider.serialize_state();
        clear_provider.restore_state(&restored_snapshot).unwrap();
        assert_eq!(
            clear_group
                .validate_binding_recovery(&clear_provider, &clear_group.binding(&clear_provider))
                .unwrap_err(),
            "phase-b2 handle: invalidated by provider restore"
        );

        let other_provider = Provider::new();
        let (other, other_proof, _) = phase_b2_identity(&other_provider, 0x53);
        let other_group = PhaseB2Group::create_new(
            &other_provider,
            &other,
            b"phase-b2-other-group",
            &other_proof,
        )
        .map_err(js_error_to_string)
        .unwrap();
        let forged_same_provider_binding = PhaseB2HandleBinding {
            provider_instance_id: other_provider.instance_id,
            provider_restore_generation: other_provider.restore_generation.get(),
            group_instance_id: other_group.instance_id,
            group_id: b"not-the-group".to_vec(),
            prior_epoch: other_group.epoch(),
        };
        assert_eq!(
            other_group
                .validate_binding_recovery(&other_provider, &forged_same_provider_binding)
                .unwrap_err(),
            "phase-b2 handle: wrong group"
        );
    }

    #[cfg(feature = "extensions-draft")]
    #[test]
    fn phase_b2_profile_and_proposal_policy_fail_closed_with_stable_errors() {
        assert!(phase_b2_check_proposal_policy(
            ProposalOrRefType::Proposal,
            PhaseB2ProposalKind::Add,
        )
        .is_ok());
        assert!(phase_b2_check_proposal_policy(
            ProposalOrRefType::Proposal,
            PhaseB2ProposalKind::Remove,
        )
        .is_ok());
        assert_eq!(
            phase_b2_check_proposal_policy(ProposalOrRefType::Reference, PhaseB2ProposalKind::Add,)
                .unwrap_err(),
            "PHASE_B2_REFERENCED_PROPOSAL_UNSUPPORTED"
        );
        assert_eq!(
            phase_b2_check_proposal_policy(
                ProposalOrRefType::Proposal,
                PhaseB2ProposalKind::Update,
            )
            .unwrap_err(),
            "PHASE_B2_PROPOSAL_UPDATE_UNSUPPORTED"
        );
        assert_eq!(
            phase_b2_check_proposal_policy(
                ProposalOrRefType::Proposal,
                PhaseB2ProposalKind::AppDataUpdate,
            )
            .unwrap_err(),
            "PHASE_B2_APP_DATA_UPDATE_UNSUPPORTED"
        );
        assert_eq!(
            phase_b2_check_proposal_policy(
                ProposalOrRefType::Proposal,
                PhaseB2ProposalKind::Custom,
            )
            .unwrap_err(),
            "PHASE_B2_CUSTOM_PROPOSAL_UNSUPPORTED"
        );
        assert_eq!(
            phase_b2_check_proposal_policy(
                ProposalOrRefType::Proposal,
                PhaseB2ProposalKind::Other,
            )
            .unwrap_err(),
            "PHASE_B2_PROPOSAL_KIND_UNSUPPORTED"
        );

        let account = vec![0x61; 32];
        let mut proof = vec![0u8; 104];
        proof[..32].copy_from_slice(&account);
        assert!(phase_b2_check_identity_proof(&account, &proof).is_ok());
        assert_eq!(
            phase_b2_check_identity_proof(&account, &proof[..103]).unwrap_err(),
            "phase-b2 identity: proof must be exactly 104 bytes"
        );
        proof[0] ^= 1;
        assert_eq!(
            phase_b2_check_identity_proof(&account, &proof).unwrap_err(),
            "phase-b2 identity: proof signer does not match credential identity"
        );

        assert!(phase_b2_check_component_profile(
            &[1, ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID],
            &PHASE_B2_COMPONENTS,
        )
        .is_ok());
        assert_eq!(
            phase_b2_check_component_profile(&[1], &PHASE_B2_COMPONENTS).unwrap_err(),
            "phase-b2 leaf: unexpected component locations"
        );
        assert_eq!(
            phase_b2_check_component_profile(
                &[1, ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID],
                &[ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID],
            )
            .unwrap_err(),
            "phase-b2 leaf: unexpected supported components"
        );
        let oversized = vec![0u16; PHASE_B2_MAX_COMPONENTS + 1];
        assert_eq!(
            phase_b2_check_component_profile(&oversized, &PHASE_B2_COMPONENTS).unwrap_err(),
            "PHASE_B2_COMPONENT_LIMIT"
        );

        assert!(phase_b2_check_leaf_capabilities(&phase_b2_capabilities()).is_ok());
        let unsupported_leaf_capabilities = Capabilities::builder()
            .ciphersuites(vec![PROBE_CIPHERSUITE])
            .extensions(vec![ExtensionType::AppDataDictionary])
            .proposals(vec![])
            .build();
        assert_eq!(
            phase_b2_check_leaf_capabilities(&unsupported_leaf_capabilities).unwrap_err(),
            "phase-b2 leaf: unexpected capabilities"
        );

        assert!(phase_b2_group_context_components_match!(vec![
            1,
            ADMIN_POLICY_V1_COMPONENT_ID,
            GROUP_LIFECYCLE_V1_COMPONENT_ID,
        ]));
        assert!(!phase_b2_group_context_components_match!(vec![
            1,
            ADMIN_POLICY_V1_COMPONENT_ID,
            ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID,
            GROUP_LIFECYCLE_V1_COMPONENT_ID,
        ]));
        assert!(phase_b2_group_lifecycle_is_active!([0x00]));
        assert!(!phase_b2_group_lifecycle_is_active!([0x01]));

        assert!(phase_b2_check_required_profile(
            &[ExtensionType::AppDataDictionary],
            &[ProposalType::AppDataUpdate],
            0,
            &PHASE_B2_COMPONENTS,
        )
        .is_ok());
        assert_eq!(
            phase_b2_check_required_profile(
                &[ExtensionType::AppDataDictionary],
                &[],
                0,
                &PHASE_B2_COMPONENTS,
            )
            .unwrap_err(),
            "phase-b2 group: unexpected required capabilities"
        );
        assert_eq!(
            phase_b2_check_required_profile(
                &[ExtensionType::AppDataDictionary],
                &[ProposalType::AppDataUpdate],
                0,
                &[0x8003, 0x8009, 0x8009],
            )
            .unwrap_err(),
            "phase-b2 group: unexpected required components"
        );

        let mut one_admin = vec![0x20];
        one_admin.extend_from_slice(&[0x11; 32]);
        assert_eq!(
            phase_b2_decode_admin_policy_recovery(&one_admin).unwrap(),
            vec![vec![0x11; 32]]
        );
        assert_eq!(
            phase_b2_decode_admin_policy_recovery(&[]).unwrap_err(),
            "phase-b2 group: administrator policy is empty"
        );
        let mut empty_policy = vec![0x00];
        assert_eq!(
            phase_b2_decode_admin_policy_recovery(&empty_policy).unwrap_err(),
            "phase-b2 group: malformed administrator policy length"
        );
        empty_policy = vec![0x40, 0x20];
        empty_policy.extend_from_slice(&[0x11; 32]);
        assert_eq!(
            phase_b2_decode_admin_policy_recovery(&empty_policy).unwrap_err(),
            "phase-b2 group: malformed administrator policy length"
        );
        let mut duplicate_admin = vec![0x40, 0x40];
        duplicate_admin.extend_from_slice(&[0x11; 32]);
        duplicate_admin.extend_from_slice(&[0x11; 32]);
        assert_eq!(
            phase_b2_decode_admin_policy_recovery(&duplicate_admin).unwrap_err(),
            "phase-b2 group: administrator policy must be sorted and unique"
        );
        let mut unsorted_admin = vec![0x40, 0x40];
        unsorted_admin.extend_from_slice(&[0x22; 32]);
        unsorted_admin.extend_from_slice(&[0x11; 32]);
        assert_eq!(
            phase_b2_decode_admin_policy_recovery(&unsorted_admin).unwrap_err(),
            "phase-b2 group: administrator policy must be sorted and unique"
        );
        let mut non_integral_admin = vec![0x21];
        non_integral_admin.extend_from_slice(&[0x11; 33]);
        assert_eq!(
            phase_b2_decode_admin_policy_recovery(&non_integral_admin).unwrap_err(),
            "phase-b2 group: malformed administrator policy length"
        );

        let mut four_byte_policy = vec![0x80, 0x00, 0x40, 0x00];
        for index in 0u16..512 {
            let mut account_key = [0u8; 32];
            account_key[30..].copy_from_slice(&index.to_be_bytes());
            four_byte_policy.extend_from_slice(&account_key);
        }
        let decoded_four_byte_policy =
            phase_b2_decode_admin_policy_recovery(&four_byte_policy).unwrap();
        assert_eq!(decoded_four_byte_policy.len(), 512);
        assert_eq!(decoded_four_byte_policy[0], vec![0u8; 32]);
        let mut last_account = vec![0u8; 32];
        last_account[30..].copy_from_slice(&511u16.to_be_bytes());
        assert_eq!(decoded_four_byte_policy[511], last_account);

        // An eight-byte QUIC prefix for a value below 2^30 is non-canonical.
        // The usize conversion overflow branch is target-width dependent and is
        // therefore not claimed by this native x86_64 test.
        let noncanonical_eight_byte_policy =
            vec![0xc0, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x20];
        assert_eq!(
            phase_b2_decode_admin_policy_recovery(&noncanonical_eight_byte_policy).unwrap_err(),
            "phase-b2 group: malformed administrator policy length"
        );

        let admin_provider = Provider::new();
        let (admin_identity, admin_proof, _) = phase_b2_identity(&admin_provider, 0x62);
        let admin_group = PhaseB2Group::create_new(
            &admin_provider,
            &admin_identity,
            b"phase-b2-admin-membership-policy",
            &admin_proof,
        )
        .map_err(js_error_to_string)
        .unwrap();
        phase_b2_validate_group_context(
            admin_group.mls_group.public_group().group_context(),
            &[vec![0x62; 32]],
        )
        .map_err(js_error_to_string)
        .unwrap();
        let admin_membership_rejection = std::panic::catch_unwind(|| {
            phase_b2_validate_group_context(
                admin_group.mls_group.public_group().group_context(),
                &[vec![0x63; 32]],
            )
        });
        assert!(
            admin_membership_rejection.is_err(),
            "a non-member administrator must fail the production validator"
        );

        assert_eq!(
            phase_b2_check_key_package_metadata(CIPHERSUITE, false, true, 60).unwrap_err(),
            "phase-b2 key package: unexpected ciphersuite"
        );
        assert_eq!(
            phase_b2_check_key_package_metadata(PROBE_CIPHERSUITE, true, true, 60).unwrap_err(),
            "phase-b2 key package: last-resort package is not accepted"
        );
        assert_eq!(
            phase_b2_check_key_package_metadata(
                PROBE_CIPHERSUITE,
                false,
                true,
                PROBE_KEY_PACKAGE_LIFETIME_SECONDS + 60 * 60 + 1,
            )
            .unwrap_err(),
            "phase-b2 key package: lifetime exceeds bounded profile"
        );

        assert!(phase_b2_check_projection_bounds(
            PHASE_B2_MAX_PROPOSALS,
            PHASE_B2_MAX_ADDS,
            PHASE_B2_MAX_MEMBERS,
            PHASE_B2_MAX_GROUP_CONTEXT_BYTES,
        )
        .is_ok());
        assert_eq!(
            phase_b2_check_projection_bounds(PHASE_B2_MAX_PROPOSALS + 1, 0, 0, 0)
                .unwrap_err(),
            "PHASE_B2_PROPOSAL_LIMIT"
        );
        assert_eq!(
            phase_b2_check_projection_bounds(0, PHASE_B2_MAX_ADDS + 1, 0, 0).unwrap_err(),
            "PHASE_B2_ADD_LIMIT"
        );
        assert_eq!(
            phase_b2_check_projection_bounds(0, 0, PHASE_B2_MAX_MEMBERS + 1, 0).unwrap_err(),
            "PHASE_B2_MEMBER_LIMIT"
        );
        assert_eq!(
            phase_b2_check_projection_bounds(0, 0, 0, PHASE_B2_MAX_GROUP_CONTEXT_BYTES + 1)
                .unwrap_err(),
            "PHASE_B2_GROUP_CONTEXT_LIMIT"
        );
    }

    #[cfg(feature = "extensions-draft")]
    mod phase_b2_restore_probes {
        use super::*;
        use openmls::{
            component::ComponentData,
            extensions::RequiredCapabilitiesExtension,
            group::{
                GroupContext, MlsGroupJoinConfig, StagedCommit, PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
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
                .with_leaf_node_extensions(current_leaf_extensions(&founder.account_public_key))
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
            MlsGroup::load(provider.inner.storage(), &GroupId::from_slice(group_id))
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
            if component_ids
                != [
                    1,
                    ADMIN_POLICY_V1_COMPONENT_ID,
                    GROUP_LIFECYCLE_V1_COMPONENT_ID,
                ]
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
                    leaf_dictionary
                        .get(&1)
                        .ok_or("member app_components missing")?,
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
                .add_members(alice_provider.as_ref(), &alice.keypair, &[bob_key_package])
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
                if second_merge.is_ok() {
                    "no-op success"
                } else {
                    "error"
                }
            );
            assert_eq!(merge_group.epoch(), epoch_after_first_merge);
            assert_eq!(merge_group.members().count(), members_after_first_merge);
            let bob_merge_provider = restore_provider(&bob_seed_snapshot);
            let bob_merge_identity =
                reload_identity(&bob_merge_provider, &bob_account, &bob_signature_key);
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
            let bob_clear_identity =
                reload_identity(&bob_clear_provider, &bob_account, &bob_signature_key);
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
            let (alice_provider, alice, mut alice_group, bob_provider, bob, bob_group) =
                setup_stable_pair(self_update_group_id);
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
            let mut clear_update_group = load_group(&clear_update_provider, self_update_group_id);
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
            let (alice_provider, alice, mut alice_group, mut bob_provider, bob, mut bob_group) =
                setup_stable_pair(group_id);
            let charlie_provider = Provider::new();
            let charlie = new_identity(&charlie_provider, 0x43);
            let charlie_key_package = current_key_package(&charlie_provider, &charlie);

            let (commit, _welcome, _) = bob_group
                .add_members(bob_provider.as_ref(), &bob.keypair, &[charlie_key_package])
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
            assert!(
                decoded_equal,
                "staging unexpectedly mutated provider storage"
            );
            drop(staged_once);
            drop(alice_group);

            let mut restored_provider = restore_provider(&pre_stage);
            let restored_identity = reload_identity(
                &restored_provider,
                &alice.account_public_key,
                &alice_signature_key,
            );
            let mut restored_group = load_group(&restored_provider, group_id);
            let staged =
                stage_public_commit(&mut restored_group, &restored_provider, &commit_bytes);
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

        fn load_phase_b1_identity(
            provider: &Provider,
            account_public_key: &[u8],
            leaf_signature_key: &[u8],
        ) -> PhaseB1Identity {
            unwrap_js(PhaseB1Identity::load(
                provider,
                account_public_key,
                leaf_signature_key,
            ))
            .expect("restored provider must contain the exact Phase B1 signing key")
        }

        fn load_phase_b1_group(provider: &Provider, group_id: &[u8]) -> PhaseB1Group {
            unwrap_js(PhaseB1Group::load(provider, group_id))
                .expect("restored provider must contain the exact Phase B1 group")
        }

        fn phase_b1_error<T>(result: Result<T, &'static str>) -> &'static str {
            match result {
                Ok(_) => panic!("expected Phase B1 operation to fail"),
                Err(error) => error,
            }
        }

        fn assert_phase_b1_liveness(
            left_group: &mut PhaseB1Group,
            left_provider: &Provider,
            left_identity: &PhaseB1Identity,
            right_group: &mut PhaseB1Group,
            right_provider: &Provider,
            right_identity: &PhaseB1Identity,
        ) {
            let left_plaintext = b"phase-b2-1-left-to-right";
            let left_message = unwrap_js(left_group.create_application_message(
                left_provider,
                left_identity,
                left_plaintext,
            ));
            assert_eq!(
                unwrap_js(right_group.process_application_message(right_provider, &left_message)),
                left_plaintext
            );

            let right_plaintext = b"phase-b2-1-right-to-left";
            let right_message = unwrap_js(right_group.create_application_message(
                right_provider,
                right_identity,
                right_plaintext,
            ));
            assert_eq!(
                unwrap_js(left_group.process_application_message(left_provider, &right_message)),
                right_plaintext
            );
        }

        #[test]
        fn phase_b1_recovery_loads_identity_and_group() {
            let provider = Provider::new();
            let (alice, alice_proof, _) = probe_identity(&provider, 0x61);
            let account_public_key = alice.account_public_key();
            let leaf_signature_key = alice.leaf_signature_key();
            let group_id = b"phase-b2-1-load";
            let group = unwrap_js(PhaseB1Group::create_new(
                &provider,
                &alice,
                group_id,
                &alice_proof,
            ));
            assert_eq!(group.group_id(), group_id);
            let snapshot = provider.serialize_state();

            let restored_provider = restore_provider(&snapshot);
            let loaded_identity = load_phase_b1_identity(
                &restored_provider,
                &account_public_key,
                &leaf_signature_key,
            );
            assert_eq!(loaded_identity.account_public_key(), account_public_key);
            assert_eq!(loaded_identity.leaf_signature_key(), leaf_signature_key);
            let loaded_group = load_phase_b1_group(&restored_provider, group_id);
            assert_eq!(loaded_group.group_id(), group_id);
            assert_eq!(loaded_group.epoch(), 0);
            assert_eq!(loaded_group.member_count(), 1);
            assert!(unwrap_js(
                loaded_group.matches_own_identity(&account_public_key, &leaf_signature_key,)
            ));
            assert!(!unwrap_js(
                loaded_group.has_pending_commit(&restored_provider)
            ));

            assert!(unwrap_js(PhaseB1Identity::load(
                &restored_provider,
                &account_public_key,
                &[0xff; 32],
            ))
            .is_none());
            assert!(unwrap_js(PhaseB1Group::load(
                &restored_provider,
                b"phase-b2-1-missing",
            ))
            .is_none());
            assert!(
                PhaseB1Identity::load_recovery(&restored_provider, &[0; 31], &[0; 32],).is_err()
            );
            assert!(
                PhaseB1Identity::load_recovery(&restored_provider, &[0; 32], &[0; 31],).is_err()
            );
            assert!(PhaseB1Group::load_recovery(&restored_provider, b"").is_err());
            assert!(PhaseB1Group::load_recovery(&restored_provider, &[0; 65]).is_err());
        }

        #[test]
        fn phase_b1_recovery_confirms_pending_commit_after_restore() {
            let alice_provider = Provider::new();
            let bob_provider = Provider::new();
            let (alice, alice_proof, _) = probe_identity(&alice_provider, 0x62);
            let (bob, _, bob_key_package) = probe_identity(&bob_provider, 0x63);
            let alice_account = alice.account_public_key();
            let alice_leaf = alice.leaf_signature_key();
            let group_id = b"phase-b2-1-confirm";
            let mut alice_group = unwrap_js(PhaseB1Group::create_new(
                &alice_provider,
                &alice,
                group_id,
                &alice_proof,
            ));
            let pending = unwrap_js(alice_group.propose_and_commit_add(
                &alice_provider,
                &alice,
                &bob_key_package,
            ));
            let welcome = pending.welcome();
            let pending_snapshot = alice_provider.serialize_state();

            let mut restored_provider = restore_provider(&pending_snapshot);
            let restored_identity =
                load_phase_b1_identity(&restored_provider, &alice_account, &alice_leaf);
            let mut restored_group = load_phase_b1_group(&restored_provider, group_id);
            assert!(unwrap_js(
                restored_group.has_pending_commit(&restored_provider)
            ));
            unwrap_js(restored_group.confirm_pending_commit(&mut restored_provider, 0));
            assert_eq!(restored_group.epoch(), 1);
            assert_eq!(restored_group.member_count(), 2);
            assert!(!unwrap_js(
                restored_group.has_pending_commit(&restored_provider)
            ));
            let stable_before_repeat = snapshot_map(&restored_provider.serialize_state());
            let repeat_error =
                phase_b1_error(restored_group.validate_pending_recovery(&restored_provider, 1));
            assert!(repeat_error.contains("pending state is absent"));
            assert_eq!(
                snapshot_map(&restored_provider.serialize_state()),
                stable_before_repeat
            );

            let tree = unwrap_js(PhaseB1RatchetTree::from_bytes(
                &restored_group.export_ratchet_tree().to_bytes().unwrap(),
            ));
            let mut bob_group = unwrap_js(PhaseB1Group::join(&bob_provider, &welcome, tree));
            assert_phase_b1_liveness(
                &mut restored_group,
                &restored_provider,
                &restored_identity,
                &mut bob_group,
                &bob_provider,
                &bob,
            );
        }

        #[test]
        fn phase_b1_recovery_clears_pending_commit_after_restore() {
            let alice_provider = Provider::new();
            let bob_provider = Provider::new();
            let (alice, alice_proof, _) = probe_identity(&alice_provider, 0x64);
            let (bob, _, bob_key_package) = probe_identity(&bob_provider, 0x65);
            let alice_account = alice.account_public_key();
            let alice_leaf = alice.leaf_signature_key();
            let group_id = b"phase-b2-1-clear";
            let mut alice_group = unwrap_js(PhaseB1Group::create_new(
                &alice_provider,
                &alice,
                group_id,
                &alice_proof,
            ));
            let _pending = unwrap_js(alice_group.propose_and_commit_add(
                &alice_provider,
                &alice,
                &bob_key_package,
            ));
            let pending_snapshot = alice_provider.serialize_state();

            let clear_provider = restore_provider(&pending_snapshot);
            let mut clear_group = load_phase_b1_group(&clear_provider, group_id);
            assert!(unwrap_js(clear_group.has_pending_commit(&clear_provider)));
            unwrap_js(clear_group.clear_pending_commit(&clear_provider, 0));
            assert_eq!(clear_group.epoch(), 0);
            assert_eq!(clear_group.member_count(), 1);
            assert!(!unwrap_js(clear_group.has_pending_commit(&clear_provider)));

            let cleared_snapshot = clear_provider.serialize_state();
            let mut recovered_provider = restore_provider(&cleared_snapshot);
            let recovered_identity =
                load_phase_b1_identity(&recovered_provider, &alice_account, &alice_leaf);
            let mut recovered_group = load_phase_b1_group(&recovered_provider, group_id);
            assert!(!unwrap_js(
                recovered_group.has_pending_commit(&recovered_provider)
            ));
            let mut fresh_pending = unwrap_js(recovered_group.propose_and_commit_add(
                &recovered_provider,
                &recovered_identity,
                &bob_key_package,
            ));
            let fresh_welcome = fresh_pending.welcome();
            unwrap_js(
                recovered_group.confirm_pending_add(&mut recovered_provider, &mut fresh_pending),
            );
            assert_eq!(recovered_group.epoch(), 1);
            let tree = unwrap_js(PhaseB1RatchetTree::from_bytes(
                &recovered_group.export_ratchet_tree().to_bytes().unwrap(),
            ));
            let mut bob_group = unwrap_js(PhaseB1Group::join(&bob_provider, &fresh_welcome, tree));
            assert_phase_b1_liveness(
                &mut recovered_group,
                &recovered_provider,
                &recovered_identity,
                &mut bob_group,
                &bob_provider,
                &bob,
            );
        }

        #[test]
        fn phase_b1_recovery_rejects_provider_and_generation_confusion() {
            let provider = Provider::new();
            let (alice, alice_proof, _) = probe_identity(&provider, 0x66);
            let group_id = b"phase-b2-1-binding";
            let group = unwrap_js(PhaseB1Group::create_new(
                &provider,
                &alice,
                group_id,
                &alice_proof,
            ));
            let wrong_provider = Provider::new();
            let provider_before = snapshot_map(&provider.serialize_state());
            let wrong_before = snapshot_map(&wrong_provider.serialize_state());
            let wrong_error =
                phase_b1_error(group.validate_durable_recovery_state_recovery(&wrong_provider));
            assert!(wrong_error.contains("wrong provider"));
            assert_eq!(snapshot_map(&provider.serialize_state()), provider_before);
            assert_eq!(
                snapshot_map(&wrong_provider.serialize_state()),
                wrong_before
            );

            let snapshot = provider.serialize_state();
            unwrap_js(provider.restore_state(&snapshot));
            let restored_before = snapshot_map(&provider.serialize_state());
            let generation_error =
                phase_b1_error(group.validate_durable_recovery_state_recovery(&provider));
            assert!(generation_error.contains("invalidated by provider restore"));
            assert_eq!(snapshot_map(&provider.serialize_state()), restored_before);
            let loaded_group = load_phase_b1_group(&provider, group_id);
            assert!(!unwrap_js(loaded_group.has_pending_commit(&provider)));

            let legacy_provider = Provider::new();
            let legacy_identity = unwrap_js(Identity::new(&legacy_provider, "legacy"));
            let _legacy_group =
                Group::create_new(&legacy_provider, &legacy_identity, "phase-b2-1-legacy");
            let legacy_before = snapshot_map(&legacy_provider.serialize_state());
            let legacy_error = phase_b1_error(PhaseB1Group::load_recovery(
                &legacy_provider,
                b"phase-b2-1-legacy",
            ));
            assert!(legacy_error.contains("unexpected ciphersuite"));
            assert_eq!(
                snapshot_map(&legacy_provider.serialize_state()),
                legacy_before
            );
        }

        #[test]
        fn phase_b1_recovery_rejects_stale_duplicate_group_and_epoch() {
            let alice_provider = Provider::new();
            let bob_provider = Provider::new();
            let (alice, alice_proof, _) = probe_identity(&alice_provider, 0x67);
            let (_, _, bob_key_package) = probe_identity(&bob_provider, 0x68);
            let group_id = b"phase-b2-1-stale";
            let mut alice_group = unwrap_js(PhaseB1Group::create_new(
                &alice_provider,
                &alice,
                group_id,
                &alice_proof,
            ));
            let _pending = unwrap_js(alice_group.propose_and_commit_add(
                &alice_provider,
                &alice,
                &bob_key_package,
            ));
            let pending_snapshot = alice_provider.serialize_state();

            let mut shared_provider = restore_provider(&pending_snapshot);
            let mut current_group = load_phase_b1_group(&shared_provider, group_id);
            let stale_group = load_phase_b1_group(&shared_provider, group_id);
            unwrap_js(current_group.confirm_pending_commit(&mut shared_provider, 0));
            let stable_after_merge = snapshot_map(&shared_provider.serialize_state());
            let stale_error = phase_b1_error(
                stale_group.validate_durable_recovery_state_recovery(&shared_provider),
            );
            assert!(stale_error.contains("durable group disagrees with memory"));
            assert_eq!(
                snapshot_map(&shared_provider.serialize_state()),
                stable_after_merge
            );

            let mut wrong_epoch_provider = restore_provider(&pending_snapshot);
            let mut wrong_epoch_group = load_phase_b1_group(&wrong_epoch_provider, group_id);
            let pending_before_wrong_epoch = snapshot_map(&wrong_epoch_provider.serialize_state());
            let epoch_error = phase_b1_error(
                wrong_epoch_group.validate_pending_recovery(&wrong_epoch_provider, 1),
            );
            assert!(epoch_error.contains("stale epoch"));
            assert_eq!(
                snapshot_map(&wrong_epoch_provider.serialize_state()),
                pending_before_wrong_epoch
            );
            unwrap_js(wrong_epoch_group.confirm_pending_commit(&mut wrong_epoch_provider, 0));
            assert_eq!(wrong_epoch_group.epoch(), 1);
            assert_eq!(wrong_epoch_group.member_count(), 2);
            let stable_before_missing = snapshot_map(&wrong_epoch_provider.serialize_state());
            let missing_error = phase_b1_error(
                wrong_epoch_group.validate_pending_recovery(&wrong_epoch_provider, 1),
            );
            assert!(missing_error.contains("pending state is absent"));
            assert_eq!(
                snapshot_map(&wrong_epoch_provider.serialize_state()),
                stable_before_missing
            );
        }

        #[test]
        fn phase_b1_recovery_matches_own_identity_strictly() {
            let mut alice_provider = Provider::new();
            let bob_provider = Provider::new();
            let (alice, alice_proof, _) = probe_identity(&alice_provider, 0x69);
            let (bob, _, bob_key_package) = probe_identity(&bob_provider, 0x6a);
            let alice_account = alice.account_public_key();
            let alice_leaf = alice.leaf_signature_key();
            let unrelated = unwrap_js(PhaseB1Identity::new(&alice_provider, &[0x6b; 32]));
            let group_id = b"phase-b2-1-own-identity";
            let mut group = unwrap_js(PhaseB1Group::create_new(
                &alice_provider,
                &alice,
                group_id,
                &alice_proof,
            ));
            let mut pending =
                unwrap_js(group.propose_and_commit_add(&alice_provider, &alice, &bob_key_package));
            unwrap_js(group.confirm_pending_add(&mut alice_provider, &mut pending));
            assert!(unwrap_js(
                group.matches_own_identity(&alice_account, &alice_leaf)
            ));
            assert!(!unwrap_js(group.matches_own_identity(
                &bob.account_public_key(),
                &bob.leaf_signature_key(),
            )));
            assert!(!unwrap_js(group.matches_own_identity(
                &unrelated.account_public_key(),
                &unrelated.leaf_signature_key(),
            )));
            assert!(group
                .matches_own_identity_recovery(&[0; 31], &[0; 32])
                .is_err());
            assert!(group
                .matches_own_identity_recovery(&[0; 32], &[0; 31])
                .is_err());

            let snapshot = alice_provider.serialize_state();
            let restored_provider = restore_provider(&snapshot);
            let restored_group = load_phase_b1_group(&restored_provider, group_id);
            assert!(unwrap_js(
                restored_group.matches_own_identity(&alice_account, &alice_leaf,)
            ));
            assert!(unwrap_js(PhaseB1Identity::load(
                &restored_provider,
                &alice_account,
                &alice_leaf,
            ))
            .is_some());
            SignatureKeyPair::delete(
                restored_provider.inner.storage(),
                &alice_leaf,
                SignatureScheme::ED25519,
            )
            .unwrap();
            assert!(unwrap_js(PhaseB1Identity::load(
                &restored_provider,
                &alice_account,
                &alice_leaf,
            ))
            .is_none());
            let group_without_signer = load_phase_b1_group(&restored_provider, group_id);
            assert!(unwrap_js(
                group_without_signer.matches_own_identity(&alice_account, &alice_leaf,)
            ));
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

            let valid_dictionary =
                current_group_context_extensions(&founder.account_public_key, true)
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
