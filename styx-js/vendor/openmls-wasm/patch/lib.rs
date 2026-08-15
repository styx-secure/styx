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
    group::{
        GroupContext, ProcessedWelcome, StagedCommit, WelcomeError,
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
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
    storage::StorageProvider as _,
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
const GROUP_PROFILE_V1_COMPONENT_ID: ComponentId = 0x8001;
#[cfg(feature = "extensions-draft")]
const PHASE_B2_COMPONENTS: [ComponentId; 3] = [
    ADMIN_POLICY_V1_COMPONENT_ID,
    ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID,
    GROUP_LIFECYCLE_V1_COMPONENT_ID,
];
#[cfg(feature = "extensions-draft")]
const PHASE_B31_SUPPORTED_COMPONENTS: [ComponentId; 4] = [
    GROUP_PROFILE_V1_COMPONENT_ID,
    ADMIN_POLICY_V1_COMPONENT_ID,
    ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID,
    GROUP_LIFECYCLE_V1_COMPONENT_ID,
];
#[cfg(feature = "extensions-draft")]
const PHASE_B32A_SUPPORTED_COMPONENTS: [ComponentId; 5] = [
    0x0001,
    GROUP_PROFILE_V1_COMPONENT_ID,
    ADMIN_POLICY_V1_COMPONENT_ID,
    ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID,
    GROUP_LIFECYCLE_V1_COMPONENT_ID,
];
#[cfg(feature = "extensions-draft")]
const PHASE_B31_REQUIRED_COMPONENTS: [ComponentId; 4] = [
    GROUP_PROFILE_V1_COMPONENT_ID,
    ADMIN_POLICY_V1_COMPONENT_ID,
    ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID,
    GROUP_LIFECYCLE_V1_COMPONENT_ID,
];
#[cfg(feature = "extensions-draft")]
const _: () = {
    assert!(PHASE_B31_REQUIRED_COMPONENTS[0] == PHASE_B31_SUPPORTED_COMPONENTS[0]);
    assert!(PHASE_B31_REQUIRED_COMPONENTS[1] == PHASE_B31_SUPPORTED_COMPONENTS[1]);
    assert!(PHASE_B31_REQUIRED_COMPONENTS[2] == PHASE_B31_SUPPORTED_COMPONENTS[2]);
    assert!(PHASE_B31_REQUIRED_COMPONENTS[3] == PHASE_B31_SUPPORTED_COMPONENTS[3]);
};
#[cfg(feature = "extensions-draft")]
const PHASE_B31_GROUP_PROFILE_NAME_MAX_BYTES: usize = 256;
#[cfg(feature = "extensions-draft")]
const PHASE_B31_GROUP_PROFILE_DESCRIPTION_MAX_BYTES: usize = 4096;
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
#[cfg(feature = "extensions-draft")]
const PHASE_B32_VERIFIED_LEAF_DOMAIN: &[u8] = b"STYX-B32-JOIN-VERIFIED-LEAVES-v1";
#[cfg(feature = "extensions-draft")]
const PHASE_B32_PROJECTION_DOMAIN: &[u8] = b"STYX-B32-JOIN-PROJECTION-v1";
#[cfg(feature = "extensions-draft")]
const PHASE_B32_PROJECTION_VERSION: u16 = 1;
#[cfg(feature = "extensions-draft")]
const PHASE_B32_MAX_WELCOME_BYTES: usize = 1_048_576;
#[cfg(feature = "extensions-draft")]
const PHASE_B32_MAX_KEY_PACKAGE_BYTES: usize = 16_384;
#[cfg(feature = "extensions-draft")]
const PHASE_B32A_MAX_PROVIDER_BYTES: usize = 8 * 1024 * 1024;
#[cfg(feature = "extensions-draft")]
const PHASE_B32A_MAX_PROVIDER_ENTRIES: usize = 4096;
#[cfg(feature = "extensions-draft")]
const PHASE_B32A_MAX_PROVIDER_KEY_BYTES: usize = 64 * 1024;
#[cfg(feature = "extensions-draft")]
const PHASE_B32A_MAX_JSON_DEPTH: usize = 64;
#[cfg(feature = "extensions-draft")]
const PHASE_B32A_MAX_JSON_NODES: usize = 262_144;
#[cfg(feature = "extensions-draft")]
const PHASE_B32A_PROJECTION_DOMAIN: &[u8] = b"STYX-B32A-JOIN-PROJECTION-v1";
#[cfg(feature = "extensions-draft")]
const PHASE_B32A_LEAF_PROFILE_DOMAIN: &[u8] = b"STYX-B32A-LEAF-PROFILE-v1";
#[cfg(feature = "extensions-draft")]
const PHASE_B32A_PROJECTION_VERSION: u16 = 1;

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

#[cfg(feature = "extensions-draft")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum PhaseB32aSnapshotRole {
    Predecessor,
    CanonicalCandidate,
}

#[cfg(feature = "extensions-draft")]
struct PhaseB32aWipeBytes(Vec<u8>);

#[cfg(feature = "extensions-draft")]
impl Drop for PhaseB32aWipeBytes {
    fn drop(&mut self) {
        self.0.fill(0);
        self.0.clear();
    }
}

#[cfg(feature = "extensions-draft")]
struct PhaseB32aSnapshotEntries(Vec<(Vec<u8>, Vec<u8>)>);

#[cfg(feature = "extensions-draft")]
impl Drop for PhaseB32aSnapshotEntries {
    fn drop(&mut self) {
        for (key, value) in &mut self.0 {
            key.fill(0);
            value.fill(0);
        }
        self.0.clear();
    }
}

#[cfg(feature = "extensions-draft")]
struct PhaseB32aSeenKeys(std::collections::HashSet<Vec<u8>>);

#[cfg(feature = "extensions-draft")]
impl Drop for PhaseB32aSeenKeys {
    fn drop(&mut self) {
        for mut key in self.0.drain() {
            key.fill(0);
        }
    }
}

#[cfg(feature = "extensions-draft")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PhaseB32aPreparationClassification {
    ByteIdentical,
    RetentionTimestampBounded,
}

#[cfg(feature = "extensions-draft")]
impl PhaseB32aPreparationClassification {
    fn tag(self) -> &'static str {
        match self {
            Self::ByteIdentical => "BYTE_IDENTICAL",
            Self::RetentionTimestampBounded => "RETENTION_TIMESTAMP_BOUNDED",
        }
    }
}

#[cfg(feature = "extensions-draft")]
struct PhaseB32aPreparationEvidence {
    classification: PhaseB32aPreparationClassification,
    second_candidate_state_sha256: Vec<u8>,
    differing_storage_key: Vec<u8>,
}

#[cfg(feature = "extensions-draft")]
#[derive(Clone, Copy)]
struct PhaseB32aTimestampSpans {
    seconds: (usize, usize),
    nanos: (usize, usize),
}

/// Minimal strict JSON recognizer for the exact serde-json representation at
/// the pinned OpenMLS revision. It retains no parsed secret values. The only
/// returned offsets identify the two local retention-timestamp integers.
#[cfg(feature = "extensions-draft")]
struct PhaseB32aStrictJson<'a> {
    bytes: &'a [u8],
    offset: usize,
    nodes: usize,
}

#[cfg(feature = "extensions-draft")]
impl<'a> PhaseB32aStrictJson<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, JsError> {
        std::str::from_utf8(bytes)
            .map_err(|_| JsError::new("PHASE_B32A_MESSAGE_SECRETS_JSON_INVALID"))?;
        Ok(Self {
            bytes,
            offset: 0,
            nodes: 0,
        })
    }

    fn error() -> JsError {
        JsError::new("PHASE_B32A_MESSAGE_SECRETS_JSON_INVALID")
    }

    fn byte(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }

    fn bump_node(&mut self) -> Result<(), JsError> {
        self.nodes = self.nodes.checked_add(1).ok_or_else(Self::error)?;
        if self.nodes > PHASE_B32A_MAX_JSON_NODES {
            return Err(Self::error());
        }
        Ok(())
    }

    fn expect(&mut self, expected: u8) -> Result<(), JsError> {
        if self.byte() != Some(expected) {
            return Err(Self::error());
        }
        self.offset += 1;
        Ok(())
    }

    fn expect_literal(&mut self, expected: &[u8]) -> Result<(), JsError> {
        let end = self
            .offset
            .checked_add(expected.len())
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(Self::error)?;
        if &self.bytes[self.offset..end] != expected {
            return Err(Self::error());
        }
        self.offset = end;
        Ok(())
    }

    /// Pinned serde field names are unescaped ASCII. Rejecting escaped object
    /// keys also rejects alternate encodings and semantic duplicate keys.
    fn object_key(&mut self) -> Result<&'a [u8], JsError> {
        self.expect(b'"')?;
        let start = self.offset;
        while let Some(byte) = self.byte() {
            match byte {
                b'"' => {
                    let key = &self.bytes[start..self.offset];
                    self.offset += 1;
                    if key.is_empty()
                        || key
                            .iter()
                            .any(|byte| *byte < 0x20 || *byte >= 0x7f || *byte == b'\\')
                    {
                        return Err(Self::error());
                    }
                    return Ok(key);
                }
                b'\\' | 0x00..=0x1f | 0x80..=0xff => return Err(Self::error()),
                _ => self.offset += 1,
            }
        }
        Err(Self::error())
    }

    fn expected_key(&mut self, expected: &[u8]) -> Result<(), JsError> {
        if self.object_key()? != expected {
            return Err(Self::error());
        }
        self.expect(b':')
    }

    fn string_value(&mut self) -> Result<(), JsError> {
        self.expect(b'"')?;
        while let Some(byte) = self.byte() {
            match byte {
                b'"' => {
                    self.offset += 1;
                    return Ok(());
                }
                b'\\' => {
                    self.offset += 1;
                    match self.byte() {
                        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {
                            self.offset += 1;
                        }
                        Some(b'u') => {
                            self.offset += 1;
                            for _ in 0..4 {
                                if !self.byte().is_some_and(|byte| byte.is_ascii_hexdigit()) {
                                    return Err(Self::error());
                                }
                                self.offset += 1;
                            }
                        }
                        _ => return Err(Self::error()),
                    }
                }
                0x00..=0x1f => return Err(Self::error()),
                _ => self.offset += 1,
            }
        }
        Err(Self::error())
    }

    fn number(&mut self) -> Result<(usize, usize), JsError> {
        let start = self.offset;
        if self.byte() == Some(b'-') {
            self.offset += 1;
        }
        match self.byte() {
            Some(b'0') => {
                self.offset += 1;
                if self.byte().is_some_and(|byte| byte.is_ascii_digit()) {
                    return Err(Self::error());
                }
            }
            Some(b'1'..=b'9') => {
                self.offset += 1;
                while self.byte().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.offset += 1;
                }
            }
            _ => return Err(Self::error()),
        }
        if self.byte() == Some(b'.') {
            self.offset += 1;
            if !self.byte().is_some_and(|byte| byte.is_ascii_digit()) {
                return Err(Self::error());
            }
            while self.byte().is_some_and(|byte| byte.is_ascii_digit()) {
                self.offset += 1;
            }
        }
        if self.byte().is_some_and(|byte| byte == b'e' || byte == b'E') {
            self.offset += 1;
            if self.byte().is_some_and(|byte| byte == b'+' || byte == b'-') {
                self.offset += 1;
            }
            if !self.byte().is_some_and(|byte| byte.is_ascii_digit()) {
                return Err(Self::error());
            }
            while self.byte().is_some_and(|byte| byte.is_ascii_digit()) {
                self.offset += 1;
            }
        }
        Ok((start, self.offset))
    }

    fn unsigned_integer(&mut self) -> Result<(usize, usize, u64), JsError> {
        let start = self.offset;
        match self.byte() {
            Some(b'0') => {
                self.offset += 1;
                if self.byte().is_some_and(|byte| byte.is_ascii_digit()) {
                    return Err(Self::error());
                }
            }
            Some(b'1'..=b'9') => {
                self.offset += 1;
                while self.byte().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.offset += 1;
                }
            }
            _ => return Err(Self::error()),
        }
        let end = self.offset;
        let value = std::str::from_utf8(&self.bytes[start..end])
            .map_err(|_| Self::error())?
            .parse::<u64>()
            .map_err(|_| Self::error())?;
        Ok((start, end, value))
    }

    fn value(&mut self, depth: usize) -> Result<(), JsError> {
        if depth > PHASE_B32A_MAX_JSON_DEPTH {
            return Err(Self::error());
        }
        self.bump_node()?;
        match self.byte() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => self.string_value(),
            Some(b't') => self.expect_literal(b"true"),
            Some(b'f') => self.expect_literal(b"false"),
            Some(b'n') => self.expect_literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.number().map(|_| ()),
            _ => Err(Self::error()),
        }
    }

    fn array(&mut self, depth: usize) -> Result<(), JsError> {
        self.expect(b'[')?;
        if self.byte() == Some(b']') {
            self.offset += 1;
            return Ok(());
        }
        loop {
            self.value(depth)?;
            match self.byte() {
                Some(b',') => self.offset += 1,
                Some(b']') => {
                    self.offset += 1;
                    return Ok(());
                }
                _ => return Err(Self::error()),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<(), JsError> {
        self.expect(b'{')?;
        if self.byte() == Some(b'}') {
            self.offset += 1;
            return Ok(());
        }
        let mut keys = std::collections::HashSet::new();
        loop {
            let key = self.object_key()?.to_vec();
            if !keys.insert(key) {
                return Err(Self::error());
            }
            self.expect(b':')?;
            self.value(depth)?;
            match self.byte() {
                Some(b',') => self.offset += 1,
                Some(b'}') => {
                    self.offset += 1;
                    return Ok(());
                }
                _ => return Err(Self::error()),
            }
        }
    }

    fn message_secrets_timestamp_spans(mut self) -> Result<PhaseB32aTimestampSpans, JsError> {
        self.expect(b'{')?;
        self.expected_key(b"max_epochs")?;
        self.unsigned_integer()?;
        self.expect(b',')?;
        self.expected_key(b"past_epoch_trees")?;
        self.array(1)?;
        self.expect(b',')?;
        self.expected_key(b"message_secrets")?;
        self.expect(b'{')?;
        for key in [
            b"sender_data_secret".as_slice(),
            b"membership_key".as_slice(),
            b"confirmation_key".as_slice(),
            b"serialized_context".as_slice(),
            b"secret_tree".as_slice(),
        ] {
            self.expected_key(key)?;
            self.value(2)?;
            self.expect(b',')?;
        }
        self.expected_key(b"added_at")?;
        self.expect(b'{')?;
        self.expected_key(b"secs_since_epoch")?;
        let (seconds_start, seconds_end, _) = self.unsigned_integer()?;
        self.expect(b',')?;
        self.expected_key(b"nanos_since_epoch")?;
        let (nanos_start, nanos_end, nanos) = self.unsigned_integer()?;
        if nanos >= 1_000_000_000 {
            return Err(Self::error());
        }
        self.expect(b'}')?;
        self.expect(b'}')?;
        self.expect(b'}')?;
        if self.offset != self.bytes.len() {
            return Err(Self::error());
        }
        Ok(PhaseB32aTimestampSpans {
            seconds: (seconds_start, seconds_end),
            nanos: (nanos_start, nanos_end),
        })
    }
}

#[cfg(feature = "extensions-draft")]
fn phase_b32a_message_secrets_timestamp_spans(
    value: &[u8],
) -> Result<PhaseB32aTimestampSpans, JsError> {
    PhaseB32aStrictJson::new(value)?.message_secrets_timestamp_spans()
}

#[cfg(feature = "extensions-draft")]
fn phase_b32a_values_equal_except_retention_timestamp(
    left: &[u8],
    left_spans: PhaseB32aTimestampSpans,
    right: &[u8],
    right_spans: PhaseB32aTimestampSpans,
) -> bool {
    left[..left_spans.seconds.0] == right[..right_spans.seconds.0]
        && left[left_spans.seconds.1..left_spans.nanos.0]
            == right[right_spans.seconds.1..right_spans.nanos.0]
        && left[left_spans.nanos.1..] == right[right_spans.nanos.1..]
}

#[cfg(feature = "extensions-draft")]
fn phase_b32a_compare_candidate_states(
    first_state: &[u8],
    second_state: &[u8],
    second_candidate_state_sha256: Vec<u8>,
) -> Result<PhaseB32aPreparationEvidence, JsError> {
    if second_candidate_state_sha256.len() != 32 {
        return Err(JsError::new(
            "PHASE_B32A_SECOND_CANDIDATE_DIGEST_INVALID",
        ));
    }
    let first = phase_b32a_snapshot_entries(
        first_state,
        PhaseB32aSnapshotRole::CanonicalCandidate,
    )?;
    let second = phase_b32a_snapshot_entries(
        second_state,
        PhaseB32aSnapshotRole::CanonicalCandidate,
    )?;
    if first.0.len() != second.0.len() {
        return Err(JsError::new("PHASE_B32A_PREPARATION_KEY_SET_MISMATCH"));
    }
    let mut message_secrets_count = 0usize;
    let mut differing_storage_key = Vec::new();
    for ((first_key, first_value), (second_key, second_value)) in
        first.0.iter().zip(second.0.iter())
    {
        if first_key != second_key {
            return Err(JsError::new("PHASE_B32A_PREPARATION_KEY_SET_MISMATCH"));
        }
        let is_message_secrets = first_key.starts_with(b"MessageSecrets");
        if is_message_secrets {
            message_secrets_count += 1;
            let first_spans = phase_b32a_message_secrets_timestamp_spans(first_value)?;
            let second_spans = phase_b32a_message_secrets_timestamp_spans(second_value)?;
            if first_value != second_value {
                if !phase_b32a_values_equal_except_retention_timestamp(
                    first_value,
                    first_spans,
                    second_value,
                    second_spans,
                ) {
                    return Err(JsError::new(
                        "PHASE_B32A_MESSAGE_SECRETS_NON_TIMESTAMP_DIVERGENCE",
                    ));
                }
                differing_storage_key = first_key.clone();
            }
        } else if first_value != second_value {
            return Err(JsError::new("PHASE_B32A_NON_RETENTION_DIVERGENCE"));
        }
    }
    if message_secrets_count != 1 {
        return Err(JsError::new(
            "PHASE_B32A_MESSAGE_SECRETS_ENTRY_COUNT_INVALID",
        ));
    }
    Ok(PhaseB32aPreparationEvidence {
        classification: if differing_storage_key.is_empty() {
            PhaseB32aPreparationClassification::ByteIdentical
        } else {
            PhaseB32aPreparationClassification::RetentionTimestampBounded
        },
        second_candidate_state_sha256,
        differing_storage_key,
    })
}

/// Private, operation-scoped provider. Its raw in-memory store is overwritten
/// best-effort on every exit before the map is dropped. This does not claim
/// allocator-page or physical erasure.
#[cfg(feature = "extensions-draft")]
struct PhaseB32aPrivateProvider {
    provider: Provider,
}

#[cfg(feature = "extensions-draft")]
impl Drop for PhaseB32aPrivateProvider {
    fn drop(&mut self) {
        if let Ok(mut values) = self.provider.inner.storage().values.write() {
            for (mut key, mut value) in values.drain() {
                key.fill(0);
                value.fill(0);
            }
        }
    }
}

#[cfg(feature = "extensions-draft")]
fn phase_b32a_constant_time_eq_32(left: &[u8], right: &[u8]) -> bool {
    if left.len() != 32 || right.len() != 32 {
        return false;
    }
    let mut difference = 0u8;
    for index in 0..32 {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

#[cfg(feature = "extensions-draft")]
fn phase_b32a_read_u64(bytes: &[u8], offset: &mut usize) -> Result<u64, JsError> {
    let end = offset
        .checked_add(8)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| JsError::new("PHASE_B32A_PROVIDER_SNAPSHOT_MALFORMED"))?;
    let mut encoded = [0u8; 8];
    encoded.copy_from_slice(&bytes[*offset..end]);
    *offset = end;
    Ok(u64::from_be_bytes(encoded))
}

#[cfg(feature = "extensions-draft")]
fn phase_b32a_snapshot_entries(
    bytes: &[u8],
    role: PhaseB32aSnapshotRole,
) -> Result<PhaseB32aSnapshotEntries, JsError> {
    if bytes.is_empty() || bytes.len() > PHASE_B32A_MAX_PROVIDER_BYTES {
        return Err(JsError::new("PHASE_B32A_PROVIDER_SNAPSHOT_SIZE_INVALID"));
    }
    let mut offset = 0usize;
    let count = usize::try_from(phase_b32a_read_u64(bytes, &mut offset)?)
        .map_err(|_| JsError::new("PHASE_B32A_PROVIDER_ENTRY_LIMIT"))?;
    if count > PHASE_B32A_MAX_PROVIDER_ENTRIES {
        return Err(JsError::new("PHASE_B32A_PROVIDER_ENTRY_LIMIT"));
    }
    let mut entries = PhaseB32aSnapshotEntries(Vec::with_capacity(count));
    let mut seen = PhaseB32aSeenKeys(std::collections::HashSet::with_capacity(count));
    let mut previous_key: Option<PhaseB32aWipeBytes> = None;
    for _ in 0..count {
        let key_len = usize::try_from(phase_b32a_read_u64(bytes, &mut offset)?)
            .map_err(|_| JsError::new("PHASE_B32A_PROVIDER_SNAPSHOT_MALFORMED"))?;
        let value_len = usize::try_from(phase_b32a_read_u64(bytes, &mut offset)?)
            .map_err(|_| JsError::new("PHASE_B32A_PROVIDER_SNAPSHOT_MALFORMED"))?;
        if key_len > PHASE_B32A_MAX_PROVIDER_KEY_BYTES {
            return Err(JsError::new("PHASE_B32A_PROVIDER_KEY_LIMIT"));
        }
        let key_end = offset
            .checked_add(key_len)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| JsError::new("PHASE_B32A_PROVIDER_SNAPSHOT_MALFORMED"))?;
        let mut key = PhaseB32aWipeBytes(bytes[offset..key_end].to_vec());
        offset = key_end;
        let value_end = offset
            .checked_add(value_len)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| JsError::new("PHASE_B32A_PROVIDER_SNAPSHOT_MALFORMED"))?;
        let mut value = PhaseB32aWipeBytes(bytes[offset..value_end].to_vec());
        offset = value_end;
        if !seen.0.insert(key.0.clone()) {
            return Err(JsError::new("PHASE_B32A_PROVIDER_DUPLICATE_KEY"));
        }
        if role == PhaseB32aSnapshotRole::CanonicalCandidate {
            if previous_key
                .as_ref()
                .is_some_and(|previous| previous.0.as_slice() >= key.0.as_slice())
            {
                return Err(JsError::new("PHASE_B32A_PROVIDER_NONCANONICAL_ORDER"));
            }
            previous_key = Some(PhaseB32aWipeBytes(key.0.clone()));
        }
        entries
            .0
            .push((std::mem::take(&mut key.0), std::mem::take(&mut value.0)));
    }
    if offset != bytes.len() {
        return Err(JsError::new("PHASE_B32A_PROVIDER_TRAILING_BYTES"));
    }
    Ok(entries)
}

#[cfg(feature = "extensions-draft")]
impl PhaseB32aPrivateProvider {
    fn from_snapshot(bytes: &[u8], role: PhaseB32aSnapshotRole) -> Result<Self, JsError> {
        let mut parsed = phase_b32a_snapshot_entries(bytes, role)?;
        let provider = Provider::new();
        let mut map = std::collections::HashMap::with_capacity(parsed.0.len());
        for (key, value) in std::mem::take(&mut parsed.0) {
            map.insert(key, value);
        }
        *provider.inner.storage().values.write().unwrap() = map;
        Ok(Self { provider })
    }

    fn canonical_state(&self) -> Result<Vec<u8>, JsError> {
        let values = self.provider.inner.storage().values.read().unwrap();
        if values.len() > PHASE_B32A_MAX_PROVIDER_ENTRIES {
            return Err(JsError::new("PHASE_B32A_PROVIDER_ENTRY_LIMIT"));
        }
        let mut entries = values.iter().collect::<Vec<_>>();
        entries.sort_by(|(left, _), (right, _)| left.as_slice().cmp(right.as_slice()));
        let mut output = Vec::new();
        output.extend_from_slice(&(entries.len() as u64).to_be_bytes());
        for (key, value) in entries {
            if key.len() > PHASE_B32A_MAX_PROVIDER_KEY_BYTES {
                return Err(JsError::new("PHASE_B32A_PROVIDER_KEY_LIMIT"));
            }
            output.extend_from_slice(&(key.len() as u64).to_be_bytes());
            output.extend_from_slice(&(value.len() as u64).to_be_bytes());
            output.extend_from_slice(key);
            output.extend_from_slice(value);
            if output.len() > PHASE_B32A_MAX_PROVIDER_BYTES {
                return Err(JsError::new("PHASE_B32A_PROVIDER_SNAPSHOT_SIZE_INVALID"));
            }
        }
        Ok(output)
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
fn phase_b31_read_canonical_quic_varint(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<usize, &'static str> {
    let first = *bytes
        .get(*offset)
        .ok_or("phase-b3.1 codec: truncated QUIC varint")?;
    let width = match first >> 6 {
        0 => 1usize,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };
    let end = offset
        .checked_add(width)
        .ok_or("phase-b3.1 codec: QUIC varint offset overflow")?;
    if end > bytes.len() {
        return Err("phase-b3.1 codec: truncated QUIC varint");
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[*offset + 1..end] {
        value = (value << 8) | u64::from(*byte);
    }
    let canonical = match width {
        1 => true,
        2 => value >= (1 << 6),
        4 => value >= (1 << 14),
        8 => value >= (1 << 30),
        _ => false,
    };
    if !canonical {
        return Err("phase-b3.1 codec: non-canonical QUIC varint");
    }
    let value = usize::try_from(value)
        .map_err(|_| "phase-b3.1 codec: QUIC varint exceeds platform size")?;
    *offset = end;
    Ok(value)
}

#[cfg(feature = "extensions-draft")]
fn phase_b31_write_canonical_quic_varint(
    value: usize,
    output: &mut Vec<u8>,
) -> Result<(), &'static str> {
    let value = u64::try_from(value)
        .map_err(|_| "phase-b3.1 codec: length exceeds QUIC varint range")?;
    if value < (1 << 6) {
        output.push(value as u8);
    } else if value < (1 << 14) {
        output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < (1 << 30) {
        output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else if value < (1u64 << 62) {
        output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    } else {
        return Err("phase-b3.1 codec: length exceeds QUIC varint range");
    }
    Ok(())
}

#[cfg(feature = "extensions-draft")]
fn phase_b31_decode_component_ids(bytes: &[u8]) -> Result<Vec<ComponentId>, &'static str> {
    let mut offset = 0usize;
    let declared_bytes = phase_b31_read_canonical_quic_varint(bytes, &mut offset)?;
    if declared_bytes > PHASE_B2_MAX_COMPONENTS * 2 {
        return Err("PHASE_B31_COMPONENT_LIMIT");
    }
    if declared_bytes % 2 != 0 {
        return Err("phase-b3.1 components: odd byte length");
    }
    let end = offset
        .checked_add(declared_bytes)
        .ok_or("PHASE_B31_COMPONENT_LIMIT")?;
    if end > bytes.len() {
        return Err("phase-b3.1 components: truncated list");
    }
    if end != bytes.len() {
        return Err("phase-b3.1 components: trailing bytes");
    }
    let component_ids: Vec<ComponentId> = bytes[offset..end]
        .chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
        .collect();
    if component_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("phase-b3.1 components: list must be sorted and unique");
    }
    Ok(component_ids)
}

#[cfg(feature = "extensions-draft")]
fn phase_b31_validate_utf8_field(
    bytes: &[u8],
    maximum: usize,
) -> Result<(), &'static str> {
    if bytes.len() > maximum {
        return Err("PHASE_B31_GROUP_PROFILE_LIMIT");
    }
    std::str::from_utf8(bytes).map_err(|_| "phase-b3.1 group profile: invalid UTF-8")?;
    Ok(())
}

#[cfg(feature = "extensions-draft")]
fn phase_b31_encode_group_profile(
    name: &[u8],
    description: &[u8],
) -> Result<Vec<u8>, &'static str> {
    phase_b31_validate_utf8_field(name, PHASE_B31_GROUP_PROFILE_NAME_MAX_BYTES)?;
    phase_b31_validate_utf8_field(
        description,
        PHASE_B31_GROUP_PROFILE_DESCRIPTION_MAX_BYTES,
    )?;
    let capacity = 4usize
        .checked_add(name.len())
        .and_then(|size| size.checked_add(description.len()))
        .ok_or("PHASE_B31_GROUP_PROFILE_LIMIT")?;
    let mut output = Vec::with_capacity(capacity);
    phase_b31_write_canonical_quic_varint(name.len(), &mut output)?;
    output.extend_from_slice(name);
    phase_b31_write_canonical_quic_varint(description.len(), &mut output)?;
    output.extend_from_slice(description);
    Ok(output)
}

#[cfg(feature = "extensions-draft")]
fn phase_b31_decode_group_profile(bytes: &[u8]) -> Result<PhaseB31GroupProfile, &'static str> {
    let mut offset = 0usize;
    let name_len = phase_b31_read_canonical_quic_varint(bytes, &mut offset)?;
    if name_len > PHASE_B31_GROUP_PROFILE_NAME_MAX_BYTES {
        return Err("PHASE_B31_GROUP_PROFILE_LIMIT");
    }
    let name_end = offset
        .checked_add(name_len)
        .ok_or("PHASE_B31_GROUP_PROFILE_LIMIT")?;
    if name_end > bytes.len() {
        return Err("phase-b3.1 group profile: truncated name");
    }
    let name = &bytes[offset..name_end];
    phase_b31_validate_utf8_field(name, PHASE_B31_GROUP_PROFILE_NAME_MAX_BYTES)?;
    offset = name_end;

    let description_len = phase_b31_read_canonical_quic_varint(bytes, &mut offset)?;
    if description_len > PHASE_B31_GROUP_PROFILE_DESCRIPTION_MAX_BYTES {
        return Err("PHASE_B31_GROUP_PROFILE_LIMIT");
    }
    let description_end = offset
        .checked_add(description_len)
        .ok_or("PHASE_B31_GROUP_PROFILE_LIMIT")?;
    if description_end > bytes.len() {
        return Err("phase-b3.1 group profile: truncated description");
    }
    if description_end != bytes.len() {
        return Err("phase-b3.1 group profile: trailing bytes");
    }
    let description = &bytes[offset..description_end];
    phase_b31_validate_utf8_field(
        description,
        PHASE_B31_GROUP_PROFILE_DESCRIPTION_MAX_BYTES,
    )?;
    Ok(PhaseB31GroupProfile {
        name: name.to_vec(),
        description: description.to_vec(),
    })
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
fn phase_b31_leaf_extensions(proof: &[u8]) -> Result<Extensions<LeafNode>, JsError> {
    if proof.len() != ACCOUNT_IDENTITY_PROOF_V2_LENGTH {
        return Err(JsError::new(
            "phase-b3.1 identity: proof must be exactly 104 bytes",
        ));
    }
    let supported = PHASE_B31_SUPPORTED_COMPONENTS
        .to_vec()
        .tls_serialize_detached()
        .map_err(|_| JsError::new("phase-b3.1 identity: component encoding failed"))?;
    let decoded = phase_b31_decode_component_ids(&supported).map_err(JsError::new)?;
    if decoded != PHASE_B31_SUPPORTED_COMPONENTS {
        return Err(JsError::new(
            "phase-b3.1 identity: encoded component list is not canonical",
        ));
    }
    let mut dictionary = AppDataDictionary::new();
    dictionary.insert(1, supported);
    dictionary.insert(ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID, proof.to_vec());
    Extensions::single(Extension::AppDataDictionary(
        AppDataDictionaryExtension::new(dictionary),
    ))
    .map_err(|_| JsError::new("phase-b3.1 identity: leaf extension construction failed"))
}

#[cfg(feature = "extensions-draft")]
fn phase_b32a_styx_capabilities() -> Capabilities {
    phase_b2_capabilities()
}

#[cfg(feature = "extensions-draft")]
fn phase_b32a_mdk_capabilities() -> Capabilities {
    Capabilities::new(
        None,
        Some(&[PROBE_CIPHERSUITE]),
        Some(&[
            ExtensionType::RequiredCapabilities,
            ExtensionType::AppDataDictionary,
        ]),
        Some(&[ProposalType::AppDataUpdate]),
        None,
    )
}

#[cfg(feature = "extensions-draft")]
fn phase_b32a_leaf_extensions(proof: &[u8]) -> Result<Extensions<LeafNode>, JsError> {
    if proof.len() != ACCOUNT_IDENTITY_PROOF_V2_LENGTH {
        return Err(JsError::new("PHASE_B32A_IDENTITY_PROOF_INVALID"));
    }
    let supported = PHASE_B32A_SUPPORTED_COMPONENTS
        .to_vec()
        .tls_serialize_detached()
        .map_err(|_| JsError::new("PHASE_B32A_COMPONENT_ENCODING_FAILED"))?;
    if phase_b31_decode_component_ids(&supported)
        .map_err(|_| JsError::new("PHASE_B32A_COMPONENT_ENCODING_FAILED"))?
        != PHASE_B32A_SUPPORTED_COMPONENTS
    {
        return Err(JsError::new("PHASE_B32A_COMPONENT_ENCODING_FAILED"));
    }
    let mut dictionary = AppDataDictionary::new();
    dictionary.insert(0x0001, supported);
    dictionary.insert(ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID, proof.to_vec());
    Extensions::single(Extension::AppDataDictionary(
        AppDataDictionaryExtension::new(dictionary),
    ))
    .map_err(|_| JsError::new("PHASE_B32A_LEAF_EXTENSION_CONSTRUCTION_FAILED"))
}

#[cfg(feature = "extensions-draft")]
fn phase_b31_check_component_profile(
    component_ids: &[ComponentId],
    supported_component_ids: &[ComponentId],
) -> Result<(), &'static str> {
    if component_ids != [1, ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID] {
        return Err("phase-b3.1 leaf: unexpected component locations");
    }
    if supported_component_ids != PHASE_B31_SUPPORTED_COMPONENTS {
        return Err("phase-b3.1 leaf: unexpected supported components");
    }
    Ok(())
}

#[cfg(feature = "extensions-draft")]
fn phase_b31_validate_leaf(leaf: &LeafNode) -> Result<Vec<ComponentId>, JsError> {
    let identity = leaf.credential().serialized_content();
    if identity.len() != 32 || leaf.signature_key().as_slice().len() != 32 {
        return Err(JsError::new(
            "phase-b3.1 leaf: identity and signature key must be exactly 32 bytes",
        ));
    }
    phase_b2_check_leaf_capabilities(leaf.capabilities())
        .map_err(|_| JsError::new("phase-b3.1 leaf: unexpected capabilities"))?;
    let dictionary = leaf
        .extensions()
        .app_data_dictionary()
        .ok_or_else(|| JsError::new("phase-b3.1 leaf: app-data dictionary missing"))?
        .dictionary();
    if dictionary.len() != 2 {
        return Err(JsError::new(
            "phase-b3.1 leaf: app-data dictionary must have exactly two entries",
        ));
    }
    let component_ids: Vec<ComponentId> =
        dictionary.entries().map(|entry| entry.id()).collect();
    let supported = phase_b31_decode_component_ids(
        dictionary
            .get(&1)
            .ok_or_else(|| JsError::new("phase-b3.1 leaf: supported components missing"))?,
    )
    .map_err(JsError::new)?;
    phase_b31_check_component_profile(&component_ids, &supported).map_err(JsError::new)?;
    let proof = dictionary
        .get(&ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID)
        .ok_or_else(|| JsError::new("phase-b3.1 leaf: identity proof missing"))?;
    phase_b2_check_identity_proof(identity, proof)
        .map_err(|_| JsError::new("phase-b3.1 leaf: invalid identity proof"))?;
    Ok(supported)
}

#[cfg(feature = "extensions-draft")]
fn phase_b31_inspect_key_package(key_package: &OpenMlsKeyPackage) -> Result<(), JsError> {
    let lifetime = key_package.life_time();
    phase_b2_check_key_package_metadata(
        key_package.ciphersuite(),
        key_package.last_resort(),
        lifetime.has_acceptable_range(),
        lifetime.not_after().saturating_sub(lifetime.not_before()),
    )
    .map_err(|_| JsError::new("phase-b3.1 key package: unexpected metadata"))?;
    phase_b31_validate_leaf(key_package.leaf_node())?;
    Ok(())
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
fn phase_b31_group_context_extensions(
    founder_account: &[u8],
    name: &[u8],
    description: &[u8],
) -> Result<Extensions<GroupContext>, JsError> {
    if founder_account.len() != 32 {
        return Err(JsError::new(
            "phase-b3.1 group: founder account key must be exactly 32 bytes",
        ));
    }
    let required = PHASE_B31_REQUIRED_COMPONENTS
        .to_vec()
        .tls_serialize_detached()
        .map_err(|_| JsError::new("phase-b3.1 group: component encoding failed"))?;
    if phase_b31_decode_component_ids(&required).map_err(JsError::new)?
        != PHASE_B31_REQUIRED_COMPONENTS
    {
        return Err(JsError::new(
            "phase-b3.1 group: encoded component list is not canonical",
        ));
    }
    let mut dictionary = AppDataDictionary::new();
    dictionary.insert(1, required);
    dictionary.insert(
        GROUP_PROFILE_V1_COMPONENT_ID,
        phase_b31_encode_group_profile(name, description).map_err(JsError::new)?,
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
    .map_err(|_| JsError::new("phase-b3.1 group: GroupContext extension construction failed"))
}

#[cfg(feature = "extensions-draft")]
fn phase_b31_validate_group_context_extensions(
    extensions: &Extensions<GroupContext>,
    member_identities: &[Vec<u8>],
) -> Result<PhaseB31GroupContext, JsError> {
    let required = extensions
        .required_capabilities()
        .ok_or_else(|| JsError::new("phase-b3.1 group: required capabilities missing"))?;
    if required.extension_types() != [ExtensionType::AppDataDictionary]
        || required.proposal_types() != [ProposalType::AppDataUpdate]
        || !required.credential_types().is_empty()
    {
        return Err(JsError::new(
            "phase-b3.1 group: unexpected required capabilities",
        ));
    }
    let dictionary = extensions
        .app_data_dictionary()
        .ok_or_else(|| JsError::new("phase-b3.1 group: app-data dictionary missing"))?
        .dictionary();
    let ids: Vec<ComponentId> = dictionary.entries().map(|entry| entry.id()).collect();
    if ids
        != [
            1,
            GROUP_PROFILE_V1_COMPONENT_ID,
            ADMIN_POLICY_V1_COMPONENT_ID,
            GROUP_LIFECYCLE_V1_COMPONENT_ID,
        ]
    {
        return Err(JsError::new(
            "phase-b3.1 group: unexpected GroupContext components",
        ));
    }
    let required_components = phase_b31_decode_component_ids(
        dictionary
            .get(&1)
            .ok_or_else(|| JsError::new("phase-b3.1 group: required components missing"))?,
    )
    .map_err(JsError::new)?;
    if required_components != PHASE_B31_REQUIRED_COMPONENTS {
        return Err(JsError::new(
            "phase-b3.1 group: unexpected required components",
        ));
    }
    let group_profile = phase_b31_decode_group_profile(
        dictionary
            .get(&GROUP_PROFILE_V1_COMPONENT_ID)
            .ok_or_else(|| JsError::new("phase-b3.1 group: group profile missing"))?,
    )
    .map_err(JsError::new)?;
    let administrator_policy = dictionary
        .get(&ADMIN_POLICY_V1_COMPONENT_ID)
        .ok_or_else(|| JsError::new("phase-b3.1 group: administrator policy missing"))?
        .to_vec();
    let admins =
        phase_b2_decode_admin_policy_recovery(&administrator_policy).map_err(JsError::new)?;
    if admins
        .iter()
        .any(|admin| !member_identities.iter().any(|member| member == admin))
    {
        return Err(JsError::new(
            "phase-b3.1 group: administrator is not a candidate member",
        ));
    }
    let lifecycle = dictionary
        .get(&GROUP_LIFECYCLE_V1_COMPONENT_ID)
        .ok_or_else(|| JsError::new("phase-b3.1 group: lifecycle missing"))?
        .to_vec();
    if lifecycle != [0x00] {
        return Err(JsError::new("phase-b3.1 group: lifecycle is not active"));
    }
    Ok(PhaseB31GroupContext {
        required_components,
        administrator_policy,
        group_profile,
        lifecycle,
    })
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

    pub fn b3_1_key_package(
        &self,
        provider: &Provider,
        proof: &[u8],
    ) -> Result<PhaseB31KeyPackage, JsError> {
        phase_b2_check_identity_proof(&self.account_public_key, proof)
            .map_err(|_| JsError::new("phase-b3.1 identity: invalid identity proof"))?;
        // Advertising 0x8001 is permitted only when this release artifact can
        // construct and strictly re-validate the canonical present-empty
        // GroupContext state. This keeps the codec reachable in release WASM
        // without exposing a product getter or mutation API.
        let profile_context = phase_b31_group_context_extensions(
            &self.account_public_key,
            b"",
            b"",
        )?;
        let profile_projection = phase_b31_validate_group_context_extensions(
            &profile_context,
            std::slice::from_ref(&self.account_public_key),
        )?;
        if profile_projection.required_components != PHASE_B31_REQUIRED_COMPONENTS
            || profile_projection.group_profile.name != b""
            || profile_projection.group_profile.description != b""
            || profile_projection.lifecycle != [0x00]
            || profile_projection.administrator_policy.len() != 33
        {
            return Err(JsError::new(
                "phase-b3.1 identity: internal group-profile self-check failed",
            ));
        }
        let key_package = OpenMlsKeyPackage::builder()
            .key_package_lifetime(Lifetime::new(PROBE_KEY_PACKAGE_LIFETIME_SECONDS))
            .leaf_node_capabilities(phase_b2_capabilities())
            .leaf_node_extensions(phase_b31_leaf_extensions(proof)?)
            .build(
                PROBE_CIPHERSUITE,
                &provider.inner,
                &self.keypair,
                self.credential_with_key.clone(),
            )?
            .key_package()
            .clone();
        phase_b31_inspect_key_package(&key_package)?;
        Ok(PhaseB31KeyPackage(key_package))
    }

    pub fn b3_2a_key_package(
        &self,
        provider: &Provider,
        proof: &[u8],
    ) -> Result<PhaseB32aKeyPackage, JsError> {
        phase_b2_check_identity_proof(&self.account_public_key, proof)
            .map_err(|_| JsError::new("PHASE_B32A_IDENTITY_PROOF_INVALID"))?;
        let key_package = OpenMlsKeyPackage::builder()
            .key_package_lifetime(Lifetime::new(PROBE_KEY_PACKAGE_LIFETIME_SECONDS))
            .leaf_node_capabilities(phase_b32a_styx_capabilities())
            .leaf_node_extensions(phase_b32a_leaf_extensions(proof)?)
            .build(
                PROBE_CIPHERSUITE,
                &provider.inner,
                &self.keypair,
                self.credential_with_key.clone(),
            )?
            .key_package()
            .clone();
        phase_b32a_validate_styx_key_package(&key_package)?;
        Ok(PhaseB32aKeyPackage(key_package))
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

/// Isolated B3.1 proof wrapper. Product code must not reference this surface.
#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
pub struct PhaseB31KeyPackage(OpenMlsKeyPackage);

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB31KeyPackage {
    pub fn to_framed_bytes(&self) -> Result<Vec<u8>, JsError> {
        MlsMessageOut::from(self.0.clone())
            .tls_serialize_detached()
            .map_err(|_| JsError::new("phase-b3.1 key package: framing failed"))
    }

    pub fn from_framed_bytes(bytes: &[u8]) -> Result<PhaseB31KeyPackage, JsError> {
        let message = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(|_| JsError::new("phase-b3.1 key package: malformed MLSMessage framing"))?;
        let input = match message.extract() {
            MlsMessageBodyIn::KeyPackage(key_package) => key_package,
            _ => {
                return Err(JsError::new(
                    "phase-b3.1 key package: MLSMessage does not contain a KeyPackage",
                ));
            }
        };
        let key_package = input
            .validate(
                &openmls_rust_crypto::RustCrypto::default(),
                openmls::prelude::ProtocolVersion::Mls10,
            )
            .map_err(|_| JsError::new("phase-b3.1 key package: validation failed"))?;
        phase_b31_inspect_key_package(&key_package)?;
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
            .expect("validated Phase B3.1 KeyPackage")
            .dictionary()
            .get(&ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID)
            .expect("validated Phase B3.1 KeyPackage")
            .to_vec()
    }

    pub fn component_ids(&self) -> Vec<u16> {
        self.0
            .leaf_node()
            .extensions()
            .app_data_dictionary()
            .expect("validated Phase B3.1 KeyPackage")
            .dictionary()
            .entries()
            .map(|entry| entry.id())
            .collect()
    }

    pub fn supported_component_ids(&self) -> Result<Vec<u16>, JsError> {
        phase_b31_decode_component_ids(
            self.0
                .leaf_node()
                .extensions()
                .app_data_dictionary()
                .ok_or_else(|| JsError::new("phase-b3.1 leaf: app-data dictionary missing"))?
                .dictionary()
                .get(&1)
                .ok_or_else(|| JsError::new("phase-b3.1 leaf: supported components missing"))?,
        )
        .map_err(JsError::new)
    }

    pub fn is_last_resort(&self) -> bool {
        self.0.last_resort()
    }
}

#[cfg(feature = "extensions-draft")]
fn phase_b32a_validate_styx_leaf(leaf: &LeafNode) -> Result<Vec<ComponentId>, JsError> {
    if leaf.credential().serialized_content().len() != 32
        || leaf.signature_key().as_slice().len() != 32
    {
        return Err(JsError::new("PHASE_B32A_STYX_IDENTITY_INVALID"));
    }
    if leaf.capabilities() != &phase_b32a_styx_capabilities() {
        return Err(JsError::new("PHASE_B32A_STYX_CAPABILITIES_INVALID"));
    }
    let dictionary = leaf
        .extensions()
        .app_data_dictionary()
        .ok_or_else(|| JsError::new("PHASE_B32A_STYX_DICTIONARY_MISSING"))?
        .dictionary();
    let ids = dictionary.entries().map(|entry| entry.id()).collect::<Vec<_>>();
    if ids != [0x0001, ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID] {
        return Err(JsError::new("PHASE_B32A_STYX_DICTIONARY_INVALID"));
    }
    let supported = phase_b31_decode_component_ids(
        dictionary
            .get(&0x0001)
            .ok_or_else(|| JsError::new("PHASE_B32A_STYX_APP_COMPONENTS_MISSING"))?,
    )
    .map_err(|_| JsError::new("PHASE_B32A_STYX_APP_COMPONENTS_INVALID"))?;
    if supported != PHASE_B32A_SUPPORTED_COMPONENTS {
        return Err(JsError::new("PHASE_B32A_STYX_APP_COMPONENTS_INVALID"));
    }
    let proof = dictionary
        .get(&ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID)
        .ok_or_else(|| JsError::new("PHASE_B32A_STYX_PROOF_MISSING"))?;
    phase_b2_check_identity_proof(leaf.credential().serialized_content(), proof)
        .map_err(|_| JsError::new("PHASE_B32A_STYX_PROOF_INVALID"))?;
    Ok(supported)
}

#[cfg(feature = "extensions-draft")]
fn phase_b32a_validate_styx_key_package(
    key_package: &OpenMlsKeyPackage,
) -> Result<(), JsError> {
    let lifetime = key_package.life_time();
    phase_b2_check_key_package_metadata(
        key_package.ciphersuite(),
        key_package.last_resort(),
        lifetime.has_acceptable_range(),
        lifetime.not_after().saturating_sub(lifetime.not_before()),
    )
    .map_err(|_| JsError::new("PHASE_B32A_KEY_PACKAGE_METADATA_INVALID"))?;
    phase_b32a_validate_styx_leaf(key_package.leaf_node())?;
    Ok(())
}

#[cfg(feature = "extensions-draft")]
fn phase_b32a_validate_mdk_leaf(leaf: &LeafNode) -> Result<Vec<ComponentId>, JsError> {
    if leaf.credential().serialized_content().len() != 32
        || leaf.signature_key().as_slice().len() != 32
    {
        return Err(JsError::new("PHASE_B32A_MDK_IDENTITY_INVALID"));
    }
    if leaf.capabilities() != &phase_b32a_mdk_capabilities() {
        return Err(JsError::new("PHASE_B32A_MDK_CAPABILITIES_INVALID"));
    }
    let dictionary = leaf
        .extensions()
        .app_data_dictionary()
        .ok_or_else(|| JsError::new("PHASE_B32A_MDK_DICTIONARY_MISSING"))?
        .dictionary();
    let ids = dictionary.entries().map(|entry| entry.id()).collect::<Vec<_>>();
    if ids != [0x0001, 0x0002, ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID] {
        return Err(JsError::new("PHASE_B32A_MDK_DICTIONARY_INVALID"));
    }
    let supported_bytes = dictionary
        .get(&0x0001)
        .ok_or_else(|| JsError::new("PHASE_B32A_MDK_APP_COMPONENTS_MISSING"))?;
    let supported = phase_b31_decode_component_ids(supported_bytes)
        .map_err(|_| JsError::new("PHASE_B32A_MDK_APP_COMPONENTS_INVALID"))?;
    if supported != PHASE_B32A_SUPPORTED_COMPONENTS {
        return Err(JsError::new("PHASE_B32A_MDK_APP_COMPONENTS_INVALID"));
    }
    let empty_components = Vec::<ComponentId>::new()
        .tls_serialize_detached()
        .map_err(|_| JsError::new("PHASE_B32A_MDK_SAFE_AAD_INVALID"))?;
    if dictionary
        .get(&0x0002)
        .ok_or_else(|| JsError::new("PHASE_B32A_MDK_SAFE_AAD_MISSING"))?
        != empty_components
    {
        return Err(JsError::new("PHASE_B32A_MDK_SAFE_AAD_INVALID"));
    }
    let proof = dictionary
        .get(&ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID)
        .ok_or_else(|| JsError::new("PHASE_B32A_MDK_PROOF_MISSING"))?;
    phase_b2_check_identity_proof(leaf.credential().serialized_content(), proof)
        .map_err(|_| JsError::new("PHASE_B32A_MDK_PROOF_INVALID"))?;
    Ok(supported)
}

/// Exact Styx B3.2a KeyPackage. It is additive and does not relabel B3.1 bytes.
#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
pub struct PhaseB32aKeyPackage(OpenMlsKeyPackage);

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB32aKeyPackage {
    pub fn to_framed_bytes(&self) -> Result<Vec<u8>, JsError> {
        MlsMessageOut::from(self.0.clone())
            .tls_serialize_detached()
            .map_err(|_| JsError::new("PHASE_B32A_KEY_PACKAGE_FRAMING_FAILED"))
    }

    pub fn from_framed_bytes(bytes: &[u8]) -> Result<PhaseB32aKeyPackage, JsError> {
        if bytes.is_empty() || bytes.len() > PHASE_B32_MAX_KEY_PACKAGE_BYTES {
            return Err(JsError::new("PHASE_B32A_KEY_PACKAGE_SIZE_INVALID"));
        }
        let message = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(|_| JsError::new("PHASE_B32A_KEY_PACKAGE_FRAMING_INVALID"))?;
        let input = match message.extract() {
            MlsMessageBodyIn::KeyPackage(key_package) => key_package,
            _ => return Err(JsError::new("PHASE_B32A_NOT_A_KEY_PACKAGE")),
        };
        let key_package = input
            .validate(
                &openmls_rust_crypto::RustCrypto::default(),
                openmls::prelude::ProtocolVersion::Mls10,
            )
            .map_err(|_| JsError::new("PHASE_B32A_KEY_PACKAGE_SIGNATURE_INVALID"))?;
        phase_b32a_validate_styx_key_package(&key_package)?;
        Ok(Self(key_package))
    }

    pub fn ciphersuite_id(&self) -> u16 {
        self.0.ciphersuite().into()
    }
    pub fn credential_identity(&self) -> Vec<u8> {
        self.0.leaf_node().credential().serialized_content().to_vec()
    }
    pub fn leaf_signature_key(&self) -> Vec<u8> {
        self.0.leaf_node().signature_key().as_slice().to_vec()
    }
    pub fn identity_proof(&self) -> Vec<u8> {
        self.0
            .leaf_node()
            .extensions()
            .app_data_dictionary()
            .expect("validated B3.2a KeyPackage")
            .dictionary()
            .get(&ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID)
            .expect("validated B3.2a KeyPackage")
            .to_vec()
    }
    pub fn component_ids(&self) -> Vec<u16> {
        self.0
            .leaf_node()
            .extensions()
            .app_data_dictionary()
            .expect("validated B3.2a KeyPackage")
            .dictionary()
            .entries()
            .map(|entry| entry.id())
            .collect()
    }
    pub fn supported_component_ids(&self) -> Result<Vec<u16>, JsError> {
        phase_b31_decode_component_ids(
            self.0
                .leaf_node()
                .extensions()
                .app_data_dictionary()
                .expect("validated B3.2a KeyPackage")
                .dictionary()
                .get(&0x0001)
                .expect("validated B3.2a KeyPackage"),
        )
        .map_err(JsError::new)
    }
    pub fn capability_extension_ids(&self) -> Vec<u16> {
        self.0
            .leaf_node()
            .capabilities()
            .extensions()
            .iter()
            .copied()
            .map(u16::from)
            .collect()
    }
    pub fn capability_proposal_ids(&self) -> Vec<u16> {
        self.0
            .leaf_node()
            .capabilities()
            .proposals()
            .iter()
            .copied()
            .map(u16::from)
            .collect()
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
#[derive(Clone, PartialEq, Eq, Debug)]
struct PhaseB31GroupProfile {
    name: Vec<u8>,
    description: Vec<u8>,
}

#[cfg(feature = "extensions-draft")]
#[derive(Clone, PartialEq, Eq)]
struct PhaseB31GroupContext {
    required_components: Vec<u16>,
    administrator_policy: Vec<u8>,
    group_profile: PhaseB31GroupProfile,
    lifecycle: Vec<u8>,
}

#[cfg(feature = "extensions-draft")]
#[derive(Clone, PartialEq, Eq)]
struct PhaseB2GroupContext {
    tls: Vec<u8>,
    required_components: Vec<u16>,
    administrator_policy: Vec<u8>,
    lifecycle: Vec<u8>,
}

/// Canonical, immutable description of one fully validated B3.2 join candidate.
///
/// Provider snapshot digests are deliberately instance-scoped commitments to
/// exact bytes within this operation. They are not canonical logical-state
/// identities across unrelated restores (the storage map has no stable order).
#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
#[derive(Clone, PartialEq, Eq)]
pub struct PhaseB32JoinProjection {
    group_id: Vec<u8>,
    epoch: u64,
    ciphersuite_id: u16,
    members: Vec<PhaseB2Member>,
    own_leaf_index: u32,
    welcome_sender_leaf_index: u32,
    welcome_sender_identity: Vec<u8>,
    welcome_sender_signature_key: Vec<u8>,
    group_context_tls: Vec<u8>,
    group_context: PhaseB31GroupContext,
    group_context_sha256: Vec<u8>,
    verified_leaf_digest: Vec<u8>,
    welcome_sha256: Vec<u8>,
    expected_key_package_sha256: Vec<u8>,
    predecessor_state_sha256: Vec<u8>,
    candidate_state_sha256: Vec<u8>,
    projection_sha256: Vec<u8>,
}

#[cfg(feature = "extensions-draft")]
#[derive(Clone)]
struct PhaseB32WelcomeBinding {
    provider_instance_id: u32,
    provider_restore_generation: u32,
    expected_author: Vec<u8>,
    predecessor_state_sha256: Vec<u8>,
    welcome_sha256: Vec<u8>,
    expected_key_package_sha256: Vec<u8>,
    candidate_state_sha256: Vec<u8>,
    projection_sha256: Vec<u8>,
}

/// One-use capability holding exact candidate provider bytes. It never owns or
/// mutates the predecessor provider.
#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
pub struct PhaseB32PendingWelcome {
    binding: Option<PhaseB32WelcomeBinding>,
    candidate_state: Vec<u8>,
    projection: PhaseB32JoinProjection,
}

/// Load-only B3.2 group. The experiment intentionally exposes no create, join,
/// message, Commit or update operation through this type.
#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
pub struct PhaseB32Group {
    mls_group: MlsGroup,
    provider_instance_id: u32,
    provider_restore_generation: u32,
}

#[cfg(feature = "extensions-draft")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum PhaseB32aLeafProfile {
    StyxB32a,
    MdkPin9396adb,
}

#[cfg(feature = "extensions-draft")]
impl PhaseB32aLeafProfile {
    fn tag(self) -> &'static str {
        match self {
            Self::StyxB32a => "STYX_B32A",
            Self::MdkPin9396adb => "MDK_PIN_9396ADB",
        }
    }
}

#[cfg(feature = "extensions-draft")]
#[derive(Clone, PartialEq, Eq)]
struct PhaseB32aMember {
    member: PhaseB2Member,
    profile: PhaseB32aLeafProfile,
    profile_sha256: Vec<u8>,
    lists_default_required_capabilities: bool,
    emits_empty_safe_aad: bool,
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
#[derive(Clone, PartialEq, Eq)]
pub struct PhaseB32aJoinProjection {
    group_id: Vec<u8>,
    epoch: u64,
    ciphersuite_id: u16,
    members: Vec<PhaseB32aMember>,
    own_leaf_index: u32,
    welcome_sender_leaf_index: u32,
    welcome_sender_identity: Vec<u8>,
    welcome_sender_signature_key: Vec<u8>,
    group_context_tls: Vec<u8>,
    group_context: PhaseB31GroupContext,
    group_context_sha256: Vec<u8>,
    verified_leaf_digest: Vec<u8>,
    welcome_sha256: Vec<u8>,
    expected_key_package_sha256: Vec<u8>,
    predecessor_state_sha256: Vec<u8>,
    candidate_state_sha256: Vec<u8>,
    projection_sha256: Vec<u8>,
}

#[cfg(feature = "extensions-draft")]
#[derive(Clone)]
struct PhaseB32aWelcomeBinding {
    expected_author: Vec<u8>,
    predecessor_state_sha256: Vec<u8>,
    welcome_sha256: Vec<u8>,
    expected_key_package_sha256: Vec<u8>,
    candidate_state_sha256: Vec<u8>,
    projection_sha256: Vec<u8>,
    preparation_classification: PhaseB32aPreparationClassification,
    second_candidate_state_sha256: Vec<u8>,
    differing_storage_key: Vec<u8>,
}

/// One-use B3.2a candidate. It owns no live Provider or identity handle.
#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
pub struct PhaseB32aPendingWelcome {
    binding: Option<PhaseB32aWelcomeBinding>,
    candidate_state: PhaseB32aWipeBytes,
    projection: PhaseB32aJoinProjection,
    preparation_classification: PhaseB32aPreparationClassification,
    second_candidate_state_sha256: Vec<u8>,
    differing_storage_key: Vec<u8>,
}

/// Load-only B3.2a group whose Provider is private and operation-scoped.
#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
pub struct PhaseB32aGroup {
    provider: PhaseB32aPrivateProvider,
    mls_group: MlsGroup,
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
fn phase_b32_sha256(
    crypto: &impl OpenMlsCrypto,
    bytes: &[u8],
    error: &'static str,
) -> Result<Vec<u8>, JsError> {
    crypto
        .hash(PROBE_CIPHERSUITE.hash_algorithm(), bytes)
        .map_err(|_| JsError::new(error))
}

#[cfg(feature = "extensions-draft")]
fn phase_b32_member_at(group: &MlsGroup, leaf_index: u32) -> Result<PhaseB2Member, JsError> {
    let index = openmls::prelude::LeafNodeIndex::new(leaf_index);
    let member = group
        .members()
        .find(|member| member.index == index)
        .ok_or_else(|| JsError::new("PHASE_B32_MEMBER_ABSENT"))?;
    let leaf = group
        .public_group()
        .leaf(index)
        .ok_or_else(|| JsError::new("PHASE_B32_MEMBER_LEAF_ABSENT"))?;
    let supported_component_ids = phase_b31_validate_leaf(leaf)
        .map_err(|_| JsError::new("PHASE_B32_MEMBER_PROFILE_INVALID"))?;
    let dictionary = leaf
        .extensions()
        .app_data_dictionary()
        .ok_or_else(|| JsError::new("PHASE_B32_MEMBER_PROFILE_INVALID"))?
        .dictionary();
    let proof = dictionary
        .get(&ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID)
        .ok_or_else(|| JsError::new("PHASE_B32_MEMBER_PROOF_INVALID"))?;
    let credential_identity = leaf.credential().serialized_content().to_vec();
    let leaf_signature_key = leaf.signature_key().as_slice().to_vec();
    if credential_identity != member.credential.serialized_content()
        || leaf_signature_key != member.signature_key
    {
        return Err(JsError::new("PHASE_B32_MEMBER_METADATA_MISMATCH"));
    }
    Ok(PhaseB2Member {
        leaf_index,
        credential_identity,
        leaf_signature_key,
        identity_proof: proof.to_vec(),
        component_ids: dictionary.entries().map(|entry| entry.id()).collect(),
        supported_component_ids,
    })
}

#[cfg(feature = "extensions-draft")]
fn phase_b32_group_state(
    group: &MlsGroup,
) -> Result<(Vec<PhaseB2Member>, Vec<u8>, PhaseB31GroupContext), JsError> {
    if group.ciphersuite() != PROBE_CIPHERSUITE {
        return Err(JsError::new("PHASE_B32_CIPHERSUITE_MISMATCH"));
    }
    if !group.is_active() || group.own_leaf_node().is_none() {
        return Err(JsError::new("PHASE_B32_GROUP_NOT_ACTIVE"));
    }
    if group.group_id().as_slice().is_empty() || group.group_id().as_slice().len() > 64 {
        return Err(JsError::new("PHASE_B32_GROUP_ID_INVALID"));
    }
    let count = group.members().count();
    if count == 0 || count > PHASE_B2_MAX_MEMBERS {
        return Err(JsError::new("PHASE_B32_MEMBER_LIMIT"));
    }
    let mut members = Vec::with_capacity(count);
    for member in group.members() {
        members.push(phase_b32_member_at(group, member.index.u32())?);
    }
    members.sort_by_key(|member| member.leaf_index);
    let identities = members
        .iter()
        .map(|member| member.credential_identity.clone())
        .collect::<Vec<_>>();
    let context = group.public_group().group_context();
    if context.tls_serialized_len() > PHASE_B2_MAX_GROUP_CONTEXT_BYTES {
        return Err(JsError::new("PHASE_B32_GROUP_CONTEXT_LIMIT"));
    }
    let context_tls = context
        .tls_serialize_detached()
        .map_err(|_| JsError::new("PHASE_B32_GROUP_CONTEXT_SERIALIZATION_FAILED"))?;
    let context_projection =
        phase_b31_validate_group_context_extensions(context.extensions(), &identities)
            .map_err(|_| JsError::new("PHASE_B32_GROUP_CONTEXT_INVALID"))?;
    Ok((members, context_tls, context_projection))
}

#[cfg(feature = "extensions-draft")]
fn phase_b32_verified_leaf_digest(
    crypto: &impl OpenMlsCrypto,
    members: &[PhaseB2Member],
) -> Result<Vec<u8>, JsError> {
    if members.is_empty() || members.len() > PHASE_B2_MAX_MEMBERS {
        return Err(JsError::new("PHASE_B32_MEMBER_LIMIT"));
    }
    let mut payload = Vec::new();
    payload.extend_from_slice(PHASE_B32_VERIFIED_LEAF_DOMAIN);
    payload.push(0);
    payload.extend_from_slice(&(members.len() as u32).to_be_bytes());
    for member in members {
        if member.credential_identity.len() != 32
            || member.leaf_signature_key.len() != 32
            || member.identity_proof.len() != ACCOUNT_IDENTITY_PROOF_V2_LENGTH
        {
            return Err(JsError::new("PHASE_B32_MEMBER_PROOF_INVALID"));
        }
        payload.extend_from_slice(&member.leaf_index.to_be_bytes());
        payload.extend_from_slice(&member.credential_identity);
        payload.extend_from_slice(&member.leaf_signature_key);
        payload.extend_from_slice(&member.identity_proof);
    }
    phase_b32_sha256(
        crypto,
        &payload,
        "PHASE_B32_VERIFIED_LEAF_DIGEST_FAILED",
    )
}

#[cfg(feature = "extensions-draft")]
fn phase_b32_append_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), JsError> {
    let len = u32::try_from(value.len()).map_err(|_| JsError::new("PHASE_B32_PROJECTION_LIMIT"))?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

#[cfg(feature = "extensions-draft")]
fn phase_b32_append_components(
    output: &mut Vec<u8>,
    components: &[u16],
) -> Result<(), JsError> {
    let len = u32::try_from(components.len())
        .map_err(|_| JsError::new("PHASE_B32_PROJECTION_LIMIT"))?;
    output.extend_from_slice(&len.to_be_bytes());
    for component in components {
        output.extend_from_slice(&component.to_be_bytes());
    }
    Ok(())
}

#[cfg(feature = "extensions-draft")]
fn phase_b32_projection_payload(
    projection: &PhaseB32JoinProjection,
) -> Result<Vec<u8>, JsError> {
    let mut output = Vec::new();
    output.extend_from_slice(PHASE_B32_PROJECTION_DOMAIN);
    output.push(0);
    output.extend_from_slice(&PHASE_B32_PROJECTION_VERSION.to_be_bytes());
    phase_b32_append_bytes(&mut output, &projection.group_id)?;
    output.extend_from_slice(&projection.epoch.to_be_bytes());
    output.extend_from_slice(&projection.ciphersuite_id.to_be_bytes());
    output.extend_from_slice(&(projection.members.len() as u32).to_be_bytes());
    for member in &projection.members {
        output.extend_from_slice(&member.leaf_index.to_be_bytes());
        phase_b32_append_bytes(&mut output, &member.credential_identity)?;
        phase_b32_append_bytes(&mut output, &member.leaf_signature_key)?;
        phase_b32_append_bytes(&mut output, &member.identity_proof)?;
        phase_b32_append_components(&mut output, &member.component_ids)?;
        phase_b32_append_components(&mut output, &member.supported_component_ids)?;
    }
    output.extend_from_slice(&projection.own_leaf_index.to_be_bytes());
    output.extend_from_slice(&projection.welcome_sender_leaf_index.to_be_bytes());
    phase_b32_append_bytes(&mut output, &projection.welcome_sender_identity)?;
    phase_b32_append_bytes(&mut output, &projection.welcome_sender_signature_key)?;
    phase_b32_append_components(
        &mut output,
        &projection.group_context.required_components,
    )?;
    phase_b32_append_bytes(&mut output, &projection.group_context.group_profile.name)?;
    phase_b32_append_bytes(
        &mut output,
        &projection.group_context.group_profile.description,
    )?;
    phase_b32_append_bytes(
        &mut output,
        &projection.group_context.administrator_policy,
    )?;
    phase_b32_append_bytes(&mut output, &projection.group_context.lifecycle)?;
    for digest in [
        &projection.group_context_sha256,
        &projection.verified_leaf_digest,
        &projection.welcome_sha256,
        &projection.expected_key_package_sha256,
        &projection.predecessor_state_sha256,
        &projection.candidate_state_sha256,
    ] {
        if digest.len() != 32 {
            return Err(JsError::new("PHASE_B32_PROJECTION_DIGEST_INVALID"));
        }
        output.extend_from_slice(digest);
    }
    Ok(output)
}

#[cfg(feature = "extensions-draft")]
fn phase_b32_projection_from_group(
    crypto: &impl OpenMlsCrypto,
    group: &MlsGroup,
    welcome_sender_leaf_index: u32,
    expected_author: &[u8],
    welcome_sha256: &[u8],
    expected_key_package_sha256: &[u8],
    predecessor_state_sha256: &[u8],
    candidate_state_sha256: &[u8],
) -> Result<PhaseB32JoinProjection, JsError> {
    if expected_author.len() != 32 {
        return Err(JsError::new("PHASE_B32_EXPECTED_AUTHOR_INVALID"));
    }
    let (members, group_context_tls, group_context) = phase_b32_group_state(group)?;
    let own_leaf_index = group.own_leaf_index().u32();
    let sender = members
        .iter()
        .find(|member| member.leaf_index == welcome_sender_leaf_index)
        .ok_or_else(|| JsError::new("PHASE_B32_WELCOME_AUTHOR_NOT_MEMBER"))?;
    if sender.credential_identity != expected_author {
        return Err(JsError::new("PHASE_B32_WELCOME_AUTHOR_MISMATCH"));
    }
    let admins = phase_b2_decode_admin_policy_recovery(&group_context.administrator_policy)
        .map_err(|_| JsError::new("PHASE_B32_ADMIN_POLICY_INVALID"))?;
    if !admins.iter().any(|admin| admin == expected_author) {
        return Err(JsError::new("PHASE_B32_WELCOME_AUTHOR_NOT_ADMIN"));
    }
    let welcome_sender_identity = sender.credential_identity.clone();
    let welcome_sender_signature_key = sender.leaf_signature_key.clone();
    let group_context_sha256 = phase_b32_sha256(
        crypto,
        &group_context_tls,
        "PHASE_B32_GROUP_CONTEXT_DIGEST_FAILED",
    )?;
    let verified_leaf_digest = phase_b32_verified_leaf_digest(crypto, &members)?;
    let mut projection = PhaseB32JoinProjection {
        group_id: group.group_id().to_vec(),
        epoch: group.epoch().as_u64(),
        ciphersuite_id: group.ciphersuite().into(),
        members,
        own_leaf_index,
        welcome_sender_leaf_index,
        welcome_sender_identity,
        welcome_sender_signature_key,
        group_context_tls,
        group_context,
        group_context_sha256,
        verified_leaf_digest,
        welcome_sha256: welcome_sha256.to_vec(),
        expected_key_package_sha256: expected_key_package_sha256.to_vec(),
        predecessor_state_sha256: predecessor_state_sha256.to_vec(),
        candidate_state_sha256: candidate_state_sha256.to_vec(),
        projection_sha256: Vec::new(),
    };
    let payload = phase_b32_projection_payload(&projection)?;
    projection.projection_sha256 = phase_b32_sha256(
        crypto,
        &payload,
        "PHASE_B32_PROJECTION_DIGEST_FAILED",
    )?;
    Ok(projection)
}

#[cfg(feature = "extensions-draft")]
fn phase_b32a_profile_digest(
    crypto: &impl OpenMlsCrypto,
    leaf: &LeafNode,
    profile: PhaseB32aLeafProfile,
) -> Result<Vec<u8>, JsError> {
    let capability_bytes = leaf
        .capabilities()
        .tls_serialize_detached()
        .map_err(|_| JsError::new("PHASE_B32A_PROFILE_SERIALIZATION_FAILED"))?;
    let extension_bytes = leaf
        .extensions()
        .tls_serialize_detached()
        .map_err(|_| JsError::new("PHASE_B32A_PROFILE_SERIALIZATION_FAILED"))?;
    let mut payload = Vec::new();
    payload.extend_from_slice(PHASE_B32A_LEAF_PROFILE_DOMAIN);
    payload.push(0);
    phase_b32_append_bytes(&mut payload, profile.tag().as_bytes())?;
    phase_b32_append_bytes(&mut payload, &capability_bytes)?;
    phase_b32_append_bytes(&mut payload, &extension_bytes)?;
    phase_b32_sha256(crypto, &payload, "PHASE_B32A_PROFILE_DIGEST_FAILED")
}

#[cfg(feature = "extensions-draft")]
fn phase_b32a_member_at(
    crypto: &impl OpenMlsCrypto,
    group: &MlsGroup,
    leaf_index: u32,
) -> Result<PhaseB32aMember, JsError> {
    let index = openmls::prelude::LeafNodeIndex::new(leaf_index);
    let metadata = group
        .members()
        .find(|member| member.index == index)
        .ok_or_else(|| JsError::new("PHASE_B32A_MEMBER_ABSENT"))?;
    let leaf = group
        .public_group()
        .leaf(index)
        .ok_or_else(|| JsError::new("PHASE_B32A_MEMBER_LEAF_ABSENT"))?;

    let (profile, supported_component_ids, lists_default, emits_empty_safe_aad) =
        if leaf.capabilities() == &phase_b32a_styx_capabilities() {
            (
                PhaseB32aLeafProfile::StyxB32a,
                phase_b32a_validate_styx_leaf(leaf)?,
                false,
                false,
            )
        } else if leaf.capabilities() == &phase_b32a_mdk_capabilities() {
            (
                PhaseB32aLeafProfile::MdkPin9396adb,
                phase_b32a_validate_mdk_leaf(leaf)?,
                true,
                true,
            )
        } else {
            return Err(JsError::new("PHASE_B32A_LEAF_PROFILE_UNKNOWN_OR_HYBRID"));
        };

    let dictionary = leaf
        .extensions()
        .app_data_dictionary()
        .ok_or_else(|| JsError::new("PHASE_B32A_MEMBER_DICTIONARY_MISSING"))?
        .dictionary();
    let proof = dictionary
        .get(&ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID)
        .ok_or_else(|| JsError::new("PHASE_B32A_MEMBER_PROOF_MISSING"))?;
    let credential_identity = leaf.credential().serialized_content().to_vec();
    let leaf_signature_key = leaf.signature_key().as_slice().to_vec();
    if credential_identity != metadata.credential.serialized_content()
        || leaf_signature_key != metadata.signature_key
    {
        return Err(JsError::new("PHASE_B32A_MEMBER_METADATA_MISMATCH"));
    }
    let member = PhaseB2Member {
        leaf_index,
        credential_identity,
        leaf_signature_key,
        identity_proof: proof.to_vec(),
        component_ids: dictionary.entries().map(|entry| entry.id()).collect(),
        supported_component_ids,
    };
    Ok(PhaseB32aMember {
        profile,
        profile_sha256: phase_b32a_profile_digest(crypto, leaf, profile)?,
        member,
        lists_default_required_capabilities: lists_default,
        emits_empty_safe_aad,
    })
}

#[cfg(feature = "extensions-draft")]
fn phase_b32a_group_state(
    crypto: &impl OpenMlsCrypto,
    group: &MlsGroup,
) -> Result<(Vec<PhaseB32aMember>, Vec<u8>, PhaseB31GroupContext), JsError> {
    if group.ciphersuite() != PROBE_CIPHERSUITE {
        return Err(JsError::new("PHASE_B32A_CIPHERSUITE_MISMATCH"));
    }
    if !group.is_active() || group.own_leaf_node().is_none() {
        return Err(JsError::new("PHASE_B32A_GROUP_NOT_ACTIVE"));
    }
    if group.group_id().as_slice().is_empty() || group.group_id().as_slice().len() > 64 {
        return Err(JsError::new("PHASE_B32A_GROUP_ID_INVALID"));
    }
    if group.members().count() != 2 {
        return Err(JsError::new("PHASE_B32A_EXACTLY_TWO_MEMBERS_REQUIRED"));
    }
    let mut members = Vec::with_capacity(2);
    for member in group.members() {
        members.push(phase_b32a_member_at(crypto, group, member.index.u32())?);
    }
    members.sort_by_key(|member| member.member.leaf_index);
    let identities = members
        .iter()
        .map(|member| member.member.credential_identity.clone())
        .collect::<Vec<_>>();
    let context = group.public_group().group_context();
    if context.tls_serialized_len() > PHASE_B2_MAX_GROUP_CONTEXT_BYTES {
        return Err(JsError::new("PHASE_B32A_GROUP_CONTEXT_LIMIT"));
    }
    let context_tls = context
        .tls_serialize_detached()
        .map_err(|_| JsError::new("PHASE_B32A_GROUP_CONTEXT_SERIALIZATION_FAILED"))?;
    let projected = phase_b31_validate_group_context_extensions(context.extensions(), &identities)
        .map_err(|_| JsError::new("PHASE_B32A_GROUP_CONTEXT_INVALID"))?;
    Ok((members, context_tls, projected))
}

#[cfg(feature = "extensions-draft")]
fn phase_b32a_verified_leaf_digest(
    crypto: &impl OpenMlsCrypto,
    members: &[PhaseB32aMember],
) -> Result<Vec<u8>, JsError> {
    let mut payload = Vec::new();
    payload.extend_from_slice(PHASE_B32_VERIFIED_LEAF_DOMAIN);
    payload.push(0);
    payload.extend_from_slice(&(members.len() as u32).to_be_bytes());
    for projected in members {
        let member = &projected.member;
        payload.extend_from_slice(&member.leaf_index.to_be_bytes());
        payload.extend_from_slice(&member.credential_identity);
        payload.extend_from_slice(&member.leaf_signature_key);
        payload.extend_from_slice(&member.identity_proof);
        phase_b32_append_bytes(&mut payload, projected.profile.tag().as_bytes())?;
        payload.extend_from_slice(&projected.profile_sha256);
    }
    phase_b32_sha256(crypto, &payload, "PHASE_B32A_VERIFIED_LEAF_DIGEST_FAILED")
}

#[cfg(feature = "extensions-draft")]
fn phase_b32a_projection_payload(
    projection: &PhaseB32aJoinProjection,
) -> Result<Vec<u8>, JsError> {
    let mut output = Vec::new();
    output.extend_from_slice(PHASE_B32A_PROJECTION_DOMAIN);
    output.push(0);
    output.extend_from_slice(&PHASE_B32A_PROJECTION_VERSION.to_be_bytes());
    phase_b32_append_bytes(&mut output, &projection.group_id)?;
    output.extend_from_slice(&projection.epoch.to_be_bytes());
    output.extend_from_slice(&projection.ciphersuite_id.to_be_bytes());
    output.extend_from_slice(&(projection.members.len() as u32).to_be_bytes());
    for projected in &projection.members {
        let member = &projected.member;
        output.extend_from_slice(&member.leaf_index.to_be_bytes());
        phase_b32_append_bytes(&mut output, &member.credential_identity)?;
        phase_b32_append_bytes(&mut output, &member.leaf_signature_key)?;
        phase_b32_append_bytes(&mut output, &member.identity_proof)?;
        phase_b32_append_components(&mut output, &member.component_ids)?;
        phase_b32_append_components(&mut output, &member.supported_component_ids)?;
        phase_b32_append_bytes(&mut output, projected.profile.tag().as_bytes())?;
        output.extend_from_slice(&projected.profile_sha256);
        output.push(u8::from(projected.lists_default_required_capabilities));
        output.push(u8::from(projected.emits_empty_safe_aad));
    }
    output.extend_from_slice(&projection.own_leaf_index.to_be_bytes());
    output.extend_from_slice(&projection.welcome_sender_leaf_index.to_be_bytes());
    phase_b32_append_bytes(&mut output, &projection.welcome_sender_identity)?;
    phase_b32_append_bytes(&mut output, &projection.welcome_sender_signature_key)?;
    phase_b32_append_components(&mut output, &projection.group_context.required_components)?;
    phase_b32_append_bytes(&mut output, &projection.group_context.group_profile.name)?;
    phase_b32_append_bytes(&mut output, &projection.group_context.group_profile.description)?;
    phase_b32_append_bytes(&mut output, &projection.group_context.administrator_policy)?;
    phase_b32_append_bytes(&mut output, &projection.group_context.lifecycle)?;
    for digest in [
        &projection.group_context_sha256,
        &projection.verified_leaf_digest,
        &projection.welcome_sha256,
        &projection.expected_key_package_sha256,
        &projection.predecessor_state_sha256,
        &projection.candidate_state_sha256,
    ] {
        if digest.len() != 32 {
            return Err(JsError::new("PHASE_B32A_PROJECTION_DIGEST_INVALID"));
        }
        output.extend_from_slice(digest);
    }
    Ok(output)
}

#[cfg(feature = "extensions-draft")]
fn phase_b32a_projection_from_group(
    crypto: &impl OpenMlsCrypto,
    group: &MlsGroup,
    welcome_sender_leaf_index: u32,
    expected_author: &[u8],
    expected_own_identity: &[u8],
    expected_own_signature_key: &[u8],
    welcome_sha256: &[u8],
    expected_key_package_sha256: &[u8],
    predecessor_state_sha256: &[u8],
    candidate_state_sha256: &[u8],
) -> Result<PhaseB32aJoinProjection, JsError> {
    if expected_author.len() != 32
        || expected_own_identity.len() != 32
        || expected_own_signature_key.len() != 32
    {
        return Err(JsError::new("PHASE_B32A_IDENTITY_LOCATOR_INVALID"));
    }
    let (members, group_context_tls, group_context) = phase_b32a_group_state(crypto, group)?;
    let own_leaf_index = group.own_leaf_index().u32();
    let own = members
        .iter()
        .find(|member| member.member.leaf_index == own_leaf_index)
        .ok_or_else(|| JsError::new("PHASE_B32A_OWN_LEAF_ABSENT"))?;
    if own.profile != PhaseB32aLeafProfile::StyxB32a
        || own.member.credential_identity != expected_own_identity
        || own.member.leaf_signature_key != expected_own_signature_key
    {
        return Err(JsError::new("PHASE_B32A_OWN_PROFILE_OR_IDENTITY_MISMATCH"));
    }
    let sender = members
        .iter()
        .find(|member| member.member.leaf_index == welcome_sender_leaf_index)
        .ok_or_else(|| JsError::new("PHASE_B32A_WELCOME_AUTHOR_NOT_MEMBER"))?;
    if sender.profile != PhaseB32aLeafProfile::MdkPin9396adb
        || sender.member.credential_identity != expected_author
    {
        return Err(JsError::new("PHASE_B32A_WELCOME_AUTHOR_PROFILE_MISMATCH"));
    }
    let admins = phase_b2_decode_admin_policy_recovery(&group_context.administrator_policy)
        .map_err(|_| JsError::new("PHASE_B32A_ADMIN_POLICY_INVALID"))?;
    if !admins.iter().any(|admin| admin == expected_author) {
        return Err(JsError::new("PHASE_B32A_WELCOME_AUTHOR_NOT_ADMIN"));
    }
    let welcome_sender_identity = sender.member.credential_identity.clone();
    let welcome_sender_signature_key = sender.member.leaf_signature_key.clone();
    let group_context_sha256 = phase_b32_sha256(
        crypto,
        &group_context_tls,
        "PHASE_B32A_GROUP_CONTEXT_DIGEST_FAILED",
    )?;
    let verified_leaf_digest = phase_b32a_verified_leaf_digest(crypto, &members)?;
    let mut projection = PhaseB32aJoinProjection {
        group_id: group.group_id().to_vec(),
        epoch: group.epoch().as_u64(),
        ciphersuite_id: group.ciphersuite().into(),
        members,
        own_leaf_index,
        welcome_sender_leaf_index,
        welcome_sender_identity,
        welcome_sender_signature_key,
        group_context_tls,
        group_context,
        group_context_sha256,
        verified_leaf_digest,
        welcome_sha256: welcome_sha256.to_vec(),
        expected_key_package_sha256: expected_key_package_sha256.to_vec(),
        predecessor_state_sha256: predecessor_state_sha256.to_vec(),
        candidate_state_sha256: candidate_state_sha256.to_vec(),
        projection_sha256: Vec::new(),
    };
    let payload = phase_b32a_projection_payload(&projection)?;
    projection.projection_sha256 = phase_b32_sha256(
        crypto,
        &payload,
        "PHASE_B32A_PROJECTION_DIGEST_FAILED",
    )?;
    Ok(projection)
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
impl PhaseB32JoinProjection {
    fn member(&self, index: usize) -> Result<&PhaseB2Member, JsError> {
        self.members
            .get(index)
            .ok_or_else(|| JsError::new("PHASE_B32_PROJECTION_MEMBER_INDEX_INVALID"))
    }
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB32JoinProjection {
    pub fn domain(&self) -> String {
        "STYX-B32-JOIN-PROJECTION-v1".into()
    }
    pub fn version(&self) -> u16 {
        PHASE_B32_PROJECTION_VERSION
    }
    pub fn group_id(&self) -> Vec<u8> {
        self.group_id.clone()
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn ciphersuite_id(&self) -> u16 {
        self.ciphersuite_id
    }
    pub fn member_count(&self) -> u32 {
        self.members.len() as u32
    }
    pub fn member_leaf_index(&self, index: usize) -> Result<u32, JsError> {
        self.member(index).map(|member| member.leaf_index)
    }
    pub fn member_identity(&self, index: usize) -> Result<Vec<u8>, JsError> {
        self.member(index)
            .map(|member| member.credential_identity.clone())
    }
    pub fn member_signature_key(&self, index: usize) -> Result<Vec<u8>, JsError> {
        self.member(index)
            .map(|member| member.leaf_signature_key.clone())
    }
    pub fn member_identity_proof(&self, index: usize) -> Result<Vec<u8>, JsError> {
        self.member(index)
            .map(|member| member.identity_proof.clone())
    }
    pub fn member_component_ids(&self, index: usize) -> Result<Vec<u16>, JsError> {
        self.member(index)
            .map(|member| member.component_ids.clone())
    }
    pub fn member_supported_component_ids(&self, index: usize) -> Result<Vec<u16>, JsError> {
        self.member(index)
            .map(|member| member.supported_component_ids.clone())
    }
    pub fn own_leaf_index(&self) -> u32 {
        self.own_leaf_index
    }
    pub fn welcome_sender_leaf_index(&self) -> u32 {
        self.welcome_sender_leaf_index
    }
    pub fn welcome_sender_identity(&self) -> Vec<u8> {
        self.welcome_sender_identity.clone()
    }
    pub fn welcome_sender_signature_key(&self) -> Vec<u8> {
        self.welcome_sender_signature_key.clone()
    }
    pub fn group_context_tls(&self) -> Vec<u8> {
        self.group_context_tls.clone()
    }
    pub fn required_component_ids(&self) -> Vec<u16> {
        self.group_context.required_components.clone()
    }
    pub fn group_profile_name(&self) -> Vec<u8> {
        self.group_context.group_profile.name.clone()
    }
    pub fn group_profile_description(&self) -> Vec<u8> {
        self.group_context.group_profile.description.clone()
    }
    pub fn administrator_policy(&self) -> Vec<u8> {
        self.group_context.administrator_policy.clone()
    }
    pub fn lifecycle(&self) -> Vec<u8> {
        self.group_context.lifecycle.clone()
    }
    pub fn group_context_sha256(&self) -> Vec<u8> {
        self.group_context_sha256.clone()
    }
    pub fn verified_leaf_digest(&self) -> Vec<u8> {
        self.verified_leaf_digest.clone()
    }
    pub fn welcome_sha256(&self) -> Vec<u8> {
        self.welcome_sha256.clone()
    }
    pub fn expected_key_package_sha256(&self) -> Vec<u8> {
        self.expected_key_package_sha256.clone()
    }
    pub fn predecessor_state_sha256(&self) -> Vec<u8> {
        self.predecessor_state_sha256.clone()
    }
    pub fn candidate_state_sha256(&self) -> Vec<u8> {
        self.candidate_state_sha256.clone()
    }
    pub fn projection_sha256(&self) -> Vec<u8> {
        self.projection_sha256.clone()
    }
}

#[cfg(feature = "extensions-draft")]
impl PhaseB32aJoinProjection {
    fn member(&self, index: usize) -> Result<&PhaseB32aMember, JsError> {
        self.members
            .get(index)
            .ok_or_else(|| JsError::new("PHASE_B32A_PROJECTION_MEMBER_INDEX_INVALID"))
    }
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB32aJoinProjection {
    pub fn domain(&self) -> String { "STYX-B32A-JOIN-PROJECTION-v1".into() }
    pub fn version(&self) -> u16 { PHASE_B32A_PROJECTION_VERSION }
    pub fn provider_format(&self) -> String { "phase-b32a-provider-canonical-v1".into() }
    pub fn group_id(&self) -> Vec<u8> { self.group_id.clone() }
    pub fn epoch(&self) -> u64 { self.epoch }
    pub fn ciphersuite_id(&self) -> u16 { self.ciphersuite_id }
    pub fn member_count(&self) -> u32 { self.members.len() as u32 }
    pub fn member_leaf_index(&self, index: usize) -> Result<u32, JsError> {
        self.member(index).map(|member| member.member.leaf_index)
    }
    pub fn member_identity(&self, index: usize) -> Result<Vec<u8>, JsError> {
        self.member(index).map(|member| member.member.credential_identity.clone())
    }
    pub fn member_signature_key(&self, index: usize) -> Result<Vec<u8>, JsError> {
        self.member(index).map(|member| member.member.leaf_signature_key.clone())
    }
    pub fn member_identity_proof(&self, index: usize) -> Result<Vec<u8>, JsError> {
        self.member(index).map(|member| member.member.identity_proof.clone())
    }
    pub fn member_component_ids(&self, index: usize) -> Result<Vec<u16>, JsError> {
        self.member(index).map(|member| member.member.component_ids.clone())
    }
    pub fn member_supported_component_ids(&self, index: usize) -> Result<Vec<u16>, JsError> {
        self.member(index).map(|member| member.member.supported_component_ids.clone())
    }
    pub fn member_profile(&self, index: usize) -> Result<String, JsError> {
        self.member(index).map(|member| member.profile.tag().into())
    }
    pub fn member_profile_sha256(&self, index: usize) -> Result<Vec<u8>, JsError> {
        self.member(index).map(|member| member.profile_sha256.clone())
    }
    pub fn member_lists_default_required_capabilities(&self, index: usize) -> Result<bool, JsError> {
        self.member(index).map(|member| member.lists_default_required_capabilities)
    }
    pub fn member_emits_empty_safe_aad(&self, index: usize) -> Result<bool, JsError> {
        self.member(index).map(|member| member.emits_empty_safe_aad)
    }
    pub fn own_leaf_index(&self) -> u32 { self.own_leaf_index }
    pub fn welcome_sender_leaf_index(&self) -> u32 { self.welcome_sender_leaf_index }
    pub fn welcome_sender_identity(&self) -> Vec<u8> { self.welcome_sender_identity.clone() }
    pub fn welcome_sender_signature_key(&self) -> Vec<u8> { self.welcome_sender_signature_key.clone() }
    pub fn group_context_tls(&self) -> Vec<u8> { self.group_context_tls.clone() }
    pub fn required_component_ids(&self) -> Vec<u16> { self.group_context.required_components.clone() }
    pub fn group_profile_name(&self) -> Vec<u8> { self.group_context.group_profile.name.clone() }
    pub fn group_profile_description(&self) -> Vec<u8> { self.group_context.group_profile.description.clone() }
    pub fn administrator_policy(&self) -> Vec<u8> { self.group_context.administrator_policy.clone() }
    pub fn lifecycle(&self) -> Vec<u8> { self.group_context.lifecycle.clone() }
    pub fn group_context_sha256(&self) -> Vec<u8> { self.group_context_sha256.clone() }
    pub fn verified_leaf_digest(&self) -> Vec<u8> { self.verified_leaf_digest.clone() }
    pub fn welcome_sha256(&self) -> Vec<u8> { self.welcome_sha256.clone() }
    pub fn expected_key_package_sha256(&self) -> Vec<u8> { self.expected_key_package_sha256.clone() }
    pub fn predecessor_state_sha256(&self) -> Vec<u8> { self.predecessor_state_sha256.clone() }
    pub fn candidate_state_sha256(&self) -> Vec<u8> { self.candidate_state_sha256.clone() }
    pub fn projection_sha256(&self) -> Vec<u8> { self.projection_sha256.clone() }
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

/// Closed result of the Phase B2 current-epoch application receive boundary.
///
/// The sender fields come from the authenticated OpenMLS `ProcessedMessage`
/// and the profile-valid leaf in the same loaded group instance. They are not
/// inferred from application payload bytes.
#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
#[derive(Debug)]
pub struct PhaseB2ReceivedApplicationMessage {
    group_id: Vec<u8>,
    epoch: u64,
    sender_leaf_index: u32,
    sender_credential_identity: Vec<u8>,
    sender_signature_key: Vec<u8>,
    plaintext: Vec<u8>,
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB2ReceivedApplicationMessage {
    pub fn group_id(&self) -> Vec<u8> {
        self.group_id.clone()
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn sender_leaf_index(&self) -> u32 {
        self.sender_leaf_index
    }

    pub fn sender_credential_identity(&self) -> Vec<u8> {
        self.sender_credential_identity.clone()
    }

    pub fn sender_signature_key(&self) -> Vec<u8> {
        self.sender_signature_key.clone()
    }

    pub fn plaintext(&self) -> Vec<u8> {
        self.plaintext.clone()
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

    fn receive_application_message_recovery(
        &mut self,
        provider: &Provider,
        bytes: &[u8],
    ) -> Result<PhaseB2ReceivedApplicationMessage, &'static str> {
        let message = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(|_| "phase-b2 receive: malformed MLSMessage")?;
        let private = match message.extract() {
            MlsMessageBodyIn::PrivateMessage(message) => message,
            _ => return Err("phase-b2 receive: PrivateMessage application required"),
        };
        if private.group_id() != self.mls_group.group_id() {
            return Err("phase-b2 receive: group id mismatch");
        }
        if private.epoch() != self.mls_group.epoch() {
            return Err("phase-b2 receive: current epoch required");
        }

        let processed = self
            .mls_group
            .process_message(provider.as_ref(), ProtocolMessage::from(private))
            .map_err(|_| "phase-b2 receive: OpenMLS processing failed")?;
        if processed.group_id() != self.mls_group.group_id() {
            return Err("phase-b2 receive: authenticated group id mismatch");
        }
        if processed.epoch() != self.mls_group.epoch() {
            return Err("phase-b2 receive: authenticated epoch mismatch");
        }
        if matches!(
            processed.content(),
            openmls::framing::ProcessedMessageContent::OwnPrivateMessage
        ) {
            return Err("phase-b2 receive: own message rejected");
        }

        let sender_leaf_index = match processed.sender() {
            Sender::Member(index) => index.u32(),
            Sender::External(_) | Sender::NewMemberProposal | Sender::NewMemberCommit => {
                return Err("phase-b2 receive: non-member sender rejected");
            }
        };
        let processed_credential_identity = processed.credential().serialized_content().to_vec();
        let sender = phase_b2_member_at(&self.mls_group, sender_leaf_index)
            .map_err(|_| "phase-b2 receive: current sender leaf is not profile-valid")?;
        if processed_credential_identity != sender.credential_identity {
            return Err(
                "phase-b2 receive: authenticated credential disagrees with current leaf",
            );
        }
        let plaintext = match processed.into_content() {
            openmls::framing::ProcessedMessageContent::ApplicationMessage(message) => {
                message.into_bytes()
            }
            _ => return Err("phase-b2 receive: message is not application data"),
        };

        Ok(PhaseB2ReceivedApplicationMessage {
            group_id: self.mls_group.group_id().to_vec(),
            epoch: self.mls_group.epoch().as_u64(),
            sender_leaf_index,
            sender_credential_identity: sender.credential_identity,
            sender_signature_key: sender.leaf_signature_key,
            plaintext,
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

    /// Legacy sender-discarding receive API. B2.7 and later must use
    /// `receive_application_message` so authenticated sender evidence is not
    /// lost before the durable boundary.
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

    pub fn receive_application_message(
        &mut self,
        provider: &Provider,
        bytes: &[u8],
    ) -> Result<PhaseB2ReceivedApplicationMessage, JsError> {
        self.validate_provider(provider)?;
        self.receive_application_message_recovery(provider, bytes)
            .map_err(JsError::new)
    }
}

#[cfg(feature = "extensions-draft")]
fn phase_b32_map_welcome_error<E>(error: WelcomeError<E>) -> JsError {
    let code = match error {
        WelcomeError::MissingRatchetTree => "PHASE_B32_MISSING_EMBEDDED_RATCHET_TREE",
        WelcomeError::NoMatchingKeyPackage
        | WelcomeError::PrivateInitKeyNotFound
        | WelcomeError::NoMatchingEncryptionKey
        | WelcomeError::JoinerSecretNotFound => "PHASE_B32_KEY_PACKAGE_NOT_AVAILABLE",
        WelcomeError::CiphersuiteMismatch | WelcomeError::UnsupportedMlsVersion => {
            "PHASE_B32_CIPHERSUITE_MISMATCH"
        }
        WelcomeError::GroupAlreadyExists => "PHASE_B32_GROUP_ID_COLLISION",
        WelcomeError::InvalidGroupInfoSignature | WelcomeError::UnknownSender => {
            "PHASE_B32_WELCOME_AUTHOR_INVALID"
        }
        WelcomeError::UnsupportedCapability | WelcomeError::UnsupportedExtensions => {
            "PHASE_B32_GROUP_PROFILE_UNSUPPORTED"
        }
        _ => "PHASE_B32_WELCOME_REJECTED",
    };
    JsError::new(code)
}

#[cfg(feature = "extensions-draft")]
impl PhaseB32PendingWelcome {
    fn validate_binding(
        provider: &Provider,
        binding: &PhaseB32WelcomeBinding,
    ) -> Result<(), JsError> {
        if provider.instance_id != binding.provider_instance_id {
            return Err(JsError::new("PHASE_B32_WRONG_PROVIDER"));
        }
        if provider.restore_generation.get() != binding.provider_restore_generation {
            return Err(JsError::new("PHASE_B32_PROVIDER_RESTORED"));
        }
        let predecessor_digest = phase_b32_sha256(
            provider.as_ref().crypto(),
            &provider.serialize_state(),
            "PHASE_B32_PREDECESSOR_DIGEST_FAILED",
        )?;
        if predecessor_digest != binding.predecessor_state_sha256 {
            return Err(JsError::new("PHASE_B32_PREDECESSOR_CHANGED"));
        }
        Ok(())
    }
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB32PendingWelcome {
    pub fn prepare(
        provider: &Provider,
        identity: &PhaseB2Identity,
        welcome_bytes: &[u8],
        expected_key_package_bytes: &[u8],
        expected_author: &[u8],
    ) -> Result<PhaseB32PendingWelcome, JsError> {
        if welcome_bytes.is_empty() || welcome_bytes.len() > PHASE_B32_MAX_WELCOME_BYTES {
            return Err(JsError::new("PHASE_B32_WELCOME_SIZE_INVALID"));
        }
        if expected_key_package_bytes.is_empty()
            || expected_key_package_bytes.len() > PHASE_B32_MAX_KEY_PACKAGE_BYTES
        {
            return Err(JsError::new("PHASE_B32_KEY_PACKAGE_SIZE_INVALID"));
        }
        if expected_author.len() != 32 {
            return Err(JsError::new("PHASE_B32_EXPECTED_AUTHOR_INVALID"));
        }

        let expected_key_package =
            PhaseB31KeyPackage::from_framed_bytes(expected_key_package_bytes)
                .map_err(|_| JsError::new("PHASE_B32_EXPECTED_KEY_PACKAGE_INVALID"))?;
        if expected_key_package.0.last_resort() {
            return Err(JsError::new("PHASE_B32_LAST_RESORT_KEY_PACKAGE_REJECTED"));
        }
        if expected_key_package.credential_identity() != identity.account_public_key
            || expected_key_package.leaf_signature_key() != identity.keypair.public()
        {
            return Err(JsError::new("PHASE_B32_OWN_IDENTITY_MISMATCH"));
        }

        let message = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|_| JsError::new("PHASE_B32_WELCOME_FRAMING_INVALID"))?;
        let welcome = match message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(JsError::new("PHASE_B32_NOT_A_WELCOME")),
        };
        if welcome.ciphersuite() != PROBE_CIPHERSUITE {
            return Err(JsError::new("PHASE_B32_CIPHERSUITE_MISMATCH"));
        }

        let predecessor_state = provider.serialize_state();
        let predecessor_state_sha256 = phase_b32_sha256(
            provider.as_ref().crypto(),
            &predecessor_state,
            "PHASE_B32_PREDECESSOR_DIGEST_FAILED",
        )?;
        let welcome_sha256 = phase_b32_sha256(
            provider.as_ref().crypto(),
            welcome_bytes,
            "PHASE_B32_WELCOME_DIGEST_FAILED",
        )?;
        let expected_key_package_sha256 = phase_b32_sha256(
            provider.as_ref().crypto(),
            expected_key_package_bytes,
            "PHASE_B32_KEY_PACKAGE_DIGEST_FAILED",
        )?;

        // Every potentially destructive OpenMLS operation below is confined to
        // this serialize/restore clone. The predecessor provider is never passed
        // to Welcome processing.
        let clone = Provider::new();
        clone.restore_state(&predecessor_state)?;
        let expected_key_package_ref = expected_key_package
            .0
            .hash_ref(clone.as_ref().crypto())
            .map_err(|_| JsError::new("PHASE_B32_KEY_PACKAGE_REFERENCE_FAILED"))?;
        if !welcome
            .secrets()
            .iter()
            .any(|secret| secret.new_member() == expected_key_package_ref)
        {
            return Err(JsError::new("PHASE_B32_KEY_PACKAGE_MISMATCH"));
        }
        let stored_key_package: openmls::key_packages::KeyPackageBundle = clone
            .inner
            .storage()
            .key_package(&expected_key_package_ref)
            .map_err(|_| JsError::new("PHASE_B32_KEY_PACKAGE_STORAGE_FAILED"))?
            .ok_or_else(|| JsError::new("PHASE_B32_KEY_PACKAGE_NOT_AVAILABLE"))?;
        phase_b31_inspect_key_package(stored_key_package.key_package())
            .map_err(|_| JsError::new("PHASE_B32_STORED_KEY_PACKAGE_INVALID"))?;
        let stored_key_package_bytes = MlsMessageOut::from(stored_key_package.key_package().clone())
            .tls_serialize_detached()
            .map_err(|_| JsError::new("PHASE_B32_KEY_PACKAGE_SERIALIZATION_FAILED"))?;
        if stored_key_package_bytes != expected_key_package_bytes {
            return Err(JsError::new("PHASE_B32_KEY_PACKAGE_MISMATCH"));
        }
        let config = MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .build();
        let processed = ProcessedWelcome::new_from_welcome(&clone.inner, &config, welcome)
            .map_err(phase_b32_map_welcome_error)?;
        let remaining_expected_key_package: Option<openmls::key_packages::KeyPackageBundle> = clone
            .inner
            .storage()
            .key_package(&expected_key_package_ref)
            .map_err(|_| JsError::new("PHASE_B32_KEY_PACKAGE_STORAGE_FAILED"))?;
        if remaining_expected_key_package.is_some() {
            return Err(JsError::new("PHASE_B32_KEY_PACKAGE_NOT_CONSUMED"));
        }

        // `None` is intentional and load-bearing: only the RatchetTree inside
        // encrypted GroupInfo is admitted by the B3.2 path.
        let staged = processed
            .into_staged_welcome(&clone.inner, None)
            .map_err(phase_b32_map_welcome_error)?;
        let welcome_sender_leaf_index = staged.welcome_sender_index().u32();
        let staged_sender = staged
            .welcome_sender()
            .map_err(|_| JsError::new("PHASE_B32_WELCOME_AUTHOR_INVALID"))?;
        phase_b31_validate_leaf(staged_sender)
            .map_err(|_| JsError::new("PHASE_B32_WELCOME_AUTHOR_PROFILE_INVALID"))?;
        if staged_sender.credential().serialized_content() != expected_author {
            return Err(JsError::new("PHASE_B32_WELCOME_AUTHOR_MISMATCH"));
        }
        let group_id = staged.group_context().group_id().to_vec();
        if group_id.is_empty() || group_id.len() > 64 {
            return Err(JsError::new("PHASE_B32_GROUP_ID_INVALID"));
        }
        if MlsGroup::load(provider.inner.storage(), &GroupId::from_slice(&group_id))?.is_some() {
            return Err(JsError::new("PHASE_B32_GROUP_ID_COLLISION"));
        }

        let group = staged
            .into_group(&clone.inner)
            .map_err(phase_b32_map_welcome_error)?;
        let own = group
            .own_leaf_node()
            .ok_or_else(|| JsError::new("PHASE_B32_OWN_LEAF_ABSENT"))?;
        if own.credential().serialized_content() != identity.account_public_key
            || own.signature_key().as_slice() != identity.keypair.public()
        {
            return Err(JsError::new("PHASE_B32_OWN_IDENTITY_MISMATCH"));
        }
        let candidate_state = clone.serialize_state();
        let candidate_state_sha256 = phase_b32_sha256(
            provider.as_ref().crypto(),
            &candidate_state,
            "PHASE_B32_CANDIDATE_DIGEST_FAILED",
        )?;
        let projection = phase_b32_projection_from_group(
            provider.as_ref().crypto(),
            &group,
            welcome_sender_leaf_index,
            expected_author,
            &welcome_sha256,
            &expected_key_package_sha256,
            &predecessor_state_sha256,
            &candidate_state_sha256,
        )?;

        // A candidate that cannot be loaded from its exact released bytes is
        // rejected before it can become the durable journal head.
        let scratch = Provider::new();
        scratch.restore_state(&candidate_state)?;
        let scratch_group = MlsGroup::load(
            scratch.inner.storage(),
            &GroupId::from_slice(&projection.group_id),
        )?
        .ok_or_else(|| JsError::new("PHASE_B32_CANDIDATE_RESTORE_FAILED"))?;
        let scratch_projection = phase_b32_projection_from_group(
            scratch.as_ref().crypto(),
            &scratch_group,
            welcome_sender_leaf_index,
            expected_author,
            &welcome_sha256,
            &expected_key_package_sha256,
            &predecessor_state_sha256,
            &candidate_state_sha256,
        )?;
        if scratch_projection != projection {
            return Err(JsError::new("PHASE_B32_CANDIDATE_PROJECTION_MISMATCH"));
        }
        if provider.serialize_state() != predecessor_state {
            return Err(JsError::new("PHASE_B32_LIVE_PROVIDER_MUTATED"));
        }

        let binding = PhaseB32WelcomeBinding {
            provider_instance_id: provider.instance_id,
            provider_restore_generation: provider.restore_generation.get(),
            expected_author: expected_author.to_vec(),
            predecessor_state_sha256,
            welcome_sha256,
            expected_key_package_sha256,
            candidate_state_sha256,
            projection_sha256: projection.projection_sha256.clone(),
        };
        Ok(Self {
            binding: Some(binding),
            candidate_state,
            projection,
        })
    }

    pub fn projection(&self) -> PhaseB32JoinProjection {
        self.projection.clone()
    }

    pub fn is_consumed(&self) -> bool {
        self.binding.is_none()
    }

    pub fn release_candidate_state(
        &mut self,
        provider: &Provider,
        projection_sha256: &[u8],
        expected_author: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let binding = self
            .binding
            .as_ref()
            .ok_or_else(|| JsError::new("PHASE_B32_HANDLE_CONSUMED"))?;
        Self::validate_binding(provider, binding)?;
        if expected_author != binding.expected_author {
            return Err(JsError::new("PHASE_B32_WELCOME_AUTHOR_MISMATCH"));
        }
        if projection_sha256.len() != 32 || projection_sha256 != binding.projection_sha256 {
            return Err(JsError::new("PHASE_B32_PROJECTION_DIGEST_MISMATCH"));
        }
        if self.projection.welcome_sha256 != binding.welcome_sha256
            || self.projection.expected_key_package_sha256
                != binding.expected_key_package_sha256
            || self.projection.candidate_state_sha256 != binding.candidate_state_sha256
            || self.projection.projection_sha256 != binding.projection_sha256
        {
            return Err(JsError::new("PHASE_B32_HANDLE_BINDING_MISMATCH"));
        }
        let candidate_digest = phase_b32_sha256(
            provider.as_ref().crypto(),
            &self.candidate_state,
            "PHASE_B32_CANDIDATE_DIGEST_FAILED",
        )?;
        if candidate_digest != binding.candidate_state_sha256 {
            return Err(JsError::new("PHASE_B32_CANDIDATE_DIGEST_MISMATCH"));
        }
        self.binding.take();
        Ok(std::mem::take(&mut self.candidate_state))
    }

    pub fn discard(&mut self, provider: &Provider) -> Result<(), JsError> {
        let binding = self
            .binding
            .as_ref()
            .ok_or_else(|| JsError::new("PHASE_B32_HANDLE_CONSUMED"))?;
        Self::validate_binding(provider, binding)?;
        self.binding.take();
        self.candidate_state.clear();
        Ok(())
    }
}

#[cfg(feature = "extensions-draft")]
impl PhaseB32Group {
    fn validate_provider(&self, provider: &Provider) -> Result<(), JsError> {
        if self.provider_instance_id != provider.instance_id {
            return Err(JsError::new("PHASE_B32_GROUP_WRONG_PROVIDER"));
        }
        if self.provider_restore_generation != provider.restore_generation.get() {
            return Err(JsError::new("PHASE_B32_GROUP_PROVIDER_RESTORED"));
        }
        Ok(())
    }
}

#[cfg(feature = "extensions-draft")]
fn phase_b32a_prepare_once(
    predecessor_state: &[u8],
    expected_predecessor_sha256: &[u8],
    account_identity: &[u8],
    leaf_signature_key: &[u8],
    welcome_bytes: &[u8],
    expected_key_package_bytes: &[u8],
    expected_author: &[u8],
) -> Result<(PhaseB32aWipeBytes, PhaseB32aJoinProjection), JsError> {
    if welcome_bytes.is_empty() || welcome_bytes.len() > PHASE_B32_MAX_WELCOME_BYTES {
        return Err(JsError::new("PHASE_B32A_WELCOME_SIZE_INVALID"));
    }
    if expected_key_package_bytes.is_empty()
        || expected_key_package_bytes.len() > PHASE_B32_MAX_KEY_PACKAGE_BYTES
    {
        return Err(JsError::new("PHASE_B32A_KEY_PACKAGE_SIZE_INVALID"));
    }
    if expected_predecessor_sha256.len() != 32
        || account_identity.len() != 32
        || leaf_signature_key.len() != 32
        || expected_author.len() != 32
    {
        return Err(JsError::new("PHASE_B32A_INPUT_LOCATOR_INVALID"));
    }
    let standalone_crypto = openmls_rust_crypto::RustCrypto::default();
    let predecessor_state_sha256 = phase_b32_sha256(
        &standalone_crypto,
        predecessor_state,
        "PHASE_B32A_PREDECESSOR_DIGEST_FAILED",
    )?;
    if !phase_b32a_constant_time_eq_32(
        &predecessor_state_sha256,
        expected_predecessor_sha256,
    ) {
        return Err(JsError::new("PHASE_B32A_PREDECESSOR_DIGEST_MISMATCH"));
    }

    let private = PhaseB32aPrivateProvider::from_snapshot(
        predecessor_state,
        PhaseB32aSnapshotRole::Predecessor,
    )?;
    let identity = PhaseB2Identity::load(
        &private.provider,
        account_identity,
        leaf_signature_key,
    )?
    .ok_or_else(|| JsError::new("PHASE_B32A_IDENTITY_KEY_NOT_FOUND"))?;
    if identity.account_public_key != account_identity || identity.keypair.public() != leaf_signature_key {
        return Err(JsError::new("PHASE_B32A_IDENTITY_KEY_MISMATCH"));
    }

    let expected_key_package = PhaseB32aKeyPackage::from_framed_bytes(expected_key_package_bytes)
        .map_err(|_| JsError::new("PHASE_B32A_EXPECTED_KEY_PACKAGE_INVALID"))?;
    if expected_key_package.0.last_resort() {
        return Err(JsError::new("PHASE_B32A_LAST_RESORT_KEY_PACKAGE_REJECTED"));
    }
    if expected_key_package.credential_identity() != account_identity
        || expected_key_package.leaf_signature_key() != leaf_signature_key
    {
        return Err(JsError::new("PHASE_B32A_OWN_KEY_PACKAGE_IDENTITY_MISMATCH"));
    }

    let message = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
        .map_err(|_| JsError::new("PHASE_B32A_WELCOME_FRAMING_INVALID"))?;
    let welcome = match message.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => return Err(JsError::new("PHASE_B32A_NOT_A_WELCOME")),
    };
    if welcome.ciphersuite() != PROBE_CIPHERSUITE {
        return Err(JsError::new("PHASE_B32A_CIPHERSUITE_MISMATCH"));
    }
    let crypto = private.provider.as_ref().crypto();
    let welcome_sha256 = phase_b32_sha256(
        crypto,
        welcome_bytes,
        "PHASE_B32A_WELCOME_DIGEST_FAILED",
    )?;
    let expected_key_package_sha256 = phase_b32_sha256(
        crypto,
        expected_key_package_bytes,
        "PHASE_B32A_KEY_PACKAGE_DIGEST_FAILED",
    )?;
    let expected_key_package_ref = expected_key_package
        .0
        .hash_ref(crypto)
        .map_err(|_| JsError::new("PHASE_B32A_KEY_PACKAGE_REFERENCE_FAILED"))?;
    if !welcome
        .secrets()
        .iter()
        .any(|secret| secret.new_member() == expected_key_package_ref)
    {
        return Err(JsError::new("PHASE_B32A_KEY_PACKAGE_MISMATCH"));
    }
    let stored_key_package: openmls::key_packages::KeyPackageBundle = private
        .provider
        .inner
        .storage()
        .key_package(&expected_key_package_ref)
        .map_err(|_| JsError::new("PHASE_B32A_KEY_PACKAGE_STORAGE_FAILED"))?
        .ok_or_else(|| JsError::new("PHASE_B32A_KEY_PACKAGE_NOT_AVAILABLE"))?;
    phase_b32a_validate_styx_key_package(stored_key_package.key_package())
        .map_err(|_| JsError::new("PHASE_B32A_STORED_KEY_PACKAGE_INVALID"))?;
    let stored_key_package_bytes = MlsMessageOut::from(stored_key_package.key_package().clone())
        .tls_serialize_detached()
        .map_err(|_| JsError::new("PHASE_B32A_KEY_PACKAGE_SERIALIZATION_FAILED"))?;
    if stored_key_package_bytes != expected_key_package_bytes {
        return Err(JsError::new("PHASE_B32A_KEY_PACKAGE_MISMATCH"));
    }

    let config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();
    let processed = ProcessedWelcome::new_from_welcome(&private.provider.inner, &config, welcome)
        .map_err(phase_b32_map_welcome_error)?;
    let remaining: Option<openmls::key_packages::KeyPackageBundle> = private
        .provider
        .inner
        .storage()
        .key_package(&expected_key_package_ref)
        .map_err(|_| JsError::new("PHASE_B32A_KEY_PACKAGE_STORAGE_FAILED"))?;
    if remaining.is_some() {
        return Err(JsError::new("PHASE_B32A_KEY_PACKAGE_NOT_CONSUMED"));
    }
    let staged = processed
        .into_staged_welcome(&private.provider.inner, None)
        .map_err(phase_b32_map_welcome_error)?;
    let welcome_sender_leaf_index = staged.welcome_sender_index().u32();
    let staged_sender = staged
        .welcome_sender()
        .map_err(|_| JsError::new("PHASE_B32A_WELCOME_AUTHOR_INVALID"))?;
    phase_b32a_validate_mdk_leaf(staged_sender)
        .map_err(|_| JsError::new("PHASE_B32A_WELCOME_AUTHOR_PROFILE_INVALID"))?;
    if staged_sender.credential().serialized_content() != expected_author {
        return Err(JsError::new("PHASE_B32A_WELCOME_AUTHOR_MISMATCH"));
    }
    let group_id = staged.group_context().group_id().to_vec();
    if group_id.is_empty() || group_id.len() > 64 {
        return Err(JsError::new("PHASE_B32A_GROUP_ID_INVALID"));
    }
    if MlsGroup::load(
        private.provider.inner.storage(),
        &GroupId::from_slice(&group_id),
    )?
    .is_some()
    {
        return Err(JsError::new("PHASE_B32A_GROUP_ID_COLLISION"));
    }
    let group = staged
        .into_group(&private.provider.inner)
        .map_err(phase_b32_map_welcome_error)?;
    let candidate_state = PhaseB32aWipeBytes(private.canonical_state()?);
    let candidate_state_sha256 = phase_b32_sha256(
        crypto,
        &candidate_state.0,
        "PHASE_B32A_CANDIDATE_DIGEST_FAILED",
    )?;
    let projection = phase_b32a_projection_from_group(
        crypto,
        &group,
        welcome_sender_leaf_index,
        expected_author,
        account_identity,
        leaf_signature_key,
        &welcome_sha256,
        &expected_key_package_sha256,
        &predecessor_state_sha256,
        &candidate_state_sha256,
    )?;

    let scratch = PhaseB32aPrivateProvider::from_snapshot(
        &candidate_state.0,
        PhaseB32aSnapshotRole::CanonicalCandidate,
    )?;
    let scratch_group = MlsGroup::load(
        scratch.provider.inner.storage(),
        &GroupId::from_slice(&projection.group_id),
    )?
    .ok_or_else(|| JsError::new("PHASE_B32A_CANDIDATE_RESTORE_FAILED"))?;
    let scratch_projection = phase_b32a_projection_from_group(
        scratch.provider.as_ref().crypto(),
        &scratch_group,
        welcome_sender_leaf_index,
        expected_author,
        account_identity,
        leaf_signature_key,
        &welcome_sha256,
        &expected_key_package_sha256,
        &predecessor_state_sha256,
        &candidate_state_sha256,
    )?;
    if scratch_projection != projection {
        return Err(JsError::new("PHASE_B32A_CANDIDATE_PROJECTION_MISMATCH"));
    }
    Ok((candidate_state, projection))
}

#[cfg(feature = "extensions-draft")]
fn phase_b32a_projections_equal_except_candidate_digests(
    first: &PhaseB32aJoinProjection,
    second: &PhaseB32aJoinProjection,
) -> bool {
    let mut first = first.clone();
    let mut second = second.clone();
    first.candidate_state_sha256.clear();
    first.projection_sha256.clear();
    second.candidate_state_sha256.clear();
    second.projection_sha256.clear();
    first == second
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB32aPendingWelcome {
    pub fn prepare_from_durable_state(
        predecessor_state: &[u8],
        expected_predecessor_sha256: &[u8],
        account_identity: &[u8],
        leaf_signature_key: &[u8],
        welcome_bytes: &[u8],
        expected_key_package_bytes: &[u8],
        expected_author: &[u8],
    ) -> Result<PhaseB32aPendingWelcome, JsError> {
        let (first_state, first_projection) = phase_b32a_prepare_once(
            predecessor_state,
            expected_predecessor_sha256,
            account_identity,
            leaf_signature_key,
            welcome_bytes,
            expected_key_package_bytes,
            expected_author,
        )?;
        let (second_state, second_projection) = phase_b32a_prepare_once(
            predecessor_state,
            expected_predecessor_sha256,
            account_identity,
            leaf_signature_key,
            welcome_bytes,
            expected_key_package_bytes,
            expected_author,
        )?;
        if !phase_b32a_projections_equal_except_candidate_digests(
            &first_projection,
            &second_projection,
        ) {
            return Err(JsError::new("PHASE_B32A_PREPARATION_PROJECTION_DIVERGENCE"));
        }
        let evidence = phase_b32a_compare_candidate_states(
            &first_state.0,
            &second_state.0,
            second_projection.candidate_state_sha256.clone(),
        )?;
        let binding = PhaseB32aWelcomeBinding {
            expected_author: expected_author.to_vec(),
            predecessor_state_sha256: first_projection.predecessor_state_sha256.clone(),
            welcome_sha256: first_projection.welcome_sha256.clone(),
            expected_key_package_sha256: first_projection.expected_key_package_sha256.clone(),
            candidate_state_sha256: first_projection.candidate_state_sha256.clone(),
            projection_sha256: first_projection.projection_sha256.clone(),
            preparation_classification: evidence.classification,
            second_candidate_state_sha256: evidence.second_candidate_state_sha256.clone(),
            differing_storage_key: evidence.differing_storage_key.clone(),
        };
        Ok(Self {
            binding: Some(binding),
            candidate_state: first_state,
            projection: first_projection,
            preparation_classification: evidence.classification,
            second_candidate_state_sha256: evidence.second_candidate_state_sha256,
            differing_storage_key: evidence.differing_storage_key,
        })
    }

    pub fn projection(&self) -> PhaseB32aJoinProjection { self.projection.clone() }
    pub fn is_consumed(&self) -> bool { self.binding.is_none() }
    pub fn preparation_classification(&self) -> String {
        self.preparation_classification.tag().to_string()
    }
    pub fn second_candidate_state_sha256(&self) -> Vec<u8> {
        self.second_candidate_state_sha256.clone()
    }
    pub fn differing_storage_key(&self) -> Vec<u8> {
        self.differing_storage_key.clone()
    }

    pub fn release_candidate_state(
        &mut self,
        projection_sha256: &[u8],
        expected_author: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let binding = self
            .binding
            .as_ref()
            .ok_or_else(|| JsError::new("PHASE_B32A_HANDLE_CONSUMED"))?;
        if expected_author != binding.expected_author {
            return Err(JsError::new("PHASE_B32A_WELCOME_AUTHOR_MISMATCH"));
        }
        if !phase_b32a_constant_time_eq_32(projection_sha256, &binding.projection_sha256) {
            return Err(JsError::new("PHASE_B32A_PROJECTION_DIGEST_MISMATCH"));
        }
        if self.projection.predecessor_state_sha256 != binding.predecessor_state_sha256
            || self.projection.welcome_sha256 != binding.welcome_sha256
            || self.projection.expected_key_package_sha256 != binding.expected_key_package_sha256
            || self.projection.candidate_state_sha256 != binding.candidate_state_sha256
            || self.projection.projection_sha256 != binding.projection_sha256
            || self.preparation_classification != binding.preparation_classification
            || self.second_candidate_state_sha256
                != binding.second_candidate_state_sha256
            || self.differing_storage_key != binding.differing_storage_key
        {
            return Err(JsError::new("PHASE_B32A_HANDLE_BINDING_MISMATCH"));
        }
        let digest = phase_b32_sha256(
            &openmls_rust_crypto::RustCrypto::default(),
            &self.candidate_state.0,
            "PHASE_B32A_CANDIDATE_DIGEST_FAILED",
        )?;
        if !phase_b32a_constant_time_eq_32(&digest, &binding.candidate_state_sha256) {
            return Err(JsError::new("PHASE_B32A_CANDIDATE_DIGEST_MISMATCH"));
        }
        self.binding.take();
        Ok(std::mem::take(&mut self.candidate_state.0))
    }

    pub fn discard(&mut self) -> Result<(), JsError> {
        self.binding
            .take()
            .ok_or_else(|| JsError::new("PHASE_B32A_HANDLE_CONSUMED"))?;
        self.candidate_state.0.fill(0);
        self.candidate_state.0.clear();
        Ok(())
    }
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB32aGroup {
    pub fn load_canonical_state(
        candidate_state: &[u8],
        group_id: &[u8],
    ) -> Result<Option<PhaseB32aGroup>, JsError> {
        if group_id.is_empty() || group_id.len() > 64 {
            return Err(JsError::new("PHASE_B32A_GROUP_ID_INVALID"));
        }
        let provider = PhaseB32aPrivateProvider::from_snapshot(
            candidate_state,
            PhaseB32aSnapshotRole::CanonicalCandidate,
        )?;
        let requested = GroupId::from_slice(group_id);
        let Some(group) = MlsGroup::load(provider.provider.inner.storage(), &requested)? else {
            return Ok(None);
        };
        if group.group_id() != &requested {
            return Err(JsError::new("PHASE_B32A_LOADED_GROUP_ID_MISMATCH"));
        }
        phase_b32a_group_state(provider.provider.as_ref().crypto(), &group)?;
        Ok(Some(Self { provider, mls_group: group }))
    }

    pub fn group_id(&self) -> Vec<u8> { self.mls_group.group_id().to_vec() }
    pub fn epoch(&self) -> u64 { self.mls_group.epoch().as_u64() }
    pub fn canonical_state(&self) -> Result<Vec<u8>, JsError> { self.provider.canonical_state() }

    pub fn projection(
        &self,
        welcome_sender_leaf_index: u32,
        expected_author: &[u8],
        expected_own_identity: &[u8],
        expected_own_signature_key: &[u8],
        welcome_sha256: &[u8],
        expected_key_package_sha256: &[u8],
        predecessor_state_sha256: &[u8],
        candidate_state_sha256: &[u8],
    ) -> Result<PhaseB32aJoinProjection, JsError> {
        phase_b32a_projection_from_group(
            self.provider.provider.as_ref().crypto(),
            &self.mls_group,
            welcome_sender_leaf_index,
            expected_author,
            expected_own_identity,
            expected_own_signature_key,
            welcome_sha256,
            expected_key_package_sha256,
            predecessor_state_sha256,
            candidate_state_sha256,
        )
    }
}

#[cfg(feature = "extensions-draft")]
#[wasm_bindgen]
impl PhaseB32Group {
    pub fn load(provider: &Provider, group_id: &[u8]) -> Result<Option<PhaseB32Group>, JsError> {
        if group_id.is_empty() || group_id.len() > 64 {
            return Err(JsError::new("PHASE_B32_GROUP_ID_INVALID"));
        }
        let requested = GroupId::from_slice(group_id);
        let Some(group) = MlsGroup::load(provider.inner.storage(), &requested)? else {
            return Ok(None);
        };
        if group.group_id() != &requested {
            return Err(JsError::new("PHASE_B32_LOADED_GROUP_ID_MISMATCH"));
        }
        phase_b32_group_state(&group)?;
        Ok(Some(Self {
            mls_group: group,
            provider_instance_id: provider.instance_id,
            provider_restore_generation: provider.restore_generation.get(),
        }))
    }

    pub fn group_id(&self) -> Vec<u8> {
        self.mls_group.group_id().to_vec()
    }

    pub fn epoch(&self) -> u64 {
        self.mls_group.epoch().as_u64()
    }

    pub fn projection(
        &self,
        provider: &Provider,
        welcome_sender_leaf_index: u32,
        expected_author: &[u8],
        welcome_sha256: &[u8],
        expected_key_package_sha256: &[u8],
        predecessor_state_sha256: &[u8],
        candidate_state_sha256: &[u8],
    ) -> Result<PhaseB32JoinProjection, JsError> {
        self.validate_provider(provider)?;
        phase_b32_projection_from_group(
            provider.as_ref().crypto(),
            &self.mls_group,
            welcome_sender_leaf_index,
            expected_author,
            welcome_sha256,
            expected_key_package_sha256,
            predecessor_state_sha256,
            candidate_state_sha256,
        )
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
    #[test]
    fn phase_b31_canonical_varints_and_group_profile_codec_are_strict() {
        for (value, width) in [
            (0usize, 1usize),
            (63, 1),
            (64, 2),
            (16_383, 2),
            (16_384, 4),
            ((1usize << 30) - 1, 4),
            (1usize << 30, 8),
        ] {
            let mut encoded = Vec::new();
            phase_b31_write_canonical_quic_varint(value, &mut encoded).unwrap();
            assert_eq!(encoded.len(), width);
            let mut offset = 0usize;
            assert_eq!(
                phase_b31_read_canonical_quic_varint(&encoded, &mut offset).unwrap(),
                value
            );
            assert_eq!(offset, encoded.len());
        }

        for noncanonical in [
            vec![0x40, 0x00],
            vec![0x80, 0x00, 0x00, 0x00],
            vec![0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ] {
            assert_eq!(
                phase_b31_read_canonical_quic_varint(&noncanonical, &mut 0usize).unwrap_err(),
                "phase-b3.1 codec: non-canonical QUIC varint"
            );
        }
        for truncated in [vec![], vec![0x40], vec![0x80, 0, 0], vec![0xc0, 0, 0, 0, 0, 0, 0]] {
            assert_eq!(
                phase_b31_read_canonical_quic_varint(&truncated, &mut 0usize).unwrap_err(),
                "phase-b3.1 codec: truncated QUIC varint"
            );
        }

        let empty = phase_b31_encode_group_profile(b"", b"").unwrap();
        assert_eq!(empty, vec![0x00, 0x00]);
        assert_eq!(
            phase_b31_decode_group_profile(&empty).unwrap(),
            PhaseB31GroupProfile {
                name: vec![],
                description: vec![],
            }
        );
        assert!(phase_b31_decode_group_profile(&[]).is_err());
        assert!(phase_b31_decode_group_profile(&[0x00]).is_err());

        let composed = phase_b31_encode_group_profile("é".as_bytes(), b"profile").unwrap();
        let decomposed = phase_b31_encode_group_profile("e\u{301}".as_bytes(), b"profile").unwrap();
        assert_ne!(composed, decomposed);
        assert_eq!(
            phase_b31_decode_group_profile(&composed).unwrap().name,
            "é".as_bytes()
        );
        assert_eq!(
            phase_b31_decode_group_profile(&decomposed).unwrap().name,
            "e\u{301}".as_bytes()
        );

        assert!(phase_b31_encode_group_profile(&vec![b'a'; 256], &vec![b'b'; 4096]).is_ok());
        assert_eq!(
            phase_b31_encode_group_profile(&vec![b'a'; 257], b"").unwrap_err(),
            "PHASE_B31_GROUP_PROFILE_LIMIT"
        );
        assert_eq!(
            phase_b31_encode_group_profile(b"", &vec![b'b'; 4097]).unwrap_err(),
            "PHASE_B31_GROUP_PROFILE_LIMIT"
        );

        for invalid in [
            vec![0xc0, 0x80],
            vec![0xed, 0xa0, 0x80],
            vec![0xf4, 0x90, 0x80, 0x80],
            vec![0xe2, 0x82],
            vec![0x80],
        ] {
            let mut payload = vec![invalid.len() as u8];
            payload.extend_from_slice(&invalid);
            payload.push(0);
            assert_eq!(
                phase_b31_decode_group_profile(&payload).unwrap_err(),
                "phase-b3.1 group profile: invalid UTF-8"
            );
        }

        let mut trailing = empty.clone();
        trailing.push(0);
        assert_eq!(
            phase_b31_decode_group_profile(&trailing).unwrap_err(),
            "phase-b3.1 group profile: trailing bytes"
        );
        let over_limit_name = vec![0x41, 0x01];
        assert_eq!(
            phase_b31_decode_group_profile(&over_limit_name).unwrap_err(),
            "PHASE_B31_GROUP_PROFILE_LIMIT"
        );
    }

    #[cfg(feature = "extensions-draft")]
    #[test]
    fn phase_b31_component_list_decoder_and_cross_profile_checks_fail_closed() {
        let canonical = PHASE_B31_SUPPORTED_COMPONENTS
            .to_vec()
            .tls_serialize_detached()
            .unwrap();
        assert_eq!(
            phase_b31_decode_component_ids(&canonical).unwrap(),
            PHASE_B31_SUPPORTED_COMPONENTS
        );
        assert!(phase_b31_check_component_profile(
            &[1, ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID],
            &PHASE_B31_SUPPORTED_COMPONENTS,
        )
        .is_ok());
        assert_eq!(
            phase_b2_check_component_profile(
                &[1, ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID],
                &PHASE_B31_SUPPORTED_COMPONENTS,
            )
            .unwrap_err(),
            "phase-b2 leaf: unexpected supported components"
        );
        assert_eq!(
            phase_b31_check_component_profile(
                &[1, ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID],
                &PHASE_B2_COMPONENTS,
            )
            .unwrap_err(),
            "phase-b3.1 leaf: unexpected supported components"
        );

        let mut overlong = vec![0x40, canonical[0]];
        overlong.extend_from_slice(&canonical[1..]);
        assert_eq!(
            phase_b31_decode_component_ids(&overlong).unwrap_err(),
            "phase-b3.1 codec: non-canonical QUIC varint"
        );
        let mut truncated = canonical.clone();
        truncated.pop();
        assert_eq!(
            phase_b31_decode_component_ids(&truncated).unwrap_err(),
            "phase-b3.1 components: truncated list"
        );
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert_eq!(
            phase_b31_decode_component_ids(&trailing).unwrap_err(),
            "phase-b3.1 components: trailing bytes"
        );
        assert_eq!(
            phase_b31_decode_component_ids(&[0x01, 0x00]).unwrap_err(),
            "phase-b3.1 components: odd byte length"
        );
        assert_eq!(
            phase_b31_decode_component_ids(&[0x04, 0x80, 0x03, 0x80, 0x03]).unwrap_err(),
            "phase-b3.1 components: list must be sorted and unique"
        );
        assert_eq!(
            phase_b31_decode_component_ids(&[0x04, 0x80, 0x09, 0x80, 0x03]).unwrap_err(),
            "phase-b3.1 components: list must be sorted and unique"
        );
        let unknown = phase_b31_decode_component_ids(&[
            0x08, 0x80, 0x01, 0x80, 0x03, 0x80, 0x09, 0x80, 0x0d,
        ])
        .unwrap();
        assert_eq!(
            phase_b31_check_component_profile(
                &[1, ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID],
                &unknown,
            )
            .unwrap_err(),
            "phase-b3.1 leaf: unexpected supported components"
        );
        assert_eq!(
            phase_b31_decode_component_ids(&[0x40, 0x82]).unwrap_err(),
            "PHASE_B31_COMPONENT_LIMIT"
        );
    }

    #[cfg(feature = "extensions-draft")]
    #[test]
    fn phase_b31_key_package_and_group_context_are_isolated_from_phase_b2() {
        let founder_provider = Provider::new();
        let bob_provider = Provider::new();
        let (founder, founder_proof, _) = phase_b2_identity(&founder_provider, 0x71);
        let (bob, bob_proof, bob_b2) = phase_b2_identity(&bob_provider, 0x72);
        let bob_b31 = bob
            .b3_1_key_package(&bob_provider, &bob_proof)
            .map_err(js_error_to_string)
            .unwrap();
        let b31_framed = bob_b31.to_framed_bytes().unwrap();
        let parsed_b31 = PhaseB31KeyPackage::from_framed_bytes(&b31_framed)
            .map_err(js_error_to_string)
            .unwrap();
        assert_eq!(parsed_b31.ciphersuite_id(), 0x0001);
        assert_eq!(parsed_b31.component_ids(), vec![1, 0x8009]);
        assert_eq!(
            parsed_b31.supported_component_ids().unwrap(),
            PHASE_B31_SUPPORTED_COMPONENTS
        );
        assert!(!parsed_b31.is_last_resort());

        let b2_reads_b31 = std::panic::catch_unwind(|| {
            PhaseB2KeyPackage::from_framed_bytes(&b31_framed)
        });
        assert!(
            b2_reads_b31.is_err() || b2_reads_b31.unwrap().is_err(),
            "the Phase B2 reader must reject exact B3.1 bytes"
        );
        let b2_framed = bob_b2.to_framed_bytes().unwrap();
        let b31_reads_b2 = std::panic::catch_unwind(|| {
            PhaseB31KeyPackage::from_framed_bytes(&b2_framed)
        });
        assert!(
            b31_reads_b2.is_err() || b31_reads_b2.unwrap().is_err(),
            "the Phase B3.1 reader must reject exact B2 bytes"
        );

        let mut b2_group = PhaseB2Group::create_new(
            &founder_provider,
            &founder,
            b"phase-b31-cross-profile-add",
            &founder_proof,
        )
        .map_err(js_error_to_string)
        .unwrap();
        let b31_as_b2 = PhaseB2KeyPackage(bob_b31.0.clone());
        let add_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            b2_group.prepare_add(&founder_provider, &founder, &b31_as_b2)
        }));
        assert!(
            add_result.is_err() || add_result.unwrap().is_err(),
            "the Phase B2 add path must reject a B3.1 package"
        );

        let profile_name = "Styx B3.1 synthetic interop".as_bytes();
        let profile_description = "Exact-pin direct-MLS evidence only".as_bytes();
        let extensions = phase_b31_group_context_extensions(
            &founder.account_public_key,
            profile_name,
            profile_description,
        )
        .map_err(js_error_to_string)
        .unwrap();
        let projected = phase_b31_validate_group_context_extensions(
            &extensions,
            &[founder.account_public_key.clone()],
        )
        .map_err(js_error_to_string)
        .unwrap();
        assert_eq!(projected.required_components, PHASE_B31_REQUIRED_COMPONENTS);
        assert_eq!(projected.group_profile.name, profile_name);
        assert_eq!(projected.group_profile.description, profile_description);
        assert_eq!(projected.lifecycle, vec![0x00]);
        assert_eq!(projected.administrator_policy.len(), 33);
        let dictionary = extensions
            .app_data_dictionary()
            .unwrap()
            .dictionary();
        assert_eq!(
            dictionary.entries().map(|entry| entry.id()).collect::<Vec<_>>(),
            vec![1, 0x8001, 0x8003, 0x800c]
        );
        assert_eq!(dictionary.get(&0x8001).unwrap(), [
            profile_name.len() as u8,
        ]
        .into_iter()
        .chain(profile_name.iter().copied())
        .chain([profile_description.len() as u8])
        .chain(profile_description.iter().copied())
        .collect::<Vec<_>>());
    }

    #[cfg(feature = "extensions-draft")]
    struct PhaseB32NativeFixture {
        joiner_provider: Provider,
        joiner: PhaseB2Identity,
        joiner_proof: Vec<u8>,
        group_id: Vec<u8>,
        expected_author: Vec<u8>,
        key_package_bytes: Vec<u8>,
        welcome_bytes: Vec<u8>,
    }

    #[cfg(feature = "extensions-draft")]
    fn phase_b32_native_fixture(
        group_id: &[u8],
        founder_byte: u8,
        joiner_byte: u8,
        embed_ratchet_tree: bool,
    ) -> PhaseB32NativeFixture {
        let mut founder_provider = Provider::new();
        let joiner_provider = Provider::new();
        let (founder, founder_proof, _) =
            phase_b2_identity(&founder_provider, founder_byte);
        let (joiner, joiner_proof, _) = phase_b2_identity(&joiner_provider, joiner_byte);
        let joiner_key_package = joiner
            .b3_1_key_package(&joiner_provider, &joiner_proof)
            .map_err(js_error_to_string)
            .unwrap();
        let key_package_bytes = joiner_key_package.to_framed_bytes().unwrap();

        let mut founder_group = MlsGroup::builder()
            .ciphersuite(PROBE_CIPHERSUITE)
            .with_group_id(GroupId::from_slice(group_id))
            .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(embed_ratchet_tree)
            .with_group_context_extensions(
                phase_b31_group_context_extensions(
                    &founder.account_public_key,
                    b"B3.2 native join",
                    b"clone-only embedded-tree Welcome fixture",
                )
                .map_err(js_error_to_string)
                .unwrap(),
            )
            .with_capabilities(phase_b2_capabilities())
            .with_leaf_node_extensions(
                phase_b31_leaf_extensions(&founder_proof)
                    .map_err(js_error_to_string)
                    .unwrap(),
            )
            .unwrap()
            .build(
                &founder_provider.inner,
                &founder.keypair,
                founder.credential_with_key.clone(),
            )
            .unwrap();
        let (_, welcome, _) = founder_group
            .add_members(
                &founder_provider.inner,
                &founder.keypair,
                &[joiner_key_package.0.clone()],
            )
            .unwrap();
        founder_group
            .merge_pending_commit(founder_provider.as_mut())
            .unwrap();

        PhaseB32NativeFixture {
            joiner_provider,
            joiner,
            joiner_proof,
            group_id: group_id.to_vec(),
            expected_author: founder.account_public_key,
            key_package_bytes,
            welcome_bytes: welcome.tls_serialize_detached().unwrap(),
        }
    }

    #[cfg(feature = "extensions-draft")]
    fn phase_b32_assert_rejected<F>(operation: F)
    where
        F: FnOnce() -> Result<(), JsError>,
    {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "hostile B3.2 operation unexpectedly succeeded"
        );
    }

    #[cfg(feature = "extensions-draft")]
    fn phase_b32a_mdk_leaf_extensions(proof: &[u8]) -> Extensions<LeafNode> {
        let mut dictionary = AppDataDictionary::new();
        dictionary.insert(
            0x0001,
            PHASE_B32A_SUPPORTED_COMPONENTS
                .to_vec()
                .tls_serialize_detached()
                .unwrap(),
        );
        dictionary.insert(
            0x0002,
            Vec::<ComponentId>::new().tls_serialize_detached().unwrap(),
        );
        dictionary.insert(ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID, proof.to_vec());
        Extensions::single(Extension::AppDataDictionary(
            AppDataDictionaryExtension::new(dictionary),
        ))
        .unwrap()
    }

    #[cfg(feature = "extensions-draft")]
    struct PhaseB32aNativeFixture {
        predecessor_state: Vec<u8>,
        predecessor_sha256: Vec<u8>,
        account_identity: Vec<u8>,
        leaf_signature_key: Vec<u8>,
        group_id: Vec<u8>,
        expected_author: Vec<u8>,
        key_package_bytes: Vec<u8>,
        welcome_bytes: Vec<u8>,
    }

    #[cfg(feature = "extensions-draft")]
    fn phase_b32a_native_fixture(
        group_id: &[u8],
        founder_byte: u8,
        joiner_byte: u8,
    ) -> PhaseB32aNativeFixture {
        let mut founder_provider = Provider::new();
        let joiner_provider = Provider::new();
        let (founder, founder_proof, _) = phase_b2_identity(&founder_provider, founder_byte);
        let (joiner, joiner_proof, _) = phase_b2_identity(&joiner_provider, joiner_byte);
        let joiner_key_package = joiner
            .b3_2a_key_package(&joiner_provider, &joiner_proof)
            .map_err(js_error_to_string)
            .unwrap();
        let key_package_bytes = joiner_key_package.to_framed_bytes().unwrap();
        let account_identity = joiner.account_public_key.clone();
        let leaf_signature_key = joiner.keypair.public().to_vec();

        let mut founder_group = MlsGroup::builder()
            .ciphersuite(PROBE_CIPHERSUITE)
            .with_group_id(GroupId::from_slice(group_id))
            .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .with_group_context_extensions(
                phase_b31_group_context_extensions(
                    &founder.account_public_key,
                    b"B3.2a exact-pin join",
                    b"durable-input canonical candidate",
                )
                .map_err(js_error_to_string)
                .unwrap(),
            )
            .with_capabilities(phase_b32a_mdk_capabilities())
            .with_leaf_node_extensions(phase_b32a_mdk_leaf_extensions(&founder_proof))
            .unwrap()
            .build(
                &founder_provider.inner,
                &founder.keypair,
                founder.credential_with_key.clone(),
            )
            .unwrap();
        let (_, welcome, _) = founder_group
            .add_members(
                &founder_provider.inner,
                &founder.keypair,
                &[joiner_key_package.0.clone()],
            )
            .unwrap();
        founder_group
            .merge_pending_commit(founder_provider.as_mut())
            .unwrap();
        let predecessor_state = joiner_provider.serialize_state();
        let predecessor_sha256 = phase_b32_sha256(
            joiner_provider.as_ref().crypto(),
            &predecessor_state,
            "test",
        )
        .map_err(js_error_to_string)
        .unwrap();
        PhaseB32aNativeFixture {
            predecessor_state,
            predecessor_sha256,
            account_identity,
            leaf_signature_key,
            group_id: group_id.to_vec(),
            expected_author: founder.account_public_key,
            key_package_bytes,
            welcome_bytes: welcome.tls_serialize_detached().unwrap(),
        }
    }

    #[cfg(feature = "extensions-draft")]
    #[test]
    fn phase_b32a_exact_profiles_accept_only_bounded_retention_metadata() {
        let fixture = phase_b32a_native_fixture(b"phase-b32a-native-success", 0x91, 0x92);
        let parsed_key_package = PhaseB32aKeyPackage::from_framed_bytes(
            &fixture.key_package_bytes,
        )
        .map_err(js_error_to_string)
        .unwrap();
        assert_eq!(parsed_key_package.capability_extension_ids(), vec![0x0006]);
        assert_eq!(parsed_key_package.capability_proposal_ids(), vec![0x0008]);
        assert_eq!(parsed_key_package.component_ids(), vec![0x0001, 0x8009]);
        assert_eq!(
            parsed_key_package.supported_component_ids().unwrap(),
            PHASE_B32A_SUPPORTED_COMPONENTS,
        );

        let (state_a, projection_a) = phase_b32a_prepare_once(
            &fixture.predecessor_state,
            &fixture.predecessor_sha256,
            &fixture.account_identity,
            &fixture.leaf_signature_key,
            &fixture.welcome_bytes,
            &fixture.key_package_bytes,
            &fixture.expected_author,
        )
        .map_err(js_error_to_string)
        .unwrap();
        let (state_b, projection_b) = phase_b32a_prepare_once(
            &fixture.predecessor_state,
            &fixture.predecessor_sha256,
            &fixture.account_identity,
            &fixture.leaf_signature_key,
            &fixture.welcome_bytes,
            &fixture.key_package_bytes,
            &fixture.expected_author,
        )
        .map_err(js_error_to_string)
        .unwrap();
        assert!(phase_b32a_projections_equal_except_candidate_digests(
            &projection_a,
            &projection_b,
        ));
        let evidence = phase_b32a_compare_candidate_states(
            &state_a.0,
            &state_b.0,
            projection_b.candidate_state_sha256.clone(),
        )
        .map_err(js_error_to_string)
        .unwrap();
        assert_eq!(evidence.second_candidate_state_sha256.len(), 32);
        match evidence.classification {
            PhaseB32aPreparationClassification::ByteIdentical => {
                assert!(evidence.differing_storage_key.is_empty());
            }
            PhaseB32aPreparationClassification::RetentionTimestampBounded => {
                assert!(evidence
                    .differing_storage_key
                    .starts_with(b"MessageSecrets"));
            }
        }

        assert_eq!(projection_a.member_count(), 2);
        assert_eq!(projection_a.member_profile(0).unwrap(), "MDK_PIN_9396ADB");
        assert_eq!(projection_a.member_profile(1).unwrap(), "STYX_B32A");
        assert!(projection_a.member_lists_default_required_capabilities(0).unwrap());
        assert!(projection_a.member_emits_empty_safe_aad(0).unwrap());
        assert!(!projection_a.member_lists_default_required_capabilities(1).unwrap());
        assert!(!projection_a.member_emits_empty_safe_aad(1).unwrap());
        assert_eq!(projection_a.welcome_sender_identity(), fixture.expected_author);

        let mut pending = PhaseB32aPendingWelcome::prepare_from_durable_state(
            &fixture.predecessor_state,
            &fixture.predecessor_sha256,
            &fixture.account_identity,
            &fixture.leaf_signature_key,
            &fixture.welcome_bytes,
            &fixture.key_package_bytes,
            &fixture.expected_author,
        )
        .map_err(js_error_to_string)
        .unwrap();
        assert!(matches!(
            pending.preparation_classification().as_str(),
            "BYTE_IDENTICAL" | "RETENTION_TIMESTAMP_BOUNDED"
        ));
        assert_eq!(pending.second_candidate_state_sha256().len(), 32);
        if pending.preparation_classification() == "RETENTION_TIMESTAMP_BOUNDED" {
            assert!(pending.differing_storage_key().starts_with(b"MessageSecrets"));
        } else {
            assert!(pending.differing_storage_key().is_empty());
        }
        let projection = pending.projection();
        let candidate = pending
            .release_candidate_state(
                &projection.projection_sha256(),
                &fixture.expected_author,
        )
            .map_err(js_error_to_string)
            .unwrap();
        assert!(pending.is_consumed());
        phase_b32_assert_rejected(|| {
            pending
                .release_candidate_state(
                &projection.projection_sha256(),
                &fixture.expected_author,
            )
                .map(|_| ())
        });
        let restored = PhaseB32aGroup::load_canonical_state(&candidate, &fixture.group_id)
            .map_err(js_error_to_string)
            .unwrap()
            .expect("released exact candidate must restore");
        assert_eq!(restored.group_id(), fixture.group_id);
        for _ in 0..200 {
            let provider = PhaseB32aPrivateProvider::from_snapshot(
                &candidate,
                PhaseB32aSnapshotRole::CanonicalCandidate,
            )
            .map_err(js_error_to_string)
            .unwrap();
            assert_eq!(
                provider.canonical_state().map_err(js_error_to_string).unwrap(),
                candidate,
            );
        }
    }

    #[cfg(feature = "extensions-draft")]
    #[test]
    fn phase_b32a_retention_comparator_is_strict_and_fail_closed() {
        let encode_snapshot = |entries: &[(&[u8], &[u8])]| {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&(entries.len() as u64).to_be_bytes());
            for (key, value) in entries {
                bytes.extend_from_slice(&(key.len() as u64).to_be_bytes());
                bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
                bytes.extend_from_slice(key);
                bytes.extend_from_slice(value);
            }
            bytes
        };
        let message_secrets = |seconds: u64, nanos: u64| {
            format!(
                "{{\"max_epochs\":0,\"past_epoch_trees\":[],\"message_secrets\":{{\"sender_data_secret\":[],\"membership_key\":[],\"confirmation_key\":[],\"serialized_context\":[],\"secret_tree\":{{}},\"added_at\":{{\"secs_since_epoch\":{seconds},\"nanos_since_epoch\":{nanos}}}}}}}"
            )
            .into_bytes()
        };
        let key = b"MessageSecrets[1,2,3]\\u0001";
        let first_value = message_secrets(100, 10);
        let second_value = message_secrets(101, 20);
        let first = encode_snapshot(&[(key, &first_value), (b"Other", b"same")]);
        let identical = encode_snapshot(&[(key, &first_value), (b"Other", b"same")]);
        let second = encode_snapshot(&[(key, &second_value), (b"Other", b"same")]);

        let identical_evidence =
            phase_b32a_compare_candidate_states(&first, &identical, vec![0x11; 32])
                .map_err(js_error_to_string)
                .unwrap();
        assert_eq!(
            identical_evidence.classification,
            PhaseB32aPreparationClassification::ByteIdentical
        );
        assert!(identical_evidence.differing_storage_key.is_empty());

        let bounded = phase_b32a_compare_candidate_states(&first, &second, vec![0x22; 32])
            .map_err(js_error_to_string)
            .unwrap();
        assert_eq!(
            bounded.classification,
            PhaseB32aPreparationClassification::RetentionTimestampBounded
        );
        assert_eq!(bounded.differing_storage_key, key);

        let other_difference =
            encode_snapshot(&[(key, &first_value), (b"Other", b"different")]);
        phase_b32_assert_rejected(|| {
            phase_b32a_compare_candidate_states(
                &first,
                &other_difference,
                vec![0x33; 32],
            )
            .map(|_| ())
        });
        let multiple_differences =
            encode_snapshot(&[(key, &second_value), (b"Other", b"different")]);
        phase_b32_assert_rejected(|| {
            phase_b32a_compare_candidate_states(
                &first,
                &multiple_differences,
                vec![0x34; 32],
            )
            .map(|_| ())
        });

        let changed_secret = String::from_utf8(first_value.clone())
            .unwrap()
            .replace("\"sender_data_secret\":[]", "\"sender_data_secret\":[1]")
            .into_bytes();
        let changed_secret_snapshot =
            encode_snapshot(&[(key, &changed_secret), (b"Other", b"same")]);
        phase_b32_assert_rejected(|| {
            phase_b32a_compare_candidate_states(
                &first,
                &changed_secret_snapshot,
                vec![0x44; 32],
            )
            .map(|_| ())
        });

        let second_message_key = b"MessageSecrets[4,5,6]\\u0001";
        let two_message_entries = encode_snapshot(&[
            (key, &first_value),
            (second_message_key, &first_value),
            (b"Other", b"same"),
        ]);
        phase_b32_assert_rejected(|| {
            phase_b32a_compare_candidate_states(
                &two_message_entries,
                &two_message_entries,
                vec![0x55; 32],
            )
            .map(|_| ())
        });
        phase_b32_assert_rejected(|| {
            phase_b32a_compare_candidate_states(&first, &identical, vec![0x66; 31])
                .map(|_| ())
        });

        for malformed in [
            String::from_utf8(first_value.clone()).unwrap().replace(
                "\"added_at\":{\"secs_since_epoch\":100,\"nanos_since_epoch\":10}",
                "\"added_at\":null",
            ),
            String::from_utf8(first_value.clone()).unwrap().replace(
                ",\"nanos_since_epoch\":10",
                "",
            ),
            String::from_utf8(first_value.clone()).unwrap().replace(
                "\"nanos_since_epoch\":10",
                "\"nanos_since_epoch\":10,\"extra\":0",
            ),
            String::from_utf8(first_value.clone()).unwrap().replace(
                "\"nanos_since_epoch\":10",
                "\"nanos_since_epoch\":10,\"nanos_since_epoch\":10",
            ),
            String::from_utf8(first_value.clone()).unwrap().replace(
                "\"secs_since_epoch\":100,\"nanos_since_epoch\":10",
                "\"nanos_since_epoch\":10,\"secs_since_epoch\":100",
            ),
            String::from_utf8(first_value.clone()).unwrap().replace(
                "\"nanos_since_epoch\":10",
                "\"nanoseconds\":10",
            ),
            String::from_utf8(first_value.clone()).unwrap().replace(
                "\"secs_since_epoch\":100",
                "\"secs_since_epoch\":-1",
            ),
            String::from_utf8(first_value.clone()).unwrap().replace(
                "\"secs_since_epoch\":100",
                "\"secs_since_epoch\":18446744073709551616",
            ),
            String::from_utf8(first_value.clone()).unwrap().replace(
                "\"nanos_since_epoch\":10",
                "\"nanos_since_epoch\":1000000000",
            ),
            String::from_utf8(first_value.clone()).unwrap().replace(
                "\"nanos_since_epoch\":10",
                "\"nanos_since_epoch\":\"10\"",
            ),
            String::from_utf8(first_value.clone()).unwrap().replace(
                "\"max_epochs\":0",
                "\"max_epochs\":0 ",
            ),
        ] {
            phase_b32_assert_rejected(|| {
                phase_b32a_message_secrets_timestamp_spans(malformed.as_bytes()).map(|_| ())
            });
        }
        let deep_value = format!("{}0{}", "[".repeat(66), "]".repeat(66));
        let too_deep = String::from_utf8(first_value)
            .unwrap()
            .replace("\"sender_data_secret\":[]", &format!("\"sender_data_secret\":{deep_value}"));
        phase_b32_assert_rejected(|| {
            phase_b32a_message_secrets_timestamp_spans(too_deep.as_bytes()).map(|_| ())
        });
    }

    #[cfg(feature = "extensions-draft")]
    #[test]
    fn phase_b32a_snapshot_parser_and_digest_binding_fail_closed() {
        let encode = |entries: &[(&[u8], &[u8])]| {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&(entries.len() as u64).to_be_bytes());
            for (key, value) in entries {
                bytes.extend_from_slice(&(key.len() as u64).to_be_bytes());
                bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
                bytes.extend_from_slice(key);
                bytes.extend_from_slice(value);
            }
            bytes
        };
        let unordered = encode(&[(b"b", b"2"), (b"a", b"1")]);
        assert!(phase_b32a_snapshot_entries(
            &unordered,
            PhaseB32aSnapshotRole::Predecessor,
        )
        .is_ok());
        phase_b32_assert_rejected(|| {
            phase_b32a_snapshot_entries(
                &unordered,
                PhaseB32aSnapshotRole::CanonicalCandidate,
            )
            .map(|_| ())
        });
        let duplicate = encode(&[(b"a", b"1"), (b"a", b"2")]);
        phase_b32_assert_rejected(|| {
            phase_b32a_snapshot_entries(&duplicate, PhaseB32aSnapshotRole::Predecessor)
                .map(|_| ())
        });
        let mut trailing = encode(&[(b"a", b"1")]);
        trailing.push(0);
        phase_b32_assert_rejected(|| {
            phase_b32a_snapshot_entries(&trailing, PhaseB32aSnapshotRole::Predecessor)
                .map(|_| ())
        });
        let private = PhaseB32aPrivateProvider::from_snapshot(
            &unordered,
            PhaseB32aSnapshotRole::Predecessor,
        )
        .map_err(js_error_to_string)
        .unwrap();
        let canonical = private.canonical_state().map_err(js_error_to_string).unwrap();
        for _ in 0..200 {
            let restored = PhaseB32aPrivateProvider::from_snapshot(
                &canonical,
                PhaseB32aSnapshotRole::CanonicalCandidate,
            )
            .map_err(js_error_to_string)
            .unwrap();
            assert_eq!(
                restored.canonical_state().map_err(js_error_to_string).unwrap(),
                canonical,
            );
        }

        let fixture = phase_b32a_native_fixture(b"phase-b32a-native-hostile", 0x93, 0x94);
        let mut wrong_digest = fixture.predecessor_sha256.clone();
        wrong_digest[0] ^= 1;
        phase_b32_assert_rejected(|| {
            PhaseB32aPendingWelcome::prepare_from_durable_state(
                &fixture.predecessor_state,
                &wrong_digest,
                &fixture.account_identity,
                &fixture.leaf_signature_key,
                &fixture.welcome_bytes,
                &fixture.key_package_bytes,
                &fixture.expected_author,
            )
            .map(|_| ())
        });
    }

    #[cfg(feature = "extensions-draft")]
    #[test]
    fn phase_b32_welcome_prepare_is_clone_only_one_use_and_restartable() {
        let fixture = phase_b32_native_fixture(b"phase-b32-native-success", 0x81, 0x82, true);
        let predecessor = fixture.joiner_provider.serialize_state();
        let mut pending = PhaseB32PendingWelcome::prepare(
            &fixture.joiner_provider,
            &fixture.joiner,
            &fixture.welcome_bytes,
            &fixture.key_package_bytes,
            &fixture.expected_author,
        )
        .map_err(js_error_to_string)
        .unwrap();
        assert_eq!(fixture.joiner_provider.serialize_state(), predecessor);

        let projection = pending.projection();
        assert_eq!(projection.domain(), "STYX-B32-JOIN-PROJECTION-v1");
        assert_eq!(projection.version(), 1);
        assert_eq!(projection.group_id(), fixture.group_id);
        assert_eq!(projection.epoch(), 1);
        assert_eq!(projection.ciphersuite_id(), 0x0001);
        assert_eq!(projection.member_count(), 2);
        assert_eq!(projection.welcome_sender_identity(), fixture.expected_author);
        assert_eq!(projection.group_profile_name(), b"B3.2 native join");
        assert_eq!(projection.lifecycle(), vec![0x00]);
        assert_eq!(projection.projection_sha256().len(), 32);

        let candidate = pending
            .release_candidate_state(
                &fixture.joiner_provider,
                &projection.projection_sha256(),
                &fixture.expected_author,
            )
            .map_err(js_error_to_string)
            .unwrap();
        assert!(pending.is_consumed());
        assert_eq!(fixture.joiner_provider.serialize_state(), predecessor);
        phase_b32_assert_rejected(|| {
            pending
                .release_candidate_state(
                    &fixture.joiner_provider,
                    &projection.projection_sha256(),
                    &fixture.expected_author,
                )
                .map(|_| ())
        });

        let activated = Provider::new();
        activated.restore_state(&candidate).unwrap();
        let loaded = PhaseB32Group::load(&activated, &fixture.group_id)
            .map_err(js_error_to_string)
            .unwrap()
            .expect("released candidate must load after a fresh restore");
        assert_eq!(loaded.group_id(), fixture.group_id);
        assert_eq!(loaded.epoch(), 1);
        let restored_projection = loaded
            .projection(
                &activated,
                projection.welcome_sender_leaf_index(),
                &fixture.expected_author,
                &projection.welcome_sha256(),
                &projection.expected_key_package_sha256(),
                &projection.predecessor_state_sha256(),
                &projection.candidate_state_sha256(),
            )
            .map_err(js_error_to_string)
            .unwrap();
        assert!(restored_projection == projection);

        let activated_before_replay = activated.serialize_state();
        phase_b32_assert_rejected(|| {
            PhaseB32PendingWelcome::prepare(
                &activated,
                &fixture.joiner,
                &fixture.welcome_bytes,
                &fixture.key_package_bytes,
                &fixture.expected_author,
            )
            .map(|_| ())
        });
        assert_eq!(activated.serialize_state(), activated_before_replay);
    }

    #[cfg(feature = "extensions-draft")]
    #[test]
    fn phase_b32_welcome_rejects_mismatch_missing_tree_and_group_collision_without_mutation() {
        let fixture = phase_b32_native_fixture(b"phase-b32-native-hostile", 0x83, 0x84, true);
        let predecessor = fixture.joiner_provider.serialize_state();

        let other_key_package = fixture
            .joiner
            .b3_1_key_package(&fixture.joiner_provider, &fixture.joiner_proof)
            .map_err(js_error_to_string)
            .unwrap()
            .to_framed_bytes()
            .unwrap();
        let with_other_key_package = fixture.joiner_provider.serialize_state();
        phase_b32_assert_rejected(|| {
            PhaseB32PendingWelcome::prepare(
                &fixture.joiner_provider,
                &fixture.joiner,
                &fixture.welcome_bytes,
                &other_key_package,
                &fixture.expected_author,
            )
            .map(|_| ())
        });
        assert_eq!(fixture.joiner_provider.serialize_state(), with_other_key_package);

        phase_b32_assert_rejected(|| {
            PhaseB32PendingWelcome::prepare(
                &fixture.joiner_provider,
                &fixture.joiner,
                &fixture.welcome_bytes,
                &fixture.key_package_bytes,
                &[0xff; 32],
            )
            .map(|_| ())
        });
        assert_eq!(fixture.joiner_provider.serialize_state(), with_other_key_package);
        assert_ne!(with_other_key_package, predecessor);

        let missing_tree =
            phase_b32_native_fixture(b"phase-b32-native-no-tree", 0x85, 0x86, false);
        let missing_tree_predecessor = missing_tree.joiner_provider.serialize_state();
        phase_b32_assert_rejected(|| {
            PhaseB32PendingWelcome::prepare(
                &missing_tree.joiner_provider,
                &missing_tree.joiner,
                &missing_tree.welcome_bytes,
                &missing_tree.key_package_bytes,
                &missing_tree.expected_author,
            )
            .map(|_| ())
        });
        assert_eq!(
            missing_tree.joiner_provider.serialize_state(),
            missing_tree_predecessor
        );

        let collision = phase_b32_native_fixture(b"phase-b32-native-collision", 0x87, 0x88, true);
        let conflicting_group = MlsGroup::builder()
            .ciphersuite(PROBE_CIPHERSUITE)
            .with_group_id(GroupId::from_slice(&collision.group_id))
            .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .with_group_context_extensions(
                phase_b31_group_context_extensions(
                    &collision.joiner.account_public_key,
                    b"collision",
                    b"pre-existing group",
                )
                .map_err(js_error_to_string)
                .unwrap(),
            )
            .with_capabilities(phase_b2_capabilities())
            .with_leaf_node_extensions(
                phase_b31_leaf_extensions(&collision.joiner_proof)
                    .map_err(js_error_to_string)
                    .unwrap(),
            )
            .unwrap()
            .build(
                &collision.joiner_provider.inner,
                &collision.joiner.keypair,
                collision.joiner.credential_with_key.clone(),
            )
            .unwrap();
        assert_eq!(conflicting_group.group_id().as_slice(), collision.group_id);
        let collision_predecessor = collision.joiner_provider.serialize_state();
        phase_b32_assert_rejected(|| {
            PhaseB32PendingWelcome::prepare(
                &collision.joiner_provider,
                &collision.joiner,
                &collision.welcome_bytes,
                &collision.key_package_bytes,
                &collision.expected_author,
            )
            .map(|_| ())
        });
        assert_eq!(collision.joiner_provider.serialize_state(), collision_predecessor);
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
    fn phase_b2_receive_binds_current_epoch_authenticated_sender() {
        fn assert_received(
            received: PhaseB2ReceivedApplicationMessage,
            expected_group_id: &[u8],
            expected_epoch: u64,
            expected_leaf: u32,
            expected_identity: &[u8],
            expected_signature_key: &[u8],
            expected_plaintext: &[u8],
        ) {
            assert_eq!(received.group_id(), expected_group_id);
            assert_eq!(received.epoch(), expected_epoch);
            assert_eq!(received.sender_leaf_index(), expected_leaf);
            assert_eq!(received.sender_credential_identity(), expected_identity);
            assert_eq!(received.sender_signature_key(), expected_signature_key);
            assert_eq!(received.plaintext(), expected_plaintext);
        }

        let group_id = b"phase-b2-authenticated-receive";
        let mut alice_provider = Provider::new();
        let mut bob_provider = Provider::new();
        let mut charlie_provider = Provider::new();
        let (alice, alice_proof, _) = phase_b2_identity(&alice_provider, 0x81);
        let (_bob, _, bob_key_package) = phase_b2_identity(&bob_provider, 0x82);
        let (charlie, charlie_proof, charlie_key_package) =
            phase_b2_identity(&charlie_provider, 0x83);

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
        let add_bob_projection = add_bob.projection();
        alice_group
            .confirm_pending(
                &mut alice_provider,
                &mut add_bob,
                &add_bob_projection.verified_leaf_digest(),
            )
            .map_err(js_error_to_string)
            .unwrap();
        let mut bob_group = PhaseB2Group::join(
            &bob_provider,
            &add_bob.welcome().unwrap(),
            PhaseB2RatchetTree::from_bytes(
                &alice_group.export_ratchet_tree().to_bytes().unwrap(),
            )
            .map_err(js_error_to_string)
            .unwrap(),
        )
        .map_err(js_error_to_string)
        .unwrap();

        let mut add_charlie = alice_group
            .prepare_add(&alice_provider, &alice, &charlie_key_package)
            .map_err(js_error_to_string)
            .unwrap();
        let add_charlie_projection = add_charlie.projection();
        let charlie_leaf = add_charlie_projection
            .proposal_added_leaf_index(0)
            .unwrap()
            .unwrap();
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
        let mut charlie_group = PhaseB2Group::join(
            &charlie_provider,
            &add_charlie.welcome().unwrap(),
            PhaseB2RatchetTree::from_bytes(
                &alice_group.export_ratchet_tree().to_bytes().unwrap(),
            )
            .map_err(js_error_to_string)
            .unwrap(),
        )
        .map_err(js_error_to_string)
        .unwrap();
        assert_eq!(alice_group.epoch(), 2);
        assert_eq!(bob_group.epoch(), 2);
        assert_eq!(charlie_group.epoch(), 2);

        for (plaintext, from_charlie) in [
            (b"alice-one".as_slice(), false),
            (b"charlie-one".as_slice(), true),
            (b"alice-two".as_slice(), false),
        ] {
            let (message, leaf, identity, signature_key) = if from_charlie {
                (
                    charlie_group
                        .create_application_message(&charlie_provider, &charlie, plaintext)
                        .map_err(js_error_to_string)
                        .unwrap(),
                    charlie_leaf,
                    charlie.account_public_key.as_slice(),
                    charlie.keypair.public(),
                )
            } else {
                (
                    alice_group
                        .create_application_message(&alice_provider, &alice, plaintext)
                        .map_err(js_error_to_string)
                        .unwrap(),
                    0,
                    alice.account_public_key.as_slice(),
                    alice.keypair.public(),
                )
            };
            let received = bob_group
                .receive_application_message(&bob_provider, &message)
                .map_err(js_error_to_string)
                .unwrap();
            assert_received(
                received,
                group_id,
                2,
                leaf,
                identity,
                signature_key,
                plaintext,
            );
        }

        let own_message = alice_group
            .create_application_message(&alice_provider, &alice, b"own echo")
            .map_err(js_error_to_string)
            .unwrap();
        assert_eq!(
            alice_group
                .receive_application_message_recovery(&alice_provider, &own_message)
                .unwrap_err(),
            "phase-b2 receive: own message rejected"
        );

        let old_charlie_message = charlie_group
            .create_application_message(
                &charlie_provider,
                &charlie,
                b"old Charlie leaf must never cross epochs",
            )
            .map_err(js_error_to_string)
            .unwrap();
        let stale_bob_snapshot = bob_provider.serialize_state();
        let stale_bob_provider = Provider::new();
        stale_bob_provider
            .restore_state(&stale_bob_snapshot)
            .map_err(js_error_to_string)
            .unwrap();
        let mut stale_bob_group = PhaseB2Group::load(&stale_bob_provider, group_id)
            .map_err(js_error_to_string)
            .unwrap()
            .unwrap();

        let mut self_update = alice_group
            .prepare_self_update(&alice_provider, &alice)
            .map_err(js_error_to_string)
            .unwrap();
        let self_projection = self_update.projection();
        let bob_before_public = bob_provider.serialize_state();
        assert_eq!(
            bob_group
                .receive_application_message_recovery(&bob_provider, &self_update.commit())
                .unwrap_err(),
            "phase-b2 receive: PrivateMessage application required"
        );
        assert_eq!(bob_before_public, bob_provider.serialize_state());
        let mut bob_staged_update = bob_group
            .stage_inbound_commit(&bob_provider, &self_update.commit())
            .map_err(js_error_to_string)
            .unwrap();
        bob_group
            .merge_staged_commit(
                &mut bob_provider,
                &mut bob_staged_update,
                &self_projection.verified_leaf_digest(),
            )
            .map_err(js_error_to_string)
            .unwrap();
        let mut charlie_staged_update = charlie_group
            .stage_inbound_commit(&charlie_provider, &self_update.commit())
            .map_err(js_error_to_string)
            .unwrap();
        charlie_group
            .merge_staged_commit(
                &mut charlie_provider,
                &mut charlie_staged_update,
                &self_projection.verified_leaf_digest(),
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

        let new_epoch_message = alice_group
            .create_application_message(&alice_provider, &alice, b"new epoch")
            .map_err(js_error_to_string)
            .unwrap();
        let stale_before = stale_bob_provider.serialize_state();
        assert_eq!(
            stale_bob_group
                .receive_application_message_recovery(&stale_bob_provider, &new_epoch_message)
                .unwrap_err(),
            "phase-b2 receive: current epoch required"
        );
        assert_eq!(stale_before, stale_bob_provider.serialize_state());
        let bob_before_old_epoch = bob_provider.serialize_state();
        assert_eq!(
            bob_group
                .receive_application_message_recovery(&bob_provider, &old_charlie_message)
                .unwrap_err(),
            "phase-b2 receive: current epoch required"
        );
        assert_eq!(bob_before_old_epoch, bob_provider.serialize_state());

        let mut remove_charlie = alice_group
            .prepare_remove(&alice_provider, &alice, charlie_leaf)
            .map_err(js_error_to_string)
            .unwrap();
        let remove_projection = remove_charlie.projection();
        let mut bob_staged_remove = bob_group
            .stage_inbound_commit(&bob_provider, &remove_charlie.commit())
            .map_err(js_error_to_string)
            .unwrap();
        bob_group
            .merge_staged_commit(
                &mut bob_provider,
                &mut bob_staged_remove,
                &remove_projection.verified_leaf_digest(),
            )
            .map_err(js_error_to_string)
            .unwrap();
        alice_group
            .confirm_pending(
                &mut alice_provider,
                &mut remove_charlie,
                &remove_projection.verified_leaf_digest(),
            )
            .map_err(js_error_to_string)
            .unwrap();

        let readd_key_package = charlie
            .key_package(&charlie_provider, &charlie_proof)
            .map_err(js_error_to_string)
            .unwrap();
        let mut readd_charlie = alice_group
            .prepare_add(&alice_provider, &alice, &readd_key_package)
            .map_err(js_error_to_string)
            .unwrap();
        let readd_projection = readd_charlie.projection();
        assert_eq!(
            readd_projection
                .proposal_added_leaf_index(0)
                .unwrap()
                .unwrap(),
            charlie_leaf,
            "test requires the removed leaf index to be reused"
        );
        let mut bob_staged_readd = bob_group
            .stage_inbound_commit(&bob_provider, &readd_charlie.commit())
            .map_err(js_error_to_string)
            .unwrap();
        bob_group
            .merge_staged_commit(
                &mut bob_provider,
                &mut bob_staged_readd,
                &readd_projection.verified_leaf_digest(),
            )
            .map_err(js_error_to_string)
            .unwrap();
        alice_group
            .confirm_pending(
                &mut alice_provider,
                &mut readd_charlie,
                &readd_projection.verified_leaf_digest(),
            )
            .map_err(js_error_to_string)
            .unwrap();
        let bob_before_reused_leaf = bob_provider.serialize_state();
        assert_eq!(
            bob_group
                .receive_application_message_recovery(&bob_provider, &old_charlie_message)
                .unwrap_err(),
            "phase-b2 receive: current epoch required"
        );
        assert_eq!(bob_before_reused_leaf, bob_provider.serialize_state());

        let replay_message = alice_group
            .create_application_message(&alice_provider, &alice, b"replay once")
            .map_err(js_error_to_string)
            .unwrap();
        assert_received(
            bob_group
                .receive_application_message(&bob_provider, &replay_message)
                .map_err(js_error_to_string)
                .unwrap(),
            group_id,
            alice_group.epoch(),
            0,
            &alice.account_public_key,
            alice.keypair.public(),
            b"replay once",
        );
        assert!(bob_group
            .receive_application_message_recovery(&bob_provider, &replay_message)
            .is_err());

        let tamper_message = alice_group
            .create_application_message(&alice_provider, &alice, b"tampered generation")
            .map_err(js_error_to_string)
            .unwrap();
        let mut tampered = tamper_message.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            bob_group
                .receive_application_message_recovery(&bob_provider, &tampered)
                .unwrap_err(),
            "phase-b2 receive: OpenMLS processing failed"
        );
        assert!(bob_group
            .receive_application_message_recovery(&bob_provider, &tamper_message)
            .is_err());
        let after_tamper_message = alice_group
            .create_application_message(&alice_provider, &alice, b"next generation remains live")
            .map_err(js_error_to_string)
            .unwrap();
        assert_received(
            bob_group
                .receive_application_message(&bob_provider, &after_tamper_message)
                .map_err(js_error_to_string)
                .unwrap(),
            group_id,
            alice_group.epoch(),
            0,
            &alice.account_public_key,
            alice.keypair.public(),
            b"next generation remains live",
        );

        let malformed_before = bob_provider.serialize_state();
        assert_eq!(
            bob_group
                .receive_application_message_recovery(&bob_provider, &[1, 2, 3])
                .unwrap_err(),
            "phase-b2 receive: malformed MLSMessage"
        );
        assert_eq!(malformed_before, bob_provider.serialize_state());
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
