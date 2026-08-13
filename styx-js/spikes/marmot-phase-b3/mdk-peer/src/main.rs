// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::BTreeSet;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use async_trait::async_trait;
use cgka_engine::account_identity_proof::{
    AccountIdentityProofRequest, AccountIdentityProofSigner,
};
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::EngineError;
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, KeyPackage, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{GroupId, MemberId, MessageId};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use storage_sqlite::{SqlCipherKey, SqliteAccountStorage};

const PROTOCOL: &str = "styx-b3-mdk-peer-jsonl-v1";
const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;
const MAX_HEX_BYTES: usize = 2 * 1024 * 1024;

#[derive(Default)]
struct DirectMlsPeeler;

fn message_id(bytes: &[u8], suffix: &[u8]) -> MessageId {
    let mut digest = Sha256::new();
    digest.update(b"styx-b3-direct-mls-message-v1");
    digest.update(bytes);
    digest.update(suffix);
    MessageId::new(digest.finalize().to_vec())
}

#[async_trait]
impl TransportPeeler for DirectMlsPeeler {
    async fn peel_group_message(
        &self,
        message: &TransportMessage,
        _context: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        Ok(PeeledMessage {
            id: message.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::MlsMessage {
                bytes: message.payload.clone(),
            },
            origin: message.clone(),
        })
    }

    async fn peel_welcome(&self, message: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        Ok(PeeledMessage {
            id: message.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::Welcome {
                bytes: message.payload.clone(),
            },
            origin: message.clone(),
        })
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        context: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        Ok(TransportMessage {
            id: message_id(&payload.ciphertext, b"group"),
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: Vec::new(),
            source: TransportSource("styx-b3-direct-mls".into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: context.transport_group_id().unwrap_or_default().to_vec(),
            },
        })
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        Ok(TransportMessage {
            id: message_id(&payload.ciphertext, recipient.as_slice()),
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: Vec::new(),
            source: TransportSource("styx-b3-direct-mls".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}

struct NodeProofSigner {
    account_identity: Vec<u8>,
    node_binary: PathBuf,
    signer_script: PathBuf,
    secret_path: PathBuf,
}

impl AccountIdentityProofSigner for NodeProofSigner {
    fn sign_account_identity_proof(
        &self,
        request: &AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        if request.account_identity != self.account_identity {
            return Err("account identity does not match the configured signer".into());
        }
        let event_id = request.proof_event_id()?;
        let output = Command::new(&self.node_binary)
            .arg(&self.signer_script)
            .arg("--sign-account-proof")
            .arg(&self.secret_path)
            .arg(hex::encode(event_id))
            .output()
            .map_err(|error| format!("launch external proof signer: {error}"))?;
        if !output.status.success() {
            return Err("external proof signer rejected the request".into());
        }
        let signature = hex::decode(
            std::str::from_utf8(&output.stdout)
                .map_err(|_| "external proof signer returned non-UTF-8 output")?
                .trim(),
        )
        .map_err(|_| "external proof signer returned non-hex output")?;
        signature
            .try_into()
            .map_err(|_| "external proof signer returned a non-64-byte signature".into())
    }
}

struct PeerState {
    engine: Option<Engine<SqliteAccountStorage>>,
    group_id: Option<GroupId>,
}

impl PeerState {
    fn new() -> Self {
        Self {
            engine: None,
            group_id: None,
        }
    }

    fn engine(&self) -> Result<&Engine<SqliteAccountStorage>, RpcError> {
        self.engine
            .as_ref()
            .ok_or_else(|| RpcError::state("peer is not initialized"))
    }

    fn engine_mut(&mut self) -> Result<&mut Engine<SqliteAccountStorage>, RpcError> {
        self.engine
            .as_mut()
            .ok_or_else(|| RpcError::state("peer is not initialized"))
    }
}

#[derive(Debug)]
struct RpcError {
    code: &'static str,
    message: String,
    details: Option<Value>,
}

impl RpcError {
    fn input(message: impl Into<String>) -> Self {
        Self {
            code: "invalid_request",
            message: message.into(),
            details: None,
        }
    }

    fn state(message: impl Into<String>) -> Self {
        Self {
            code: "invalid_state",
            message: message.into(),
            details: None,
        }
    }

    fn peer(message: impl Into<String>) -> Self {
        Self {
            code: "mdk_peer_error",
            message: message.into(),
            details: None,
        }
    }

    fn bounded(message: impl Into<String>) -> Self {
        Self {
            code: "bounded_nogo",
            message: message.into(),
            details: None,
        }
    }

    fn missing_capabilities(
        required: &cgka_traits::capabilities::GroupCapabilities,
        had: &cgka_traits::capabilities::GroupCapabilities,
    ) -> Self {
        let missing_app_components: Vec<u16> = required
            .app_components
            .ids
            .difference(&had.app_components.ids)
            .copied()
            .collect();
        Self {
            code: "mdk_missing_required_capabilities",
            message: format!("missing required capabilities: required={required:?} had={had:?}"),
            details: Some(json!({
                "had": {
                    "app_components": had.app_components.ids,
                    "extensions": had.extensions,
                    "proposals": had.proposals,
                },
                "missing_app_components": missing_app_components,
                "required": {
                    "app_components": required.app_components.ids,
                    "extensions": required.extensions,
                    "proposals": required.proposals,
                },
            })),
        }
    }
}

fn exact_fields(object: &Map<String, Value>, expected: &[&str]) -> Result<(), RpcError> {
    let actual: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let wanted: BTreeSet<&str> = expected.iter().copied().collect();
    if actual == wanted {
        Ok(())
    } else {
        Err(RpcError::input(format!(
            "unexpected fields: expected {wanted:?}, got {actual:?}"
        )))
    }
}

fn object(value: &Value) -> Result<&Map<String, Value>, RpcError> {
    value
        .as_object()
        .ok_or_else(|| RpcError::input("request must be a JSON object"))
}

fn string_field<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, RpcError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::input(format!("{field} must be a string")))
}

fn decode_hex_field(object: &Map<String, Value>, field: &str) -> Result<Vec<u8>, RpcError> {
    let encoded = string_field(object, field)?;
    if encoded.len() > MAX_HEX_BYTES * 2 || encoded.len() % 2 != 0 {
        return Err(RpcError::input(format!("{field} has an invalid length")));
    }
    hex::decode(encoded).map_err(|_| RpcError::input(format!("{field} must be lowercase hex")))
}

fn path_field(object: &Map<String, Value>, field: &str) -> Result<PathBuf, RpcError> {
    let path = PathBuf::from(string_field(object, field)?);
    if !path.is_absolute() {
        return Err(RpcError::input(format!("{field} must be absolute")));
    }
    Ok(path)
}

fn initialize(state: &mut PeerState, request: &Map<String, Value>) -> Result<Value, RpcError> {
    exact_fields(
        request,
        &[
            "account_identity_hex",
            "database_key_path",
            "database_path",
            "id",
            "node_binary",
            "op",
            "signer_script",
            "signer_secret_path",
        ],
    )?;
    if state.engine.is_some() {
        return Err(RpcError::state("peer is already initialized"));
    }
    let account_identity = decode_hex_field(request, "account_identity_hex")?;
    if account_identity.len() != 32 {
        return Err(RpcError::input("account_identity_hex must encode 32 bytes"));
    }
    let database_key_path = path_field(request, "database_key_path")?;
    let database_key = std::fs::read_to_string(database_key_path)
        .map_err(|error| RpcError::peer(format!("read database key: {error}")))?;
    let database_key = SqlCipherKey::new(database_key.trim().to_owned())
        .map_err(|error| RpcError::peer(format!("invalid database key: {error}")))?;
    let storage =
        SqliteAccountStorage::open_encrypted(path_field(request, "database_path")?, &database_key)
            .map_err(|error| RpcError::peer(format!("open durable storage: {error}")))?;
    let signer = NodeProofSigner {
        account_identity: account_identity.clone(),
        node_binary: path_field(request, "node_binary")?,
        signer_script: path_field(request, "signer_script")?,
        secret_path: path_field(request, "signer_secret_path")?,
    };
    let engine = EngineBuilder::new(storage)
        .identity(account_identity)
        .account_identity_proof_signer(Arc::new(signer))
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(DirectMlsPeeler))
        .build()
        .map_err(|error| RpcError::peer(format!("build current-profile engine: {error}")))?;
    state.engine = Some(engine);
    Ok(json!({"protocol_profile": "current"}))
}

async fn create_group(
    state: &mut PeerState,
    request: &Map<String, Value>,
) -> Result<Value, RpcError> {
    exact_fields(request, &["id", "key_package_hex", "op"])?;
    if state.group_id.is_some() {
        return Err(RpcError::state("group already exists in this process"));
    }
    let key_package = KeyPackage::new(decode_hex_field(request, "key_package_hex")?)
        .with_protocol_profile(ProtocolProfile::Current);
    let creation = state
        .engine_mut()?
        .create_group(CreateGroupRequest {
            name: "Styx B3 synthetic interop".into(),
            description: "Exact-pin direct-MLS evidence only".into(),
            members: vec![key_package],
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await;
    let (group_id, result) = match creation {
        Ok(created) => created,
        Err(EngineError::MissingRequiredCapabilities { required, had }) => {
            return Err(RpcError::missing_capabilities(&required, &had));
        }
        Err(error) => {
            return Err(RpcError::peer(format!(
                "create_group rejected Styx KeyPackage: {error}"
            )));
        }
    };
    let welcomes = match result {
        SendResult::FoundingGroupCreated { welcomes } => welcomes,
        other => {
            return Err(RpcError::peer(format!(
                "unexpected current-profile create disposition: {other:?}"
            )));
        }
    };
    if welcomes.len() != 1 {
        return Err(RpcError::peer(format!(
            "expected exactly one Welcome, got {}",
            welcomes.len()
        )));
    }
    let welcome = &welcomes[0];
    let projection = state
        .engine()?
        .conformance_group_snapshot(&group_id)
        .map_err(|error| RpcError::peer(format!("capture conformance projection: {error}")))?;
    state.group_id = Some(group_id.clone());
    Ok(json!({
        "group_id_hex": hex::encode(group_id.as_slice()),
        "welcome_hex": hex::encode(&welcome.payload),
        "welcome_message_id_hex": hex::encode(welcome.id.as_slice()),
        "welcome_sha256": hex::encode(Sha256::digest(&welcome.payload)),
        "ratchet_tree_delivery": "embedded_in_encrypted_group_info_only",
        "public_external_ratchet_tree_hex": Value::Null,
        "projection": projection,
    }))
}

fn confirm_published(
    state: &mut PeerState,
    request: &Map<String, Value>,
) -> Result<Value, RpcError> {
    exact_fields(request, &["id", "op", "welcome_message_id_hex"])?;
    let id = MessageId::new(decode_hex_field(request, "welcome_message_id_hex")?);
    state
        .engine()?
        .mark_sent_welcome_delivered(&id)
        .map_err(|error| RpcError::peer(format!("acknowledge Welcome delivery: {error}")))?;
    Ok(json!({"disposition": "welcome_delivery_processed"}))
}

fn public_projection(state: &PeerState, request: &Map<String, Value>) -> Result<Value, RpcError> {
    exact_fields(request, &["id", "op"])?;
    let group_id = state
        .group_id
        .as_ref()
        .ok_or_else(|| RpcError::state("group is not initialized"))?;
    let projection = state
        .engine()?
        .conformance_group_snapshot(group_id)
        .map_err(|error| RpcError::peer(format!("capture conformance projection: {error}")))?;
    serde_json::to_value(projection)
        .map_err(|error| RpcError::peer(format!("serialize conformance projection: {error}")))
}

fn unsupported_after_nogo(
    request: &Map<String, Value>,
    operation: &str,
) -> Result<Value, RpcError> {
    if !request.contains_key("id") || !request.contains_key("op") {
        return Err(RpcError::input("id and op are required"));
    }
    Err(RpcError::bounded(format!(
        "{operation} is unreachable after the first bounded incompatibility at Styx Welcome join"
    )))
}

async fn dispatch(state: &mut PeerState, value: &Value) -> Result<(Value, bool), RpcError> {
    let request = object(value)?;
    let operation = string_field(request, "op")?;
    let result = match operation {
        "hello" => {
            exact_fields(request, &["id", "op"])?;
            json!({
                "protocol": PROTOCOL,
                "mdk_revision": "9396adb6aa6b95b521a7979facd5ea7040c07288",
                "transport": "direct_mls_identity_wrapper",
            })
        }
        "initialize" => initialize(state, request)?,
        "create_group" => create_group(state, request).await?,
        "confirm_published" => confirm_published(state, request)?,
        "public_projection" => public_projection(state, request)?,
        "send_application" | "ingest_group_message" | "self_update" => {
            unsupported_after_nogo(request, operation)?
        }
        "checkpoint_and_exit" => {
            exact_fields(request, &["id", "op"])?;
            return Ok((json!({"checkpointed": true}), true));
        }
        "destroy" => {
            exact_fields(request, &["id", "op"])?;
            state.engine = None;
            state.group_id = None;
            json!({"destroyed": true})
        }
        _ => return Err(RpcError::input("unknown operation")),
    };
    Ok((result, false))
}

#[tokio::main]
async fn main() {
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    let mut state = PeerState::new();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) if line.len() <= MAX_LINE_BYTES => line,
            Ok(_) => {
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({"ok": false, "error": {"code": "request_too_large", "message": "request line exceeds the bound"}})
                );
                let _ = stdout.flush();
                continue;
            }
            Err(_) => break,
        };
        let parsed: Result<Value, _> = serde_json::from_str(&line);
        let id = parsed
            .as_ref()
            .ok()
            .and_then(Value::as_object)
            .and_then(|object| object.get("id"))
            .cloned()
            .unwrap_or(Value::Null);
        let (response, should_exit) = match parsed {
            Ok(value) => match dispatch(&mut state, &value).await {
                Ok((result, should_exit)) => {
                    (json!({"id": id, "ok": true, "result": result}), should_exit)
                }
                Err(error) => (
                    json!({"id": id, "ok": false, "error": {"code": error.code, "details": error.details, "message": error.message}}),
                    false,
                ),
            },
            Err(_) => (
                json!({"id": id, "ok": false, "error": {"code": "invalid_json", "message": "request is not valid JSON"}}),
                false,
            ),
        };
        if writeln!(stdout, "{response}").is_err() || stdout.flush().is_err() {
            break;
        }
        if should_exit {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_ids_are_domain_separated() {
        assert_ne!(message_id(b"same", b"group"), message_id(b"same", b"peer"));
    }

    #[test]
    fn exact_fields_rejects_extras() {
        let value = json!({"id": 1, "op": "hello", "extra": true});
        assert!(exact_fields(object(&value).unwrap(), &["id", "op"]).is_err());
    }
}
