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
use cgka_traits::app_event::MarmotAppEvent;
use cgka_traits::engine::{
    CgkaEngine, CreateGroupRequest, GroupEvent, KeyPackage, SendIntent, SendResult,
};
use cgka_traits::error::PeelerError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{IngestOutcome, InputRejectionCategory, PeeledContent, PeeledMessage};
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
const MAX_GROUP_ID_BYTES: usize = 64;
const MAX_APPLICATION_EVENT_BYTES: usize = 320 * 1024;
const MAX_GROUP_MESSAGE_BYTES: usize = 1024 * 1024;

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
    terminate: bool,
}

impl RpcError {
    fn input(message: impl Into<String>) -> Self {
        Self {
            code: "invalid_request",
            message: message.into(),
            details: None,
            terminate: false,
        }
    }

    fn state(message: impl Into<String>) -> Self {
        Self {
            code: "invalid_state",
            message: message.into(),
            details: None,
            terminate: false,
        }
    }

    fn peer(message: impl Into<String>) -> Self {
        Self {
            code: "mdk_peer_error",
            message: message.into(),
            details: None,
            terminate: false,
        }
    }

    fn fatal_peer(message: impl Into<String>) -> Self {
        Self {
            code: "mdk_peer_quarantined",
            message: message.into(),
            details: None,
            terminate: true,
        }
    }

    fn bounded(message: impl Into<String>) -> Self {
        Self {
            code: "bounded_nogo",
            message: message.into(),
            details: None,
            terminate: false,
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
            terminate: false,
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
    if !encoded
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RpcError::input(format!("{field} must be lowercase hex")));
    }
    hex::decode(encoded).map_err(|_| RpcError::input(format!("{field} must be lowercase hex")))
}

fn decode_bounded_hex_field(
    object: &Map<String, Value>,
    field: &str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RpcError> {
    let decoded = decode_hex_field(object, field)?;
    if decoded.is_empty() || decoded.len() > maximum_bytes {
        return Err(RpcError::input(format!(
            "{field} is outside its resource envelope"
        )));
    }
    Ok(decoded)
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
    let mut engine = EngineBuilder::new(storage)
        .identity(account_identity)
        .account_identity_proof_signer(Arc::new(signer))
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(DirectMlsPeeler))
        .build()
        .map_err(|error| RpcError::peer(format!("build current-profile engine: {error}")))?;
    engine
        .hydrate_all_stored_groups()
        .map_err(|error| RpcError::peer(format!("hydrate durable groups: {error}")))?;
    if !engine.quarantined_groups().is_empty() {
        return Err(RpcError::fatal_peer(
            "one or more durable groups were quarantined during hydration",
        ));
    }
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
    let creation_events = state.engine_mut()?.drain_events();
    if creation_events.iter().any(|event| {
        !matches!(event, GroupEvent::GroupCreated { group_id: event_group_id }
            if event_group_id == &group_id)
    }) {
        state.engine = None;
        return Err(RpcError::fatal_peer(
            "group creation emitted an unexpected application-visible event",
        ));
    }
    state.group_id = Some(group_id.clone());
    Ok(json!({
        "creation_event_count": creation_events.len(),
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

fn restore_group(state: &mut PeerState, request: &Map<String, Value>) -> Result<Value, RpcError> {
    exact_fields(request, &["group_id_hex", "id", "op"])?;
    if state.group_id.is_some() {
        return Err(RpcError::state("group is already selected in this process"));
    }
    let group_id = GroupId::new(decode_bounded_hex_field(
        request,
        "group_id_hex",
        MAX_GROUP_ID_BYTES,
    )?);
    let projection = state
        .engine()?
        .conformance_group_snapshot(&group_id)
        .map_err(|error| RpcError::peer(format!("restore durable group projection: {error}")))?;
    let hydration_events = state.engine_mut()?.drain_events();
    if !hydration_events.is_empty() {
        state.engine = None;
        return Err(RpcError::fatal_peer(
            "durable group restoration produced pending application-visible events",
        ));
    }
    state.group_id = Some(group_id);
    Ok(json!({
        "disposition": "durable_group_restored",
        "projection": projection,
    }))
}

async fn send_application(
    state: &mut PeerState,
    request: &Map<String, Value>,
) -> Result<Value, RpcError> {
    exact_fields(request, &["id", "op", "payload_hex"])?;
    let group_id = state
        .group_id
        .clone()
        .ok_or_else(|| RpcError::state("group is not initialized"))?;
    let payload = decode_bounded_hex_field(request, "payload_hex", MAX_APPLICATION_EVENT_BYTES)?;
    MarmotAppEvent::decode(&payload)
        .map_err(|error| RpcError::input(format!("invalid Marmot application event: {error}")))?;
    let result = match state
        .engine_mut()?
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload,
        })
        .await
    {
        Ok(result) => result,
        Err(error) => {
            state.engine = None;
            state.group_id = None;
            return Err(RpcError::fatal_peer(format!(
                "application send failed after entering the MDK mutation boundary: {error}"
            )));
        }
    };
    let unexpected_events = state.engine_mut()?.drain_events();
    if !unexpected_events.is_empty() {
        state.engine = None;
        state.group_id = None;
        return Err(RpcError::fatal_peer(
            "application send produced unexpected application-visible events",
        ));
    }
    match result {
        SendResult::ApplicationMessage {
            msg,
            group_id: result_group_id,
            app_event_id,
            source_epoch,
            retention,
        } if result_group_id == group_id => Ok(json!({
            "app_event_id_hex": app_event_id,
            "disposition": "application_message_durably_prepared",
            "group_id_hex": hex::encode(result_group_id.as_slice()),
            "group_message_hex": hex::encode(&msg.payload),
            "message_id_hex": hex::encode(msg.id.as_slice()),
            "retention": retention,
            "source_epoch": source_epoch,
        })),
        SendResult::ApplicationMessage { .. } => {
            state.engine = None;
            state.group_id = None;
            Err(RpcError::fatal_peer(
                "application send returned ciphertext for a different group",
            ))
        }
        SendResult::Queued { .. } => Err(RpcError::bounded(
            "application send was convergence-queued outside the B3.3a stable-group claim",
        )),
        other => Err(RpcError::bounded(format!(
            "application send returned a non-application disposition: {other:?}"
        ))),
    }
}

async fn ingest_group_message(
    state: &mut PeerState,
    request: &Map<String, Value>,
) -> Result<Value, RpcError> {
    exact_fields(request, &["group_message_hex", "id", "op"])?;
    let group_id = state
        .group_id
        .clone()
        .ok_or_else(|| RpcError::state("group is not initialized"))?;
    let payload = decode_bounded_hex_field(request, "group_message_hex", MAX_GROUP_MESSAGE_BYTES)?;
    let transport = TransportMessage {
        id: message_id(&payload, b"group"),
        payload,
        timestamp: Timestamp(0),
        causal_deps: Vec::new(),
        source: TransportSource("styx-b3-direct-mls".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    };
    let transport_message_id_hex = hex::encode(transport.id.as_slice());
    let outcome = match state.engine_mut()?.ingest(transport).await {
        Ok(outcome) => outcome,
        Err(error) => {
            state.engine = None;
            state.group_id = None;
            return Err(RpcError::fatal_peer(format!(
                "group-message ingest failed after entering the MDK mutation boundary: {error}"
            )));
        }
    };
    let events = state.engine_mut()?.drain_events();
    match outcome {
        IngestOutcome::Processed => match events.as_slice() {
            [
                GroupEvent::MessageReceived {
                    group_id: event_group_id,
                    sender,
                    epoch,
                    payload,
                    retention,
                },
            ] if event_group_id == &group_id => {
                let sender_identity_hex = hex::encode(sender.as_slice());
                let app_event = MarmotAppEvent::decode(payload).map_err(|error| {
                    RpcError::fatal_peer(format!(
                        "MDK released a malformed application event: {error}"
                    ))
                })?;
                app_event
                    .validate_sender(&sender_identity_hex)
                    .map_err(|error| {
                        RpcError::fatal_peer(format!(
                            "MDK application event broke authenticated sender binding: {error}"
                        ))
                    })?;
                Ok(json!({
                    "app_event_id_hex": app_event.id,
                    "disposition": "application_message_processed",
                    "epoch": epoch,
                    "group_id_hex": hex::encode(event_group_id.as_slice()),
                    "message_id_hex": transport_message_id_hex,
                    "payload_hex": hex::encode(payload),
                    "retention": retention,
                    "sender_identity_hex": sender_identity_hex,
                }))
            }
            _ => {
                state.engine = None;
                state.group_id = None;
                Err(RpcError::fatal_peer(
                    "processed application ingest did not emit exactly one matching message",
                ))
            }
        },
        IngestOutcome::Ignored { category }
            if matches!(
                category,
                InputRejectionCategory::Duplicate | InputRejectionCategory::OwnEcho
            ) =>
        {
            if !events.is_empty() {
                state.engine = None;
                state.group_id = None;
                return Err(RpcError::fatal_peer(
                    "duplicate or own-echo ingest unexpectedly released events",
                ));
            }
            Ok(json!({
                "disposition": match category {
                    InputRejectionCategory::Duplicate => "duplicate",
                    InputRejectionCategory::OwnEcho => "own_echo",
                    _ => unreachable!(),
                },
                "message_id_hex": transport_message_id_hex,
            }))
        }
        other => {
            if !events.is_empty() {
                state.engine = None;
                state.group_id = None;
                return Err(RpcError::fatal_peer(
                    "non-processed ingest unexpectedly released events",
                ));
            }
            Err(RpcError {
                code: "bounded_nogo",
                message: "group message did not reach the exact B3.3a application outcome".into(),
                details: serde_json::to_value(other).ok(),
                terminate: false,
            })
        }
    }
}

fn unsupported_in_b33a(request: &Map<String, Value>, operation: &str) -> Result<Value, RpcError> {
    if !request.contains_key("id") || !request.contains_key("op") {
        return Err(RpcError::input("id and op are required"));
    }
    Err(RpcError::bounded(format!(
        "{operation} is intentionally outside the B3.3a application-traffic boundary"
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
        "restore_group" => restore_group(state, request)?,
        "send_application" => send_application(state, request).await?,
        "ingest_group_message" => ingest_group_message(state, request).await?,
        "self_update" => unsupported_in_b33a(request, operation)?,
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
                Err(error) => {
                    let terminate = error.terminate;
                    (
                        json!({"id": id, "ok": false, "error": {"code": error.code, "details": error.details, "message": error.message}}),
                        terminate,
                    )
                }
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

    #[test]
    fn hex_fields_require_canonical_lowercase_encoding() {
        let uppercase = json!({"payload_hex": "AB"});
        let error = decode_hex_field(object(&uppercase).unwrap(), "payload_hex").unwrap_err();
        assert_eq!(error.code, "invalid_request");
        assert!(!error.terminate);

        let lowercase = json!({"payload_hex": "ab"});
        assert_eq!(
            decode_hex_field(object(&lowercase).unwrap(), "payload_hex").unwrap(),
            vec![0xab]
        );
    }

    #[test]
    fn bounded_hex_fields_reject_empty_and_oversized_values() {
        let empty = json!({"payload_hex": ""});
        assert!(decode_bounded_hex_field(object(&empty).unwrap(), "payload_hex", 1).is_err());

        let oversized = json!({"payload_hex": "0001"});
        assert!(decode_bounded_hex_field(object(&oversized).unwrap(), "payload_hex", 1).is_err());

        let exact = json!({"payload_hex": "00"});
        assert_eq!(
            decode_bounded_hex_field(object(&exact).unwrap(), "payload_hex", 1).unwrap(),
            vec![0]
        );
    }

    #[test]
    fn fatal_peer_errors_quarantine_the_process() {
        let error = RpcError::fatal_peer("synthetic fatal mutation failure");
        assert_eq!(error.code, "mdk_peer_quarantined");
        assert!(error.terminate);
    }
}
