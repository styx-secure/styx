# M2 internal session adapter API contract

Status: normative candidate for the exact M2 profile. Dependent implementation is blocked until the owner ratifies the SHA-256 of this exact file.

## 1. Scope and boundaries

This is the closed, versioned, data-only internal API between application (`AP`), secure session (`SS`) and durable record store (`RS`). `TR` is absent. **MUST**, **MUST NOT**, **REJECT** and **UNSUPPORTED** are normative.

Application bytes are opaque. Session membership, decryption or possession never proves application identity, role, authorization, causality, freshness or business truth. No value denotes transport publication, delivery, receipt, order or retry.

The contract defines logical types and transitions, not persisted bytes, HKDF labels, key versions, AAD encoding, physical layout, migration or implementation structure. Later contracts own those choices but MUST NOT add an API operation or disposition without a new hash-ratified C-API contract.

## 2. Exact profile

| Field | Exact value |
| --- | --- |
| `adapterApi` | `styx-m2-session-adapter/v1` |
| `bindingVersion` | `m2-opaque-binding/v0` |
| `logicalAdapter` | `session` |
| `physicalStore` | `mls` |
| `stage` | `test-profile` |
| `topology` | `two-member-direct` |
| `openMlsRevision` | `09e92777dba0528d3d29e2e5e681b7e91637c7be` |
| `wasmArtifactPath` | `styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm` |
| `wasmArtifactSha256` | `fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e` |
| `ciphersuiteIanaId` | `0x0001` |
| `ciphersuiteName` | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` |
| `ss0DecisionsSha256` | `235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07` |
| `pastEpochWindow` | `5` |

Every field is required. Unknown/missing fields or values, tuple/version/topology/stage drift, and legacy shipping-envelope state fail closed before mutation. There is no negotiation, downgrade or fallback. The ciphersuite fields identify the SS-0 evidenced suite; they do not assert which suite is compiled into the frozen WASM artifact. F-WASM owns that determination.

## 3. Ownership

| Layer | Responsibility | Prohibition |
| --- | --- | --- |
| `AP` | Opaque request/output bytes and application authorization. | Cannot assert RS outcomes or SS-authenticated facts. |
| `SS` | Exact-profile validation, authentication, staging and session transitions. | In-memory state, ciphertext or local optimism is not durable truth. |
| `RS` | Authenticated durable commit, restore and reconciliation evidence. | Deserialization or storage presence is not freshness. |
| `TR` | Absent. | No API result means delivery or receipt. |

Every state-gate and decision row repeats AP/SS/RS/absent-TR ownership and its persistence obligation. One complete logical mutation contains the session transition, binding metadata, replay/retention state and authenticated manifest. It is indivisible and authoritative only after `COMMITTED`.

AP supplies only fields marked `AP_*` in section 10. SS derives authenticated epoch, replay identity, proposal shape, committer identity, candidates and witness facts. RS supplies restore bytes and commit/reconciliation outcomes. A contradiction in authenticated material is never resolved from an AP assertion.

## 4. Closed data model

All objects are closed maps. Unspecified fields and enum values are rejected. Bounded-byte limits are selected later; over-limit values reject rather than truncate.

States are `EMPTY`, `ACTIVE` and `RECONCILIATION_REQUIRED`. `ACTIVE` means exactly one authoritative M2 session. Reconciliation retains the original state and held mutation internally; it is not an authoritative mutation. Restored decoded bytes are internal transient input and never a public state.

The operation set is `CREATE`, `RESTORE`, `JOIN_WELCOME`, `PROTECT_APPLICATION`, `OPEN_APPLICATION`, `SELF_UPDATE`, `APPLY_PEER_UPDATE`, `RECONCILE_INDETERMINATE`. Any other operation, including every Issue #312-affected operation, is `UNSUPPORTED_OPERATION` before mutation.

The complete operation × state matrix is normative in section 10. `ALLOW` continues to the operation table; every other matrix disposition rejects without mutation.

Result kinds are disjoint:

| Kind | Meaning |
| --- | --- |
| `SUCCESS` | Named success; a staged mutation was first `COMMITTED`. |
| `NO_CHANGE` | Exact in-window duplicate; no plaintext and no transition. |
| `NOT_COMMITTED` | RS proves absence; restore `originalStateBefore`; no output. |
| `INDETERMINATE` | Unknown result; retain original state and held mutation; reconcile only. |
| `REJECTED` | Stable value-free error; state unchanged and no output. |

Section 10 closes code-to-kind mapping and the value-free error shape. Error details never contain secrets/plaintext, stable group ids, paths, host/user identity, timing, evidence identity or arbitrary upstream text. An unknown internal cause strictly before any RS commit request is `FAIL_CLOSED_INTERNAL`; once a commit request may have reached RS, an absent/failed/unknown outcome is `INDETERMINATE`, never `REJECTED`.

## 5. Commit and reconciliation

For `RS_TRI_STATE`, SS stages one complete logical mutation and requests exactly one RS outcome. `COMMITTED` applies it once and emits success; interrupted response emission retains reconciliation evidence and never changes that commit into `REJECTED`. `NOT_COMMITTED` discards it, restores `originalStateBefore` and emits no operation output. Every missing, failed or unknown outcome after the request is `INDETERMINATE`: it retains the original state plus held mutation internally, applies nothing, enters `RECONCILIATION_REQUIRED`, emits an opaque reference and forbids blind retry.

The indeterminate response carries `originalStateBefore`. Reconciliation obtains the outcome from RS; AP cannot supply it. Proven commit applies the held transition once and releases held output. Proven absence restores `EMPTY` or `ACTIVE` according to the original state. Continued uncertainty stays blocked.

## 6. Operations

`CREATE` authenticates a peer framed non-last-resort KeyPackage, commits the founder session and emits an opaque embedded-tree Welcome only after commit. `JOIN_WELCOME` uses an SS/RS-owned unconsumed local KeyPackage reference and AP-supplied opaque Welcome; consumption and joined state commit together. C-BIND owns local KeyPackage issuance at the SS bootstrap boundary. Unsupported or unmatched onboarding rejects before mutation.

`RESTORE` classifies the complete stored set into four mutually exclusive cases: no session material; only legacy or tuple/version-drifted session records; exactly one exact-profile M2 candidate with no additional nonlegacy candidate; or multiple/mixed nonlegacy candidates. Preserved legacy bytes beside exactly one exact-profile candidate are ignored and never make it incompatible. SS/RS then synchronously perform authentication, complete-record, binding, version and tuple revalidation. Only full success returns `ACTIVE`; decoded bytes never become authoritative. Authenticated inconsistency, including multiple/mixed nonlegacy candidates or coarse-anchor regression, differs from authentication failure. Coherent whole-profile rollback may remain invisible.

`PROTECT_APPLICATION`/`OPEN_APPLICATION` carry opaque bytes. SS structurally classifies the bounded framing epoch without trusting content: current through current-5 continue, while distance 6+ and future epochs reject. Eligible framing then undergoes key-dependent authentication and replay lookup. Exact duplicate identity emits no duplicate plaintext and makes no second transition.

`SELF_UPDATE` creates an ordinary proposal-free local update and emits opaque protected Commit bytes only after commit. `APPLY_PEER_UPDATE` consumes one opaque incoming Commit. A current-parent ordinary update applies normally. Selection is available only when the incoming candidate shares the parent of the immediately preceding authoritative local self-update committed through `CAPI-S014` and the two authenticated raw 32-byte committer identities are distinct. The lower identity wins, selected complete state commits, and the valid loser remains non-authoritative retained evidence. Equal-committer pairs, re-presented candidates, peer-predecessor pairs, proposals, unrelated parents and every other topology reject before mutation. Application data, digest, arrival, time and transport never select.

## 7. Complete tables

Section 10 is canonical. `stateMatrix` covers every operation/state pair. `errorDefinitions` close each value-free error and applicability condition; each error row has a stable `CAPI-E` scenario id. `decisionRows` are mutually exclusive within each allowed operation/state; each has ownership, precedence, persistence, transition, result kind and stable scenario id. No wildcard row exists.

## 8. Total precedence

Levels `P01` through `P10` are highest-first. All 45 ordered level pairs and all ordered within-level error pairs have stable scenario ids. Every error belongs to exactly one level. Bounds are P06; untrusted structural epoch-window rejection is P07; key-dependent authentication is P08; authenticated operation support and replay are P09. Applicable errors always preempt success/no-change rows.

## 9. Non-claims and gates

No application semantics/authority, transport delivery, legacy import/cleanup, Issue #312 extension, whole-profile rollback prevention, remote freshness, physical deletion, zeroization, general forward secrecy, arbitrary retention, general groups/convergence, public SDK, production activation or general Marmot compatibility is claimed.

The adapter remains internal and unsupported by this document. Binding bytes, mutation/storage tables, restore/retention/recovery contracts, formats, HKDF labels/key versions and independent scenarios remain separately owner-gated.

## 10. Machine-readable normative record

The JSON below is normative and closed. Prose clarifies but does not widen it.

<!-- styx-m2-adapter-contract-json:v1:start -->
```json
{
  "schema": "styx-m2-session-adapter-contract/v1",
  "status": "owner-ratification-required-before-dependent-implementation",
  "closed": true,
  "profile": {
    "adapterApi": "styx-m2-session-adapter/v1",
    "bindingVersion": "m2-opaque-binding/v0",
    "logicalAdapter": "session",
    "physicalStore": "mls",
    "stage": "test-profile",
    "topology": "two-member-direct",
    "openMlsRevision": "09e92777dba0528d3d29e2e5e681b7e91637c7be",
    "wasmArtifactPath": "styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm",
    "wasmArtifactSha256": "fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e",
    "ciphersuiteIanaId": "0x0001",
    "ciphersuiteName": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
    "ss0DecisionsSha256": "235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07",
    "pastEpochWindow": 5
  },
  "owners": {
    "AP": "opaque request/output and application authorization only",
    "SS": "exact-profile validation, authentication, staging and session transition",
    "RS": "authenticated durable commit, restore and reconciliation evidence",
    "TR": "ABSENT"
  },
  "stateEnum": [
    "EMPTY",
    "ACTIVE",
    "RECONCILIATION_REQUIRED"
  ],
  "operationEnum": [
    "CREATE",
    "RESTORE",
    "JOIN_WELCOME",
    "PROTECT_APPLICATION",
    "OPEN_APPLICATION",
    "SELF_UPDATE",
    "APPLY_PEER_UPDATE",
    "RECONCILE_INDETERMINATE"
  ],
  "commitOutcomeEnum": [
    "COMMITTED",
    "NOT_COMMITTED",
    "INDETERMINATE"
  ],
  "resultKindEnum": [
    "SUCCESS",
    "NO_CHANGE",
    "NOT_COMMITTED",
    "INDETERMINATE",
    "REJECTED"
  ],
  "successCodeEnum": [
    "CREATED",
    "RESTORED",
    "JOINED",
    "APPLICATION_PROTECTED",
    "APPLICATION_OPENED",
    "SELF_UPDATED",
    "PEER_UPDATE_APPLIED",
    "CANDIDATE_SELECTED",
    "RECONCILED_COMMITTED",
    "DUPLICATE_IGNORED"
  ],
  "errorCodeEnum": [
    "UNKNOWN_FIELD",
    "INVALID_REQUEST",
    "UNKNOWN_VALUE",
    "UNSUPPORTED_API_VERSION",
    "UNSUPPORTED_PROFILE",
    "BINDING_MISMATCH",
    "UNSUPPORTED_OPERATION",
    "SESSION_ALREADY_EXISTS",
    "NO_ACTIVE_SESSION",
    "NO_STORED_SESSION",
    "STORED_SESSION_INCOMPATIBLE",
    "RECONCILIATION_REQUIRED",
    "NO_RECONCILIATION_PENDING",
    "RECONCILIATION_REFERENCE_MISMATCH",
    "UNSUPPORTED_ONBOARDING",
    "WELCOME_NO_MATCHING_KEY_PACKAGE",
    "UNSUPPORTED_UPDATE_FORM",
    "UNSUPPORTED_COMMIT_SHAPE",
    "KEY_PACKAGE_ALREADY_CONSUMED",
    "AUTHENTICATION_FAILED",
    "AUTHENTICATED_STATE_INCONSISTENT",
    "EPOCH_OUTSIDE_RETAINED_WINDOW",
    "FUTURE_EPOCH",
    "VALUE_OUT_OF_RANGE",
    "FAIL_CLOSED_INTERNAL"
  ],
  "codeToResultKind": {
    "CREATED": "SUCCESS",
    "RESTORED": "SUCCESS",
    "JOINED": "SUCCESS",
    "APPLICATION_PROTECTED": "SUCCESS",
    "APPLICATION_OPENED": "SUCCESS",
    "SELF_UPDATED": "SUCCESS",
    "PEER_UPDATE_APPLIED": "SUCCESS",
    "CANDIDATE_SELECTED": "SUCCESS",
    "RECONCILED_COMMITTED": "SUCCESS",
    "DUPLICATE_IGNORED": "NO_CHANGE",
    "UNKNOWN_FIELD": "REJECTED",
    "INVALID_REQUEST": "REJECTED",
    "UNKNOWN_VALUE": "REJECTED",
    "UNSUPPORTED_API_VERSION": "REJECTED",
    "UNSUPPORTED_PROFILE": "REJECTED",
    "BINDING_MISMATCH": "REJECTED",
    "UNSUPPORTED_OPERATION": "REJECTED",
    "SESSION_ALREADY_EXISTS": "REJECTED",
    "NO_ACTIVE_SESSION": "REJECTED",
    "NO_STORED_SESSION": "REJECTED",
    "STORED_SESSION_INCOMPATIBLE": "REJECTED",
    "RECONCILIATION_REQUIRED": "REJECTED",
    "NO_RECONCILIATION_PENDING": "REJECTED",
    "RECONCILIATION_REFERENCE_MISMATCH": "REJECTED",
    "UNSUPPORTED_ONBOARDING": "REJECTED",
    "WELCOME_NO_MATCHING_KEY_PACKAGE": "REJECTED",
    "UNSUPPORTED_UPDATE_FORM": "REJECTED",
    "UNSUPPORTED_COMMIT_SHAPE": "REJECTED",
    "KEY_PACKAGE_ALREADY_CONSUMED": "REJECTED",
    "AUTHENTICATION_FAILED": "REJECTED",
    "AUTHENTICATED_STATE_INCONSISTENT": "REJECTED",
    "EPOCH_OUTSIDE_RETAINED_WINDOW": "REJECTED",
    "FUTURE_EPOCH": "REJECTED",
    "VALUE_OUT_OF_RANGE": "REJECTED",
    "FAIL_CLOSED_INTERNAL": "REJECTED",
    "NOT_COMMITTED": "NOT_COMMITTED",
    "INDETERMINATE": "INDETERMINATE"
  },
  "request": {
    "commonRequired": [
      "api",
      "operation",
      "requestId",
      "profile",
      "bindingRef",
      "input"
    ],
    "commonOptional": [],
    "fieldSources": {
      "api": "AP_COPY_OF_CONSTANT_VALIDATED_BY_SS",
      "operation": "AP",
      "requestId": "AP_CORRELATION_ONLY",
      "profile": "AP_COPY_OF_CONSTANT_VALIDATED_BY_SS",
      "bindingRef": "AP_OPAQUE_REFERENCE_VALIDATED_BY_SS",
      "input": "PER_OPERATION_BELOW"
    },
    "inputByOperation": {
      "CREATE": {
        "peerFramedKeyPackage": "AP_OPAQUE_BYTES"
      },
      "RESTORE": {},
      "JOIN_WELCOME": {
        "embeddedTreeWelcome": "AP_OPAQUE_BYTES"
      },
      "PROTECT_APPLICATION": {
        "applicationBytes": "AP_OPAQUE_BYTES"
      },
      "OPEN_APPLICATION": {
        "protectedApplicationMessage": "AP_OPAQUE_BYTES"
      },
      "SELF_UPDATE": {},
      "APPLY_PEER_UPDATE": {
        "protectedCommitBytes": "AP_OPAQUE_BYTES"
      },
      "RECONCILE_INDETERMINATE": {
        "reconciliationRef": "AP_OPAQUE_VALUE_PREVIOUSLY_EMITTED_BY_SS"
      }
    },
    "derivedByOperation": {
      "CREATE": [
        "memberIdentity",
        "peerIdentity",
        "proposalFree",
        "profileFacts"
      ],
      "RESTORE": [
        "restoredLogicalSession from RS",
        "profileFacts",
        "bindingFacts"
      ],
      "JOIN_WELCOME": [
        "framedKeyPackageRef from SS/RS",
        "memberIdentity",
        "peerIdentity",
        "profileFacts"
      ],
      "PROTECT_APPLICATION": [
        "session ratchet mutation"
      ],
      "OPEN_APPLICATION": [
        "messageEpoch",
        "replayIdentity",
        "authenticationFacts"
      ],
      "SELF_UPDATE": [
        "proposalFree",
        "committerIdentity",
        "protectedCommitBytes"
      ],
      "APPLY_PEER_UPDATE": [
        "proposalFree",
        "committerIdentity",
        "authenticationFacts",
        "parentStateRef",
        "immediately preceding eligible candidate",
        "witness and priority facts"
      ],
      "RECONCILE_INDETERMINATE": [
        "rsCommitOutcome from RS",
        "originalStateBefore from held SS state"
      ]
    },
    "closedObjects": true
  },
  "response": {
    "commonRequired": [
      "api",
      "requestId",
      "operation",
      "kind",
      "stateBefore",
      "stateAfter"
    ],
    "byKind": {
      "SUCCESS": {
        "required": [
          "successCode"
        ],
        "optional": [
          "output",
          "commitOutcome"
        ],
        "allowedCodes": [
          "CREATED",
          "RESTORED",
          "JOINED",
          "APPLICATION_PROTECTED",
          "APPLICATION_OPENED",
          "SELF_UPDATED",
          "PEER_UPDATE_APPLIED",
          "CANDIDATE_SELECTED",
          "RECONCILED_COMMITTED"
        ],
        "commitOutcomeIfPresent": "COMMITTED"
      },
      "NO_CHANGE": {
        "required": [
          "successCode"
        ],
        "optional": [],
        "allowedCodes": [
          "DUPLICATE_IGNORED"
        ]
      },
      "NOT_COMMITTED": {
        "required": [
          "commitOutcome"
        ],
        "optional": [],
        "commitOutcome": "NOT_COMMITTED"
      },
      "INDETERMINATE": {
        "required": [
          "commitOutcome",
          "reconciliationRef",
          "originalStateBefore"
        ],
        "optional": [],
        "commitOutcome": "INDETERMINATE"
      },
      "REJECTED": {
        "required": [
          "error"
        ],
        "optional": [],
        "allowedCodes": [
          "UNKNOWN_FIELD",
          "INVALID_REQUEST",
          "UNKNOWN_VALUE",
          "UNSUPPORTED_API_VERSION",
          "UNSUPPORTED_PROFILE",
          "BINDING_MISMATCH",
          "UNSUPPORTED_OPERATION",
          "SESSION_ALREADY_EXISTS",
          "NO_ACTIVE_SESSION",
          "NO_STORED_SESSION",
          "STORED_SESSION_INCOMPATIBLE",
          "RECONCILIATION_REQUIRED",
          "NO_RECONCILIATION_PENDING",
          "RECONCILIATION_REFERENCE_MISMATCH",
          "UNSUPPORTED_ONBOARDING",
          "WELCOME_NO_MATCHING_KEY_PACKAGE",
          "UNSUPPORTED_UPDATE_FORM",
          "UNSUPPORTED_COMMIT_SHAPE",
          "KEY_PACKAGE_ALREADY_CONSUMED",
          "AUTHENTICATION_FAILED",
          "AUTHENTICATED_STATE_INCONSISTENT",
          "EPOCH_OUTSIDE_RETAINED_WINDOW",
          "FUTURE_EPOCH",
          "VALUE_OUT_OF_RANGE",
          "FAIL_CLOSED_INTERNAL"
        ],
        "valueFree": true
      }
    },
    "outputBySuccessCode": {
      "CREATED": [
        "embeddedTreeWelcome"
      ],
      "RESTORED": [],
      "JOINED": [],
      "APPLICATION_PROTECTED": [
        "protectedApplicationBytes"
      ],
      "APPLICATION_OPENED": [
        "applicationBytes"
      ],
      "SELF_UPDATED": [
        "protectedCommitBytes"
      ],
      "PEER_UPDATE_APPLIED": [],
      "CANDIDATE_SELECTED": [
        "selectedCandidateRef"
      ],
      "RECONCILED_COMMITTED": [
        "originalSuccessCode",
        "originalOutput"
      ],
      "DUPLICATE_IGNORED": []
    },
    "valueDomains": {
      "originalStateBefore": [
        "EMPTY",
        "ACTIVE"
      ]
    },
    "errorShape": {
      "required": [
        "code"
      ],
      "optional": [
        "detailTag"
      ],
      "detailTagEnum": [
        "FIELD",
        "PROFILE",
        "BINDING",
        "STATE",
        "AUTH",
        "EPOCH",
        "ONBOARDING",
        "UPDATE",
        "COMMIT",
        "INTERNAL"
      ],
      "valueFree": true
    },
    "closedObjects": true
  },
  "rules": {
    "closedObjects": "unknown fields and values reject before mutation",
    "tupleDrift": "UNSUPPORTED_PROFILE before mutation; no negotiation or fallback",
    "bindingMismatch": "AP originates bindingRef from its opaque application context; SS compares it with the session binding established by C-BIND; mismatch is BINDING_MISMATCH before mutation and never authority by itself",
    "derivedFacts": "AP cannot supply RS commit outcomes, epochs, replay identities, proposal shape, committer identities, candidates, witness facts or authenticated profile facts",
    "rsTriState": {
      "COMMITTED": "apply the complete staged logical mutation once and emit SUCCESS; if response emission is interrupted, retain reconciliation evidence and never report REJECTED",
      "NOT_COMMITTED": "discard the staged mutation, restore originalStateBefore and emit NOT_COMMITTED without output",
      "INDETERMINATE": "includes every absent, failed or unknown RS outcome after a commit request; retain originalStateBefore and held mutation internally, apply nothing, enter RECONCILIATION_REQUIRED, emit no operation output and forbid blind retry"
    },
    "internalFailureBoundary": "FAIL_CLOSED_INTERNAL applies only before any RS commit request; after a request any missing/failed/unknown outcome is INDETERMINATE, and after COMMITTED the adapter emits success or retains reconciliation evidence but never emits REJECTED",
    "framingEpochBeforeAuthentication": "SS structurally parses bounded framing and rejects past distance at least six or a future epoch at P07 without trusting content; only distance 0 through 5 continues to key-dependent authentication at P08 and replay lookup at P09",
    "replayOrder": "for authenticated distance 0 through 5, unseen identity continues and an exact duplicate emits DUPLICATE_IGNORED; framing-window cases and replay cases are disjoint",
    "candidateSelector": "APPLY_PEER_UPDATE compares the current authoritative candidate with one incoming authenticated same-parent candidate only when the current transition is the immediately preceding eligible proposal-free local self-update committed through CAPI-S014 and the authenticated raw 32-byte committer identities are distinct; unsigned lexicographic comparison selects the lower; equal-committer, re-presented, peer-predecessor and every other pair is UNSUPPORTED_COMMIT_SHAPE; selected complete state commits and the valid loser remains non-authoritative retained evidence",
    "payloadRelease": "application, Welcome and Commit bytes appear only in SUCCESS after COMMITTED; never in other kinds",
    "completeLogicalMutation": [
      "session transition",
      "binding metadata",
      "replay and retention state",
      "authenticated manifest"
    ],
    "restore": "RS classifies the complete stored set into mutually exclusive cases: no session material; only legacy or tuple/version-drifted session records; exactly one exact-profile M2 candidate with no additional nonlegacy candidate; or multiple/mixed nonlegacy candidates. Preserved legacy bytes beside exactly one exact-profile M2 candidate are ignored and never make that candidate incompatible. SS and RS synchronously revalidate the exact candidate before RESTORED; decoded bytes are never a public state and remain non-authoritative on any failure",
    "keyPackageProvisioning": "C-BIND owns local framed KeyPackage issuance at the SS bootstrap boundary; SS/RS own its reference and one-shot state; AP can supply only peer KeyPackage bytes and Welcome bytes",
    "peerMaterial": "CREATE emits opaque embedded-tree Welcome bytes; SELF_UPDATE emits opaque protected Commit bytes; APPLY_PEER_UPDATE consumes one incoming Commit and either applies a current-parent update or selects the exact bounded same-parent pair; no transport semantics follow",
    "singleWriter": "I-LOCK prevents a second active context before it invokes this API; session-active-elsewhere is therefore an outer UI/controller result, not an adapter result",
    "coarseAnchorRegression": "RESTORE maps an authenticated regressed coarse external anchor to AUTHENTICATED_STATE_INCONSISTENT; absence of such an anchor makes no rollback-prevention claim",
    "legacy": "legacy session bytes are never accepted, imported or cleaned up",
    "issue312": "affected operations are absent from operationEnum and therefore UNSUPPORTED_OPERATION before mutation; no local-observation extension",
    "runtimeArtifactSuite": "ciphersuite fields identify the SS-0 evidenced suite and do not assert which suite is compiled into the frozen WASM artifact; F-WASM owns that feasibility determination"
  },
  "stateMatrix": [
    {
      "scenario": "CAPI-G001",
      "state": "EMPTY",
      "operation": "CREATE",
      "disposition": "ALLOW",
      "resultKind": null,
      "stateAfter": "EMPTY",
      "precedenceLevel": "P05",
      "persistence": "OPERATION_ROW",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G002",
      "state": "EMPTY",
      "operation": "RESTORE",
      "disposition": "ALLOW",
      "resultKind": null,
      "stateAfter": "EMPTY",
      "precedenceLevel": "P05",
      "persistence": "OPERATION_ROW",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G003",
      "state": "EMPTY",
      "operation": "JOIN_WELCOME",
      "disposition": "ALLOW",
      "resultKind": null,
      "stateAfter": "EMPTY",
      "precedenceLevel": "P05",
      "persistence": "OPERATION_ROW",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G004",
      "state": "EMPTY",
      "operation": "PROTECT_APPLICATION",
      "disposition": "NO_ACTIVE_SESSION",
      "resultKind": "REJECTED",
      "stateAfter": "EMPTY",
      "precedenceLevel": "P05",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G005",
      "state": "EMPTY",
      "operation": "OPEN_APPLICATION",
      "disposition": "NO_ACTIVE_SESSION",
      "resultKind": "REJECTED",
      "stateAfter": "EMPTY",
      "precedenceLevel": "P05",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G006",
      "state": "EMPTY",
      "operation": "SELF_UPDATE",
      "disposition": "NO_ACTIVE_SESSION",
      "resultKind": "REJECTED",
      "stateAfter": "EMPTY",
      "precedenceLevel": "P05",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G007",
      "state": "EMPTY",
      "operation": "APPLY_PEER_UPDATE",
      "disposition": "NO_ACTIVE_SESSION",
      "resultKind": "REJECTED",
      "stateAfter": "EMPTY",
      "precedenceLevel": "P05",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G008",
      "state": "EMPTY",
      "operation": "RECONCILE_INDETERMINATE",
      "disposition": "NO_RECONCILIATION_PENDING",
      "resultKind": "REJECTED",
      "stateAfter": "EMPTY",
      "precedenceLevel": "P05",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G009",
      "state": "ACTIVE",
      "operation": "CREATE",
      "disposition": "SESSION_ALREADY_EXISTS",
      "resultKind": "REJECTED",
      "stateAfter": "ACTIVE",
      "precedenceLevel": "P05",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G010",
      "state": "ACTIVE",
      "operation": "RESTORE",
      "disposition": "SESSION_ALREADY_EXISTS",
      "resultKind": "REJECTED",
      "stateAfter": "ACTIVE",
      "precedenceLevel": "P05",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G011",
      "state": "ACTIVE",
      "operation": "JOIN_WELCOME",
      "disposition": "SESSION_ALREADY_EXISTS",
      "resultKind": "REJECTED",
      "stateAfter": "ACTIVE",
      "precedenceLevel": "P05",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G012",
      "state": "ACTIVE",
      "operation": "PROTECT_APPLICATION",
      "disposition": "ALLOW",
      "resultKind": null,
      "stateAfter": "ACTIVE",
      "precedenceLevel": "P05",
      "persistence": "OPERATION_ROW",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G013",
      "state": "ACTIVE",
      "operation": "OPEN_APPLICATION",
      "disposition": "ALLOW",
      "resultKind": null,
      "stateAfter": "ACTIVE",
      "precedenceLevel": "P05",
      "persistence": "OPERATION_ROW",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G014",
      "state": "ACTIVE",
      "operation": "SELF_UPDATE",
      "disposition": "ALLOW",
      "resultKind": null,
      "stateAfter": "ACTIVE",
      "precedenceLevel": "P05",
      "persistence": "OPERATION_ROW",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G015",
      "state": "ACTIVE",
      "operation": "APPLY_PEER_UPDATE",
      "disposition": "ALLOW",
      "resultKind": null,
      "stateAfter": "ACTIVE",
      "precedenceLevel": "P05",
      "persistence": "OPERATION_ROW",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G016",
      "state": "ACTIVE",
      "operation": "RECONCILE_INDETERMINATE",
      "disposition": "NO_RECONCILIATION_PENDING",
      "resultKind": "REJECTED",
      "stateAfter": "ACTIVE",
      "precedenceLevel": "P05",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G017",
      "state": "RECONCILIATION_REQUIRED",
      "operation": "CREATE",
      "disposition": "RECONCILIATION_REQUIRED",
      "resultKind": "REJECTED",
      "stateAfter": "RECONCILIATION_REQUIRED",
      "precedenceLevel": "P05",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G018",
      "state": "RECONCILIATION_REQUIRED",
      "operation": "RESTORE",
      "disposition": "RECONCILIATION_REQUIRED",
      "resultKind": "REJECTED",
      "stateAfter": "RECONCILIATION_REQUIRED",
      "precedenceLevel": "P05",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G019",
      "state": "RECONCILIATION_REQUIRED",
      "operation": "JOIN_WELCOME",
      "disposition": "RECONCILIATION_REQUIRED",
      "resultKind": "REJECTED",
      "stateAfter": "RECONCILIATION_REQUIRED",
      "precedenceLevel": "P05",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G020",
      "state": "RECONCILIATION_REQUIRED",
      "operation": "PROTECT_APPLICATION",
      "disposition": "RECONCILIATION_REQUIRED",
      "resultKind": "REJECTED",
      "stateAfter": "RECONCILIATION_REQUIRED",
      "precedenceLevel": "P05",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G021",
      "state": "RECONCILIATION_REQUIRED",
      "operation": "OPEN_APPLICATION",
      "disposition": "RECONCILIATION_REQUIRED",
      "resultKind": "REJECTED",
      "stateAfter": "RECONCILIATION_REQUIRED",
      "precedenceLevel": "P05",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G022",
      "state": "RECONCILIATION_REQUIRED",
      "operation": "SELF_UPDATE",
      "disposition": "RECONCILIATION_REQUIRED",
      "resultKind": "REJECTED",
      "stateAfter": "RECONCILIATION_REQUIRED",
      "precedenceLevel": "P05",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G023",
      "state": "RECONCILIATION_REQUIRED",
      "operation": "APPLY_PEER_UPDATE",
      "disposition": "RECONCILIATION_REQUIRED",
      "resultKind": "REJECTED",
      "stateAfter": "RECONCILIATION_REQUIRED",
      "precedenceLevel": "P05",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-G024",
      "state": "RECONCILIATION_REQUIRED",
      "operation": "RECONCILE_INDETERMINATE",
      "disposition": "ALLOW",
      "resultKind": null,
      "stateAfter": "RECONCILIATION_REQUIRED",
      "precedenceLevel": "P05",
      "persistence": "OPERATION_ROW",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    }
  ],
  "errorDefinitions": [
    {
      "scenario": "CAPI-E001",
      "errorCode": "UNKNOWN_FIELD",
      "condition": "a closed request object contains an unrecognized field",
      "precedenceLevel": "P01",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E002",
      "errorCode": "INVALID_REQUEST",
      "condition": "required framing or field type is missing or malformed",
      "precedenceLevel": "P01",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E003",
      "errorCode": "UNKNOWN_VALUE",
      "condition": "a closed value is unknown, excluding api, profile and operation selectors governed by P02-P04",
      "precedenceLevel": "P01",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E004",
      "errorCode": "UNSUPPORTED_API_VERSION",
      "condition": "request.api is not the exact adapterApi constant or disagrees with profile.adapterApi",
      "precedenceLevel": "P02",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E005",
      "errorCode": "UNSUPPORTED_PROFILE",
      "condition": "any exact profile or tuple field differs",
      "precedenceLevel": "P03",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E006",
      "errorCode": "BINDING_MISMATCH",
      "condition": "AP bindingRef does not match the SS-bound opaque application context",
      "precedenceLevel": "P03",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E007",
      "errorCode": "UNSUPPORTED_OPERATION",
      "condition": "operation is absent from operationEnum",
      "precedenceLevel": "P04",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E008",
      "errorCode": "SESSION_ALREADY_EXISTS",
      "condition": "a create, restore or join operation is requested in ACTIVE",
      "precedenceLevel": "P05",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E009",
      "errorCode": "NO_ACTIVE_SESSION",
      "condition": "an active-session operation is requested in EMPTY",
      "precedenceLevel": "P05",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E010",
      "errorCode": "NO_STORED_SESSION",
      "condition": "RESTORE finds no session material of any kind",
      "precedenceLevel": "P05",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E011",
      "errorCode": "RECONCILIATION_REQUIRED",
      "condition": "a non-reconciliation operation is requested while reconciliation is required",
      "precedenceLevel": "P05",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E012",
      "errorCode": "NO_RECONCILIATION_PENDING",
      "condition": "reconciliation is requested without a held mutation",
      "precedenceLevel": "P05",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E013",
      "errorCode": "RECONCILIATION_REFERENCE_MISMATCH",
      "condition": "the echoed opaque reference does not match the held reference",
      "precedenceLevel": "P05",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E014",
      "errorCode": "VALUE_OUT_OF_RANGE",
      "condition": "a structural byte/count bound is exceeded before stateful processing",
      "precedenceLevel": "P06",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E015",
      "errorCode": "EPOCH_OUTSIDE_RETAINED_WINDOW",
      "condition": "structurally valid framing declares past distance at least six",
      "precedenceLevel": "P07",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E016",
      "errorCode": "FUTURE_EPOCH",
      "condition": "structurally valid framing declares a future epoch",
      "precedenceLevel": "P07",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E017",
      "errorCode": "AUTHENTICATION_FAILED",
      "condition": "key-dependent authentication or keyed-root validation fails",
      "precedenceLevel": "P08",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E018",
      "errorCode": "AUTHENTICATED_STATE_INCONSISTENT",
      "condition": "authenticated owning-layer state is internally inconsistent, including multiple or mixed nonlegacy session candidates",
      "precedenceLevel": "P08",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E019",
      "errorCode": "UNSUPPORTED_ONBOARDING",
      "condition": "authenticated onboarding shape is outside the exact profile",
      "precedenceLevel": "P09",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E020",
      "errorCode": "STORED_SESSION_INCOMPATIBLE",
      "condition": "RESTORE finds no exact-profile candidate and one or more legacy or tuple/version-drifted session records",
      "precedenceLevel": "P09",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E021",
      "errorCode": "WELCOME_NO_MATCHING_KEY_PACKAGE",
      "condition": "authenticated Welcome matches no single unconsumed local KeyPackage",
      "precedenceLevel": "P09",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E022",
      "errorCode": "UNSUPPORTED_UPDATE_FORM",
      "condition": "authenticated update is proposal-bearing or otherwise unselected",
      "precedenceLevel": "P09",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E023",
      "errorCode": "UNSUPPORTED_COMMIT_SHAPE",
      "condition": "authenticated candidate topology is outside the selected bounded case",
      "precedenceLevel": "P09",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E024",
      "errorCode": "KEY_PACKAGE_ALREADY_CONSUMED",
      "condition": "the matching logical KeyPackage was already consumed",
      "precedenceLevel": "P09",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-E025",
      "errorCode": "FAIL_CLOSED_INTERNAL",
      "condition": "an unclassified internal failure occurs strictly before any RS commit request",
      "precedenceLevel": "P10",
      "resultKind": "REJECTED",
      "stateAfter": "UNCHANGED",
      "persistence": "NONE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    }
  ],
  "decisionRows": [
    {
      "scenario": "CAPI-S001",
      "operation": "CREATE",
      "stateBefore": "EMPTY",
      "condition": "authenticated framed non-last-resort peer KeyPackage; exact profile",
      "precedenceLevel": "P10",
      "persistence": "RS_TRI_STATE",
      "stateAfterOnNamedDisposition": "ACTIVE",
      "namedDisposition": "CREATED",
      "resultKindOnNamedDisposition": "SUCCESS",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "authenticate and stage the complete session transition; apply it only after RS returns COMMITTED",
        "RS": "commit the complete logical mutation and return the closed tri-state",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S002",
      "operation": "CREATE",
      "stateBefore": "EMPTY",
      "condition": "LastResort, unframed, foreign-profile or otherwise unsupported peer KeyPackage",
      "precedenceLevel": "P09",
      "persistence": "NONE",
      "stateAfterOnNamedDisposition": "EMPTY",
      "namedDisposition": "UNSUPPORTED_ONBOARDING",
      "resultKindOnNamedDisposition": "REJECTED",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S003",
      "operation": "RESTORE",
      "stateBefore": "EMPTY",
      "condition": "RS supplies exactly one exact-profile M2 candidate and no additional nonlegacy session candidate; separately preserved legacy bytes are ignored; SS and RS owning-layer revalidation succeeds for binding, authentication and internal consistency",
      "precedenceLevel": "P10",
      "persistence": "NONE",
      "stateAfterOnNamedDisposition": "ACTIVE",
      "namedDisposition": "RESTORED",
      "resultKindOnNamedDisposition": "SUCCESS",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "synchronously authenticate and revalidate the exact committed record before re-establishing ACTIVE",
        "RS": "supply the complete stored record set and keyed-root/authenticity evidence; perform no write",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S004",
      "operation": "RESTORE",
      "stateBefore": "EMPTY",
      "condition": "RS-supplied record set has authenticated local inconsistency, including a regressed coarse external anchor",
      "precedenceLevel": "P08",
      "persistence": "NONE",
      "stateAfterOnNamedDisposition": "EMPTY",
      "namedDisposition": "AUTHENTICATED_STATE_INCONSISTENT",
      "resultKindOnNamedDisposition": "REJECTED",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "synchronously authenticate and revalidate the exact committed record before re-establishing ACTIVE",
        "RS": "supply the complete stored record set and keyed-root/authenticity evidence; perform no write",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S005",
      "operation": "RESTORE",
      "stateBefore": "EMPTY",
      "condition": "authentication or keyed-root validation fails",
      "precedenceLevel": "P08",
      "persistence": "NONE",
      "stateAfterOnNamedDisposition": "EMPTY",
      "namedDisposition": "AUTHENTICATION_FAILED",
      "resultKindOnNamedDisposition": "REJECTED",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "synchronously authenticate and revalidate the exact committed record before re-establishing ACTIVE",
        "RS": "supply the complete stored record set and keyed-root/authenticity evidence; perform no write",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S006",
      "operation": "JOIN_WELCOME",
      "stateBefore": "EMPTY",
      "condition": "authenticated framed non-last-resort local KeyPackage reference exists in SS/RS; embedded-tree Welcome; exact profile",
      "precedenceLevel": "P10",
      "persistence": "RS_TRI_STATE",
      "stateAfterOnNamedDisposition": "ACTIVE",
      "namedDisposition": "JOINED",
      "resultKindOnNamedDisposition": "SUCCESS",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "authenticate and stage the complete session transition; apply it only after RS returns COMMITTED",
        "RS": "commit the complete logical mutation and return the closed tri-state",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S007",
      "operation": "JOIN_WELCOME",
      "stateBefore": "EMPTY",
      "condition": "matching KeyPackage already logically consumed",
      "precedenceLevel": "P09",
      "persistence": "NONE",
      "stateAfterOnNamedDisposition": "EMPTY",
      "namedDisposition": "KEY_PACKAGE_ALREADY_CONSUMED",
      "resultKindOnNamedDisposition": "REJECTED",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S008",
      "operation": "JOIN_WELCOME",
      "stateBefore": "EMPTY",
      "condition": "LastResort, external Commit/tree, PSK, ReInit, rejoin, rotation, multi-device or foreign profile",
      "precedenceLevel": "P09",
      "persistence": "NONE",
      "stateAfterOnNamedDisposition": "EMPTY",
      "namedDisposition": "UNSUPPORTED_ONBOARDING",
      "resultKindOnNamedDisposition": "REJECTED",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S009",
      "operation": "PROTECT_APPLICATION",
      "stateBefore": "ACTIVE",
      "condition": "opaque bounded application bytes",
      "precedenceLevel": "P10",
      "persistence": "RS_TRI_STATE",
      "stateAfterOnNamedDisposition": "ACTIVE",
      "namedDisposition": "APPLICATION_PROTECTED",
      "resultKindOnNamedDisposition": "SUCCESS",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "authenticate and stage the complete session transition; apply it only after RS returns COMMITTED",
        "RS": "commit the complete logical mutation and return the closed tri-state",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S010",
      "operation": "OPEN_APPLICATION",
      "stateBefore": "ACTIVE",
      "condition": "framing epoch distance is 0 through 5; SS authentication succeeds; replay identity is unseen",
      "precedenceLevel": "P10",
      "persistence": "RS_TRI_STATE",
      "stateAfterOnNamedDisposition": "ACTIVE",
      "namedDisposition": "APPLICATION_OPENED",
      "resultKindOnNamedDisposition": "SUCCESS",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "authenticate and stage the complete session transition; apply it only after RS returns COMMITTED",
        "RS": "commit the complete logical mutation and return the closed tri-state",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S011",
      "operation": "OPEN_APPLICATION",
      "stateBefore": "ACTIVE",
      "condition": "framing epoch distance is 0 through 5; SS authentication succeeds; replay identity was already accepted",
      "precedenceLevel": "P10",
      "persistence": "NONE",
      "stateAfterOnNamedDisposition": "ACTIVE",
      "namedDisposition": "DUPLICATE_IGNORED",
      "resultKindOnNamedDisposition": "NO_CHANGE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S012",
      "operation": "OPEN_APPLICATION",
      "stateBefore": "ACTIVE",
      "condition": "structurally valid framing declares past epoch distance 6 or greater; key-dependent authentication and replay lookup are not attempted",
      "precedenceLevel": "P07",
      "persistence": "NONE",
      "stateAfterOnNamedDisposition": "ACTIVE",
      "namedDisposition": "EPOCH_OUTSIDE_RETAINED_WINDOW",
      "resultKindOnNamedDisposition": "REJECTED",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S013",
      "operation": "OPEN_APPLICATION",
      "stateBefore": "ACTIVE",
      "condition": "structurally valid framing declares an epoch greater than current; key-dependent authentication and replay lookup are not attempted",
      "precedenceLevel": "P07",
      "persistence": "NONE",
      "stateAfterOnNamedDisposition": "ACTIVE",
      "namedDisposition": "FUTURE_EPOCH",
      "resultKindOnNamedDisposition": "REJECTED",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S014",
      "operation": "SELF_UPDATE",
      "stateBefore": "ACTIVE",
      "condition": "SS creates authenticated ordinary proposal-free local self-update",
      "precedenceLevel": "P10",
      "persistence": "RS_TRI_STATE",
      "stateAfterOnNamedDisposition": "ACTIVE",
      "namedDisposition": "SELF_UPDATED",
      "resultKindOnNamedDisposition": "SUCCESS",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "authenticate and stage the complete session transition; apply it only after RS returns COMMITTED",
        "RS": "commit the complete logical mutation and return the closed tri-state",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S015",
      "operation": "SELF_UPDATE",
      "stateBefore": "ACTIVE",
      "condition": "SS derives a proposal-bearing or otherwise unselected update form",
      "precedenceLevel": "P09",
      "persistence": "NONE",
      "stateAfterOnNamedDisposition": "ACTIVE",
      "namedDisposition": "UNSUPPORTED_UPDATE_FORM",
      "resultKindOnNamedDisposition": "REJECTED",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S016",
      "operation": "APPLY_PEER_UPDATE",
      "stateBefore": "ACTIVE",
      "condition": "SS authenticates an ordinary proposal-free incoming peer self-update whose parent is the current authoritative state",
      "precedenceLevel": "P10",
      "persistence": "RS_TRI_STATE",
      "stateAfterOnNamedDisposition": "ACTIVE",
      "namedDisposition": "PEER_UPDATE_APPLIED",
      "resultKindOnNamedDisposition": "SUCCESS",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "authenticate and stage the complete session transition; apply it only after RS returns COMMITTED",
        "RS": "commit the complete logical mutation and return the closed tri-state",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S017",
      "operation": "APPLY_PEER_UPDATE",
      "stateBefore": "ACTIVE",
      "condition": "incoming authenticated proposal-free depth-one candidate has the same parent as the immediately preceding authoritative local self-update committed through CAPI-S014; the authenticated raw committer identities are distinct; together they are exactly two candidates with no application witnesses, zero witness score, ordinary priority and valid tip digests",
      "precedenceLevel": "P10",
      "persistence": "RS_TRI_STATE",
      "stateAfterOnNamedDisposition": "ACTIVE",
      "namedDisposition": "CANDIDATE_SELECTED",
      "resultKindOnNamedDisposition": "SUCCESS",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "authenticate and stage the complete session transition; apply it only after RS returns COMMITTED",
        "RS": "commit the complete logical mutation and return the closed tri-state",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S018",
      "operation": "APPLY_PEER_UPDATE",
      "stateBefore": "ACTIVE",
      "condition": "incoming form contains a proposal or any unselected update form",
      "precedenceLevel": "P09",
      "persistence": "NONE",
      "stateAfterOnNamedDisposition": "ACTIVE",
      "namedDisposition": "UNSUPPORTED_UPDATE_FORM",
      "resultKindOnNamedDisposition": "REJECTED",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S019",
      "operation": "APPLY_PEER_UPDATE",
      "stateBefore": "ACTIVE",
      "condition": "candidate parent is neither the current authoritative state nor the immediately preceding CAPI-S014 local-self-update parent; or committer identities are equal; or a candidate is re-presented; or candidate count/topology/witness/priority/digest shape is outside the exact two-candidate profile",
      "precedenceLevel": "P09",
      "persistence": "NONE",
      "stateAfterOnNamedDisposition": "ACTIVE",
      "namedDisposition": "UNSUPPORTED_COMMIT_SHAPE",
      "resultKindOnNamedDisposition": "REJECTED",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S020",
      "operation": "RECONCILE_INDETERMINATE",
      "stateBefore": "RECONCILIATION_REQUIRED",
      "condition": "reconciliationRef matches; originalStateBefore EMPTY; RS proves original mutation COMMITTED",
      "precedenceLevel": "P10",
      "persistence": "NONE",
      "stateAfterOnNamedDisposition": "ACTIVE",
      "namedDisposition": "RECONCILED_COMMITTED",
      "resultKindOnNamedDisposition": "SUCCESS",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "match the held reconciliation reference and apply or discard the held transition exactly once from RS proof",
        "RS": "supply authoritative reconciliation evidence for the prior commit request; perform no new commit",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S021",
      "operation": "RECONCILE_INDETERMINATE",
      "stateBefore": "RECONCILIATION_REQUIRED",
      "condition": "reconciliationRef matches; originalStateBefore EMPTY; RS proves original mutation NOT_COMMITTED",
      "precedenceLevel": "P10",
      "persistence": "NONE",
      "stateAfterOnNamedDisposition": "EMPTY",
      "namedDisposition": "NOT_COMMITTED",
      "resultKindOnNamedDisposition": "NOT_COMMITTED",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "match the held reconciliation reference and apply or discard the held transition exactly once from RS proof",
        "RS": "supply authoritative reconciliation evidence for the prior commit request; perform no new commit",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S022",
      "operation": "RECONCILE_INDETERMINATE",
      "stateBefore": "RECONCILIATION_REQUIRED",
      "condition": "reconciliationRef matches; originalStateBefore ACTIVE; RS proves original mutation COMMITTED",
      "precedenceLevel": "P10",
      "persistence": "NONE",
      "stateAfterOnNamedDisposition": "ACTIVE",
      "namedDisposition": "RECONCILED_COMMITTED",
      "resultKindOnNamedDisposition": "SUCCESS",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "match the held reconciliation reference and apply or discard the held transition exactly once from RS proof",
        "RS": "supply authoritative reconciliation evidence for the prior commit request; perform no new commit",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S023",
      "operation": "RECONCILE_INDETERMINATE",
      "stateBefore": "RECONCILIATION_REQUIRED",
      "condition": "reconciliationRef matches; originalStateBefore ACTIVE; RS proves original mutation NOT_COMMITTED",
      "precedenceLevel": "P10",
      "persistence": "NONE",
      "stateAfterOnNamedDisposition": "ACTIVE",
      "namedDisposition": "NOT_COMMITTED",
      "resultKindOnNamedDisposition": "NOT_COMMITTED",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "match the held reconciliation reference and apply or discard the held transition exactly once from RS proof",
        "RS": "supply authoritative reconciliation evidence for the prior commit request; perform no new commit",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S024",
      "operation": "RECONCILE_INDETERMINATE",
      "stateBefore": "RECONCILIATION_REQUIRED",
      "condition": "reconciliationRef matches; RS remains INDETERMINATE",
      "precedenceLevel": "P10",
      "persistence": "NONE",
      "stateAfterOnNamedDisposition": "RECONCILIATION_REQUIRED",
      "namedDisposition": "INDETERMINATE",
      "resultKindOnNamedDisposition": "INDETERMINATE",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "match the held reconciliation reference and apply or discard the held transition exactly once from RS proof",
        "RS": "supply authoritative reconciliation evidence for the prior commit request; perform no new commit",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S025",
      "operation": "RESTORE",
      "stateBefore": "EMPTY",
      "condition": "RS proves there is no exact-profile candidate, no incompatible session candidate and no legacy session material",
      "precedenceLevel": "P05",
      "persistence": "NONE",
      "stateAfterOnNamedDisposition": "EMPTY",
      "namedDisposition": "NO_STORED_SESSION",
      "resultKindOnNamedDisposition": "REJECTED",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "synchronously authenticate and revalidate the exact committed record before re-establishing ACTIVE",
        "RS": "supply the complete stored record set and keyed-root/authenticity evidence; perform no write",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S026",
      "operation": "RESTORE",
      "stateBefore": "EMPTY",
      "condition": "RS finds no exact-profile candidate and finds one or more legacy or tuple/version-drifted session records",
      "precedenceLevel": "P09",
      "persistence": "NONE",
      "stateAfterOnNamedDisposition": "EMPTY",
      "namedDisposition": "STORED_SESSION_INCOMPATIBLE",
      "resultKindOnNamedDisposition": "REJECTED",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "synchronously authenticate and revalidate the exact committed record before re-establishing ACTIVE",
        "RS": "supply the complete stored record set and keyed-root/authenticity evidence; perform no write",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S027",
      "operation": "JOIN_WELCOME",
      "stateBefore": "EMPTY",
      "condition": "authenticated Welcome matches no single unconsumed local KeyPackage reference",
      "precedenceLevel": "P09",
      "persistence": "NONE",
      "stateAfterOnNamedDisposition": "EMPTY",
      "namedDisposition": "WELCOME_NO_MATCHING_KEY_PACKAGE",
      "resultKindOnNamedDisposition": "REJECTED",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "validate the exact profile and operation; emit the closed disposition without authoritative mutation",
        "RS": "no durable write required by this row",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S028",
      "operation": "RECONCILE_INDETERMINATE",
      "stateBefore": "RECONCILIATION_REQUIRED",
      "condition": "AP-echoed reconciliationRef does not byte-equal the single held SS reconciliation reference",
      "precedenceLevel": "P05",
      "persistence": "NONE",
      "stateAfterOnNamedDisposition": "RECONCILIATION_REQUIRED",
      "namedDisposition": "RECONCILIATION_REFERENCE_MISMATCH",
      "resultKindOnNamedDisposition": "REJECTED",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "match the held reconciliation reference and apply or discard the held transition exactly once from RS proof",
        "RS": "supply authoritative reconciliation evidence for the prior commit request; perform no new commit",
        "TR": "ABSENT"
      }
    },
    {
      "scenario": "CAPI-S029",
      "operation": "RESTORE",
      "stateBefore": "EMPTY",
      "condition": "RS finds more than one nonlegacy session candidate, or one exact-profile candidate beside an incompatible nonlegacy session candidate; separately preserved legacy bytes do not count",
      "precedenceLevel": "P08",
      "persistence": "NONE",
      "stateAfterOnNamedDisposition": "EMPTY",
      "namedDisposition": "AUTHENTICATED_STATE_INCONSISTENT",
      "resultKindOnNamedDisposition": "REJECTED",
      "ownership": {
        "AP": "opaque request/output only; no identity, role, authority, causality, freshness or business meaning inferred",
        "SS": "synchronously authenticate and revalidate the exact committed record before re-establishing ACTIVE",
        "RS": "supply the complete stored record set and keyed-root/authenticity evidence; perform no write",
        "TR": "ABSENT"
      }
    }
  ],
  "precedenceLevels": [
    {
      "id": "P01",
      "name": "REQUEST_SHAPE",
      "scenario": "CAPI-P001"
    },
    {
      "id": "P02",
      "name": "API_VERSION",
      "scenario": "CAPI-P002"
    },
    {
      "id": "P03",
      "name": "PROFILE_AND_BINDING",
      "scenario": "CAPI-P003"
    },
    {
      "id": "P04",
      "name": "OPERATION",
      "scenario": "CAPI-P004"
    },
    {
      "id": "P05",
      "name": "STATE_GATE",
      "scenario": "CAPI-P005"
    },
    {
      "id": "P06",
      "name": "VALUE_BOUNDS",
      "scenario": "CAPI-P006"
    },
    {
      "id": "P07",
      "name": "FRAMING_EPOCH_WINDOW",
      "scenario": "CAPI-P007"
    },
    {
      "id": "P08",
      "name": "AUTHENTICATION_AND_INTEGRITY",
      "scenario": "CAPI-P008"
    },
    {
      "id": "P09",
      "name": "OPERATION_SUPPORT_AND_REPLAY",
      "scenario": "CAPI-P009"
    },
    {
      "id": "P10",
      "name": "COMMIT_OR_INTERNAL_RESULT",
      "scenario": "CAPI-P010"
    }
  ],
  "precedencePairs": [
    {
      "scenario": "CAPI-PP001",
      "higher": "P01",
      "lower": "P02"
    },
    {
      "scenario": "CAPI-PP002",
      "higher": "P01",
      "lower": "P03"
    },
    {
      "scenario": "CAPI-PP003",
      "higher": "P01",
      "lower": "P04"
    },
    {
      "scenario": "CAPI-PP004",
      "higher": "P01",
      "lower": "P05"
    },
    {
      "scenario": "CAPI-PP005",
      "higher": "P01",
      "lower": "P06"
    },
    {
      "scenario": "CAPI-PP006",
      "higher": "P01",
      "lower": "P07"
    },
    {
      "scenario": "CAPI-PP007",
      "higher": "P01",
      "lower": "P08"
    },
    {
      "scenario": "CAPI-PP008",
      "higher": "P01",
      "lower": "P09"
    },
    {
      "scenario": "CAPI-PP009",
      "higher": "P01",
      "lower": "P10"
    },
    {
      "scenario": "CAPI-PP010",
      "higher": "P02",
      "lower": "P03"
    },
    {
      "scenario": "CAPI-PP011",
      "higher": "P02",
      "lower": "P04"
    },
    {
      "scenario": "CAPI-PP012",
      "higher": "P02",
      "lower": "P05"
    },
    {
      "scenario": "CAPI-PP013",
      "higher": "P02",
      "lower": "P06"
    },
    {
      "scenario": "CAPI-PP014",
      "higher": "P02",
      "lower": "P07"
    },
    {
      "scenario": "CAPI-PP015",
      "higher": "P02",
      "lower": "P08"
    },
    {
      "scenario": "CAPI-PP016",
      "higher": "P02",
      "lower": "P09"
    },
    {
      "scenario": "CAPI-PP017",
      "higher": "P02",
      "lower": "P10"
    },
    {
      "scenario": "CAPI-PP018",
      "higher": "P03",
      "lower": "P04"
    },
    {
      "scenario": "CAPI-PP019",
      "higher": "P03",
      "lower": "P05"
    },
    {
      "scenario": "CAPI-PP020",
      "higher": "P03",
      "lower": "P06"
    },
    {
      "scenario": "CAPI-PP021",
      "higher": "P03",
      "lower": "P07"
    },
    {
      "scenario": "CAPI-PP022",
      "higher": "P03",
      "lower": "P08"
    },
    {
      "scenario": "CAPI-PP023",
      "higher": "P03",
      "lower": "P09"
    },
    {
      "scenario": "CAPI-PP024",
      "higher": "P03",
      "lower": "P10"
    },
    {
      "scenario": "CAPI-PP025",
      "higher": "P04",
      "lower": "P05"
    },
    {
      "scenario": "CAPI-PP026",
      "higher": "P04",
      "lower": "P06"
    },
    {
      "scenario": "CAPI-PP027",
      "higher": "P04",
      "lower": "P07"
    },
    {
      "scenario": "CAPI-PP028",
      "higher": "P04",
      "lower": "P08"
    },
    {
      "scenario": "CAPI-PP029",
      "higher": "P04",
      "lower": "P09"
    },
    {
      "scenario": "CAPI-PP030",
      "higher": "P04",
      "lower": "P10"
    },
    {
      "scenario": "CAPI-PP031",
      "higher": "P05",
      "lower": "P06"
    },
    {
      "scenario": "CAPI-PP032",
      "higher": "P05",
      "lower": "P07"
    },
    {
      "scenario": "CAPI-PP033",
      "higher": "P05",
      "lower": "P08"
    },
    {
      "scenario": "CAPI-PP034",
      "higher": "P05",
      "lower": "P09"
    },
    {
      "scenario": "CAPI-PP035",
      "higher": "P05",
      "lower": "P10"
    },
    {
      "scenario": "CAPI-PP036",
      "higher": "P06",
      "lower": "P07"
    },
    {
      "scenario": "CAPI-PP037",
      "higher": "P06",
      "lower": "P08"
    },
    {
      "scenario": "CAPI-PP038",
      "higher": "P06",
      "lower": "P09"
    },
    {
      "scenario": "CAPI-PP039",
      "higher": "P06",
      "lower": "P10"
    },
    {
      "scenario": "CAPI-PP040",
      "higher": "P07",
      "lower": "P08"
    },
    {
      "scenario": "CAPI-PP041",
      "higher": "P07",
      "lower": "P09"
    },
    {
      "scenario": "CAPI-PP042",
      "higher": "P07",
      "lower": "P10"
    },
    {
      "scenario": "CAPI-PP043",
      "higher": "P08",
      "lower": "P09"
    },
    {
      "scenario": "CAPI-PP044",
      "higher": "P08",
      "lower": "P10"
    },
    {
      "scenario": "CAPI-PP045",
      "higher": "P09",
      "lower": "P10"
    }
  ],
  "withinLevelPrecedencePairs": [
    {
      "scenario": "CAPI-EP001",
      "level": "P01",
      "higher": "UNKNOWN_FIELD",
      "lower": "INVALID_REQUEST"
    },
    {
      "scenario": "CAPI-EP002",
      "level": "P01",
      "higher": "UNKNOWN_FIELD",
      "lower": "UNKNOWN_VALUE"
    },
    {
      "scenario": "CAPI-EP003",
      "level": "P01",
      "higher": "INVALID_REQUEST",
      "lower": "UNKNOWN_VALUE"
    },
    {
      "scenario": "CAPI-EP004",
      "level": "P03",
      "higher": "UNSUPPORTED_PROFILE",
      "lower": "BINDING_MISMATCH"
    },
    {
      "scenario": "CAPI-EP005",
      "level": "P05",
      "higher": "RECONCILIATION_REQUIRED",
      "lower": "SESSION_ALREADY_EXISTS"
    },
    {
      "scenario": "CAPI-EP006",
      "level": "P05",
      "higher": "RECONCILIATION_REQUIRED",
      "lower": "NO_ACTIVE_SESSION"
    },
    {
      "scenario": "CAPI-EP007",
      "level": "P05",
      "higher": "RECONCILIATION_REQUIRED",
      "lower": "NO_STORED_SESSION"
    },
    {
      "scenario": "CAPI-EP008",
      "level": "P05",
      "higher": "RECONCILIATION_REQUIRED",
      "lower": "NO_RECONCILIATION_PENDING"
    },
    {
      "scenario": "CAPI-EP009",
      "level": "P05",
      "higher": "RECONCILIATION_REQUIRED",
      "lower": "RECONCILIATION_REFERENCE_MISMATCH"
    },
    {
      "scenario": "CAPI-EP010",
      "level": "P05",
      "higher": "SESSION_ALREADY_EXISTS",
      "lower": "NO_ACTIVE_SESSION"
    },
    {
      "scenario": "CAPI-EP011",
      "level": "P05",
      "higher": "SESSION_ALREADY_EXISTS",
      "lower": "NO_STORED_SESSION"
    },
    {
      "scenario": "CAPI-EP012",
      "level": "P05",
      "higher": "SESSION_ALREADY_EXISTS",
      "lower": "NO_RECONCILIATION_PENDING"
    },
    {
      "scenario": "CAPI-EP013",
      "level": "P05",
      "higher": "SESSION_ALREADY_EXISTS",
      "lower": "RECONCILIATION_REFERENCE_MISMATCH"
    },
    {
      "scenario": "CAPI-EP014",
      "level": "P05",
      "higher": "NO_ACTIVE_SESSION",
      "lower": "NO_STORED_SESSION"
    },
    {
      "scenario": "CAPI-EP015",
      "level": "P05",
      "higher": "NO_ACTIVE_SESSION",
      "lower": "NO_RECONCILIATION_PENDING"
    },
    {
      "scenario": "CAPI-EP016",
      "level": "P05",
      "higher": "NO_ACTIVE_SESSION",
      "lower": "RECONCILIATION_REFERENCE_MISMATCH"
    },
    {
      "scenario": "CAPI-EP017",
      "level": "P05",
      "higher": "NO_STORED_SESSION",
      "lower": "NO_RECONCILIATION_PENDING"
    },
    {
      "scenario": "CAPI-EP018",
      "level": "P05",
      "higher": "NO_STORED_SESSION",
      "lower": "RECONCILIATION_REFERENCE_MISMATCH"
    },
    {
      "scenario": "CAPI-EP019",
      "level": "P05",
      "higher": "NO_RECONCILIATION_PENDING",
      "lower": "RECONCILIATION_REFERENCE_MISMATCH"
    },
    {
      "scenario": "CAPI-EP020",
      "level": "P07",
      "higher": "EPOCH_OUTSIDE_RETAINED_WINDOW",
      "lower": "FUTURE_EPOCH"
    },
    {
      "scenario": "CAPI-EP021",
      "level": "P08",
      "higher": "AUTHENTICATION_FAILED",
      "lower": "AUTHENTICATED_STATE_INCONSISTENT"
    },
    {
      "scenario": "CAPI-EP022",
      "level": "P09",
      "higher": "STORED_SESSION_INCOMPATIBLE",
      "lower": "UNSUPPORTED_ONBOARDING"
    },
    {
      "scenario": "CAPI-EP023",
      "level": "P09",
      "higher": "STORED_SESSION_INCOMPATIBLE",
      "lower": "WELCOME_NO_MATCHING_KEY_PACKAGE"
    },
    {
      "scenario": "CAPI-EP024",
      "level": "P09",
      "higher": "STORED_SESSION_INCOMPATIBLE",
      "lower": "UNSUPPORTED_UPDATE_FORM"
    },
    {
      "scenario": "CAPI-EP025",
      "level": "P09",
      "higher": "STORED_SESSION_INCOMPATIBLE",
      "lower": "UNSUPPORTED_COMMIT_SHAPE"
    },
    {
      "scenario": "CAPI-EP026",
      "level": "P09",
      "higher": "STORED_SESSION_INCOMPATIBLE",
      "lower": "KEY_PACKAGE_ALREADY_CONSUMED"
    },
    {
      "scenario": "CAPI-EP027",
      "level": "P09",
      "higher": "UNSUPPORTED_ONBOARDING",
      "lower": "WELCOME_NO_MATCHING_KEY_PACKAGE"
    },
    {
      "scenario": "CAPI-EP028",
      "level": "P09",
      "higher": "UNSUPPORTED_ONBOARDING",
      "lower": "UNSUPPORTED_UPDATE_FORM"
    },
    {
      "scenario": "CAPI-EP029",
      "level": "P09",
      "higher": "UNSUPPORTED_ONBOARDING",
      "lower": "UNSUPPORTED_COMMIT_SHAPE"
    },
    {
      "scenario": "CAPI-EP030",
      "level": "P09",
      "higher": "UNSUPPORTED_ONBOARDING",
      "lower": "KEY_PACKAGE_ALREADY_CONSUMED"
    },
    {
      "scenario": "CAPI-EP031",
      "level": "P09",
      "higher": "WELCOME_NO_MATCHING_KEY_PACKAGE",
      "lower": "UNSUPPORTED_UPDATE_FORM"
    },
    {
      "scenario": "CAPI-EP032",
      "level": "P09",
      "higher": "WELCOME_NO_MATCHING_KEY_PACKAGE",
      "lower": "UNSUPPORTED_COMMIT_SHAPE"
    },
    {
      "scenario": "CAPI-EP033",
      "level": "P09",
      "higher": "WELCOME_NO_MATCHING_KEY_PACKAGE",
      "lower": "KEY_PACKAGE_ALREADY_CONSUMED"
    },
    {
      "scenario": "CAPI-EP034",
      "level": "P09",
      "higher": "UNSUPPORTED_UPDATE_FORM",
      "lower": "UNSUPPORTED_COMMIT_SHAPE"
    },
    {
      "scenario": "CAPI-EP035",
      "level": "P09",
      "higher": "UNSUPPORTED_UPDATE_FORM",
      "lower": "KEY_PACKAGE_ALREADY_CONSUMED"
    },
    {
      "scenario": "CAPI-EP036",
      "level": "P09",
      "higher": "UNSUPPORTED_COMMIT_SHAPE",
      "lower": "KEY_PACKAGE_ALREADY_CONSUMED"
    }
  ],
  "errorPrecedenceLevel": {
    "UNKNOWN_FIELD": "P01",
    "INVALID_REQUEST": "P01",
    "UNKNOWN_VALUE": "P01",
    "UNSUPPORTED_API_VERSION": "P02",
    "UNSUPPORTED_PROFILE": "P03",
    "BINDING_MISMATCH": "P03",
    "UNSUPPORTED_OPERATION": "P04",
    "SESSION_ALREADY_EXISTS": "P05",
    "NO_ACTIVE_SESSION": "P05",
    "NO_STORED_SESSION": "P05",
    "RECONCILIATION_REQUIRED": "P05",
    "NO_RECONCILIATION_PENDING": "P05",
    "RECONCILIATION_REFERENCE_MISMATCH": "P05",
    "VALUE_OUT_OF_RANGE": "P06",
    "EPOCH_OUTSIDE_RETAINED_WINDOW": "P07",
    "FUTURE_EPOCH": "P07",
    "AUTHENTICATION_FAILED": "P08",
    "AUTHENTICATED_STATE_INCONSISTENT": "P08",
    "UNSUPPORTED_ONBOARDING": "P09",
    "STORED_SESSION_INCOMPATIBLE": "P09",
    "WELCOME_NO_MATCHING_KEY_PACKAGE": "P09",
    "UNSUPPORTED_UPDATE_FORM": "P09",
    "UNSUPPORTED_COMMIT_SHAPE": "P09",
    "KEY_PACKAGE_ALREADY_CONSUMED": "P09",
    "FAIL_CLOSED_INTERNAL": "P10"
  },
  "withinLevelErrorOrder": {
    "P01": [
      "UNKNOWN_FIELD",
      "INVALID_REQUEST",
      "UNKNOWN_VALUE"
    ],
    "P02": [
      "UNSUPPORTED_API_VERSION"
    ],
    "P03": [
      "UNSUPPORTED_PROFILE",
      "BINDING_MISMATCH"
    ],
    "P04": [
      "UNSUPPORTED_OPERATION"
    ],
    "P05": [
      "RECONCILIATION_REQUIRED",
      "SESSION_ALREADY_EXISTS",
      "NO_ACTIVE_SESSION",
      "NO_STORED_SESSION",
      "NO_RECONCILIATION_PENDING",
      "RECONCILIATION_REFERENCE_MISMATCH"
    ],
    "P06": [
      "VALUE_OUT_OF_RANGE"
    ],
    "P07": [
      "EPOCH_OUTSIDE_RETAINED_WINDOW",
      "FUTURE_EPOCH"
    ],
    "P08": [
      "AUTHENTICATION_FAILED",
      "AUTHENTICATED_STATE_INCONSISTENT"
    ],
    "P09": [
      "STORED_SESSION_INCOMPATIBLE",
      "UNSUPPORTED_ONBOARDING",
      "WELCOME_NO_MATCHING_KEY_PACKAGE",
      "UNSUPPORTED_UPDATE_FORM",
      "UNSUPPORTED_COMMIT_SHAPE",
      "KEY_PACKAGE_ALREADY_CONSUMED"
    ],
    "P10": [
      "FAIL_CLOSED_INTERNAL"
    ]
  },
  "nonClaims": [
    "No application semantic, identity, role, authority, causality, freshness or business-truth claim.",
    "No transport publication, delivery, receipt, retry, ordering or reliable-delivery claim.",
    "No persisted byte layout, record/key version value, HKDF label, AAD encoding, storage layout or migration.",
    "No legacy MLS-byte import or cleanup and no Issue #312 semantic extension.",
    "No detection or prevention of coherent whole-profile rollback; no remote freshness anchor.",
    "No physical deletion, zeroization, general forward secrecy, post-compromise recovery or arbitrary retention claim.",
    "No general groups, arbitrary convergence, public SDK, production-default activation or general Marmot compatibility."
  ]
}
```
<!-- styx-m2-adapter-contract-json:v1:end -->

## 11. Conformance

A conforming validator accepts this exact complete record and rejects copies with: missing/duplicate/overlapping row; unknown field/value; changed enum or tuple; incomplete operation/state matrix; missing/reversed precedence pair; unmapped error; overlapping result code/kind; AP-supplied SS/RS fact; wrong reconciliation origin transition; output before commit; unsupported topology mutation; restored bytes authoritative before revalidation; or widened ownership/TR.

Required negative fixtures include at least missing row, duplicate row signature, unknown nested field, unsupported tuple and missing precedence pair. Duplicate JSON keys are invalid.

## 12. Authority and ratification

This contract implements C-API under #313, #314, #317 and #319 at base `e1538ef9c070e463a8256872a3fd0882c424e2ef`. It applies D0–D5, D8–D15 and D17–D18 and preserves G-SCOPE's exact tuple.

The final file SHA-256 must be separately owner-ratified before C-BIND, C-MUT or dependent implementation. Any byte change voids that act. Removing this file fully rolls back C-API; no implementation or persisted bytes are introduced.
