# M3 early-lane SDK and reference PWA threat model (runtime profile)

Status: informative threat model for the M3 early-lane SDK and the reference chat PWA, written on `m3/integration` at `ab1ebf7874c01e4131657c6547d566ac463749f9` (#567). It is not a contract, not protocol authority and not an audit. It adds no rule, bound, state, code, port method, wire structure or persisted format. Where it and a normative document could be read differently, the normative document wins and the difference is a defect of this document: the public SDK interface `docs/architecture/m3/sdk-interface.md` (C-SDK, interface `styx-m3-sdk/0.4.0-experimental`, SHA-256 `9a0b1c4ba77c6e5e6c90902ddf49b4c0193e21c6f13732bec2e74f0b05272184` at that commit) and the delivery-layer contract `docs/architecture/m3/delivery-layer.md` (C-DLV, wire `styx-m3-sdk/0.3.0-experimental`, SHA-256 `ace94ab76745ce40f74e3465ae976bc6884a9d82a60e56c9ee0d409f5845dd9f` at that commit). They are cited below as "interface §n" and "C-DLV §n".

## 1. Scope and relation to the protocol threat model

The application-protocol threat model `docs/security/STYX-THREAT-MODEL.md` covers the language-neutral application protocol and the secure-session profile. Its bytes are pinned by frozen protocol evidence (SHA-256 `8863ce4b2ef697055e95da22e0a2fbb630172cdf3f5fd0c91b27ec02f9d2ba54`) and it is not changed here. It does not cover the M3 runtime profile (invitations, cursors, durable receive state, the in-memory outbound queue) or the concrete reference PWA (service worker, notifications, URL parameters). This document covers those two surfaces. The protocol threat model receives a pointer to this document at its next protocol resynchronisation, which is separate work.

Covered: the SDK under `styx-js/src/sdk/**` as specified by C-SDK and C-DLV, and the reference chat PWA under `styx-js/apps/chat/**` with the chat library it uses. Not covered: the protocol ledger, the vault cryptography, OpenMLS internals, the Phase B MDK evidence, CI and supply chain beyond what §5.1 names.

The reference PWA does not use the M3 SDK. It runs the existing chat library (`StyxChat`) over its own transports. Nothing below transfers an SDK property to the PWA or the reverse. Wiring the SDK into a product, or backing its ports with the vault or MLS engine, is a separate owner act (interface §8).

### 1.1 How each threat is written

Every threat separates three kinds of obligation, because they have different owners and different evidence:

- **SDK obligation**: behaviour the SDK code itself enforces, fixed by C-SDK or C-DLV and exercised by lane tests. Only these are SDK properties.
- **Integration contract**: semantics that a caller-injected port MUST provide (interface §8). The SDK validates shapes and bounds calls, but cannot verify the meaning; a port that violates them voids the dependent property without any SDK signal.
- **Downstream duty**: what an application, deployment or operator must do above both. Nothing in the SDK or the PWA performs it.

The **residual behaviour** of each threat states what still happens on the current code when every obligation is met. It is a description of behaviour; it declares no risk resolved and gives no attack procedure.

## 2. Assets, boundaries and adversaries

Assets: identity signing capability (secret keys never cross the SDK boundary, interface §8.3); MLS group state, KeyPackages, Welcome material and peer bindings (caller-owned); message plaintext (at endpoints, in listener callbacks, and with `ports.receiveState` in durable `READY` entries until acknowledged); ciphertext and signed events; delivery and receipt states; routing metadata (public keys, `p`, `e`, `v`, `n`, `r` tags, timing, sizes, network addresses); the PWA code served by an origin, its service worker and its push registration.

Boundaries: relay WebSocket frames and connection timing; caller-injected ports (storage, session, identity, receive state, clock, randomness); caller configuration (relay URLs, allowlisted hosts, quotas); the browser origin, service worker and URL of the PWA; the push bridge and the platform push service.

Adversaries considered: a configured relay that stores, omits, replays, reorders, duplicates, delays or fabricates frames, `OK` and `EOSE`; a network observer; a malicious inviter, invitee or known sender; a faulty or dishonest injected port; a crash, power loss or torn write; a hostile web origin or a modified service worker; a person who can make the user open a crafted PWA link; a bystander who sees notifications.

## 3. M3 SDK

### 3.1 Invitations: KeyPackage, Welcome and delegated gift wrap

Threat: a stale, deceptive or wrong-signer KeyPackage, or a substituted or unreadable Welcome, binds a session to the wrong peer, fails a join, or leaves stranded state.

- SDK obligation: KeyPackage candidates (kind 4743) pass shape, kind, exact tags and wire version, size, expiration and the 600-second future bound, recomputed id and signature, and must come from the named invitee (C-DLV §6.5, §7.1). The fetch waits for the `EOSE` of each relay counted connected at the end of its connection phase, identified by index, or one `perRelayTimeoutMs`, and picks the newest valid `created_at` among the answers received within that wait (C-DLV §5.5). Gift-wrap candidates (kind 1059) pass shape, kind, exact `p`, size, id and signature before any unwrap; the rumor must have the exact keys, kind, `e` and version tags and sizes, and both the seal signer and the rumor `pubkey` must equal the explicit inviter. A Welcome is joined only before the admission deadline and before the expiration of the own KeyPackage its `e` tag names, read with one clock reading immediately before `joinSession` (C-DLV §7.1). Publication ends at the first `ACCEPTED`, once every relay has settled without one, or at the attempt timeout, and never waits for the other relays once one has accepted (C-DLV §5.5).
- Integration contract: the session port binds the KeyPackage credential to `peer`, creates exactly a two-member session and fails without creation for a wrong credential or an existing peer session; `joinSession` fails for a different other member or an existing peer session (interface §8.2). The identity port implements a kind-1059 NIP-59 wrap with a kind-13 seal signed by the identity key, a fresh wrapping key and NIP-44 v2, and reports the authenticated seal signer on unwrap (interface §8.3). The SDK implements none of these constructions and verifies none of their meaning.
- Downstream duty: confirm the peer identity out of band before trusting an invitation; never use the cleartext test wrapping outside tests; after any failed join, start again with fresh engines, ports and clients on both sides.
- Residual behaviour: a failed join may consume the KeyPackage while the inviter retains a group, with no rollback of caller state (interface §4.2, C-DLV §11). The fetch picks the newest package among the answers received within its wait, not the newest one the invitee published; a relay silent for the whole wait does not contribute (review label H7, C-DLV §5.5). The first passing Welcome whose join fails ends the acceptance, even when a later candidate of the same inviter would have been usable (review label H9, C-DLV §7.1). A failed `startSession` is not rolled back in the caller's engine, and repeated failures may grow that state (review label H15, C-DLV §11). A late join after shutdown may leave an unreported caller session. Invitation relays see the KeyPackage publisher and the named invitee in `p`, plus sizes and timing.

### 3.2 Inbound frames, validation and flooding

Threat: a relay sends forged, misaddressed, oversized or numerous frames to reach session processing or to exhaust memory and processing.

- SDK obligation: every inbound kind-4741 or kind-4742 event passes the closed checks of C-DLV §7.1 (exactly the seven own keys of §6.1, enumerable and symbol keys included; kind; exact tags; own `p`; wire version; recomputed id; BIP-340 signature) before duplicate handling, opening or receipt processing. Raw queued frames, the frame in validation and validated messages waiting for an audience share one 1 024-entry bound and one retained-cost bound: at most 1 048 576 cost units per frame and 16 777 216 in total, computed once per decoded frame before validation; every valid event stays below the per-frame maximum, so only the shared total can drop it (C-DLV §3, §7.1). The single active open/delivery unit is outside these bounds. A frame over the per-frame bound is not retained; a marker keeps its turn and reports `E_SDK_INBOUND_INVALID`. With `ports.receiveState` at most 4 096 distinct failed event ids are kept per relay for the cursor barrier, and only the earliest outstanding request per pool is kept (C-DLV §5.4).
- Integration contract: none beyond the ports used after validation.
- Downstream duty: configure only relays the deployment is prepared to receive load from; treat a relay that repeatedly fills the bounds as an availability incident.
- Residual behaviour: the transport decodes each frame's JSON before any SDK bound applies, so a relay can still make the client decode one large frame before it is dropped (C-DLV §11). The cost units are conservative, not a memory measurement. A relay that fills the count or cost bound can make the client drop other relays' frames until a later replay, and there is no per-sender or per-relay fairness. With `ports.receiveState`, a relay that causes more than 4 096 distinct failures blocks its own cursor commits for the rest of the client run; a restart retries from the last committed cursor.

### 3.3 Catch-up cursors and EOSE

Threat: a misleading or premature `EOSE`, a dropped frame or a local clock change advances a cursor past events that were never safely received, so later requests omit them.

- SDK obligation: without `ports.receiveState`, cursors are volatile local-clock values per relay, advanced only by an `EOSE` that names the subscription of that relay's current pool and that has an outstanding request; `since` is the cursor minus 120 seconds; no `EVENT` field is read for the cursor (C-DLV §5.4). With `ports.receiveState`, every inbound `EVENT` frame is counted per relay before the volatile queue, and a durable cursor is committed only when every frame counted before the `EOSE` has been accounted and no barrier failure remains for that relay; a cursor ahead of the local clock is treated as absent and reported once per relay per run with `RECEIVE_STATE_CLOCK_SKEW`; during an invitation operation no delivery cursor is committed (C-DLV §5.4).
- Integration contract: `commitCursor` records only the value it is given, durably, and `load` returns it (interface §8.5).
- Downstream duty: do not present catch-up as complete delivery; keep relays that retain events long enough for the deployment's offline periods.
- Residual behaviour: EOSE is never proof of completeness. It is a local barrier for the relay that sent it, and only for frames that relay actually delivered. Events that no relay delivers, or that were lost before `stage`, are not recovered by the durable barrier: they depend on a later delivery or replay by a relay, and stay unavailable if no relay delivers them again; relays may rate-limit re-requests or ignore `since`; events older than the cursor minus 120 seconds may be missed (C-DLV §11). Without the durable port, ids evicted from the 4 096-id duplicate window may be opened again. No catch-up runs when the injected clock's timers do not fire.

### 3.4 Durable receive: stage, openCandidate, commit and resolve

Threat: a crash, timeout, concurrent mutation or uncertain write between staging, MLS processing and commit loses a message, opens it twice against MLS, exposes half a transition, or reports false redelivery state.

- SDK obligation (with `ports.receiveState` only, kind 4741 only): an admitted event is staged durably before `openCandidate`; at most one entry is open at a time; `application` and `reject` results are committed with the ticket unchanged; `retry` and a failed, timed-out or malformed `openCandidate` leave the entry `PENDING` for a bounded in-run retry; an id whose outcome was durably committed is never opened again; a committed application result becomes `READY` and is redelivered until `acknowledgeMessage` succeeds. An uncertain `commit` pauses the receive state and `resolve` is called at once and at every periodic pass. Any definite refusal or uncertain result of `stage`, `ack`, `receiptDone` or `commitCursor`, and a `commit` refused for failure or conflict, freezes the receive state for the rest of the client's lifetime (fail-stop); a `commit` refused for capacity leaves the entry `PENDING` without pausing or freezing. While paused or frozen no new admission, open, commit, cursor commit or receipt publication starts (a commit already issued completes and `resolve` applies its outcome), and `send` and the invitation methods return `E_SDK_RECEIVE_STATE_FAILED` before any mutation; nothing falls back to the path without the port (interface §8.5, C-DLV §7.4).
- Integration contract: one exclusive coordinator per MLS provider serialises `openCandidate`, `commit`, `resolve` and candidate installation with every other provider mutation; `commit` makes the session state bound to the ticket, the entry state, the receipt obligation and the seen mark durable atomically as one unit; `resolve` answers only for the named commit and returns `aborted` only when that commit can no longer take effect; a write against another revision returns `E_SDK_RECEIVE_STATE_CONFLICT`; `load` rejects another identity, scope, schema or an inconsistent snapshot; one client owns one receive state and a second writer is unsupported; the port encrypts at rest everything it holds (interface §8.2, §8.5). The SDK cannot verify any of this.
- Downstream duty: implement the port on storage that really provides the atomicity it claims; run one writer per receive state; acknowledge a message only after the application has durably taken it over; handle a frozen state by shutting the client down and starting a new one.
- Residual behaviour: the cross-restart exception is conditional on those caller semantics and covers kind 4741 only, never an outbound item. Application delivery is at least once: a `READY` result is redelivered until acknowledged, so the application must deduplicate by `eventId`. Physical erasure after `ack` is not claimed without a completed atomic compaction. A frozen state stops reception, cursor commits, receipts and new sends until a new client loads successfully.

### 3.5 Quotas and injected ports

Threat: a known sender fills durable capacity with ciphertext that stays unclassified, or a faulty injected port reports success it did not achieve (a pass-through `seal`, a mismatched `sign`, an unstable public key, a storage write that did nothing).

- SDK obligation: every call to the storage, session, identity and receive-state ports is bounded by the port-call timeout on the host timer and its return is validated against a closed shape; the clock and random ports are called synchronously and an invalid value from them is `E_SDK_INTERNAL`; a value outside a closed set in a closed slot is `E_SDK_UNKNOWN_CODE` (interface §5.3, §8, §8.4). Admission requires `isKnownSender` to return `true` and no quota to be reached (`maxPending`, `maxUnacknowledged`, `maxSeen`, `maxStoredBytes`); the write that crosses a limit completes, nothing is deleted, and `RECEIVE_STATE_CAPACITY` is emitted once per crossing; each `PENDING` entry is retried at most once per catch-up interval (interface §4.1, §8.5; C-DLV §7.4).
- Integration contract: `isKnownSender` is `true` only for a sender with a durable peer binding; `seal` provides the payload protection the application relies on; `sign` signs exactly the given digest with the key `getPublicKey` returns; storage and receive-state writes take the effect their success value states (interface §8).
- Downstream duty: size quotas for the expected peers; monitor capacity events; never accept unknown senders by default; review every port implementation as security-critical code.
- Residual behaviour: there is no per-sender fairness; permanently unclassified ciphertext from a known sender occupies capacity and is retried at the bounded rate; reaching `maxSeen` is persistent saturation (interface §8.5, C-DLV §11). Admission filtering acts after decoding, validation and signature verification, so it protects the durable state and MLS processing, not network, CPU or inbound-queue availability. A shape-valid port return proves nothing about encryption, signing meaning or durability; with a pass-through session port there is no payload confidentiality.

### 3.6 Outbound queue in memory

Threat: a caller treats `send` as durable, and a crash or stop loses the item, or a stored item is replayed into a new process.

- SDK obligation: the outbound queue lives only in process memory (at most 256 non-terminal items, finite attempts at most 10 and a deadline at most 600 000 ms); the initial record is stored before `seal`; retransmissions republish the identical signed event; on an orderly `shutdown()` every non-terminal item becomes `LOST_ON_SHUTDOWN`; `start()` refuses a non-empty storage port with `E_SDK_STORAGE_NOT_EMPTY` and never resumes, replays or re-sends a stored item (interface §2, §8.1; C-DLV §3, §4).
- Integration contract: the storage port stores and returns records without interpretation; holding a record is not a delivery guarantee (interface §8.1).
- Downstream duty: treat `QUEUED`, relay acceptance and `LOST_ON_SHUTDOWN` as distinct; re-send at the application level after a restart when the application needs it; present relay acceptance and recipient receipt separately and never as reading.
- Residual behaviour: after a crash or abrupt termination nothing is reported and nothing is recovered; the outbound queue never resumes across processes. `FAILED_NOT_ACCEPTED` does not prove that no relay received the bytes, and `FAILED_NO_RECEIPT` does not prove that the recipient did not receive the message. Every item is retained for the client's lifetime, so memory grows with the number of items sent until a new client is created (C-DLV §11). The start-up `storage.list()` inspection runs synchronously in two ordered passes, linear in the listed data, with no paging or length bound (review label H18, C-DLV §5.2).

### 3.7 Duplicates and transient open failures without the durable port

Threat: a transient `session.open` failure suppresses later copies of the same event, or a replay is treated as new work.

- SDK obligation: without `ports.receiveState`, each client remembers at most 4 096 processed inbound ids, first in first out; a duplicate within the window is dropped without an event or a second receipt (C-DLV §8).
- Integration contract: none.
- Downstream duty: use `ports.receiveState` where a transient open failure must not lose a message.
- Residual behaviour: an id enters the window immediately before its `session.open` call, so a copy of the same id from another relay or a re-request is not opened again while the id is in the window, even when the first failure was transient (review label H17, C-DLV §8). An id outside the window, or in a new process, may be opened again; no exactly-once claim follows.

### 3.8 Routing metadata

Threat: a relay or observer links identities, contacts, cases or activity from routing metadata even when content is encrypted.

- SDK obligation: remote relays only over `wss:`, on the default port, to hosts the caller lists in `publicRelayHosts`; no relay URL literal, host name or default list in SDK modules (interface §2, §4.1).
- Integration contract: none.
- Downstream duty: choose relays and allowlisted hosts deliberately; every added relay is another observer.
- Residual behaviour: relays see public keys, the `p`, `e`, `v`, `n` and `r` tags, timing, sizes and the client network address; a receipt tells the sender's relays that a holder of the recipient's key answered. A relay endpoint sees decrypted WebSocket frames, while a passive observer of a sound TLS link sees connection metadata, timing and sizes; C-DLV §11 lists the two together. No DNS policy, TLS pinning, identity hiding, unlinkability, padding or timing protection is provided (interface §10).

## 4. Reference chat PWA

### 4.1 Service worker and update path

Behaviour on the current code: the app is built with `vite-plugin-pwa` in `injectManifest` mode with `registerType: 'autoUpdate'` (`styx-js/apps/chat/vite.config.js`). The service worker precaches the app shell and the OpenMLS WASM, calls `self.skipWaiting()` on install and `self.clients.claim()` on activate (`styx-js/apps/chat/src/sw.js`).

Threat: whoever controls the origin, its hosting or its deployment pipeline serves modified JavaScript or a modified service worker, and the user runs it with the application's full authority.

- SDK obligation: none; the PWA does not use the SDK.
- Integration contract: none.
- Downstream duty: serve the app only from an origin whose hosting and deployment are trusted; protect the build and release pipeline; apply the Node static server's security headers (`static-server.mjs`) or equivalent on every deployment.
- Residual behaviour: a new service worker activates without waiting and takes control of open pages, so a modified build reaches open sessions at the next update check with no user confirmation. Pinned and reproducibly built WASM does not authenticate the HTML, JavaScript or service worker around it. `serve.py` sets no Content-Security-Policy or other security header. The browser profile remains weaker against origin control than a native client.

### 4.2 Notifications and push

Behaviour on the current code: local and push notifications show one generic text (title `Styx Chat`, body `Hai un nuovo messaggio`, tag `styx-new`) with no content and no sender (`src/lib/notify.js`). Local notifications appear only with permission granted and the page hidden, coalesced to one per 4 seconds. The service worker's `push` handler ignores `event.data` and shows the same generic notification (`src/sw.js`). Push registration is opt-in: only with a bridge URL configured and notification permission already granted, the app automatically attempts, best effort, to subscribe with the browser push manager and to send its public key, the push subscription and a signature to the bridge (`src/push/push-registrar.js`, `src/hooks/useStyxChat.js`).

Threat: notifications disclose content, contacts or activity to bystanders, the platform push service or the bridge.

- SDK obligation: none.
- Integration contract: none.
- Downstream duty: operate or choose the bridge as a party that learns the link between the public key and the push endpoint; keep notification text generic in any derived app; do not add content to push payloads.
- Residual behaviour: notification text and push carry no content or sender, but the existence and timing of notifications are visible on the device; the push service sees the push messages sent through it and their timing, not local notifications; once a registration succeeds, the bridge knows which push endpoint belongs to which public key. No metadata-protection claim is made for the notification path.

### 4.3 URL parameters as hostile input

Behaviour on the current code (`src/lib/config.js`, `src/lib/ns.js`): `?local=1` selects no relays, which selects the same-origin BroadcastChannel transport, and only then sets `allowInsecureTransport` because that channel carries no signatures; `?relay=` (repeatable) replaces the default relays; `?bridge=` sets the push bridge URL, otherwise the build-time `VITE_BRIDGE_URL` is used; `?ns=` selects a separate local identity namespace. These values are accepted from the URL without a confirmation step.

Threat: a crafted link changes which relays the app talks to, routes push registration to a chosen bridge, switches to the unsigned local transport, or selects another local namespace, without the user noticing.

- SDK obligation: none; the PWA does not use the SDK and its URL handling is outside the SDK's relay rules.
- Integration contract: none.
- Downstream duty: treat `local`, `relay`, `bridge` and `ns` from the URL as hostile input; deploy with a `connect-src` policy that lists only the relays and bridge the deployment intends (the Node static server allows `'self'`, its two default relays and the origins in `STYX_CONNECT_SRC`); do not deploy with `serve.py`; do not rely on `?local=1` outside same-machine tests.
- Residual behaviour: where the Content-Security-Policy does not restrict `connect-src`, a crafted `?relay=` or `?bridge=` reaches the chosen endpoint, and the app automatically attempts the push registration with a configured bridge when permission was already granted. `?local=1` is not a network connection, so `connect-src` never blocks it, and the transport it selects carries no signatures. Adding a confirmation step for these parameters is open work, not done.

### 4.4 Inbound chat payloads and local state

Behaviour on the current code: since #562 the chat library validates the typed fields of every inbound payload that decodes to a JSON object before that payload is stored (message `id`, `text` and timestamp; receipt `id` and kind; introduction alias) and discards and counts an object payload that fails. A payload that decodes to a JSON array is discarded and counted as malformed. A payload that decodes to neither a JSON object nor a JSON array is still accepted as bare legacy text, with only the text-length bound and a locally generated id and time. The MLS state advanced by decryption is persisted before the payload is classified, separately from the payload. Stored records written before that validation are neutralised on load, and the UI is wrapped in a recoverable React error boundary. Since #579 the name a peer declares for itself in an introduction is kept apart from the alias chosen on the device: for an accepted contact it is stored as a separate optional field, never replaces the local alias and leaves the verified state unchanged, and the conversation header shows it, when it differs, on its own line without the verified mark.

Threat: an authenticated peer sends values that break rendering or persist hostile state.

- SDK obligation: none.
- Integration contract: none.
- Downstream duty: treat every peer-supplied field as untrusted when it is rendered; keep the validation bounds when deriving another app.
- Residual behaviour: validation covers field types and ranges, not meaning; a peer can still send arbitrary text within the bounds. A pairing accepted without typing a name still takes, as the local alias, the name the peer declared before acceptance (in the QR code or in its first introduction); the reference chat can mark a message sent without an open relay connection, and the pairing lifecycle after a failed join or an ignored pairing request is incomplete; these are open work, not done. Two tabs on the same identity and storage namespace are not a supported configuration.

## 5. Cross-cutting

### 5.1 Supply chain and CI

Since #565 the CI path-aware change detectors read the changed-file list from a temporary file and fail visibly on any read error, so a large pull request no longer skips protected checks silently. Downstream duty: keep owner review of workflows and lockfiles; residual behaviour: a path containing a newline is still split in two lines by the detectors, and a passing CI run is evidence for the exact head it ran on, not release provenance.

### 5.2 State after the model-assisted review of November 2026

These corrections are integrated on `m3/integration` and are described above as current behaviour: #560 (the invitation fetch waits for the `EOSE` of its phase-end relays by identity, and invitation publication ends at the first acceptance), #565 (CI change detectors), #562 (typed inbound chat fields and the error boundary), #567 (bounded SDK reception memory and the exact C-DLV frame, filter, event-key and outcome rules), #579 (the peer-declared introduction name kept apart from the local alias). The review was model-assisted, not a human audit.

Other behaviour named in this document as residual (§4.1 to §4.4, the declared limits of §6) is not resolved by this document or by those corrections.

## 6. Declared limits

These limits are declared in C-DLV and pinned by tests; they are behaviour of the current code, not defects hidden by this document.

| Review label | Behaviour | Where declared |
| --- | --- | --- |
| H7 | The KeyPackage fetch chooses among the answers received within its wait; a relay silent for the whole wait does not contribute. | C-DLV §5.5 |
| H9 | A failed join of the first passing Welcome ends the acceptance; no later candidate is tried. | C-DLV §7.1 |
| H15 | A failed `startSession` is not rolled back in the caller's engine. | C-DLV §11 |
| H17 | Without `ports.receiveState`, a failed open keeps its event id processed in the duplicate window. | C-DLV §8 |
| H18 | The start-up `storage.list()` inspection is synchronous, in two ordered passes, linear in the listed data. | C-DLV §5.2 |

## 7. Known documentation limits

The documents below carry statements that a reader can take for current state. They concern ratification records or contracts and are not changed by this document; read them with these notes.

- `docs/architecture/m3/scenarios/README.md` cites the C-SDK and C-DLV bytes it was derived from by SHA-256. Those are historical hashes of earlier versions, not the current files (interface 0.4.0, wire 0.3.0). Conformance of the current files to the scenarios needs its own check; the scenarios are not evidence for bytes they did not read.
- `docs/architecture/m3/flegias-preview.md` §1 cites historical C-SDK and C-DLV hashes and their ratifications in the same way.
- `docs/PROJECT_BRIEF.md` has two phase readings: its active-hardening section says the freeze was not lifted, while its later phase-exit marker says `BOUNDED_GO` with the broad freeze ended for separately authorized work. Neither authorizes product or sensitive use. Its funded "reliable delivery" milestone (persistent outbox, crash recovery) is future work; the M3 early lane keeps outbound items in memory and does not satisfy it.
- `docs/architecture/m3/delivery-layer.md` §11 lists relays and network observers together when it names visible metadata; §3.8 above distinguishes the two vantage points.

## 8. Invariant index

Each invariant below is a pass/fail property that an audit can check against the code and contracts. "Conditional" ones apply only with `ports.receiveState`.

- **TM3-INV-01**: No secret key crosses the SDK boundary; SDK signing uses only `identity.sign({ digest })`.
- **TM3-INV-02**: No inbound kind-4741 or kind-4742 event reaches opening, duplicate handling or receipt processing before the closed checks of C-DLV §7.1.
- **TM3-INV-03**: Invitation cryptography is delegated: the SDK checks only the outer structure of KeyPackages and gift wraps, and a failed join may consume the KeyPackage with no rollback.
- **TM3-INV-04**: An accepted Welcome has the explicit inviter as seal signer and rumor `pubkey`, and names an unexpired own KeyPackage.
- **TM3-INV-05**: The shared volatile inbound queue (raw frames, the frame in validation and waiting messages) is bounded by 1 024 entries and 16 777 216 cost units, plus the single active open/delivery unit; the transport's earlier JSON decoding is not bounded.
- **TM3-INV-06**: EOSE is never proof of completeness; a durable cursor is committed only after the barrier of C-DLV §5.4 (conditional).
- **TM3-INV-07**: A kind-4741 id is durably staged before `openCandidate`, and a committed id is never opened again (conditional).
- **TM3-INV-08**: An uncertain `commit` pauses until `resolve`; a `commit` refused for capacity leaves the entry `PENDING`; a `commit` refused for failure or conflict, and a refused or uncertain `stage`, `ack`, `receiptDone` or `commitCursor`, is fail-stop for the client's lifetime, with no fallback to the volatile path (conditional).
- **TM3-INV-09**: Quotas stop admission without deleting anything; there is no per-sender fairness (conditional).
- **TM3-INV-10**: The outbound queue is in memory only: `LOST_ON_SHUTDOWN` on orderly shutdown, nothing after a crash, and no resume of a stored item.
- **TM3-INV-11**: Relay acceptance, recipient receipt and human reading are never inferred from one another.
- **TM3-INV-12**: The reference PWA service worker updates with `autoUpdate`, `skipWaiting()` and `clients.claim()`, so origin control is code control.
- **TM3-INV-13**: Notifications carry generic text only, and the push handler never reads `event.data`.
- **TM3-INV-14**: The URL parameters `local`, `relay`, `bridge` and `ns` are hostile input to the reference PWA.

## 9. Non-claims

This document claims no security property beyond those its cited contracts state, and it does not make the SDK or the PWA a product. Relays are untrusted: they can read whatever the session port leaves readable and every routing field. Styx is not a zero-metadata system, the SDK does not hide identities, and the PWA is not authorized for sensitive use.

These statements stay in force verbatim:

- "Styx is under active development and has **not** completed an independent security audit. Do not use current builds for sensitive, high-risk, or life-critical use."
- "C0.3 remains `NO-GO` for implementation alignment, demo, product, and sensitive use."
