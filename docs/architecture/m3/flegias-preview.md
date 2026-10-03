# M3 early-lane Flegias preview (synthetic data only) contract

Status: normative candidate for card `C-PREV` of the M3 early lane. It fixes the Flegias preview (synthetic data only) before any preview code exists. Preview code (card `P-PREV`) is written only after the owner hash-ratifies the SHA-256 of this exact file and every `beforePreviewCode` gate of the M3 scope record holds: this file hash-ratified and merged into `m3/integration`, `I-SDK` merged and `T-RELAY` merged.

## 1. Scope and boundaries

This document fixes, for the Flegias preview (synthetic data only) authorized by the separate clause §3 of the owner act in Issue #400: the single-reply flow under a per-case key, the property the preview may state (§2, verbatim), the exact handler-side input fields that the property covers, the runtime, the exact files and imports, the labelling, the not-a-demo and no-deployment conditions, and the non-claims. **MUST**, **MUST NOT** and **REJECT** are normative. `C-PREV` writes only this document; it writes no preview code, test, example or harness.

The preview is a synthetic test fixture built on the early-lane SDK. It uses only the public SDK interface `docs/architecture/m3/sdk-interface.md` (card `C-SDK`, SHA-256 `47f75d6cd0bd3d542fd699f99144da6ccd9d6965908e5d1f4b2c1dfd976a9a11`, ratified in #400 comment `5960945402`), called "the interface" below, and the delivery behaviour fixed by `docs/architecture/m3/delivery-layer.md` (card `C-DLV`, SHA-256 `9ffd2accd7bf715d87728bc484669b70501d10c198707f15c4ce12b3935cf1b8`, ratified in #400 comment `5965357982`), called "the delivery layer" below. Both are merged into `m3/integration`; their section numbers are cited as "interface §n" and "delivery layer §n". This document adds, removes or renames nothing of either: no entry point, configuration field, method, result code, delivery state, transition, per-relay outcome, event kind or field, port method, bound, on-wire structure or allowed import of the SDK. Where this document and either of them could be read differently, they win, and the difference is a defect of this document.

It is not protocol authority. It introduces no cryptographic construction, selects no Styx protocol semantic, no Marmot or Nostr envelope standard and no normative wire or persisted format. Its only cryptographic operations are BIP-340 Schnorr key generation, public-key derivation and signing inside the preview's identity ports (§6.2), public-key derivation in the test file to obtain the public values of §8.1 (§6.3), and SHA-256 event-id recomputation in the test relay (§7), the constructions the existing transport code already uses for Nostr events; everything on the wire is the SDK-internal structure of delivery layer §6.

## 2. The property (verbatim copy of act §3)

The paragraph between the two markers below is a byte-for-byte copy of the property paragraph of #400 §3, as the act requires (its SHA-256, without a line terminator, is pinned in the record of §10). It is the only place in this document where the word that the act restricts appears; no `P-PREV` file carries a copy.

<!-- styx-m3-act400-s3-property:verbatim:start -->
The only property the preview may state is this: **the handler's software receives no reporter identifier that exists outside this case.** Concretely, the property covers only the explicit software inputs of the handler-side code: the case public key, the case messages and the relay metadata of those messages, with exact fields fixed by the preview contract. It does not cover logs, errors, timing, the process environment, network observation or other side channels. The preview tests assert that none of those explicit inputs contains a key or identifier the reporter-side code used in any other synthetic case or outside the preview. Relays, network observers and the handler's network path see keys, timing and network metadata. No anonymity, unlinkability or unobservability is claimed. The case key and the reply address are preview mechanisms. They are not the Milestone 4 per-case identity or return capability and carry no guarantee. The word "anonymous" in any form does not appear in preview screens, files, card text or progress reports, except inside a verbatim copy of this paragraph. The preview contract carries this paragraph verbatim.
<!-- styx-m3-act400-s3-property:verbatim:end -->

Outside that copy, no text of this document, of the `C-PREV` contract Issue, of any `P-PREV` file, or of any progress report about the preview matches the case-insensitive pattern that the scope record's `blockSemantics` forbids. `P-PREV` files refer to this section instead of copying the paragraph.

The preview states the property above and nothing stronger. The exact fields it covers are fixed in §5; the tests that assert it are fixed in §8. A representation of an identifier that the tests of §8 do not scan is a limit of the verification, not an exclusion from the property: the property is stated for every representation, and the tests check the representations listed in §8.

## 3. Labelling, not a demo, no deployment

- **Label.** Every screen, document, test name and progress report of the preview calls it exactly `Flegias preview (synthetic data only)`. It is not the Milestone 4 Flegias alpha. It makes no Milestone 4 claim: no per-case identity guarantee, return capability, multi-turn dialogue, roles or revocation.
- **Synthetic data only.** No real report, person, organization or contact detail is entered, stored, logged or published. Every key and identifier is generated by the test run and discarded with it; every payload is one of the fixed synthetic texts of §4.3; no synthetic value is read from the environment, the file system, the network outside the loopback relays, or a user. The only file-system access of the preview is the read-only hygiene check of `A7` (§8), which reads the six preview files of §6.2 and nothing else.
- **Not a demo.** The preview is a synthetic test fixture, not a demo in the sense of the C0.3 `NO-GO` and #287. It is not presented to third parties as a Styx capability, not hosted, and not shown outside local and CI runs and the owner's progress reports, which describe it only with the label and limits of this document.
- **No deployment.** It runs locally and in CI only, inside one Jest process, against loopback relays that the test starts. It has no screen, server, page, package entry point or published artifact. Public hosting or any deployment is a separate owner act.

## 4. Flow

### 4.1 Roles and synthetic identifiers

All roles run in one Jest process, as separate SDK clients created with `createStyxClient` (interface §4.1), each with its own fresh ports (§6.2):

| Role | Code side | Identity key | Purpose |
| --- | --- | --- | --- |
| Handler | handler-side | `H`, one synthetic handler key per test run | receives case messages, replies once per case |
| Case reporter | reporter-side | `C_k`, a fresh key generated for case `k` only | opens case `k` and receives its reply |
| Outside reporter | reporter-side | `R`, one synthetic key per test run that stands for a reporter identifier existing outside every case | sends one synthetic outside message per case to the bystander key `B` |

`B` is a synthetic bystander public key that the test file derives with `schnorr.getPublicKey` from a secret key it generates with `generateSecretKey` (§6.2), keeps only for the forbidden set of §8.1, and passes to the reporter-side code as the outside recipient; no client runs under it. The test file also generates `T` with `randomBytes(16)`, a synthetic outside token that stands for a reporter identifier existing outside the preview (for example an account identifier), and passes it to the reporter-side code, where it appears only in the outside message payload (§4.3). Both are values the reporter-side code uses. `H` is given to the reporter-side code as configuration, as a published handler key would be. No other key or identifier is generated by the preview. Below it, the SDK generates the event `n` tags and subscription ids of delivery layer §5.4 and §6, and the `ws` WebSocket implementation generates, for every socket, a 16-byte `Sec-WebSocket-Key` that it sends in the upgrade request, and a 4-byte masking key for every frame. The forbidden set of §8.1 covers the `n` tags, subscription ids and `Sec-WebSocket-Key` values; masking keys stay inside WebSocket framing, which is network observation (§5.4), and at 4 bytes are below the length of every forbidden value.

`C_k` is generated by `schnorr.utils.randomPrivateKey()` at the start of case `k`, is used by exactly one client (the case reporter of case `k`), and is never reused, derived from another key, or derived from `R`, `T` or `B`. The test keeps its public value, and the evidence of §8, in memory until the assertions of both cases have run, then drops them.

The outside reporter, its message to `B` and the token `T` are a test fixture that the act's required assertion needs (a reporter identifier that exists outside the case must be present for the test to show that it does not reach the handler). They are not part of the case flow: the case flow is exactly the three act steps of §4.3 (open, reply once, receive), and the outside message is not addressed to the handler.

### 4.2 Relays and cases

The test runs exactly two synthetic cases, `k = 1` and `k = 2`, one after the other. For each case it starts two fresh loopback relays (§7) and stops them at the end of the case, so no relay holds an event of another case. The relays of a case are shared by every client of that case, so the outside message of the case reaches the same relays as the case messages.

### 4.3 Steps of case `k`

1. The test starts the two relays of case `k`.
2. In parallel it creates and starts three clients (interface §4.2 `start()`), each configured with the two relays of case `k` in the same order and with its own role path (§7): the handler (identity `H`), the case reporter (identity `C_k`) and the outside reporter (identity `R`). Each `start()` MUST resolve success.
3. Fixture: the outside reporter sends one message to `B` with the payload `Flegias preview (synthetic data only): synthetic outside message <k> <T as lowercase hex>` (UTF-8), and the test waits until its item is `RELAY_ACCEPTED` (the default receipt mode, delivery layer §3). This places an outside identifier on the same relays before the case opens.
4. **Act step 1, open.** The case reporter sends one message to `H` with the payload `Flegias preview (synthetic data only): synthetic case <k> opening text.` (UTF-8). This is the case-opening message.
5. **Act step 2, reply once.** The handler-side code waits for its first `MESSAGE_RECEIVED` event. It MUST have `sender` equal to `C_k` and `payload` equal to the case-opening bytes; anything else fails the test. The handler-side code then calls `send({ recipient: sender, payload })` exactly once with the payload `Flegias preview (synthetic data only): synthetic reply to case <k>.` (UTF-8). The `sender` value is the reply address. A later `MESSAGE_RECEIVED` with the same `sender` and payload (a duplicate, interface §4.3) causes no further send; any other later `MESSAGE_RECEIVED` fails the test.
6. **Act step 3, receive.** The case reporter waits for a `MESSAGE_RECEIVED` event with `sender` equal to `H` and `payload` equal to the reply bytes, and the test waits until the reply's item is `RELAY_ACCEPTED`. The reporter receives the reply under `C_k` only: its client's identity port holds only the secret key of `C_k`, its subscription is the one the delivery layer opens for its own public key (delivery layer §5.4), and no other reporter-side value is configured on that client.
7. The test calls `shutdown()` on the three clients, which MUST resolve success, records the socket state of `A6`, then stops the relays, and keeps the captures of §5 and §7 for case `k` in memory. The shutdown of every client created and the stop of every relay started run in a `finally` block, so they also run after a failure; a failure is reported after that cleanup.

After both cases, the test evaluates the assertions of §8 for each case, with the complete forbidden sets that both cases determine.

The flow has exactly one case-opening message and exactly one reply per case. It has no receipt (every client uses the default `RELAY_ACCEPTANCE_ONLY` mode, so no event carries an `r` tag, delivery layer §6.2), no second turn, no roles beyond the three above and no revocation. A need for more than this single-reply flow stops the lane for owner rescope (#400 §8).

### 4.4 Configuration of every client

`config` is exactly `{ interfaceVersion: SDK_INTERFACE_VERSION, relays: [<relay 1 URL>, <relay 2 URL>], ports: { storage, session, identity } }`. `clock`, `random` and `delivery` are absent, so the built-in clock and randomness and the defaults of delivery layer §3 apply (`perRelayTimeoutMs` 12 000, so each `start()` resolves at the end of its 12 000 ms connection phase, plus host scheduling, delivery layer §5.2). Both relay URLs are built from the loopback IP literal, the ephemeral port the relay reports, and the client's role path (§7).

## 5. Handler-side code and the covered input fields

### 5.1 Handler-side code

The handler-side code is: the handler's SDK client (the `I-SDK` client object and everything it runs for the handler, including its `RelayPool` instances), the handler's three ports (§6.2), the handler's event listener, and the handler logic in `styx-js/examples/flegias-preview/handler.js`. Every other client of the run is reporter-side code, together with `styx-js/examples/flegias-preview/reporter.js`. The test file and the test relay are neither; they observe both sides.

### 5.2 Covered fields

The property of §2 covers exactly these explicit software inputs of the handler-side code, in the three categories the act names:

| Id | Act category | Exact field | Where the test captures it |
| --- | --- | --- | --- |
| `H1` | the case public key | `sender` of every `MESSAGE_RECEIVED` event delivered to the handler listener, and `sender` of every `session.open` call on the handler's session port | handler listener; handler session port |
| `H2` | the case messages | `payload` of every `MESSAGE_RECEIVED` event delivered to the handler listener, and `ciphertext` of every `session.open` call on the handler's session port | handler listener; handler session port |
| `H3` | the relay metadata of those messages | every `EVENT` and `OK` frame that a relay of the case sends on a connection of the handler client, whole, with every field: for `EVENT` frames the subscription id and the event's `id`, `pubkey`, `created_at`, `kind`, `tags` (every tag name and value), `content` and `sig`; for `OK` frames the event id, the boolean and the message. These are the frames that deliver the case messages to the handler and that answer the handler's reply | test relay, per connection, and the client socket recorder, per socket (§7); the scan covers the union of both |

`H3` covers every `EVENT` and `OK` frame that a relay of the case sends to the handler client: the frames that carry the case messages to it (including any replay of a stored event) and the frames that answer its reply. On the fresh relays of a case these are the only `EVENT` and `OK` frames the handler client can receive. `H3` nevertheless includes any other `EVENT` or `OK` frame sent to the handler client, so that the property scan covers every such frame whatever it carries; in addition, `A1` requires that the handler-bound `EVENT` frames of case `k` are exactly the case-opening event (and relay copies of it) and the `OK` frames are exactly those that answer the reply. `RelayPool` decodes each such message with `JSON.parse` before the SDK sees it, so the scan of §8 covers both the message text and every decoded value. Bytes that the handler client receives below the WebSocket message level (TCP and WebSocket framing and handshake) are network observation and are not covered.

### 5.3 Additionally scanned values

The tests also scan `H4`: every other text message that a relay of the case sends on a connection of the handler client (`EOSE`, `NOTICE`, `CLOSED` and any other frame), every SDK event delivered to the handler listener, whole (including `CLIENT_STATE_CHANGED` and `DELIVERY_STATE_CHANGED`), every result envelope that the handler logic receives from the handler client, and every argument of every call to the handler's storage, session and identity ports. `H4` overlaps `H1` and `H2`. Scanning it is a strength measure of the tests only (assertion `A9`, separate from the property assertion `A2`); the property is stated for `H1` to `H3` and for nothing else, and the scan of `H4` extends no claim.

### 5.4 Not covered

As the act states, the property does not cover logs, errors, timing, the process environment, network observation or other side channels. It also does not cover what relays, network observers or the handler's network path see: they see `C_k`, `H`, `R`, `B`, the tags, the payload bytes (the session port of the preview provides no confidentiality, §6.2), timing, sizes and network metadata, and they can relate the events of a case and of its outside message by connection and time. No such relation is claimed absent.

## 6. Runtime, files and imports

### 6.1 Runtime

The runtime is a **Jest-driven run**: one Jest test file under `styx-js/test/sdk/flegias-preview/**`, run by the existing `npm test` of `styx-js` (locally and in the existing `styx-js web` CI job), in Node 20 or later, the version that CI job sets up (`node-version: '20'`). Before it generates any value or creates any client, the test asserts that `globalThis.crypto.getRandomValues` is a function (Node 20 provides it as a global; `utils.randomBytes`, `schnorr.utils.randomPrivateKey` and the SDK's default randomness need it) and fails otherwise; it imports no `node:crypto`. It installs the client socket recorder of §7, a subclass of the `ws` WebSocket implementation, as the global `WebSocket` before any client is created, as delivery layer §10 requires for Node. There is no Node script entry point, no static page, no server and no browser run.

The whole run is one Jest test with a timeout of 300 000 ms, passed as the third argument of `test`, which takes precedence over the `--testTimeout=20000` of the CI command `npm test -- --runInBand --testTimeout=20000` (`.github/workflows/styx-js-web.yml`, step "Unit + app tests"): each case takes about one per-relay timeout (§4.4) plus the deliveries, and the assertions of §8 run after both cases. This changes no configuration of the repository. The test body never relies on that outer timeout for cleanup: every wait of §4.3 (for a `start()`, a delivery state, a `MESSAGE_RECEIVED` event, a `shutdown()`) has its own host-timer deadline of 30 000 ms, bounded by a run deadline of 200 000 ms from the start of the test, and rejects inside the test body when it expires or when the awaited item reaches a terminal state other than the one awaited; the close wait of `A6` and of §7 has a deadline of 40 000 ms. Cleanup (§4.3 step 7) therefore always runs inside the test body, with at least 60 000 ms left before the outer timeout. The test also checks, before the two cases and without any client, relay or key, that the wait helper rejects at its deadline on a promise that never settles; this check generates no identifier and is not a case.

### 6.2 Files

`P-PREV` writes exactly these files, all new, inside its allowlist, and no other file:

| File | Exports | Content |
| --- | --- | --- |
| `styx-js/examples/flegias-preview/README.md` | — | The label, a short description of the flow of §4, a reference to this document for the property and its limits (§2), the non-claims of §9 and the verbatim statements of §9. No copy of the §2 paragraph. |
| `styx-js/examples/flegias-preview/ports.js` | `generateSecretKey`, `createPreviewPorts` | `generateSecretKey()` returns `schnorr.utils.randomPrivateKey()`. `createPreviewPorts({ secretKey, recorder })` returns `{ storage, session, identity }` for one client: an in-memory storage port (one `Map`, implementing `put`, `get`, `update`, `remove` and `list` exactly as interface §8.1 defines); a pass-through session port whose `seal` returns `{ ciphertext }` with a copy of `plaintext` and whose `open` returns `{ plaintext }` with a copy of `ciphertext`; an identity port whose `getPublicKey()` returns the lowercase hex of `schnorr.getPublicKey(secretKey)` and whose `sign({ digest })` returns `schnorr.sign(digest, secretKey)`. `recorder`, when given, receives the port name, the method name and a copy of the arguments of every call (used by the test for `H1`, `H2`, `H4`). The secret key never leaves the identity port's closure and is never passed to the recorder. |
| `styx-js/examples/flegias-preview/handler.js` | `runHandler` | The handler logic of §4.3 step 5 over a client it creates from given relay URLs, ports and recorder; it passes every SDK event and every result envelope it receives from that client to the recorder (`H4`), resolves when its one reply is `RELAY_ACCEPTED` and exposes a `shutdown` function. |
| `styx-js/examples/flegias-preview/reporter.js` | `runCaseReporter`, `runOutsideReporter` | The case reporter logic of §4.3 steps 4 and 6 and the outside reporter fixture of step 3, over clients they create from given relay URLs, ports and payload values; each exposes a `shutdown` function. |
| `styx-js/test/sdk/flegias-preview/loopback-relay.js` | `startLoopbackRelay` | The test relay of §7, used only by the test file below. |
| `styx-js/test/sdk/flegias-preview/flegias-preview.test.js` | — | The two cases of §4 and the assertions of §8. |

The pass-through session port means the preview has no payload confidentiality, which interface §8.2 allows and nothing here claims. The preview persists nothing: the storage port is a `Map` in memory, and no file, database, browser storage or environment variable is written. Every file starts with a comment or heading that carries the label of §3.

### 6.3 Exact imports

Each `P-PREV` file imports exactly the specifiers and names below and nothing else (scope record `importRule` and `noImport`; #400 §2(c)). Dynamic `import()` and `require()` are not used. No file imports `styx-js/src/sdk/client.js`, any module under `styx-js/src/sdk/delivery/**`, any file under `styx-js/src/transport/**`, `styx-js/src/storage/**`, `styx-js/src/crypto/**`, `styx-js/src/config/**` or `styx-js/apps/**`, or any file under `styx-js/test/sdk/**` outside `styx-js/test/sdk/flegias-preview/**`.

| Importing file | Specifier (resolved path) | Names | Operation |
| --- | --- | --- | --- |
| `ports.js` | `@noble/curves/secp256k1` (declared runtime dependency) | `schnorr` | only `schnorr.utils.randomPrivateKey`, `schnorr.getPublicKey` and `schnorr.sign`, inside the identity port and `generateSecretKey` |
| `ports.js` | `styx-js/src/utils.js` | `bytesToHex` | public key as lowercase hex |
| `handler.js` | `styx-js/src/sdk/index.js` | `SDK_INTERFACE_VERSION`, `createStyxClient`, `SdkEventKind`, `DeliveryState` | the public SDK entry points of interface §4 |
| `handler.js` | `styx-js/src/utils.js` | `utf8Encode` | reply payload |
| `reporter.js` | `styx-js/src/sdk/index.js` | `SDK_INTERFACE_VERSION`, `createStyxClient`, `SdkEventKind`, `DeliveryState` | the public SDK entry points of interface §4 |
| `reporter.js` | `styx-js/src/utils.js` | `utf8Encode`, `bytesToHex` | payloads, `T` as hex |
| `loopback-relay.js` | `ws` (declared development dependency) | `WebSocketServer` | loopback relays |
| `loopback-relay.js` | `@noble/hashes/sha256` (declared runtime dependency) | `sha256` | event-id recomputation (§7) |
| `loopback-relay.js` | `styx-js/src/utils.js` | `bytesToHex`, `utf8Encode` | event-id recomputation (§7) |
| the test file | `styx-js/examples/flegias-preview/ports.js` | `generateSecretKey`, `createPreviewPorts` | identities, the secret key of `B`, and ports |
| the test file | `styx-js/examples/flegias-preview/handler.js` | `runHandler` | handler side |
| the test file | `styx-js/examples/flegias-preview/reporter.js` | `runCaseReporter`, `runOutsideReporter` | reporter side |
| the test file | `styx-js/test/sdk/flegias-preview/loopback-relay.js` | `startLoopbackRelay` | the relay of §7 |
| the test file | `styx-js/src/sdk/index.js` | `ClientState`, `DeliveryState` | state assertions |
| the test file | `styx-js/src/utils.js` | `bytesToHex`, `hexToBytes`, `utf8Encode`, `bytesToBase64`, `base64ToBytes`, `randomBytes` | `T`, `B`, and the encodings of the scan of §8 |
| the test file | `@noble/curves/secp256k1` (declared runtime dependency) | `schnorr` | only `schnorr.getPublicKey`, to derive the public values `H`, `C_k`, `R`, `B` for the forbidden sets, the ownership checks of `A4` and `A5` |
| the test file | `@jest/globals` (declared development dependency) | `describe`, `test`, `expect` | test runner |
| the test file | `ws` (declared development dependency) | `WebSocket` | subclassed as the client socket recorder (§7) and installed as the global `WebSocket` |
| the test file | `node:fs` (Node built-in) | `readFileSync`, `readdirSync` | the read-only hygiene check `A7` only |
| the test file | `node:url` (Node built-in) | `fileURLToPath` | locating the preview files for `A7` only |
| the test file | `node:async_hooks` (Node built-in) | `AsyncLocalStorage` | the socket owner records of §7 only |

Files under `styx-js/examples/flegias-preview/**` import no `node:` built-in; they use only language globals and `setTimeout`, `clearTimeout`, `Promise`, `Uint8Array`, `Map`, `Set` and `JSON`. `loopback-relay.js` imports no `node:` built-in. No file adds a dependency or changes `styx-js/package.json`, a lockfile, `styx-js/vendor/**`, a pin or a ciphersuite.

## 7. Loopback relay

`loopback-relay.js` builds each relay with `WebSocketServer` from `ws`, listening on `127.0.0.1` with port `0` (an ephemeral port the operating system chooses), within the requirements of delivery layer §10 that apply to a single relay behaviour. Relay URLs are built from that address, the port the server reports, and one role path: `ws://127.0.0.1:<port>/handler`, `ws://127.0.0.1:<port>/case-reporter` or `ws://127.0.0.1:<port>/outside-reporter`. The test gives each client only the URLs with its own role path (interface §4.1 allows a path; `RelayPool` opens each connection with `new WebSocket(url)` on the URL as configured, `styx-js/src/transport/nostr-transport.js`). These role paths are URL paths, not file-system paths. Before any message is exchanged, the relay checks that the request path of every connection is one of the three role paths, and the test fails otherwise (`A4`). No file of the preview contains any other `ws://` or `wss://` URL, host name or relay list. The relay implements the NIP-01 subset that the delivery layer uses: `EVENT` (recompute the event id as delivery layer §6.1 defines it, with `sha256`; answer `["OK", <id>, false, "invalid: id"]` when it differs, otherwise store the event and answer `["OK", <id>, true, ""]`), `REQ` with `kinds`, `#p` and `ids` filters (send stored matches, then `EOSE`, then forward live matches), and `CLOSE`. It does not verify signatures (as in delivery layer §10). It does not use the `styx-js/docker-compose*.yml` relay infrastructure or any image.

**Attribution.** The relay attributes each WebSocket connection to a role by the request path of its upgrade request, read in the `connection` event before any message is exchanged; this attribution is fixed by the test configuration and does not depend on anything the client sends. A connection with any other path is refused and fails the test (`A4`). As a cross-check, the first `REQ` on a connection MUST carry exactly one `#p` value, equal to `H` on handler connections, `C_k` on case-reporter connections and `R` on outside-reporter connections; a mismatch fails the test (`A4`). Replacement connections of a client (delivery layer §5.2) use the same URLs and are attributed the same way.

**Capture.** For each connection the relay records the `Sec-WebSocket-Key` header of the upgrade request and, in order, every WebSocket message it sends and every WebSocket message it receives, each with its type (text or binary) and its exact bytes, with the connection's role. The test relay sends text messages only.

**Client socket recorder.** Independently of the relay, the test installs as the global `WebSocket` a subclass of the `ws` `WebSocket` defined in the test file. Ownership of a socket is established without the URL: the test creates and drives each client (each call of `runHandler`, `runCaseReporter` and `runOutsideReporter`, and every later call on the returned object) inside `AsyncLocalStorage.run` from `node:async_hooks` with an owner record `{ role, case, publicKey }`, and the recorder's constructor reads that record with `getStore()`. Host timers and promise continuations keep the record, so reconnection sockets that `RelayPool` opens later from a timer carry the same owner. A socket constructed with no owner record fails the test. For every socket the recorder records the owner, the URL and, in order, every WebSocket message the socket receives and every message the client sends on it, each with its type (text or binary) and its exact bytes, and every call to `close()`, before passing each one through unchanged. It changes no behaviour of the socket. The relay capture and the client socket recorder are two separate records of the same traffic; they are matched by relay URL and by opening order of the sockets with the same URL (the SDK opens at most one socket per relay at a time for a client, and a replacement after the previous one, delivery layer §5.2). A binary message in either record fails the test (`A4`): the unchanged `RelayPool` would pass its bytes to `JSON.parse` like a text message, so a binary message could carry a covered frame past a text-only scan. A record is final only when its socket has reached the `CLOSED` state on both ends, after which neither end can add to it; that state alone does not show that every message was delivered, which is why `A4` compares the records message by message. The test awaits that state with the close deadline of §6.1 before it compares the records; a socket that does not close by then fails the test.

A socket belongs to the handler client when its owner record says so, whatever its URL; a relay connection belongs to the handler when it is matched to such a socket or when its path is `/handler`. `H3` is every `EVENT` and `OK` frame sent to the handler client, in either record: the relay's sent messages on every connection that belongs to the handler, and the messages received by every socket that belongs to the handler client. Every other message sent to the handler client is in `H4` (§5.3). The forbidden values of §8.1 that are read from captures are read from the union of both records.

## 8. Required tests (normative for `P-PREV`)

### 8.1 Forbidden values

For each case `k`, the forbidden set `F_k` is every reporter key and identifier that the reporter-side code used other than in case `k`, enumerated here; it includes the `Sec-WebSocket-Key` values, which go beyond the act's minimum and only strengthen the assertion:

- the public keys `R`, `B` and `C_j` for every case `j ≠ k`;
- the secret keys of `R` and `C_j` for every case `j ≠ k`;
- the token `T`;
- the event `id`, `sig` and `n`-tag value of every event that a reporter-side client published or received, other than the events of case `k`, read from the captures of §7: every outside message of every case (the outside reporter stands for a reporter identity that exists outside every case, so its events, including the one it publishes while case `k` runs, are not events of case `k`), every case-opening event of a case `j ≠ k`, and every handler reply of a case `j ≠ k` (which the case reporter of case `j` received and validated). The events of case `k` are the events that the case reporter of case `k` published and the events that the handler published to `C_k`;
- the subscription id of every connection attributed to a reporter-side client other than the case reporter of case `k`, read from the captures of §7;
- the `Sec-WebSocket-Key` (the 16 bytes its base64 header value decodes to) of every socket whose owner record (§7) is a reporter-side client other than the case reporter of case `k`, read by the test relay from the upgrade request in its `connection` event and bound to the owner through the one-to-one match of relay connections and client sockets of §7. This value is generated by the WebSocket implementation of a reporter-side client and sent by it to identify one of its connections, so it is an identifier that the reporter-side code used.

In addition, `S_k` is the secret key of `C_k`, used in case `k` inside the case reporter's identity port only, and `S_B` is the secret key of `B`, which the test file holds only to derive `B` and no client uses. Neither is a value of the act's assertion; the tests check that neither reaches a covered input (`A9`), as a strength measure that extends no claim.

Not forbidden, because they are not reporter identifiers that exist outside case `k`: `C_k`, the events of case `k` and the subscription id of the case reporter of case `k` (they belong to the case); `deliveryId` values (a client-scoped queue handle, `d` followed by a per-client counter that starts at 1, which every client of the run therefore also has, and which never appears on the wire, delivery layer §4.2); `H` (the handler's own key, which the reporter-side code holds as a published handler key), relay URLs and ports (relay endpoints; fresh relays can reuse a port number), the interface version string, kinds, constant tag names and `created_at` values.

### 8.2 Occurrence rule

A forbidden value is a byte string of 16 bytes (`T`, `n` tags, `Sec-WebSocket-Key` values), 32 bytes (public keys, secret keys, event ids) or 64 bytes (signatures), or a subscription id, the letter `s` followed by 32 lowercase hexadecimal digits from `randomBytes` (delivery layer §5.4), which the rule below treats both as the string itself and as the 16-byte value of its hexadecimal digits. Every forbidden value therefore carries at least 128 random bits, so a coincidental occurrence in the captures of a correct run has negligible probability. The scan inputs of a covered field are:

- **text inputs:** every string value of `H1` and `H2` (`sender` values are strings; byte values are scanned as byte inputs below); every captured relay message as received on the wire; every string obtained by `JSON.parse` of that message, recursively, including object keys; and, for `H4`, the JSON rendering of each value with byte arrays rendered as lowercase hex;
- **byte inputs:** every byte array of `H1`, `H2` and `H4`, the `base64ToBytes` decoding of the `content` of every `EVENT` frame of `H3` (when it decodes), and the embedded-base64 decodings of every text input: for every maximal run of characters of the standard base64 alphabet (`A`–`Z`, `a`–`z`, `0`–`9`, `+`, `/`) and every maximal run of the URL-safe alphabet (`-` and `_` instead of `+` and `/`) in a text input, and for each start offset 0, 1, 2 and 3 into that run, the bytes obtained by decoding all the remaining characters of the run, normalised first: URL-safe characters are mapped to standard ones, `=` padding is not part of the run and is never carried over, and, when the count of the remaining characters leaves a remainder of 1 modulo 4, the last character, which cannot carry a whole byte, is dropped; when it then leaves a remainder of 2 or 3, the missing `=` padding is added, so a final group of two or three characters yields its one or two bytes. Every normalised string is valid base64 and MUST decode with `base64ToBytes`; a decoding error fails the test (`A3` exercises padded and unpadded inputs at every offset). These decodings find a value that is embedded in a base64 string after or before other bytes at any alignment, which the whole-value base64 forms of the rule below do not.

A value occurs in a text input when its hex form occurs case-insensitively, or its standard base64 form or its URL-safe base64 form, each with or without padding, occurs, or (for a subscription id) the string itself occurs; it occurs in a byte input when its raw bytes, or the UTF-8 bytes of any of those text forms, occur as a contiguous subsequence. The same rule applies to every kind of value. Because text inputs include the `JSON.parse` results, JSON escape sequences (for example `\u0061`) do not hide a value, and the embedded-base64 decodings are taken from those results as well. The scan has no size or time budget: it runs over every input completely, and an input that it cannot process (for example a capture that is not valid UTF-8 where text is expected) fails the test instead of being skipped.

The payload texts of the cases and of the outside messages are fixed synthetic strings, not identifiers; the identifiers they carry (`T`) and the events that carry them (event `id`, `sig` and `n` tag) are in `F_k`, so a copied event of another case or an outside message, or an outside payload (which contains `T`), that reaches a covered input of case `k` is detected through them. The plaintext of another case's opening or reply alone carries none of these identifiers; it is a fixed synthetic text, not a reporter identifier, and `A1` checks separately that the handler receives no application payload other than the case-opening payload of case `k`.

### 8.3 Assertions

After both cases, the test file MUST assert, for each case `k`:

| Id | Assertion |
| --- | --- |
| `A1` | The flow of §4.3 completed: every `start()` and `shutdown()` resolved success; the handler received `MESSAGE_RECEIVED` with `sender` `C_k` and the case-opening payload, received no `MESSAGE_RECEIVED` with any other `sender` or payload (a repeated case-opening message is allowed, interface §4.3), and called `send` exactly once; in the records of §7, every `EVENT` frame sent to the handler client carries the case-opening event of case `k` and every `OK` frame sent to it answers the reply's event id; the case-opening item, the outside message item and the reply's item each reached `RELAY_ACCEPTED`; the case reporter received `MESSAGE_RECEIVED` with `sender` `H` and the reply payload. |
| `A2` | The property scan: no value of `F_k` occurs (§8.2) in `H1`, `H2` or `H3` of case `k`. |
| `A3` | The scan is not vacuous: for every kind of value (16-byte, 32-byte and 64-byte byte strings and a subscription id) and every representation of §8.2 (each hex case, each base64 variant with and without padding, raw bytes, the UTF-8 bytes of a text form, a JSON `\u` escape inside a captured message, and the value's raw bytes with a prefix of 0, 1 and 2 other bytes and a suffix of 0, 1 and 2 other bytes encoded together as one standard and one URL-safe base64 string, placed in the message field of a captured `OK` frame and in the `content` of a captured `EVENT` frame), the scan function reports a copy of the captured inputs of case `k` with one value of that kind planted in that representation as containing it, using planted values that do not occur in the original captures; the planted values include a handler reply id of the other case, a subscription id of the outside reporter and a `Sec-WebSocket-Key` of an outside-reporter socket placed in the message field of a captured `OK` frame; and the captures are not empty: `H3` of case `k` contains the case-opening `EVENT` frame (event `pubkey` `C_k`, `content` decoding to the case-opening payload) and the `OK` frame of the reply's event id, and `H1` contains `C_k`. |
| `A4` | Capture is complete: neither record of case `k` contains a binary message (§7); on both relays of case `k`, every connection is attributed by its path to exactly one role and its first `REQ` carries exactly the `#p` value of that role (§7); the handler, the case reporter and the outside reporter each have at least one connection; no connection is refused or unattributed; every client socket has an owner record (§7), its URL is one of the two URLs configured for that owner and carries the owner's role path, and every `REQ` it sends carries exactly one `#p` value, equal to the owner's public key; every `EVENT` that a client socket sends carries an event id that its owner's identity port signed, and every event id that a client's identity port signed is sent by that client only on its own sockets; the relay connections and the client sockets of case `k` match one to one (§7); and, for each matched pair, after both ends reached the closed state (§7), the messages the client socket received equal, in order, the messages the relay sent on that connection, and the messages the client sent equal, in order, the messages the relay received. A mismatch, a missing or an extra record in either direction fails the test. The test also checks, on a copy of the records of case `k`, that removing one relay-sent message to the handler, removing one outside-reporter publication, changing the role path of one handler socket while keeping its owner, and adding a handler-owned socket that only receives (no `EVENT` sent), uses the `/outside-reporter` path and a `REQ` with `#p` `R`, and receives the outside message, are each reported as a failure. |
| `A5` | Case-key separation: `C_1`, `C_2`, `R`, `B` and `H` are pairwise different; the identity port of the case reporter of case `k` reports `C_k`, and no other client of the run reports `C_k`. |
| `A6` | Loopback only and closed: every relay URL of the run starts with `ws://127.0.0.1:`; after each client's `shutdown()` resolved and before the test stops any relay, every socket that the client opened has had `close()` called by the client (the closure that delivery layer §5.5 defines, checked by the client socket recorder of §7, as delivery layer §10 requires), and then reaches the `CLOSED` state within the close deadline of §6.1; every client was `STOPPED` and every relay server was closed at the end of its case. |
| `A8` | Reply under the case key only (act §3 step 3): the case reporter's client was created with only the relay URLs of case `k` and ports built from `S_k`; and no value of `F_k` occurs (§8.2) in any message that a relay of case `k` sent or received on a connection attributed to the case reporter. |
| `A9` | Strength measure, not part of the property: no value of `F_k`, and neither `S_k` nor `S_B`, occurs (§8.2) in `H4` of case `k`, and neither `S_k` nor `S_B` occurs in `H1`, `H2` or `H3` of case `k`. |

And once for the run:

| Id | Assertion |
| --- | --- |
| `A7` | Text hygiene of the preview: no file under `styx-js/examples/flegias-preview/**` or `styx-js/test/sdk/flegias-preview/**` matches the case-insensitive pattern forbidden by the scope record's `blockSemantics`; every such file carries the label of §3; every Jest `describe` and `test` name starts with `Flegias preview (synthetic data only)`. The test lists and reads these files with `node:fs` and locates them with `node:url` (§6.3). It builds the forbidden pattern by joining two string parts, so that no file, the test file included, contains a match itself; since the test file is one of the files it reads, a match in its own source fails `A7`. |

A failing assertion fails the `styx-js web` job; no assertion is skipped, retried as success or marked expected-to-fail.

## 9. Non-claims and gates

The Flegias preview (synthetic data only) is a synthetic test fixture. It is not a demo, not a product, not audited, not deployed and not authorized for sensitive use. It states only the property of §2 for the fields of §5.2. It claims no payload confidentiality (its session port is a pass-through), no identity hiding, unlinkability, unobservability, padding, timing protection, onion routing or metadata protection, no exactly-once delivery, ordering or cross-restart reliability, and nothing about relays, network observers, logs, errors, timing, the process environment or other side channels. The case key and the reply address are preview mechanisms, not the Milestone 4 per-case identity or return capability, and carry no guarantee. No Milestone 4 element is implemented or claimed.

These statements stay in force verbatim:

- "Styx is under active development and has **not** completed an independent security audit. Do not use current builds for sensitive, high-risk, or life-critical use."
- "C0.3 remains `NO-GO` for implementation alignment, demo, product, and sensitive use."

The lane stops for owner rescope (#400 §8) if the preview needs real data, a new cryptographic construction, persisted state, more than the single-reply flow, deployment, an import outside §6.3, or a public relay.

## 10. Machine-readable normative record

The JSON below is normative and closed. Prose clarifies but does not widen it. Duplicate keys are invalid.

<!-- styx-m3-flegias-preview-json:v1:start -->
```json
{
  "schema": "styx-m3-flegias-preview/v1",
  "closed": true,
  "card": "C-PREV",
  "label": "Flegias preview (synthetic data only)",
  "sdkInterfaceDoc": { "path": "docs/architecture/m3/sdk-interface.md", "sha256": "47f75d6cd0bd3d542fd699f99144da6ccd9d6965908e5d1f4b2c1dfd976a9a11" },
  "deliveryLayerDoc": { "path": "docs/architecture/m3/delivery-layer.md", "sha256": "9ffd2accd7bf715d87728bc484669b70501d10c198707f15c4ce12b3935cf1b8" },
  "actPropertyParagraphSha256": "089d14b5d3d21af741c58cab3a04b950b530dc63cf8cc356521800e2b9bd5636",
  "sdkSurfaceChanged": false,
  "runtime": "jest",
  "nodeMin": 20,
  "testTimeoutMs": 300000,
  "waitDeadlineMs": 30000,
  "runDeadlineMs": 200000,
  "closeDeadlineMs": 40000,
  "cases": 2,
  "relaysPerCase": 2,
  "relayHost": "127.0.0.1",
  "rolePaths": { "handler": "/handler", "caseReporter": "/case-reporter", "outsideReporter": "/outside-reporter" },
  "clientConfigKeys": ["interfaceVersion", "relays", "ports"],
  "receiptMode": "RELAY_ACCEPTANCE_ONLY",
  "caseFlow": ["open", "replyOnce", "receive"],
  "fixtures": ["outsideMessage"],
  "assertionsAfterBothCases": true,
  "roles": {
    "handler": { "side": "handler", "key": "H" },
    "caseReporter": { "side": "reporter", "key": "C_k" },
    "outsideReporter": { "side": "reporter", "key": "R" }
  },
  "syntheticValues": ["H", "C_k", "R", "B", "T"],
  "socketOwnership": "AsyncLocalStorage owner record, independent of URL",
  "coveredFields": {
    "H1": "MESSAGE_RECEIVED.sender; session.open sender",
    "H2": "MESSAGE_RECEIVED.payload; session.open ciphertext",
    "H3": "every EVENT and OK frame sent to the handler client, relay record and client socket recorder"
  },
  "scannedNotClaimed": ["H4", "S_k", "S_B"],
  "forbiddenSet": ["R", "B", "C_j (j != k)", "secret keys of R and C_j (j != k)", "T", "id, sig and n tag of events reporter-side clients published or received outside case k, every outside message included", "subscription ids of reporter-side connections outside case k", "Sec-WebSocket-Key of reporter-side sockets outside case k"],
  "valueSizesBytes": [16, 32, 64],
  "encodings": ["hexCaseInsensitive", "base64", "base64url", "unpadded", "rawBytes", "utf8OfTextForm", "jsonDecoded", "subscriptionIdAsStringAndBytes", "embeddedBase64AllAlignments"],
  "assertions": ["A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9"],
  "files": {
    "styx-js/examples/flegias-preview/README.md": [],
    "styx-js/examples/flegias-preview/ports.js": ["generateSecretKey", "createPreviewPorts"],
    "styx-js/examples/flegias-preview/handler.js": ["runHandler"],
    "styx-js/examples/flegias-preview/reporter.js": ["runCaseReporter", "runOutsideReporter"],
    "styx-js/test/sdk/flegias-preview/loopback-relay.js": ["startLoopbackRelay"],
    "styx-js/test/sdk/flegias-preview/flegias-preview.test.js": []
  },
  "imports": {
    "styx-js/examples/flegias-preview/ports.js": {
      "@noble/curves/secp256k1": ["schnorr"],
      "styx-js/src/utils.js": ["bytesToHex"]
    },
    "styx-js/examples/flegias-preview/handler.js": {
      "styx-js/src/sdk/index.js": ["SDK_INTERFACE_VERSION", "createStyxClient", "SdkEventKind", "DeliveryState"],
      "styx-js/src/utils.js": ["utf8Encode"]
    },
    "styx-js/examples/flegias-preview/reporter.js": {
      "styx-js/src/sdk/index.js": ["SDK_INTERFACE_VERSION", "createStyxClient", "SdkEventKind", "DeliveryState"],
      "styx-js/src/utils.js": ["utf8Encode", "bytesToHex"]
    },
    "styx-js/test/sdk/flegias-preview/loopback-relay.js": {
      "ws": ["WebSocketServer"],
      "@noble/hashes/sha256": ["sha256"],
      "styx-js/src/utils.js": ["bytesToHex", "utf8Encode"]
    },
    "styx-js/test/sdk/flegias-preview/flegias-preview.test.js": {
      "styx-js/examples/flegias-preview/ports.js": ["generateSecretKey", "createPreviewPorts"],
      "styx-js/examples/flegias-preview/handler.js": ["runHandler"],
      "styx-js/examples/flegias-preview/reporter.js": ["runCaseReporter", "runOutsideReporter"],
      "styx-js/test/sdk/flegias-preview/loopback-relay.js": ["startLoopbackRelay"],
      "styx-js/src/sdk/index.js": ["ClientState", "DeliveryState"],
      "styx-js/src/utils.js": ["bytesToHex", "hexToBytes", "utf8Encode", "bytesToBase64", "base64ToBytes", "randomBytes"],
      "@noble/curves/secp256k1": ["schnorr"],
      "@jest/globals": ["describe", "test", "expect"],
      "ws": ["WebSocket"],
      "node:fs": ["readFileSync", "readdirSync"],
      "node:url": ["fileURLToPath"],
      "node:async_hooks": ["AsyncLocalStorage"]
    }
  },
  "schnorrOperations": { "ports.js": ["utils.randomPrivateKey", "getPublicKey", "sign"], "test": ["getPublicKey"] },
  "persistence": "none",
  "deployment": "none",
  "demo": false,
  "milestone4Claims": false,
  "beforePreviewCode": ["C-PREV output hash-ratified and merged", "I-SDK merged", "T-RELAY merged"]
}
```
<!-- styx-m3-flegias-preview-json:v1:end -->

## 11. Authority and ratification

This document is authorized by #400 §3 and the M3 scope record (#400 comment `5950987413`, card `C-PREV`: kind `contract`, `dependsOn` `C-SDK` and `C-DLV`, allowlist exactly `docs/architecture/m3/flegias-preview.md`). It takes effect only when the owner hash-ratifies its exact SHA-256 with a `styx-m3-ratification:v1` comment on #400 and it is merged into `m3/integration`. Any change to the flow, the covered fields, the runtime, the files or the imports needs a new hash-ratified version.
