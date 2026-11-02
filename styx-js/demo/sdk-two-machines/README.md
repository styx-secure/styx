# PROTOTYPE — DO NOT MERGE

Two-machine SDK demonstration. Synthetic data, pre-audit. This branch is not a
product integration proposal and must not be merged.

Base: `3b314074568aa435572bca44ec4348e1a084c60e` (`m3/integration`).
Authorization: Kanban `t_403664d9`, owner-approved prototype lane.

## Boundaries

The application calls only `src/sdk/index.js` for invitation and delivery:
`createStyxClient`, `start`, `publishKeyPackage`, `invite`, `acceptInvite`,
`send`, `onEvent`, `getDelivery`, `shutdown`. It does not import SDK internals.
Caller-owned ports call the existing, unchanged `MlsEngine` and its pinned WASM.
The adapter follows `test/sdk-mls/invite-mls.test.js`, including credential
validation on an isolated engine before changing the live engine.

The identity lives in memory. `DEMO_SEED` is an optional high-entropy secret
(minimum 32 characters); without it a random identity is generated. Never pass
seeds on command lines, commit them or print them. The harness generates each
host's seed locally and supplies it through the child environment. No identity,
KeyPackage, Welcome, MLS state or message is copied between members. Only public
peer keys are sent by the controller; evidence is collected after the exchange.
Each invitee pins the expected inviter's Nostr public key. This is not an external
identity verification service.

No production NIP-59 helper was present in this base. This demo uses the already
installed `nostr-tools/nip59` `wrapEvent` / `unwrapEvent` implementation, plus
outer signature verification via `nostr-tools/pure`. NIP-59's private seal is
NIP-44 encrypted, and a one-time outer key signs kind 1059. The helper verifies
the seal signature and binds it to the rumor author. Its cached-verification
Symbol is removed before returning the SDK's closed event object. On unwrap the
rumor id is omitted to match the SDK's closed port contract. This is caller glue,
not a replacement cryptographic implementation.

`nostr-tools` is an additional DEMO-ONLY dependency; it is not declared in the
product manifest. Use the installed demo environment or install it in an isolated
demo dependency directory and expose that directory to Node resolution. No product
manifest, lockfile, SDK, crypto or vendor file is changed by this prototype.
The evidence records the exact dependency versions actually used. Also required:
Node 24, the product's existing dependencies (including `ws`), Python 3, dumpcap,
tshark and, for video rendering, Pillow and ffmpeg. No WASM rebuild is needed.

## Local fixture run (on the compute host)

From `styx-js` with the above dependencies available:

    EVIDENCE_DIR=/absolute/evidence/loopback node demo/sdk-two-machines/loopback.mjs

This uses three loopback relay fixtures with signature verification and two
independent Node processes. Negative checks cover wrong MLS credentials, altered
gift wraps, and third-party unwrap. The main flow uses real time, real MLS and
real encrypted NIP-59, not the plaintext identity fixture in the SDK test.

## Two hosts

Deploy this same base and demo code to both hosts, without identity or protocol
state. On AI395 the reference deployment is
`/home/mverde/reviews/sdk-demo-2026-11/styx`; `ai395` is an existing SSH alias.
From MVLINNA, run:

    python3 demo/sdk-two-machines/run-two.py --out /absolute/evidence/two-host-N

The controller compares public egress addresses in memory and retains only the
boolean result. The lightweight invitee runs on MVLINNA. The inviter runs on
AI395 with nice 19, idle I/O and the shared test lock; a memory monitor terminates
the demo if available RAM falls below 15 GB. Existing services are not restarted
or changed. PC4070TI is never contacted.

The invitee publishes kind 4743, the inviter retrieves it and publishes kind 1059
containing the encrypted kind-4744 Welcome, and the invitee accepts it. Three
messages and three replies request recipient receipts. The host-local WebSocket
wrapper excludes R1 (`relay.nostr.net`) after message 1. It then blackholes both
directions on R2/R3 until a publish attempt times out. The SDK retries after those
links are restored and recovers a reply sent during the stall. R1 itself remains
online; the experiment does not shut down or attack any public relay.

Configured relays:

- `wss://relay.nostr.net`
- `wss://relay.primal.net`
- `wss://offchain.pub`

The real clock, volatile delivery storage and these public hosts are explicitly
supplied by the caller. Three seconds of final linger is a demo precaution, not
a stronger shutdown guarantee.

## Evidence and limits

`host.py` captures only relay-address TCP/443 traffic during the run. `netview.py`
retains only streams whose ClientHello random matches that node's own TLS key
log, masks IP addresses, and emits two views: on-wire TLS metadata and WebSocket
frames after removing the node's own TLS layer. TLS keys and original captures
are shredded immediately after extraction; only capture hashes and sanitized
views remain. Shredding is best effort on modern filesystems, not a secure erase
guarantee. Keys are never committed, exported as evidence or transferred.

Message events carry MLS ciphertext, not application plaintext. Invitation
KeyPackages are public. Recipient public keys, kinds, timing, sizes, event ids,
receipt metadata and routing tags remain observable. This is not anonymity,
production readiness, an audit, a formal proof, or a general outage guarantee.
Experimental kinds 4743/4744 are not a claim of Marmot interoperability. Volatile
identity/session state is lost when an original `member.mjs` process exits.
The separate persistence variant below restores caller-owned state; it does not
change the SDK's cross-restart guarantees.

The video is a labeled, evidence-derived playback of actual logs and captures,
not an unedited live screen recording. Its rendering script records which source
lines it uses. See `RISULTATI.IT.md` in the deliverable workspace for measured
outcomes and failed attempts. Optional attacker replay/injection is not implied
unless explicitly recorded there.

## Persistent caller-owned variant (prototype only)

Authorization: Kanban `t_892091c7`. The original volatile demo is unchanged.
`persistent-ports.mjs` encrypts the synthetic identity seed, MLS provider snapshot,
contact/group mapping, application inbox and archived outbox records with Node's
AES-256-GCM. A host-local supervisor generates the key in memory and provides it
through `DEMO_STATE_KEY`; never put it on the command line or in evidence.
State directories are 0700, files 0600; writes use fsync and atomic rename.
The supervisor deletes its own test state and verifies removal after each run.

Deploy the same `persistent-*` files and unchanged source/vendor files on both
hosts. With existing demo dependencies, from the demo checkout:

    # On AI395, using the installed Node 24 and the shared execution lock:
    DEMO_NODE=$HOME/.nvm/versions/node/v24.18.0/bin/node nice -n 19 ionice -c 3 python3 styx-js/demo/sdk-two-machines/persistent-run.py --mode loopback --out /absolute/evidence/persistence-loopback-N

    # From MVLINNA, AI395 is the inviter; MVLINNA only the lightweight invitee:
    DEMO_NODE=node nice -n 19 ionice -c 3 python3 styx-js/demo/sdk-two-machines/persistent-run.py --mode public --out /absolute/evidence/persistence-public-N

    # Negative/port checks on AI395 only:
    flock /home/mverde/reviews/styx-kanban/.ai395-test.lock nice -n 19 ionice -c 3 env TMPDIR=/home/mverde/.hermes/cache/scratch $HOME/.nvm/versions/node/v24.18.0/bin/node styx-js/demo/sdk-two-machines/persistent-checks.mjs

Each run pairs once, sends three messages and three replies with recipient
receipts, cleanly stops/restarts both member processes, sends three more in each
direction, then externally SIGKILLs the inviter during publication. The member
first SIGSTOPs immediately after its first kind-4741 socket send returns, allowing
the supervisor to issue deterministic SIGKILL before the SDK processes the result.
The sender restores the same group, reports the old pending delivery as an
application-level `FAILED_AFTER_RESTART_UNKNOWN_OUTCOME` without retransmitting it,
and exchanges one further message/reply with receipts. The pending message may
already have reached the recipient: failure is not a claim of non-delivery.

Important limits:

- SDK `start()` rejects a nonempty outbox. Old namespaces remain archived; a new
  SDK process gets a genuinely new empty namespace. There is no SDK hydration,
  old `getDelivery`, receipt recovery or automatic retry after crash.
- The invitee learns its groupId in the first authenticated synthetic application
  payload. Crash before that checkpoint is not covered.
- SDK catch-up cursors and owed receipts have no persistence port. They are NOT
  persisted or emulated by this demo.
- MLS snapshot, inbound callback and outbox are not one transaction. Zero observed
  duplicates is not an exactly-once or no-loss guarantee for arbitrary crashes.
- These are member-process restarts, not physical machine reboots. The supervisor
  retains the encryption key in memory; a real reboot needs external provisioning.
- No packet captures or videos are generated by this variant. Evidence consists
  of structured SDK/application and supervisor logs, not independent wire capture.

See [PERSISTENZA-GAP.IT.md](PERSISTENZA-GAP.IT.md) for the pinned file:line map,
missing SDK contracts and proposed future acceptance tests. Measured results,
including failed attempts, are in `RISULTATI-PERSISTENZA.IT.md` in the task
workspace. No product persistence claim or SDK release follows from this test.

Rollback: discard this prototype branch and its isolated deployments. Never merge
it into `main` or `m3/integration`. No council review was requested or performed.
