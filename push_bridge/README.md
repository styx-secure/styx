# Styx Push Bridge

Stateless, blind Web Push bridge for Styx Chat. It listens to Nostr relays for
kind-1059 events addressed to registered pubkeys and sends an **empty** Web Push
to wake the device — the content stays end-to-end encrypted and is never seen by
the bridge. Its only state is a `pubkey → [subscription]` registry (JSON file).

## Setup

```bash
npm install
npx web-push generate-vapid-keys   # prints a public and a private key
```

## Run

```bash
VAPID_PUBLIC_KEY=... VAPID_PRIVATE_KEY=... VAPID_SUBJECT=mailto:you@example.com \
RELAYS=wss://relay.damus.io,wss://nos.lol \
PORT=8095 REGISTRY_FILE=./registry.json \
npm start
```

Point the app at it with `?bridge=https://your-bridge-host` (or the build-time
`VITE_BRIDGE_URL`). The bridge is optional: without it the app still works, just
without notifications while closed.

## Test

```bash
npm test
```
