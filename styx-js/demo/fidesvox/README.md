# FidesVox — demo

> ⚠️ **DEMO ONLY.** Standalone example app (Express + SQLite + a Nostr subscriber) that
> shows how a form/reporting product could route private answers through Styx. It is
> **not** part of the Styx product, not shipped in the chat bundle, and not in CI. Do not
> deploy it as-is.

## Configuration

The demo signs session tokens (JWT) with a secret read from the environment. There is **no
hardcoded default** — the demo refuses to start without a strong `JWT_SECRET`.

Generate one and run:

```bash
export JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
node demo/fidesvox/server.js
```

or put it in a local `.env` (git-ignored) — copy `.env.example` to `.env` and fill it in.

`JWT_SECRET` must be at least 32 characters of high-entropy randomness; the demo fails fast
on a missing or weak value (see `config.js`).

## Run

1. `docker compose -f styx-js/docker-compose.test.yml up -d` (start the strfry relay)
2. `JWT_SECRET=… node demo/fidesvox/server.js`
3. open <http://localhost:3456/login>

## Note (security)

The demo also uses a hardcoded Nostr identity for illustration (`server.js`, "Server Nostr
identity — hardcoded for demo"). That is a throwaway demo keypair, not a product credential;
do not reuse it anywhere real.
