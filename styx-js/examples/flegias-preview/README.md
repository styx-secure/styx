# Flegias preview (synthetic data only)

Local Jest-driven fixture on the integrated SDK: two sequential synthetic cases,
two fresh loopback relays per case, one opening and one handler reply under the
case key. An outside synthetic sender publishes to a synthetic bystander first.
No page, server entry point, public relay, real data or retired prototype is used.

The property and its precise limits are defined only by
`docs/architecture/m3/flegias-preview.md` §2 and §5. A1–A9 verify the enumerated
representations; this is not a proof over arbitrary transformations. H4 scanning
is a separate strength measure, not an extension of the property.

From `styx-js`, with the existing qualified dependencies and Node >=20:

    NODE_OPTIONS=--experimental-vm-modules node node_modules/jest/bin/jest.js --runInBand --runTestsByPath test/sdk/flegias-preview/flegias-preview.test.js --testTimeout=20000 --json --outputFile=<external dossier>/jest.json

The authorized phase permits one invocation on AI395 under the shared lock and
resource guards. This command documents the entry point, not permission to rerun.
Raw failure requires a specific continuation; no forceExit or hidden retry.
The test restores WebSocket and closes all its own clients and relays in finally.

Not a demo, product, deployment or completed SDK. No payload confidentiality:
sessions copy plaintext. No identity hiding, metadata/timing/network protection,
ordering, exactly-once, cross-restart reliability or Milestone 4 guarantee.
Relays see keys and plaintext. Case key and reply address are preview mechanisms.
Best-effort catch-up may miss old events; dedup eviction can reopen events.

Styx is under active development and has **not** completed an independent security audit. Do not use current builds for sensitive, high-risk, or life-critical use.

C0.3 remains `NO-GO` for implementation alignment, demo, product, and sensitive use.

Historical 47 FAIL and 48/47 versus 47/47 FAIL remain, with the original 48th
cause unknown. Prior relay qualification has 18 substantive and two weak legacy
oracles, not EOSE/closure proof. Chat evidence is single-relay MLS, not multi-relay
MLS. Historical BLOCKED DELIVERY reviews and bounded 22-path reuse are not new
review or SIGN. Initial supervisor mount-order FAIL remains preserved.
No commit/push or independent review is authorized in this local phase.
