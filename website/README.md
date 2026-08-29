# Styx static landing page

This directory contains the dependency-free source for the Styx public landing
page. It is a review artifact, not a deployed service. The page uses semantic
HTML, one local stylesheet, and one original SVG mark. It deliberately has no
JavaScript, analytics, remote fonts, forms, cookies, or runtime dependencies.

## Preview locally

From the repository root:

```bash
python3 -m http.server 8080 --bind 127.0.0.1 --directory website
```

Then open `http://127.0.0.1:8080/`. Stop the server with `Ctrl-C` when the
review is complete.

## Test

```bash
python3 -m unittest website/test_site.py
```

The test uses only the Python standard library and checks the document
structure, local resources, prohibited runtime elements, external-link safety,
required content, and SVG restrictions. It does not replace browser,
accessibility, security-claims, or human visual review.

## C0.3 Evidence Explorer

The landing page stays clean and informational. Its single local explorer link
opens `demo/index.html`, a separate corpus-backed trace interface with its own
styles, JavaScript, tests and claim boundaries. The explorer is generated from
the pinned synthetic C0.3 corpus and replays precomputed evidence; it is not an
implementation adapter, cryptographic runtime, product demo or phase verdict.

Regenerate its tracked projection from the repository root:

```bash
python3 website/demo/build_data.py \
  --repo-root . \
  --output website/demo/data/c03-evidence.json
```

Run both site test suites and the browser-logic unit tests:

```bash
python3 -m unittest website/test_site.py website/demo/test_demo.py
node --test website/demo/test_core.mjs
```

## Status and publishing

The source is covered by the repository's existing licensing and trademark
policies. Publishing, hosting, DNS, TLS, analytics, forms, or release claims
require a separate approved task. Do not add a deployment workflow or external
asset as a side effect of editing this directory.
