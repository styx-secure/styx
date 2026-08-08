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

## Status and publishing

The source is covered by the repository's existing licensing and trademark
policies. Publishing, hosting, DNS, TLS, analytics, forms, or release claims
require a separate approved task. Do not add a deployment workflow or external
asset as a side effect of editing this directory.
