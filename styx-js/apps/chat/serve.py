#!/usr/bin/env python3
"""Threaded static server for the built dist/ (used behind the Cloudflare tunnel).

Handles concurrent testers loading the 1.8 MB WASM without blocking, and serves
.wasm with the correct MIME type. Bind is localhost-only; the tunnel points here.

Usage:  cd apps/chat && npm run build && python3 serve.py [port]
"""
import os
import sys
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8090
DIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist")

os.chdir(DIST)
SimpleHTTPRequestHandler.extensions_map[".wasm"] = "application/wasm"
ThreadingHTTPServer.allow_reuse_address = True

httpd = ThreadingHTTPServer(("127.0.0.1", PORT), SimpleHTTPRequestHandler)
print(f"Styx Chat static server (threaded) on http://127.0.0.1:{PORT}", flush=True)
httpd.serve_forever()
