#!/usr/bin/env bash
# Aggregator for the required "WASM integrity gate" check. Pure and testable
# (styx-js/test/ci/wasm-gate.test.js runs the full decision table).
#
# FAIL-CLOSED (review K9): the green-skip branch is reachable ONLY when change
# detection itself completed successfully. If the `changes` job failed, was
# cancelled or skipped, its outputs are empty strings — which must never be
# interpreted as "nothing changed".
#
# Inputs (env):
#   CHANGES_RESULT                        result of the `changes` job
#   LIGHT_NEEDED CRATE_NEEDED             openmls-wasm tier flags ("true"/other)
#   KDFLIGHT_NEEDED KDF_NEEDED            styx-kdf-wasm tier flags
#   LIGHT HERMETIC KDF_LIGHT KDF_HERMETIC results of the tier jobs
set -euo pipefail

if [ "${CHANGES_RESULT:-}" != "success" ]; then
  echo "::error::WASM change detection did not complete successfully: ${CHANGES_RESULT:-<empty>}"
  exit 1
fi

if [ "${LIGHT_NEEDED:-}" != "true" ] && [ "${CRATE_NEEDED:-}" != "true" ] \
   && [ "${KDF_NEEDED:-}" != "true" ] && [ "${KDFLIGHT_NEEDED:-}" != "true" ]; then
  echo "No WASM/MLS/chat/KDF paths changed — integrity checks skipped (green)."
  exit 0
fi

fail=0
if [ "${LIGHT_NEEDED:-}" = "true" ]; then
  echo "light: ${LIGHT:-}"; [ "${LIGHT:-}" = "success" ] || fail=1
fi
if [ "${CRATE_NEEDED:-}" = "true" ]; then
  echo "hermetic: ${HERMETIC:-}"; [ "${HERMETIC:-}" = "success" ] || fail=1
fi
if [ "${KDFLIGHT_NEEDED:-}" = "true" ]; then
  echo "kdf-light: ${KDF_LIGHT:-}"; [ "${KDF_LIGHT:-}" = "success" ] || fail=1
fi
if [ "${KDF_NEEDED:-}" = "true" ]; then
  echo "kdf-hermetic: ${KDF_HERMETIC:-}"; [ "${KDF_HERMETIC:-}" = "success" ] || fail=1
fi
if [ "$fail" -ne 0 ]; then
  echo "WASM integrity checks FAILED."; exit 1
fi
echo "WASM integrity checks passed."
