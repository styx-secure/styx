#!/usr/bin/env bash
# check_coverage.sh — Verify test coverage meets a minimum threshold.
# Usage: bash tool/check_coverage.sh [threshold]
# Default threshold: 90

set -euo pipefail

THRESHOLD="${1:-90}"
FAILED=0

if ! command -v lcov &>/dev/null; then
  echo "Error: lcov is not installed. Install it with: sudo dnf install lcov"
  exit 1
fi

PACKAGES=$(melos list --parsable)

for PKG in $PACKAGES; do
  PKG_NAME=$(basename "$PKG")

  # Skip packages with no test directory or empty lib
  if [ ! -d "$PKG/test" ] || [ ! -d "$PKG/lib" ]; then
    echo "SKIP $PKG_NAME — no test/ or lib/ directory"
    continue
  fi

  # Check if there are any Dart files in lib
  if ! find "$PKG/lib" -name '*.dart' -print -quit | grep -q .; then
    echo "SKIP $PKG_NAME — no Dart files in lib/"
    continue
  fi

  # Check if there are any test files
  if ! find "$PKG/test" -name '*_test.dart' -print -quit | grep -q .; then
    echo "SKIP $PKG_NAME — no test files in test/"
    continue
  fi

  echo "--- Checking coverage for $PKG_NAME ---"

  pushd "$PKG" >/dev/null

  # Run tests with coverage
  dart test --coverage=coverage 2>/dev/null

  # Format coverage output
  dart pub global run coverage:format_coverage \
    --lcov \
    --in=coverage \
    --out=coverage/lcov.info \
    --report-on=lib/ 2>/dev/null

  if [ ! -f coverage/lcov.info ]; then
    echo "WARN $PKG_NAME — no coverage data generated"
    popd >/dev/null
    continue
  fi

  # Extract line coverage percentage
  SUMMARY=$(lcov --summary coverage/lcov.info 2>&1)
  RATE=$(echo "$SUMMARY" | grep -oP 'lines\.*:\s*\K[\d.]+' || echo "0")

  # Compare as integers (truncate decimals)
  RATE_INT=${RATE%.*}
  if [ -z "$RATE_INT" ]; then
    RATE_INT=0
  fi

  if [ "$RATE_INT" -lt "$THRESHOLD" ]; then
    echo "FAIL $PKG_NAME — coverage ${RATE}% < ${THRESHOLD}%"
    FAILED=1
  else
    echo "PASS $PKG_NAME — coverage ${RATE}%"
  fi

  # Clean up
  rm -rf coverage

  popd >/dev/null
done

if [ "$FAILED" -ne 0 ]; then
  echo ""
  echo "Coverage check FAILED: one or more packages below ${THRESHOLD}%"
  exit 1
fi

echo ""
echo "Coverage check PASSED: all packages >= ${THRESHOLD}%"
