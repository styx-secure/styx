#!/usr/bin/env bash
# check_coverage.sh — Non-regression line-coverage gate for the Dart reference stack.
#
# Policy (see tool/coverage_baseline.tsv):
#   * 90% is an improvement TARGET, not a current guarantee for every package.
#   * Each package must not drop below its committed floor in coverage_baseline.tsv,
#     with a documented tolerance of 0.1 percentage points for non-deterministic noise.
#   * Generated Drift code (*.g.dart) is excluded — it is machine-generated, not
#     hand-written. No other real source is excluded.
#
# Usage: bash tool/check_coverage.sh [--target N] [--record]
#   --target N  aspirational target shown in the report (default 90)
#   --record    print measured "<pkg>\t<pct>" lines and exit 0 (to refresh the baseline)
#
# No lcov dependency: coverage is parsed straight from the LCOV info file (LF/LH),
# which is exactly how line coverage is defined. LC_ALL=C forces '.' as the decimal
# separator so the gate is identical on any host locale.
set -euo pipefail
export LC_ALL=C

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BASELINE="$HERE/coverage_baseline.tsv"
TARGET=90
TOLERANCE=0.1
RECORD=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2;;
    --record) RECORD=1; shift;;
    [0-9]*)   TARGET="$1"; shift;;   # backward-compatible positional target
    *) echo "unknown argument: $1" >&2; exit 2;;
  esac
done

[ -f "$BASELINE" ] || { echo "Error: baseline not found at $BASELINE" >&2; exit 1; }

floor_for() { # package -> floor (defaults to TARGET when the package is not listed)
  grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$BASELINE" \
    | awk -v p="$1" -v d="$TARGET" '$1==p{print $2; f=1} END{if(!f)print d}'
}

FAILED=0
declare -a RECORD_LINES=()
printf "%-22s %9s %8s %8s   %s\n" "package" "coverage" "floor" "target" "status"
printf -- "-------------------------------------------------------------------\n"

for PKG in $(cd "$ROOT" && melos list --parsable); do
  NAME=$(basename "$PKG")
  { [ -d "$PKG/test" ] && [ -d "$PKG/lib" ]; } || continue
  find "$PKG/lib"  -name '*.dart'      -print -quit | grep -q . || continue
  find "$PKG/test" -name '*_test.dart' -print -quit | grep -q . || continue

  pushd "$PKG" >/dev/null
  dart test --coverage=coverage >/dev/null 2>&1 || true
  dart pub global run coverage:format_coverage \
    --lcov --in=coverage --out=coverage/lcov.info --report-on=lib/ >/dev/null 2>&1 || true

  if [ ! -f coverage/lcov.info ]; then
    echo "WARN $NAME — no coverage data generated"
    rm -rf coverage; popd >/dev/null; continue
  fi

  # Sum LF/LH across all source files EXCEPT generated *.g.dart sections.
  read -r H F PCT < <(awk -F: '
    /^SF:/{gen = ($0 ~ /\.g\.dart$/)}
    /^LF:/{ if(!gen) f += $2 }
    /^LH:/{ if(!gen) h += $2 }
    END{ printf "%d %d %.2f\n", h, f, (f>0 ? h/f*100 : 0) }' coverage/lcov.info)
  rm -rf coverage
  popd >/dev/null

  RECORD_LINES+=("$NAME	$PCT")
  FLOOR=$(floor_for "$NAME")

  if awk -v p="$PCT" -v fl="$FLOOR" -v t="$TOLERANCE" 'BEGIN{exit !((p+0) >= (fl-t))}'; then
    if awk -v p="$PCT" -v t="$TARGET" 'BEGIN{exit !((p+0) >= t)}'; then
      STATUS="OK (>= target)"
    else
      STATUS="OK (>= baseline)"
    fi
  else
    STATUS="REGRESSION (< floor)"
    FAILED=1
  fi
  printf "%-22s %8s%% %7s%% %7s%%   %s\n" "$NAME" "$PCT" "$FLOOR" "$TARGET" "$STATUS"
done

if [ "$RECORD" -eq 1 ]; then
  echo; echo "# measured (paste into tool/coverage_baseline.tsv after review):"
  printf '%s\n' "${RECORD_LINES[@]}"
  exit 0
fi

echo
if [ "$FAILED" -ne 0 ]; then
  echo "Coverage check FAILED: a package regressed below its baseline floor."
  echo "Baseline floors live in tool/coverage_baseline.tsv (never lower one to pass a PR)."
  exit 1
fi
echo "Coverage check PASSED: no package regressed below its baseline floor."
