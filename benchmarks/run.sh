#!/usr/bin/env bash
set -euo pipefail

# Reproducible benchmark runner. Each invocation tests one model
# configuration against the labeled corpus and saves results.
#
# Usage:
#   ./benchmarks/run.sh                          # uses current ~/.sondera/env
#   ./benchmarks/run.sh --label glm-5-turbo      # add a label override
#
# Or set env directly for a specific model:
#   SONDERA_PROVIDER=zai SONDERA_MODEL=glm-5-turbo ./benchmarks/run.sh
#
# To run a full sweep, call it once per model config:
#   for model in glm-4.5-flash glm-5-turbo glm-4.6; do
#    SONDERA_PROVIDER=zai SONDERA_MODEL=$model ./benchmarks/run.sh
#  done

cd "$(dirname "$0")/.."

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CORPUS="${CORPUS:-$SCRIPT_DIR/corpus.jsonl}"
POLICIES="${POLICIES:-policies}"
RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/results}"

mkdir -p "$RESULTS_DIR"

# Auto-generate a label from the configured provider/model if not given.
LABEL="${LABEL:-}"
if [[ -z "$LABEL" ]]; then
  PROVIDER="${SONDERA_PROVIDER:-default}"
  MODEL="${SONDERA_MODEL:-default}"
  LABEL="${PROVIDER}/${MODEL}"
fi

TIMESTAMP=$(date -u +%Y%m%dT%H%M%S)
OUTPUT="$RESULTS_DIR/$(echo "$LABEL" | tr '/' '_')-${TIMESTAMP}.json"

echo "=== Sondera Benchmark ==="
echo "Label:    $LABEL"
echo "Corpus:   $CORPUS"
echo "Policies: $POLICIES"
echo "Output:   $OUTPUT"
echo

exec ./target/debug/sondera-benchmark \
  --corpus "$CORPUS" \
  --policies "$POLICIES" \
  --label "$LABEL" \
  --output "$OUTPUT"
