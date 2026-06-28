#!/usr/bin/env bash
set -euo pipefail

# Sweep multiple model configurations through the benchmark.
# Each entry is: PROVIDER|MODEL|EXTRA_ENV
#
# Results are saved to benchmarks/results/ and a comparison summary
# is printed at the end.

cd "$(dirname "$0")/.."

# Load the base env (for API keys) then override per-model.
sondera_config_load() {
  for f in /etc/sondera/env "$HOME/.sondera/env"; do
    if [[ -f "$f" ]]; then
      set -a
      # shellcheck disable=SC1090
      source "$f"
      set +a
    fi
  done
}
sondera_config_load

CONFIGS=(
  # z.ai models
  "zai|glm-4.5-flash|"
  "zai|glm-5-turbo|"
  "zai|glm-4.6|"
)

echo "=== Sondera Benchmark Sweep ==="
echo "Testing ${#CONFIGS[@]} model configurations"
echo

for cfg in "${CONFIGS[@]}"; do
  IFS='|' read -r provider model extra <<< "$cfg"
  export SONDERA_PROVIDER="$provider"
  export SONDERA_MODEL="$model"
  if [[ -n "$extra" ]]; then export "$extra"; fi
  LABEL="${provider}/${model}"

  echo ">>> Running: $LABEL"

  # Rebuild is not needed — same binary, different env.
  ./target/debug/sondera-benchmark \
    --corpus benchmarks/corpus.jsonl \
    --policies policies \
    --label "$LABEL" \
    --output "benchmarks/results/$(echo "$LABEL" | tr '/' '_').json" \
    2>&1 | tail -20

  echo
done

echo "=== Sweep complete. Results in benchmarks/results/ ==="

# Print comparison table from all result files.
echo
echo "=== COMPARISON ==="
echo
for f in benchmarks/results/*.json; do
  label=$(grep -o '"label":"[^"]*"' "$f" | head -1 | cut -d'"' -f4)
  label_acc=$(grep -o '"label_accuracy":[0-9.]*' "$f" | head -1 | cut -d':' -f2)
  comp_acc=$(grep -o '"compliance_accuracy":[0-9.]*' "$f" | head -1 | cut -d':' -f2)
  fpr=$(grep -o '"false_positive_rate":[0-9.]*' "$f" | head -1 | cut -d':' -f2)
  fnr=$(grep -o '"false_negative_rate":[0-9.]*' "$f" | head -1 | cut -d':' -f2)
  ifc_p95=$(grep -o '"p95_ifc_latency_ms":[0-9]*' "$f" | head -1 | cut -d':' -f2)
  pol_p95=$(grep -o '"p95_policy_latency_ms":[0-9]*' "$f" | head -1 | cut -d':' -f2)
  printf "%-24s  L:%5.1f%%  P:%5.1f%%  FPR:%5.1f%%  FNR:%5.1f%%  p95:%4s+%-4sms\n" \
    "$label" \
    "$(echo "$label_acc * 100" | bc)" \
    "$(echo "$comp_acc * 100" | bc)" \
    "$(echo "$fpr * 100" | bc)" \
    "$(echo "$fnr * 100" | bc)" \
    "$ifc_p95" "$pol_p95"
done
