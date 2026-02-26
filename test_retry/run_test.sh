#!/usr/bin/env bash
# Test opencode empty-response retry via mitmdump.
#
# Usage:
#   ./test_retry/run_test.sh                          # 1 run, default prompt
#   ./test_retry/run_test.sh "custom prompt"          # 1 run, custom prompt
#   N_RUNS=5 ./test_retry/run_test.sh                 # 5 runs
#   SDK=@ai-sdk/anthropic N_RUNS=3 ./test_retry/run_test.sh



set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$DIR/.." && pwd)"
PROMPT="${1:-Read all the files in ./ and summarize them}"

VLLM_URL="${VLLM_URL:-https://vllm.concrete-security.com}"
PORT="${PROXY_PORT:-8010}"
SDK="${SDK:-@ai-sdk/anthropic}"
MODEL_ID="${MODEL_ID:-openai/gpt-oss-120b}"
N_RUNS="${N_RUNS:-1}"
RETRIES="${OPENCODE_EMPTY_RESPONSE_RETRIES:-2}"
RETRY_DELAY="${OPENCODE_EMPTY_RESPONSE_RETRY_DELAY:-1000}"
SYS_PROMPT="${OPENCODE_SYSTEM_PROMPT:-}"
MAX_TOKENS="${MAX_TOKENS:-128000}"

echo
echo "═══════════════════════════════════════"
echo "  SDK:    $SDK"
echo "  Model:  $MODEL_ID"
echo "  Runs:   $N_RUNS"
echo "  Retry:  $RETRIES (delay ${RETRY_DELAY}ms)"
echo "  SysP:   ${SYS_PROMPT:-auto}"
echo "  MaxTok: $MAX_TOKENS"
echo "  Prompt: ${PROMPT:0:60}"
echo "═══════════════════════════════════════"

for run in $(seq 1 "$N_RUNS"); do
  RUN_ID=$(date +%d%m%Y_%H_%M_%S)
  echo
  echo "── Run $run/$N_RUNS [$RUN_ID] ──"
  RUN_DIR="$DIR/experiments/$RUN_ID"
  mkdir -p "$RUN_DIR"

  # ── Config ──
  cat > "$RUN_DIR/config.json" <<JSON
{
  "\$schema": "https://opencode.ai/config.json",
  "model": "vllm/gpt-oss-120b",
  "permission": {
    "read": "allow",
    "edit": "allow",
    "bash": "allow",
    "glob": "allow",
    "grep": "allow",
    "list": "allow",
    "task": "allow",
    "question": "allow",
    "webfetch": "allow",
    "websearch": "allow",
    "codesearch": "allow",
    "external_directory": "allow"
  },
  "experimental": {
    "continue_loop_on_deny": true
  },
  "provider": {
    "vllm": {
      "npm": "$SDK",
      "options": { "baseURL": "http://localhost:$PORT/v1", "apiKey": "dummy" },
      "models": { "gpt-oss-120b": { "id": "$MODEL_ID", "name": "GPT-OSS-120B" } }
    }
  }
}
JSON

  # ── mitmdump ──
  pkill -f "mitmdump.*$PORT" 2>/dev/null || true
  sleep 0.5
  mitmdump --mode "reverse:${VLLM_URL}" -p "$PORT" --ssl-insecure -w "$RUN_DIR/flows.mitm" &>/dev/null &
  MITM_PID=$!
  disown

  # Wait for mitm to be ready
  for i in $(seq 1 20); do
    curl -so /dev/null "http://localhost:$PORT" 2>/dev/null && break
    sleep 0.5
  done
  echo "  mitmdump ready on port $PORT (PID $MITM_PID)"

  echo "  Start OpenCode"
  # ── opencode (live output) ──
  OPENCODE_CONFIG="$RUN_DIR/config.json" OPENCODE_DISABLE_PROJECT_CONFIG=1 \
    OPENCODE_EXPERIMENTAL_OUTPUT_TOKEN_MAX="$MAX_TOKENS" \
    OPENCODE_EMPTY_RESPONSE_RETRIES="$RETRIES" \
    OPENCODE_EMPTY_RESPONSE_RETRY_DELAY="$RETRY_DELAY" \
    OPENCODE_SYSTEM_PROMPT="${SYS_PROMPT}" \
    bun run --conditions=browser "$PROJECT_DIR/packages/opencode/src/index.ts" \
    run --format json "$PROMPT" 2>/dev/null \
    | tee "$RUN_DIR/output.json" \
    | python3 -u "$DIR/live_output.py" || true

  # ── Stop mitm ──
  kill "$MITM_PID" 2>/dev/null || true

  # ── Analyze ──
  python3 "$DIR/analyze.py" "$RUN_DIR" "$DIR/results.csv" "$RUN_ID" "$SDK" "$VLLM_URL" "$PROMPT" "$RETRIES" "${SYS_PROMPT:-qwen}" "$MAX_TOKENS"


  # Avoid timestamp collision between runs
  sleep 1
done

echo
echo "── Results in $DIR/results.csv ──"

