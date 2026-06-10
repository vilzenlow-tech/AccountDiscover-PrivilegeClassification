#!/usr/bin/env bash
# Ticking Clock CTF — server-time-gated flag fetcher.
# Window: 2026-05-31 11:58–12:00 SGT (= 03:58–04:00 UTC = 09:28–09:30 IST).
# Logs in fresh, polls /time, extracts ieee{...}, submits via CTFd API.

set -u
BASE="https://ieeesahackathon.ctfd.io"
USERNAME="vilzenlow@gmail.com"
PASSWORD="pwd_ByteForce"
CHAL_ID=5

STATE_DIR="$(cd "$(dirname "$0")" && pwd)/.state"
mkdir -p "$STATE_DIR"
COOKIES="$STATE_DIR/cookies.txt"
LOG="$STATE_DIR/run_$(date +%Y%m%d_%H%M%S).log"
BASELINE="$STATE_DIR/time_baseline.html"

log() { printf '%s | %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "$LOG"; }

log "=== Ticking Clock fetcher start ==="
log "Local time: $(date)"

# ---- Login fresh ----
rm -f "$COOKIES"
LOGIN_HTML=$(curl -sL -c "$COOKIES" -b "$COOKIES" "$BASE/login")
NONCE=$(printf '%s' "$LOGIN_HTML" | grep -oE 'name="nonce"[^>]*value="[a-f0-9]+"' \
        | grep -oE 'value="[a-f0-9]+"' | head -1 | sed 's/value="//;s/"$//')
if [ -z "$NONCE" ]; then log "FATAL: could not extract login nonce"; exit 2; fi
log "Got nonce: ${NONCE:0:12}..."

LOGIN_CODE=$(curl -s -o /dev/null -w "%{http_code}" -c "$COOKIES" -b "$COOKIES" \
  -X POST "$BASE/login" \
  --data-urlencode "name=$USERNAME" \
  --data-urlencode "password=$PASSWORD" \
  --data-urlencode "nonce=$NONCE" \
  --data-urlencode "_submit=Submit")
log "Login HTTP: $LOGIN_CODE (expect 302)"

# Verify auth
VERIFY=$(curl -s -b "$COOKIES" -o /dev/null -w "%{http_code}" "$BASE/team")
log "Auth check /team: $VERIFY (expect 200)"

# CSRF nonce for flag submission
CSRF=$(curl -s -b "$COOKIES" "$BASE/team" | grep -oE "csrfNonce':\s*\"[a-f0-9]+\"" \
       | head -1 | grep -oE '"[a-f0-9]+"' | tr -d '"')
log "CSRF nonce: ${CSRF:0:12}..."

# ---- Poll /time ----
# 180 seconds covers the full LAST TWO MINUTES window + buffer.
FOUND_FLAG=""
END=$(( $(date +%s) + 180 ))
ITER=0
while [ "$(date +%s)" -lt "$END" ]; do
  ITER=$((ITER+1))
  BODY="$STATE_DIR/time_$(date +%H%M%S)_${ITER}.html"
  curl -s -b "$COOKIES" "$BASE/time" -o "$BODY"
  SIZE=$(wc -c <"$BODY" | tr -d ' ')

  # Look for any flag
  FLAG=$(grep -oE 'ieee\{[^}]+\}' "$BODY" | head -1 || true)
  if [ -n "$FLAG" ]; then
    log "*** FLAG FOUND on iter $ITER: $FLAG ***"
    FOUND_FLAG="$FLAG"
    break
  fi

  # Log if body diverged from baseline (any structural change)
  if ! cmp -s "$BODY" "$BASELINE" 2>/dev/null; then
    # Trim recaptcha cache buster line before comparing
    DIFF=$(diff <(grep -v 'recaptcha.js?t=' "$BASELINE") <(grep -v 'recaptcha.js?t=' "$BODY"))
    if [ -n "$DIFF" ]; then
      log "Body DIVERGED from baseline (iter $ITER, size=$SIZE). Diff snippet:"
      printf '%s\n' "$DIFF" | head -40 | tee -a "$LOG" >/dev/null
    fi
  fi

  sleep 3
done

if [ -z "$FOUND_FLAG" ]; then
  log "No ieee{...} found in $ITER polls. Latest body saved at $BODY ($SIZE bytes)."
  log "Inspect $STATE_DIR/ manually."
  exit 3
fi

# ---- Submit ----
log "Submitting flag to /api/v1/challenges/attempt ..."
RESP=$(curl -s -b "$COOKIES" \
  -H "Content-Type: application/json" \
  -H "CSRF-Token: $CSRF" \
  -X POST "$BASE/api/v1/challenges/attempt" \
  -d "{\"challenge_id\": $CHAL_ID, \"submission\": \"$FOUND_FLAG\"}")
log "Submission response: $RESP"

# Check status
if echo "$RESP" | grep -q '"status":\s*"correct"'; then
  log "=== ✓ FLAG ACCEPTED: $FOUND_FLAG ==="
  exit 0
elif echo "$RESP" | grep -q '"status":\s*"already_solved"'; then
  log "=== Already solved: $FOUND_FLAG ==="
  exit 0
else
  log "=== Submission rejected. Flag captured but not accepted: $FOUND_FLAG ==="
  exit 4
fi
