#!/usr/bin/env bash
# Runs the detector every INTERVAL_MINUTES for RUN_MINUTES, dispatching the full
# detect-security pipeline only when it reports new findings, then dispatches the
# next poll run. See README § Polling.
#
#   RUN_MINUTES=330 INTERVAL_MINUTES=10 bin/poll.sh
#
# Requires GH_TOKEN with actions:write and a clean checkout of main.

set -uo pipefail

RUN_MINUTES="${RUN_MINUTES:-330}"
INTERVAL_MINUTES="${INTERVAL_MINUTES:-10}"
# How long a dispatched set of findings is left to the pipeline before it is
# dispatched again. The pipeline commits state within ~2 minutes; still seeing the
# same keys after this means it failed, and a retry is what the cron used to provide.
REDISPATCH_MINUTES="${REDISPATCH_MINUTES:-60}"
REF="${POLL_REF:-main}"
REPORT="$(mktemp)"

deadline=$(( $(date +%s) + RUN_MINUTES * 60 ))
last_keys=""
last_dispatch=0

while :; do
  # The pipeline's `record` job commits state/seen.json to main; without a fresh
  # copy every poll would re-report what was already tracked.
  git fetch -q origin "$REF" && git reset -q --hard "origin/$REF"

  : > "$REPORT"
  node bin/detect-security.js --report="$REPORT"
  code=$?
  if [ "$code" -eq 3 ] || [ ! -s "$REPORT" ]; then
    echo "::warning::detector crashed (exit $code); next poll in ${INTERVAL_MINUTES}m"
  else
    keys=$(node -p "JSON.parse(require('fs').readFileSync('$REPORT', 'utf8')).findings.map(f => f.key).sort().join(' ')")
    now=$(date +%s)
    if [ -n "$keys" ] && { [ "$keys" != "$last_keys" ] || [ $(( now - last_dispatch )) -ge $(( REDISPATCH_MINUTES * 60 )) ]; }; then
      echo "::notice::new findings: $keys; dispatching detect-security"
      gh workflow run detect-security.yml --ref "$REF" && { last_keys="$keys"; last_dispatch=$now; }
    fi
  fi

  [ $(( $(date +%s) + INTERVAL_MINUTES * 60 )) -ge "$deadline" ] && break
  sleep $(( INTERVAL_MINUTES * 60 ))
done

echo "poll window over; dispatching the next poll run"
for attempt in 1 2 3; do
  gh workflow run poll.yml --ref "$REF" && exit 0
  sleep $(( attempt * 30 ))
done
# The watchdog cron in poll.yml restarts the chain; failing here makes the break visible.
echo "::error::could not dispatch the next poll run"
exit 1
