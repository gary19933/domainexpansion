#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_FILE="${LOG_FILE:-/var/log/domainexpansion/daily.log}"
ENV_FILE="${ENV_FILE:-/etc/domainexpansion.env}"

mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
exec >>"$LOG_FILE" 2>&1

echo "[$(date '+%Y-%m-%d %H:%M:%S %Z')] run_daily_check start"

if [[ ! -r "$ENV_FILE" ]]; then
  echo "ERROR: env file not readable: $ENV_FILE"
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

required_vars=(
  TG_BOT_TOKEN
  TG_CHAT_ID
)

for var_name in "${required_vars[@]}"; do
  if [[ -z "${!var_name:-}" ]]; then
    echo "ERROR: missing required env var: $var_name"
    exit 1
  fi
done

cd "$REPO_DIR"

# Pull latest domain lists and scripts from GitHub before running
git pull --ff-only origin main || echo "WARNING: git pull failed, running with local copy"

mkdir -p out records

RUN_DATE="$(TZ=Asia/Kuala_Lumpur date '+%Y-%m-%d')"

# ---------------------------------------------------------------------------
# VPS node-based countries (MY, SG, TH, NP)
# SSH host aliases are expected in ~/.ssh/config:
#   Host my-node / sg-node / th-node / np-node
# Each node just needs the repo cloned at /root/domainexpansion
# ---------------------------------------------------------------------------
VPS_COUNTRIES=(my sg th np)
NODE_USER="root"
NODE_REPO="/root/domainexpansion"

run_country() {
  local country="$1"
  local node_host="${country}-node"
  echo "[$(date '+%Y-%m-%d %H:%M:%S %Z')] VPS check country=$country node=$node_host"

  # Filter out already-banned domains before checking
  python3 scripts/filter_list.py \
    --list "lists/${country}.txt" \
    --banned-file "records/banned_domains.csv" \
    --country "$country" \
    --output "/tmp/${country}_active.txt"

  SSH_OPTS="-o ConnectTimeout=10 -o ServerAliveInterval=30 -o ServerAliveCountMax=20"

  # Pull latest lists and scripts on node
  ssh $SSH_OPTS "${NODE_USER}@${node_host}" \
    "cd ${NODE_REPO} && git pull --ff-only origin main" || {
    echo "WARNING: git pull failed on $node_host, running with existing copy"
  }

  # Copy filtered active list to node
  scp -q "/tmp/${country}_active.txt" \
    "${NODE_USER}@${node_host}:/tmp/${country}_active.txt" || {
    echo "WARNING: failed to copy filtered list to $node_host"
  }

  # Clean up old results before starting fresh check
  ssh $SSH_OPTS "${NODE_USER}@${node_host}" \
    "pkill -f checker_node.py 2>/dev/null; rm -f /tmp/${country}_results.json" || true

  # Start checker in background on node via nohup so it survives SSH drops
  ssh $SSH_OPTS "${NODE_USER}@${node_host}" \
    "nohup python3 ${NODE_REPO}/scripts/checker_node.py \
     --config ${NODE_REPO}/deploy/node_configs/${country}.json \
     --list /tmp/${country}_active.txt \
     --output /tmp/${country}_results.json \
     > /tmp/${country}_check.log 2>&1 &" || {
    echo "WARNING: failed to start checker on $node_host"
  }

  # Wait for results file to appear (poll every 30s, timeout 90min)
  echo "[$(date '+%Y-%m-%d %H:%M:%S %Z')] waiting for $node_host results..."
  WAIT_SECS=0
  until ssh $SSH_OPTS "${NODE_USER}@${node_host}" \
      "test -f /tmp/${country}_results.json" 2>/dev/null; do
    sleep 30
    WAIT_SECS=$((WAIT_SECS + 30))
    if (( WAIT_SECS >= 5400 )); then
      echo "WARNING: timeout waiting for results from $node_host"
      break
    fi
  done

  # Pull results back to controller
  scp -q "${NODE_USER}@${node_host}:/tmp/${country}_results.json" \
    "out/${country}_node_results.json" || {
    echo "WARNING: failed to pull results from $node_host"
  }

  echo "[$(date '+%Y-%m-%d %H:%M:%S %Z')] done country=$country"
}

# Run all country checks in parallel
for country in "${VPS_COUNTRIES[@]}"; do
  run_country "$country" &
done
wait  # wait for all 4 to finish

# Convert VPS node results to CSV
python3 scripts/collect_results.py \
  --date "$RUN_DATE" \
  --out-dir "out" \
  --countries "my,sg,th,np"

# Record newly banned domains
python3 scripts/auto_ban.py \
  --date "$RUN_DATE" \
  --out-dir "out" \
  --banned-file "records/banned_domains.csv"

# ---------------------------------------------------------------------------
# Merge all results and send Telegram summary
# ---------------------------------------------------------------------------
python3 scripts/merge_summary.py \
  --date "$RUN_DATE" \
  --out-dir "out" \
  --log-file "records/ban_log.csv" \
  --banned-file "records/banned_domains.csv" \
  --summary-file "out/telegram_daily_summary.txt"

if [[ ! -s out/telegram_daily_summary.txt ]]; then
  echo "ERROR: summary file is empty"
  exit 1
fi

curl --silent --show-error --fail -X POST \
  "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
  --data-urlencode "chat_id=${TG_CHAT_ID}" \
  --data-urlencode "text=$(cat out/telegram_daily_summary.txt)" \
  --data-urlencode "disable_web_page_preview=true" \
  >/dev/null

echo "[$(date '+%Y-%m-%d %H:%M:%S %Z')] run_daily_check done"
