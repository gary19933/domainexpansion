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
# VPS node-based countries (MY, SG, TH)
# SSH host aliases are expected in ~/.ssh/config:
#   Host my-node / sg-node / th-node
# Each node just needs the repo cloned at /root/domainexpansion
# ---------------------------------------------------------------------------
VPS_COUNTRIES=(my sg th np)
NODE_USER="root"
NODE_REPO="/root/domainexpansion"

for country in "${VPS_COUNTRIES[@]}"; do
  node_host="${country}-node"
  echo "[$(date '+%Y-%m-%d %H:%M:%S %Z')] VPS check country=$country node=$node_host"

  # Pull latest lists and scripts on node
  ssh -o ConnectTimeout=10 "${NODE_USER}@${node_host}" \
    "cd ${NODE_REPO} && git pull --ff-only origin main" || {
    echo "WARNING: git pull failed on $node_host, running with existing copy"
  }

  # Trigger check on node — output to /tmp for easy retrieval
  ssh -o ConnectTimeout=10 "${NODE_USER}@${node_host}" \
    "python3 ${NODE_REPO}/scripts/checker_node.py \
     --config ${NODE_REPO}/deploy/node_configs/${country}.json \
     --list ${NODE_REPO}/lists/${country}.txt \
     --output /tmp/${country}_results.json" || {
    echo "WARNING: checker_node.py failed on $node_host"
  }

  # Pull results back to controller
  scp -q "${NODE_USER}@${node_host}:/tmp/${country}_results.json" \
    "out/${country}_node_results.json" || {
    echo "WARNING: failed to pull results from $node_host"
  }
done

# Convert VPS node results to CSV
python3 scripts/collect_results.py \
  --date "$RUN_DATE" \
  --out-dir "out" \
  --countries "my,sg,th,np"


# ---------------------------------------------------------------------------
# Merge all results and send Telegram summary
# ---------------------------------------------------------------------------
python3 scripts/merge_summary.py \
  --date "$RUN_DATE" \
  --out-dir "out" \
  --log-file "records/ban_log.csv" \
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
