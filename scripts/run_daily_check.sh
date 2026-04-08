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
mkdir -p out records

RUN_DATE="$(TZ=Asia/Kuala_Lumpur date '+%Y-%m-%d')"

# ---------------------------------------------------------------------------
# VPS node-based countries (MY, SG, TH)
# SSH host aliases are expected in ~/.ssh/config:
#   Host my-node / sg-node / th-node
# ---------------------------------------------------------------------------
VPS_COUNTRIES=(my sg th)
CHECKER_USER="${CHECKER_USER:-checker}"
CHECKER_SCRIPT="/home/${CHECKER_USER}/checker_node.py"
CHECKER_CONFIG="/home/${CHECKER_USER}/config.json"

for country in "${VPS_COUNTRIES[@]}"; do
  node_host="${country}-node"
  echo "[$(date '+%Y-%m-%d %H:%M:%S %Z')] VPS check country=$country node=$node_host"

  # Sync domain list to node
  scp -q "lists/${country}.txt" "${CHECKER_USER}@${node_host}:/home/${CHECKER_USER}/lists/${country}.txt" || {
    echo "WARNING: failed to sync list to $node_host, skipping"
    continue
  }

  # Trigger check on node
  ssh -o ConnectTimeout=10 "${CHECKER_USER}@${node_host}" \
    "python3 ${CHECKER_SCRIPT} --config ${CHECKER_CONFIG} --list /home/${CHECKER_USER}/lists/${country}.txt" || {
    echo "WARNING: checker_node.py failed on $node_host"
  }

  # Pull results
  scp -q "${CHECKER_USER}@${node_host}:/home/${CHECKER_USER}/results/latest.json" \
    "out/${country}_node_results.json" || {
    echo "WARNING: failed to pull results from $node_host"
  }
done

# Convert VPS node results to CSV
python3 scripts/collect_results.py \
  --date "$RUN_DATE" \
  --out-dir "out" \
  --countries "$(IFS=,; echo "${VPS_COUNTRIES[*]}")"

# ---------------------------------------------------------------------------
# Proxy-based fallback countries (NP)
# ---------------------------------------------------------------------------
PROXY_COUNTRIES=(np)
COUNTRY_SLEEP_SECONDS="${COUNTRY_SLEEP_SECONDS:-10}"

for i in "${!PROXY_COUNTRIES[@]}"; do
  country="${PROXY_COUNTRIES[$i]}"
  upper_country="$(echo "$country" | tr '[:lower:]' '[:upper:]')"
  proxy_var="RES_PROXY_${upper_country}"
  proxy_url="${!proxy_var:-}"

  if [[ -z "$proxy_url" ]]; then
    echo "WARNING: no proxy for $country (${proxy_var} not set), skipping"
    continue
  fi

  echo "[$(date '+%Y-%m-%d %H:%M:%S %Z')] proxy check country=$country"
  python3 scripts/check_domains.py \
    --country "$country" \
    --list-file "lists/${country}.txt" \
    --log-file "records/ban_log.csv" \
    --rows-output "out/${country}_rows.csv" \
    --no-append-log \
    --date "$RUN_DATE" \
    --proxy-url "$proxy_url"

  if (( i < ${#PROXY_COUNTRIES[@]} - 1 )) && (( COUNTRY_SLEEP_SECONDS > 0 )); then
    sleep "$COUNTRY_SLEEP_SECONDS"
  fi
done

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
