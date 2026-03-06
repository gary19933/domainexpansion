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
COUNTRIES=(my sg th np)
COUNTRY_SLEEP_SECONDS="${COUNTRY_SLEEP_SECONDS:-10}"

for i in "${!COUNTRIES[@]}"; do
  country="${COUNTRIES[$i]}"

  echo "[$(date '+%Y-%m-%d %H:%M:%S %Z')] checking country=$country"
  python3 scripts/check_domains.py \
    --country "$country" \
    --list-file "lists/${country}.txt" \
    --log-file "records/ban_log.csv" \
    --rows-output "out/${country}_rows.csv" \
    --no-append-log \
    --date "$RUN_DATE"

  if (( i < ${#COUNTRIES[@]} - 1 )) && (( COUNTRY_SLEEP_SECONDS > 0 )); then
    echo "[$(date '+%Y-%m-%d %H:%M:%S %Z')] sleeping ${COUNTRY_SLEEP_SECONDS}s before next country"
    sleep "$COUNTRY_SLEEP_SECONDS"
  fi
done

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
