#!/usr/bin/env bash
# Local-only synthetic live traffic. Keeps Recent Activity and the map flash
# alive while the demo is running. Never use outside a laptop.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROJECT="${COMPOSE_PROJECT_NAME:-pricetag-oidc-local}"
COMPOSE_FILE="${ROOT}/docker-compose.oidc-local.yaml"
SQL="${ROOT}/tools/local/live-demo-traffic.sql"
INTERVAL="${LIVE_DEMO_INTERVAL:-6}"

while true; do
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T postgres \
    psql -q -v ON_ERROR_STOP=1 -U metering -d metering -f - < "$SQL" >/dev/null 2>&1 || true
  sleep "$INTERVAL"
done
