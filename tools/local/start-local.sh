#!/usr/bin/env bash
# Local-only EnMaaS SSO/dashboard demo. Starts Postgres, the MaaS stub, the mock
# OIDC provider (with personas), and metering-service from this checkout.
#
#   ./tools/local/start-local.sh          start (or restart) everything
#   ./tools/local/start-local.sh stop     stop everything, keep volumes
#   ./tools/local/start-local.sh reset    stop everything and delete volumes
#
# Nothing here touches a cluster, a secret, or production data.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE="${HOME}/enmaas-oidc-local"
COMPOSE_FILE="${ROOT}/docker-compose.oidc-local.yaml"
PROJECT="pricetag-oidc-local"
DB_URL="postgres://metering:metering-oidc-local@localhost:15432/metering?sslmode=disable"

mkdir -p "$STATE"

stop_all() {
  for name in metering oidc-mock live-traffic; do
    pid_file="$STATE/${name}.pid"
    if [[ -f "$pid_file" ]]; then
      pid="$(cat "$pid_file")"
      pkill -P "$pid" 2>/dev/null || true
      kill "$pid" 2>/dev/null || true
      rm -f "$pid_file"
    fi
  done
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" down --remove-orphans >/dev/null 2>&1 || true
}

if [[ "${1:-start}" == "stop" ]]; then
  stop_all
  echo "Stopped local EnMaaS demo."
  exit 0
fi

if [[ "${1:-start}" == "reset" ]]; then
  stop_all
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
  echo "Stopped and deleted local volumes."
  exit 0
fi

stop_all

echo "==> starting Postgres and the MaaS stub"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d --wait

echo "==> building the mock OIDC provider"
(cd "$ROOT" && go build -o "$STATE/oidc-mock" ./tools/local/oidc-mock)

MOCK_OIDC_ISSUER="http://localhost:9999" \
MOCK_OIDC_LISTEN=":9999" \
  nohup "$STATE/oidc-mock" >"$STATE/oidc-mock.log" 2>&1 &
echo $! >"$STATE/oidc-mock.pid"

for _ in $(seq 1 50); do
  curl -fsS http://localhost:9999/.well-known/openid-configuration >/dev/null 2>&1 && break
  sleep 0.2
done

echo "==> starting metering-service"
(
  cd "$ROOT"
  DATABASE_URL="$DB_URL" \
  PORT=8080 \
  SESSION_SECRET=local-demo-session-secret \
  SESSION_COOKIE_SECURE=false \
  OIDC_ENABLED=true \
  OIDC_ISSUER_URL=http://localhost:9999 \
  OIDC_CLIENT_ID=local-dashboard \
  OIDC_CLIENT_SECRET=local-secret \
  OIDC_REDIRECT_URL=http://localhost:8080/oauth/callback \
  OIDC_SCOPES="openid profile email" \
  OIDC_CLAIMS_DEBUG=false \
  OIDC_DEVELOPMENT_MODE=true \
  OIDC_TEST_LOGIN=true \
  MODEL_CATALOG_FILE="$ROOT/tools/local/model-catalog.yaml" \
  MODEL_ACCESS_ENFORCEMENT=observe \
  DEFAULT_KEY_EXPIRY_HOURS=2160 \
  MAX_KEY_EXPIRY_HOURS=8760 \
  WELCOME_GATEWAY_URL=http://localhost:18081 \
  WELCOME_DASHBOARD_URL=http://localhost:8080 \
  MAAS_API_URL=http://localhost:18081 \
  MAAS_VALIDATE_URL=http://localhost:18081/internal/v1/api-keys/validate \
  MAAS_TENANT=models-as-a-service \
  SUPERADMIN_USERS=local-admin@example.com \
  go run ./cmd >"$STATE/metering.log" 2>&1 &
  echo $! >"$STATE/metering.pid"
)

echo "==> waiting for migrations and readiness"
ready=0
for _ in $(seq 1 180); do
  if curl -fsS http://localhost:8080/ready >/dev/null 2>&1; then ready=1; break; fi
  sleep 0.5
done
if [[ "$ready" != "1" ]]; then
  echo "metering-service did not become ready; tail of $STATE/metering.log:" >&2
  tail -30 "$STATE/metering.log" >&2
  exit 1
fi

echo "==> seeding local personas"
COMPOSE_PROJECT_NAME="$PROJECT" COMPOSE_FILE="$COMPOSE_FILE" bash "$ROOT/tools/local/bootstrap.sh" >/dev/null
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T postgres \
  psql -q -U metering -d metering < "$ROOT/tools/local/seed-sso-personas.sql"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T postgres \
  psql -q -U metering -d metering < "$ROOT/tools/local/seed-dashboard-demo.sql"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T postgres \
  psql -q -U metering -d metering < "$ROOT/tools/local/seed-model-access.sql"

echo "==> starting synthetic live traffic"
nohup bash "$ROOT/tools/local/live-demo-traffic.sh" >"$STATE/live-traffic.log" 2>&1 &
echo $! >"$STATE/live-traffic.pid"

cat <<EOF

EnMaaS local demo is running.

  Login             http://localhost:8080/login
  Mock IdP picker   http://localhost:9999/authorize  (shown automatically)
  Account           http://localhost:8080/account
  API-key login     local-admin-key

  Personas (Test sign-in or pick at the mock IdP):
    new-user          regular user → My usage + API keys
    returning-user    regular user with keys + month-to-date usage; \$500 role budget + \$75 credit
    manager-user      Maya Manager, two direct reports + seeded team traffic → My team
    admin             super-admin → org usage and Admin → Model access

  Model access demo (Admin → Model access):
    catalog           8 local models imported from tools/local/model-catalog.yaml
    Standard          default role, \$300/person
    Super users       +\$200/person (returning-user, manager-user → \$500 total)
    Research          models only, no budget (team-alice)
    credit            \$75 for returning-user, expires end of month
    exclusion         team-bob is excluded from the default role
    enforcement       MODEL_ACCESS_ENFORCEMENT=observe (evaluates, never blocks)

  Logs: $STATE/metering.log · $STATE/oidc-mock.log · $STATE/live-traffic.log
  Stop: $ROOT/tools/local/start-local.sh stop
EOF
