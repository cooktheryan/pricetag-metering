#!/usr/bin/env bash
# Local-only EnMaaS onboarding demo. Starts Postgres, the MaaS stub, the mock
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
  for name in metering oidc-mock; do
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
  OIDC_SCOPES="openid profile email groups" \
  OIDC_TEST_LOGIN=true \
  DEV_LOGIN_USERS="new-user@example.com,returning-user@example.com,manager-user@example.com,blocked-user@example.com,nogroup-user@example.com,team-alice@example.com,team-bob@example.com" \
  ONBOARDING_MODE=enforce \
  ONBOARDING_TERMS_VERSION=draft-tbd \
  ONBOARDING_TERMS_URL=/legal/terms \
  ACCESS_ALLOWED_GROUPS=GE \
  ACCESS_BLOCKED_COUNTRIES=IRN \
  DEFAULT_KEY_EXPIRY_HOURS=2160 \
  MAX_KEY_EXPIRY_HOURS=8760 \
  WELCOME_GATEWAY_URL=http://localhost:18081 \
  WELCOME_DASHBOARD_URL=http://localhost:8080 \
  MAAS_API_URL=http://localhost:18081 \
  MAAS_VALIDATE_URL=http://localhost:18081/internal/v1/api-keys/validate \
  MAAS_TENANT=models-as-a-service \
  SUPERADMIN_USERS=nitzikow@redhat.com \
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
  psql -q -U metering -d metering < "$ROOT/tools/local/seed-onboarding.sql"

cat <<EOF

EnMaaS local demo is running.

  Login             http://localhost:8080/login
  Mock IdP picker   http://localhost:9999/authorize  (shown automatically)
  Account           http://localhost:8080/account
  Admin policy      http://localhost:8080/admin/access
  API-key login     local-noy-key

  Personas (Dev test sign-in on /login, Test sign-in, or pick at the mock IdP):
    new-user          first login → onboarding + Terms → keys
    returning-user    terms accepted, has keys + month-to-date usage
    manager-user      Maya Manager, two direct reports + seeded team traffic → My team
    blocked-country   GE group, IR (IRN) → region block
    no-group          only technical realm roles → group block
    admin             super-admin (existing /dashboard)

  Logs: $STATE/metering.log · $STATE/oidc-mock.log
  Stop: $ROOT/tools/local/start-local.sh stop
EOF
