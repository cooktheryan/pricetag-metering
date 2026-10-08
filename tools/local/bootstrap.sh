#!/usr/bin/env bash
set -euo pipefail

# Local-only fixture. This deliberately creates no production key and never
# imports production data or provider credentials.
PROJECT="${COMPOSE_PROJECT_NAME:-pricetag-safety}"
until docker compose -p "$PROJECT" exec -T postgres pg_isready -U metering -d metering >/dev/null 2>&1; do
  sleep 1
done

docker compose -p "$PROJECT" exec -T postgres psql -U metering -d metering <<'SQL'
INSERT INTO partner_users (user_id, tags, role, active, created_by, updated_by)
VALUES (
  '00000000-0000-4000-8000-000000000001',
  '{"email":"nitzikow@redhat.com","first_name":"Noy","last_name":"Itzikowitz","country":"US","kerberos_id":"nitzikow"}',
  'super_admin', true, 'local-bootstrap', 'local-bootstrap'
)
ON CONFLICT (user_id) DO UPDATE SET role='super_admin', active=true;

INSERT INTO partner_user_logins (username, user_id, is_current)
VALUES ('nitzikow@redhat.com', '00000000-0000-4000-8000-000000000001', true)
ON CONFLICT (username) DO UPDATE SET user_id=EXCLUDED.user_id, is_current=true;

INSERT INTO partner_users (user_id, tags, role, active, created_by, updated_by)
VALUES (
  '00000000-0000-4000-8000-000000000002',
  '{"email":"local-test-user@example.com","first_name":"Local","last_name":"Test User","country":"US"}',
  'user', true, 'local-bootstrap', 'local-bootstrap'
)
ON CONFLICT (user_id) DO UPDATE SET active=true;

INSERT INTO partner_user_logins (username, user_id, is_current)
VALUES ('local-test-user@example.com', '00000000-0000-4000-8000-000000000002', true)
ON CONFLICT (username) DO UPDATE SET user_id=EXCLUDED.user_id, is_current=true;

INSERT INTO partner_user_keys (key_id, user_id, username, name, created_by)
VALUES ('local-test-user-key', '00000000-0000-4000-8000-000000000002',
        'local-test-user@example.com', 'local test inference key', 'local-bootstrap')
ON CONFLICT (key_id) DO UPDATE SET revoked_at=NULL;

-- Synthetic current-month spend. cost_usd is frozen at $150 so this fixture
-- does not depend on production pricing or provider credentials.
DELETE FROM usage_events
WHERE username='local-test-user@example.com' AND source='local-bootstrap';
INSERT INTO usage_events
  (event_id, timestamp, username, model, provider, source,
   prompt_tokens, completion_tokens, total_tokens, status_code, cost_usd)
VALUES
  ('local-bootstrap-$150', date_trunc('month', NOW()) + interval '1 hour',
   'local-test-user@example.com', 'local-echo', 'llm-katan', 'local-bootstrap',
   0, 2000000, 2000000, 200, 150.00)
ON CONFLICT DO NOTHING;

-- Tool-color/chart fixtures. Each client has a distinct user-agent so the
-- Usage page can exercise the four primary tool colors, curl's gray, and the
-- catch-all "Other" color without relying on any real traffic.
DELETE FROM usage_events WHERE source='local-tool-fixture';

INSERT INTO partner_users (user_id, tags, role, active, created_by, updated_by)
VALUES
  ('00000000-0000-4000-8000-000000000003', '{"email":"fixture-claude@example.com","first_name":"Fixture","last_name":"Claude","country":"US"}', 'user', true, 'local-bootstrap', 'local-bootstrap'),
  ('00000000-0000-4000-8000-000000000004', '{"email":"fixture-codex@example.com","first_name":"Fixture","last_name":"Codex","country":"US"}', 'user', true, 'local-bootstrap', 'local-bootstrap'),
  ('00000000-0000-4000-8000-000000000005', '{"email":"fixture-opencode@example.com","first_name":"Fixture","last_name":"OpenCode","country":"US"}', 'user', true, 'local-bootstrap', 'local-bootstrap'),
  ('00000000-0000-4000-8000-000000000006', '{"email":"fixture-pi@example.com","first_name":"Fixture","last_name":"Pi","country":"US"}', 'user', true, 'local-bootstrap', 'local-bootstrap'),
  ('00000000-0000-4000-8000-000000000007', '{"email":"fixture-curl@example.com","first_name":"Fixture","last_name":"curl","country":"US"}', 'user', true, 'local-bootstrap', 'local-bootstrap'),
  ('00000000-0000-4000-8000-000000000008', '{"email":"fixture-other@example.com","first_name":"Fixture","last_name":"Other","country":"US"}', 'user', true, 'local-bootstrap', 'local-bootstrap')
ON CONFLICT (user_id) DO UPDATE SET active=true;

INSERT INTO partner_user_logins (username, user_id, is_current)
VALUES
  ('fixture-claude@example.com', '00000000-0000-4000-8000-000000000003', true),
  ('fixture-codex@example.com', '00000000-0000-4000-8000-000000000004', true),
  ('fixture-opencode@example.com', '00000000-0000-4000-8000-000000000005', true),
  ('fixture-pi@example.com', '00000000-0000-4000-8000-000000000006', true),
  ('fixture-curl@example.com', '00000000-0000-4000-8000-000000000007', true),
  ('fixture-other@example.com', '00000000-0000-4000-8000-000000000008', true)
ON CONFLICT (username) DO UPDATE SET user_id=EXCLUDED.user_id, is_current=true;

INSERT INTO usage_events
  (event_id, timestamp, username, model, provider, source, user_agent,
   prompt_tokens, completion_tokens, total_tokens, status_code, cost_usd)
VALUES
  ('local-tool-claude', NOW() - interval '6 hours', 'fixture-claude@example.com', 'fixture-model', 'fixture', 'local-tool-fixture', 'claude-code/2.1.0', 120000, 80000, 200000, 200, 12.00),
  ('local-tool-codex', NOW() - interval '5 hours', 'fixture-codex@example.com', 'fixture-model', 'fixture', 'local-tool-fixture', 'codex-tui/0.1.0', 220000, 100000, 320000, 200, 18.00),
  ('local-tool-opencode', NOW() - interval '4 hours', 'fixture-opencode@example.com', 'fixture-model', 'fixture', 'local-tool-fixture', 'opencode-nightly/1.0', 180000, 70000, 250000, 200, 15.00),
  ('local-tool-pi', NOW() - interval '3 hours', 'fixture-pi@example.com', 'fixture-model', 'fixture', 'local-tool-fixture', 'pi-coding-agent/0.1', 260000, 140000, 400000, 200, 24.00),
  ('local-tool-curl', NOW() - interval '2 hours', 'fixture-curl@example.com', 'fixture-model', 'fixture', 'local-tool-fixture', 'curl/8.7.1', 50000, 20000, 70000, 200, 4.00),
  ('local-tool-other', NOW() - interval '1 hour', 'fixture-other@example.com', 'fixture-model', 'fixture', 'local-tool-fixture', 'python-requests/2.32', 90000, 40000, 130000, 200, 8.00)
ON CONFLICT DO NOTHING;
SQL

echo "Local super-admin key: local-noy-key"
echo "Local test-user key: local-test-user-key"
echo "Test user synthetic month-to-date spend: \$150"
echo "Dashboard: http://localhost:8080/admin"
