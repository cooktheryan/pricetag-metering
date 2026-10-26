-- Local-only onboarding personas. Runs after the service has migrated the
-- schema and after tools/local/bootstrap.sh. Never use outside a laptop.

BEGIN;

-- ---------------------------------------------------------------------------
-- Personas. UUIDs, emails, and countries match tools/local/oidc-mock.
-- ---------------------------------------------------------------------------
INSERT INTO partner_users (user_id, tags, role, manager_user_id, active, created_by, updated_by)
VALUES
  ('11111111-1111-4111-8111-111111111111',
   '{"email":"new-user@example.com","first_name":"Nina","last_name":"New","country":"US","kerberos_id":"newuser"}',
   'user', NULL, true, 'local-seed', 'local-seed'),
  ('22222222-2222-4222-8222-222222222222',
   '{"email":"returning-user@example.com","first_name":"Ravi","last_name":"Return","country":"US","kerberos_id":"returning"}',
   'user', NULL, true, 'local-seed', 'local-seed'),
  ('33333333-3333-4333-8333-333333333333',
   '{"email":"blocked-user@example.com","first_name":"Bea","last_name":"Blocked","country":"IR","kerberos_id":"blocked"}',
   'user', NULL, true, 'local-seed', 'local-seed'),
  ('44444444-4444-4444-8444-444444444444',
   '{"email":"nogroup-user@example.com","first_name":"Noah","last_name":"Nogroup","country":"US","kerberos_id":"nogroup"}',
   'user', NULL, true, 'local-seed', 'local-seed'),
  ('55555555-5555-4555-8555-555555555555',
   '{"email":"manager-user@example.com","first_name":"Maya","last_name":"Manager","country":"US","kerberos_id":"manager"}',
   'user', NULL, true, 'local-seed', 'local-seed'),
  ('66666666-6666-4666-8666-666666666666',
   '{"email":"team-alice@example.com","first_name":"Alice","last_name":"Team","country":"US","kerberos_id":"team-alice"}',
   'user', '55555555-5555-4555-8555-555555555555', true, 'local-seed', 'local-seed'),
  ('77777777-7777-4777-8777-777777777777',
   '{"email":"team-bob@example.com","first_name":"Bob","last_name":"Team","country":"US","kerberos_id":"team-bob"}',
   'user', '55555555-5555-4555-8555-555555555555', true, 'local-seed', 'local-seed')
ON CONFLICT (user_id) DO UPDATE
   SET tags = EXCLUDED.tags, manager_user_id = EXCLUDED.manager_user_id, active = true, updated_by = 'local-seed';

INSERT INTO partner_user_logins (username, user_id, is_current)
VALUES
  ('new-user@example.com', '11111111-1111-4111-8111-111111111111', true),
  ('returning-user@example.com', '22222222-2222-4222-8222-222222222222', true),
  ('blocked-user@example.com', '33333333-3333-4333-8333-333333333333', true),
  ('nogroup-user@example.com', '44444444-4444-4444-8444-444444444444', true)
 ,('manager-user@example.com', '55555555-5555-4555-8555-555555555555', true)
 ,('team-alice@example.com', '66666666-6666-4666-8666-666666666666', true)
 ,('team-bob@example.com', '77777777-7777-4777-8777-777777777777', true)
ON CONFLICT (username) DO UPDATE SET user_id = EXCLUDED.user_id, is_current = true;

-- ---------------------------------------------------------------------------
-- Policy: GE is authorized; Iran (ISO3 IRN) is blocked. Editable in
-- /admin/access as the super admin.
-- ---------------------------------------------------------------------------
INSERT INTO access_policy (id, allowed_groups, blocked_countries, allow_unknown_country, updated_by)
VALUES (1, ARRAY['GE'], ARRAY['IRN'], false, 'local-seed')
ON CONFLICT (id) DO UPDATE
  SET allowed_groups = EXCLUDED.allowed_groups,
      blocked_countries = EXCLUDED.blocked_countries,
      allow_unknown_country = EXCLUDED.allow_unknown_country,
      updated_by = EXCLUDED.updated_by,
      updated_at = NOW();

-- ---------------------------------------------------------------------------
-- Terms: the returning user already accepted; every other persona starts
-- fresh so restarting the demo always shows the onboarding gates again.
-- ---------------------------------------------------------------------------
DELETE FROM user_agreements WHERE user_id IN (
  '11111111-1111-4111-8111-111111111111',
  '33333333-3333-4333-8333-333333333333',
  '44444444-4444-4444-8444-444444444444'
 , '55555555-5555-4555-8555-555555555555'
 , '66666666-6666-4666-8666-666666666666'
 , '77777777-7777-4777-8777-777777777777'
);
DELETE FROM user_agreements WHERE user_id = '22222222-2222-4222-8222-222222222222';
INSERT INTO user_agreements (user_id, doc_type, version, accepted_at, method)
VALUES ('22222222-2222-4222-8222-222222222222', 'terms', 'draft-tbd', NOW() - interval '30 days', 'oidc')
ON CONFLICT DO NOTHING;
INSERT INTO user_agreements (user_id, doc_type, version, accepted_at, method)
SELECT id, 'terms', 'draft-tbd', NOW() - interval '14 days', 'oidc'
FROM (VALUES
  ('55555555-5555-4555-8555-555555555555'::uuid),
  ('66666666-6666-4666-8666-666666666666'::uuid),
  ('77777777-7777-4777-8777-777777777777'::uuid)
) AS seeded(id)
ON CONFLICT DO NOTHING;

-- Pricing for the hosted models used by the demo. Without a row the rollup
-- refresh prices them at the frontier fallback rate, which makes a hosted
-- model look like the most expensive thing in the account.
INSERT INTO model_pricing
  (model, provider, input_cost_per_mtok, output_cost_per_mtok,
   cache_read_cost_per_mtok, cache_write_cost_per_mtok,
   list_input_cost_per_mtok, list_output_cost_per_mtok,
   list_cache_read_cost_per_mtok, list_cache_write_cost_per_mtok)
VALUES
  ('qwen3-coder',    'vllm', 0.5000, 1.5000, 0.0500, 0.5000, 0.5000, 1.5000, 0.0500, 0.5000),
  ('llama-4-scout',  'vllm', 0.2000, 0.6000, 0.0200, 0.2000, 0.2000, 0.6000, 0.0200, 0.2000)
ON CONFLICT (model) DO UPDATE
  SET provider = EXCLUDED.provider,
      input_cost_per_mtok = EXCLUDED.input_cost_per_mtok,
      output_cost_per_mtok = EXCLUDED.output_cost_per_mtok,
      cache_read_cost_per_mtok = EXCLUDED.cache_read_cost_per_mtok,
      cache_write_cost_per_mtok = EXCLUDED.cache_write_cost_per_mtok,
      list_input_cost_per_mtok = EXCLUDED.list_input_cost_per_mtok,
      list_output_cost_per_mtok = EXCLUDED.list_output_cost_per_mtok,
      list_cache_read_cost_per_mtok = EXCLUDED.list_cache_read_cost_per_mtok,
      list_cache_write_cost_per_mtok = EXCLUDED.list_cache_write_cost_per_mtok;

-- ---------------------------------------------------------------------------
-- Usage for the returning user: frontier + hosted traffic, month to date.
-- ---------------------------------------------------------------------------
DELETE FROM usage_events WHERE username = 'returning-user@example.com' AND source = 'local-onboarding';

INSERT INTO usage_events
  (event_id, timestamp, username, group_name, model, provider, source, user_agent,
   prompt_tokens, completion_tokens, total_tokens, cached_input_tokens,
   status_code, cost_usd)
VALUES
  ('local-onb-01', NOW() - interval '2 days 4 hours', 'returning-user@example.com', 'GE', 'claude-sonnet-4-5', 'anthropic', 'local-onboarding', 'claude-code/2.1.0', 120000, 38000, 158000, 40000, 200, 4.82),
  ('local-onb-02', NOW() - interval '2 days 1 hour',  'returning-user@example.com', 'GE', 'claude-sonnet-4-5', 'anthropic', 'local-onboarding', 'claude-code/2.1.0',  90000, 26000, 116000, 22000, 200, 3.41),
  ('local-onb-03', NOW() - interval '1 day 9 hours',  'returning-user@example.com', 'GE', 'gpt-5',             'openai',    'local-onboarding', 'codex-tui/0.1.0',    210000, 64000, 274000,     0, 200, 5.95),
  ('local-onb-04', NOW() - interval '1 day 6 hours',  'returning-user@example.com', 'GE', 'qwen3-coder',       'qwen-flash',      'local-onboarding', 'opencode-nightly/1.0', 340000, 120000, 460000, 80000, 200, 1.15),
  ('local-onb-05', NOW() - interval '1 day 2 hours',  'returning-user@example.com', 'GE', 'qwen3-coder',       'qwen-flash',      'local-onboarding', 'opencode-nightly/1.0', 180000,  55000, 235000, 30000, 200, 0.59),
  ('local-onb-06', NOW() - interval '20 hours',       'returning-user@example.com', 'GE', 'claude-sonnet-4-5', 'anthropic', 'local-onboarding', 'claude-code/2.1.0',   65000,  21000,  86000, 12000, 200, 2.63),
  ('local-onb-07', NOW() - interval '14 hours',       'returning-user@example.com', 'GE', 'gpt-5',             'openai',    'local-onboarding', 'codex-tui/0.1.0',    140000,  42000, 182000,     0, 200, 4.05),
  ('local-onb-08', NOW() - interval '9 hours',        'returning-user@example.com', 'GE', 'llama-4-scout',     'qwen-flash',      'local-onboarding', 'pi-coding-agent/0.1', 220000,  88000, 308000, 50000, 200, 0.74),
  ('local-onb-09', NOW() - interval '5 hours',        'returning-user@example.com', 'GE', 'claude-sonnet-4-5', 'anthropic', 'local-onboarding', 'claude-code/2.1.0',   48000,  16000,  64000,  8000, 200, 1.94),
  ('local-onb-10', NOW() - interval '3 hours',        'returning-user@example.com', 'GE', 'qwen3-coder',       'qwen-flash',      'local-onboarding', 'opencode-nightly/1.0',  95000,  31000, 126000, 15000, 200, 0.32),
  ('local-onb-11', NOW() - interval '90 minutes',     'returning-user@example.com', 'GE', 'gpt-5',             'openai',    'local-onboarding', 'codex-tui/0.1.0',     52000,  18000,  70000,     0, 429, 0.00),
  ('local-onb-12', NOW() - interval '25 minutes',     'returning-user@example.com', 'GE', 'claude-sonnet-4-5', 'anthropic', 'local-onboarding', 'claude-code/2.1.0',   31000,  11000,  42000,  5000, 200, 1.27),
  ('local-onb-13', NOW() - interval '22 minutes', 'returning-user@example.com', 'GE', 'claude-sonnet-4-5', 'anthropic', 'local-onboarding', 'claude-code/2.1.0', 1000000, 2466667, 3466667, 0, 200, 40.000005),
  ('local-onb-14', NOW() - interval '20 minutes', 'returning-user@example.com', 'GE', 'claude-sonnet-4-5', 'anthropic', 'local-onboarding', 'claude-code/2.1.0', 1000000, 2466667, 3466667, 0, 200, 40.000005),
  ('local-onb-15', NOW() - interval '18 minutes', 'returning-user@example.com', 'GE', 'claude-sonnet-4-5', 'anthropic', 'local-onboarding', 'claude-code/2.1.0', 1000000, 2466667, 3466667, 0, 200, 40.000005),
  ('local-onb-16', NOW() - interval '16 minutes', 'returning-user@example.com', 'GE', 'gpt-5', 'openai', 'local-onboarding', 'codex-tui/0.1.0', 1000000, 3625000, 4625000, 0, 200, 30.000000),
  ('local-onb-17', NOW() - interval '14 minutes', 'returning-user@example.com', 'GE', 'gpt-5', 'openai', 'local-onboarding', 'codex-tui/0.1.0', 1000000, 3625000, 4625000, 0, 200, 30.000000),
  ('local-onb-18', NOW() - interval '12 minutes', 'returning-user@example.com', 'GE', 'gpt-5', 'openai', 'local-onboarding', 'codex-tui/0.1.0', 1000000, 3625000, 4625000, 0, 200, 30.000000),
  ('local-onb-19', NOW() - interval '10 minutes', 'returning-user@example.com', 'GE', 'qwen3-coder', 'qwen-flash', 'local-onboarding', 'opencode-nightly/1.0', 5000000, 5000000, 10000000, 0, 200, 10.000000),
  ('local-onb-20', NOW() - interval '8 minutes', 'returning-user@example.com', 'GE', 'qwen3-coder', 'qwen-flash', 'local-onboarding', 'opencode-nightly/1.0', 5000000, 5000000, 10000000, 0, 200, 10.000000),
  ('local-onb-21', NOW() - interval '7 minutes', 'returning-user@example.com', 'GE', 'qwen3-coder', 'qwen-flash', 'local-onboarding', 'opencode-nightly/1.0', 5000000, 5000000, 10000000, 0, 200, 10.000000),
  ('local-onb-22', NOW() - interval '6 minutes', 'returning-user@example.com', 'GE', 'llama-4-scout', 'qwen-flash', 'local-onboarding', 'pi-coding-agent/0.1', 10000000, 6666667, 16666667, 0, 200, 6.000000),
  ('local-onb-23', NOW() - interval '5 minutes', 'returning-user@example.com', 'GE', 'llama-4-scout', 'qwen-flash', 'local-onboarding', 'pi-coding-agent/0.1', 10000000, 6666667, 16666667, 0, 200, 6.000000),
  ('local-onb-24', NOW() - interval '4 minutes', 'returning-user@example.com', 'GE', 'claude-sonnet-4-5', 'anthropic', 'local-onboarding', 'claude-code/2.1.0', 150000, 66723, 216723, 0, 200, 1.450845);

-- ---------------------------------------------------------------------------
-- Local manager demo: Maya has two direct reports and team traffic.
-- ---------------------------------------------------------------------------
DELETE FROM usage_events WHERE username IN ('manager-user@example.com', 'team-alice@example.com', 'team-bob@example.com') AND source = 'local-manager';

INSERT INTO usage_events
  (event_id, timestamp, username, group_name, model, provider, source, user_agent,
   prompt_tokens, completion_tokens, total_tokens, cached_input_tokens,
   status_code, cost_usd)
VALUES
  ('local-mgr-01', NOW() - interval '2 hours',  'manager-user@example.com', 'GE', 'gpt-5', 'openai', 'local-manager', 'codex-tui/0.1.0', 220000, 80000, 300000, 0, 200, 0.86),
  ('local-mgr-02', NOW() - interval '90 minutes','manager-user@example.com', 'GE', 'qwen3-coder', 'qwen-flash', 'local-manager', 'opencode-nightly/1.0', 800000, 300000, 1100000, 100000, 200, 0.85),
  ('local-mgr-03', NOW() - interval '70 minutes','team-alice@example.com', 'GE', 'claude-sonnet-4-5', 'anthropic', 'local-manager', 'claude-code/2.1.0', 180000, 70000, 250000, 20000, 200, 1.32),
  ('local-mgr-04', NOW() - interval '55 minutes','team-alice@example.com', 'GE', 'llama-4-scout', 'qwen-flash', 'local-manager', 'pi-coding-agent/0.1', 900000, 400000, 1300000, 0, 200, 0.42),
  ('local-mgr-05', NOW() - interval '40 minutes','team-bob@example.com', 'GE', 'gpt-5', 'openai', 'local-manager', 'codex-tui/0.1.0', 350000, 120000, 470000, 0, 200, 1.31),
  ('local-mgr-06', NOW() - interval '25 minutes','team-bob@example.com', 'GE', 'qwen3-coder', 'qwen-flash', 'local-manager', 'opencode-nightly/1.0', 1200000, 500000, 1700000, 200000, 200, 1.25);

-- Rebuild derived rollups so the account page reads the seeded rows.
TRUNCATE usage_hourly;
INSERT INTO usage_hourly
  (hour, username, group_name, model, provider, requests,
   prompt_tokens, completion_tokens, total_tokens, cached_input_tokens,
   cache_creation_tokens, cost_usd)
SELECT date_trunc('hour', e.timestamp), e.username, COALESCE(e.group_name, ''),
  e.model, e.provider,
  COUNT(*), SUM(e.prompt_tokens), SUM(e.completion_tokens), SUM(e.total_tokens),
  SUM(e.cached_input_tokens), SUM(e.cache_creation_tokens), COALESCE(SUM(e.cost_usd), 0)
FROM usage_events e
GROUP BY date_trunc('hour', e.timestamp), e.username, COALESCE(e.group_name, ''),
   e.model, e.provider;

COMMIT;
