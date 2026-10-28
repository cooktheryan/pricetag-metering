-- Local-only dashboard demo data. Never run outside a laptop.
--
-- Seeds a varied directory (countries, US states, cost centers), enough
-- users/models/tools to exercise every new Usage-page chart, and usage across
-- the last 30 days. tools/local/live-demo-traffic.sh adds one fresh request
-- every few seconds so the live map flash can be observed.

BEGIN;

CREATE TEMP TABLE demo_users ON COMMIT DROP AS
SELECT * FROM (VALUES
  ( 1, 'demo-01@example.com', 'Alex',   'Rivera',    'US', 'CA',  'Americas', 'CC-AI-PLATFORM',  'AI Platform Engineering',    'Technology', 'GE'),
  ( 2, 'demo-02@example.com', 'Priya',  'Shah',      'US', 'NY',  'Americas', 'CC-APPLIED-AI',   'Applied AI Research',        'Technology', 'AI'),
  ( 3, 'demo-03@example.com', 'Mateo',  'Garcia',    'US', 'TX',  'Americas', 'CC-DATA-SCIENCE', 'Data Science & Analytics',   'Technology', 'Research'),
  ( 4, 'demo-04@example.com', 'Hannah', 'Lee',       'US', 'WA',  'Americas', 'CC-SECURITY',     'Security Engineering',       'Technology', 'Platform'),
  ( 5, 'demo-05@example.com', 'Omar',   'Hassan',    'US', 'NC',  'Americas', 'CC-CLOUD',        'Cloud Infrastructure',       'Technology', 'GE'),
  ( 6, 'demo-06@example.com', 'Sofia',  'Rossi',     'IT', '',    'EMEA',     'CC-DEVPROD',      'Developer Productivity',     'Technology', 'AI'),
  ( 7, 'demo-07@example.com', 'Lukas',  'Weber',     'DE', 'BE',  'EMEA',     'CC-PLATFORM',     'Platform Engineering',       'Technology', 'Platform'),
  ( 8, 'demo-08@example.com', 'Anika',  'Rao',       'IN', 'KA',  'APAC',     'CC-APPLIED-AI',   'Applied AI Research',        'Technology', 'GE'),
  ( 9, 'demo-09@example.com', 'Emily',  'Clarke',    'GB', 'ENG', 'EMEA',     'CC-CTO',          'Office of the CTO',          'Technology', 'Research'),
  (10, 'demo-10@example.com', 'Noa',    'Cohen',     'IL', 'TA',  'EMEA',     'CC-DATA-SCIENCE', 'Data Science & Analytics',   'Technology', 'AI'),
  (11, 'demo-11@example.com', 'Lucas',  'Silva',     'BR', 'SP',  'Americas', 'CC-DEVPROD',      'Developer Productivity',     'Technology', 'GE'),
  (12, 'demo-12@example.com', 'Yuki',   'Tanaka',    'JP', '13',  'APAC',     'CC-CTO',          'Office of the CTO',          'Technology', 'Research'),
  (13, 'demo-13@example.com', 'Amelie', 'Martin',    'FR', 'IDF', 'EMEA',     'CC-AI-PLATFORM',  'AI Platform Engineering',    'Technology', 'AI'),
  (14, 'demo-14@example.com', 'Diego',  'Lopez',     'ES', 'MD',  'EMEA',     'CC-CLOUD',        'Cloud Infrastructure',       'Technology', 'Platform'),
  (15, 'demo-15@example.com', 'Zofia',  'Nowak',     'PL', 'MZ',  'EMEA',     'CC-SECURITY',     'Security Engineering',       'Technology', 'GE'),
  (16, 'demo-16@example.com', 'Wei',    'Chen',      'SG', '01',  'APAC',     'CC-PLATFORM',     'Platform Engineering',       'Technology', 'AI'),
  (17, 'demo-17@example.com', 'Thabo',  'Nkosi',     'ZA', 'GP',  'EMEA',     'CC-DEVPROD',      'Developer Productivity',     'Technology', 'Research'),
  (18, 'demo-18@example.com', 'Maria',  'Hernandez', 'MX', 'CMX', 'Americas', 'CC-SALES-ENG',    'Sales Engineering',          'Sales',      'GE'),
  (19, 'demo-19@example.com', 'Sofia',  'Andersson', 'SE', 'AB',  'EMEA',     'CC-CTO',          'Office of the CTO',          'Technology', 'Research'),
  (20, 'demo-20@example.com', 'Jonas',  'Meier',     'CH', 'ZH',  'EMEA',     'CC-DATA-SCIENCE', 'Data Science & Analytics',   'Technology', 'AI'),
  (21, 'demo-21@example.com', 'Min-jun','Park',      'KR', '11',  'APAC',     'CC-AI-PLATFORM',  'AI Platform Engineering',    'Technology', 'Platform'),
  (22, 'demo-22@example.com', 'Hsin',   'Chen',      'TW', 'TPE', 'APAC',     'CC-CLOUD',        'Cloud Infrastructure',       'Technology', 'GE'),
  (23, 'demo-23@example.com', 'Fatima', 'Zahra',     'MA', 'CAS', 'EMEA',     'CC-CUSTOMER',     'Customer Success',           'Sales',      'AI'),
  (24, 'demo-24@example.com', 'Grace',  'Kim',       'US', 'MA',  'Americas', 'CC-APPLIED-AI',   'Applied AI Research',        'Technology', 'Research')
) AS u(idx, email, first_name, last_name, country, state, region, cost_center, cost_center_description, organization, group_name);

INSERT INTO partner_users (user_id, tags, role, active, created_by, updated_by)
SELECT ('aaaaaaaa-0000-4000-8000-' || lpad(u.idx::text, 12, '0'))::uuid,
       jsonb_build_object(
         'email', u.email,
         'first_name', u.first_name,
         'last_name', u.last_name,
         'country', u.country,
         'state', u.state,
         'region', u.region,
         'cost_center', u.cost_center,
         'cost_center_description', u.cost_center_description,
         'organization', u.organization,
         'employee_type', 'employee',
         'groups', jsonb_build_array(u.group_name),
         'demo_dashboard', 'true'
       ),
       'user', true, 'local-dashboard-seed', 'local-dashboard-seed'
FROM demo_users u
ON CONFLICT (user_id) DO UPDATE
  SET tags = EXCLUDED.tags, active = true, updated_by = EXCLUDED.updated_by, updated_at = NOW();

-- Give the onboarding/fixture personas a cost center too, so the local
-- By Cost Center pie does not collapse their (useful) traffic into "Unknown".
UPDATE partner_users
SET tags = tags || '{"cost_center":"CC-ONBOARDING","cost_center_description":"Applied AI Research"}'::jsonb,
    updated_by = 'local-dashboard-seed', updated_at = NOW()
WHERE COALESCE(tags->>'cost_center_description', '') = '';
UPDATE partner_users
SET tags = tags || jsonb_build_object('state', 'CA'),
    updated_by = 'local-dashboard-seed', updated_at = NOW()
WHERE COALESCE(tags->>'state', '') = '' AND tags->>'country' = 'US';

INSERT INTO partner_user_logins (username, user_id, is_current)
SELECT u.email, ('aaaaaaaa-0000-4000-8000-' || lpad(u.idx::text, 12, '0'))::uuid, true
FROM demo_users u
ON CONFLICT (username) DO UPDATE
  SET user_id = EXCLUDED.user_id, is_current = true;

-- Pricing for the demo model mix. Hosted providers (vllm) are deliberately
-- cheaper than the vendor models so the hosted-percentage bar is meaningful.
INSERT INTO model_pricing
  (model, provider, input_cost_per_mtok, output_cost_per_mtok,
   cache_read_cost_per_mtok, cache_write_cost_per_mtok,
   list_input_cost_per_mtok, list_output_cost_per_mtok,
   list_cache_read_cost_per_mtok, list_cache_write_cost_per_mtok)
VALUES
  ('qwen3-coder',        'vllm',     0.50,  1.50, 0.05, 0.50,  0.50,  1.50, 0.05, 0.50),
  ('llama-4-scout',      'vllm',     0.20,  0.60, 0.02, 0.20,  0.20,  0.60, 0.02, 0.20),
  ('qwen3-235b',         'vllm',     0.35,  1.10, 0.04, 0.35,  0.35,  1.10, 0.04, 0.35),
  ('granite-3.3-8b',     'vllm',     0.10,  0.30, 0.01, 0.10,  0.10,  0.30, 0.01, 0.10),
  ('claude-opus-4-8',    'anthropic',5.00, 25.00, 0.50, 6.25,  5.00, 25.00, 0.50, 6.25),
  ('claude-sonnet-4-6',  'anthropic',3.00, 15.00, 0.30, 3.75,  3.00, 15.00, 0.30, 3.75),
  ('gpt-5.5',            'openai',   5.00, 30.00, 0.50, 0.00,  5.00, 30.00, 0.50, 0.00),
  ('gpt-5.4',            'openai',   2.50, 15.00, 0.00, 0.00,  2.50, 15.00, 0.00, 0.00),
  ('gemini-2.5-pro',     'google',   1.25, 10.00, 0.31, 0.00,  1.25, 10.00, 0.31, 0.00),
  ('llama-4-maverick',   'openrouter',0.27, 0.85, 0.03, 0.27,  0.27,  0.85, 0.03, 0.27),
  ('mistral-large-3',    'mistral',  2.00,  6.00, 0.20, 2.00,  2.00,  6.00, 0.20, 2.00),
  ('command-r-plus',     'cohere',   2.50, 10.00, 0.25, 2.50,  2.50, 10.00, 0.25, 2.50)
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

DELETE FROM usage_events WHERE source = 'local-dashboard-demo';

WITH models(idx, model, provider) AS (VALUES
  (1, 'qwen3-coder',       'vllm'),
  (2, 'llama-4-scout',     'vllm'),
  (3, 'qwen3-235b',        'vllm'),
  (4, 'granite-3.3-8b',    'vllm'),
  (5, 'claude-opus-4-8',   'anthropic'),
  (6, 'claude-sonnet-4-6', 'anthropic'),
  (7, 'gpt-5.5',           'openai'),
  (8, 'gpt-5.4',           'openai'),
  (9, 'gemini-2.5-pro',    'google'),
  (10,'llama-4-maverick',  'openrouter'),
  (11,'mistral-large-3',   'mistral'),
  (12,'command-r-plus',    'cohere')
),
events AS (
  SELECT u.idx, u.email, u.group_name, d, n,
         NOW() - make_interval(days => d, hours => (n * 2 + (u.idx % 5))) AS ts,
         m.model, m.provider,
         3000 + ((u.idx * 7919 + d * 613 + n * 97) % 60000) AS prompt,
         500 + ((u.idx * 3571 + d * 211 + n * 53) % 12000) AS completion,
         CASE WHEN ((u.idx + d + n) % 3) = 0
              THEN (3000 + ((u.idx * 7919 + d * 613 + n * 97) % 60000)) / 2
              ELSE 0 END AS cached,
         CASE ((u.idx + d * 2 + n * 3) % 11)
           WHEN 0 THEN 'claude-code/2.1.0'
           WHEN 1 THEN 'codex-tui/0.1.0'
           WHEN 2 THEN 'opencode-nightly/1.0'
           WHEN 3 THEN 'pi-coding-agent/0.1'
           WHEN 4 THEN 'charm-crush/v0.1.0'
           WHEN 5 THEN 'OpenAI/Python 2.43.0'
           WHEN 6 THEN 'gemini-cli/0.7.0'
           WHEN 7 THEN 'aider/0.86.1'
           WHEN 8 THEN 'omp/18.10.2'
           WHEN 9 THEN 'curl/8.7.1'
           ELSE 'python-requests/2.32'
         END AS user_agent
  FROM demo_users u
  CROSS JOIN generate_series(0, 29) AS d
  CROSS JOIN generate_series(0, 2) AS n
  JOIN models m ON m.idx = ((u.idx + d * 3 + n * 5) % 12) + 1
)
INSERT INTO usage_events
  (event_id, timestamp, username, group_name, model, provider, source, user_agent,
   prompt_tokens, completion_tokens, total_tokens, cached_input_tokens, status_code, cost_usd)
SELECT 'demo-' || e.idx || '-' || e.d || '-' || e.n, e.ts, e.email, e.group_name,
       e.model, e.provider, 'local-dashboard-demo', e.user_agent,
       e.prompt, e.completion, e.prompt + e.completion, e.cached, 200,
       ROUND(((e.prompt - e.cached) * p.input_cost_per_mtok
              + e.cached * p.cache_read_cost_per_mtok
              + e.completion * p.output_cost_per_mtok) / 1000000.0, 6)
FROM events e
JOIN model_pricing p ON p.model = e.model;

-- Keep the rollups consistent with the fixture. Local reads default to raw,
-- but a tester may flip DASHBOARD_USE_ROLLUPS on.
TRUNCATE usage_hourly;
INSERT INTO usage_hourly
  (hour, username, group_name, model, provider, requests,
   prompt_tokens, completion_tokens, total_tokens, cached_input_tokens,
   cache_creation_tokens, cost_usd)
SELECT date_trunc('hour', e.timestamp), e.username, COALESCE(e.group_name, ''),
       e.model, e.provider, COUNT(*), SUM(e.prompt_tokens), SUM(e.completion_tokens),
       SUM(e.total_tokens), SUM(e.cached_input_tokens), SUM(e.cache_creation_tokens),
       COALESCE(SUM(e.cost_usd), 0)
FROM usage_events e
GROUP BY date_trunc('hour', e.timestamp), e.username, COALESCE(e.group_name, ''),
         e.model, e.provider;

TRUNCATE usage_tool_hourly;
INSERT INTO usage_tool_hourly
  (hour, username, group_name, model, provider, tool, requests,
   prompt_tokens, completion_tokens, total_tokens, cached_input_tokens,
   cache_creation_tokens, cost_usd)
SELECT date_trunc('hour', e.timestamp), e.username, COALESCE(e.group_name, ''),
       e.model, e.provider,
       CASE
         WHEN btrim(lower(coalesce(e.user_agent, ''))) LIKE 'claude-cli%' OR btrim(lower(coalesce(e.user_agent, ''))) LIKE 'claude-code%' THEN 'Claude Code'
         WHEN btrim(lower(coalesce(e.user_agent, ''))) LIKE 'codex-tui%' OR btrim(lower(coalesce(e.user_agent, ''))) LIKE 'codex/%' THEN 'Codex'
         WHEN btrim(lower(coalesce(e.user_agent, ''))) = 'opencode' OR btrim(lower(coalesce(e.user_agent, ''))) LIKE 'opencode/%' OR btrim(lower(coalesce(e.user_agent, ''))) LIKE 'opencode-%' OR btrim(lower(coalesce(e.user_agent, ''))) LIKE 'opencode.%' THEN 'OpenCode'
         WHEN btrim(lower(coalesce(e.user_agent, ''))) = 'pi' OR btrim(lower(coalesce(e.user_agent, ''))) LIKE 'pi/%' OR btrim(lower(coalesce(e.user_agent, ''))) LIKE 'pi-%' OR btrim(lower(coalesce(e.user_agent, ''))) LIKE 'pi.%' OR btrim(lower(coalesce(e.user_agent, ''))) LIKE 'pi %' THEN 'Pi'
         WHEN btrim(lower(coalesce(e.user_agent, ''))) LIKE 'charm-crush/%' THEN 'Charm-Crush'
         WHEN btrim(lower(coalesce(e.user_agent, ''))) LIKE 'openai/%' THEN 'OpenAI'
         WHEN btrim(lower(coalesce(e.user_agent, ''))) LIKE 'gemini-cli/%' THEN 'Gemini CLI'
         WHEN btrim(lower(coalesce(e.user_agent, ''))) LIKE 'aider/%' THEN 'Aider'
         WHEN btrim(lower(coalesce(e.user_agent, ''))) LIKE 'omp/%' THEN 'omp'
         WHEN btrim(lower(coalesce(e.user_agent, ''))) LIKE 'curl/%' THEN 'curl'
         ELSE 'Other'
       END,
       COUNT(*), SUM(e.prompt_tokens), SUM(e.completion_tokens), SUM(e.total_tokens),
       SUM(e.cached_input_tokens), SUM(e.cache_creation_tokens), COALESCE(SUM(e.cost_usd), 0)
FROM usage_events e
GROUP BY date_trunc('hour', e.timestamp), e.username, COALESCE(e.group_name, ''),
         e.model, e.provider,
         CASE
           WHEN btrim(lower(coalesce(e.user_agent, ''))) LIKE 'claude-cli%' OR btrim(lower(coalesce(e.user_agent, ''))) LIKE 'claude-code%' THEN 'Claude Code'
           WHEN btrim(lower(coalesce(e.user_agent, ''))) LIKE 'codex-tui%' OR btrim(lower(coalesce(e.user_agent, ''))) LIKE 'codex/%' THEN 'Codex'
           WHEN btrim(lower(coalesce(e.user_agent, ''))) = 'opencode' OR btrim(lower(coalesce(e.user_agent, ''))) LIKE 'opencode/%' OR btrim(lower(coalesce(e.user_agent, ''))) LIKE 'opencode-%' OR btrim(lower(coalesce(e.user_agent, ''))) LIKE 'opencode.%' THEN 'OpenCode'
           WHEN btrim(lower(coalesce(e.user_agent, ''))) = 'pi' OR btrim(lower(coalesce(e.user_agent, ''))) LIKE 'pi/%' OR btrim(lower(coalesce(e.user_agent, ''))) LIKE 'pi-%' OR btrim(lower(coalesce(e.user_agent, ''))) LIKE 'pi.%' OR btrim(lower(coalesce(e.user_agent, ''))) LIKE 'pi %' THEN 'Pi'
           WHEN btrim(lower(coalesce(e.user_agent, ''))) LIKE 'charm-crush/%' THEN 'Charm-Crush'
           WHEN btrim(lower(coalesce(e.user_agent, ''))) LIKE 'openai/%' THEN 'OpenAI'
           WHEN btrim(lower(coalesce(e.user_agent, ''))) LIKE 'gemini-cli/%' THEN 'Gemini CLI'
           WHEN btrim(lower(coalesce(e.user_agent, ''))) LIKE 'aider/%' THEN 'Aider'
           WHEN btrim(lower(coalesce(e.user_agent, ''))) LIKE 'omp/%' THEN 'omp'
           WHEN btrim(lower(coalesce(e.user_agent, ''))) LIKE 'curl/%' THEN 'curl'
           ELSE 'Other'
         END;

COMMIT;
