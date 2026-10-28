-- One synthetic live request for the local dashboard map. The shell wrapper
-- runs this every few seconds; it only touches the disposable local volume.
WITH u AS (
  SELECT p.tags->>'email' AS email
  FROM partner_users p
  WHERE p.tags->>'demo_dashboard' = 'true'
  ORDER BY random() LIMIT 1
), m AS (
  SELECT model, provider, input_cost_per_mtok, output_cost_per_mtok, cache_read_cost_per_mtok
  FROM model_pricing
  WHERE model IN ('qwen3-coder','llama-4-scout','qwen3-235b','granite-3.3-8b',
                  'claude-opus-4-8','claude-sonnet-4-6','gpt-5.5','gpt-5.4',
                  'gemini-2.5-pro','llama-4-maverick','mistral-large-3','command-r-plus')
  ORDER BY random() LIMIT 1
), tok AS (
  SELECT p AS prompt, c AS completion,
         CASE WHEN random() < 0.3 THEN p / 2 ELSE 0 END AS cached
  FROM (SELECT 5000 + floor(random() * 60000)::int AS p,
               500 + floor(random() * 12000)::int AS c) x
), agents AS (
  SELECT ARRAY[
    'claude-code/2.1.0','codex-tui/0.1.0','opencode-nightly/1.0','pi-coding-agent/0.1',
    'charm-crush/v0.1.0','OpenAI/Python 2.43.0','gemini-cli/0.7.0','aider/0.86.1',
    'omp/18.10.2','curl/8.7.1','python-requests/2.32'
  ] AS a
)
INSERT INTO usage_events
  (event_id, timestamp, username, group_name, model, provider, source, user_agent,
   prompt_tokens, completion_tokens, total_tokens, cached_input_tokens, status_code, cost_usd)
SELECT 'live-' || extract(epoch from clock_timestamp())::bigint || '-' || floor(random() * 100000)::int,
       NOW(), u.email, 'GE', m.model, m.provider, 'local-dashboard-live',
       agents.a[1 + floor(random() * array_length(agents.a, 1))::int],
       tok.prompt, tok.completion, tok.prompt + tok.completion, tok.cached, 200,
       ROUND(((tok.prompt - tok.cached) * m.input_cost_per_mtok
              + tok.cached * m.cache_read_cost_per_mtok
              + tok.completion * m.output_cost_per_mtok) / 1000000.0, 6)
FROM u, m, tok, agents;
