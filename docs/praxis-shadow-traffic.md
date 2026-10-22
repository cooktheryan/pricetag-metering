# Praxis llm-katan traffic watcher

Run from a laptop with no arguments:

```console
python3 tools/praxis-shadow-traffic.py
```

The run uses only normal PriceTag routes and has three lanes:

- 96 synthetic users distributed across `ai-gateway-openai-echo` and
  `ai-gateway-glm-echo`, both backed by llm-katan;
- one low-rate real GLM user through the normal PriceTag gateway;
- no direct shadow URL and no route-weight mutation.

Synthetic requests use random `max_tokens` from 1 through 32. The real GLM
lane is one request every 30 seconds by default. All requests use the same
single dashboard and JSONL evidence file.

## Safety

- The PriceTag context, server, and namespace are explicit defaults and can be
  overridden.
- EnMaaS markers are rejected before any `oc` command.
- `oc` is used read-only and only against the configured PriceTag namespace.
- Route discovery uses the explicit `--namespace`; a missing or non-Praxis route
  fails closed unless its URL is supplied with `--openai-url`,
  `--anthropic-url`, or `--gateway-url`.
- Baseline does not require shadow resources. Canary requires the shadow
  deployment and Service, but still sends to the same normal URLs.
- No retries; timeouts, resets, incomplete responses, and non-2xx responses are
  visible drops.
- Keys, prompts, and response bodies are never written to evidence.

## Dry-run

```console
python3 tools/praxis-shadow-traffic.py --dry-run
```

Dry-run performs read-only PriceTag discovery only. It sends no HTTP traffic
and makes no cluster mutations.

## Canary

```console
python3 tools/praxis-shadow-traffic.py --phase canary
```

Route weights are changed separately by the operator. The watcher never sends
directly to shadow; response markers identify whether the normal URL was served
by `praxis` or `shadow`.

Real-provider calls are intentionally limited to the single GLM lane. Adding
other provider lanes requires a separate PriceTag/Praxis configuration change;
the watcher does not invent or apply those lanes.
