# Praxis upgrade traffic watcher

`tools/praxis-shadow-traffic.py` is a laptop-side, **PriceTag-only** traffic
watcher for the Praxis upgrade sequence. It uses the normal PriceTag
Benchmark route backed by `llm-katan` for the large synthetic load.

It does not access EnMaaS, create shadow resources, change route weights, or
call real OpenAI/Anthropic/Vertex/GLM providers by default. Real-provider
checks are a separate, opt-in small canary matrix.

## Safety model

- The PriceTag server, namespace, and context are explicit hardcoded defaults;
  all can be overridden.
- EnMaaS markers are rejected before any `oc` command.
- `oc` is always invoked with the explicit PriceTag context/server and only
  reads the configured PriceTag namespace.
- Baseline does not require `praxis-shadow` or any shadow route.
- Canary requires `deployment/praxis-shadow`, `service/praxis-shadow`, and the
  shadow Benchmark route.
- Both phases send to the **normal** Benchmark route. The tool never sends
  directly to the shadow route.
- No retries. Timeouts, resets, incomplete responses, and non-2xx responses
  are visible drops.
- No keys, prompts, or response bodies are written to JSONL evidence.

## Normal use

The default is a five-minute baseline run with 100 synthetic users:

```console
python3 tools/praxis-shadow-traffic.py
```

The tool reads the PriceTag key from `~/.mykey`. It exits with a clear error if
the file is missing or empty.

The dashboard shows sent/responses/drops/availability, p50/p95/p99 latency,
the synthetic user, lane/provider/model, and the served backend (`praxis`,
`shadow`, or `unknown`). Press `q` to stop early. Evidence defaults to `/tmp`.

The default large load is intentionally Benchmark/llm-katan only. Add
`--real-matrix` in canary mode to send one small probe through each normal
gateway path: Messages, Chat Completions, Responses, and Conversations. The
matrix also uses the normal gateway host and never targets a shadow URL.

## Dry run

Dry run performs only read-only PriceTag `oc` checks and resource discovery:

```console
python3 tools/praxis-shadow-traffic.py --dry-run
```

It sends no HTTP requests and makes no cluster mutations.

## Phases

### Baseline

```console
python3 tools/praxis-shadow-traffic.py --phase baseline
```

Requires only the normal Benchmark route. A missing `praxis-shadow` service or
route is not an error.

### Canary

```console
python3 tools/praxis-shadow-traffic.py --phase canary
```

Requires the shadow deployment, service, and Benchmark route. Route weights
must be changed separately by the operator; this tool never changes them.
Requests continue to target the normal route. Backend classification uses
`x-praxis-lane` by default and also understands the existing
`x-gateway-build` marker (`new` means `shadow`).

## Overrides

Useful overrides for the single-environment defaults are:

```console
python3 tools/praxis-shadow-traffic.py \
  --phase baseline \
  --oc-server https://price-tag-api.example:6443 \
  --namespace ai-gateway-dogfood \
  --gateway-url https://normal-benchmark-route.example
```

The gateway override is still required to be HTTPS and is rejected if it
contains an EnMaaS marker.

After the shadow deployment and route weights are ready, the opt-in canary
matrix is:

```console
python3 tools/praxis-shadow-traffic.py --phase canary --real-matrix
```
