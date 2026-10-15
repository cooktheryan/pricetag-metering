# Praxis shadow traffic watcher

`tools/praxis-shadow-traffic.py` is a laptop-side, PriceTag-only watcher for
the Praxis shadow routes. It uses the existing `llm-katan` echo backend only;
it does not test real OpenAI, Anthropic, Vertex, or GLM providers.

## Safety model

- `--oc-context`, `--oc-server`, and `--namespace` are mandatory.
- EnMaaS markers are rejected in the context, server, namespace, and route URLs.
- The default context, server, namespace, and key path are the single PriceTag
  dogfood environment. Each can be overridden for maintenance or recovery.
- The tool requires `~/.mykey` by default and explains how to fix a missing or
  empty key file.
- The tool performs only read-only `oc` checks in the PriceTag namespace before
  sending requests.
- The tool never mutates OpenShift resources and never falls back to an
  implicit/current `oc` context; discovery always uses the explicit PriceTag
  context, server, and namespace.
- Every request is attempted once. There are no retries.
- Evidence contains request outcomes, status codes, timings, lane/provider/model,
  and synthetic logical-user labels. It does not contain keys, prompts, or
  response bodies.

## Echo lanes

The current local Praxis AI manifests configure `llm-katan` with:

- backend: `echo`
- model: `benchmark-echo`
- providers: `openai,anthropic`

The shadow config exposes three echo lanes, all backed by that deployment:

- OpenAI Chat Completions → `benchmark-echo`
- Anthropic Messages Benchmark → `benchmark-echo`
- Anthropic Messages GLM echo → `rits/zai-org/glm-5-3`

The first and third lanes use automatic read-only `oc port-forward` processes
to `praxis-shadow` ports 8087 and 8086. The Benchmark lane uses the discovered
`ai-gateway-benchmark-shadow` route. Optional endpoint flags override these
defaults.

Pass the two **PriceTag echo endpoints** explicitly. The OpenAI echo lane may
use the explicitly approved local port-forward; the Anthropic-format echo lane
uses the PriceTag benchmark shadow route. Do not substitute a provider
endpoint or an EnMaaS URL.

## Dry-run first

The normal command is intentionally short:

```console
python3 tools/praxis-shadow-traffic.py
```

It checks the PriceTag namespace, discovers the deployed `llm-katan` providers
and model, discovers the Benchmark shadow route, starts the two local
port-forwards, and runs a five-minute 100-user test. Press `q` to stop the live
dashboard early.

To validate configuration without sending HTTP traffic, use:

```console
python3 tools/praxis-shadow-traffic.py --dry-run
```

Dry-run still performs the read-only PriceTag `oc` discovery, but starts no
port-forward and sends no HTTP traffic.

## Traffic mode (requires separate approval)

Traffic mode requires `PRICETAG_API_KEY`, unless `--users-file` supplies a
`users` array with per-user `key` values. Keys are read in memory and never
printed or written to evidence.

The terminal view shows total requests, responses, drops, status codes,
p50/p95/p99 latency, lane/provider/model, and the last result for every
logical user. Non-interactive runs print the same safe summary periodically.

Optional overrides include `--key-file`, `--oc-context`, `--oc-server`,
`--namespace`, `--benchmark-url`, `--openai-echo-url`, and
`--glm-echo-url`. The default key is read from `~/.mykey`; it is never printed
or written to evidence.

This document intentionally does not provide a command that discovers routes,
changes route weights, applies manifests, or touches any EnMaaS resource.
