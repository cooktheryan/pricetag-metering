# User Usage Report API

`GET /api/v1/usage/users/{username}` returns a read-only current-calendar-month usage report for one MaaS username. Unlike the gateway entitlement check, polling this endpoint does not record quota denials.

## Authentication

Send the dedicated `USAGE_REPORT_API_SECRET` as a bearer token:

```http
Authorization: Bearer <USAGE_REPORT_API_SECRET>
```

This partner endpoint fails closed: if the secret is missing from service configuration it returns `503`; missing or incorrect bearer credentials return `401`. Do not place the secret in browser code. The bearer secret is partner-wide: anyone holding it can request a report for any username in the service's tenant, so the Atlas backend must derive the username from its verified identity rather than accept an arbitrary browser-supplied username.

## Deployment status and boundary

The current PriceTag EnMaaS deployment does not configure `USAGE_REPORT_API_SECRET` or expose `/api/v1/usage/users` through a public Route. Until Atlas's service identity, network path, and secret-distribution process are approved, keep this endpoint unavailable; an unset secret returns `503`.

When enabling Atlas access, either keep the call on an approved private service path or add a dedicated HTTPS Route scoped only to `/api/v1/usage/users`. Do not add the endpoint to a catch-all dashboard Route. Deliver the same secret to the Atlas backend through an approved secret store; never expose it to browser code.

## Request

```http
GET /api/v1/usage/users/{url-encoded-maas-username}
```

The report covers the current calendar month. If PriceTag has linked multiple MaaS logins to the same directory person, their events are included together. Otherwise, only the requested username's events are included.

## Response

```json
{
  "username": "alice",
  "month": "2026-09",
  "asOf": "2026-09-30T12:00:00Z",
  "totals": {
    "requests": 42,
    "promptTokens": 12000,
    "completionTokens": 3400,
    "totalTokens": 15400,
    "cachedInputTokens": 2300,
    "cacheCreationTokens": 800,
    "reasoningTokens": 500,
    "estimatedCostUsd": 0.4821
  },
  "models": [
    {
      "provider": "anthropic",
      "model": "claude-sonnet-4-5",
      "requests": 42,
      "promptTokens": 12000,
      "completionTokens": 3400,
      "totalTokens": 15400,
      "cachedInputTokens": 2300,
      "cacheCreationTokens": 800,
      "reasoningTokens": 500,
      "estimatedCostUsd": 0.4821
    }
  ]
}
```

`promptTokens` follows the event contract and includes cached/cache-creation input tokens; those categories are also reported separately. `estimatedCostUsd` is computed using the metering service's current model pricing and fallback rates, so treat it as an estimate rather than a provider invoice. The model rows are the breakdown; totals are their sum.

## Errors

| Status | Meaning |
|---|---|
| `400` | Malformed or missing username path segment |
| `401` | Missing or invalid M2M bearer token |
| `503` | M2M secret not configured for this deployment |
| `500` | Database/report query failed |

Do not cache this response in shared intermediaries. It is user billing data; keep it behind an authenticated route and redact identity/authorization data from logs.
