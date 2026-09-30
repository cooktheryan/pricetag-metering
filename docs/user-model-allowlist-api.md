# Per-user Model Allowlist API

This API lets the authorized budget integration replace or clear one MaaS user's exact model allowlist. It is a **restriction layered on top of** existing MaaS/Praxis model access and monthly quotas; it does not grant access to a model that the existing platform policy denies.

## Authentication

All endpoints require:

```http
Authorization: Bearer <M2M_SHARED_SECRET>
```

The partner API fails closed: it returns `503` if no shared secret is configured and `401` for missing/invalid credentials. Never expose the secret in browser code.

## Replace a user's allowlist

```http
PUT /api/v1/model-policies/users/{url-encoded-maas-username}/allowlist
Content-Type: application/json
```

```json
{
  "models": ["claude-sonnet-4-5", "gpt-5.6-luna"]
}
```

`PUT` replaces the complete list. It is intended for the monthly refresh job: call it with the user's approved models. Model identifiers are exact and case-sensitive; wildcards and whitespace are rejected. Up to 50 model identifiers are accepted, each no longer than 100 bytes.

An empty list explicitly blocks all models for that user. To remove the additional restriction and return to baseline MaaS/Praxis access, use `DELETE`.

```http
DELETE /api/v1/model-policies/users/{url-encoded-maas-username}/allowlist
```

## Read the policy

```http
GET /api/v1/model-policies/users/{url-encoded-maas-username}/allowlist
```

Example response when configured:

```json
{
  "username": "alice",
  "enabled": true,
  "models": ["claude-sonnet-4-5", "gpt-5.6-luna"],
  "updatedBy": "partner-m2m",
  "updatedAt": "2026-09-30T12:00:00Z"
}
```

If no user policy exists, `enabled` is `false` and `models` is empty; baseline platform access applies. Usernames are MaaS usernames. If multiple non-service logins are linked to the same PriceTag person, the policy is applied to all of them.

## Enforcement semantics

The synchronous entitlement check also applies the model allowlist to the model passed in its `model` query parameter. For a user with a configured policy, missing or non-matching model IDs fail closed. The final `hasAccess` is false if the model is outside the user's allowlist, even when token/dollar quota would otherwise permit it. Normal MaaS/Praxis model restrictions and quota rules continue to apply.

Policy changes invalidate the local quota-decision cache. Other metering replicas may retain a prior decision for up to the 15-second cache TTL; integrations should allow for that propagation window after updates.

The user usage-report endpoint is separate and read-only; polling it does not record denials. Actual blocked inference checks are recorded as denial events.

## Important deployment dependency

Enforcement requires the gateway's preflight entitlement call to send the public client model ID. If the request model is absent, a user with an allowlist is denied. Confirm the deployed Praxis `external_metering` filter supplies that model before enabling policies for users.
