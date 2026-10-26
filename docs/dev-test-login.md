# Dev test login (temporary — remove before merge/production)

`/login` can show a **Dev test sign-in** panel beneath the normal Red Hat SSO
button. It opens a local session for seeded test identities so reviewers and
designers can exercise onboarding, manager, usage, and access-failure flows in
a deployed development environment without real IdP accounts.

This is **not** part of the product surface. It must be removed before this
branch is merged or deployed to production — **removal is a merge blocker**,
not a follow-up.

## How it is gated

Three independent conditions must all hold:

1. `DEV_LOGIN_USERS` is set to a comma/space-separated allowlist. Empty (the
   default) removes the panel and makes `/dev-login` return 404.
2. The requested username appears in that allowlist.
3. The matching active `partner_users` row carries `"dev_test": true`.

Any other request is rejected with 403. The allowlist is checked before the
database, so a mistyped or missing row cannot open a session.

Dev logins are routed through the normal `loginDestination` logic, and the
`AccessGate` applies onboarding mode `enforce` only to allowlisted `dev_test`
identities. That demonstrates the country, group, and terms gates without
switching the whole deployment to enforcing mode (which would affect real
users). IdP group claims are supplied by an optional `"dev_groups": ["GE"]`
tag.

The country persona needs a blocklist in the deployment. Dogfood uses
`ACCESS_BLOCKED_COUNTRIES=IRN`; with `ONBOARDING_MODE=off` this does not block
real users, it only feeds the enforced check for the dev identities.

## Personas

| Persona | Tag behavior | Landing |
| --- | --- | --- |
| Nina New | `dev_reset_on_login: true`; terms and API keys reset on every login | `/onboarding` |
| Ravi Return | terms accepted, has usage | `/account` |
| Bea Blocked | `country: IR` | `/onboarding` (country gate) |
| Noah Nogroup | no `dev_groups` | `/onboarding` (group gate) |
| Maya Manager | has two seeded direct reports with team traffic | `/manager` |

Nina's reset revokes every API key currently owned by that identity and hides
revoked/expired keys from her key list, so each click starts exactly like a new
account. MaaS retains revoked keys in its own record; the hiding is only for
this dev persona. Maya is listed last because the manager flow is already the
best-established path and is not what most testers need first.

The same panel is used locally (`tools/local/start-local.sh` sets
`DEV_LOGIN_USERS`) and in the dogfood deployment.

## Enable / disable

```bash
# Enable on a development Deployment
oc -n ai-gateway-dogfood set env deployment/metering-service \
  DEV_LOGIN_USERS='maya.manager@example.invalid,nina.new@example.invalid,ravi.return@example.invalid,bea.blocked@example.invalid,noah.nogroup@example.invalid,alice.team@example.invalid,bob.team@example.invalid'

# Disable (panel and endpoint disappear)
oc -n ai-gateway-dogfood set env deployment/metering-service DEV_LOGIN_USERS-
```

## Removal checklist before merge or production

Code:

- [ ] Delete the `/dev-login` route in `cmd/main.go`.
- [ ] Delete `HandleDevLogin`, `devLoginPanel`, `devLoginGroups`,
      `isDevTestUser`, `isDevResetUser`, `revokeDevKeys`, `devResetIdentity`,
      and the `SetMaaSClient` wiring in `internal/handler/auth.go` and
      `cmd/main.go`.
- [ ] Remove the dev-reset key filter in `internal/handler/me_keys.go`.
- [ ] Remove `devEnforcedIdentity` and the forced-mode branch in
      `AccessGate.Evaluate`, and restore the `NeedsOnboarding` short-circuit,
      in `internal/handler/access.go`.
- [ ] Remove the `<!-- DEV_LOGIN -->` injection block from `HandleLogin` and
      the placeholder from `internal/dashboard/login.html`.
- [ ] Remove `DevLoginUsers` and its `DEV_LOGIN_USERS` parsing from
      `internal/config/config.go`.
- [ ] Delete `internal/handler/dev_login_test.go`.
- [ ] Remove `DEV_LOGIN_USERS` from `tools/local/start-local.sh`.
- [ ] Remove all `dev_test`, `dev_groups`, `dev_label`, and
      `dev_reset_on_login` tags from `tools/local/seed-onboarding.sql` and the
      dogfood seed SQL.
- [ ] Decide whether the local mock-IdP persona picker (`OIDC_TEST_LOGIN`)
      remains. It is separate from this feature and still tests the real
      callback path.

Environment / data:

- [ ] Unset `DEV_LOGIN_USERS` on every deployment.
- [ ] Delete the dogfood test identities, their logins, agreements, usage,
      rollups, and month-spend rows (scoped by the seeded usernames/UUIDs).
- [ ] Confirm `/dev-login` returns 404 and `/login` has no dev panel.
- [ ] Confirm the Red Hat SSO button and its redirect are unchanged.

Reviewers should treat any remaining `/dev-login` reference as a merge blocker.
