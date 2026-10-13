# PriceTag dashboard OIDC rollout

OIDC login is disabled by default. Do not enable it in the production
deployment until the identity provider and the partner directory have been
validated in a non-production environment.

## Required settings

Inject these as deployment configuration; never commit the client secret:

```text
OIDC_ENABLED=true
OIDC_ISSUER_URL=<exact issuer URL from IAM>
OIDC_CLIENT_ID=enmaas-pricetag-dashboard
OIDC_CLIENT_SECRET=<Secret-backed value>
OIDC_REDIRECT_URL=https://dashboard.enmaas.devshift.net/oauth/callback
OIDC_SCOPES=openid profile email groups
```

The callback URL must exactly match the URL registered with IAM. The issuer
must be the exact `iss` value from the provider discovery document; do not
substitute the dashboard URL or a provider host guessed from the client ID.

## Login behavior

`GET /login` continues to provide API-key login. When OIDC is enabled it also
shows a Red Hat SSO button. The button starts Authorization Code + PKCE at
`/oauth/login`, and the provider returns to `/oauth/callback`.

The callback validates state, nonce, PKCE, issuer, audience, signature, and
token expiry. It requires `sub`, `rhatUUID`, and an email or
`preferred_username`. OIDC groups are copied into the signed session for
display/context only; they do not grant PriceTag roles.

The user must already exist as an active partner user. The partner user's
stable UUID must equal the OIDC `rhatUUID`; login does not auto-provision or
elevate accounts. LDAP synchronization remains responsible for creating and
updating the partner directory, including manager links.

## Safe rollout sequence

1. Obtain the exact IAM discovery/issuer URL and confirm the claims.
2. Deploy the code with `OIDC_ENABLED=false`.
3. Build and test against a non-production PriceTag environment.
4. Create the `/oauth/login` and `/oauth/callback` routes.
5. Add the client secret through the deployment secret manager.
6. Enable OIDC only in the approved environment.
7. Verify ordinary user, manager, inactive/unprovisioned user, and admin cases.
8. Keep API-key login during the migration and define rollback as
   `OIDC_ENABLED=false`.

No production cluster mutation is part of this change.

## Local real-SSO testing

The provider must have the exact local callback registered. The production
callback cannot be reused for a laptop callback unless IAM explicitly adds it.
Use a separate development/stage client and secret whenever possible.

An HTTPS tunnel is the safest way to test the real provider while keeping the
application local:

1. Start PriceTag locally on port `8080` with a local database containing the
   test partner user.
2. Start an approved HTTPS tunnel, for example a temporary Cloudflare Tunnel
   or ngrok endpoint, forwarding to `http://127.0.0.1:8080`.
3. Ask IAM to register the tunnel callback exactly, for example:
   `https://<temporary-host>/oauth/callback`.
4. Configure local-only values:

   ```text
   OIDC_ENABLED=true
   OIDC_ISSUER_URL=<exact IAM issuer>
   OIDC_CLIENT_ID=<development client>
   OIDC_CLIENT_SECRET=<local secret file value>
   OIDC_REDIRECT_URL=https://<temporary-host>/oauth/callback
   ```

5. Open `https://<temporary-host>/login` in a browser. The provider returns
   through the tunnel to the local callback.

For a local-only HTTP mock-provider test, `SESSION_COOKIE_SECURE=false` may be
used. Never use that setting on a shared, staged, or production deployment.

The HTTPS tunnel is important because the session and OIDC state cookies are
`Secure`. Do not map the production dashboard hostname to `127.0.0.1` in
`/etc/hosts`, and do not use the production client secret for an unapproved
local callback. The local database must also contain the test user's active
partner record with a matching `rhatUUID`; production data or databases must
not be used for this test.

## Claims and directory storage

The approved IAM registration currently requests these OIDC claims:

```text
sub
rhatUUID
preferred_username / username
email
given_name
family_name
groups
```

PriceTag currently consumes `sub`, `rhatUUID`, email/username, and groups at
the login boundary. `rhatUUID` must match the active partner user's stable UUID;
groups are carried in the signed session but do not grant PriceTag roles.
Given/family names are available in the token but are not copied into the
browser cookie.

Country, state, city, office location, cost center, and manager data are **not
promised by the SSO registration**. They should continue to come from the
approved LDAP sync. The existing partner record supports string tags such as
`country`, `state`, `region`, and `rhat_cost_center`; group membership should
become a normalized `groups`/`group_memberships` model rather than a
comma-separated tag. `manager_user_id` is already a relational field.
