# Partner user API

The partner user API keeps PriceTag's UUID-keyed user directory synchronized
with an external identity source such as Atlas/LDAP. Every endpoint requires
the `USER_MANAGEMENT_API_SECRET` bearer credential; callers may set a valid
`X-Partner-Client` value (for example `atlas`) to identify themselves in the
audit trail.

## User resource

| Method | Path | Semantics |
|---|---|---|
| `POST` | `/api/v1/users` | Create a user from a complete tag set |
| `GET` | `/api/v1/users/{user_id}` | Read one user |
| `PUT` | `/api/v1/users/{user_id}` | Replace all tags; upsert if missing |
| `PATCH` | `/api/v1/users/{user_id}` | Merge supplied tags into an existing user |
| `DELETE` | `/api/v1/users/{user_id}` | Deactivate the user and revoke partner-managed keys |
| `POST` | `/api/v1/users/{user_id}/reactivate` | Reactivate after key revocation completes |

`user_id` is the stable external UUID. It is not an email address or MaaS key
ID.

`DELETE` is a two-phase operation: the user is marked inactive first, then
partner-managed keys are revoked in MaaS. The entitlement layer resolves both
inactive and revocation-pending users (including historical logins) and denies
every model, so access stops immediately even when the MaaS revocation fails
and has to be retried.

## Partial profile synchronization

Use `PATCH` when an upstream login or directory sync detects changed LDAP
attributes:

```http
PATCH /api/v1/users/cf760670-4481-11ea-9298-0a58ac142d76
Authorization: Bearer <user-management-token>
X-Partner-Client: atlas
Content-Type: application/json

{
  "tags": {
    "first_name": "Updated",
    "email": "updated@example.com"
  }
}
```

Only supplied keys are replaced. Omitted tags, including attributes another
integration owns, are preserved. `manager_uuid: null` explicitly clears the
manager. An empty patch is rejected with `400`; a missing user returns `404`.
PATCH never creates a user.

The merged record must still satisfy the complete user invariant:
`email`, `first_name`, and `last_name` remain required; emails are globally
unique; values must be strings (except nullable `manager_uuid` and group-list
tags such as `groups` / `*_groups`, which may be string arrays); and tag names
must match the documented lowercase tag format. An email change updates the
current MaaS username while retaining historical logins for usage attribution.

The merge and validation run under a row lock. Concurrent profile refreshes
therefore cannot overwrite one another using stale reads. Successful patches
write a `partner_user.patch` audit record containing the changed tag keys and
whether the email changed.

## LDAP directory sync

The scheduled LDAP sync is a direct, scoped `partner_users` correction job, not
an API caller. It matches on `user_id` (`rhatUUID`) and merges only fields that
have a non-empty LDAP value. Its default `directory` field set keeps
`first_name`, `last_name`, `country`, `cost_center`,
`cost_center_description`, `organization`, `job_title`, `job_code`, `geo`,
`office_location`, `worker_id`, `supervisor_worker_id`, `employee_subtype`,
`person_type`, `hire_date`, `term_date`, and `deactivated` current. `email` and
`kerberos_id` are opt-in: a direct `tags.email` write does not update
`partner_user_logins`, so email changes should go through the partner API (or a
future SQL path that reconciles logins in the same transaction). An LDAP
`manager` DN is resolved to the manager's `rhatUUID` and written to
`tags.manager_uuid`; the self-referencing `manager_user_id` column is updated
when that manager exists and is active. If the manager is missing or inactive,
the existing link is preserved. If the manager is active but not a partner user
yet (for example, they have never signed in), the sync can create a minimal
placeholder `partner_users` row from the same LDAP result set, but only when
the manager belongs to a partner user matched in this run and the `email` field
is explicitly selected; the row must satisfy the same email + first_name +
last_name contract as this API. The placeholder has no login mapping; its first
SSO login creates one from the merged email, which is why login can claim an
existing row without provisioning a new user. Unresolved manager DNs leave the
existing manager untouched. The job never changes `updated_at`, only creates
these scoped manager placeholders, and writes a rollback artifact before every
apply. See [deploy/ldap-sync/README.md](../deploy/ldap-sync/README.md).
