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
unique; values must be strings (except nullable `manager_uuid`); and tag names
must match the documented lowercase tag format. An email change updates the
current MaaS username while retaining historical logins for usage attribution.

The merge and validation run under a row lock. Concurrent profile refreshes
therefore cannot overwrite one another using stale reads. Successful patches
write a `partner_user.patch` audit record containing the changed tag keys and
whether the email changed.
