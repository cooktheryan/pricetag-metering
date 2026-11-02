# EnMaaS eligibility: Atlas parity

This note maps the Atlas EnMaaS eligibility logic to the PriceTag onboarding
gates. The Atlas sources reviewed are in
`openshift-eng/infra-toolbox` at commit `44bcf9b16b3a6aad2b230280b0a16ec18350e75a`:

- `apps/atlas/atlas/support/functions/enmaas.py`
- `apps/atlas/atlas/support/views/EnmaasEligibility.py`
- `apps/atlas/atlas/support/templates/support/EnmaasEligibility.html`
- `apps/atlas/atlas/support/views/feature_checks.py`
- `libs/dpp-ldap-redhat/dpp/ldap_redhat/UserRecord.py`

## Atlas logic

Atlas has three independent eligibility gates:

1. **Works Council country gate.** Read the user's LDAP `c` attribute (the
   2-letter country code; `co` is the 3-letter code) and compare it with a
   hard-coded map. At the reviewed commit the map contains only
   `NL` (The Netherlands), with Jira tracking issue `PCO-2112`. Users in a
   listed country are blocked unless their profile carries
   `additional_data.ai.has_works_council_override = true`.
2. **Policy acknowledgement gate.** Read
   `additional_data.ai.has_read_legal_guidelines`. When false, the user is
   shown the eligibility page with a checkbox labelled
   "I have reviewed the Red Hat policy for using AI and code assistant tools."
   Submitting sets the flag to true. The page links to the authoritative
   policy at
   `https://source.redhat.com/departments/legal/products_privacy_and_innovation/legal_wiki/policy_on_the_use_of_ai_technology`.
   Atlas does not copy the policy text into its own repository.
3. **Guest list / Rover Group gate.** Read the LDAP `memberOf` attribute and
   check membership of the Rover Group configured in the
   `ENMAAS_GUEST_LIST_CHECK` feature flag (`rover_group`). The group name is
   runtime configuration, not hard-coded in the repository. When the feature
   flag is inactive or has no group, the check is disabled and everyone
   passes. Atlas's current onboarding text refers to the group as the EnMaaS
   guest-list Rover Group; the group discussed for PriceTag is
   `enmaas-users`.

The Atlas user is fully eligible only when all three checks pass.

## PriceTag mapping

| Atlas gate | PriceTag gate | Source of truth |
| --- | --- | --- |
| Works Council country | `country` check | `partner_users.tags.country`, normalized from LDAP/OIDC `c` (2-letter accepted, stored as ISO-3166 alpha-3 for comparison) |
| Policy acknowledgement | `terms` check | `user_agreements` row for the configured policy version |
| Guest list Rover Group | `group` check | `partner_users.tags.rover_groups` (LDAP `memberOf`), with the OIDC `groups` claim as the rollout fallback |

The group and country policy is editable by a super admin under
**Admin → Access** and is stored in `access_policy`; it overrides
`ACCESS_ALLOWED_GROUPS`, `ACCESS_BLOCKED_COUNTRIES`, and
`ACCESS_UNKNOWN_COUNTRY_ALLOW` without a redeploy.

## Differences to keep in mind

- **Group source.** Atlas reads LDAP `memberOf`. PriceTag now prefers the
  `rover_groups` partner tag, which the directory sync must populate from
  LDAP `memberOf`. Until that sync ships, the gate falls back to the OIDC
  `groups` claim. Do not assume the OIDC claim is the LDAP distinguished
  name.
- **Country override.** Atlas uses `ai.has_works_council_override`. PriceTag
  accepts the flat partner tag `works_council_override: "true"` (alias
  `has_works_council_override`). The Atlas directory sync can PATCH it through
  the partner user API.
- **Unknown country.** Atlas passes when the country is absent. PriceTag
  denies by default. To match Atlas exactly, enable "allow unknown country"
  in **Admin → Access** (or set `ACCESS_UNKNOWN_COUNTRY_ALLOW=true` when no
  database policy is saved). Keeping it off is a deliberate hardening
  difference, not missing functionality.
- **Policy record.** Atlas stores one boolean. PriceTag records acceptance per
  policy version, which makes a future policy update require a fresh
  acknowledgement.
- **Identity.** PriceTag additionally requires an active, pre-provisioned
  partner user whose UUID matches the OIDC `rhatUUID`; OIDC never provisions
  or elevates a user.

## Current configuration guidance

- Restricted country for Atlas parity: `ACCESS_BLOCKED_COUNTRIES=NLD` (or set
  `NLD` in Admin → Access). The repository's local demo uses `IRN` only to
  exercise the blocked-country persona with `ONBOARDING_MODE=enforce`.
- Allowed group for Atlas parity: set `ACCESS_ALLOWED_GROUPS=enmaas-users` (or
  the same value in Admin → Access) and have the directory sync populate
  `rover_groups` from LDAP `memberOf`.
- Policy version: `ONBOARDING_TERMS_VERSION=redhat-ai-policy-v1`. Bump this
  when the linked Red Hat policy changes in a way that requires a new
  acknowledgement.
- Policy URL shown by `/legal/terms` is the Red Hat Legal source link above.

## Closure checklist

Code parity is in place. Closing the operational gaps requires these steps:

1. **Directory sync:** have the Atlas/LDAP sync PATCH `rover_groups` with the
   complete LDAP `memberOf` list and PATCH `works_council_override` when an
   exception exists. Until `rover_groups` is populated, PriceTag falls back
   to the OIDC `groups` claim. Once the tag exists it is authoritative, so a
   user who leaves every Rover Group is denied even if the OIDC claim still
   has an unrelated group.
2. **Access policy:** set `allowed_groups` to the exact Rover group
   (`enmaas-users`), set `blocked_countries` to `NLD`, and decide whether
   unknown countries are allowed. Prefer **Admin → Access**; a saved policy
   overrides the environment.
3. **Identity provider:** confirm the Stage realm's `groups` claim values.
   They are not necessarily the same names as LDAP `memberOf`.
4. **Acceptance data:** verify the deployed `ONBOARDING_TERMS_VERSION` is
   `redhat-ai-policy-v1`; users who accepted `draft-tbd` will be asked again.
5. **Verification:** test one eligible user, one NL user without override, one
   NL user with override, one user outside `enmaas-users`, and one user who
   has not acknowledged the policy.
6. **Merge hygiene:** remove the temporary dev-login scaffolding before this
   branch is marked ready; it can force onboarding for test identities.
