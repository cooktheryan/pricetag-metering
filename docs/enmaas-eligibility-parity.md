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
| Guest list Rover Group | `group` check | OIDC `groups` claim in the signed session, compared with the saved/ENV group allowlist |

The group and country policy is editable by a super admin under
**Admin → Access** and is stored in `access_policy`; it overrides
`ACCESS_ALLOWED_GROUPS`, `ACCESS_BLOCKED_COUNTRIES`, and
`ACCESS_UNKNOWN_COUNTRY_ALLOW` without a redeploy.

## Differences to keep in mind

- **Group source.** Atlas reads LDAP `memberOf`. PriceTag reads the OIDC
  `groups` claim. The IdP must map the Rover Group into that claim, or the
  PriceTag allowlist must use the value the IdP actually returns. Do not
  assume the claim is the LDAP distinguished name.
- **Country override.** Atlas supports a per-user Works Council override.
  PriceTag's super-admin policy removes a country from the blocklist for
  everyone instead. A per-user override can be added if Atlas parity is
  required.
- **Unknown country.** Atlas passes when the country is absent. PriceTag
  denies by default; set `ACCESS_UNKNOWN_COUNTRY_ALLOW=true` to match Atlas,
  or keep the stricter default deliberately.
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
- Allowed group for Atlas parity: set the group exactly as it appears in the
  OIDC `groups` claim, expected to be `enmaas-users`.
- Policy version: `ONBOARDING_TERMS_VERSION=redhat-ai-policy-v1`. Bump this
  when the linked Red Hat policy changes in a way that requires a new
  acknowledgement.
- Policy URL shown by `/legal/terms` is the Red Hat Legal source link above.
