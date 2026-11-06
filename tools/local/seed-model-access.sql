-- Local-only model-access fixtures for the PriceTag demo.
--
-- Runs after migrations and after seed-sso-personas.sql. The service syncs
-- partner users into policy subjects only at startup (and again at OIDC
-- login), so this file materializes the local personas first, then seeds:
--   * a $300 default role (Standard)
--   * a $200 Super users role (adds to the default: $500/person)
--   * a $0 Research role (models only)
--   * one temporary $75 credit for the returning user
--   * one default-role exclusion
--
-- Never use outside a laptop.

BEGIN;

-- ---------------------------------------------------------------------------
-- Materialize policy subjects from the seeded partner directory.
-- Mirrors storage.SyncPartnerUserSubjects.
-- ---------------------------------------------------------------------------
INSERT INTO policy_subjects
  (subject_id, tenant_id, principal_type, external_id, display_name, status, source)
SELECT gen_random_uuid(), t.tenant_id, 'partner_user', u.user_id::text,
       COALESCE(NULLIF(u.tags->>'preferred_username', ''),
                NULLIF(u.tags->>'email', ''), u.user_id::text),
       CASE WHEN u.active THEN 'active' ELSE 'inactive' END,
       'partner'
FROM partner_users u
CROSS JOIN policy_tenants t
WHERE t.slug = 'default'
ON CONFLICT (tenant_id, principal_type, external_id) DO UPDATE
  SET display_name = EXCLUDED.display_name,
      status = EXCLUDED.status,
      updated_at = NOW();

-- Give the seeded personas the same directory context the mock IdP returns so
-- the create-role wizard's cost-center/organization filters have data before
-- anyone logs in.
UPDATE partner_users u
SET tags = u.tags || jsonb_build_object(
      'organization', 'Technology',
      'cost_center', CASE WHEN u.tags->>'email' = 'manager-user@example.com'
                          THEN 'CC-AI-PLATFORM' ELSE 'CC-APPLIED-AI' END,
      'cost_center_description', CASE WHEN u.tags->>'email' = 'manager-user@example.com'
                                      THEN 'AI Platform Engineering' ELSE 'Applied AI Research' END,
      'employee_type', 'employee',
      'groups', '["GE"]'::jsonb
    ),
    updated_by = 'local-seed'
WHERE u.tags->>'email' IN (
  'new-user@example.com', 'returning-user@example.com', 'manager-user@example.com',
  'team-alice@example.com', 'team-bob@example.com'
);

-- ---------------------------------------------------------------------------
-- Roles. One default per tenant: clear it first so re-runs are idempotent.
-- ---------------------------------------------------------------------------
UPDATE model_access_roles r
SET is_default = FALSE, updated_at = NOW()
FROM policy_tenants t
WHERE r.tenant_id = t.tenant_id AND t.slug = 'default' AND r.is_default;

INSERT INTO model_access_roles
  (role_id, tenant_id, name, description, is_default, monthly_usd, created_by, updated_by)
SELECT gen_random_uuid(), t.tenant_id, v.name, v.description, v.is_default, v.monthly_usd,
       'local-seed', 'local-seed'
FROM policy_tenants t
CROSS JOIN (VALUES
  ('Standard',    'Baseline access for every active person', TRUE,  300.00),
  ('Super users', 'Power users: adds budget and premium models', FALSE, 200.00),
  ('Research',    'Experimental models, no extra budget', FALSE,   0.00)
) AS v(name, description, is_default, monthly_usd)
WHERE t.slug = 'default'
ON CONFLICT (tenant_id, name) DO UPDATE
  SET description = EXCLUDED.description,
      is_default = EXCLUDED.is_default,
      monthly_usd = EXCLUDED.monthly_usd,
      retired_at = NULL,
      updated_by = 'local-seed',
      updated_at = NOW();

-- Replace the seeded role/model membership so re-runs converge.
DELETE FROM model_access_role_models rm
USING model_access_roles r, policy_tenants t
WHERE rm.role_id = r.role_id
  AND r.tenant_id = t.tenant_id
  AND t.slug = 'default'
  AND r.name IN ('Standard', 'Super users', 'Research');

INSERT INTO model_access_role_models (tenant_id, role_id, model_id, added_by)
SELECT r.tenant_id, r.role_id, v.model_id, 'local-seed'
FROM model_access_roles r
JOIN policy_tenants t ON t.tenant_id = r.tenant_id AND t.slug = 'default'
CROSS JOIN (VALUES
  ('Standard',    'llama-4-scout'),
  ('Standard',    'qwen3-coder'),
  ('Standard',    'gpt-5-mini'),
  ('Super users', 'gpt-5'),
  ('Super users', 'claude-sonnet-4-5'),
  ('Research',    'claude-opus-4-1'),
  ('Research',    'deepseek-v3'),
  ('Research',    'gemini-2-5-pro')
) AS v(role_name, model_id)
WHERE r.name = v.role_name AND r.retired_at IS NULL
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- Explicit role assignments (one-time snapshots, not dynamic bindings).
-- ---------------------------------------------------------------------------
DELETE FROM model_access_role_assignments a
USING model_access_roles r, policy_tenants t
WHERE a.role_id = r.role_id
  AND r.tenant_id = t.tenant_id
  AND t.slug = 'default'
  AND r.name IN ('Super users', 'Research');

INSERT INTO model_access_role_assignments (tenant_id, role_id, subject_id, assigned_by)
SELECT r.tenant_id, r.role_id, s.subject_id, 'local-seed'
FROM model_access_roles r
JOIN policy_tenants t ON t.tenant_id = r.tenant_id AND t.slug = 'default'
JOIN policy_subjects s ON s.tenant_id = r.tenant_id AND s.principal_type = 'partner_user'
JOIN partner_users u ON s.external_id = u.user_id::text
JOIN (VALUES
  ('Super users', 'returning-user@example.com'),
  ('Super users', 'manager-user@example.com'),
  ('Research',    'team-alice@example.com')
) AS v(role_name, email) ON v.role_name = r.name AND v.email = u.tags->>'email'
WHERE r.retired_at IS NULL
ON CONFLICT (role_id, subject_id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Temporary per-person credit, expiring at the end of the current month.
-- ---------------------------------------------------------------------------
DELETE FROM quota_credits WHERE reason = 'Local demo credit';

INSERT INTO quota_credits
  (credit_id, tenant_id, subject_id, amount_usd, expires_at, reason, created_by)
SELECT gen_random_uuid(), t.tenant_id, s.subject_id, 75.00,
       date_trunc('month', NOW()) + interval '1 month',
       'Local demo credit', 'local-seed'
FROM policy_tenants t
JOIN policy_subjects s ON s.tenant_id = t.tenant_id AND s.principal_type = 'partner_user'
JOIN partner_users u ON s.external_id = u.user_id::text
WHERE t.slug = 'default' AND u.tags->>'email' = 'returning-user@example.com';

-- ---------------------------------------------------------------------------
-- Default-role exclusion: Bob shows the "excluded, falls back to global"
-- path in the person drawer.
-- ---------------------------------------------------------------------------
DELETE FROM model_access_default_exclusions WHERE reason = 'Local demo exclusion';

INSERT INTO model_access_default_exclusions
  (tenant_id, subject_id, reason, created_by)
SELECT t.tenant_id, s.subject_id, 'Local demo exclusion', 'local-seed'
FROM policy_tenants t
JOIN policy_subjects s ON s.tenant_id = t.tenant_id AND s.principal_type = 'partner_user'
JOIN partner_users u ON s.external_id = u.user_id::text
WHERE t.slug = 'default' AND u.tags->>'email' = 'team-bob@example.com'
ON CONFLICT (tenant_id, subject_id) DO UPDATE
  SET reason = EXCLUDED.reason, expires_at = NULL, created_by = EXCLUDED.created_by;

COMMIT;
