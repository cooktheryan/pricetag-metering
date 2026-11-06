package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// DefaultTenantID is the stable ID of the single tenant used by v1. The
// schema is tenant-scoped from day one; a multi-tenant deployment would
// create additional rows, but the v1 UI only exposes this one.
const (
	DefaultTenantID   = "00000000-0000-0000-0000-000000000001"
	DefaultTenantSlug = "default"

	PrincipalPartnerUser    = "partner_user"
	PrincipalGroup          = "group"
	PrincipalService        = "service_identity"
	PrincipalTenant         = "tenant"
	PrincipalUnlinkedLegacy = "unlinked_legacy"
)

var (
	ErrModelAccessTenantNotFound  = errors.New("policy tenant not found")
	ErrModelAccessTenantSuspended = errors.New("policy tenant is suspended")
	ErrModelAccessSubjectNotFound = errors.New("policy subject not found")
	ErrModelAccessSubjectInactive = errors.New("policy subject is inactive")
)

// EffectiveModelAccess is the resolved model-access view for one subject in
// one tenant. It separates the sources so the admin UI can explain "why?"
// without reimplementing policy. EffectiveModels is the hot-path answer.
type ModelAccessRoleRef struct {
	RoleID string `json:"role_id"`
	Name   string `json:"name"`
}

type EffectiveModelAccess struct {
	TenantID           string               `json:"tenant_id"`
	SubjectID          string               `json:"subject_id"`
	PrincipalType      string               `json:"principal_type"`
	Active             bool                 `json:"active"`
	SuperAdmin         bool                 `json:"super_admin"`
	Unrestricted       bool                 `json:"unrestricted"`
	DefaultRoleID      string               `json:"default_role_id,omitempty"`
	DefaultRoleName    string               `json:"default_role_name,omitempty"`
	DefaultExcluded    bool                 `json:"default_excluded"`
	RoleIDs            []string             `json:"role_ids,omitempty"`
	RoleNames          []string             `json:"role_names,omitempty"`
	RoleRefs           []ModelAccessRoleRef `json:"role_refs,omitempty"`
	DefaultModels      []string             `json:"default_models,omitempty"`
	RoleModels         []string             `json:"role_models,omitempty"`
	DirectModels       []string             `json:"direct_models,omitempty"`
	RestrictionEnabled bool                 `json:"restriction_enabled"`
	RestrictionModels  []string             `json:"restriction_models,omitempty"`
	EffectiveModels    []string             `json:"effective_models"`
	PolicyVersion      int64                `json:"policy_version"`
}

func (s *Store) migrateModelAccess(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS policy_tenants (
			tenant_id UUID PRIMARY KEY,
			slug TEXT NOT NULL UNIQUE,
			display_name TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
			is_default BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS policy_tenants_one_default ON policy_tenants (is_default) WHERE is_default`,

		`CREATE TABLE IF NOT EXISTS policy_subjects (
			subject_id UUID PRIMARY KEY,
			tenant_id UUID NOT NULL REFERENCES policy_tenants(tenant_id) ON DELETE CASCADE,
			principal_type TEXT NOT NULL CHECK (principal_type IN ('partner_user', 'group', 'service_identity', 'tenant', 'unlinked_legacy')),
			external_id TEXT NOT NULL,
			display_name TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'pending')),
			source TEXT NOT NULL DEFAULT 'manual',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE (tenant_id, principal_type, external_id),
			UNIQUE (subject_id, tenant_id)
		)`,
		`CREATE INDEX IF NOT EXISTS policy_subjects_tenant_type_idx ON policy_subjects (tenant_id, principal_type)`,

		`CREATE TABLE IF NOT EXISTS model_access_roles (
			role_id UUID PRIMARY KEY,
			tenant_id UUID NOT NULL REFERENCES policy_tenants(tenant_id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			owner_subject_id UUID NULL REFERENCES policy_subjects(subject_id) ON DELETE SET NULL,
			is_default BOOLEAN NOT NULL DEFAULT FALSE,
			created_by TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_by TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			retired_at TIMESTAMPTZ NULL,
			UNIQUE (tenant_id, name),
			UNIQUE (role_id, tenant_id)
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS model_access_roles_one_default ON model_access_roles (tenant_id) WHERE is_default AND retired_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS model_access_roles_tenant_idx ON model_access_roles (tenant_id, retired_at)`,

		`CREATE TABLE IF NOT EXISTS model_access_role_models (
			tenant_id UUID NOT NULL,
			role_id UUID NOT NULL,
			model_id TEXT NOT NULL,
			added_by TEXT NOT NULL DEFAULT '',
			added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (role_id, model_id),
			FOREIGN KEY (role_id, tenant_id) REFERENCES model_access_roles(role_id, tenant_id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS model_access_role_models_tenant_model_idx ON model_access_role_models (tenant_id, model_id)`,

		`CREATE TABLE IF NOT EXISTS model_access_role_assignments (
			tenant_id UUID NOT NULL,
			role_id UUID NOT NULL,
			subject_id UUID NOT NULL,
			assigned_by TEXT NOT NULL DEFAULT '',
			assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (role_id, subject_id),
			FOREIGN KEY (role_id, tenant_id) REFERENCES model_access_roles(role_id, tenant_id) ON DELETE CASCADE,
			FOREIGN KEY (subject_id, tenant_id) REFERENCES policy_subjects(subject_id, tenant_id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS model_access_role_assignments_subject_idx ON model_access_role_assignments (tenant_id, subject_id)`,

		`CREATE TABLE IF NOT EXISTS model_access_subject_grants (
			tenant_id UUID NOT NULL,
			subject_id UUID NOT NULL,
			model_id TEXT NOT NULL,
			granted_by TEXT NOT NULL DEFAULT '',
			granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (subject_id, model_id),
			FOREIGN KEY (subject_id, tenant_id) REFERENCES policy_subjects(subject_id, tenant_id) ON DELETE CASCADE
		)`,

		`CREATE TABLE IF NOT EXISTS model_access_subject_restrictions (
			tenant_id UUID NOT NULL,
			subject_id UUID PRIMARY KEY,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			updated_by TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE (subject_id, tenant_id),
			FOREIGN KEY (subject_id, tenant_id) REFERENCES policy_subjects(subject_id, tenant_id) ON DELETE CASCADE
		)`,

		`CREATE TABLE IF NOT EXISTS model_access_subject_restriction_models (
			tenant_id UUID NOT NULL,
			subject_id UUID NOT NULL,
			model_id TEXT NOT NULL,
			PRIMARY KEY (subject_id, model_id),
			FOREIGN KEY (subject_id, tenant_id) REFERENCES model_access_subject_restrictions(subject_id, tenant_id) ON DELETE CASCADE
		)`,

		`CREATE TABLE IF NOT EXISTS model_access_default_exclusions (
			tenant_id UUID NOT NULL,
			subject_id UUID NOT NULL,
			reason TEXT NOT NULL,
			created_by TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMPTZ NULL,
			PRIMARY KEY (tenant_id, subject_id),
			FOREIGN KEY (subject_id, tenant_id) REFERENCES policy_subjects(subject_id, tenant_id) ON DELETE CASCADE
		)`,

		`CREATE TABLE IF NOT EXISTS catalog_models (
			tenant_id UUID NOT NULL REFERENCES policy_tenants(tenant_id) ON DELETE CASCADE,
			model_id TEXT NOT NULL,
			display_name TEXT NOT NULL DEFAULT '',
			provider TEXT NOT NULL DEFAULT '',
			provider_target TEXT NULL,
			dialects TEXT[] NOT NULL DEFAULT '{}',
			paths TEXT[] NOT NULL DEFAULT '{}',
			aliases TEXT[] NOT NULL DEFAULT '{}',
			lifecycle TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active', 'deprecated', 'retired')),
			region TEXT NULL,
			cost_class TEXT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (tenant_id, model_id)
		)`,
		`CREATE TABLE IF NOT EXISTS catalog_model_aliases (
			tenant_id UUID NOT NULL,
			alias TEXT NOT NULL,
			model_id TEXT NOT NULL,
			PRIMARY KEY (tenant_id, alias),
			FOREIGN KEY (tenant_id, model_id) REFERENCES catalog_models(tenant_id, model_id) ON DELETE CASCADE
		)`,

		`CREATE TABLE IF NOT EXISTS policy_versions (
			tenant_id UUID PRIMARY KEY REFERENCES policy_tenants(tenant_id) ON DELETE CASCADE,
			version BIGINT NOT NULL DEFAULT 1,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,

		`CREATE TABLE IF NOT EXISTS policy_decisions (
			decision_id UUID PRIMARY KEY,
			tenant_id UUID NOT NULL REFERENCES policy_tenants(tenant_id) ON DELETE CASCADE,
			subject_id UUID NULL,
			principal_type TEXT NULL,
			model_id TEXT NULL,
			action TEXT NOT NULL,
			decision TEXT NOT NULL,
			reason TEXT NOT NULL,
			policy_version BIGINT NOT NULL,
			latency_ms INT NOT NULL DEFAULT 0,
			request_id TEXT NULL,
			evaluated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS policy_decisions_tenant_time_idx ON policy_decisions (tenant_id, evaluated_at DESC)`,
		`CREATE INDEX IF NOT EXISTS policy_decisions_subject_time_idx ON policy_decisions (tenant_id, subject_id, evaluated_at DESC)`,

		`CREATE TABLE IF NOT EXISTS legacy_policy_imports (
			source TEXT NOT NULL,
			source_key TEXT NOT NULL,
			tenant_id UUID NOT NULL REFERENCES policy_tenants(tenant_id) ON DELETE CASCADE,
			subject_id UUID NULL,
			imported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			checksum TEXT NOT NULL,
			status TEXT NOT NULL,
			PRIMARY KEY (tenant_id, source, source_key)
		)`,

		// v1 has one default tenant. The fixed UUID keeps API aliases and
		// tests deterministic; additional tenants get new IDs.
		`INSERT INTO policy_tenants (tenant_id, slug, display_name, is_default, status)
		 VALUES ('` + DefaultTenantID + `', '` + DefaultTenantSlug + `', 'Default', TRUE, 'active')
		 ON CONFLICT (slug) DO NOTHING`,
		`INSERT INTO policy_versions (tenant_id, version)
		 SELECT tenant_id, 1 FROM policy_tenants WHERE slug = '` + DefaultTenantSlug + `'
		 ON CONFLICT (tenant_id) DO NOTHING`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("model access migration failed: %w", err)
		}
	}
	return nil
}

// EnsureDefaultTenant returns the v1 tenant ID, creating the row if an older
// database predates the migration seed.
func (s *Store) EnsureDefaultTenant(ctx context.Context) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT tenant_id FROM policy_tenants WHERE slug = $1`, DefaultTenantSlug).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO policy_tenants (tenant_id, slug, display_name, is_default, status)
		VALUES ($1, $2, 'Default', TRUE, 'active')
		ON CONFLICT (slug) DO NOTHING`, DefaultTenantID, DefaultTenantSlug)
	if err != nil {
		return "", err
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT tenant_id FROM policy_tenants WHERE slug = $1`, DefaultTenantSlug).Scan(&id); err != nil {
		return "", err
	}
	return id, nil
}

// SyncPartnerUserSubjects materializes the current partner directory into
// policy subjects. It is idempotent and safe to run on startup and after a
// directory sync: existing subject IDs and any role assignments stay intact.
// v1 maps people only; service identities and groups are explicit.
func (s *Store) SyncPartnerUserSubjects(ctx context.Context, tenantID string) (int, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT user_id::text, active,
		       COALESCE(NULLIF(tags->>'preferred_username', ''), NULLIF(tags->>'email', ''), user_id::text)
		FROM partner_users
		ORDER BY user_id`)
	if err != nil {
		return 0, fmt.Errorf("partner user sync read: %w", err)
	}
	defer rows.Close()

	type row struct {
		userID      string
		active      bool
		displayName string
	}
	var users []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.userID, &r.active, &r.displayName); err != nil {
			return 0, err
		}
		users = append(users, r)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	count := 0
	for _, u := range users {
		status := "inactive"
		if u.active {
			status = "active"
		}
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO policy_subjects
				(subject_id, tenant_id, principal_type, external_id, display_name, status, source)
			VALUES ($1, $2, $3, $4, $5, $6, 'partner')
			ON CONFLICT (tenant_id, principal_type, external_id) DO UPDATE SET
				display_name = EXCLUDED.display_name,
				status = EXCLUDED.status,
				updated_at = NOW()`,
			uuid.NewString(), tenantID, PrincipalPartnerUser, u.userID, u.displayName, status)
		if err != nil {
			return count, fmt.Errorf("partner user subject upsert: %w", err)
		}
		count++
	}
	return count, nil
}

// SyncPartnerUserSubject materializes one partner user as a policy subject.
// OIDC login calls this after profile persistence so a person who logs in
// after startup is immediately eligible for the default role. It is
// idempotent: the subject ID is stable for an existing (tenant, type,
// external_id) row.
func (s *Store) SyncPartnerUserSubject(ctx context.Context, tenantID, userID string) (string, error) {
	var active bool
	var displayName string
	if err := s.db.QueryRowContext(ctx, `
		SELECT active,
		       COALESCE(NULLIF(tags->>'preferred_username', ''), NULLIF(tags->>'email', ''), user_id::text)
		FROM partner_users WHERE user_id = $1`, userID).Scan(&active, &displayName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrPartnerUserNotFound
		}
		return "", fmt.Errorf("partner user subject lookup: %w", err)
	}
	status := "inactive"
	if active {
		status = "active"
	}
	var subjectID string
	if err := s.db.QueryRowContext(ctx, `
		INSERT INTO policy_subjects
			(subject_id, tenant_id, principal_type, external_id, display_name, status, source)
		VALUES ($1, $2, $3, $4, $5, $6, 'partner')
		ON CONFLICT (tenant_id, principal_type, external_id) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			status = EXCLUDED.status,
			updated_at = NOW()
		RETURNING subject_id::text`,
		uuid.NewString(), tenantID, PrincipalPartnerUser, userID, displayName, status).Scan(&subjectID); err != nil {
		return "", fmt.Errorf("partner user subject upsert: %w", err)
	}
	return subjectID, nil
}

// ResolvePolicySubjectByUsername maps a MaaS login to the stable policy
// subject. It creates the subject lazily if the startup sync or OIDC login
// missed it, so the compatibility entitlement path does not cut off a valid
// partner user. Unlinked usernames return ErrPartnerUserNotFound.
func (s *Store) ResolvePolicySubjectByUsername(ctx context.Context, tenantID, username string) (string, string, error) {
	user, err := s.PartnerUserByMaaSUsername(ctx, username)
	if err != nil {
		return "", "", err
	}
	var subjectID, principalType string
	err = s.db.QueryRowContext(ctx, `
		SELECT subject_id::text, principal_type
		FROM policy_subjects
		WHERE tenant_id = $1 AND principal_type = $2 AND external_id = $3`,
		tenantID, PrincipalPartnerUser, user.UserID).Scan(&subjectID, &principalType)
	if errors.Is(err, sql.ErrNoRows) {
		subjectID, err = s.SyncPartnerUserSubject(ctx, tenantID, user.UserID)
		if err != nil {
			return "", "", err
		}
		return subjectID, PrincipalPartnerUser, nil
	}
	if err != nil {
		return "", "", fmt.Errorf("resolve policy subject: %w", err)
	}
	return subjectID, principalType, nil
}

// BumpPolicyVersion increments the tenant's policy version and returns it.
// Callers invalidate local caches after a successful mutation.
func (s *Store) BumpPolicyVersion(ctx context.Context, tenantID string) (int64, error) {
	var version int64
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO policy_versions (tenant_id, version)
		VALUES ($1, 1)
		ON CONFLICT (tenant_id) DO UPDATE SET
			version = policy_versions.version + 1,
			updated_at = NOW()
		RETURNING version`, tenantID).Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("bump policy version: %w", err)
	}
	return version, nil
}

// GetEffectiveModelAccess resolves the subject's effective model set. It is
// deliberately tenant-scoped: a role or grant in another tenant never leaks.
// superAdmin is supplied by the caller (the existing entitlement exemption);
// when true the result is Unrestricted and role/restriction data is not used.
func (s *Store) GetEffectiveModelAccess(ctx context.Context, tenantID, subjectID string, superAdmin bool) (EffectiveModelAccess, error) {
	result := EffectiveModelAccess{
		TenantID:  tenantID,
		SubjectID: subjectID,
	}

	var tenantStatus string
	if err := s.db.QueryRowContext(ctx,
		`SELECT status FROM policy_tenants WHERE tenant_id = $1`, tenantID).Scan(&tenantStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return result, ErrModelAccessTenantNotFound
		}
		return result, fmt.Errorf("policy tenant lookup: %w", err)
	}
	if tenantStatus != "active" {
		return result, ErrModelAccessTenantSuspended
	}

	var subjectStatus string
	if err := s.db.QueryRowContext(ctx, `
		SELECT principal_type, status
		FROM policy_subjects
		WHERE tenant_id = $1 AND subject_id = $2`, tenantID, subjectID).
		Scan(&result.PrincipalType, &subjectStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return result, ErrModelAccessSubjectNotFound
		}
		return result, fmt.Errorf("policy subject lookup: %w", err)
	}
	result.Active = subjectStatus == "active"
	if !result.Active {
		return result, ErrModelAccessSubjectInactive
	}

	if err := s.db.QueryRowContext(ctx,
		`SELECT version FROM policy_versions WHERE tenant_id = $1`, tenantID).
		Scan(&result.PolicyVersion); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return result, fmt.Errorf("policy version lookup: %w", err)
	}

	if superAdmin {
		result.SuperAdmin = true
		result.Unrestricted = true
		result.EffectiveModels = nil
		return result, nil
	}

	// Default role (zero or one).
	var defaultRoleID, defaultRoleName string
	err := s.db.QueryRowContext(ctx, `
		SELECT role_id, name FROM model_access_roles
		WHERE tenant_id = $1 AND is_default AND retired_at IS NULL
		LIMIT 1`, tenantID).Scan(&defaultRoleID, &defaultRoleName)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return result, fmt.Errorf("default role lookup: %w", err)
	}
	// Only partner users receive the tenant default. Service identities,
	// groups, tenant subjects, and unlinked legacy identities need explicit
	// assignments; otherwise automation would inherit the broad baseline.
	if defaultRoleID != "" && result.PrincipalType == PrincipalPartnerUser {
		result.DefaultRoleID = defaultRoleID
		result.DefaultRoleName = defaultRoleName
		var excluded bool
		if err := s.db.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM model_access_default_exclusions
				WHERE tenant_id = $1 AND subject_id = $2
				  AND (expires_at IS NULL OR expires_at > NOW())
			)`, tenantID, subjectID).Scan(&excluded); err != nil {
			return result, fmt.Errorf("default exclusion lookup: %w", err)
		}
		result.DefaultExcluded = excluded
		if !excluded {
			models, err := s.modelIDsForRole(ctx, tenantID, defaultRoleID)
			if err != nil {
				return result, err
			}
			result.DefaultModels = models
		}
	}

	// Explicit roles (additive).
	roleRefs, roleModels, err := s.explicitRoleModels(ctx, tenantID, subjectID)
	if err != nil {
		return result, err
	}
	result.RoleRefs = roleRefs
	for _, ref := range roleRefs {
		result.RoleIDs = append(result.RoleIDs, ref.RoleID)
		result.RoleNames = append(result.RoleNames, ref.Name)
	}
	result.RoleModels = roleModels

	direct, err := s.subjectGrantModels(ctx, tenantID, subjectID)
	if err != nil {
		return result, err
	}
	result.DirectModels = direct

	restrictionEnabled, restrictionModels, err := s.subjectRestriction(ctx, tenantID, subjectID)
	if err != nil {
		return result, err
	}
	result.RestrictionEnabled = restrictionEnabled
	result.RestrictionModels = restrictionModels

	base := unionModels(result.DefaultModels, result.RoleModels, result.DirectModels)
	if restrictionEnabled {
		result.EffectiveModels = intersectModels(base, restrictionModels)
	} else {
		result.EffectiveModels = base
	}
	if result.EffectiveModels == nil {
		result.EffectiveModels = []string{}
	}
	return result, nil
}

const (
	PolicyDecisionAllow = "allow"
	PolicyDecisionDeny  = "deny"

	PolicyReasonAllowed         = "allowed"
	PolicyReasonModelNotAllowed = "model_not_allowed"
	PolicyReasonAuthentication  = "authentication_failed"
	PolicyReasonTenantSuspended = "tenant_suspended"
	PolicyReasonTenantNotFound  = "tenant_not_found"
	PolicyReasonUnavailable     = "authorization_unavailable"
)

// PolicyDecision is the persisted AuthZEN-shaped answer. AllowedModels is an
// obligation for the router; it is nil when the subject is unrestricted.
type PolicyDecision struct {
	DecisionID    string `json:"decisionId"`
	TenantID      string `json:"tenant"`
	SubjectID     string `json:"subjectId,omitempty"`
	PrincipalType string `json:"principalType,omitempty"`
	ModelID       string `json:"modelId,omitempty"`
	Action        string `json:"action"`
	Decision      string `json:"decision"`
	Reason        string `json:"reason"`
	PolicyVersion int64  `json:"policyVersion"`
	// nil = unrestricted; [] = restricted with nothing allowed. Do not
	// omitempty: the gateway must distinguish those two cases.
	AllowedModels []string  `json:"allowedModels"`
	LatencyMS     int64     `json:"latencyMs"`
	EvaluatedAt   time.Time `json:"evaluatedAt"`
}

// DecideModelAccess resolves and persists one decision. The caller maps
// resolver errors (unknown/inactive/suspended) to the transport status. The
// decision row is written for allows and denies; the usage ledger stays a
// separate, zero-cost denial record.
func (s *Store) DecideModelAccess(ctx context.Context, tenantID, subjectID, model, action string, superAdmin bool) (PolicyDecision, error) {
	started := time.Now()
	action = strings.TrimSpace(action)
	if action == "" {
		action = "invoke"
	}
	effective, err := s.GetEffectiveModelAccess(ctx, tenantID, subjectID, superAdmin)
	if err != nil {
		return PolicyDecision{}, err
	}

	decision := PolicyDecision{
		DecisionID:    uuid.NewString(),
		TenantID:      tenantID,
		SubjectID:     subjectID,
		PrincipalType: effective.PrincipalType,
		ModelID:       model,
		Action:        action,
		PolicyVersion: effective.PolicyVersion,
		EvaluatedAt:   time.Now().UTC(),
	}
	if effective.Unrestricted {
		decision.Decision = PolicyDecisionAllow
		decision.Reason = PolicyReasonAllowed
	} else if action == "list" {
		decision.Decision = PolicyDecisionAllow
		decision.Reason = PolicyReasonAllowed
		decision.AllowedModels = effective.EffectiveModels
	} else if strings.TrimSpace(model) != "" && slicesContain(effective.EffectiveModels, model) {
		decision.Decision = PolicyDecisionAllow
		decision.Reason = PolicyReasonAllowed
		decision.AllowedModels = effective.EffectiveModels
	} else {
		decision.Decision = PolicyDecisionDeny
		decision.Reason = PolicyReasonModelNotAllowed
		decision.AllowedModels = effective.EffectiveModels
	}
	decision.LatencyMS = time.Since(started).Milliseconds()

	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO policy_decisions
			(decision_id, tenant_id, subject_id, principal_type, model_id, action,
			 decision, reason, policy_version, latency_ms, evaluated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		decision.DecisionID, tenantID, subjectID, decision.PrincipalType, nullIfEmpty(model),
		action, decision.Decision, decision.Reason, decision.PolicyVersion,
		decision.LatencyMS, decision.EvaluatedAt); err != nil {
		return PolicyDecision{}, fmt.Errorf("record policy decision: %w", err)
	}
	return decision, nil
}

func slicesContain(haystack []string, needle string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}

func nullIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func (s *Store) modelIDsForRole(ctx context.Context, tenantID, roleID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT model_id FROM model_access_role_models
		WHERE tenant_id = $1 AND role_id = $2
		ORDER BY model_id`, tenantID, roleID)
	if err != nil {
		return nil, fmt.Errorf("role models lookup: %w", err)
	}
	defer rows.Close()
	return scanStrings(rows)
}

func (s *Store) explicitRoleModels(ctx context.Context, tenantID, subjectID string) ([]ModelAccessRoleRef, []string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.role_id, r.name, rm.model_id
		FROM model_access_role_assignments a
		JOIN model_access_roles r
		  ON r.role_id = a.role_id AND r.tenant_id = a.tenant_id
		LEFT JOIN model_access_role_models rm
		  ON rm.role_id = r.role_id AND rm.tenant_id = r.tenant_id
		WHERE a.tenant_id = $1 AND a.subject_id = $2 AND r.retired_at IS NULL
		ORDER BY r.name, r.role_id, rm.model_id`, tenantID, subjectID)
	if err != nil {
		return nil, nil, fmt.Errorf("role assignments lookup: %w", err)
	}
	defer rows.Close()

	refs := []ModelAccessRoleRef{}
	seen := map[string]struct{}{}
	modelSet := map[string]struct{}{}
	for rows.Next() {
		var roleID, name string
		var model sql.NullString
		if err := rows.Scan(&roleID, &name, &model); err != nil {
			return nil, nil, err
		}
		if _, ok := seen[roleID]; !ok {
			seen[roleID] = struct{}{}
			refs = append(refs, ModelAccessRoleRef{RoleID: roleID, Name: name})
		}
		if model.Valid && strings.TrimSpace(model.String) != "" {
			modelSet[model.String] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
	return refs, sortedKeys(modelSet), nil
}

func (s *Store) subjectGrantModels(ctx context.Context, tenantID, subjectID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT model_id FROM model_access_subject_grants
		WHERE tenant_id = $1 AND subject_id = $2
		ORDER BY model_id`, tenantID, subjectID)
	if err != nil {
		return nil, fmt.Errorf("subject grants lookup: %w", err)
	}
	defer rows.Close()
	return scanStrings(rows)
}

func (s *Store) subjectRestriction(ctx context.Context, tenantID, subjectID string) (bool, []string, error) {
	var enabled bool
	err := s.db.QueryRowContext(ctx, `
		SELECT enabled FROM model_access_subject_restrictions
		WHERE tenant_id = $1 AND subject_id = $2`, tenantID, subjectID).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, fmt.Errorf("restriction lookup: %w", err)
	}
	if !enabled {
		return false, nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT model_id FROM model_access_subject_restriction_models
		WHERE tenant_id = $1 AND subject_id = $2
		ORDER BY model_id`, tenantID, subjectID)
	if err != nil {
		return false, nil, fmt.Errorf("restriction models lookup: %w", err)
	}
	defer rows.Close()
	models, err := scanStrings(rows)
	if err != nil {
		return false, nil, err
	}
	return true, models, nil
}

func scanStrings(rows *sql.Rows) ([]string, error) {
	out := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func unionModels(sets ...[]string) []string {
	seen := map[string]struct{}{}
	for _, set := range sets {
		for _, model := range set {
			if strings.TrimSpace(model) != "" {
				seen[model] = struct{}{}
			}
		}
	}
	return sortedKeys(seen)
}

func intersectModels(a, b []string) []string {
	keep := make(map[string]struct{}, len(b))
	for _, model := range b {
		keep[model] = struct{}{}
	}
	out := []string{}
	for _, model := range a {
		if _, ok := keep[model]; ok {
			out = append(out, model)
		}
	}
	return out
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
