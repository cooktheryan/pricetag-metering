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
	"github.com/lib/pq"
)

var (
	ErrModelAccessRoleNotFound = errors.New("model access role not found")
	ErrInvalidModelAccessRole  = errors.New("invalid model access role")
	ErrInvalidModelAccessModel = errors.New("invalid model identifier")
	ErrCannotRetireDefaultRole = errors.New("cannot retire the default role; create or assign another default first")
)

const modelAccessRoleMaxModels = 500

type ModelAccessRole struct {
	RoleID         string     `json:"role_id"`
	TenantID       string     `json:"tenant_id"`
	Name           string     `json:"name"`
	Description    string     `json:"description"`
	OwnerSubjectID string     `json:"owner_subject_id,omitempty"`
	IsDefault      bool       `json:"is_default"`
	MonthlyUSD     float64    `json:"monthly_usd"`
	Models         []string   `json:"models"`
	SubjectCount   int        `json:"subject_count"`
	RetiredAt      *time.Time `json:"retired_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type PolicySubjectRecord struct {
	SubjectID             string    `json:"subject_id"`
	TenantID              string    `json:"tenant_id"`
	PrincipalType         string    `json:"principal_type"`
	ExternalID            string    `json:"external_id"`
	DisplayName           string    `json:"display_name"`
	Status                string    `json:"status"`
	Source                string    `json:"source"`
	Email                 string    `json:"email,omitempty"`
	CostCenter            string    `json:"cost_center,omitempty"`
	CostCenterDescription string    `json:"cost_center_description,omitempty"`
	Organization          string    `json:"organization,omitempty"`
	JobTitle              string    `json:"job_title,omitempty"`
	EmployeeType          string    `json:"employee_type,omitempty"`
	Groups                []string  `json:"groups,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

func normalizeRoleModels(models []string) ([]string, error) {
	return normalizeExactModels(models, modelAccessRoleMaxModels)
}

func normalizeExactModels(models []string, max int) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(models))
	for _, model := range models {
		model = strings.TrimSpace(model)
		if model == "" {
			return nil, fmt.Errorf("%w: empty model id", ErrInvalidModelAccessModel)
		}
		if len(model) > 100 || strings.ContainsAny(model, "*?[ \t\r\n") {
			return nil, fmt.Errorf("%w: exact ids only, max 100 bytes", ErrInvalidModelAccessModel)
		}
		if _, ok := seen[model]; ok {
			continue
		}
		seen[model] = struct{}{}
		out = append(out, model)
	}
	if len(out) > max {
		return nil, fmt.Errorf("%w: at most %d models", ErrInvalidModelAccessModel, max)
	}
	sort.Strings(out)
	return out, nil
}

func (s *Store) ListModelAccessRoles(ctx context.Context, tenantID string) ([]ModelAccessRole, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.role_id::text, r.tenant_id::text, r.name, r.description,
		       COALESCE(r.owner_subject_id::text, ''), r.is_default, r.monthly_usd,
		       COALESCE(array_agg(rm.model_id ORDER BY rm.model_id)
		                FILTER (WHERE rm.model_id IS NOT NULL), '{}')::text[],
		       CASE WHEN r.is_default THEN (
		         SELECT COUNT(*) FROM policy_subjects s
		         WHERE s.tenant_id = r.tenant_id
		           AND s.principal_type = 'partner_user'
		           AND s.status = 'active'
		           AND NOT EXISTS (
		             SELECT 1 FROM model_access_default_exclusions e
		             WHERE e.tenant_id = s.tenant_id AND e.subject_id = s.subject_id
		               AND (e.expires_at IS NULL OR e.expires_at > NOW())
		           )
		       ) ELSE (
		         SELECT COUNT(*) FROM model_access_role_assignments a
		         WHERE a.tenant_id = r.tenant_id AND a.role_id = r.role_id
		       ) END,
		       r.retired_at, r.created_at, r.updated_at
		FROM model_access_roles r
		LEFT JOIN model_access_role_models rm
		  ON rm.tenant_id = r.tenant_id AND rm.role_id = r.role_id
		WHERE r.tenant_id = $1 AND r.retired_at IS NULL
		GROUP BY r.role_id
		ORDER BY r.is_default DESC, r.name`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list model access roles: %w", err)
	}
	defer rows.Close()
	var out []ModelAccessRole
	for rows.Next() {
		var role ModelAccessRole
		var models []string
		var retired sql.NullTime
		if err := rows.Scan(&role.RoleID, &role.TenantID, &role.Name, &role.Description,
			&role.OwnerSubjectID, &role.IsDefault, &role.MonthlyUSD, pq.Array(&models), &role.SubjectCount,
			&retired, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, err
		}
		role.Models = models
		if role.Models == nil {
			role.Models = []string{}
		}
		if retired.Valid {
			t := retired.Time
			role.RetiredAt = &t
		}
		out = append(out, role)
	}
	return out, rows.Err()
}

func (s *Store) GetDefaultModelAccessRole(ctx context.Context, tenantID string) (ModelAccessRole, error) {
	var roleID string
	if err := s.db.QueryRowContext(ctx, `
		SELECT role_id::text FROM model_access_roles
		WHERE tenant_id = $1 AND is_default AND retired_at IS NULL
		LIMIT 1`, tenantID).Scan(&roleID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ModelAccessRole{}, ErrModelAccessRoleNotFound
		}
		return ModelAccessRole{}, err
	}
	return s.GetModelAccessRole(ctx, tenantID, roleID)
}

func (s *Store) GetModelAccessRole(ctx context.Context, tenantID, roleID string) (ModelAccessRole, error) {
	roles, err := s.ListModelAccessRoles(ctx, tenantID)
	if err != nil {
		return ModelAccessRole{}, err
	}
	for _, role := range roles {
		if role.RoleID == roleID {
			return role, nil
		}
	}
	return ModelAccessRole{}, ErrModelAccessRoleNotFound
}

func (s *Store) CreateModelAccessRole(ctx context.Context, tenantID, actor, name, description string, models []string, isDefault bool, monthlyUSD float64) (ModelAccessRole, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 120 {
		return ModelAccessRole{}, fmt.Errorf("%w: name required, max 120 bytes", ErrInvalidModelAccessRole)
	}
	if monthlyUSD < 0 {
		return ModelAccessRole{}, fmt.Errorf("%w: monthly_usd must be >= 0", ErrInvalidModelAccessRole)
	}
	clean, err := normalizeRoleModels(models)
	if err != nil {
		return ModelAccessRole{}, err
	}
	roleID := uuid.NewString()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ModelAccessRole{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if isDefault {
		if _, err := tx.ExecContext(ctx, `
			UPDATE model_access_roles SET is_default = FALSE, updated_at = NOW()
			WHERE tenant_id = $1 AND is_default AND retired_at IS NULL`, tenantID); err != nil {
			return ModelAccessRole{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO model_access_roles
			(role_id, tenant_id, name, description, is_default, monthly_usd, created_by, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $7)`,
		roleID, tenantID, name, strings.TrimSpace(description), isDefault, monthlyUSD, actor); err != nil {
		return ModelAccessRole{}, fmt.Errorf("create role: %w", err)
	}
	for _, model := range clean {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO model_access_role_models (tenant_id, role_id, model_id, added_by)
			VALUES ($1, $2, $3, $4)`, tenantID, roleID, model, actor); err != nil {
			return ModelAccessRole{}, err
		}
	}
	if err := s.bumpPolicyVersionTx(ctx, tx, tenantID); err != nil {
		return ModelAccessRole{}, err
	}
	if err := s.auditTx(ctx, tx, actor, "model_access.role_create", roleID, map[string]any{
		"name": name, "models": clean, "is_default": isDefault, "monthly_usd": monthlyUSD,
	}); err != nil {
		return ModelAccessRole{}, err
	}
	if err := tx.Commit(); err != nil {
		return ModelAccessRole{}, err
	}
	return s.GetModelAccessRole(ctx, tenantID, roleID)
}

func (s *Store) RetireModelAccessRole(ctx context.Context, tenantID, roleID, actor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var isDefault bool
	if err := tx.QueryRowContext(ctx, `
		SELECT is_default FROM model_access_roles
		WHERE tenant_id = $1 AND role_id = $2 AND retired_at IS NULL
		FOR UPDATE`, tenantID, roleID).Scan(&isDefault); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrModelAccessRoleNotFound
		}
		return err
	}
	if isDefault {
		return ErrCannotRetireDefaultRole
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE model_access_roles
		SET retired_at = NOW(), updated_at = NOW(), updated_by = $3
		WHERE tenant_id = $1 AND role_id = $2`, tenantID, roleID, actor); err != nil {
		return err
	}
	if err := s.bumpPolicyVersionTx(ctx, tx, tenantID); err != nil {
		return err
	}
	if err := s.auditTx(ctx, tx, actor, "model_access.role_retire", roleID, nil); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SetModelAccessRoleBudget(ctx context.Context, tenantID, roleID, actor string, monthlyUSD float64) error {
	if monthlyUSD < 0 {
		return fmt.Errorf("%w: monthly_usd must be >= 0", ErrInvalidModelAccessRole)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		UPDATE model_access_roles
		SET monthly_usd = $3, updated_by = $4, updated_at = NOW()
		WHERE tenant_id = $1 AND role_id = $2 AND retired_at IS NULL`,
		tenantID, roleID, monthlyUSD, actor)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return ErrModelAccessRoleNotFound
	}
	if err := s.bumpPolicyVersionTx(ctx, tx, tenantID); err != nil {
		return err
	}
	if err := s.auditTx(ctx, tx, actor, "model_access.role_budget_set", roleID, map[string]any{
		"monthly_usd": monthlyUSD,
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.invalidateQuotaCache()
	return nil
}

type QuotaCredit struct {
	CreditID   string     `json:"credit_id"`
	TenantID   string     `json:"tenant_id"`
	SubjectID  string     `json:"subject_id"`
	AmountUSD  float64    `json:"amount_usd"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	Reason     string     `json:"reason"`
	CreatedBy  string     `json:"created_by"`
	ApprovedBy string     `json:"approved_by,omitempty"`
	RequestID  string     `json:"request_id,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

func (s *Store) AddQuotaCredit(ctx context.Context, tenantID, subjectID string, amountUSD float64, expiresAt *time.Time, reason, actor string) (QuotaCredit, error) {
	if amountUSD <= 0 {
		return QuotaCredit{}, fmt.Errorf("credit amount must be > 0")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return QuotaCredit{}, fmt.Errorf("reason is required")
	}
	credit := QuotaCredit{
		CreditID:  uuid.NewString(),
		TenantID:  tenantID,
		SubjectID: subjectID,
		AmountUSD: amountUSD,
		ExpiresAt: expiresAt,
		Reason:    reason,
		CreatedBy: actor,
		CreatedAt: time.Now().UTC(),
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO quota_credits
			(credit_id, tenant_id, subject_id, amount_usd, expires_at, reason, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		credit.CreditID, tenantID, subjectID, amountUSD, expiresAt, reason, actor); err != nil {
		return QuotaCredit{}, fmt.Errorf("add quota credit: %w", err)
	}
	if err := s.Audit(ctx, actor, "model_access.credit_add", subjectID, map[string]any{
		"amount_usd": amountUSD, "expires_at": expiresAt, "reason": reason,
	}); err != nil {
		return QuotaCredit{}, err
	}
	s.invalidateQuotaCache()
	return credit, nil
}

func (s *Store) ListQuotaCredits(ctx context.Context, tenantID, subjectID string) ([]QuotaCredit, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT credit_id::text, tenant_id::text, subject_id::text, amount_usd,
		       expires_at, reason, created_by, COALESCE(approved_by, ''),
		       COALESCE(request_id, ''), created_at
		FROM quota_credits
		WHERE tenant_id = $1 AND subject_id = $2
		ORDER BY created_at DESC`, tenantID, subjectID)
	if err != nil {
		return nil, fmt.Errorf("list quota credits: %w", err)
	}
	defer rows.Close()
	out := []QuotaCredit{}
	for rows.Next() {
		var c QuotaCredit
		var expires sql.NullTime
		if err := rows.Scan(&c.CreditID, &c.TenantID, &c.SubjectID, &c.AmountUSD,
			&expires, &c.Reason, &c.CreatedBy, &c.ApprovedBy, &c.RequestID, &c.CreatedAt); err != nil {
			return nil, err
		}
		if expires.Valid {
			t := expires.Time
			c.ExpiresAt = &t
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) DeleteQuotaCredit(ctx context.Context, tenantID, subjectID, creditID, actor string) error {
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM quota_credits
		WHERE tenant_id = $1 AND subject_id = $2 AND credit_id = $3`,
		tenantID, subjectID, creditID)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return fmt.Errorf("quota credit not found")
	}
	if err := s.Audit(ctx, actor, "model_access.credit_delete", subjectID, map[string]any{
		"credit_id": creditID,
	}); err != nil {
		return err
	}
	s.invalidateQuotaCache()
	return nil
}

func (s *Store) SetModelAccessRoleModels(ctx context.Context, tenantID, roleID, actor string, models []string) error {
	clean, err := normalizeRoleModels(models)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var exists bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM model_access_roles
		 WHERE tenant_id = $1 AND role_id = $2 AND retired_at IS NULL)`,
		tenantID, roleID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrModelAccessRoleNotFound
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM model_access_role_models WHERE tenant_id = $1 AND role_id = $2`,
		tenantID, roleID); err != nil {
		return err
	}
	for _, model := range clean {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO model_access_role_models (tenant_id, role_id, model_id, added_by)
			VALUES ($1, $2, $3, $4)`, tenantID, roleID, model, actor); err != nil {
			return err
		}
	}
	if err := s.bumpPolicyVersionTx(ctx, tx, tenantID); err != nil {
		return err
	}
	if err := s.auditTx(ctx, tx, actor, "model_access.role_models_set", roleID, map[string]any{
		"models": clean,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) AssignModelAccessRole(ctx context.Context, tenantID, roleID, subjectID, actor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO model_access_role_assignments (tenant_id, role_id, subject_id, assigned_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (role_id, subject_id) DO NOTHING`,
		tenantID, roleID, subjectID, actor); err != nil {
		return fmt.Errorf("assign role: %w", err)
	}
	if err := s.bumpPolicyVersionTx(ctx, tx, tenantID); err != nil {
		return err
	}
	if err := s.auditTx(ctx, tx, actor, "model_access.assignment_add", roleID, map[string]any{
		"subject_id": subjectID,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// AssignModelAccessRoleSubjects assigns an explicit, pre-resolved set of
// subjects to a role. It is the bulk path behind the admin picker; it never
// creates a dynamic group/organization binding.
func (s *Store) AssignModelAccessRoleSubjects(ctx context.Context, tenantID, roleID string, subjectIDs []string, actor string) (int, error) {
	unique := make([]string, 0, len(subjectIDs))
	seen := map[string]struct{}{}
	for _, id := range subjectIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	if len(unique) == 0 {
		return 0, nil
	}
	if len(unique) > 5000 {
		return 0, fmt.Errorf("at most 5000 subjects per assignment")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var exists bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM model_access_roles
		 WHERE tenant_id = $1 AND role_id = $2 AND retired_at IS NULL)`,
		tenantID, roleID).Scan(&exists); err != nil {
		return 0, err
	}
	if !exists {
		return 0, ErrModelAccessRoleNotFound
	}
	assigned := 0
	for _, subjectID := range unique {
		result, err := tx.ExecContext(ctx, `
			INSERT INTO model_access_role_assignments (tenant_id, role_id, subject_id, assigned_by)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (role_id, subject_id) DO NOTHING`,
			tenantID, roleID, subjectID, actor)
		if err != nil {
			return assigned, fmt.Errorf("assign subject %s: %w", subjectID, err)
		}
		n, _ := result.RowsAffected()
		assigned += int(n)
	}
	if err := s.bumpPolicyVersionTx(ctx, tx, tenantID); err != nil {
		return assigned, err
	}
	if err := s.auditTx(ctx, tx, actor, "model_access.assignment_bulk", roleID, map[string]any{
		"requested": len(unique), "assigned": assigned,
	}); err != nil {
		return assigned, err
	}
	if err := tx.Commit(); err != nil {
		return assigned, err
	}
	return assigned, nil
}

func (s *Store) RemoveModelAccessRoleSubject(ctx context.Context, tenantID, roleID, subjectID, actor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM model_access_role_assignments
		WHERE tenant_id = $1 AND role_id = $2 AND subject_id = $3`,
		tenantID, roleID, subjectID); err != nil {
		return err
	}
	if err := s.bumpPolicyVersionTx(ctx, tx, tenantID); err != nil {
		return err
	}
	if err := s.auditTx(ctx, tx, actor, "model_access.assignment_remove", roleID, map[string]any{
		"subject_id": subjectID,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListModelAccessRoleSubjects(ctx context.Context, tenantID, roleID string) ([]PolicySubjectRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.subject_id::text, s.tenant_id::text, s.principal_type, s.external_id,
		       s.display_name, s.status, s.source,
		       COALESCE(pu.tags->>'email', ''),
		       COALESCE(pu.tags->>'cost_center', ''),
		       COALESCE(pu.tags->>'cost_center_description', ''),
		       COALESCE(pu.tags->>'organization', ''),
		       COALESCE(pu.tags->>'job_title', ''),
		       COALESCE(pu.tags->>'employee_type', ''),
		       COALESCE(ARRAY(SELECT jsonb_array_elements_text(pu.tags->'groups')), '{}')::text[],
		       s.created_at, s.updated_at
		FROM model_access_role_assignments a
		JOIN policy_subjects s
		  ON s.subject_id = a.subject_id AND s.tenant_id = a.tenant_id
		LEFT JOIN partner_users pu
		  ON s.principal_type = 'partner_user' AND pu.user_id::text = s.external_id
		WHERE a.tenant_id = $1 AND a.role_id = $2
		ORDER BY s.display_name, s.external_id`, tenantID, roleID)
	if err != nil {
		return nil, fmt.Errorf("list role subjects: %w", err)
	}
	defer rows.Close()
	out := []PolicySubjectRecord{}
	for rows.Next() {
		var s PolicySubjectRecord
		if err := rows.Scan(&s.SubjectID, &s.TenantID, &s.PrincipalType, &s.ExternalID,
			&s.DisplayName, &s.Status, &s.Source, &s.Email, &s.CostCenter,
			&s.CostCenterDescription, &s.Organization, &s.JobTitle, &s.EmployeeType,
			pq.Array(&s.Groups), &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (s *Store) ListPolicySubjects(ctx context.Context, tenantID, query string, limit, offset int) ([]PolicySubjectRecord, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.subject_id::text, s.tenant_id::text, s.principal_type, s.external_id,
		       s.display_name, s.status, s.source,
		       COALESCE(pu.tags->>'email', ''),
		       COALESCE(pu.tags->>'cost_center', ''),
		       COALESCE(pu.tags->>'cost_center_description', ''),
		       COALESCE(pu.tags->>'organization', ''),
		       COALESCE(pu.tags->>'job_title', ''),
		       COALESCE(pu.tags->>'employee_type', ''),
		       COALESCE(ARRAY(SELECT jsonb_array_elements_text(pu.tags->'groups')), '{}')::text[],
		       s.created_at, s.updated_at
		FROM policy_subjects s
		LEFT JOIN partner_users pu
		  ON s.principal_type = 'partner_user' AND pu.user_id::text = s.external_id
		WHERE s.tenant_id = $1
		  AND ($2 = '' OR s.display_name ILIKE '%' || $2 || '%'
		       OR s.external_id ILIKE '%' || $2 || '%'
		       OR COALESCE(pu.tags->>'email', '') ILIKE '%' || $2 || '%'
		       OR COALESCE(pu.tags->>'cost_center', '') ILIKE '%' || $2 || '%'
		       OR COALESCE(pu.tags->>'cost_center_description', '') ILIKE '%' || $2 || '%'
		       OR COALESCE(pu.tags->>'organization', '') ILIKE '%' || $2 || '%'
		       OR COALESCE(pu.tags->>'job_title', '') ILIKE '%' || $2 || '%'
		       OR COALESCE(pu.tags->>'employee_type', '') ILIKE '%' || $2 || '%'
		       OR COALESCE(pu.tags->>'groups', '') ILIKE '%' || $2 || '%')
		ORDER BY s.display_name, s.external_id
		LIMIT $3 OFFSET $4`, tenantID, strings.TrimSpace(query), limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list policy subjects: %w", err)
	}
	defer rows.Close()
	var out []PolicySubjectRecord
	for rows.Next() {
		var s PolicySubjectRecord
		if err := rows.Scan(&s.SubjectID, &s.TenantID, &s.PrincipalType, &s.ExternalID,
			&s.DisplayName, &s.Status, &s.Source, &s.Email, &s.CostCenter,
			&s.CostCenterDescription, &s.Organization, &s.JobTitle, &s.EmployeeType,
			pq.Array(&s.Groups), &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// GetRoleBudgetUSD sums the per-member budget contributions of the roles
// currently assigned to a subject. The default role contributes only to
// partner users and only when the subject is not excluded. A zero result
// means "no role budget configured"; quota falls back to the global default.
func (s *Store) GetRoleBudgetUSD(ctx context.Context, tenantID, subjectID string) (float64, error) {
	var budget float64
	if err := s.db.QueryRowContext(ctx, `
		WITH assigned AS (
			SELECT r.monthly_usd
			FROM model_access_roles r
			WHERE r.tenant_id = $1 AND r.is_default AND r.retired_at IS NULL
			  AND EXISTS (
			    SELECT 1 FROM policy_subjects s
			    WHERE s.tenant_id = $1 AND s.subject_id = $2 AND s.principal_type = 'partner_user'
			  )
			  AND NOT EXISTS (
			    SELECT 1 FROM model_access_default_exclusions e
			    WHERE e.tenant_id = $1 AND e.subject_id = $2
			      AND (e.expires_at IS NULL OR e.expires_at > NOW())
			  )
			  -- An explicit assignment of the default role is counted once,
			  -- in the assignment branch below.
			  AND NOT EXISTS (
			    SELECT 1 FROM model_access_role_assignments a
			    WHERE a.tenant_id = r.tenant_id AND a.role_id = r.role_id
			      AND a.subject_id = $2
			  )
			UNION ALL
			SELECT r.monthly_usd
			FROM model_access_role_assignments a
			JOIN model_access_roles r
			  ON r.role_id = a.role_id AND r.tenant_id = a.tenant_id
			WHERE a.tenant_id = $1 AND a.subject_id = $2 AND r.retired_at IS NULL
		)
		SELECT COALESCE(SUM(monthly_usd), 0) FROM assigned`,
		tenantID, subjectID).Scan(&budget); err != nil {
		return 0, fmt.Errorf("role budget lookup: %w", err)
	}
	return budget, nil
}

// GetActiveCreditUSD sums non-expired temporary per-person credits.
func (s *Store) GetActiveCreditUSD(ctx context.Context, tenantID, subjectID string) (float64, error) {
	var credits float64
	if err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(amount_usd), 0)
		FROM quota_credits
		WHERE tenant_id = $1 AND subject_id = $2
		  AND (expires_at IS NULL OR expires_at > NOW())`,
		tenantID, subjectID).Scan(&credits); err != nil {
		return 0, fmt.Errorf("quota credit lookup: %w", err)
	}
	return credits, nil
}

func policySubjectFilterClause(field, placeholder string) (string, error) {
	switch field {
	case "cost_center":
		return `COALESCE(pu.tags->>'cost_center', '') = ` + placeholder, nil
	case "organization":
		return `COALESCE(pu.tags->>'organization', '') = ` + placeholder, nil
	case "group":
		return `EXISTS (SELECT 1 FROM jsonb_array_elements_text(pu.tags->'groups') g WHERE g = ` + placeholder + `)`, nil
	default:
		return "", fmt.Errorf("unsupported subject filter %q", field)
	}
}

func (s *Store) ListPolicySubjectsByFilter(ctx context.Context, tenantID, field, value string, limit int) ([]PolicySubjectRecord, error) {
	clause, err := policySubjectFilterClause(field, "$2")
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.subject_id::text, s.tenant_id::text, s.principal_type, s.external_id,
		       s.display_name, s.status, s.source,
		       COALESCE(pu.tags->>'email', ''),
		       COALESCE(pu.tags->>'cost_center', ''),
		       COALESCE(pu.tags->>'cost_center_description', ''),
		       COALESCE(pu.tags->>'organization', ''),
		       COALESCE(pu.tags->>'job_title', ''),
		       COALESCE(pu.tags->>'employee_type', ''),
		       COALESCE(ARRAY(SELECT jsonb_array_elements_text(pu.tags->'groups')), '{}')::text[],
		       s.created_at, s.updated_at
		FROM policy_subjects s
		LEFT JOIN partner_users pu
		  ON s.principal_type = 'partner_user' AND pu.user_id::text = s.external_id
		WHERE s.tenant_id = $1 AND s.principal_type = 'partner_user' AND s.status = 'active'
		  AND `+clause+`
		ORDER BY s.display_name, s.external_id
		LIMIT $3`, tenantID, strings.TrimSpace(value), limit)
	if err != nil {
		return nil, fmt.Errorf("list policy subjects by filter: %w", err)
	}
	defer rows.Close()
	out := []PolicySubjectRecord{}
	for rows.Next() {
		var s PolicySubjectRecord
		if err := rows.Scan(&s.SubjectID, &s.TenantID, &s.PrincipalType, &s.ExternalID,
			&s.DisplayName, &s.Status, &s.Source, &s.Email, &s.CostCenter,
			&s.CostCenterDescription, &s.Organization, &s.JobTitle, &s.EmployeeType,
			pq.Array(&s.Groups), &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (s *Store) CountPolicySubjectsByFilter(ctx context.Context, tenantID, field, value string) (int, error) {
	clause, err := policySubjectFilterClause(field, "$2")
	if err != nil {
		return 0, err
	}
	var count int
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM policy_subjects s
		LEFT JOIN partner_users pu
		  ON s.principal_type = 'partner_user' AND pu.user_id::text = s.external_id
		WHERE s.tenant_id = $1 AND s.principal_type = 'partner_user' AND s.status = 'active'
		  AND `+clause, tenantID, strings.TrimSpace(value)).Scan(&count); err != nil {
		return 0, fmt.Errorf("count policy subjects by filter: %w", err)
	}
	return count, nil
}

// AssignModelAccessRoleByFilter assigns every currently matching person to a
// role. It resolves the match at apply time and writes explicit assignment
// rows; it does not create a dynamic organization/group binding.
func (s *Store) AssignModelAccessRoleByFilter(ctx context.Context, tenantID, roleID, field, value, actor string) (int, error) {
	clause, err := policySubjectFilterClause(field, "$3")
	if err != nil {
		return 0, err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("filter value is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var exists bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM model_access_roles
		 WHERE tenant_id = $1 AND role_id = $2 AND retired_at IS NULL)`,
		tenantID, roleID).Scan(&exists); err != nil {
		return 0, err
	}
	if !exists {
		return 0, ErrModelAccessRoleNotFound
	}
	result, err := tx.ExecContext(ctx, `
		INSERT INTO model_access_role_assignments (tenant_id, role_id, subject_id, assigned_by)
		SELECT $1, $2, s.subject_id, $4
		FROM policy_subjects s
		LEFT JOIN partner_users pu
		  ON s.principal_type = 'partner_user' AND pu.user_id::text = s.external_id
		WHERE s.tenant_id = $1 AND s.principal_type = 'partner_user' AND s.status = 'active'
		  AND `+clause+`
		ON CONFLICT (role_id, subject_id) DO NOTHING`,
		tenantID, roleID, value, actor)
	if err != nil {
		return 0, fmt.Errorf("assign role by filter: %w", err)
	}
	n, _ := result.RowsAffected()
	if err := s.bumpPolicyVersionTx(ctx, tx, tenantID); err != nil {
		return int(n), err
	}
	if err := s.auditTx(ctx, tx, actor, "model_access.assignment_filter", roleID, map[string]any{
		"field": field, "value": value, "assigned": n,
	}); err != nil {
		return int(n), err
	}
	if err := tx.Commit(); err != nil {
		return int(n), err
	}
	return int(n), nil
}

func (s *Store) EnsureServiceIdentity(ctx context.Context, tenantID, externalID, displayName string) (string, error) {
	externalID = strings.TrimSpace(externalID)
	if externalID == "" {
		return "", fmt.Errorf("service identity external_id required")
	}
	var id string
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO policy_subjects
			(subject_id, tenant_id, principal_type, external_id, display_name, status, source)
		VALUES ($1, $2, $3, $4, $5, 'active', 'manual')
		ON CONFLICT (tenant_id, principal_type, external_id) DO UPDATE SET
			display_name = EXCLUDED.display_name, updated_at = NOW()
		RETURNING subject_id::text`,
		uuid.NewString(), tenantID, PrincipalService, externalID, strings.TrimSpace(displayName)).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("ensure service identity: %w", err)
	}
	return id, nil
}

func (s *Store) SetSubjectGrants(ctx context.Context, tenantID, subjectID, actor string, models []string) error {
	clean, err := normalizeExactModels(models, 50)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM model_access_subject_grants WHERE tenant_id = $1 AND subject_id = $2`,
		tenantID, subjectID); err != nil {
		return err
	}
	for _, model := range clean {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO model_access_subject_grants (tenant_id, subject_id, model_id, granted_by)
			VALUES ($1, $2, $3, $4)`, tenantID, subjectID, model, actor); err != nil {
			return err
		}
	}
	if err := s.bumpPolicyVersionTx(ctx, tx, tenantID); err != nil {
		return err
	}
	if err := s.auditTx(ctx, tx, actor, "model_access.subject_grant_set", subjectID, map[string]any{
		"models": clean,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SetSubjectRestriction(ctx context.Context, tenantID, subjectID, actor string, enabled bool, models []string) error {
	clean, err := normalizeExactModels(models, 50)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO model_access_subject_restrictions (tenant_id, subject_id, enabled, updated_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (subject_id) DO UPDATE SET
			enabled = EXCLUDED.enabled, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
		tenantID, subjectID, enabled, actor); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM model_access_subject_restriction_models WHERE tenant_id = $1 AND subject_id = $2`,
		tenantID, subjectID); err != nil {
		return err
	}
	for _, model := range clean {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO model_access_subject_restriction_models (tenant_id, subject_id, model_id)
			VALUES ($1, $2, $3)`, tenantID, subjectID, model); err != nil {
			return err
		}
	}
	if err := s.bumpPolicyVersionTx(ctx, tx, tenantID); err != nil {
		return err
	}
	if err := s.auditTx(ctx, tx, actor, "model_access.restriction_set", subjectID, map[string]any{
		"enabled": enabled, "models": clean,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ExcludeSubjectFromDefault(ctx context.Context, tenantID, subjectID, actor, reason string, expiresAt *time.Time) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return fmt.Errorf("reason required for default exclusion")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO model_access_default_exclusions
			(tenant_id, subject_id, reason, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, subject_id) DO UPDATE SET
			reason = EXCLUDED.reason, created_by = EXCLUDED.created_by,
			created_at = NOW(), expires_at = EXCLUDED.expires_at`,
		tenantID, subjectID, reason, actor, expiresAt); err != nil {
		return err
	}
	if err := s.bumpPolicyVersionTx(ctx, tx, tenantID); err != nil {
		return err
	}
	if err := s.auditTx(ctx, tx, actor, "model_access.default_exclusion", subjectID, map[string]any{
		"reason": reason, "expires_at": expiresAt,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ClearDefaultExclusion(ctx context.Context, tenantID, subjectID, actor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM model_access_default_exclusions
		WHERE tenant_id = $1 AND subject_id = $2`, tenantID, subjectID); err != nil {
		return err
	}
	if err := s.bumpPolicyVersionTx(ctx, tx, tenantID); err != nil {
		return err
	}
	if err := s.auditTx(ctx, tx, actor, "model_access.default_exclusion_clear", subjectID, nil); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) bumpPolicyVersionTx(ctx context.Context, ex execer, tenantID string) error {
	var version int64
	if err := ex.QueryRowContext(ctx, `
		INSERT INTO policy_versions (tenant_id, version)
		VALUES ($1, 1)
		ON CONFLICT (tenant_id) DO UPDATE SET
			version = policy_versions.version + 1, updated_at = NOW()
		RETURNING version`, tenantID).Scan(&version); err != nil {
		return err
	}
	// Role membership and budget changes affect the cached quota decision.
	s.invalidateQuotaCache()
	return nil
}
