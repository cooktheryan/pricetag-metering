package storage

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

func createTestTenant(t *testing.T, s *Store, ctx context.Context, slug string, isDefault bool) string {
	t.Helper()
	id := uuid.NewString()
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO policy_tenants (tenant_id, slug, display_name, is_default, status)
		VALUES ($1, $2, $2, $3, 'active')`, id, slug, isDefault); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO policy_versions (tenant_id, version) VALUES ($1, 1)`, id); err != nil {
		t.Fatalf("create policy version: %v", err)
	}
	return id
}

func createTestSubject(t *testing.T, s *Store, ctx context.Context, tenantID, principal, external, status string) string {
	t.Helper()
	id := uuid.NewString()
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO policy_subjects
			(subject_id, tenant_id, principal_type, external_id, display_name, status, source)
		VALUES ($1, $2, $3, $4, $4, $5, 'manual')`,
		id, tenantID, principal, external, status); err != nil {
		t.Fatalf("create subject: %v", err)
	}
	return id
}

func createTestRole(t *testing.T, s *Store, ctx context.Context, tenantID, name string, isDefault bool, models ...string) string {
	t.Helper()
	id := uuid.NewString()
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO model_access_roles (role_id, tenant_id, name, is_default, created_by, updated_by)
		VALUES ($1, $2, $3, $4, 'test', 'test')`, id, tenantID, name, isDefault); err != nil {
		t.Fatalf("create role: %v", err)
	}
	for _, model := range models {
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO model_access_role_models (tenant_id, role_id, model_id, added_by)
			VALUES ($1, $2, $3, 'test')`, tenantID, id, model); err != nil {
			t.Fatalf("add role model: %v", err)
		}
	}
	return id
}

func assignTestRole(t *testing.T, s *Store, ctx context.Context, tenantID, roleID, subjectID string) {
	t.Helper()
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO model_access_role_assignments (tenant_id, role_id, subject_id, assigned_by)
		VALUES ($1, $2, $3, 'test')`, tenantID, roleID, subjectID); err != nil {
		t.Fatalf("assign role: %v", err)
	}
}

func grantTestModel(t *testing.T, s *Store, ctx context.Context, tenantID, subjectID, model string) {
	t.Helper()
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO model_access_subject_grants (tenant_id, subject_id, model_id, granted_by)
		VALUES ($1, $2, $3, 'test')`, tenantID, subjectID, model); err != nil {
		t.Fatalf("grant model: %v", err)
	}
}

func restrictTestSubject(t *testing.T, s *Store, ctx context.Context, tenantID, subjectID string, models ...string) {
	t.Helper()
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO model_access_subject_restrictions (tenant_id, subject_id, enabled, updated_by)
		VALUES ($1, $2, TRUE, 'test')`, tenantID, subjectID); err != nil {
		t.Fatalf("create restriction: %v", err)
	}
	for _, model := range models {
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO model_access_subject_restriction_models (tenant_id, subject_id, model_id)
			VALUES ($1, $2, $3)`, tenantID, subjectID, model); err != nil {
			t.Fatalf("add restriction model: %v", err)
		}
	}
}

func excludeTestDefault(t *testing.T, s *Store, ctx context.Context, tenantID, subjectID string, expiresAt *time.Time) {
	t.Helper()
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO model_access_default_exclusions
			(tenant_id, subject_id, reason, created_by, expires_at)
		VALUES ($1, $2, 'test', 'test', $3)`, tenantID, subjectID, expiresAt); err != nil {
		t.Fatalf("exclude default: %v", err)
	}
}

func TestModelAccessNoDefaultNoRoles(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, err := s.EnsureDefaultTenant(ctx)
	if err != nil {
		t.Fatal(err)
	}
	subject := createTestSubject(t, s, ctx, tenant, PrincipalPartnerUser, uuid.NewString(), "active")

	got, err := s.GetEffectiveModelAccess(ctx, tenant, subject, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.EffectiveModels) != 0 {
		t.Fatalf("effective = %v, want empty", got.EffectiveModels)
	}
	if got.DefaultRoleID != "" {
		t.Fatalf("default role = %q, want none", got.DefaultRoleID)
	}
}

func TestModelAccessDefaultRoleApplies(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, _ := s.EnsureDefaultTenant(ctx)
	createTestRole(t, s, ctx, tenant, "Engineer", true, "model-a", "model-b")
	subject := createTestSubject(t, s, ctx, tenant, PrincipalPartnerUser, uuid.NewString(), "active")

	got, err := s.GetEffectiveModelAccess(ctx, tenant, subject, false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.DefaultModels, []string{"model-a", "model-b"}) {
		t.Fatalf("default models = %v", got.DefaultModels)
	}
	if !slices.Equal(got.EffectiveModels, []string{"model-a", "model-b"}) {
		t.Fatalf("effective = %v", got.EffectiveModels)
	}
	if len(got.RoleIDs) != 0 {
		t.Fatalf("explicit roles = %v, want none", got.RoleIDs)
	}
}

func TestModelAccessExplicitRoleAdditive(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, _ := s.EnsureDefaultTenant(ctx)
	createTestRole(t, s, ctx, tenant, "Engineer", true, "model-a")
	research := createTestRole(t, s, ctx, tenant, "Research", false, "model-a", "model-b")
	subject := createTestSubject(t, s, ctx, tenant, PrincipalPartnerUser, uuid.NewString(), "active")
	assignTestRole(t, s, ctx, tenant, research, subject)

	got, err := s.GetEffectiveModelAccess(ctx, tenant, subject, false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.EffectiveModels, []string{"model-a", "model-b"}) {
		t.Fatalf("effective = %v", got.EffectiveModels)
	}
	if !slices.Equal(got.RoleNames, []string{"Research"}) {
		t.Fatalf("role names = %v", got.RoleNames)
	}
}

func TestModelAccessDirectGrant(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, _ := s.EnsureDefaultTenant(ctx)
	createTestRole(t, s, ctx, tenant, "Engineer", true, "model-a")
	subject := createTestSubject(t, s, ctx, tenant, PrincipalPartnerUser, uuid.NewString(), "active")
	grantTestModel(t, s, ctx, tenant, subject, "model-c")

	got, err := s.GetEffectiveModelAccess(ctx, tenant, subject, false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.EffectiveModels, []string{"model-a", "model-c"}) {
		t.Fatalf("effective = %v", got.EffectiveModels)
	}
}

func TestModelAccessRestrictionDenyOverrides(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, _ := s.EnsureDefaultTenant(ctx)
	createTestRole(t, s, ctx, tenant, "Engineer", true, "model-a")
	research := createTestRole(t, s, ctx, tenant, "Research", false, "model-b")
	subject := createTestSubject(t, s, ctx, tenant, PrincipalPartnerUser, uuid.NewString(), "active")
	assignTestRole(t, s, ctx, tenant, research, subject)
	grantTestModel(t, s, ctx, tenant, subject, "model-c")
	restrictTestSubject(t, s, ctx, tenant, subject, "model-a")

	got, err := s.GetEffectiveModelAccess(ctx, tenant, subject, false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.EffectiveModels, []string{"model-a"}) {
		t.Fatalf("effective = %v", got.EffectiveModels)
	}
	if !got.RestrictionEnabled {
		t.Fatal("restriction should be enabled")
	}
}

func TestModelAccessEmptyRestrictionDeniesAll(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, _ := s.EnsureDefaultTenant(ctx)
	createTestRole(t, s, ctx, tenant, "Engineer", true, "model-a")
	subject := createTestSubject(t, s, ctx, tenant, PrincipalPartnerUser, uuid.NewString(), "active")
	restrictTestSubject(t, s, ctx, tenant, subject)

	got, err := s.GetEffectiveModelAccess(ctx, tenant, subject, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.EffectiveModels) != 0 {
		t.Fatalf("effective = %v, want empty", got.EffectiveModels)
	}
}

func TestModelAccessDefaultExclusion(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, _ := s.EnsureDefaultTenant(ctx)
	createTestRole(t, s, ctx, tenant, "Engineer", true, "model-a")
	research := createTestRole(t, s, ctx, tenant, "Research", false, "model-b")
	subject := createTestSubject(t, s, ctx, tenant, PrincipalPartnerUser, uuid.NewString(), "active")
	assignTestRole(t, s, ctx, tenant, research, subject)
	excludeTestDefault(t, s, ctx, tenant, subject, nil)

	got, err := s.GetEffectiveModelAccess(ctx, tenant, subject, false)
	if err != nil {
		t.Fatal(err)
	}
	if !got.DefaultExcluded {
		t.Fatal("default should be excluded")
	}
	if !slices.Equal(got.EffectiveModels, []string{"model-b"}) {
		t.Fatalf("effective = %v, want research only", got.EffectiveModels)
	}
}

func TestModelAccessExpiredExclusionIsIgnored(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, _ := s.EnsureDefaultTenant(ctx)
	createTestRole(t, s, ctx, tenant, "Engineer", true, "model-a")
	subject := createTestSubject(t, s, ctx, tenant, PrincipalPartnerUser, uuid.NewString(), "active")
	past := time.Now().Add(-time.Minute)
	excludeTestDefault(t, s, ctx, tenant, subject, &past)

	got, err := s.GetEffectiveModelAccess(ctx, tenant, subject, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.DefaultExcluded {
		t.Fatal("expired exclusion should be ignored")
	}
	if !slices.Equal(got.EffectiveModels, []string{"model-a"}) {
		t.Fatalf("effective = %v", got.EffectiveModels)
	}
}

func TestModelAccessServiceIdentityDoesNotGetDefault(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, _ := s.EnsureDefaultTenant(ctx)
	createTestRole(t, s, ctx, tenant, "Engineer", true, "model-a")
	subject := createTestSubject(t, s, ctx, tenant, PrincipalService, "svc-build", "active")

	got, err := s.GetEffectiveModelAccess(ctx, tenant, subject, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.EffectiveModels) != 0 {
		t.Fatalf("effective = %v, want empty (service gets no default)", got.EffectiveModels)
	}
}

func TestModelAccessInactiveSubject(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, _ := s.EnsureDefaultTenant(ctx)
	subject := createTestSubject(t, s, ctx, tenant, PrincipalPartnerUser, uuid.NewString(), "inactive")

	if _, err := s.GetEffectiveModelAccess(ctx, tenant, subject, false); !errors.Is(err, ErrModelAccessSubjectInactive) {
		t.Fatalf("err = %v, want ErrModelAccessSubjectInactive", err)
	}
}

func TestModelAccessSuspendedTenant(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, _ := s.EnsureDefaultTenant(ctx)
	subject := createTestSubject(t, s, ctx, tenant, PrincipalPartnerUser, uuid.NewString(), "active")
	if _, err := s.db.ExecContext(ctx,
		`UPDATE policy_tenants SET status = 'suspended' WHERE tenant_id = $1`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetEffectiveModelAccess(ctx, tenant, subject, false); !errors.Is(err, ErrModelAccessTenantSuspended) {
		t.Fatalf("err = %v, want ErrModelAccessTenantSuspended", err)
	}
}

func TestModelAccessSuperAdminUnrestricted(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, _ := s.EnsureDefaultTenant(ctx)
	subject := createTestSubject(t, s, ctx, tenant, PrincipalPartnerUser, uuid.NewString(), "active")

	got, err := s.GetEffectiveModelAccess(ctx, tenant, subject, true)
	if err != nil {
		t.Fatal(err)
	}
	if !got.SuperAdmin || !got.Unrestricted {
		t.Fatalf("superadmin = %v unrestricted = %v", got.SuperAdmin, got.Unrestricted)
	}
}

func TestModelAccessTenantIsolation(t *testing.T) {
	s, ctx := openTestStore(t)
	tenantA, _ := s.EnsureDefaultTenant(ctx)
	tenantB := createTestTenant(t, s, ctx, "tenant-b", false)
	createTestRole(t, s, ctx, tenantA, "Engineer", true, "model-a")
	createTestRole(t, s, ctx, tenantB, "Engineer", true, "model-b")
	subjectA := createTestSubject(t, s, ctx, tenantA, PrincipalPartnerUser, uuid.NewString(), "active")
	subjectB := createTestSubject(t, s, ctx, tenantB, PrincipalPartnerUser, uuid.NewString(), "active")

	gotA, err := s.GetEffectiveModelAccess(ctx, tenantA, subjectA, false)
	if err != nil {
		t.Fatal(err)
	}
	gotB, err := s.GetEffectiveModelAccess(ctx, tenantB, subjectB, false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(gotA.EffectiveModels, []string{"model-a"}) {
		t.Fatalf("tenant A effective = %v", gotA.EffectiveModels)
	}
	if !slices.Equal(gotB.EffectiveModels, []string{"model-b"}) {
		t.Fatalf("tenant B effective = %v", gotB.EffectiveModels)
	}
}

func TestSyncPartnerUserSubjects(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, _ := s.EnsureDefaultTenant(ctx)
	createTestRole(t, s, ctx, tenant, "Engineer", true, "model-a")
	userID := uuid.NewString()
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO partner_users (user_id, tags, role, active, created_by, updated_by)
		VALUES ($1, '{"preferred_username":"alice","email":"alice@example.com","cost_center":"cc-42","cost_center_description":"Platform","organization":"AI Engineering","job_title":"Staff Engineer","employee_type":"employee","groups":["ai-eng"]}', 'user', TRUE, 'test', 'test')`,
		userID); err != nil {
		t.Fatal(err)
	}

	count, err := s.SyncPartnerUserSubjects(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("synced = %d, want 1", count)
	}
	var subjectID, displayName, status string
	if err := s.db.QueryRowContext(ctx, `
		SELECT subject_id::text, display_name, status FROM policy_subjects
		WHERE tenant_id = $1 AND principal_type = $2 AND external_id = $3`,
		tenant, PrincipalPartnerUser, userID).Scan(&subjectID, &displayName, &status); err != nil {
		t.Fatal(err)
	}
	if displayName != "alice" || status != "active" {
		t.Fatalf("subject = %q/%q", displayName, status)
	}
	got, err := s.GetEffectiveModelAccess(ctx, tenant, subjectID, false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.EffectiveModels, []string{"model-a"}) {
		t.Fatalf("effective = %v", got.EffectiveModels)
	}

	if _, err := s.db.ExecContext(ctx,
		`UPDATE partner_users SET active = FALSE WHERE user_id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SyncPartnerUserSubjects(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetEffectiveModelAccess(ctx, tenant, subjectID, false); !errors.Is(err, ErrModelAccessSubjectInactive) {
		t.Fatalf("err = %v, want inactive", err)
	}

	// Single-user sync is idempotent and returns the same subject ID.
	if _, err := s.db.ExecContext(ctx,
		`UPDATE partner_users SET active = TRUE WHERE user_id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	again, err := s.SyncPartnerUserSubject(ctx, tenant, userID)
	if err != nil {
		t.Fatal(err)
	}
	if again != subjectID {
		t.Fatalf("subject id changed: %s -> %s", subjectID, again)
	}
	subjects, err := s.ListPolicySubjects(ctx, tenant, "cc-42", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(subjects) != 1 || subjects[0].CostCenter != "cc-42" ||
		subjects[0].CostCenterDescription != "Platform" ||
		subjects[0].Organization != "AI Engineering" ||
		subjects[0].JobTitle != "Staff Engineer" ||
		subjects[0].EmployeeType != "employee" ||
		!slices.Equal(subjects[0].Groups, []string{"ai-eng"}) {
		t.Fatalf("subject tags = %#v", subjects)
	}
}

func TestBumpPolicyVersion(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, _ := s.EnsureDefaultTenant(ctx)
	v1, err := s.BumpPolicyVersion(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := s.BumpPolicyVersion(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if v2 != v1+1 {
		t.Fatalf("versions = %d, %d; want consecutive", v1, v2)
	}
}

func TestDecideModelAccess(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, _ := s.EnsureDefaultTenant(ctx)
	createTestRole(t, s, ctx, tenant, "Engineer", true, "model-a")
	subject := createTestSubject(t, s, ctx, tenant, PrincipalPartnerUser, uuid.NewString(), "active")

	allow, err := s.DecideModelAccess(ctx, tenant, subject, "model-a", "invoke", false)
	if err != nil {
		t.Fatal(err)
	}
	if allow.Decision != PolicyDecisionAllow || allow.Reason != PolicyReasonAllowed {
		t.Fatalf("allow = %#v", allow)
	}
	if !slices.Equal(allow.AllowedModels, []string{"model-a"}) {
		t.Fatalf("allowed models = %v", allow.AllowedModels)
	}
	if allow.DecisionID == "" {
		t.Fatal("decision ID is empty")
	}

	deny, err := s.DecideModelAccess(ctx, tenant, subject, "model-b", "invoke", false)
	if err != nil {
		t.Fatal(err)
	}
	if deny.Decision != PolicyDecisionDeny || deny.Reason != PolicyReasonModelNotAllowed {
		t.Fatalf("deny = %#v", deny)
	}

	var count int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM policy_decisions WHERE tenant_id = $1 AND subject_id = $2`,
		tenant, subject).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("decision rows = %d, want 2", count)
	}

	unrestricted, err := s.DecideModelAccess(ctx, tenant, subject, "anything", "invoke", true)
	if err != nil {
		t.Fatal(err)
	}
	if unrestricted.Decision != PolicyDecisionAllow || unrestricted.AllowedModels != nil {
		t.Fatalf("superadmin decision = %#v", unrestricted)
	}

	empty, err := s.DecideModelAccess(ctx, tenant, subject, "", "invoke", false)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Decision != PolicyDecisionDeny {
		t.Fatalf("empty model decision = %#v", empty)
	}
}

func TestModelAccessAdminCRUD(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, _ := s.EnsureDefaultTenant(ctx)
	subject := createTestSubject(t, s, ctx, tenant, PrincipalPartnerUser, uuid.NewString(), "active")

	role, err := s.CreateModelAccessRole(ctx, tenant, "admin", "Engineer", "baseline", []string{"model-b", "model-a"}, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !role.IsDefault || !slices.Equal(role.Models, []string{"model-a", "model-b"}) {
		t.Fatalf("role = %#v", role)
	}
	roles, err := s.ListModelAccessRoles(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 1 || roles[0].RoleID != role.RoleID {
		t.Fatalf("roles = %#v", roles)
	}

	if err := s.SetModelAccessRoleModels(ctx, tenant, role.RoleID, "admin", []string{"model-c"}); err != nil {
		t.Fatal(err)
	}
	effective, err := s.GetEffectiveModelAccess(ctx, tenant, subject, false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(effective.EffectiveModels, []string{"model-c"}) {
		t.Fatalf("effective = %v", effective.EffectiveModels)
	}
	if effective.DefaultRoleName != "Engineer" {
		t.Fatalf("default role name = %q", effective.DefaultRoleName)
	}

	research, err := s.CreateModelAccessRole(ctx, tenant, "admin", "Research", "", []string{"model-d"}, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AssignModelAccessRole(ctx, tenant, research.RoleID, subject, "admin"); err != nil {
		t.Fatal(err)
	}
	effective, err = s.GetEffectiveModelAccess(ctx, tenant, subject, false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(effective.EffectiveModels, []string{"model-c", "model-d"}) {
		t.Fatalf("effective with role = %v", effective.EffectiveModels)
	}
	if err := s.RemoveModelAccessRoleSubject(ctx, tenant, research.RoleID, subject, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.RetireModelAccessRole(ctx, tenant, research.RoleID, "admin"); err != nil {
		t.Fatal(err)
	}
	roles, err = s.ListModelAccessRoles(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range roles {
		if r.RoleID == research.RoleID {
			t.Fatal("retired role still listed")
		}
	}

	if err := s.SetSubjectGrants(ctx, tenant, subject, "admin", []string{"model-e"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSubjectRestriction(ctx, tenant, subject, "admin", true, []string{"model-c", "model-e"}); err != nil {
		t.Fatal(err)
	}
	effective, err = s.GetEffectiveModelAccess(ctx, tenant, subject, false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(effective.EffectiveModels, []string{"model-c", "model-e"}) {
		t.Fatalf("effective with restriction = %v", effective.EffectiveModels)
	}

	if err := s.ExcludeSubjectFromDefault(ctx, tenant, subject, "admin", "contractor", nil); err != nil {
		t.Fatal(err)
	}
	effective, err = s.GetEffectiveModelAccess(ctx, tenant, subject, false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(effective.EffectiveModels, []string{"model-e"}) {
		t.Fatalf("effective with exclusion = %v", effective.EffectiveModels)
	}

	svc, err := s.EnsureServiceIdentity(ctx, tenant, "svc-build", "Build service")
	if err != nil {
		t.Fatal(err)
	}
	subjects, err := s.ListPolicySubjects(ctx, tenant, "build", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(subjects) != 1 || subjects[0].SubjectID != svc {
		t.Fatalf("subjects = %#v", subjects)
	}
}

func TestDefaultRoleSubjectCount(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, _ := s.EnsureDefaultTenant(ctx)
	role, err := s.CreateModelAccessRole(ctx, tenant, "admin", "Engineer", "", []string{"model-a"}, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	alice := createTestSubject(t, s, ctx, tenant, PrincipalPartnerUser, uuid.NewString(), "active")
	createTestSubject(t, s, ctx, tenant, PrincipalPartnerUser, uuid.NewString(), "active")
	createTestSubject(t, s, ctx, tenant, PrincipalPartnerUser, uuid.NewString(), "inactive")
	excludeTestDefault(t, s, ctx, tenant, alice, nil)

	roles, err := s.ListModelAccessRoles(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	var got ModelAccessRole
	for _, r := range roles {
		if r.RoleID == role.RoleID {
			got = r
		}
	}
	if got.SubjectCount != 1 {
		t.Fatalf("default role people = %d, want 1 active non-excluded partner user", got.SubjectCount)
	}
}

func TestAssignModelAccessRoleSubjects(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, _ := s.EnsureDefaultTenant(ctx)
	role, err := s.CreateModelAccessRole(ctx, tenant, "admin", "Research", "", []string{"model-a"}, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{
		createTestSubject(t, s, ctx, tenant, PrincipalPartnerUser, uuid.NewString(), "active"),
		createTestSubject(t, s, ctx, tenant, PrincipalPartnerUser, uuid.NewString(), "active"),
		createTestSubject(t, s, ctx, tenant, PrincipalPartnerUser, uuid.NewString(), "active"),
	}
	assigned, err := s.AssignModelAccessRoleSubjects(ctx, tenant, role.RoleID, append(ids, ids[0]), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if assigned != 3 {
		t.Fatalf("assigned = %d, want 3", assigned)
	}
	assigned, err = s.AssignModelAccessRoleSubjects(ctx, tenant, role.RoleID, ids, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if assigned != 0 {
		t.Fatalf("repeat assigned = %d, want 0", assigned)
	}
	subjects, err := s.ListModelAccessRoleSubjects(ctx, tenant, role.RoleID)
	if err != nil {
		t.Fatal(err)
	}
	if len(subjects) != 3 {
		t.Fatalf("role subjects = %d, want 3", len(subjects))
	}
}

func TestAssignModelAccessRoleByFilter(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, _ := s.EnsureDefaultTenant(ctx)
	role, err := s.CreateModelAccessRole(ctx, tenant, "admin", "Cost center role", "", []string{"model-a"}, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []struct{ id, cc string }{
		{uuid.NewString(), "CC-1"},
		{uuid.NewString(), "CC-1"},
		{uuid.NewString(), "CC-2"},
	} {
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO partner_users (user_id, tags, role, active, created_by, updated_by)
			VALUES ($1, jsonb_build_object('email', $2::text, 'cost_center', $3::text), 'user', TRUE, 'test', 'test')`,
			u.id, u.id+"@example.com", u.cc); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.SyncPartnerUserSubjects(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	count, err := s.CountPolicySubjectsByFilter(ctx, tenant, "cost_center", "CC-1")
	if err != nil || count != 2 {
		t.Fatalf("count = %d, err %v", count, err)
	}
	assigned, err := s.AssignModelAccessRoleByFilter(ctx, tenant, role.RoleID, "cost_center", "CC-1", "admin")
	if err != nil || assigned != 2 {
		t.Fatalf("assigned = %d, err %v", assigned, err)
	}
	assigned, err = s.AssignModelAccessRoleByFilter(ctx, tenant, role.RoleID, "cost_center", "CC-1", "admin")
	if err != nil || assigned != 0 {
		t.Fatalf("repeat assigned = %d, err %v", assigned, err)
	}
	subjects, err := s.ListModelAccessRoleSubjects(ctx, tenant, role.RoleID)
	if err != nil || len(subjects) != 2 {
		t.Fatalf("role subjects = %d, err %v", len(subjects), err)
	}
}

func TestResolvePolicySubjectByUsername(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, _ := s.EnsureDefaultTenant(ctx)
	userID := uuid.NewString()
	if _, err := s.CreatePartnerUser(ctx, "partner-m2m", userID, map[string]any{
		"email": "resolve@example.com", "first_name": "Resolve", "last_name": "User",
	}); err != nil {
		t.Fatal(err)
	}
	subjectID, principal, err := s.ResolvePolicySubjectByUsername(ctx, tenant, "resolve@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if principal != PrincipalPartnerUser || subjectID == "" {
		t.Fatalf("resolved = %q/%q", subjectID, principal)
	}
	again, _, err := s.ResolvePolicySubjectByUsername(ctx, tenant, "resolve@example.com")
	if err != nil || again != subjectID {
		t.Fatalf("second resolve = %q, err %v; want %q", again, err, subjectID)
	}
}

func TestMonthlyUsageWithModelAllowedOverride(t *testing.T) {
	s, ctx := openTestStore(t)
	userID := uuid.NewString()
	if _, err := s.CreatePartnerUser(ctx, "partner-m2m", userID, map[string]any{
		"email": "usage@example.com", "first_name": "Usage", "last_name": "User",
	}); err != nil {
		t.Fatal(err)
	}
	allowed, err := s.GetMonthlyUsageWithModelAllowed(ctx, "usage@example.com", "model-x", false, true)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed.ModelAllowed || !allowed.HasAccess {
		t.Fatalf("allowed = %#v", allowed)
	}
	denied, err := s.GetMonthlyUsageWithModelAllowed(ctx, "usage@example.com", "model-x", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if denied.ModelAllowed || denied.HasAccess {
		t.Fatalf("denied = %#v", denied)
	}
}

func TestRoleBudgetAndCredits(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, _ := s.EnsureDefaultTenant(ctx)
	if _, err := s.CreateModelAccessRole(ctx, tenant, "admin", "Engineer", "", nil, true, 300); err != nil {
		t.Fatal(err)
	}
	super, err := s.CreateModelAccessRole(ctx, tenant, "admin", "Super users", "", nil, false, 200)
	if err != nil {
		t.Fatal(err)
	}
	username := "budget@example.com"
	userID := uuid.NewString()
	if _, err := s.CreatePartnerUser(ctx, "test", userID, map[string]any{
		"email": username, "first_name": "Budget", "last_name": "User",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SyncPartnerUserSubjects(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	subjectID, _, err := s.ResolvePolicySubjectByUsername(ctx, tenant, username)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AssignModelAccessRole(ctx, tenant, super.RoleID, subjectID, "admin"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetRoleBudgetUSD(ctx, tenant, subjectID); err != nil || got != 500 {
		t.Fatalf("role budget = %v, err %v; want 500", got, err)
	}
	defaultRole, err := s.GetDefaultModelAccessRole(ctx, tenant)
	if err != nil || defaultRole.MonthlyUSD != 300 {
		t.Fatalf("default role budget = %#v, err %v", defaultRole, err)
	}

	future := time.Now().Add(24 * time.Hour)
	past := time.Now().Add(-time.Hour)
	if _, err := s.AddQuotaCredit(ctx, tenant, subjectID, 50, &future, "launch", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddQuotaCredit(ctx, tenant, subjectID, 100, &past, "expired", "admin"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetActiveCreditUSD(ctx, tenant, subjectID); err != nil || got != 50 {
		t.Fatalf("credits = %v, err %v; want 50", got, err)
	}
	decision, _, err := s.QuotaDecisionCached(ctx, username, false)
	if err != nil {
		t.Fatal(err)
	}
	if decision.BaseUSD != 500 || decision.LimitUSD != 550 || decision.BudgetSource != "role" {
		t.Fatalf("quota decision = %#v", decision)
	}
	if err := s.SetModelAccessRoleBudget(ctx, tenant, super.RoleID, "admin", 250); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetRoleBudgetUSD(ctx, tenant, subjectID); err != nil || got != 550 {
		t.Fatalf("role budget after update = %v, err %v; want 550", got, err)
	}

	// Excluding the subject from the default drops its $300 contribution.
	if err := s.ExcludeSubjectFromDefault(ctx, tenant, subjectID, "admin", "test", nil); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetRoleBudgetUSD(ctx, tenant, subjectID); err != nil || got != 250 {
		t.Fatalf("excluded role budget = %v, err %v; want 250", got, err)
	}
}

func TestModelAccessDefaultRoleChange(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, _ := s.EnsureDefaultTenant(ctx)
	role := createTestRole(t, s, ctx, tenant, "Engineer", true, "model-a")
	subject := createTestSubject(t, s, ctx, tenant, PrincipalPartnerUser, uuid.NewString(), "active")

	got, err := s.GetEffectiveModelAccess(ctx, tenant, subject, false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.EffectiveModels, []string{"model-a"}) {
		t.Fatalf("before = %v", got.EffectiveModels)
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO model_access_role_models (tenant_id, role_id, model_id, added_by)
		VALUES ($1, $2, 'model-b', 'test')`, tenant, role); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetEffectiveModelAccess(ctx, tenant, subject, false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.EffectiveModels, []string{"model-a", "model-b"}) {
		t.Fatalf("after = %v", got.EffectiveModels)
	}
}
