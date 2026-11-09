package storage

import (
	"errors"
	"testing"
	"time"
)

func TestPartnerUserDirectoryPolicyAndHistoricalUsage(t *testing.T) {
	s, ctx := openTestStore(t)
	const id = "123e4567-e89b-12d3-a456-426614174000"
	user, err := s.CreatePartnerUser(ctx, "partner-m2m", id, map[string]any{
		"email": "alice@example.com", "first_name": "Alice", "last_name": "Example", "manager_uuid": nil,
	})
	if err != nil {
		t.Fatalf("CreatePartnerUser: %v", err)
	}
	if !user.Active || user.UserID != id {
		t.Fatalf("created user = %#v", user)
	}

	_, err = s.UpdatePartnerUser(ctx, "partner-m2m", id, map[string]any{
		"email": "alice.new@example.com", "first_name": "Alice", "last_name": "Example", "manager_uuid": nil,
		"department": "engineering",
	})
	if err != nil {
		t.Fatalf("UpdatePartnerUser: %v", err)
	}
	page, err := s.ListPartnerUsers(ctx, map[string]string{"department": "engineering"}, false, 10, 0)
	if err != nil || len(page.Users) != 1 || page.Users[0].UserID != id {
		t.Fatalf("ListPartnerUsers by tag = %#v, err %v", page, err)
	}
	logins, err := s.ListPartnerUsernames(ctx, id)
	if err != nil || len(logins) != 2 {
		t.Fatalf("ListPartnerUsernames = %v, err %v", logins, err)
	}

	policy, err := s.SetPartnerUserModelAllowlist(ctx, "partner-m2m", id, []string{"model-a"})
	if err != nil || !policy.Enabled || len(policy.Models) != 1 || policy.Models[0] != "model-a" {
		t.Fatalf("SetPartnerUserModelAllowlist = %#v, err %v", policy, err)
	}
	for _, username := range []string{"alice@example.com", "alice.new@example.com"} {
		resolved, err := s.GetUserModelAllowlist(ctx, username)
		if err != nil || !resolved.Enabled || len(resolved.Models) != 1 || resolved.Models[0] != "model-a" {
			t.Fatalf("resolved policy for %s = %#v, err %v", username, resolved, err)
		}
	}
	// Entitlement must follow the same retained alias so an older MaaS key
	// cannot fall back to the global budget or lose the user's role access.
	tenant, err := s.EnsureDefaultTenant(ctx)
	if err != nil {
		t.Fatalf("EnsureDefaultTenant: %v", err)
	}
	var subjectID string
	for _, username := range []string{"alice@example.com", "alice.new@example.com"} {
		got, principal, err := s.ResolvePolicySubjectByUsername(ctx, tenant, username)
		if err != nil || principal != PrincipalPartnerUser {
			t.Fatalf("policy subject for %s = %q (%s), err %v", username, got, principal, err)
		}
		if subjectID == "" {
			subjectID = got
		} else if got != subjectID {
			t.Fatalf("alias %s resolved to subject %s; want %s", username, got, subjectID)
		}
	}
	if _, err := s.PartnerUserByMaaSUsername(ctx, "alice@example.com"); !errors.Is(err, ErrPartnerUserNotFound) {
		t.Fatalf("authentication lookup must reject retained login: %v", err)
	}
	if _, err := s.PartnerUserByMaaSUsername(ctx, "alice.new@example.com"); err != nil {
		t.Fatalf("authentication lookup must accept current active login: %v", err)
	}

	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(24 * time.Hour)
	for _, event := range []struct {
		id, username              string
		prompt, completion, total int
	}{
		{id: "partner-old-email", username: "alice@example.com", prompt: 4, completion: 3, total: 7},
		{id: "partner-new-email", username: "alice.new@example.com", prompt: 5, completion: 3, total: 8},
	} {
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO usage_events (event_id,timestamp,username,model,prompt_tokens,completion_tokens,total_tokens)
			VALUES ($1,$2,$3,'model-a',$4,$5,$6)`, event.id, from.Add(time.Hour), event.username, event.prompt, event.completion, event.total); err != nil {
			t.Fatalf("insert usage event %s: %v", event.id, err)
		}
	}
	missingID := "123e4567-e89b-12d3-a456-426614174001"
	report, err := s.GetPartnerUsersUsageReport(ctx, []string{id, missingID}, from, to)
	if err != nil {
		t.Fatalf("GetPartnerUsersUsageReport: %v", err)
	}
	if len(report.Users) != 1 || len(report.MissingUserIDs) != 1 || report.MissingUserIDs[0] != missingID || report.Users[0].Totals.Requests != 2 || report.Users[0].Totals.TotalTokens != 15 || report.Users[0].Tags["email"] != "alice.new@example.com" {
		t.Fatalf("historical usage report = %#v", report)
	}

	if err := s.RecordPartnerUserKey(ctx, "partner-m2m", id, "key-old", "alice@example.com", "old"); err != nil {
		t.Fatalf("RecordPartnerUserKey: %v", err)
	}
	if err := s.RecordPartnerUserKey(ctx, "partner-m2m", id, "key-new", "alice.new@example.com", "new"); err != nil {
		t.Fatalf("RecordPartnerUserKey: %v", err)
	}
	if err := s.MarkPartnerUserKeyRevoked(ctx, "partner-m2m", id, "key-old"); err != nil {
		t.Fatalf("MarkPartnerUserKeyRevoked: %v", err)
	}
	deletion, err := s.BeginPartnerUserDeactivation(ctx, "partner-m2m", id)
	if err != nil || len(deletion.Keys) != 1 || deletion.Keys[0].KeyID != "key-new" || deletion.Keys[0].Username != "alice.new@example.com" {
		t.Fatalf("BeginPartnerUserDeactivation must list only unrevoked partner keys: %#v, err %v", deletion, err)
	}
	if err := s.RecordPartnerUserKey(ctx, "partner-m2m", id, "key-late", "alice.new@example.com", "late"); !errors.Is(err, ErrPartnerUserInactive) {
		t.Fatalf("recording a key for a deactivated user = %v, want inactive", err)
	}
	// Deactivation must deny both the current login and every historical login
	// mapped to the person. Resolving only the active current login would make
	// the inactive user look unknown and fall through to the legacy allowlist,
	// which is empty and therefore allows every model.
	for _, login := range []string{"alice@example.com", "alice.new@example.com"} {
		blocked, err := s.GetUserModelAllowlist(ctx, login)
		if err != nil || !blocked.Enabled || len(blocked.Models) != 0 {
			t.Fatalf("inactive partner policy for %s must fail closed: %#v, err %v", login, blocked, err)
		}
		stats, err := s.GetMonthlyUsage(ctx, login, "model-a", false)
		if err != nil || stats.HasAccess || stats.ModelAllowed {
			t.Fatalf("deactivated login %s must be denied: %#v, err %v", login, stats, err)
		}
	}
	for _, username := range []string{"alice@example.com", "alice.new@example.com"} {
		if _, err := s.PartnerUserByMaaSUsername(ctx, username); !errors.Is(err, ErrPartnerUserNotFound) {
			t.Fatalf("authentication lookup must reject inactive login %s: %v", username, err)
		}
		policy, err := s.GetUserModelAllowlist(ctx, username)
		if err != nil || !policy.Enabled || len(policy.Models) != 0 {
			t.Fatalf("inactive login %s must retain deny-all policy: %#v, %v", username, policy, err)
		}
	}
	blocked, err := s.GetUserModelAllowlist(ctx, "alice@example.com")
	if err != nil || !blocked.Enabled || len(blocked.Models) != 0 {
		t.Fatalf("inactive partner policy must fail closed: %#v, err %v", blocked, err)
	}
	if _, err := s.ReactivatePartnerUser(ctx, "partner-m2m", id); !errors.Is(err, ErrPartnerUserRevocationPending) {
		t.Fatalf("reactivation before MaaS revocation completion = %v, want pending error", err)
	}
	if err := s.CompletePartnerUserKeyRevocation(ctx, "partner-m2m", id); err != nil {
		t.Fatalf("CompletePartnerUserKeyRevocation: %v", err)
	}
	reactivated, err := s.ReactivatePartnerUser(ctx, "partner-m2m", id)
	if err != nil || !reactivated.Active {
		t.Fatalf("ReactivatePartnerUser = %#v, err %v", reactivated, err)
	}
}

func TestPatchPartnerUserMergesTagsAndUpdatesEmail(t *testing.T) {
	s, ctx := openTestStore(t)
	const id = "123e4567-e89b-12d3-a456-426614174010"
	_, err := s.CreatePartnerUser(ctx, "partner-m2m", id, map[string]any{
		"email": "patch.old@example.com", "first_name": "Patch", "last_name": "User",
		"manager_uuid": nil, "department": "engineering", "country": "US",
	})
	if err != nil {
		t.Fatalf("CreatePartnerUser: %v", err)
	}

	patched, err := s.PatchPartnerUser(ctx, "partner-m2m:atlas", id, map[string]any{
		"first_name": "Patched", "department": "platform",
	})
	if err != nil {
		t.Fatalf("PatchPartnerUser partial update: %v", err)
	}
	if patched.Tags["first_name"] != "Patched" || patched.Tags["department"] != "platform" ||
		patched.Tags["email"] != "patch.old@example.com" || patched.Tags["last_name"] != "User" || patched.Tags["country"] != "US" {
		t.Fatalf("patch did not merge/preserve tags: %#v", patched.Tags)
	}

	patched, err = s.PatchPartnerUser(ctx, "partner-m2m:atlas", id, map[string]any{"email": "patch.new@example.com"})
	if err != nil || patched.Tags["email"] != "patch.new@example.com" {
		t.Fatalf("PatchPartnerUser email update = %#v, err %v", patched, err)
	}
	logins, err := s.ListPartnerUsernames(ctx, id)
	if err != nil || len(logins) != 2 {
		t.Fatalf("email patch must retain login history: %v, err %v", logins, err)
	}
	current, err := s.CurrentPartnerUserLogin(ctx, id)
	if err != nil || current != "patch.new@example.com" {
		t.Fatalf("CurrentPartnerUserLogin = %q, err %v; want the new current login", current, err)
	}

	if _, err := s.PatchPartnerUser(ctx, "partner-m2m:atlas", id, map[string]any{}); !errors.Is(err, ErrInvalidPartnerUser) {
		t.Fatalf("empty patch error = %v, want ErrInvalidPartnerUser", err)
	}
	if _, err := s.PatchPartnerUser(ctx, "partner-m2m:atlas", "123e4567-e89b-12d3-a456-426614174011", map[string]any{"first_name": "Missing"}); !errors.Is(err, ErrPartnerUserNotFound) {
		t.Fatalf("missing user patch error = %v, want ErrPartnerUserNotFound", err)
	}
}

func TestCreatePartnerUserReconcilesReportsWhenManagerArrivesLater(t *testing.T) {
	s, ctx := openTestStore(t)
	const (
		managerID = "123e4567-e89b-12d3-a456-426614174030"
		reportID  = "123e4567-e89b-12d3-a456-426614174031"
	)

	report, err := s.CreatePartnerUser(ctx, "partner-m2m", reportID, map[string]any{
		"email": "report@example.com", "first_name": "Report", "last_name": "User",
		"manager_uuid": managerID,
	})
	if err != nil {
		t.Fatalf("create report: %v", err)
	}
	if report.ManagerUserID != nil {
		t.Fatalf("report unexpectedly resolved manager before manager existed: %v", *report.ManagerUserID)
	}

	if _, err := s.CreatePartnerUser(ctx, "partner-m2m", managerID, map[string]any{
		"email": "manager@example.com", "first_name": "Manager", "last_name": "User",
		"manager_uuid": nil,
	}); err != nil {
		t.Fatalf("create manager: %v", err)
	}

	repaired, err := s.GetPartnerUser(ctx, reportID)
	if err != nil {
		t.Fatalf("get repaired report: %v", err)
	}
	if repaired.ManagerUserID == nil || *repaired.ManagerUserID != managerID {
		t.Fatalf("report manager_user_id = %v, want %s", repaired.ManagerUserID, managerID)
	}
}

// TestPatchPartnerUserClaimsRowWithoutLogin pins the manager-placeholder
// claim path: LDAP creates the directory row before the manager ever signs in,
// so there is no partner_user_logins row. The first verified profile patch
// (the OIDC callback) must create the login from the merged email instead of
// failing with sql.ErrNoRows.
func TestPatchPartnerUserClaimsRowWithoutLogin(t *testing.T) {
	s, ctx := openTestStore(t)
	const id = "123e4567-e89b-12d3-a456-426614174050"

	// Simulate the placeholder: names only, no email tag and no login row.
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO partner_users (user_id,tags,role,active,created_by,updated_by)
		VALUES ($1,'{"first_name":"Boss","last_name":"Person"}','user',TRUE,'ldap-sync','ldap-sync')`, id); err != nil {
		t.Fatalf("insert manager placeholder: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM partner_user_logins WHERE user_id=$1`, id); err != nil {
		t.Fatalf("clear placeholder logins: %v", err)
	}

	patched, err := s.PatchPartnerUser(ctx, "oidc", id, map[string]any{"email": "boss@example.com"})
	if err != nil {
		t.Fatalf("PatchPartnerUser claim = %#v, err %v", patched, err)
	}
	if patched.Tags["email"] != "boss@example.com" || patched.Tags["first_name"] != "Boss" || patched.Tags["last_name"] != "Person" {
		t.Fatalf("claim did not merge tags: %#v", patched.Tags)
	}
	current, err := s.CurrentPartnerUserLogin(ctx, id)
	if err != nil || current != "boss@example.com" {
		t.Fatalf("CurrentPartnerUserLogin = %q, err %v; want the merged email", current, err)
	}
	logins, err := s.ListPartnerUsernames(ctx, id)
	if err != nil || len(logins) != 1 {
		t.Fatalf("login history = %v, err %v; want exactly the claimed login", logins, err)
	}
}
