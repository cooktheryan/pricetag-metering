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

	if _, err := s.PatchPartnerUser(ctx, "partner-m2m:atlas", id, map[string]any{}); !errors.Is(err, ErrInvalidPartnerUser) {
		t.Fatalf("empty patch error = %v, want ErrInvalidPartnerUser", err)
	}
	if _, err := s.PatchPartnerUser(ctx, "partner-m2m:atlas", "123e4567-e89b-12d3-a456-426614174011", map[string]any{"first_name": "Missing"}); !errors.Is(err, ErrPartnerUserNotFound) {
		t.Fatalf("missing user patch error = %v, want ErrPartnerUserNotFound", err)
	}
}
