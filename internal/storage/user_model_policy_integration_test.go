package storage

import (
	"fmt"
	"testing"
)

func TestUserModelAllowlistEnforcesAndFollowsLinkedLogins(t *testing.T) {
	s, ctx := openTestStore(t)
	seedQuotaRoster(t, s, ctx)
	quotaExec(t, s, ctx, `INSERT INTO person_identities (username, person_slug) VALUES ('alice_alt', 'alice')`)

	policy, err := s.SetUserModelAllowlist(ctx, "partner-m2m", "alice", []string{"model-a", "model-b", "model-a"})
	if err != nil {
		t.Fatalf("SetUserModelAllowlist: %v", err)
	}
	if !policy.Enabled || len(policy.Models) != 2 || policy.Models[0] != "model-a" || policy.Models[1] != "model-b" {
		t.Fatalf("stored policy = %#v", policy)
	}
	if decision, err := s.GetMonthlyUsage(ctx, "alice_alt", "model-a", false); err != nil || !decision.ModelAllowed || !decision.HasAccess {
		t.Fatalf("allowed alias model decision = %#v, err %v", decision, err)
	}
	if decision, err := s.GetMonthlyUsage(ctx, "alice_alt", "model-c", false); err != nil || decision.ModelAllowed || decision.HasAccess {
		t.Fatalf("disallowed alias model decision = %#v, err %v", decision, err)
	}

	// Empty is an explicit deny-all allowlist, not the same as no policy.
	policy, err = s.SetUserModelAllowlist(ctx, "partner-m2m", "alice", []string{})
	if err != nil {
		t.Fatalf("set empty allowlist: %v", err)
	}
	if !policy.Enabled || len(policy.Models) != 0 {
		t.Fatalf("empty allowlist should remain enabled: %#v", policy)
	}
	if decision, err := s.GetMonthlyUsage(ctx, "alice", "model-a", false); err != nil || decision.ModelAllowed || decision.HasAccess {
		t.Fatalf("empty allowlist decision = %#v, err %v", decision, err)
	}

	if err := s.DeleteUserModelAllowlist(ctx, "partner-m2m", "alice"); err != nil {
		t.Fatalf("DeleteUserModelAllowlist: %v", err)
	}
	policy, err = s.GetUserModelAllowlist(ctx, "alice_alt")
	if err != nil || policy.Enabled {
		t.Fatalf("cleared alias policy = %#v, err %v", policy, err)
	}
	if decision, err := s.GetMonthlyUsage(ctx, "alice", "model-c", false); err != nil || !decision.ModelAllowed || !decision.HasAccess {
		t.Fatalf("baseline access after clearing policy = %#v, err %v", decision, err)
	}
}

func TestNormalizeUserModelAllowlistRejectsWildcardsAndBoundsList(t *testing.T) {
	if _, err := normalizeUserModelAllowlist([]string{"model-*"}); err == nil {
		t.Fatal("expected wildcard model ID to be rejected")
	}
	tooMany := make([]string, userModelAllowlistMax+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("model-%d", i)
	}
	if _, err := normalizeUserModelAllowlist(tooMany); err == nil {
		t.Fatal("expected oversized allowlist to be rejected")
	}
}
