package storage

import (
	"fmt"
	"testing"
	"time"
)

func TestManagementLoginPreservesIdentity(t *testing.T) {
	s, ctx := openTestStore(t)
	first, err := s.ProvisionLogin(ctx, "test-admin", LoginProvision{Subject: "alice", Name: "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.ProvisionLogin(ctx, "test-admin", LoginProvision{Subject: "alice", Name: "Alice Updated"})
	if err != nil {
		t.Fatal(err)
	}
	if first.UserID != second.UserID {
		t.Fatal("repeat setup changed identity")
	}
	if _, err = s.ProvisionLogin(ctx, "test-admin", LoginProvision{Subject: "bad\nsubject"}); err == nil {
		t.Fatal("invalid login accepted")
	}
	if _, err = s.ProvisionLogin(ctx, "test-admin", LoginProvision{Subject: "alice", Role: "unexpected"}); err == nil {
		t.Fatal("invalid role accepted")
	}
}

func TestManagementPendingRevocationRejectsActivationAtomically(t *testing.T) {
	s, ctx := openTestStore(t)
	user, err := s.ProvisionLogin(ctx, "test-admin", LoginProvision{Subject: "pending-user", Name: "Original"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE partner_users SET active=false,key_revocation_pending=true WHERE user_id=$1`, user.UserID); err != nil {
		t.Fatal(err)
	}
	active := true
	if _, err := s.ProvisionLogin(ctx, "test-admin", LoginProvision{Subject: "pending-user", Name: "Changed", Active: &active}); err == nil {
		t.Fatal("pending revocation reported successful activation")
	}
	var actualActive bool
	var name string
	if err := s.db.QueryRowContext(ctx, `SELECT active,tags->>'first_name' FROM partner_users WHERE user_id=$1`, user.UserID).Scan(&actualActive, &name); err != nil {
		t.Fatal(err)
	}
	if actualActive || name != "Original" {
		t.Fatal("failed activation partially changed the profile")
	}
}

func TestManagedPricesPreserveRecordedCharges(t *testing.T) {
	s, ctx := openTestStore(t)
	one, zero, ten := 1.0, 0.0, 10.0
	p := ManagedPrice{Model: "management-fixture", Provider: "mock", Input: &one, Output: &zero, CacheWrite: &zero, CacheRead: &zero}
	if err := s.SetManagedPrice(ctx, "test", p); err != nil {
		t.Fatal(err)
	}
	event := UsageEvent{EventID: "frozen-before", Timestamp: time.Now(), Username: "alice", Model: p.Model, PromptTokens: 1000000, TotalTokens: 1000000}
	if err := s.InsertEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	p.Input = &ten
	if err := s.SetManagedPrice(ctx, "test", p); err != nil {
		t.Fatal(err)
	}
	var charge float64
	if err := s.db.QueryRowContext(ctx, fmt.Sprintf(`SELECT %s FROM usage_events e LEFT JOIN model_pricing p ON p.model=e.model WHERE e.event_id=$1`, costUSDExpr), event.EventID).Scan(&charge); err != nil {
		t.Fatal(err)
	}
	if charge != 1 {
		t.Fatalf("old charge changed to %v", charge)
	}
	event.EventID = "frozen-after"
	if err := s.InsertEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT cost_usd FROM usage_events WHERE event_id=$1`, event.EventID).Scan(&charge); err != nil {
		t.Fatal(err)
	}
	if charge != 10 {
		t.Fatalf("new charge=%v", charge)
	}
}

func TestUserBudgetOverridePages(t *testing.T) {
	s, ctx := openTestStore(t)
	for _, name := range []string{"page-alice", "page-bob", "other-user"} {
		if err := s.UpsertQuotaOverride(ctx, "test", "user", name, 7); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UpsertQuotaOverride(ctx, "test", "group", "page-group", 8); err != nil {
		t.Fatal(err)
	}
	rows, more, err := s.UserBudgetOverridesPage(ctx, "page-", "", 1, 0)
	if err != nil || len(rows) != 1 || rows[0].Principal != "page-alice" || !more {
		t.Fatalf("first page: %v %v %v", rows, more, err)
	}
	rows, more, err = s.UserBudgetOverridesPage(ctx, "page-", "", 1, 1)
	if err != nil || len(rows) != 1 || rows[0].Principal != "page-bob" || more {
		t.Fatalf("next page: %v %v %v", rows, more, err)
	}
	rows, _, err = s.UserBudgetOverridesPage(ctx, "", "page-alice", 20, 0)
	if err != nil || len(rows) != 1 || rows[0].MonthlyUSD != 7 {
		t.Fatal("exact subject lookup failed")
	}
	rows, _, err = s.UserBudgetOverridesPage(ctx, "%", "", 20, 0)
	if err != nil || len(rows) != 0 {
		t.Fatal("literal search treated as wildcard")
	}
	if _, _, err = s.UserBudgetOverridesPage(ctx, "", "", 1001, 0); err == nil {
		t.Fatal("unbounded page accepted")
	}
}

func TestManagerBudgetUsesCalendarMonthAndOverride(t *testing.T) {
	s, ctx := openTestStore(t)
	user, err := s.ProvisionLogin(ctx, "test", LoginProvision{Subject: "budget-member", Name: "Member"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertQuotaOverride(ctx, "test", "user", "budget-member", 5); err != nil {
		t.Fatal(err)
	}
	one, zero := 1.0, 0.0
	if err := s.SetManagedPrice(ctx, "test", ManagedPrice{Model: "manager-budget", Provider: "mock", Input: &one, Output: &zero, CacheWrite: &zero, CacheRead: &zero}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertEvent(ctx, UsageEvent{EventID: "manager-budget-event", Timestamp: time.Now(), Username: "budget-member", Model: "manager-budget", PromptTokens: 1000000, TotalTokens: 1000000}); err != nil {
		t.Fatal(err)
	}
	// A historical chart window must not change the current monthly budget gauge.
	rows, err := s.GetPartnerOrgUsage(ctx, user.UserID, time.Now().AddDate(0, -2, 0), time.Now().AddDate(0, -1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].QuotaUSD != 5 || rows[0].QuotaSpentUSD != 1 || rows[0].Requests != 0 || rows[0].OverLimit {
		t.Fatalf("incorrect budget summary: %+v", rows)
	}
	if err := s.DeleteQuotaOverride(ctx, "test", "user", "budget-member"); err != nil {
		t.Fatal(err)
	}
	policy, err := s.GetQuotaPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rows, err = s.GetPartnerOrgUsage(ctx, user.UserID, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].QuotaUSD != policy.DefaultMonthlyUSD || rows[0].QuotaSpentUSD != 1 {
		t.Fatal("removing override reset spend or failed inheritance")
	}
}

func TestManagedPriceSurvivesImportedPriceRefresh(t *testing.T) {
	s, ctx := openTestStore(t)
	one, two := 1.0, 2.0
	p := ManagedPrice{Model: "custom-retained", Provider: "mock", Input: &one, Output: &two, CacheWrite: &one, CacheRead: &one}
	if err := s.SetManagedPrice(ctx, "test", p); err != nil {
		t.Fatal(err)
	}
	count, err := s.SeedPricing(ctx, []ModelPrice{{Model: p.Model, Provider: "import", InputCost: 9, OutputCost: 9}, {Model: "imported", Provider: "import", InputCost: 3}})
	if err != nil || count != 1 {
		t.Fatalf("refresh count=%d error=%v", count, err)
	}
	prices, err := s.GetCurrentPricing(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, price := range prices {
		if price.Model == p.Model && (price.InputCost != 1 || price.OutputCost != 2 || !price.Managed) {
			t.Fatal("refresh overwrote managed rates")
		}
	}
}
