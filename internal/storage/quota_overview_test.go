package storage

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestListUsersOverLimit(t *testing.T) {
	s, ctx := openTestStore(t)
	s.SetMonthSpendEnabled(true)
	tenant, err := s.EnsureDefaultTenant(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO quota_policy (id, default_monthly_usd, enforced, allowed_over_limit_models)
		VALUES (true, 999, true, '{}')
		ON CONFLICT (id) DO UPDATE SET default_monthly_usd=999, enforced=true, allowed_over_limit_models='{}'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateModelAccessRole(ctx, tenant, "admin", "Default", "", nil, true, 300); err != nil {
		t.Fatal(err)
	}
	big, err := s.CreateModelAccessRole(ctx, tenant, "admin", "Big", "", nil, false, 200)
	if err != nil {
		t.Fatal(err)
	}

	type person struct {
		email      string
		costCenter string
		spend      float64
		bigRole    bool
		override   float64
		credit     float64
	}
	people := []person{
		{email: "alice@example.com", costCenter: "CC-A", spend: 350},
		{email: "bob@example.com", costCenter: "CC-B", spend: 450, bigRole: true},
		{email: "carol@example.com", costCenter: "CC-C", spend: 150, bigRole: true, override: 100},
		{email: "dave@example.com", costCenter: "CC-D", spend: 400, credit: 100},
	}
	for _, p := range people {
		userID := uuid.NewString()
		if _, err := s.CreatePartnerUser(ctx, "test", userID, map[string]any{
			"email":       p.email,
			"first_name":  "Test",
			"last_name":   "User",
			"cost_center": p.costCenter,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.SyncPartnerUserSubjects(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	for _, p := range people {
		subjectID, _, err := s.ResolvePolicySubjectByUsername(ctx, tenant, p.email)
		if err != nil {
			t.Fatal(err)
		}
		if p.bigRole {
			if err := s.AssignModelAccessRole(ctx, tenant, big.RoleID, subjectID, "admin"); err != nil {
				t.Fatal(err)
			}
		}
		if p.override > 0 {
			if err := s.UpsertQuotaOverride(ctx, "admin", "user", p.email, p.override); err != nil {
				t.Fatal(err)
			}
		}
		if p.credit > 0 {
			if _, err := s.AddQuotaCredit(ctx, tenant, subjectID, p.credit, &future, "test", "admin"); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO user_month_spend (username, month, spent_usd, tokens, requests)
			VALUES ($1, date_trunc('month', NOW())::date, $2, 0, 1)
			ON CONFLICT (username, month) DO UPDATE SET spent_usd=EXCLUDED.spent_usd`,
			p.email, p.spend); err != nil {
			t.Fatal(err)
		}
	}

	page, err := s.ListUsersOverLimit(ctx, tenant, "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !page.Enforced {
		t.Fatal("expected enforcement on")
	}
	if page.Total != 3 || len(page.Users) != 3 {
		t.Fatalf("over-limit page = %#v; want 3 users", page)
	}
	byEmail := map[string]OverLimitUser{}
	for _, u := range page.Users {
		byEmail[u.Email] = u
	}
	if u, ok := byEmail["alice@example.com"]; !ok {
		t.Fatal("alice missing from over-limit list")
	} else if u.LimitUSD != 300 || u.SpentUSD != 350 || u.OverByUSD != 50 || u.UsedPct != 117 || u.BudgetSource != "role" {
		t.Fatalf("alice = %#v", u)
	}
	if _, ok := byEmail["bob@example.com"]; ok {
		t.Fatal("bob has $500 budget and should not be listed")
	}
	if u, ok := byEmail["carol@example.com"]; !ok {
		t.Fatal("carol missing from over-limit list")
	} else if u.LimitUSD != 100 || u.SpentUSD != 150 || u.OverByUSD != 50 || u.BudgetSource != "user_override" {
		t.Fatalf("carol = %#v", u)
	}
	if u, ok := byEmail["dave@example.com"]; !ok {
		t.Fatal("dave missing from over-limit list")
	} else if u.LimitUSD != 400 || u.SpentUSD != 400 || u.OverByUSD != 0 || u.BudgetSource != "role" {
		t.Fatalf("dave = %#v", u)
	}

	// Search narrows the list.
	page, err = s.ListUsersOverLimit(ctx, tenant, "alice", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Users) != 1 || page.Users[0].Email != "alice@example.com" {
		t.Fatalf("search page = %#v", page)
	}
	page, err = s.ListUsersOverLimit(ctx, tenant, "bob", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 0 || len(page.Users) != 0 {
		t.Fatalf("bob search page = %#v", page)
	}

	// Pagination keeps the total while returning one row.
	page, err = s.ListUsersOverLimit(ctx, tenant, "", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 3 || len(page.Users) != 1 {
		t.Fatalf("paged result = %#v", page)
	}
}
