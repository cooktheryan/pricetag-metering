package storage

import (
	"testing"
	"time"
)

// TestGetDashboardCostCentersReturnsIDAndDescription verifies the cost-center
// rollup keeps the directory code alongside the human label, groups on both,
// and falls back to the code (then "Unknown") when a tag is absent. It needs a
// Postgres (DATABASE_URL); otherwise it skips.
func TestGetDashboardCostCentersReturnsIDAndDescription(t *testing.T) {
	s, ctx := openTestStore(t)

	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	until := from.Add(48 * time.Hour)

	users := []struct {
		uuid       string
		email      string
		tokens     int
		tags       map[string]any
		wantCenter string
		wantDesc   string
	}{
		{
			uuid: "223e4567-e89b-12d3-a456-4266140000a1", email: "alice@example.com", tokens: 15,
			tags: map[string]any{"email": "alice@example.com", "first_name": "Alice", "last_name": "A",
				"cost_center": "CC-100", "cost_center_description": "Platform Engineering"},
			wantCenter: "CC-100", wantDesc: "Platform Engineering",
		},
		{
			uuid: "223e4567-e89b-12d3-a456-4266140000a2", email: "bob@example.com", tokens: 20,
			tags: map[string]any{"email": "bob@example.com", "first_name": "Bob", "last_name": "B",
				"cost_center": "CC-100", "cost_center_description": "Platform Engineering"},
			wantCenter: "CC-100", wantDesc: "Platform Engineering",
		},
		{
			// Same description, different code: must stay a separate bucket.
			uuid: "223e4567-e89b-12d3-a456-4266140000a3", email: "erin@example.com", tokens: 10,
			tags: map[string]any{"email": "erin@example.com", "first_name": "Erin", "last_name": "E",
				"cost_center": "CC-300", "cost_center_description": "Platform Engineering"},
			wantCenter: "CC-300", wantDesc: "Platform Engineering",
		},
		{
			// Code only: the description falls back to the code.
			uuid: "223e4567-e89b-12d3-a456-4266140000a4", email: "carol@example.com", tokens: 30,
			tags: map[string]any{"email": "carol@example.com", "first_name": "Carol", "last_name": "C",
				"cost_center": "CC-200"},
			wantCenter: "CC-200", wantDesc: "CC-200",
		},
		{
			// No cost-center tags at all.
			uuid: "223e4567-e89b-12d3-a456-4266140000a5", email: "dave@example.com", tokens: 40,
			tags:       map[string]any{"email": "dave@example.com", "first_name": "Dave", "last_name": "D"},
			wantCenter: "", wantDesc: "Unknown",
		},
	}
	for _, u := range users {
		if _, err := s.CreatePartnerUser(ctx, "partner-m2m", u.uuid, u.tags); err != nil {
			t.Fatalf("CreatePartnerUser(%s): %v", u.email, err)
		}
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO usage_events (event_id,timestamp,username,model,prompt_tokens,completion_tokens,total_tokens)
			VALUES ($1,$2,$3,'model-a',$4,0,$4)`, "ev-"+u.email, from.Add(time.Hour), u.email, u.tokens); err != nil {
			t.Fatalf("insert usage %s: %v", u.email, err)
		}
	}

	got, err := s.GetDashboardCostCenters(ctx, from, until, "", "", "")
	if err != nil {
		t.Fatalf("GetDashboardCostCenters: %v", err)
	}

	byCenter := make(map[string]CostCenterSummary, len(got))
	for _, item := range got {
		byCenter[item.CostCenter] = item
		if item.CostCenterDescription == "" {
			t.Errorf("bucket %q has an empty description", item.CostCenter)
		}
	}

	for _, u := range users {
		if u.wantCenter == "" {
			continue
		}
		item, ok := byCenter[u.wantCenter]
		if !ok {
			t.Fatalf("missing bucket %q in %#v", u.wantCenter, got)
		}
		if item.CostCenterDescription != u.wantDesc {
			t.Errorf("bucket %q description = %q, want %q", u.wantCenter, item.CostCenterDescription, u.wantDesc)
		}
	}

	if item := byCenter["CC-100"]; item.Requests != 2 || item.TotalTokens != 35 || item.UserCount != 2 {
		t.Errorf("CC-100 = %#v; want 2 requests, 35 tokens, 2 users", item)
	}
	if item := byCenter["CC-300"]; item.Requests != 1 || item.TotalTokens != 10 {
		t.Errorf("CC-300 = %#v; want 1 request, 10 tokens", item)
	}
	if item := byCenter["CC-200"]; item.Requests != 1 || item.TotalTokens != 30 {
		t.Errorf("CC-200 = %#v; want 1 request, 30 tokens", item)
	}
	if item, ok := byCenter[""]; !ok || item.CostCenterDescription != "Unknown" || item.TotalTokens != 40 {
		t.Errorf("unknown bucket = %#v, ok=%v; want 40 tokens labelled Unknown", item, ok)
	}
	if len(got) != 4 {
		t.Errorf("got %d buckets (%#v); want 4", len(got), got)
	}
}
