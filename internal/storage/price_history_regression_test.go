package storage

import (
	"fmt"
	"testing"
	"time"
)

func TestCatalogRefreshPreservesLegacyUnpricedCharges(t *testing.T) {
	s, ctx := openTestStore(t)
	model := ModelPrice{Model: "legacy-refresh-fixture", Provider: "mock", InputCost: 1}
	if _, err := s.SeedPricing(ctx, []ModelPrice{model}); err != nil {
		t.Fatal(err)
	}
	event := UsageEvent{EventID: "legacy-refresh-before", Timestamp: time.Now(), Username: "alice", Model: model.Model, PromptTokens: 1000000, TotalTokens: 1000000}
	if err := s.InsertEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	// Simulate a ledger row predating the stored-charge backfill.
	if _, err := s.db.ExecContext(ctx, `UPDATE usage_events SET cost_usd=NULL WHERE event_id=$1`, event.EventID); err != nil {
		t.Fatal(err)
	}
	model.InputCost = 10
	if _, err := s.SeedPricing(ctx, []ModelPrice{model}); err != nil {
		t.Fatal(err)
	}
	var charge float64
	if err := s.db.QueryRowContext(ctx, fmt.Sprintf(`SELECT %s FROM usage_events e LEFT JOIN model_pricing p ON p.model=e.model WHERE e.event_id=$1`, costUSDExpr), event.EventID).Scan(&charge); err != nil {
		t.Fatal(err)
	}
	if charge != 1 {
		t.Fatalf("catalog refresh changed legacy charge to %v", charge)
	}
	event.EventID = "legacy-refresh-after"
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
