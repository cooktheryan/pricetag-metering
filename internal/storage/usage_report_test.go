package storage

import (
	"math"
	"testing"
	"time"
)

func TestUserUsageReportCurrentMonthBreakdown(t *testing.T) {
	s, ctx := openTestStore(t)
	prices := []ModelPrice{{
		Model:          "report-model",
		Provider:       "report-provider",
		InputCost:      2,
		OutputCost:     10,
		CacheWriteCost: 18.75,
		CacheReadCost:  0.5,
	}}
	if _, err := s.SeedPricing(ctx, prices); err != nil {
		t.Fatalf("seed pricing: %v", err)
	}

	now := time.Now().UTC()
	for _, event := range []UsageEvent{
		{
			EventID:             "usage-report-current",
			Timestamp:           now,
			Username:            "report-user",
			Provider:            "report-provider",
			Model:               "report-model",
			PromptTokens:        1000,
			CompletionTokens:    500,
			TotalTokens:         1500,
			CachedInputTokens:   200,
			CacheCreationTokens: 100,
			ReasoningTokens:     50,
		},
		{
			EventID:          "usage-report-other-user",
			Timestamp:        now,
			Username:         "another-user",
			Provider:         "report-provider",
			Model:            "report-model",
			PromptTokens:     7000,
			CompletionTokens: 9000,
			TotalTokens:      16000,
		},
	} {
		if err := s.InsertEvent(ctx, event); err != nil {
			t.Fatalf("insert event %s: %v", event.EventID, err)
		}
	}

	report, err := s.GetUserUsageReport(ctx, "report-user")
	if err != nil {
		t.Fatalf("GetUserUsageReport: %v", err)
	}
	if report.Username != "report-user" || report.Month != now.Format("2006-01") {
		t.Fatalf("report identity/period = %q/%q, want report-user/%q", report.Username, report.Month, now.Format("2006-01"))
	}
	if len(report.Models) != 1 {
		t.Fatalf("model rows = %d, want 1: %#v", len(report.Models), report.Models)
	}
	model := report.Models[0]
	if model.Provider != "report-provider" || model.Model != "report-model" ||
		model.Requests != 1 || model.PromptTokens != 1000 || model.CompletionTokens != 500 ||
		model.TotalTokens != 1500 || model.CachedInputTokens != 200 ||
		model.CacheCreationTokens != 100 || model.ReasoningTokens != 50 {
		t.Fatalf("model breakdown = %#v", model)
	}
	// Uncached input: 700*2/1M; cache read: 200*.5/1M;
	// cache write: 100*18.75/1M; output: 500*10/1M.
	wantCost := 0.008375
	if math.Abs(model.EstimatedCostUSD-wantCost) > 1e-9 {
		t.Fatalf("estimated model cost = %.12f, want %.12f", model.EstimatedCostUSD, wantCost)
	}
	if report.Totals != model.UsageTotals {
		t.Fatalf("totals = %#v, want model total %#v", report.Totals, model.UsageTotals)
	}
}

func TestUserUsageReportUnknownUserReturnsEmptyTotals(t *testing.T) {
	s, ctx := openTestStore(t)
	report, err := s.GetUserUsageReport(ctx, "usage-report-no-rows")
	if err != nil {
		t.Fatalf("GetUserUsageReport: %v", err)
	}
	if report.Username != "usage-report-no-rows" || len(report.Models) != 0 || report.Totals.Requests != 0 {
		t.Fatalf("empty report = %#v", report)
	}
}
