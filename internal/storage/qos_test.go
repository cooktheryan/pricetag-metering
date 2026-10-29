package storage

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func qosTestConfig() QosConfig {
	return QosConfig{
		Enabled:             true,
		WindowSeconds:       60,
		HoldWindowSeconds:   300,
		PremiumMaxTokens:    600_000,
		RatelimitMinTokens:  2_000_000,
		HoldMainTokens:      3_000_000,
		HoldRatelimitTokens: 10_000_000,
		CacheReadWeight:     0.05,
		ClassCacheTTL:       time.Minute,
		HoldCacheTTL:        time.Minute,
		Providers:           []string{"cb-glm"},
		ExemptTagKey:        "origin",
		ExemptTagValue:      "loadtest",
	}
}

func TestClassifyQos(t *testing.T) {
	cfg := qosTestConfig()
	cases := []struct {
		name         string
		window, hold int64
		want         string
	}{
		{"premium", 100_000, 500_000, QosPremium},
		{"window main boundary", 600_000, 600_000, QosMain},
		{"window ratelimit boundary", 2_000_000, 2_000_000, QosRatelimit},
		{"hold main", 100_000, 3_000_000, QosMain},
		{"hold ratelimit", 100_000, 10_000_000, QosRatelimit},
		{"hold ratelimit beats main", 700_000, 10_000_000, QosRatelimit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyQos(tc.window, tc.hold, cfg); got != tc.want {
				t.Fatalf("classifyQos(%d, %d) = %q, want %q", tc.window, tc.hold, got, tc.want)
			}
		})
	}
}

func TestGetQosStatusBoundariesAndHoldGuard(t *testing.T) {
	store, ctx := openTestStore(t)
	store.SetQosConfig(qosTestConfig())

	userID := "11111111-1111-1111-1111-111111111111"
	email := "qos-user@example.com"
	if _, err := store.CreatePartnerUser(ctx, "test", userID, map[string]any{
		"email": email, "first_name": "QoS", "last_name": "User",
	}); err != nil {
		t.Fatalf("CreatePartnerUser: %v", err)
	}

	insertQosUsage(t, store, email, time.Now().Add(-20*time.Second), 100_000, 0, 0, 0)
	assertQosClass(t, store, ctx, email, userID, QosPremium)

	insertQosUsage(t, store, email, time.Now().Add(-10*time.Second), 500_000, 0, 0, 0)
	store.SetQosConfig(qosTestConfig()) // reset caches for the boundary case
	assertQosClass(t, store, ctx, email, userID, QosMain)

	insertQosUsage(t, store, email, time.Now().Add(-5*time.Second), 1_500_000, 0, 0, 0)
	store.SetQosConfig(qosTestConfig())
	assertQosClass(t, store, ctx, email, userID, QosRatelimit)
}

func TestGetQosStatusHoldGuard(t *testing.T) {
	store, ctx := openTestStore(t)
	store.SetQosConfig(qosTestConfig())

	userID := "22222222-2222-2222-2222-222222222222"
	email := "qos-hold@example.com"
	if _, err := store.CreatePartnerUser(ctx, "test", userID, map[string]any{
		"email": email, "first_name": "QoS", "last_name": "Hold",
	}); err != nil {
		t.Fatalf("CreatePartnerUser: %v", err)
	}

	// Keep the 60s window under the premium boundary but push the 5m guard
	// over the main boundary.
	insertQosUsage(t, store, email, time.Now().Add(-2*time.Minute), 1_000_000, 0, 0, 0)
	insertQosUsage(t, store, email, time.Now().Add(-3*time.Minute), 1_000_000, 0, 0, 0)
	insertQosUsage(t, store, email, time.Now().Add(-4*time.Minute), 1_000_000, 0, 0, 0)
	insertQosUsage(t, store, email, time.Now().Add(-10*time.Second), 100_000, 0, 0, 0)
	assertQosClass(t, store, ctx, email, userID, QosMain)

	// Push the guard over the ratelimit boundary without moving the 60s window.
	insertQosUsage(t, store, email, time.Now().Add(-2*time.Minute-10*time.Second), 7_000_000, 0, 0, 0)
	store.SetQosConfig(qosTestConfig())
	assertQosClass(t, store, ctx, email, userID, QosRatelimit)
}

func TestGetQosStatusProviderScopeAndExemption(t *testing.T) {
	store, ctx := openTestStore(t)
	store.SetQosConfig(qosTestConfig())

	userID := "33333333-3333-3333-3333-333333333333"
	email := "qos-scope@example.com"
	if _, err := store.CreatePartnerUser(ctx, "test", userID, map[string]any{
		"email": email, "first_name": "QoS", "last_name": "Scope", "origin": "loadtest",
	}); err != nil {
		t.Fatalf("CreatePartnerUser: %v", err)
	}

	// Paid-provider usage does not count toward the cb-glm class.
	insertQosUsageProvider(t, store, email, "openai", time.Now().Add(-10*time.Second), 3_000_000, 0, 0, 0)
	assertQosClass(t, store, ctx, email, userID, QosPremium)

	// Even heavy cb-glm usage is exempt for a tagged load-test user.
	insertQosUsage(t, store, email, time.Now().Add(-5*time.Second), 3_000_000, 0, 0, 0)
	assertQosClass(t, store, ctx, email, userID, QosPremium)
}

func TestGetQosStatusMultiLoginAggregation(t *testing.T) {
	store, ctx := openTestStore(t)
	store.SetQosConfig(qosTestConfig())

	userID := "44444444-4444-4444-4444-444444444444"
	email := "qos-primary@example.com"
	if _, err := store.CreatePartnerUser(ctx, "test", userID, map[string]any{
		"email": email, "first_name": "QoS", "last_name": "Multi",
	}); err != nil {
		t.Fatalf("CreatePartnerUser: %v", err)
	}
	second := "qos-secondary@example.com"
	if _, err := store.db.ExecContext(ctx,
		`INSERT INTO partner_user_logins (username,user_id,is_current) VALUES ($1,$2,FALSE)`,
		second, userID); err != nil {
		t.Fatalf("insert second login: %v", err)
	}
	insertQosUsage(t, store, email, time.Now().Add(-10*time.Second), 400_000, 0, 0, 0)
	insertQosUsage(t, store, second, time.Now().Add(-5*time.Second), 400_000, 0, 0, 0)
	assertQosClass(t, store, ctx, email, userID, QosMain)
}

func TestGetQosStatusCacheTTL(t *testing.T) {
	store, ctx := openTestStore(t)
	cfg := qosTestConfig()
	cfg.ClassCacheTTL = 20 * time.Millisecond
	cfg.HoldCacheTTL = time.Minute
	store.SetQosConfig(cfg)

	userID := "55555555-5555-5555-5555-555555555555"
	email := "qos-cache@example.com"
	if _, err := store.CreatePartnerUser(ctx, "test", userID, map[string]any{
		"email": email, "first_name": "QoS", "last_name": "Cache",
	}); err != nil {
		t.Fatalf("CreatePartnerUser: %v", err)
	}
	insertQosUsage(t, store, email, time.Now().Add(-10*time.Second), 100_000, 0, 0, 0)
	assertQosClass(t, store, ctx, email, userID, QosPremium)

	// Within the short cache TTL the old class is served even though a
	// main-level event now exists.
	insertQosUsage(t, store, email, time.Now().Add(-5*time.Second), 600_000, 0, 0, 0)
	decision, _, err := store.QuotaDecisionCached(ctx, email, false)
	if err != nil {
		t.Fatalf("QuotaDecisionCached: %v", err)
	}
	status, err := store.GetQosStatus(ctx, email, decision, false)
	if err != nil {
		t.Fatalf("GetQosStatus cached: %v", err)
	}
	if status.Class != QosPremium {
		t.Fatalf("cache TTL not honored: got %q, want premium", status.Class)
	}

	time.Sleep(30 * time.Millisecond)
	status, err = store.GetQosStatus(ctx, email, decision, false)
	if err != nil {
		t.Fatalf("GetQosStatus after TTL: %v", err)
	}
	if status.Class != QosMain {
		t.Fatalf("cache did not refresh: got %q, want main", status.Class)
	}
}

func TestGetQosStatusUnmatchedDefaultsMain(t *testing.T) {
	store, ctx := openTestStore(t)
	store.SetQosConfig(qosTestConfig())

	status, err := store.GetQosStatus(ctx, "unknown-user", QuotaDecision{Logins: []string{"unknown-user"}}, false)
	if err != nil {
		t.Fatalf("GetQosStatus: %v", err)
	}
	if status.Class != QosMain {
		t.Fatalf("unmatched class = %q, want main", status.Class)
	}
	if status.Subject != "" {
		t.Fatalf("unmatched subject = %q, want empty", status.Subject)
	}
}

func TestGetMonthlyUsageIncludesQosFields(t *testing.T) {
	store, ctx := openTestStore(t)
	store.SetQosConfig(qosTestConfig())

	userID := "66666666-6666-6666-6666-666666666666"
	email := "qos-response@example.com"
	if _, err := store.CreatePartnerUser(ctx, "test", userID, map[string]any{
		"email": email, "first_name": "QoS", "last_name": "Response",
	}); err != nil {
		t.Fatalf("CreatePartnerUser: %v", err)
	}
	insertQosUsage(t, store, email, time.Now().Add(-5*time.Second), 700_000, 0, 0, 0)
	stats, err := store.GetMonthlyUsage(ctx, email, "rits/zai-org/glm-5-3", false)
	if err != nil {
		t.Fatalf("GetMonthlyUsage: %v", err)
	}
	if stats.QosClass != QosMain {
		t.Fatalf("QosClass = %q, want main", stats.QosClass)
	}
	if stats.QosSubject != userID {
		t.Fatalf("QosSubject = %q, want %q", stats.QosSubject, userID)
	}
	if stats.QosWindowTokens < 700_000 {
		t.Fatalf("QosWindowTokens = %d, want >= 700000", stats.QosWindowTokens)
	}
}

func assertQosClass(t *testing.T, store *Store, ctx context.Context, username, userID, want string) {
	t.Helper()
	decision, _, err := store.QuotaDecisionCached(ctx, username, false)
	if err != nil {
		t.Fatalf("QuotaDecisionCached: %v", err)
	}
	if decision.Subject != userID {
		t.Fatalf("Subject = %q, want %q", decision.Subject, userID)
	}
	status, err := store.GetQosStatus(ctx, username, decision, false)
	if err != nil {
		t.Fatalf("GetQosStatus: %v", err)
	}
	if status.Class != want {
		t.Fatalf("class = %q, want %q (window=%d hold=%d)", status.Class, want, status.WindowTokens, status.HoldWindowTokens)
	}
}

func insertQosUsage(t *testing.T, store *Store, username string, ts time.Time, prompt, cached, cacheWrite, completion int) {
	t.Helper()
	insertQosUsageProvider(t, store, username, "cb-glm", ts, prompt, cached, cacheWrite, completion)
}

func insertQosUsageProvider(t *testing.T, store *Store, username, provider string, ts time.Time, prompt, cached, cacheWrite, completion int) {
	t.Helper()
	_, err := store.db.ExecContext(context.Background(), `
		INSERT INTO usage_events
			(event_id, timestamp, username, provider, model,
			 prompt_tokens, completion_tokens, total_tokens,
			 cached_input_tokens, cache_creation_tokens, reasoning_tokens)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,0)`,
		fmt.Sprintf("qos-test-%d-%d", time.Now().UnixNano(), prompt),
		ts, username, provider, "rits/zai-org/glm-5-3",
		prompt, completion, prompt+completion, cached, cacheWrite)
	if err != nil {
		t.Fatalf("insert usage event: %v", err)
	}
}
