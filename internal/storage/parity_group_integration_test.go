package storage

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func testIntegrationStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set — parity group normalization needs PostgreSQL")
	}
	store, err := New(dsn, 0, PoolConfig{})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return store, ctx
}

// TestParityGroupNormalizationIntegration pins the empty-string/NULL group
// normalization: the raw side and the rollup side must both key such rows as
// 'unknown' so legacy empty-group rows cannot flip the standing parity gate
// red (which would send every api pod back to raw reads for a full tick).
func TestParityGroupNormalizationIntegration(t *testing.T) {
	store, ctx := testIntegrationStore(t)
	hour := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	username := "parity-group-test@example.invalid"
	model := "parity-group-test-model"

	cleanup := func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = store.db.ExecContext(cleanupCtx, `DELETE FROM usage_events WHERE username = $1 AND model = $2`, username, model)
		_, _ = store.db.ExecContext(cleanupCtx, `DELETE FROM usage_hourly WHERE username = $1 AND model = $2`, username, model)
	}
	cleanup()
	t.Cleanup(cleanup)

	for i, group := range []any{"", nil, ""} {
		if _, err := store.db.ExecContext(ctx, `
			INSERT INTO usage_events (event_id, timestamp, username, group_name, provider, model, prompt_tokens, completion_tokens, total_tokens)
			VALUES ($1, $2, $3, $4, '', $5, 1, 0, 1)`,
			fmt.Sprintf("parity-group-%d-%d", time.Now().UnixNano(), i), hour, username, group, model); err != nil {
			t.Fatalf("insert raw row %d: %v", i, err)
		}
	}
	if _, err := store.db.ExecContext(ctx, `
		INSERT INTO usage_hourly (hour, username, group_name, model, provider, requests, prompt_tokens, completion_tokens, total_tokens)
		VALUES ($1, $2, '', $3, '', 3, 3, 0, 3)`, hour, username, model); err != nil {
		t.Fatalf("insert rollup row: %v", err)
	}

	report, err := store.ParityReport(ctx, hour, hour.Add(time.Hour))
	if err != nil {
		t.Fatalf("parity report: %v", err)
	}
	found := false
	for _, ps := range report {
		if ps.Shape != "per_group" {
			continue
		}
		if ps.Key == "" {
			t.Fatalf("empty group key leaked into parity report: %+v", ps)
		}
		if ps.Key == "unknown" {
			found = true
			if !ps.Match || ps.RawRequests != 3 || ps.RollRequests != 3 {
				t.Fatalf("per_group 'unknown' mismatch: %+v", ps)
			}
		}
	}
	if !found {
		t.Fatal("per_group 'unknown' shape not found")
	}
}

// TestMetaSetParityGuardIntegration covers the atomic verdict write and the
// check-start guard: a verdict that started before a newer invalidation
// (repricing) must not overwrite it. Run against a disposable database.
func TestMetaSetParityGuardIntegration(t *testing.T) {
	store, ctx := testIntegrationStore(t)
	keys := []string{metaParityHealthy, metaParityCheckedAt}
	type saved struct {
		value string
		found bool
	}
	previous := make(map[string]saved, len(keys))
	for _, key := range keys {
		value, found, err := store.metaLookup(ctx, key)
		if err != nil {
			t.Fatalf("snapshot %s: %v", key, err)
		}
		previous[key] = saved{value: value, found: found}
	}
	t.Cleanup(func() {
		restoreCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, key := range keys {
			prev := previous[key]
			if prev.found {
				_ = store.metaSet(restoreCtx, key, prev.value)
			} else {
				_, _ = store.db.ExecContext(restoreCtx, `DELETE FROM rollup_meta WHERE key = $1`, key)
			}
		}
	})

	now := time.Now().UTC()
	if err := store.metaSet(ctx, metaParityHealthy, "true"); err != nil {
		t.Fatalf("seed healthy: %v", err)
	}
	if err := store.metaSet(ctx, metaParityCheckedAt, now.Add(-time.Minute).Format(time.RFC3339)); err != nil {
		t.Fatalf("seed checked_at: %v", err)
	}

	wrote, err := store.metaSetParity(ctx, false, now, now.Add(-30*time.Second))
	if err != nil {
		t.Fatalf("write with older verdict: %v", err)
	}
	if !wrote {
		t.Fatal("write should proceed when the stored verdict is older than the guard")
	}
	healthy, _, _, err := store.metaLookupParity(ctx)
	if err != nil {
		t.Fatalf("read after write: %v", err)
	}
	if healthy != "false" {
		t.Fatalf("healthy = %q, want false", healthy)
	}

	if err := store.metaSet(ctx, metaParityHealthy, "true"); err != nil {
		t.Fatalf("reseed healthy: %v", err)
	}
	if err := store.metaSet(ctx, metaParityCheckedAt, now.Format(time.RFC3339)); err != nil {
		t.Fatalf("reseed checked_at: %v", err)
	}
	wrote, err = store.metaSetParity(ctx, false, now.Add(time.Minute), now.Add(-30*time.Second))
	if err != nil {
		t.Fatalf("guarded write: %v", err)
	}
	if wrote {
		t.Fatal("guarded write should be skipped when a newer verdict is stored")
	}
	healthy, _, _, err = store.metaLookupParity(ctx)
	if err != nil {
		t.Fatalf("read after guarded write: %v", err)
	}
	if healthy != "true" {
		t.Fatalf("healthy = %q, want true (newer verdict preserved)", healthy)
	}

	wrote, err = store.metaSetParity(ctx, false, now.Add(2*time.Minute), time.Time{})
	if err != nil {
		t.Fatalf("unguarded write: %v", err)
	}
	if !wrote {
		t.Fatal("unguarded write should always proceed")
	}
}

// TestMaintainOnceFailureClearsLocalParity covers Mode "all": the pod that
// owns maintenance must clear its own in-memory parity gate on a failed pass,
// not just the shared rollup_meta verdict (all mode has no parity sync loop).
func TestMaintainOnceFailureClearsLocalParity(t *testing.T) {
	store, _ := testIntegrationStore(t)
	store.rollupsReadyNow.Store(true)
	store.parityHealthy.Store(true)
	store.servingRollups.Store(true)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // refreshRecentHours fails immediately on the cancelled context
	store.maintainOnce(ctx, false)

	if store.parityHealthy.Load() {
		t.Fatal("failed maintenance pass must clear the local parity flag")
	}
	if store.servingRollups.Load() {
		t.Fatal("failed maintenance pass must clear the serving flag")
	}
}
