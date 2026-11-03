package storage

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestParitySyncLatchIntegration covers the blocker found in review: api-mode
// pods do not run the backfill, so the parity sync must latch rollupsReadyNow
// from rollup_meta before dashboards can serve rollups. Like the other live
// tests, it skips without DATABASE_URL and restores the shared meta rows.
func TestParitySyncLatchIntegration(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set — parity latch needs PostgreSQL")
	}

	store, err := New(dsn, 0, PoolConfig{})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	keys := []string{metaRollupsReady, metaParityHealthy, metaParityCheckedAt}
	type saved struct {
		value string
		found bool
	}
	previous := make(map[string]saved, len(keys))
	for _, key := range keys {
		value, found, lookupErr := store.metaLookup(ctx, key)
		if lookupErr != nil {
			t.Fatalf("snapshot %s: %v", key, lookupErr)
		}
		previous[key] = saved{value: value, found: found}
	}
	t.Cleanup(func() {
		restoreCtx, restoreCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer restoreCancel()
		for _, key := range keys {
			prev := previous[key]
			if prev.found {
				_ = store.metaSet(restoreCtx, key, prev.value)
			} else {
				_, _ = store.db.ExecContext(restoreCtx, `DELETE FROM rollup_meta WHERE key = $1`, key)
			}
		}
	})

	store.rollupsReadyNow.Store(false)
	store.parityHealthy.Store(false)

	if err := store.metaSet(ctx, metaRollupsReady, "true"); err != nil {
		t.Fatalf("seed rollups_ready: %v", err)
	}
	if err := store.metaSet(ctx, metaParityHealthy, "true"); err != nil {
		t.Fatalf("seed parity_healthy: %v", err)
	}
	if err := store.metaSet(ctx, metaParityCheckedAt, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("seed parity_checked_at: %v", err)
	}

	store.syncParityFromMeta(ctx, 15*time.Minute)

	if !store.rollupsReadyNow.Load() {
		t.Fatal("syncParityFromMeta did not latch rollupsReadyNow from rollup_meta")
	}
	if !store.parityHealthy.Load() {
		t.Fatal("syncParityFromMeta did not sync parityHealthy=true from rollup_meta")
	}
}

// TestParitySyncClearsLocalStateOnMissingMetaIntegration covers the review
// follow-up: a pod that was serving rollups must fall back to raw when the
// shared parity verdict disappears instead of keeping its last green state.
func TestParitySyncClearsLocalStateOnMissingMetaIntegration(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set — parity state sync needs PostgreSQL")
	}

	store, err := New(dsn, 0, PoolConfig{})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	keys := []string{metaRollupsReady, metaParityHealthy, metaParityCheckedAt}
	type saved struct {
		value string
		found bool
	}
	previous := make(map[string]saved, len(keys))
	for _, key := range keys {
		value, found, lookupErr := store.metaLookup(ctx, key)
		if lookupErr != nil {
			t.Fatalf("snapshot %s: %v", key, lookupErr)
		}
		previous[key] = saved{value: value, found: found}
	}
	t.Cleanup(func() {
		restoreCtx, restoreCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer restoreCancel()
		for _, key := range keys {
			prev := previous[key]
			if prev.found {
				_ = store.metaSet(restoreCtx, key, prev.value)
			} else {
				_, _ = store.db.ExecContext(restoreCtx, `DELETE FROM rollup_meta WHERE key = $1`, key)
			}
		}
	})

	store.rollupsReadyNow.Store(true)
	store.parityHealthy.Store(true)
	store.servingRollups.Store(true)
	if _, err := store.db.ExecContext(ctx,
		`DELETE FROM rollup_meta WHERE key IN ($1, $2)`, metaParityHealthy, metaParityCheckedAt); err != nil {
		t.Fatalf("delete parity meta: %v", err)
	}

	store.syncParityFromMeta(ctx, 15*time.Minute)

	if store.parityHealthy.Load() {
		t.Fatal("missing parity meta must clear the local green gate")
	}
	if store.servingRollups.Load() {
		t.Fatal("missing parity meta must clear the serving flag")
	}
}
