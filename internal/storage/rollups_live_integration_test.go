package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"
)

// This test needs PostgreSQL because the behavior under review is the
// interaction between the usage_events transaction, usage_hourly, and the
// bounded recent-hour rebuild. It deliberately skips in ordinary unit-test
// runs and is exercised by the integration environment with DATABASE_URL.
func TestLiveRollupConfigurationMatrixIntegration(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set — live rollup matrix needs PostgreSQL")
	}

	store, err := New(dsn, 0, PoolConfig{})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	prefix := fmt.Sprintf("rollup-matrix-%d-", time.Now().UnixNano())
	defer func() {
		_, _ = store.db.ExecContext(ctx, `DELETE FROM usage_hourly WHERE username LIKE $1`, prefix+"%")
		_, _ = store.db.ExecContext(ctx, `DELETE FROM usage_events WHERE username LIKE $1`, prefix+"%")
	}()

	// Make the read gate deterministic so this test covers the read/write
	// matrix independently of whether the shared integration database has
	// completed its asynchronous backfill.
	store.rollupsReadyNow.Store(true)
	store.parityHealthy.Store(true)

	cases := []struct {
		name       string
		readRollup bool
		liveWrite  bool
	}{
		{name: "raw reads live writes off", readRollup: false, liveWrite: false},
		{name: "raw reads live writes on", readRollup: false, liveWrite: true},
		{name: "rollup reads live writes off", readRollup: true, liveWrite: false},
		{name: "rollup reads live writes on", readRollup: true, liveWrite: true},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store.SetLiveRollups(tc.liveWrite)
			store.UseRollups(tc.readRollup)

			username := fmt.Sprintf("%s%d", prefix, i)
			model := fmt.Sprintf("rollup-matrix-model-%d", i)
			eventTime := time.Now().UTC()
			if err := store.InsertEvent(ctx, UsageEvent{
				EventID:      fmt.Sprintf("%s-event", username),
				Timestamp:    eventTime,
				Username:     username,
				Model:        model,
				Provider:     "rollup-integration",
				Source:       "rollup-integration-test",
				TotalTokens:  1,
				PromptTokens: 1,
				StatusCode:   intPtr(200),
			}); err != nil {
				t.Fatalf("InsertEvent: %v", err)
			}

			if got := store.rollupsLive(); got != tc.readRollup {
				t.Fatalf("rollupsLive() = %v, want %v", got, tc.readRollup)
			}

			got, err := hourlyRequests(ctx, store, eventTime, username, model)
			if err != nil {
				t.Fatalf("read immediate hourly row: %v", err)
			}
			wantImmediate := int64(0)
			if tc.liveWrite {
				wantImmediate = 1
			}
			if got != wantImmediate {
				t.Fatalf("immediate hourly requests = %d, want %d", got, wantImmediate)
			}

			if !tc.liveWrite {
				if err := store.refreshRecentHours(ctx); err != nil {
					t.Fatalf("refreshRecentHours: %v", err)
				}
				got, err = hourlyRequests(ctx, store, eventTime, username, model)
				if err != nil {
					t.Fatalf("read refreshed hourly row: %v", err)
				}
				if got != 1 {
					t.Fatalf("refreshed hourly requests = %d, want 1", got)
				}
			}
		})
	}
}

func hourlyRequests(ctx context.Context, store *Store, eventTime time.Time, username, model string) (int64, error) {
	var requests int64
	err := store.db.QueryRowContext(ctx, `
		SELECT requests
		FROM usage_hourly
		WHERE hour = date_trunc('hour', $1::timestamptz)
		  AND username = $2
		  AND group_name = ''
		  AND model = $3
		  AND provider = 'rollup-integration'`, eventTime, username, model).Scan(&requests)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return requests, err
}

func intPtr(value int) *int { return &value }
