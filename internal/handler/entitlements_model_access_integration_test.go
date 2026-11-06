package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

func openHandlerTestStore(t *testing.T) (*storage.Store, context.Context) {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set — integration tests need a Postgres")
	}
	dbName := fmt.Sprintf("handlertest_%d", time.Now().UnixNano())
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := admin.Exec("CREATE DATABASE " + dbName); err != nil {
		admin.Close()
		t.Fatalf("create test db: %v", err)
	}
	admin.Close()
	testDSN := replaceHandlerDBName(dsn, dbName)
	store, err := storage.New(testDSN, 0, storage.PoolConfig{})
	if err != nil {
		t.Fatalf("connect fresh db: %v", err)
	}
	t.Cleanup(func() {
		store.Close()
		admin, err := sql.Open("postgres", dsn)
		if err == nil {
			admin.Exec("DROP DATABASE " + dbName) //nolint:errcheck
			admin.Close()
		}
	})
	return store, context.Background()
}

func replaceHandlerDBName(dsn, name string) string {
	for i := len(dsn) - 1; i >= 0; i-- {
		if dsn[i] == '/' {
			end := len(dsn)
			if q := indexByte(dsn[i:], '?'); q >= 0 {
				end = i + q
				return dsn[:i+1] + name + dsn[end:]
			}
			return dsn[:i+1] + name
		}
	}
	return dsn
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func entitlementFor(t *testing.T, h *EntitlementsHandler, username, model string) storage.UsageStats {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/customers/"+username+"/entitlements/inference-tokens/value?model="+model, nil)
	rec := httptest.NewRecorder()
	h.HandleEntitlement(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var stats storage.UsageStats
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	return stats
}

func TestEntitlementModelAccessModes(t *testing.T) {
	store, ctx := openHandlerTestStore(t)
	tenant, err := store.EnsureDefaultTenant(ctx)
	if err != nil {
		t.Fatal(err)
	}
	const username = "entitlement-mode@example.com"
	userID := uuid.NewString()
	if _, err := store.CreatePartnerUser(ctx, "test", userID, map[string]any{
		"email": username, "first_name": "Mode", "last_name": "Test",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateModelAccessRole(ctx, tenant, "test", "Engineering", "", []string{"model-a"}, true, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SyncPartnerUserSubjects(ctx, tenant); err != nil {
		t.Fatal(err)
	}

	enforce := NewEntitlementsHandler(store, config.Config{ModelAccessEnforcement: "enforce"})
	if got := entitlementFor(t, enforce, username, "model-a"); !got.HasAccess || !got.ModelAllowed {
		t.Fatalf("enforce allowed = %#v", got)
	}
	if got := entitlementFor(t, enforce, username, "model-b"); got.HasAccess || got.ModelAllowed {
		t.Fatalf("enforce denied = %#v", got)
	}

	observe := NewEntitlementsHandler(store, config.Config{ModelAccessEnforcement: "observe"})
	if got := entitlementFor(t, observe, username, "model-b"); !got.HasAccess {
		t.Fatalf("observe must not block: %#v", got)
	}

	off := NewEntitlementsHandler(store, config.Config{ModelAccessEnforcement: "off"})
	if got := entitlementFor(t, off, username, "model-b"); !got.HasAccess {
		t.Fatalf("off must preserve legacy behavior: %#v", got)
	}
}
