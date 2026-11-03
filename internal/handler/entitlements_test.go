package handler

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/redhat-et/pricetag-metering/internal/config"
)

func newRoleCacheTestHandler(resolve func(context.Context, string) (bool, bool)) *EntitlementsHandler {
	h := NewEntitlementsHandler(nil, config.Config{})
	h.resolveRole = resolve
	return h
}

func TestEntitlementsHandlerRoleCacheHit(t *testing.T) {
	var calls atomic.Int64
	h := newRoleCacheTestHandler(func(context.Context, string) (bool, bool) {
		calls.Add(1)
		return false, true
	})
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if h.isSuperAdmin(ctx, "User@Example.com") {
			t.Fatal("expected non-superadmin")
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("role lookups = %d, want 1", got)
	}
}

func TestEntitlementsHandlerRoleCacheNormalizesUsername(t *testing.T) {
	var calls atomic.Int64
	h := newRoleCacheTestHandler(func(context.Context, string) (bool, bool) {
		calls.Add(1)
		return true, true
	})
	ctx := context.Background()
	if !h.isSuperAdmin(ctx, "User@Example.com") {
		t.Fatal("expected superadmin")
	}
	if !h.isSuperAdmin(ctx, "  user@example.com  ") {
		t.Fatal("expected superadmin for normalized variant")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("role lookups = %d, want 1", got)
	}
}

func TestEntitlementsHandlerRoleCacheExpires(t *testing.T) {
	var calls atomic.Int64
	h := newRoleCacheTestHandler(func(context.Context, string) (bool, bool) {
		calls.Add(1)
		return false, true
	})
	h.roleCache = expirable.NewLRU[string, bool](roleCacheMaxEntries, nil, 10*time.Millisecond)
	ctx := context.Background()
	h.isSuperAdmin(ctx, "a@example.com")
	h.isSuperAdmin(ctx, "a@example.com")
	if got := calls.Load(); got != 1 {
		t.Fatalf("role lookups = %d, want 1", got)
	}
	time.Sleep(30 * time.Millisecond)
	h.isSuperAdmin(ctx, "a@example.com")
	if got := calls.Load(); got != 2 {
		t.Fatalf("role lookups after expiry = %d, want 2", got)
	}
}

func TestEntitlementsHandlerRoleCacheCapacity(t *testing.T) {
	h := newRoleCacheTestHandler(func(context.Context, string) (bool, bool) {
		return false, true
	})
	h.roleCache = expirable.NewLRU[string, bool](2, nil, time.Minute)
	ctx := context.Background()
	for _, username := range []string{"a@example.com", "b@example.com", "c@example.com"} {
		h.isSuperAdmin(ctx, username)
	}
	if _, ok := h.roleCache.Get("a@example.com"); ok {
		t.Fatal("oldest entry should be evicted at capacity")
	}
	if _, ok := h.roleCache.Get("c@example.com"); !ok {
		t.Fatal("newest entry should be cached")
	}
}

func TestEntitlementsHandlerRoleLookupErrorNotCached(t *testing.T) {
	var calls atomic.Int64
	h := newRoleCacheTestHandler(func(context.Context, string) (bool, bool) {
		calls.Add(1)
		return false, false
	})
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if h.isSuperAdmin(ctx, "a@example.com") {
			t.Fatal("expected non-superadmin")
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("role lookups = %d, want 2 (fallback verdicts must not be cached)", got)
	}
}

func TestPartnerSuperAdminVerdictBreakGlassWithoutStore(t *testing.T) {
	cfg := config.Config{SuperAdminUsers: []string{"Break@Glass.example"}}
	superAdmin, resolved := partnerSuperAdminVerdict(context.Background(), cfg, nil, " break@glass.example ")
	if !superAdmin {
		t.Fatal("expected break-glass superadmin")
	}
	if !resolved {
		t.Fatal("break-glass verdict without a store should be cacheable")
	}
	if superAdmin, resolved := partnerSuperAdminVerdict(context.Background(), cfg, nil, "someone@example.com"); superAdmin || !resolved {
		t.Fatalf("unexpected verdict for non-superadmin: superAdmin=%v resolved=%v", superAdmin, resolved)
	}
}

func TestPartnerSuperAdminVerdictUnauthenticatedAdmin(t *testing.T) {
	cfg := config.Config{AllowUnauthenticatedAdmin: true}
	superAdmin, resolved := partnerSuperAdminVerdict(context.Background(), cfg, nil, " ")
	if !superAdmin {
		t.Fatal("expected unauthenticated admin")
	}
	if !resolved {
		t.Fatal("unauthenticated admin verdict should be cacheable")
	}
}
