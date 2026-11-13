package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/maasapi"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

func TestManagementCanRevokeInactiveIdentityKeys(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	inactive := false
	if _, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "suspended", Active: &inactive}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("X-MaaS-Username") != "suspended" {
			t.Error("wrong revocation identity")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"revokedCount":2}`))
	}))
	defer upstream.Close()
	cfg := config.Config{UserHeader: "X-User", PartnerUserKeyGroup: "system:authenticated"}
	h := NewManagementKeyRevocationsHandler(store, cfg, maasapi.NewClient(upstream.URL, ""))
	r := httptest.NewRequest("POST", "/api/v1/management/key-revocations", strings.NewReader(`{"subject":"suspended","dry_run":false}`))
	r.Header.Set("X-User", "admin")
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != 200 || calls != 1 {
		t.Fatalf("status=%d calls=%d; suspended users must remain revocable", w.Code, calls)
	}
	if _, err := store.PartnerUserByMaaSUsername(t.Context(), "suspended"); err == nil {
		t.Fatal("authentication unexpectedly accepted suspended account")
	}
}

func TestManagementKeyIssuanceUsesStoredLoginSpelling(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	if _, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "alice", Name: "Alice"}); err != nil {
		t.Fatal(err)
	}
	var gotSubject string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSubject = r.Header.Get("X-MaaS-Username")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"key-1","name":"onboarding","username":"alice","status":"active"}`))
	}))
	defer upstream.Close()
	cfg := config.Config{UserHeader: "X-User", PartnerUserKeyGroup: "system:authenticated"}
	h := NewManagementKeysHandler(store, cfg, maasapi.NewClient(upstream.URL, ""))
	r := httptest.NewRequest("POST", "/api/v1/management/keys", strings.NewReader(`{"subject":"  ALICE ","name":"onboarding","expiresIn":"24h"}`))
	r.Header.Set("X-User", "admin")
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != 200 {
		t.Fatalf("status=%d; issuance must succeed for a padded, case-variant subject", w.Code)
	}
	if gotSubject != "alice" {
		t.Fatalf("upstream subject=%q; the stored login spelling must be used", gotSubject)
	}
}
