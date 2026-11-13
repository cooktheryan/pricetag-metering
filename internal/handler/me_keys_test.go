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

func TestPersonalKeyExpiryHonorsMaximumIncludingDefault(t *testing.T) {
	for _, tc := range []struct {
		name, value           string
		defaultHours, maximum int
		wantError             bool
	}{
		{"explicit within maximum", "24h", 48, 72, false},
		{"explicit exceeds maximum", "73h", 48, 72, true},
		{"default within maximum", "", 48, 72, false},
		{"default exceeds maximum", "", 48, 24, true},
		{"named default exceeds maximum", "default", 48, 24, true},
		{"fallback default exceeds maximum", "", 0, 24, true},
		{"negative duration", "-1h", 48, 72, true},
		{"no expiry", "none", 48, 72, true},
		{"whole days", "3d", 48, 72, false},
		{"days exceed maximum", "4d", 48, 72, true},
		{"overflowing days", "999999999999999999d", 48, 72, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewAdminHandler(nil, nil, config.Config{KeyPolicy: config.KeyPolicy{DefaultExpiryHours: tc.defaultHours, MaxExpiryHours: tc.maximum}})
			_, err := h.validatedExpiry(tc.value)
			if (err != nil) != tc.wantError {
				t.Fatalf("error=%v; want error=%v", err, tc.wantError)
			}
		})
	}
}

func TestPersonalKeysDoNotInheritOldAdministratorSession(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	cfg := config.Config{ManagementAPISecret: "fixture-only", UserHeader: "X-User", GroupsHeader: "X-Groups", PartnerUserKeyGroup: "system:authenticated"}
	if _, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "alice", Role: storage.PartnerRoleSuperAdmin}); err != nil {
		t.Fatal(err)
	}
	auth := NewAuthHandler(cfg)
	auth.SetOrgStore(store)
	cookie := httptest.NewRecorder()
	auth.setCookie(cookie, "alice", []string{"system:masters"}, "")
	if _, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "alice", Role: storage.PartnerRoleUser}); err != nil {
		t.Fatal(err)
	}
	deletes := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-MaaS-Username") != "alice" || r.Header.Get("X-MaaS-Group") != `["system:authenticated"]` {
			t.Error("personal endpoint forwarded privileged or foreign identity")
		}
		if r.Method == http.MethodDelete {
			deletes++
			w.WriteHeader(204)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"mine","username":"alice"},{"id":"foreign","username":"bob"}],"has_more":false}`))
	}))
	defer upstream.Close()
	h := NewAdminHandler(nil, maasapi.NewClient(upstream.URL, ""), cfg)
	h.SetStore(store)
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/api/v1/me/keys", 200}, {"DELETE", "/api/v1/me/keys/foreign", 404}, {"DELETE", "/api/v1/me/keys/mine", 204},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r.AddCookie(cookie.Result().Cookies()[0])
		w := httptest.NewRecorder()
		auth.RequireAuth(h.HandleMyKeys)(w, r)
		if w.Code != tc.status {
			t.Errorf("%s: got %d want %d", tc.path, w.Code, tc.status)
		}
		if tc.method == "GET" && strings.Contains(w.Body.String(), "foreign") {
			t.Error("foreign key disclosed")
		}
	}
	if deletes != 1 {
		t.Errorf("forwarded %d deletions, want only the owned key", deletes)
	}
	inactive := false
	if _, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "alice", Active: &inactive}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/v1/me/keys", nil)
	r.AddCookie(cookie.Result().Cookies()[0])
	w := httptest.NewRecorder()
	auth.RequireAuth(h.HandleMyKeys)(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("inactive session accepted: %d", w.Code)
	}
}

// A deactivation that commits while a self-service mint is in flight must
// not hand out a live credential: the fresh key is revoked and the caller is
// told the account is no longer active.
func TestPersonalKeyMintRevokedWhenAccountDeactivatedMidRequest(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	cfg := config.Config{ManagementAPISecret: "fixture-only", UserHeader: "X-User", GroupsHeader: "X-Groups", PartnerUserKeyGroup: "system:authenticated"}
	if _, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "alice"}); err != nil {
		t.Fatal(err)
	}
	revokes := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			// Deactivate the account while the mint is in flight.
			inactive := false
			if _, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "alice", Active: &inactive}); err != nil {
				t.Errorf("mid-mint deactivation: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"raced","key":"fixture-only-key"}`))
		case http.MethodDelete:
			revokes++
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer upstream.Close()
	h := NewAdminHandler(nil, maasapi.NewClient(upstream.URL, ""), cfg)
	h.SetStore(store)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/me/keys", strings.NewReader(`{"name":"Raced mint"}`))
	r.Header.Set("X-User", "alice")
	w := httptest.NewRecorder()
	h.HandleMyKeys(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "fixture-only-key") {
		t.Fatal("revoked key secret was disclosed")
	}
	if revokes != 1 {
		t.Fatalf("revokes=%d want 1", revokes)
	}
}

// Outside management mode, identity is derived from session groups and users
// legitimately have no partner record. A missing record must not revoke a
// freshly minted key: the post-mint recheck only guards managed accounts.
func TestPersonalKeyMintSucceedsWithoutPartnerRecordOutsideManagement(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	cfg := config.Config{UserHeader: "X-User", GroupsHeader: "X-Groups"}
	revokes := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"plain","key":"fixture-only-key"}`))
		case http.MethodDelete:
			revokes++
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer upstream.Close()
	h := NewAdminHandler(nil, maasapi.NewClient(upstream.URL, ""), cfg)
	h.SetStore(store)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/me/keys", strings.NewReader(`{"name":"Plain mint"}`))
	r.Header.Set("X-User", "alice")
	r.Header.Set("X-Groups", `["team-a"]`)
	w := httptest.NewRecorder()
	h.HandleMyKeys(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if revokes != 0 {
		t.Fatalf("revokes=%d want 0", revokes)
	}
	if !strings.Contains(w.Body.String(), "fixture-only-key") {
		t.Fatal("minted key was not returned")
	}
}

// Outside management mode a deactivated partner account must still fail the
// post-mint recheck: deactivation is reachable through the partner-user
// routes, and the recheck must distinguish an inactive record from an absent
// one instead of treating both as "no partner record".
func TestPersonalKeyMintRevokedForDeactivatedAccountOutsideManagement(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	inactive := false
	if _, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "carol", Active: &inactive}); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{UserHeader: "X-User", GroupsHeader: "X-Groups"}
	revokes := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"deactivated","key":"fixture-only-key"}`))
		case http.MethodDelete:
			revokes++
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer upstream.Close()
	h := NewAdminHandler(nil, maasapi.NewClient(upstream.URL, ""), cfg)
	h.SetStore(store)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/me/keys", strings.NewReader(`{"name":"Deactivated mint"}`))
	r.Header.Set("X-User", "carol")
	r.Header.Set("X-Groups", `["team-a"]`)
	w := httptest.NewRecorder()
	h.HandleMyKeys(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "fixture-only-key") {
		t.Fatal("revoked key secret was disclosed")
	}
	if revokes != 1 {
		t.Fatalf("revokes=%d want 1", revokes)
	}
}
