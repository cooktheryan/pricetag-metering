package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

func TestManagementEntitlementRequiresDirectory(t *testing.T) {
	h := NewEntitlementsHandler(nil, config.Config{ManagementAPISecret: "test-only"})
	w := httptest.NewRecorder()
	h.HandleEntitlement(w, httptest.NewRequest(http.MethodGet, "/customers/alice/entitlements", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestManagementEntitlementRejectsInactiveAndUnknownUsers(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	inactive := false
	if _, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "disabled", Active: &inactive}); err != nil {
		t.Fatal(err)
	}
	h := NewEntitlementsHandler(store, config.Config{ManagementAPISecret: "test-only"})
	for _, subject := range []string{"disabled", "unknown"} {
		w := httptest.NewRecorder()
		h.HandleEntitlement(w, httptest.NewRequest(http.MethodGet, "/customers/"+subject+"/entitlements?model=free-exception", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("subject=%s status=%d", subject, w.Code)
		}
		var result storage.UsageStats
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.HasAccess || result.ModelAllowed {
			t.Fatal("inactive or unknown account admitted")
		}
	}
}

func TestManagementUserListIncludesSuspendedProfiles(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	inactive := false
	profile, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "suspended", Active: &inactive})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	NewManagementHandler(store, config.Config{})(w, httptest.NewRequest(http.MethodGet, "/api/v1/management/users", nil))
	var users []struct {
		UserID string   `json:"user_id"`
		Active bool     `json:"active"`
		Logins []string `json:"logins"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &users); err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].UserID != profile.UserID || users[0].Active || len(users[0].Logins) != 1 || users[0].Logins[0] != "suspended" {
		t.Fatal("management list must retain the suspended profile and its login")
	}
}
