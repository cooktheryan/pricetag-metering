package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

// A renamed administrator must not be able to demote or suspend their own
// account by submitting one of their retained logins as the subject: the
// guard compares stable user IDs, not login spellings, because
// ProvisionLogin resolves a retained login back to the same account.
func TestManagementSelfDemotionGuardCoversRetainedLogins(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	admin, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "admin@old.example", Role: storage.PartnerRoleSuperAdmin})
	if err != nil {
		t.Fatal(err)
	}
	// Rename the administrator: the old spelling is retained on the account.
	if _, err := store.UpdatePartnerUser(t.Context(), "test", admin.UserID, map[string]any{
		"email": "admin@new.example", "first_name": "Admin", "last_name": "Example", "manager_uuid": nil,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "member@example"}); err != nil {
		t.Fatal(err)
	}
	inactive := false
	h := NewManagementHandler(store, config.Config{UserHeader: "X-User"})
	for _, tc := range []struct {
		name, subject, role string
		active              *bool
		want                int
	}{
		{"retained login deactivation", "admin@old.example", "", &inactive, 400},
		{"current login deactivation", "admin@new.example", "", &inactive, 400},
		{"retained login demotion", "admin@old.example", storage.PartnerRoleUser, nil, 400},
		{"case-variant self deactivation", "ADMIN@OLD.EXAMPLE", "", &inactive, 400},
		{"padded case-variant self demotion", " Admin@New.Example ", storage.PartnerRoleUser, nil, 400},
		{"another account deactivation", "member@example", "", &inactive, 200},
		{"benign self-update", "admin@new.example", "", nil, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"subject":"` + tc.subject + `","name":"Renamed"`
			if tc.role != "" {
				body += `,"role":"` + tc.role + `"`
			}
			if tc.active != nil {
				body += `,"active":` + boolString(*tc.active)
			}
			body += `}`
			r := httptest.NewRequest(http.MethodPut, "/api/v1/management/users", strings.NewReader(body))
			r.Header.Set("X-User", "admin@new.example")
			w := httptest.NewRecorder()
			h(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want %d body=%s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
