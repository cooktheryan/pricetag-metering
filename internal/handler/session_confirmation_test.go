package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/redhat-et/pricetag-metering/internal/config"
)

func TestSessionConfirmationFallbackIsStyledAndEscapesTarget(t *testing.T) {
	h := NewAuthHandler(config.Config{ManagementAPISecret: "test", ManagementPublicOrigin: "https://gateway.example"})
	r := httptest.NewRequest("GET", "/admin/impersonate?as=%3Cimg%20src=x%20onerror=alert(1)%3E&to=/manager", nil)
	w := httptest.NewRecorder()
	if h.confirmSessionChange(w, r, "Change dashboard view") {
		t.Fatal("GET changed session")
	}
	body := w.Body.String()
	for _, content := range []string{"<style>", "Price", "Read-only", "&lt;img", `method="post"`} {
		if !strings.Contains(body, content) {
			t.Fatalf("missing %q", content)
		}
	}
	if strings.Contains(body, "<img") {
		t.Fatal("unescaped target")
	}
	if len(w.Result().Cookies()) != 0 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("confirmation must not mutate/cache session")
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("confirmation can be framed")
	}
	for _, tc := range []struct {
		method, origin, site string
		want                 int
	}{
		{"POST", "https://gateway.example", "cross-site", 403}, {"PUT", "https://gateway.example", "same-origin", 405},
	} {
		req := httptest.NewRequest(tc.method, r.URL.String(), nil)
		req.Header.Set("Origin", tc.origin)
		req.Header.Set("Sec-Fetch-Site", tc.site)
		response := httptest.NewRecorder()
		if h.confirmSessionChange(response, req, "Change dashboard view") || response.Code != tc.want {
			t.Fatal("unsafe confirmation accepted")
		}
	}
}

func TestSessionDialogIncludedOnlyInManagedDashboards(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		cfg := config.Config{}
		if enabled {
			cfg.ManagementAPISecret = "test"
		}
		admin := NewAdminHandler(nil, nil, cfg)
		for name, serve := range map[string]http.HandlerFunc{
			"account": NewAccountHandler(cfg).ServeAccount,
			"admin":   admin.ServeAdmin, "routing": admin.ServeRouting,
			"dashboard": NewDashboardHandler(nil, cfg).ServeDashboard,
			"manager":   NewPartnerOrgHandler(nil, cfg).ServeManager,
		} {
			w := httptest.NewRecorder()
			serve(w, httptest.NewRequest("GET", "/"+name, nil))
			if strings.Contains(w.Body.String(), `id="session-view-dialog"`) != enabled {
				t.Fatalf("%s dialog enabled=%v", name, enabled)
			}
		}
	}
}
