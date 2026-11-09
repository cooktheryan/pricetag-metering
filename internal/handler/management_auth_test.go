package handler

import (
	"github.com/redhat-et/pricetag-metering/internal/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManagementBrowserOrigin(t *testing.T) {
	for _, tc := range []struct {
		origin, method string
		want           int
	}{
		{"", "POST", 403}, {"https://evil.invalid", "POST", 403}, {"null", "POST", 403},
		{"https://gateway.example", "POST", 204}, {"", "GET", 204},
	} {
		r := httptest.NewRequest(tc.method, "/api/v1/management/users", nil)
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		RequireBrowserOrigin("https://gateway.example", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })(w, r)
		if w.Code != tc.want {
			t.Fatalf("origin=%q method=%s got %d want %d", tc.origin, tc.method, w.Code, tc.want)
		}
	}
}

func TestManagementCredentialBoundary(t *testing.T) {
	for _, tc := range []struct {
		secret, header string
		want           int
	}{
		{"", "Bearer operator-test-secret", 503},
		{"operator-test-secret", "Bearer wrong", 401},
		{"operator-test-secret", "Basic operator-test-secret", 401},
		{"operator-test-secret", "Bearer operator-test-secret", 204},
		{"operator-test-secret", "", 401},
	} {
		cfg := config.Config{ManagementAPISecret: tc.secret, UserHeader: "X-User"}
		auth := func(next http.HandlerFunc) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) { http.Error(w, "session required", 401) }
		}
		h := RequireManagement(cfg, nil, auth, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-User") != "management-service" {
				t.Fatal("spoofed actor accepted")
			}
			w.WriteHeader(204)
		})
		r := httptest.NewRequest("PUT", "/api/v1/management/users", nil)
		r.Header.Set("Authorization", tc.header)
		r.Header.Set("X-User", "admin")
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != tc.want {
			t.Fatalf("got %d want %d", w.Code, tc.want)
		}
	}
}

func TestManagementSessionRequiresDirectory(t *testing.T) {
	cfg := config.Config{ManagementAPISecret: "operator-test-secret", UserHeader: "X-User"}
	h := NewAuthHandler(cfg)
	cookie := httptest.NewRecorder()
	h.setCookie(cookie, "alice", nil, "")
	r := httptest.NewRequest("GET", "/management", nil)
	r.AddCookie(cookie.Result().Cookies()[0])
	w := httptest.NewRecorder()
	h.RequireAuth(func(w http.ResponseWriter, r *http.Request) { t.Fatal("session accepted without directory") })(w, r)
	if w.Code != 503 {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestManagementLoginRejectsCrossOrigin(t *testing.T) {
	cfg := config.Config{ManagementAPISecret: "test-only", ManagementPublicOrigin: "https://gateway.example"}
	h := NewAuthHandler(cfg)
	for _, origin := range []string{"", "null", "https://attacker.invalid", "https://gateway.example"} {
		req := httptest.NewRequest("POST", "/login", nil)
		req.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		h.HandleLogin(w, req)
		want := http.StatusForbidden
		if origin == cfg.ManagementPublicOrigin {
			want = http.StatusFound
		}
		if w.Code != want {
			t.Fatalf("origin=%q status=%d want=%d", origin, w.Code, want)
		}
	}
}

func TestManagementSessionChangesRequireConfirmedSameOriginPost(t *testing.T) {
	t.Setenv("SESSION_SECRET", "test-session-secret")
	cfg := config.Config{ManagementAPISecret: "test", ManagementPublicOrigin: "https://gateway.example", SuperAdminUsers: []string{"admin"}}
	h := NewAuthHandler(cfg)
	issued := httptest.NewRecorder()
	h.setCookie(issued, "admin", nil, "")
	for _, operation := range []struct {
		path    string
		handler http.HandlerFunc
	}{
		{"/admin/impersonate?as=alice", h.HandleImpersonate}, {"/logout", h.HandleLogout},
	} {
		for _, tc := range []struct {
			method, origin string
			status         int
			changes        bool
		}{
			{"GET", "", 200, false}, {"POST", "", 403, false}, {"POST", "https://attacker.invalid", 403, false},
			{"POST", "https://gateway.example", 302, true},
		} {
			req := httptest.NewRequest(tc.method, operation.path, nil)
			req.AddCookie(issued.Result().Cookies()[0])
			req.Header.Set("Origin", tc.origin)
			w := httptest.NewRecorder()
			operation.handler(w, req)
			// This unit fixture deliberately has no account directory. A target
			// impersonation must fail closed even after a valid origin check.
			if strings.Contains(operation.path, "as=") && tc.status == 302 {
				tc.status = 503
				tc.changes = false
			}
			if w.Code != tc.status {
				t.Fatalf("%s %s status=%d want %d", tc.method, operation.path, w.Code, tc.status)
			}
			if (len(w.Result().Cookies()) > 0) != tc.changes {
				t.Fatal("unexpected session mutation")
			}
			if tc.method == "GET" && !strings.Contains(w.Body.String(), `method="post"`) {
				t.Fatal("confirmation form missing")
			}
		}
	}
}
