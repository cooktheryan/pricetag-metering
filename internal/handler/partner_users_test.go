package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Key endpoints fail closed when no MaaS group is configured, before any
// store or MaaS access, so a deployment can never mint under a guessed group.
func TestPartnerKeyEndpointsRequireConfiguredGroup(t *testing.T) {
	h := NewPartnerUsersHandler(nil, nil, " ")
	const id = "/api/v1/users/123e4567-e89b-12d3-a456-426614174000"
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPost, id + "/keys", `{"name":"x"}`},
		{http.MethodGet, id + "/keys", ""},
		{http.MethodDelete, id + "/keys/k1", ""},
		{http.MethodDelete, id, ""},
	} {
		rec := httptest.NewRecorder()
		h.HandleUsers(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s = %d, want 503", tc.method, tc.path, rec.Code)
		}
	}
}

func TestPartnerActorHeader(t *testing.T) {
	for header, want := range map[string]string{
		"":                      "partner-m2m",
		"atlas":                 "partner-m2m:atlas",
		"aibh-refresh":          "partner-m2m:aibh-refresh",
		"Bad Value!":            "partner-m2m",
		strings.Repeat("a", 40): "partner-m2m",
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Partner-Client", header)
		if got := partnerActor(r); got != want {
			t.Fatalf("partnerActor(%q) = %q, want %q", header, got, want)
		}
	}
}

func TestPartnerUserResourceAllowHeaderIncludesPatch(t *testing.T) {
	h := NewPartnerUsersHandler(nil, nil, "GE")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/users/123e4567-e89b-12d3-a456-426614174000", nil)
	h.HandleUsers(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("OPTIONS user = %d, want 405", rec.Code)
	}
	if got, want := rec.Header().Get("Allow"), "GET, PUT, PATCH, DELETE"; got != want {
		t.Fatalf("Allow = %q, want %q", got, want)
	}
}
