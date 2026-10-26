package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/redhat-et/pricetag-metering/internal/config"
)

func TestOIDCStateCookieRoundTripAndTamperProtection(t *testing.T) {
	t.Setenv("SESSION_SECRET", "test-session-secret")
	h := NewAuthHandler(config.Config{})
	state := oidcState{
		State: "state", Nonce: "nonce", CodeVerifier: "verifier",
		Exp: time.Now().Add(time.Minute).Unix(),
	}
	response := httptest.NewRecorder()
	if err := h.setOIDCState(response, state); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/oauth/callback?state=state", nil)
	request.AddCookie(response.Result().Cookies()[0])
	got, err := h.readOIDCState(request)
	if err != nil {
		t.Fatal(err)
	}
	if got != state {
		t.Fatalf("state = %+v, want %+v", got, state)
	}

	tampered := *response.Result().Cookies()[0]
	tampered.Value += "x"
	tamperedRequest := httptest.NewRequest(http.MethodGet, "/oauth/callback?state=state", nil)
	tamperedRequest.AddCookie(&tampered)
	if _, err := h.readOIDCState(tamperedRequest); err == nil {
		t.Fatal("tampered state cookie was accepted")
	}
}

func TestOIDCLoginIsUnavailableWhenDisabled(t *testing.T) {
	h := NewAuthHandler(config.Config{})
	response := httptest.NewRecorder()
	h.HandleOIDCLogin(response, httptest.NewRequest(http.MethodGet, "/oauth/login", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

// newTestOIDCHandler starts a minimal discovery document so InitOIDC succeeds.
// The token and JWKS endpoints are never called by these tests.
func newTestOIDCHandler(t *testing.T, testLogin bool) *AuthHandler {
	t.Helper()
	provider := httptest.NewServer(nil)
	provider.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"` + provider.URL + `","authorization_endpoint":"` + provider.URL + `/authorize","token_endpoint":"` + provider.URL + `/token","jwks_uri":"` + provider.URL + `/jwks"}`))
	})
	t.Cleanup(provider.Close)

	h := NewAuthHandler(config.Config{OIDC: config.OIDC{
		Enabled: true, TestLogin: testLogin,
		IssuerURL: provider.URL, ClientID: "client",
		ClientSecret: "secret", RedirectURL: "https://dashboard.example/oauth/callback",
		Scopes: []string{"openid", "profile", "email", "groups"},
	}})
	if err := h.InitOIDC(context.Background()); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestOIDCLoginForwardsPersonaOnlyWhenTestLoginEnabled(t *testing.T) {
	tests := []struct {
		name      string
		testLogin bool
		query     string
		wantHint  bool
	}{
		{name: "test login enabled", testLogin: true, query: "?persona=new-user", wantHint: true},
		{name: "test login disabled", testLogin: false, query: "?persona=new-user", wantHint: false},
		{name: "invalid persona ignored", testLogin: true, query: "?persona=NEW%20USER", wantHint: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestOIDCHandler(t, tc.testLogin)
			response := httptest.NewRecorder()
			h.HandleOIDCLogin(response, httptest.NewRequest(http.MethodGet, "/oauth/login"+tc.query, nil))
			if response.Code != http.StatusFound {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusFound)
			}
			location := response.Header().Get("Location")
			hasHint := strings.Contains(location, "login_hint=")
			if hasHint != tc.wantHint {
				t.Fatalf("login_hint present = %v, want %v: %s", hasHint, tc.wantHint, location)
			}
			if tc.wantHint && !strings.Contains(location, "login_hint=new-user") {
				t.Fatalf("authorization URL missing persona hint: %s", location)
			}
		})
	}
}

func TestLoginPageTestPanelDoesNotChangeSSOLink(t *testing.T) {
	const ssoLink = `<a class="sso-button" href="/oauth/login">Sign in with Red Hat SSO</a>`

	enabled := newTestOIDCHandler(t, true)
	response := httptest.NewRecorder()
	enabled.HandleLogin(response, httptest.NewRequest(http.MethodGet, "/login", nil))
	body := response.Body.String()
	if !strings.Contains(body, ssoLink) {
		t.Fatalf("SSO link changed or missing from login page:\n%s", body)
	}
	if !strings.Contains(body, "Test sign-in") || !strings.Contains(body, "/oauth/login?persona=new-user") {
		t.Fatalf("test-login panel missing when enabled:\n%s", body)
	}
	if strings.Contains(body, "<!-- TEST_LOGIN -->") {
		t.Fatal("test-login placeholder was not replaced")
	}

	disabled := newTestOIDCHandler(t, false)
	response = httptest.NewRecorder()
	disabled.HandleLogin(response, httptest.NewRequest(http.MethodGet, "/login", nil))
	body = response.Body.String()
	if !strings.Contains(body, ssoLink) {
		t.Fatalf("SSO link changed or missing from login page:\n%s", body)
	}
	if strings.Contains(body, "Test sign-in") || strings.Contains(body, "<!-- TEST_LOGIN -->") {
		t.Fatalf("test-login panel leaked when disabled:\n%s", body)
	}
}

func TestOIDCLoginBuildsAuthorizationCodePKCERequest(t *testing.T) {
	t.Setenv("SESSION_SECRET", "test-session-secret")
	provider := httptest.NewServer(nil)
	provider.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"` + provider.URL + `","authorization_endpoint":"` + provider.URL + `/authorize","token_endpoint":"` + provider.URL + `/token","jwks_uri":"` + provider.URL + `/jwks"}`))
	})
	defer provider.Close()

	h := NewAuthHandler(config.Config{OIDC: config.OIDC{
		Enabled: true, IssuerURL: provider.URL, ClientID: "client",
		ClientSecret: "secret", RedirectURL: "https://dashboard.example/oauth/callback",
		Scopes: []string{"openid", "profile", "email", "groups"},
	}})
	if err := h.InitOIDC(context.Background()); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	h.HandleOIDCLogin(response, httptest.NewRequest(http.MethodGet, "/oauth/login", nil))
	if response.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusFound)
	}
	location := response.Header().Get("Location")
	for _, required := range []string{"client_id=client", "redirect_uri=", "code_challenge=", "code_challenge_method=S256", "nonce=", "state="} {
		if !strings.Contains(location, required) {
			t.Fatalf("authorization URL missing %q: %s", required, location)
		}
	}
	if len(response.Result().Cookies()) != 1 || response.Result().Cookies()[0].Name != oidcStateCookie {
		t.Fatalf("expected signed OIDC state cookie, got %v", response.Result().Cookies())
	}
}
