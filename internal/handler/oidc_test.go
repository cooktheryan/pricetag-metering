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
