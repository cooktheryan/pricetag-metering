package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/redhat-et/pricetag-metering/internal/config"
)

func TestRequireM2MAuthDisabledPreservesCompatibility(t *testing.T) {
	reached := false
	h := RequireM2MAuth(config.Config{}, func(http.ResponseWriter, *http.Request) { reached = true })
	h(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !reached {
		t.Fatal("disabled M2M auth should pass through")
	}
}

func TestRequireM2MAuthRejectsMissingAndWrongBearer(t *testing.T) {
	cfg := config.Config{M2MAuthRequired: true, M2MSharedSecret: "secret"}
	h := RequireM2MAuth(cfg, func(http.ResponseWriter, *http.Request) { t.Fatal("request should be rejected") })

	for _, header := range []string{"", "Bearer wrong", "secret"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		w := httptest.NewRecorder()
		h(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("header %q: status = %d, want 401", header, w.Code)
		}
	}
}

func TestRequireM2MAuthAcceptsBearerSecret(t *testing.T) {
	reached := false
	cfg := config.Config{M2MAuthRequired: true, M2MSharedSecret: "secret"}
	h := RequireM2MAuth(cfg, func(http.ResponseWriter, *http.Request) { reached = true })
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer secret")
	h(httptest.NewRecorder(), req)
	if !reached {
		t.Fatal("valid bearer secret should pass")
	}
}

func TestRequirePartnerM2MAuthFailsClosedWithoutSecret(t *testing.T) {
	reached := false
	h := RequirePartnerM2MAuth(config.Config{}, func(http.ResponseWriter, *http.Request) { reached = true })
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	if reached {
		t.Fatal("partner handler reached without a configured secret")
	}
}

func TestRequirePartnerM2MAuthRejectsBadBearer(t *testing.T) {
	cfg := config.Config{M2MSharedSecret: "partner-secret"}
	h := RequirePartnerM2MAuth(cfg, func(http.ResponseWriter, *http.Request) { t.Fatal("handler should not be reached") })
	for _, header := range []string{"", "Bearer wrong", "partner-secret"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		w := httptest.NewRecorder()
		h(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("header %q: status = %d, want 401", header, w.Code)
		}
	}
}

func TestRequirePartnerM2MAuthAcceptsBearerSecret(t *testing.T) {
	reached := false
	cfg := config.Config{M2MSharedSecret: "partner-secret"}
	h := RequirePartnerM2MAuth(cfg, func(http.ResponseWriter, *http.Request) { reached = true })
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer partner-secret")
	h(httptest.NewRecorder(), req)
	if !reached {
		t.Fatal("valid partner bearer secret did not reach the handler")
	}
}
