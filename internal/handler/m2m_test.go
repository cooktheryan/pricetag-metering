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

func TestRequirePartnerAPIAuthFailsClosedWithoutSecret(t *testing.T) {
	h := RequirePartnerAPIAuth("", func(http.ResponseWriter, *http.Request) {
		t.Fatal("partner handler should not be reached")
	})
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func TestRequirePartnerAPIAuthRejectsMissingAndWrongBearer(t *testing.T) {
	h := RequirePartnerAPIAuth("secret", func(http.ResponseWriter, *http.Request) {
		t.Fatal("partner handler should not be reached")
	})
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

func TestRequirePartnerAPIAuthAcceptsBearerSecret(t *testing.T) {
	reached := false
	h := RequirePartnerAPIAuth("secret", func(http.ResponseWriter, *http.Request) { reached = true })
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer secret")
	h(httptest.NewRecorder(), req)
	if !reached {
		t.Fatal("valid partner bearer secret did not reach the handler")
	}
}

func TestRequirePartnerAPIAuthAnyAcceptsConfiguredPartner(t *testing.T) {
	reached := false
	h := RequirePartnerAPIAuthAny([]string{"legacy", "air", "aibt"}, func(http.ResponseWriter, *http.Request) { reached = true })
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer air")
	h(httptest.NewRecorder(), req)
	if !reached {
		t.Fatal("configured additional partner bearer did not reach the handler")
	}
}

func TestRequireM2MAuthStrictFailsClosedWhenUnconfigured(t *testing.T) {
	h := RequireM2MAuthStrict(config.Config{}, func(http.ResponseWriter, *http.Request) {
		t.Fatal("request should be rejected")
	})
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/api/v2/policy/decide", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestRequireM2MAuthStrictRequiresBearerEvenWhenGlobalBypassIsOff(t *testing.T) {
	cfg := config.Config{M2MSharedSecret: "s3cret", M2MAuthRequired: false}
	reached := false
	h := RequireM2MAuthStrict(cfg, func(http.ResponseWriter, *http.Request) { reached = true })

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/api/v2/policy/decide", nil))
	if rec.Code != http.StatusUnauthorized || reached {
		t.Fatalf("missing bearer: status = %d reached = %v", rec.Code, reached)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v2/policy/decide", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rec = httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK || !reached {
		t.Fatalf("valid bearer: status = %d reached = %v", rec.Code, reached)
	}
}
