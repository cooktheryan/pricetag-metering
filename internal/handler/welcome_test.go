package handler

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/redhat-et/pricetag-metering/internal/config"
)

func TestServeWelcomeSubstitution(t *testing.T) {
	h := NewDashboardHandler(nil, config.Config{
		Welcome: config.Welcome{
			GatewayURL:   "https://gateway.test",
			DashboardURL: "https://dash.test",
		},
		MonthlyTokenQuota: 10_000_000_000,
	})
	req := httptest.NewRequest(http.MethodGet, "https://dashboard.test/welcome", nil)
	rec := httptest.NewRecorder()
	h.ServeWelcome(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"https://gateway.test",
		"https://dash.test",
		"10B monthly allowance",
		"Inferact/Qwen3.8-Flash-Next-NVFP4",
		"rits/zai-org/glm-5-3",
		"GLM 5.3",
		"free: $0 for every token type",
		"effortLevel",
		"Set up Hermes CLI",
		"~/.hermes/config.yaml",
		"opencode-enmaas",
		"XDG_CONFIG_HOME",
		"gpt-5.6-luna",
		"/v1/messages",
		"/v1/chat/completions",
		"/v1/responses",
		"https://gateway.test/v1",
		"anthropic-version",
		"matching API's model-list envelope",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	// Configured URLs must suppress the example fallbacks, and no
	// placeholder may survive substitution.
	for _, absent := range []string{"gateway.example.com", "{{"} {
		if strings.Contains(body, absent) {
			t.Errorf("page unexpectedly contains %q", absent)
		}
	}
}

var anyPlaceholder = regexp.MustCompile(`\{\{[A-Z_]+\}\}`)

func TestServeWelcomeFallbacks(t *testing.T) {
	h := NewDashboardHandler(nil, config.Config{MonthlyTokenQuota: 100_000_000})
	req := httptest.NewRequest(http.MethodGet, "https://dashboard.test/welcome", nil)
	rec := httptest.NewRecorder()
	h.ServeWelcome(rec, req)

	body := rec.Body.String()
	if m := anyPlaceholder.FindString(body); m != "" {
		t.Errorf("unsubstituted placeholder %s in served page", m)
	}
	for _, want := range []string{
		welcomeGatewayFallback, welcomeDashboardFallback,
		"100M monthly allowance",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("fallback page missing %q", want)
		}
	}
}

func TestServeWelcomeFallbackIgnoresForwardedOrigin(t *testing.T) {
	h := NewDashboardHandler(nil, config.Config{MonthlyTokenQuota: 100_000_000})
	req := httptest.NewRequest(http.MethodGet, "https://attacker.example/welcome", nil)
	req.Host = `evil.example"><script>alert(1)</script>`
	req.Header.Set("X-Forwarded-Proto", `javascript:alert(1)//`)
	rec := httptest.NewRecorder()
	h.ServeWelcome(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, welcomeDashboardFallback) {
		t.Fatalf("fallback page missing trusted dashboard fallback %q", welcomeDashboardFallback)
	}
	for _, forbidden := range []string{"attacker.example", "evil.example", "javascript:alert"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("fallback page contains request-controlled value %q", forbidden)
		}
	}
}

func TestServeWelcomeEscapesConfiguredURLs(t *testing.T) {
	h := NewDashboardHandler(nil, config.Config{Welcome: config.Welcome{
		GatewayURL:   `https://gateway.test/?q="<script>`,
		DashboardURL: `https://dashboard.test/?q="<script>`,
	}})
	rec := httptest.NewRecorder()
	h.ServeWelcome(rec, httptest.NewRequest(http.MethodGet, "https://dashboard.test/welcome", nil))

	body := rec.Body.String()
	for _, raw := range []string{`https://gateway.test/?q="`, `https://dashboard.test/?q="`} {
		if strings.Contains(body, raw) {
			t.Fatalf("configured URL was inserted as raw HTML: %q", raw)
		}
	}
	for _, escaped := range []string{"&#34;", "&lt;script&gt;"} {
		if !strings.Contains(body, escaped) {
			t.Errorf("escaped configured URL missing %q", escaped)
		}
	}
}

func TestQuotaLabel(t *testing.T) {
	cases := map[float64]string{
		10_000_000_000: "10B",
		100_000_000:    "100M",
		1_500_000:      "1.5M",
		20_000:         "20K",
		999:            "999",
	}
	for in, want := range cases {
		if got := quotaLabel(in); got != want {
			t.Errorf("quotaLabel(%v) = %q, want %q", in, got, want)
		}
	}
}
