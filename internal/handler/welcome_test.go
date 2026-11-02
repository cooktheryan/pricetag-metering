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
		Welcome: config.Welcome{GatewayURL: "https://gateway.test"},
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
		"Welcome to",
		"MaaS User Guide",
		"Claude Code",
		"Codex",
		"OpenCode",
		"Pi",
		"What you need",
		"Make a test request",
		"Find a supported model",
		"MAAS_BASE_URL",
		"MAAS_API_KEY",
		"MAAS_MODEL",
		"your-maas-host.example",
		"https://gateway.test/v1",
		"/chat/completions",
		"/models",
		"Replace them with details from your service provider.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if strings.Contains(body, "{{") {
		t.Errorf("page contains unsubstituted placeholder")
	}
	if strings.Contains(body, "Current status") {
		t.Errorf("page still contains removed Current status section")
	}
	for _, url := range regexp.MustCompile(`https?://[^"'\s]+`).FindAllString(body, -1) {
		allowed := false
		for _, origin := range []string{
			"https://gateway.test",
			"https://your-maas-host.example",
			"https://fonts.googleapis.com",
			"https://fonts.gstatic.com",
		} {
			if url == origin || strings.HasPrefix(url, origin+"/") {
				allowed = true
				break
			}
		}
		if !allowed {
			t.Errorf("public welcome page contains an unexpected URL %q", url)
		}
	}
}

var anyPlaceholder = regexp.MustCompile(`\{\{[A-Z_]+\}\}`)

func TestServeWelcomeFallbacks(t *testing.T) {
	h := NewDashboardHandler(nil, config.Config{})
	req := httptest.NewRequest(http.MethodGet, "https://dashboard.test/welcome", nil)
	rec := httptest.NewRecorder()
	h.ServeWelcome(rec, req)

	body := rec.Body.String()
	if m := anyPlaceholder.FindString(body); m != "" {
		t.Errorf("unsubstituted placeholder %s in served page", m)
	}
	for _, want := range []string{welcomeGatewayFallback} {
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
	if !strings.Contains(body, welcomeGatewayFallback) {
		t.Fatalf("fallback page missing trusted gateway fallback %q", welcomeGatewayFallback)
	}
	for _, forbidden := range []string{"attacker.example", "evil.example", "javascript:alert"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("fallback page contains request-controlled value %q", forbidden)
		}
	}
}

func TestServeWelcomeEscapesConfiguredURLs(t *testing.T) {
	h := NewDashboardHandler(nil, config.Config{Welcome: config.Welcome{
		GatewayURL: `https://gateway.test/?q="<script>`,
	}})
	rec := httptest.NewRecorder()
	h.ServeWelcome(rec, httptest.NewRequest(http.MethodGet, "https://dashboard.test/welcome", nil))

	body := rec.Body.String()
	for _, raw := range []string{`https://gateway.test/?q="`} {
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
