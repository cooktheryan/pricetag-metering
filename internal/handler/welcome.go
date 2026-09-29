package handler

import (
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	"github.com/redhat-et/pricetag-metering/internal/dashboard"
)

// The gateway fallback remains a visible local-development placeholder. The
// dashboard fallback is derived from the request host because welcome and
// dashboard are served by the same application and therefore share an origin.
const (
	welcomeGatewayFallback = "https://gateway.example.com"
)

func requestOrigin(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = "http"
		if r.TLS != nil {
			scheme = "https"
		}
	}
	if r.Host == "" {
		return ""
	}
	return scheme + "://" + r.Host
}

// ServeWelcome renders the public onboarding page. It is intentionally
// unauthenticated — it is what you send to a new user before they have a
// key. The page template carries {{...}} placeholders instead of cluster
// hosts; the real endpoints are substituted here, at serve time, from the
// deployment environment (config.Welcome), so no cluster-specific URL ever
// enters the repository.
func (h *DashboardHandler) ServeWelcome(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(dashboard.FS, "welcome.html")
	if err != nil {
		http.Error(w, "welcome page not found", http.StatusInternalServerError)
		return
	}
	gateway := h.cfg.Welcome.GatewayURL
	if gateway == "" {
		gateway = welcomeGatewayFallback
	}
	dash := h.cfg.Welcome.DashboardURL
	if dash == "" {
		dash = requestOrigin(r)
		if dash == "" {
			dash = welcomeGatewayFallback
		}
	}
	page := strings.NewReplacer(
		"{{GATEWAY_URL}}", gateway,
		"{{DASHBOARD_URL}}", dash,
		"{{QUOTA_LABEL}}", quotaLabel(h.cfg.MonthlyTokenQuota),
	).Replace(string(data))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write([]byte(page))
}

// quotaLabel renders a token quota compactly for the welcome page prose:
// 10000000000 -> "10B", 100000000 -> "100M".
func quotaLabel(q float64) string {
	var v float64
	var suffix string
	switch {
	case q >= 1e9:
		v, suffix = q/1e9, "B"
	case q >= 1e6:
		v, suffix = q/1e6, "M"
	case q >= 1e3:
		v, suffix = q/1e3, "K"
	default:
		v, suffix = q, ""
	}
	s := strconv.FormatFloat(v, 'f', -1, 64)
	if s == "" {
		s = "0"
	}
	return s + suffix
}
