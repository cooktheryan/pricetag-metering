package handler

import (
	"crypto/subtle"
	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/storage"
	"net/http"
	"strings"
)

// RequireBrowserOrigin protects cookie-authenticated mutations. The origin is
// deployment configuration, never inferred from caller-controlled proxy headers.
func RequireBrowserOrigin(origin string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
			if origin == "" || r.Header.Get("Origin") != origin || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				http.Error(w, "same-origin request required", http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}

// RequireManagement accepts a dedicated operator credential OR a super-admin
// browser session. It must never be used on inference or ordinary user routes.
func RequireManagement(cfg config.Config, store *storage.Store, auth func(http.HandlerFunc) http.HandlerFunc, next http.HandlerFunc) http.HandlerFunc {
	browser := auth(RequirePartnerSuperAdmin(cfg, store, RequireBrowserOrigin(cfg.ManagementPublicOrigin, next)))
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if cfg.ManagementAPISecret == "" {
			http.Error(w, "management API is not configured", 503)
			return
		}
		if raw := r.Header.Get("Authorization"); raw != "" {
			token := strings.TrimPrefix(raw, "Bearer ")
			if token == raw || subtle.ConstantTimeCompare([]byte(token), []byte(cfg.ManagementAPISecret)) != 1 {
				http.Error(w, "unauthorized", 401)
				return
			}
			r.Header.Set(cfg.UserHeader, "management-service")
			next(w, r)
			return
		}
		browser(w, r)
	}
}
