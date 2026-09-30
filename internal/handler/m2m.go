package handler

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/redhat-et/pricetag-metering/internal/config"
)

const bearerPrefix = "Bearer "

// RequireM2MAuth protects the gateway-to-metering endpoints when the
// deployment enables M2M_AUTH_REQUIRED. It is deliberately opt-in so local
// development and existing gateways keep working until the gateway-side
// credential injection is deployed at the same time.
func RequireM2MAuth(cfg config.Config, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !cfg.M2MAuthRequired {
			next(w, r)
			return
		}

		header := r.Header.Get("Authorization")
		provided := ""
		if strings.HasPrefix(header, bearerPrefix) {
			provided = strings.TrimSpace(strings.TrimPrefix(header, bearerPrefix))
		}
		if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(cfg.M2MSharedSecret)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// RequirePartnerAPIAuth always authenticates partner-facing APIs, even when
// legacy gateway M2M authentication remains disabled for compatibility. An
// unset secret leaves the endpoint unavailable rather than exposing user
// usage data.
func RequirePartnerAPIAuth(secret string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if secret == "" {
			http.Error(w, "partner API authentication is not configured", http.StatusServiceUnavailable)
			return
		}

		header := r.Header.Get("Authorization")
		provided := ""
		if strings.HasPrefix(header, bearerPrefix) {
			provided = strings.TrimSpace(strings.TrimPrefix(header, bearerPrefix))
		}
		if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(secret)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}
