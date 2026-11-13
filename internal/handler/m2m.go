package handler

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/redhat-et/pricetag-metering/internal/config"
)

const bearerPrefix = "Bearer "

// RequireM2MAuth protects gateway-to-metering APIs. Partner-facing APIs use
// RequirePartnerAPIAuth below so Service and port-forward access is protected
// independently of the edge.
func RequireM2MAuth(cfg config.Config, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !cfg.M2MAuthRequired {
			next(w, r)
			return
		}
		if !m2mBearerOK(r, cfg.M2MSharedSecret) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// RequireM2MAuthStrict is for decision endpoints that must never be
// unauthenticated. Unlike RequireM2MAuth it does not honor the global
// compatibility bypass: an unset secret fails closed.
func RequireM2MAuthStrict(cfg config.Config, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(cfg.M2MSharedSecret) == "" {
			http.Error(w, "machine-to-machine auth is not configured", http.StatusServiceUnavailable)
			return
		}
		if !m2mBearerOK(r, cfg.M2MSharedSecret) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func m2mBearerOK(r *http.Request, secret string) bool {
	header := r.Header.Get("Authorization")
	provided := ""
	if strings.HasPrefix(header, bearerPrefix) {
		provided = strings.TrimSpace(strings.TrimPrefix(header, bearerPrefix))
	}
	return provided != "" && subtle.ConstantTimeCompare([]byte(provided), []byte(secret)) == 1
}

// RequirePartnerAPIAuth protects one partner API with its endpoint-specific
// bearer secret. An unset secret fails closed: the endpoint is unavailable
// until deployment wiring is complete rather than accidentally unauthenticated.
func RequirePartnerAPIAuth(secret string, next http.HandlerFunc) http.HandlerFunc {
	return RequirePartnerAPIAuthAny([]string{secret}, next)
}

// RequirePartnerAPIAuthAny accepts the legacy endpoint secret plus optional
// additional least-privilege partner credentials. Every configured value is
// compared in constant time; an empty set fails closed with 503.
func RequirePartnerAPIAuthAny(secrets []string, next http.HandlerFunc) http.HandlerFunc {
	configured := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		if secret != "" {
			configured = append(configured, secret)
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if len(configured) == 0 {
			http.Error(w, "partner API authentication is not configured", http.StatusServiceUnavailable)
			return
		}
		header := r.Header.Get("Authorization")
		provided := ""
		if strings.HasPrefix(header, bearerPrefix) {
			provided = strings.TrimSpace(strings.TrimPrefix(header, bearerPrefix))
		}
		valid := false
		if provided != "" {
			for _, secret := range configured {
				if subtle.ConstantTimeCompare([]byte(provided), []byte(secret)) == 1 {
					valid = true
				}
			}
		}
		if !valid {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}
