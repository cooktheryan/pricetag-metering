package handler

import (
	"net/http"
	"strings"

	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/maasapi"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

// NewManagementKeysHandler is protected by RequireManagement. It issues an
// onboarding key as the selected user, never as the operator's MaaS identity.
func NewManagementKeysHandler(store *storage.Store, cfg config.Config, maas *maasapi.Client) http.HandlerFunc {
	slots := make(chan struct{}, partnerMintConcurrency)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		if cfg.PartnerUserKeyGroup == "" {
			http.Error(w, "key group not configured", 503)
			return
		}
		var body struct {
			Subject   string `json:"subject"`
			Name      string `json:"name"`
			ExpiresIn string `json:"expiresIn"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		if strings.TrimSpace(body.Name) == "" || len(body.Name) > 128 || body.ExpiresIn == "" || len(body.ExpiresIn) > 64 {
			http.Error(w, "name and finite lifetime are required", 400)
			return
		}
		user, err := store.PartnerUserByMaaSUsername(r.Context(), body.Subject)
		if err != nil || !user.Active || user.KeyRevocationPending {
			http.Error(w, "active user required", 409)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "key issuance busy", 429)
			return
		}
		expiry, err := NewAdminHandler(nil, nil, cfg).validatedExpiry(body.ExpiresIn)
		if err != nil || expiry == "" {
			http.Error(w, "invalid finite lifetime", 400)
			return
		}
		key, err := maas.CreateUserAPIKey(r.Context(), body.Subject, cfg.PartnerUserKeyGroup, maasapi.CreateKeyRequest{Name: body.Name, ExpiresIn: expiry})
		if err != nil {
			http.Error(w, "key service rejected issuance", 502)
			return
		}
		if err = store.RecordPartnerUserKey(r.Context(), r.Header.Get(cfg.UserHeader), user.UserID, key.ID, body.Subject, body.Name); err != nil {
			_, revokeErr := maas.RevokeUserAPIKey(r.Context(), key.ID, body.Subject, cfg.PartnerUserKeyGroup)
			if revokeErr != nil {
				http.Error(w, "key issuance failed; operator reconciliation required", 503)
				return
			}
			http.Error(w, "key issuance cancelled", 409)
			return
		}
		writeJSON(w, key)
	}
}

// NewManagementKeyRevocationsHandler is administrator-only via RequireManagement.
// Every login attached to the selected stable identity is covered, even after
// suspension. MaaS revokes
// each login atomically; a partial upstream failure is explicit and safely retryable.
func NewManagementKeyRevocationsHandler(store *storage.Store, cfg config.Config, maas *maasapi.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		var body struct {
			Subject string `json:"subject"`
			DryRun  bool   `json:"dry_run"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		if strings.TrimSpace(body.Subject) == "" || len(body.Subject) > 128 {
			http.Error(w, "invalid subject", 400)
			return
		}
		user, err := store.ManagedUserByLogin(r.Context(), body.Subject)
		if err != nil {
			http.Error(w, "user not found", 404)
			return
		}
		logins, err := store.ListPartnerUsernames(r.Context(), user.UserID)
		if err != nil || len(logins) == 0 {
			http.Error(w, "user logins unavailable", 503)
			return
		}
		if !body.DryRun {
			if err := store.Audit(r.Context(), r.Header.Get(cfg.UserHeader), "partner_user.keys_revoke_requested", user.UserID, map[string]any{"logins": logins}); err != nil {
				http.Error(w, "revocation audit unavailable", 503)
				return
			}
		}
		total := 0
		for _, login := range logins {
			count, err := maas.RevokeAllUserAPIKeys(r.Context(), login, cfg.PartnerUserKeyGroup, body.DryRun)
			if err != nil {
				http.Error(w, "key service failed; revocation may be partial, retry this user", 502)
				return
			}
			total += count
		}
		if !body.DryRun {
			if err := store.Audit(r.Context(), r.Header.Get(cfg.UserHeader), "partner_user.keys_revoked", user.UserID, map[string]any{"count": total}); err != nil {
				http.Error(w, "keys revoked; audit completion unavailable", 503)
				return
			}
		}
		writeJSON(w, map[string]any{"count": total, "dry_run": body.DryRun})
	}
}
