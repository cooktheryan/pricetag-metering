package handler

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/redhat-et/pricetag-metering/internal/maasapi"
	"github.com/redhat-et/pricetag-metering/internal/metrics"
)

// Self-service key endpoints. They are deliberately separate from
// /api/v1/admin/keys: the admin surface accepts a target username, this one
// derives everything from the signed session and can never mint for someone
// else. The MaaS identity headers come from that derived identity.

func (h *AdminHandler) HandleMyKeys(w http.ResponseWriter, r *http.Request) {
	if h.maasClient == nil {
		http.Error(w, "key service is not configured", http.StatusServiceUnavailable)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/me/keys")
	path = strings.TrimSuffix(path, "/")

	switch {
	case r.Method == http.MethodGet && path == "":
		h.myKeysList(w, r)
	case r.Method == http.MethodPost && path == "":
		h.myKeysCreate(w, r)
	case r.Method == http.MethodDelete && path != "":
		h.myKeysRevoke(w, r, strings.TrimPrefix(path, "/"))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// myKeyIdentity resolves the caller, their normalized groups, and the MaaS
// group to scope the request. MaaS requires one non-empty group header; a
// user with several groups is scoped to the first authorized one.
func (h *AdminHandler) myKeyIdentity(w http.ResponseWriter, r *http.Request) (username, group string, groups []string, ok bool) {
	username = strings.TrimSpace(caller(r, h.cfg))
	if username == "" {
		http.Error(w, "who are you?", http.StatusUnauthorized)
		return "", "", nil, false
	}
	groups = NormalizeGroups(sessionGroups(r, h.cfg))
	if len(groups) == 0 {
		http.Error(w, "your session has no EnMaaS group; sign in again", http.StatusForbidden)
		return "", "", nil, false
	}
	group = groups[0]
	// Prefer a group that the cluster's MaaSSubscription actually lists.
	if h.k8sClient != nil {
		if platform, err := h.platformGroups(r.Context()); err == nil && len(platform) > 0 {
			for _, g := range groups {
				for _, pg := range platform {
					if strings.EqualFold(g, pg) {
						group = pg
						return username, group, groups, true
					}
				}
			}
		}
	}
	return username, group, groups, true
}

func (h *AdminHandler) myKeysList(w http.ResponseWriter, r *http.Request) {
	username, group, _, ok := h.myKeyIdentity(w, r)
	if !ok {
		return
	}
	keys, err := h.maasClient.ListUserAPIKeys(r.Context(), username, group)
	if err != nil {
		slog.Error("self-service key list failed", "user", username, "error", err)
		http.Error(w, "could not load your keys", http.StatusBadGateway)
		return
	}
	if keys == nil {
		keys = []maasapi.APIKeyResponse{}
	}
	// The dev-login reset persona must look like a brand-new account. MaaS
	// keeps revoked keys for its own record, so hide them for this identity
	// only. Temporary scaffolding, removed with dev login.
	if devResetIdentity(r.Context(), h.cfg, h.store, username) {
		visible := make([]maasapi.APIKeyResponse, 0, len(keys))
		for _, key := range keys {
			switch strings.ToLower(strings.TrimSpace(key.Status)) {
			case "revoked", "expired":
				continue
			}
			visible = append(visible, key)
		}
		keys = visible
	}
	writeJSON(w, map[string]any{"data": keys})
}

func (h *AdminHandler) myKeysCreate(w http.ResponseWriter, r *http.Request) {
	username, group, groups, ok := h.myKeyIdentity(w, r)
	if !ok {
		return
	}
	var body struct {
		Name      string `json:"name"`
		Group     string `json:"group"`
		ExpiresIn string `json:"expiresIn"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || len(body.Name) > 64 {
		http.Error(w, "key name is required (max 64 characters)", http.StatusBadRequest)
		return
	}
	if body.Group != "" {
		matched := ""
		for _, g := range groups {
			if strings.EqualFold(g, body.Group) {
				matched = g
				break
			}
		}
		if matched == "" {
			http.Error(w, "you are not a member of that group", http.StatusForbidden)
			return
		}
		group = matched
	}

	expiresIn, err := h.validatedExpiry(body.ExpiresIn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result, err := h.maasClient.CreateUserAPIKey(r.Context(), username, group, maasapi.CreateKeyRequest{
		Name:      body.Name,
		ExpiresIn: expiresIn,
		Labels:    map[string]string{"created_by": "pricetag-onboarding"},
	})
	if err != nil {
		// The MaaS error body is not echoed: it can contain request context.
		slog.Error("self-service key create failed", "user", username, "error", err)
		http.Error(w, "could not create the key; try again", http.StatusBadGateway)
		return
	}
	metrics.KeysMintedTotal.Inc()
	writeJSON(w, result)
}

// validatedExpiry enforces the deployment's key-expiry policy. The request
// may omit expiresIn (deployment default), or send a Go duration string.
func (h *AdminHandler) validatedExpiry(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "default") {
		hours := h.cfg.Onboarding.DefaultKeyExpiryHours
		if hours <= 0 {
			hours = 90 * 24
		}
		return (time.Duration(hours) * time.Hour).String(), nil
	}
	if strings.EqualFold(raw, "none") || raw == "0" {
		if !h.cfg.Onboarding.AllowNoExpiry {
			return "", errText("keys must expire; choose a duration")
		}
		return "", nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return "", errText("expiresIn must be a positive Go duration such as 720h")
	}
	max := time.Duration(h.cfg.Onboarding.MaxKeyExpiryHours) * time.Hour
	if max > 0 && d > max {
		return "", errText("expiresIn exceeds the maximum allowed lifetime")
	}
	return d.String(), nil
}

func (h *AdminHandler) myKeysRevoke(w http.ResponseWriter, r *http.Request, keyID string) {
	username, group, _, ok := h.myKeyIdentity(w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(keyID) == "" {
		http.Error(w, "key id is required", http.StatusBadRequest)
		return
	}
	status, err := h.maasClient.RevokeUserAPIKey(r.Context(), keyID, username, group)
	if err != nil {
		slog.Error("self-service key revoke failed", "user", username, "error", err)
		http.Error(w, "could not revoke the key", http.StatusBadGateway)
		return
	}
	switch status {
	case http.StatusNotFound, http.StatusForbidden:
		http.Error(w, "key not found", http.StatusNotFound)
	case http.StatusNoContent, http.StatusOK:
		w.WriteHeader(http.StatusNoContent)
	default:
		if status >= 400 {
			http.Error(w, "could not revoke the key", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// errText keeps the error strings out of the handler's HTTP write path.
type errText string

func (e errText) Error() string { return string(e) }
