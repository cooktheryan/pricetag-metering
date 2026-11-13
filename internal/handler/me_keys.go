package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/redhat-et/pricetag-metering/internal/maasapi"
	"github.com/redhat-et/pricetag-metering/internal/metrics"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

// Self-service key endpoints. They are deliberately separate from
// /api/v1/admin/keys: the admin surface accepts a target username, this one
// derives everything from the signed session and can never mint for someone
// else. The MaaS identity headers come from that derived identity.

func (h *AdminHandler) HandleMyKeys(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if h.maasClient == nil {
		http.Error(w, "key service is not configured", http.StatusServiceUnavailable)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/me/keys")
	if path == r.URL.Path {
		// Legacy alias: the old /me/keys proxy forwarded raw upstream calls.
		// Route it through the same self-scoped, validated handler instead.
		path = strings.TrimPrefix(r.URL.Path, "/me/keys")
	}
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
// user with several groups is scoped to the first group that the live
// MaaSSubscription lists. Group MEMBERSHIP is not revalidated here: the
// groups come from the signed session (IdP assertion at login) and are only
// intersected with the subscription's group list, so an IdP removal takes
// effect when the session expires. See docs/oidc-rollout.md.
func (h *AdminHandler) myKeyIdentity(w http.ResponseWriter, r *http.Request) (username, group string, groups []string, ok bool) {
	username = strings.TrimSpace(caller(r, h.cfg))
	if username == "" {
		http.Error(w, "who are you?", http.StatusUnauthorized)
		return "", "", nil, false
	}
	if h.cfg.ManagementAPISecret != "" {
		// Standalone keys always use the operator-configured unprivileged
		// group, never a stale administrator group from the browser session.
		if h.store == nil || h.cfg.PartnerUserKeyGroup == "" {
			http.Error(w, "personal key management unavailable", http.StatusServiceUnavailable)
			return "", "", nil, false
		}
		profile, err := h.store.PartnerUserByMaaSUsername(r.Context(), username)
		if err != nil || !profile.Active || profile.KeyRevocationPending {
			http.Error(w, "active account required", http.StatusForbidden)
			return "", "", nil, false
		}
		group = h.cfg.PartnerUserKeyGroup
		return username, group, []string{group}, true
	}
	groups = NormalizeGroups(sessionGroups(r, h.cfg))
	if len(groups) == 0 {
		http.Error(w, "your session has no EnMaaS group; sign in again", http.StatusForbidden)
		return "", "", nil, false
	}
	group = groups[0]
	// Prefer a group that the cluster's MaaSSubscription actually lists. When
	// the platform list is available, a session group that is not on it must
	// not fall through: that would let a forged/stale header scope a key.
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
			http.Error(w, "your session has no EnMaaS group enabled for key management", http.StatusForbidden)
			return "", "", nil, false
		}
	}
	return username, group, groups, true
}

// matchSessionGroup returns the session-cased group that equals requested, or
// an empty string when the caller is not a member. Case-insensitive matching
// preserves the platform's canonical spelling for the X-MaaS-Group header.
func matchSessionGroup(groups []string, requested string) string {
	for _, g := range groups {
		if strings.EqualFold(g, requested) {
			return g
		}
	}
	return ""
}

// keyGroupEnabled applies the live MaaSSubscription allow-list when it is
// available. A missing/unreadable list keeps the legacy behavior; the
// application-level session membership check still applies.
func (h *AdminHandler) keyGroupEnabled(ctx context.Context, group string) bool {
	if h.k8sClient == nil {
		return true
	}
	platform, err := h.platformGroups(ctx)
	if err != nil || len(platform) == 0 {
		return true
	}
	for _, pg := range platform {
		if strings.EqualFold(group, pg) {
			return true
		}
	}
	return false
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
	owned := []maasapi.APIKeyResponse{}
	for _, key := range keys {
		if key.Username == username {
			key.Key = "" // One-time secrets must never be re-exposed by a list.
			owned = append(owned, key)
		}
	}
	writeJSON(w, map[string]any{"data": owned})
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
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if dec.Decode(new(any)) != io.EOF {
		http.Error(w, "expected one JSON object", http.StatusBadRequest)
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || len(body.Name) > 64 {
		http.Error(w, "key name is required (max 64 characters)", http.StatusBadRequest)
		return
	}
	if body.Group != "" {
		matched := matchSessionGroup(groups, body.Group)
		if matched == "" {
			http.Error(w, "you are not a member of that group", http.StatusForbidden)
			return
		}
		if !h.keyGroupEnabled(r.Context(), matched) {
			http.Error(w, "that group is not enabled for key management", http.StatusForbidden)
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
		Labels:    map[string]string{"created_by": "pricetag-dashboard"},
	})
	if err != nil {
		// The MaaS error body is not echoed: it can contain request context.
		slog.Error("self-service key create failed", "user", username, "error", err)
		http.Error(w, "could not create the key; try again", http.StatusBadGateway)
		return
	}
	metrics.KeysMintedTotal.Inc()
	if h.store != nil {
		// The identity check above does not lock the account; a deactivation
		// can commit while the mint is in flight. Re-check and revoke a key
		// that slipped past the revocation sweep rather than hand out a live
		// credential. This fails closed: an unreadable account state revokes
		// a freshly minted key the caller can simply re-request. Outside
		// management mode the identity check above derives identity from
		// session groups, and those deployments legitimately serve users
		// with no partner record; a missing record there is not a
		// deactivation. The state-returning lookup keeps deactivated and
		// revocation-pending accounts distinguishable from absent ones, so
		// the exception below can never cover them.
		profile, err := h.store.ManagedUserByLogin(r.Context(), username)
		noRecord := h.cfg.ManagementAPISecret == "" && errors.Is(err, storage.ErrPartnerUserNotFound)
		if !noRecord && (err != nil || !profile.Active || profile.KeyRevocationPending) {
			if result.ID != "" {
				cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
				defer cancel()
				status, revokeErr := h.maasClient.RevokeUserAPIKey(cleanupCtx, result.ID, username, group)
				if revokeErr != nil || status < 200 || status > 299 {
					slog.Error("post-mint revocation failed; operator reconciliation required",
						"user", username, "key_id", result.ID, "status", status, "error", revokeErr)
				}
			}
			http.Error(w, "account is no longer active; key revoked", http.StatusForbidden)
			return
		}
	}
	writeJSON(w, result)
}

// validatedExpiry enforces the deployment's key-expiry policy. The request
// may omit expiresIn (deployment default), or send a Go duration string.
func (h *AdminHandler) validatedExpiry(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "default") {
		hours := h.cfg.KeyPolicy.DefaultExpiryHours
		if hours <= 0 {
			hours = 90 * 24
		}
		if h.cfg.KeyPolicy.MaxExpiryHours > 0 && hours > h.cfg.KeyPolicy.MaxExpiryHours {
			return "", errText("default key lifetime exceeds the maximum allowed lifetime")
		}
		// Guard the integer conversion as well as the configured maximum.
		if hours > int((1<<63-1)/time.Hour) {
			return "", errText("default key lifetime is too large")
		}
		return (time.Duration(hours) * time.Hour).String(), nil
	}
	if strings.EqualFold(raw, "none") || raw == "0" {
		if !h.cfg.KeyPolicy.AllowNoExpiry {
			return "", errText("keys must expire; choose a duration")
		}
		return "", nil
	}
	// MaaS and the standalone CLI also accept whole days. Normalize before
	// applying the same maximum used for native Go durations.
	if strings.HasSuffix(raw, "d") {
		days, err := strconv.ParseInt(strings.TrimSuffix(raw, "d"), 10, 64)
		if err != nil || days <= 0 || days > (1<<63-1)/int64(24*time.Hour) {
			return "", errText("invalid day duration")
		}
		raw = (time.Duration(days) * 24 * time.Hour).String()
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return "", errText("expiresIn must be a positive Go duration such as 720h")
	}
	max := time.Duration(h.cfg.KeyPolicy.MaxExpiryHours) * time.Hour
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
	// MaaS administrator groups can act on other users' keys. This personal
	// endpoint must retain ownership checks even when the caller has that role.
	keys, err := h.maasClient.ListUserAPIKeys(r.Context(), username, group)
	if err != nil {
		http.Error(w, "could not verify key ownership", http.StatusBadGateway)
		return
	}
	owned := false
	for _, key := range keys {
		if key.ID == keyID && key.Username == username {
			owned = true
			break
		}
	}
	if !owned {
		http.Error(w, "key not found", http.StatusNotFound)
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
