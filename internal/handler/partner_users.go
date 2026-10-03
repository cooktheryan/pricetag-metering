package handler

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/redhat-et/pricetag-metering/internal/maasapi"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

// partnerMintConcurrency bounds in-flight MaaS mints per replica so a burst
// (or a leaked credential) cannot exhaust the DB pool or MaaS. Mints hold no
// DB connection while waiting on MaaS; this bounds the goroutines and the
// MaaS load itself.
const partnerMintConcurrency = 4

// partnerActorPattern validates the optional X-Partner-Client header, which
// lets the audit trail distinguish callers that share one credential.
var partnerActorPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

type PartnerUsersHandler struct {
	store    *storage.Store
	maas     *maasapi.Client
	keyGroup string
	mints    chan struct{}
}

// NewPartnerUsersHandler wires the partner API. keyGroup is the MaaS group
// presented on every key operation; when empty, key endpoints answer 503 so a
// deployment cannot mint under an unintended group.
func NewPartnerUsersHandler(store *storage.Store, maas *maasapi.Client, keyGroup string) *PartnerUsersHandler {
	return &PartnerUsersHandler{store: store, maas: maas, keyGroup: strings.TrimSpace(keyGroup), mints: make(chan struct{}, partnerMintConcurrency)}
}

// actor returns the audit identity for a request: the validated
// X-Partner-Client value, or the shared default.
func partnerActor(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Partner-Client")); v != "" && partnerActorPattern.MatchString(v) {
		return "partner-m2m:" + v
	}
	return "partner-m2m"
}

func (h *PartnerUsersHandler) requireKeyGroup(w http.ResponseWriter) bool {
	if h.keyGroup == "" {
		http.Error(w, "partner key group is not configured", http.StatusServiceUnavailable)
		return false
	}
	return true
}

// HandleUsers serves authenticated partner CRUD, directory search, and
// per-user MaaS key minting at /api/v1/users[/{user_id}[/keys]].
func (h *PartnerUsersHandler) HandleUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	const prefix = "/api/v1/users"
	if r.URL.Path == prefix || r.URL.Path == prefix+"/" {
		h.handleCollection(w, r)
		return
	}
	if !strings.HasPrefix(r.URL.Path, prefix+"/") {
		http.NotFound(w, r)
		return
	}
	path := strings.TrimPrefix(r.URL.EscapedPath(), prefix+"/")
	parts := strings.Split(path, "/")
	userID, err := url.PathUnescape(parts[0])
	if err != nil || userID == "" || strings.Contains(userID, "/") {
		http.Error(w, "invalid user_id path segment", http.StatusBadRequest)
		return
	}
	if len(parts) == 2 && parts[1] == "keys" {
		h.handleKeys(w, r, userID)
		return
	}
	if len(parts) == 3 && parts[1] == "keys" {
		keyID, err := url.PathUnescape(parts[2])
		if err != nil || keyID == "" || strings.Contains(keyID, "/") {
			http.Error(w, "invalid key_id path segment", http.StatusBadRequest)
			return
		}
		h.handleKeyRevoke(w, r, userID, keyID)
		return
	}
	if len(parts) == 2 && parts[1] == "reactivate" {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		user, err := h.store.ReactivatePartnerUser(r.Context(), partnerActor(r), userID)
		if err != nil {
			h.userError(w, r, err)
			return
		}
		writeJSON(w, user)
		return
	}
	if len(parts) != 1 {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		user, err := h.store.GetPartnerUser(r.Context(), userID)
		if err != nil {
			h.userError(w, r, err)
			return
		}
		writeJSON(w, user)
	case http.MethodPut:
		var body struct {
			Tags map[string]any `json:"tags"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		if body.Tags == nil {
			http.Error(w, "tags is required", http.StatusBadRequest)
			return
		}
		// PUT is an upsert so an SSO front end can send the user's current
		// profile on every visit without a create-or-update round trip.
		user, err := h.store.UpdatePartnerUser(r.Context(), partnerActor(r), userID, body.Tags)
		if errors.Is(err, storage.ErrPartnerUserNotFound) {
			user, err = h.store.CreatePartnerUser(r.Context(), partnerActor(r), userID, body.Tags)
			if err == nil {
				w.Header().Set("Location", "/api/v1/users/"+user.UserID)
				w.WriteHeader(http.StatusCreated)
			}
		}
		if err != nil {
			h.userError(w, r, err)
			return
		}
		writeJSON(w, user)
	case http.MethodPatch:
		var body struct {
			Tags map[string]any `json:"tags"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		if body.Tags == nil {
			http.Error(w, "tags is required", http.StatusBadRequest)
			return
		}
		user, err := h.store.PatchPartnerUser(r.Context(), partnerActor(r), userID, body.Tags)
		if err != nil {
			h.userError(w, r, err)
			return
		}
		writeJSON(w, user)
	case http.MethodDelete:
		h.deactivate(w, r, userID)
	default:
		w.Header().Set("Allow", "GET, PUT, PATCH, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *PartnerUsersHandler) handleCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var body struct {
			UserID string         `json:"user_id"`
			Tags   map[string]any `json:"tags"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		if body.UserID == "" || body.Tags == nil {
			http.Error(w, "user_id and tags are required", http.StatusBadRequest)
			return
		}
		user, err := h.store.CreatePartnerUser(r.Context(), partnerActor(r), body.UserID, body.Tags)
		if err != nil {
			h.userError(w, r, err)
			return
		}
		w.Header().Set("Location", "/api/v1/users/"+user.UserID)
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, user)
	case http.MethodGet:
		query := r.URL.Query()
		filters := make(map[string]string)
		for key, values := range query {
			if strings.HasPrefix(key, "tag.") {
				if len(values) != 1 {
					http.Error(w, "each tag filter must have one value", http.StatusBadRequest)
					return
				}
				filters[strings.TrimPrefix(key, "tag.")] = values[0]
			}
		}
		limit, err := queryInt(query.Get("limit"), 50)
		if err != nil {
			http.Error(w, "limit must be an integer", http.StatusBadRequest)
			return
		}
		offset, err := queryInt(query.Get("offset"), 0)
		if err != nil {
			http.Error(w, "offset must be an integer", http.StatusBadRequest)
			return
		}
		includeInactive := false
		if raw := query.Get("include_inactive"); raw != "" {
			includeInactive, err = strconv.ParseBool(raw)
			if err != nil {
				http.Error(w, "include_inactive must be true or false", http.StatusBadRequest)
				return
			}
		}
		for key := range query {
			if key != "limit" && key != "offset" && key != "include_inactive" && !strings.HasPrefix(key, "tag.") {
				http.Error(w, "unsupported query parameter", http.StatusBadRequest)
				return
			}
		}
		page, err := h.store.ListPartnerUsers(r.Context(), filters, includeInactive, limit, offset)
		if err != nil {
			if errors.Is(err, storage.ErrInvalidPartnerUserQuery) {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			slog.Error("partner user list failed", "error", err)
			http.Error(w, "partner user list failed", http.StatusInternalServerError)
			return
		}
		if page.HasMore {
			nextQuery := query
			nextQuery.Set("offset", strconv.Itoa(offset+limit))
			nextURL := *r.URL
			nextURL.RawQuery = nextQuery.Encode()
			nextPage := nextURL.String()
			page.NextPage = &nextPage
		}
		writeJSON(w, page)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func queryInt(raw string, fallback int) (int, error) {
	if raw == "" {
		return fallback, nil
	}
	return strconv.Atoi(raw)
}

func (h *PartnerUsersHandler) handleKeys(w http.ResponseWriter, r *http.Request, userID string) {
	switch r.Method {
	case http.MethodGet:
		h.listKeys(w, r, userID)
	case http.MethodPost:
		h.mintKey(w, r, userID)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// listKeys returns the user's MaaS keys (every login ever mapped to the
// user), flagging which ones this API minted and therefore may revoke.
func (h *PartnerUsersHandler) listKeys(w http.ResponseWriter, r *http.Request, userID string) {
	if !h.requireKeyGroup(w) {
		return
	}
	user, err := h.store.GetPartnerUser(r.Context(), userID)
	if err != nil {
		h.userError(w, r, err)
		return
	}
	usernames, err := h.store.ListPartnerUsernames(r.Context(), user.UserID)
	if err != nil {
		h.userError(w, r, err)
		return
	}
	tracked, err := h.store.ListPartnerUserKeys(r.Context(), user.UserID)
	if err != nil {
		h.userError(w, r, err)
		return
	}
	minted := make(map[string]bool, len(tracked))
	for _, k := range tracked {
		minted[k.KeyID] = true
	}
	type keyView struct {
		maasapi.APIKeyResponse
		PartnerManaged bool `json:"partner_managed"`
	}
	keys := []keyView{}
	for _, username := range usernames {
		page, err := h.maas.ListUserAPIKeys(r.Context(), username, h.keyGroup)
		if err != nil {
			slog.Error("partner MaaS key list failed", "user_id", user.UserID, "error", err)
			http.Error(w, "MaaS key list failed", http.StatusBadGateway)
			return
		}
		for _, k := range page {
			k.Key = ""
			keys = append(keys, keyView{APIKeyResponse: k, PartnerManaged: minted[k.ID]})
		}
	}
	writeJSON(w, map[string]any{"user_id": user.UserID, "keys": keys})
}

// mintKey: check active (no lock) → MaaS mint (bounded, no DB connection
// held) → record in a short transaction that re-checks the user. If the user
// was deactivated in between, the fresh key is revoked before answering.
func (h *PartnerUsersHandler) mintKey(w http.ResponseWriter, r *http.Request, userID string) {
	if !h.requireKeyGroup(w) {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || len(body.Name) > 128 {
		http.Error(w, "name is required and must be at most 128 characters", http.StatusBadRequest)
		return
	}
	user, err := h.store.GetActivePartnerUser(r.Context(), userID)
	if err != nil {
		h.userError(w, r, err)
		return
	}
	email, ok := user.Tags["email"].(string)
	if !ok || email == "" {
		h.userError(w, r, storage.ErrInvalidPartnerUser)
		return
	}
	select {
	case h.mints <- struct{}{}:
		defer func() { <-h.mints }()
	default:
		w.Header().Set("Retry-After", "2")
		http.Error(w, "too many concurrent key mints; retry shortly", http.StatusTooManyRequests)
		return
	}
	actor := partnerActor(r)
	key, err := h.maas.CreateAPIKey(r.Context(), email, h.keyGroup, body.Name)
	if err != nil {
		slog.Error("partner MaaS key mint failed", "user_id", user.UserID, "error", err)
		http.Error(w, "MaaS key mint failed", http.StatusBadGateway)
		return
	}
	if err := h.store.RecordPartnerUserKey(r.Context(), actor, user.UserID, key.ID, email, body.Name); err != nil {
		// The key is live in MaaS but we cannot hand it out. Revoke it so it
		// does not become an orphan; log the id (never the secret) either way.
		status, revokeErr := h.maas.RevokeUserAPIKey(r.Context(), key.ID, email, h.keyGroup)
		slog.Error("partner key minted but not recorded; revoked", "user_id", user.UserID, "key_id", key.ID,
			"record_error", err, "revoke_status", status, "revoke_error", revokeErr)
		if errors.Is(err, storage.ErrPartnerUserInactive) {
			http.Error(w, "user is inactive", http.StatusConflict)
			return
		}
		http.Error(w, "key mint could not be recorded; the key was revoked, retry", http.StatusInternalServerError)
		return
	}
	// The secret is returned only here, exactly once; Metering stores the id.
	writeJSON(w, key)
}

// handleKeyRevoke revokes one partner-minted key as its owner. Keys the user
// obtained elsewhere (dashboard, MaaS directly) are out of scope by design.
func (h *PartnerUsersHandler) handleKeyRevoke(w http.ResponseWriter, r *http.Request, userID, keyID string) {
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", http.MethodDelete)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.requireKeyGroup(w) {
		return
	}
	user, err := h.store.GetPartnerUser(r.Context(), userID)
	if err != nil {
		h.userError(w, r, err)
		return
	}
	tracked, err := h.store.ListPartnerUserKeys(r.Context(), user.UserID)
	if err != nil {
		h.userError(w, r, err)
		return
	}
	var target *storage.PartnerUserKey
	for i := range tracked {
		if tracked[i].KeyID == keyID {
			target = &tracked[i]
			break
		}
	}
	if target == nil {
		http.Error(w, "key was not minted through this API for this user", http.StatusNotFound)
		return
	}
	if target.RevokedAt == nil {
		if err := h.revokeTracked(r, user.UserID, *target); err != nil {
			slog.Error("partner MaaS key revoke failed", "user_id", user.UserID, "key_id", keyID, "error", err)
			http.Error(w, "MaaS key revoke failed", http.StatusBadGateway)
			return
		}
	}
	writeJSON(w, map[string]any{"user_id": user.UserID, "key_id": keyID, "status": "revoked"})
}

// revokeTracked revokes one tracked key in MaaS as its owner and records the
// outcome. A MaaS 404 means the key is already gone and is treated as done.
func (h *PartnerUsersHandler) revokeTracked(r *http.Request, userID string, key storage.PartnerUserKey) error {
	status, err := h.maas.RevokeUserAPIKey(r.Context(), key.KeyID, key.Username, h.keyGroup)
	if err != nil {
		return err
	}
	if status >= http.StatusBadRequest && status != http.StatusNotFound {
		return fmt.Errorf("maas-api revoke status %d", status)
	}
	return h.store.MarkPartnerUserKeyRevoked(r.Context(), partnerActor(r), userID, key.KeyID)
}

// deactivate soft-disables the user, then revokes every partner-minted key
// that is still active. Keys issued outside this API are left alone.
func (h *PartnerUsersHandler) deactivate(w http.ResponseWriter, r *http.Request, userID string) {
	if !h.requireKeyGroup(w) {
		return
	}
	actor := partnerActor(r)
	deletion, err := h.store.BeginPartnerUserDeactivation(r.Context(), actor, userID)
	if err != nil {
		h.userError(w, r, err)
		return
	}
	for _, key := range deletion.Keys {
		if err := h.revokeTracked(r, deletion.UserID, key); err != nil {
			slog.Error("partner key revocation remains pending", "user_id", deletion.UserID, "key_id", key.KeyID, "error", err)
			http.Error(w, "user deactivated; MaaS key revocation is pending", http.StatusBadGateway)
			return
		}
	}
	if err := h.store.CompletePartnerUserKeyRevocation(r.Context(), actor, deletion.UserID); err != nil {
		slog.Error("partner user deactivation completion failed", "user_id", deletion.UserID, "error", err)
		http.Error(w, "user deactivated; key revocation completion is pending", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"user_id": deletion.UserID, "active": false, "keys_revoked": len(deletion.Keys)})
}

func (h *PartnerUsersHandler) userError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, storage.ErrPartnerUserNotFound):
		http.Error(w, "user not found", http.StatusNotFound)
	case errors.Is(err, storage.ErrPartnerUserConflict):
		http.Error(w, "user_id or email already exists", http.StatusConflict)
	case errors.Is(err, storage.ErrPartnerUserInactive):
		http.Error(w, "user is inactive", http.StatusConflict)
	case errors.Is(err, storage.ErrPartnerUserRevocationPending):
		http.Error(w, "user key revocation is pending", http.StatusConflict)
	case errors.Is(err, storage.ErrInvalidPartnerUser):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		slog.Error("partner user operation failed", "path", r.URL.Path, "error", err)
		http.Error(w, "partner user operation failed", http.StatusInternalServerError)
	}
}
