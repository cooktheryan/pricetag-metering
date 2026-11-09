package handler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

// caller returns the identity in effect for this request (the impersonated
// user while viewing-as). All scope math runs against this.
func caller(r *http.Request, cfg config.Config) string {
	return r.Header.Get(cfg.UserHeader)
}

// ApplyScope resolves the usernames a dashboard caller may query. Admins see
// whatever they ask for; a non-admin is constrained to the logins mapped to
// their own partner user. Returns ok=false when an error response was already
// written.
//
// Package-level so every dashboard handler can reach it without constructing a
// handler first.
func ApplyScope(w http.ResponseWriter, r *http.Request, store *storage.Store, cfg config.Config, requestedUser string) (string, bool) {
	if IsPartnerAdmin(r.Context(), cfg, store, r) {
		return requestedUser, true
	}
	me := caller(r, cfg)
	if me == "" {
		http.Error(w, "who are you?", http.StatusUnauthorized)
		return "", false
	}
	list := selfScope(r.Context(), store, me)
	if requestedUser == "" {
		return strings.Join(list, ","), true
	}
	inScope := make(map[string]bool, len(list))
	for _, u := range list {
		inScope[u] = true
	}
	for _, u := range strings.Split(requestedUser, ",") {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if !inScope[u] {
			http.Error(w, "user outside your visibility scope", http.StatusForbidden)
			return "", false
		}
	}
	return requestedUser, true
}

// selfScope resolves the logins a non-admin caller may see on the Usage page:
// every login mapped to their partner user (one person can hold several MaaS
// logins), otherwise the session username alone. Fails closed to the session
// username on any directory error.
func selfScope(ctx context.Context, store *storage.Store, me string) []string {
	logins, err := store.PartnerLoginsForUsername(ctx, me)
	if err != nil {
		slog.Error("scope resolution failed, falling back to self", "user", me, "error", err)
		return []string{me}
	}
	if len(logins) == 0 {
		return []string{me}
	}
	return logins
}

// WhoAmIScope reports whether the caller manages anyone and how many logins
// are in their scope, so the dashboard can decide whether to show a team view.
func WhoAmIScope(r *http.Request, store *storage.Store, cfg config.Config) (isManager bool, scopeSize int) {
	me := caller(r, cfg)
	if me == "" {
		return false, 0
	}
	list, isMgr, err := store.PartnerManagerScope(r.Context(), me)
	if err != nil {
		return false, 0
	}
	return isMgr, len(list)
}

// decodeJSON decodes a size-limited, strict JSON request body. Returns false
// when a 400 response was already written.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return false
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		http.Error(w, "expected one JSON object", http.StatusBadRequest)
		return false
	}
	return true
}
