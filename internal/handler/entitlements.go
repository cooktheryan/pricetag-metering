package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

type EntitlementsHandler struct {
	store *storage.Store
	cfg   config.Config

	roleCache   *expirable.LRU[string, bool]
	resolveRole func(context.Context, string) (bool, bool)
}

const (
	roleCacheTTL        = 15 * time.Second
	roleCacheMaxEntries = 10_000
)

func NewEntitlementsHandler(store *storage.Store, cfg config.Config) *EntitlementsHandler {
	return &EntitlementsHandler{
		store:     store,
		cfg:       cfg,
		roleCache: expirable.NewLRU[string, bool](roleCacheMaxEntries, nil, roleCacheTTL),
		resolveRole: func(ctx context.Context, username string) (bool, bool) {
			return partnerSuperAdminVerdict(ctx, cfg, store, username)
		},
	}
}

// isSuperAdmin caches the role lookup for the entitlement hot path. The
// per-request role query used to run for every gateway request; a short TTL
// keeps role changes bounded by the same staleness as the quota decision.
// Verdicts that fell back after a directory error are not cached, so the next
// request retries the directory.
func (h *EntitlementsHandler) isSuperAdmin(ctx context.Context, username string) bool {
	key := strings.ToLower(strings.TrimSpace(username))
	if cached, ok := h.roleCache.Get(key); ok {
		return cached
	}
	superAdmin, resolved := h.resolveRole(ctx, username)
	if resolved {
		h.roleCache.Add(key, superAdmin)
	}
	return superAdmin
}

func (h *EntitlementsHandler) HandleEntitlement(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	var username string
	for i, p := range parts {
		if p == "customers" && i+1 < len(parts) {
			username = parts[i+1]
			break
		}
	}
	if username == "" {
		http.Error(w, "missing customer ID", http.StatusBadRequest)
		return
	}

	model := r.URL.Query().Get("model")

	// Operators never gate themselves: a quota misfire must not lock the
	// people who can fix it out of their own dogfood keys.
	exempt := h.isSuperAdmin(r.Context(), username)

	stats, err := h.store.GetMonthlyUsage(r.Context(), username, model, exempt)
	if err != nil {
		slog.Error("failed to get usage", "error", err, "user", username)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)

	// Count the denial AFTER the answer is on the wire: this runs on the
	// gateway's synchronous 5s path, and a hasAccess:false here is exactly
	// the request the client sees as a 429 (fail_open means no denial when
	// we are unreachable, so there is no 429 this counter could miss).
	// Detached context — the request context dies when the handler returns.
	if !stats.HasAccess {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := h.store.RecordQuotaDenial(ctx, username, model); err != nil {
				slog.Warn("quota denial record failed", "error", err, "user", username)
			}
		}()
	}
}
