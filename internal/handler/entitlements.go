package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/metrics"
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

// isSuperAdmin resolves the platform-admin verdict with a short cache. It is
// kept for callers/tests that need the admin verdict; entitlement no longer
// uses it to bypass quota or model access.
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

// entitlementStats evaluates the legacy entitlement path and, when enabled,
// the new role policy. The default is off, so existing deployments keep the
// old allowlist behavior. Observe records would-deny decisions without
// changing the answer; enforce supplies the new model verdict to the same
// quota/accounting path.
func (h *EntitlementsHandler) entitlementStats(ctx context.Context, username, model string) (storage.UsageStats, error) {
	mode := strings.ToLower(strings.TrimSpace(h.cfg.ModelAccessEnforcement))
	if mode != "observe" && mode != "enforce" {
		return h.store.GetMonthlyUsage(ctx, username, model, false)
	}

	tenantID, err := h.store.EnsureDefaultTenant(ctx)
	if err != nil {
		return h.modelAccessUnavailable(ctx, mode, username, model, false, err)
	}
	subjectID, _, err := h.store.ResolvePolicySubjectByUsername(ctx, tenantID, username)
	if err != nil {
		return h.modelAccessUnavailable(ctx, mode, username, model, true, err)
	}
	effective, err := h.store.GetEffectiveModelAccess(ctx, tenantID, subjectID, false)
	if err != nil {
		return h.modelAccessUnavailable(ctx, mode, username, model, true, err)
	}
	allowed := effective.Unrestricted
	if !allowed && strings.TrimSpace(model) != "" {
		for _, candidate := range effective.EffectiveModels {
			if candidate == model {
				allowed = true
				break
			}
		}
	}
	result := "would_allow"
	if !allowed {
		result = "would_deny"
		slog.Debug("model access would deny", "user", username, "model", model, "mode", mode)
	}
	if mode == "enforce" {
		if allowed {
			result = "allow"
		} else {
			result = "deny"
		}
		metrics.ModelAccessDecisionsTotal.WithLabelValues(mode, result).Inc()
		return h.store.GetMonthlyUsageWithModelAllowed(ctx, username, model, false, allowed)
	}
	metrics.ModelAccessDecisionsTotal.WithLabelValues(mode, result).Inc()
	return h.store.GetMonthlyUsage(ctx, username, model, false)
}

func (h *EntitlementsHandler) modelAccessUnavailable(ctx context.Context, mode, username, model string, missingPolicy bool, cause error) (storage.UsageStats, error) {
	if mode == "enforce" {
		metrics.ModelAccessDecisionsTotal.WithLabelValues(mode, "deny").Inc()
		slog.Warn("model access policy unavailable; denying", "user", username, "model", model, "error", cause)
		return h.store.GetMonthlyUsageWithModelAllowed(ctx, username, model, false, false)
	}
	result := "error"
	if missingPolicy {
		result = "would_deny"
	}
	metrics.ModelAccessDecisionsTotal.WithLabelValues(mode, result).Inc()
	slog.Warn("model access policy unavailable; preserving legacy decision", "user", username, "model", model, "error", cause)
	return h.store.GetMonthlyUsage(ctx, username, model, false)
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

	// Standalone management owns the account directory. Check it before any
	// quota exemption or model exception, without the spending cache: disabling
	// an account must also deny keys created through the personal lifecycle API.
	if h.cfg.ManagementAPISecret != "" {
		if h.store == nil {
			http.Error(w, "account directory unavailable", http.StatusServiceUnavailable)
			return
		}
		profile, err := h.store.PartnerUserByMaaSUsername(r.Context(), username)
		if errors.Is(err, storage.ErrPartnerUserNotFound) {
			writeJSON(w, storage.UsageStats{HasAccess: false, ModelAllowed: false})
			return
		}
		if err != nil {
			// A directory outage is an explicit availability decision, like
			// every other store error on this endpoint: the 503 is answered
			// per the gateway's external_metering fail_open setting (see
			// GetMonthlyUsage). A fail-open gateway therefore keeps serving
			// during the outage — including suspended or revocation-pending
			// accounts, whose deny verdicts are unreadable while the
			// directory is down. Deployments that need suspension to hold
			// through an outage must configure the gateway to deny errors
			// from this endpoint for managed accounts.
			http.Error(w, "account directory unavailable", http.StatusServiceUnavailable)
			return
		}
		if !profile.Active || profile.KeyRevocationPending {
			writeJSON(w, storage.UsageStats{HasAccess: false, ModelAllowed: false})
			return
		}
	}

	model := r.URL.Query().Get("model")

	// Super-admins are governed by the same model-access and budget policy as
	// everyone else. Dashboard/admin authorization is separate: broad inference
	// access comes from a normal role, not a hardcoded bypass.
	stats, err := h.entitlementStats(r.Context(), username, model)
	if err != nil {
		slog.Error("failed to get usage", "error", err, "user", username)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// The gateway's enmaas_policy filter consumes the decision fields in
	// addition to hasAccess; keep this response additive and JSON-encoded.
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
