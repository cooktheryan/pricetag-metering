package handler

import (
	"net/http"
	"time"

	"github.com/redhat-et/pricetag-metering/internal/storage"
)

// RollupHandler exposes Phase 3 state for the read-switch gate and the
// parity check, super-admin gated at registration.
type RollupHandler struct {
	store           *storage.Store
	refreshInterval time.Duration
}

func NewRollupHandler(store *storage.Store, refreshSeconds int) *RollupHandler {
	if refreshSeconds < 60 {
		refreshSeconds = 60
	}
	return &RollupHandler{
		store:           store,
		refreshInterval: time.Duration(refreshSeconds) * time.Second,
	}
}

// HandleStatus returns backfill readiness; with ?parity=<window> it also
// runs the raw-vs-rollup parity diff (total and per-model) for that
// window. The parity query scans raw aggregates — super-admin only, and
// the window is clamped to 90 days so it can't be weaponized into a
// full-table re-pricing on every page refresh.
func (h *RollupHandler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	lastRefresh := h.store.RollupLastRefreshedAt()
	freshness := "raw"
	if h.store.RollupFlag() {
		if h.store.LiveRollupsEnabled() {
			freshness = "transactional"
		} else {
			freshness = "eventual"
		}
	}
	resp := map[string]any{
		"ready":                    h.store.RollupsReady(),
		"use_rollups":              h.store.RollupFlag(),
		"live_writes":              h.store.LiveRollupsEnabled(),
		"freshness":                freshness,
		"refresh_interval_seconds": int(h.refreshInterval / time.Second),
		"parity_healthy":           h.store.ParityHealthy(),
		"serving":                  "raw",
	}
	if lastRefresh.IsZero() {
		resp["last_refresh_at"] = nil
		resp["refresh_lag_seconds"] = nil
	} else {
		lag := time.Since(lastRefresh)
		if lag < 0 {
			lag = 0
		}
		resp["last_refresh_at"] = lastRefresh.Format(time.RFC3339)
		resp["refresh_lag_seconds"] = int(lag / time.Second)
	}
	if h.store.RollupServing() {
		resp["serving"] = "rollup"
	}
	if p := r.URL.Query().Get("parity"); p != "" {
		window, ok := parseTimeWindowNamed(p)
		if !ok {
			http.Error(w, "bad parity window (use 24h, 7d, 30d, 90d)", http.StatusBadRequest)
			return
		}
		until := time.Now()
		report, err := h.store.ParityReport(r.Context(), until.Add(-window), until)
		if err != nil {
			http.Error(w, "parity report failed", http.StatusInternalServerError)
			return
		}
		resp["parity_window"] = p
		resp["parity"] = report
	}
	writeJSON(w, resp)
}

func parseTimeWindowNamed(name string) (time.Duration, bool) {
	switch name {
	case "24h":
		return 24 * time.Hour, true
	case "7d":
		return 7 * 24 * time.Hour, true
	case "30d":
		return 30 * 24 * time.Hour, true
	case "90d":
		return 90 * 24 * time.Hour, true
	}
	return 0, false
}
