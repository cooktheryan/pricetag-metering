package handler

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/redhat-et/pricetag-metering/internal/storage"
)

type UsageReportHandler struct {
	store *storage.Store
}

func NewUsageReportHandler(store *storage.Store) *UsageReportHandler {
	return &UsageReportHandler{store: store}
}

// HandleUserUsage serves a read-only calendar-month report for one MaaS
// username. Unlike the entitlement check, polling this endpoint does not
// create quota-denial ledger rows.
func (h *UsageReportHandler) HandleUserUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")

	const prefix = "/api/v1/usage/users/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	username, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, prefix))
	if err != nil || username == "" || strings.Contains(username, "/") {
		http.Error(w, "invalid username path segment", http.StatusBadRequest)
		return
	}

	report, err := h.store.GetUserUsageReport(r.Context(), username)
	if err != nil {
		http.Error(w, "usage report unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, report)
}
