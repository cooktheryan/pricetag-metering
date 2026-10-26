package handler

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

// MeUsageHandler exposes the caller's own usage. It is a thin, self-pinned
// wrapper over the same storage queries the admin Usage page uses, so the
// numbers can never disagree with the org view. Any ?user= parameter is
// ignored: the scope is always every login mapped to the caller's partner
// user (a person may hold several MaaS logins).
type MeUsageHandler struct {
	store *storage.Store
	cfg   config.Config
}

func NewMeUsageHandler(store *storage.Store, cfg config.Config) *MeUsageHandler {
	return &MeUsageHandler{store: store, cfg: cfg}
}

// selfScopeParam returns the comma-separated login list for the caller.
func (h *MeUsageHandler) selfScopeParam(r *http.Request) string {
	me := caller(r, h.cfg)
	if me == "" {
		return ""
	}
	return strings.Join(selfScope(r.Context(), h.store, me), ",")
}

func (h *MeUsageHandler) HandleSummary(w http.ResponseWriter, r *http.Request) {
	user := h.selfScopeParam(r)
	if user == "" {
		http.Error(w, "who are you?", http.StatusUnauthorized)
		return
	}
	since, until := parseTimeWindow(r)
	overview, err := h.store.GetDashboardOverview(r.Context(), since, until, "", user, "")
	if err != nil {
		http.Error(w, "could not load usage", http.StatusInternalServerError)
		return
	}
	resp := map[string]any{"overview": overview}
	if quota, qerr := h.store.GetQuotaView(r.Context(), caller(r, h.cfg), false); qerr == nil {
		resp["quota"] = quota
	}
	writeJSON(w, resp)
}

func (h *MeUsageHandler) HandleModels(w http.ResponseWriter, r *http.Request) {
	user := h.selfScopeParam(r)
	if user == "" {
		http.Error(w, "who are you?", http.StatusUnauthorized)
		return
	}
	since, until := parseTimeWindow(r)
	models, err := h.store.GetDashboardModels(r.Context(), since, until, "", user, "")
	if err != nil {
		http.Error(w, "could not load usage", http.StatusInternalServerError)
		return
	}
	if models == nil {
		models = []storage.ModelSummary{}
	}
	writeJSON(w, models)
}

func (h *MeUsageHandler) HandleRecent(w http.ResponseWriter, r *http.Request) {
	user := h.selfScopeParam(r)
	if user == "" {
		http.Error(w, "who are you?", http.StatusUnauthorized)
		return
	}
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 50 {
		limit = l
	}
	events, err := h.store.GetRecentEvents(r.Context(), limit, "", user, "")
	if err != nil {
		http.Error(w, "could not load recent activity", http.StatusInternalServerError)
		return
	}
	if events == nil {
		events = []storage.RecentEvent{}
	}
	writeJSON(w, events)
}
