package handler

import (
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/dashboard"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

type PartnerOrgHandler struct {
	store *storage.Store
	cfg   config.Config
}

func NewPartnerOrgHandler(store *storage.Store, cfg config.Config) *PartnerOrgHandler {
	return &PartnerOrgHandler{store: store, cfg: cfg}
}

// ServeManager serves the manager.html page from the embedded dashboard FS.
func (h *PartnerOrgHandler) ServeManager(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(dashboard.FS, "manager.html")
	if err != nil {
		http.Error(w, "manager page not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(data)
}

// scopeResponse is the JSON envelope for HandleScope.
type scopeResponse struct {
	Username     string   `json:"username"`
	Scope        string   `json:"scope"`
	IsAdmin      bool     `json:"isAdmin"`
	IsSuperAdmin bool     `json:"isSuperAdmin"`
	IsManager    bool     `json:"isManager"`
	ScopeSize    int      `json:"scopeSize"`
	Roots        []string `json:"roots"`
	PersonSlug   string   `json:"personSlug"`
}

// HandleScope reports the caller's authorization scope so the manager page
// can decide which UI surface to render (self / manager / admin).
func (h *PartnerOrgHandler) HandleScope(w http.ResponseWriter, r *http.Request) {
	me := caller(r, h.cfg)
	if me == "" {
		http.Error(w, "who are you?", http.StatusUnauthorized)
		return
	}

	resp := scopeResponse{
		Username: me,
		Roots:    []string{},
	}

	if IsPartnerSuperAdmin(r.Context(), h.cfg, h.store, r) {
		resp.Scope = "admin"
		resp.IsAdmin = true
		resp.IsSuperAdmin = true
		writeJSON(w, resp)
		return
	}

	pu, puErr := h.store.PartnerUserByMaaSUsername(r.Context(), me)
	list, isMgr, mgrErr := h.store.PartnerManagerScope(r.Context(), me)
	if mgrErr != nil {
		slog.Error("partner manager scope failed", "user", me, "error", mgrErr)
	}

	resp.IsAdmin = IsPartnerAdmin(r.Context(), h.cfg, h.store, r)

	if isMgr {
		resp.Scope = "manager"
		resp.IsManager = true
		resp.ScopeSize = len(list)
		if puErr == nil {
			resp.PersonSlug = pu.UserID
		}
		writeJSON(w, resp)
		return
	}

	resp.Scope = "self"
	resp.ScopeSize = len(list)
	if puErr == nil {
		resp.PersonSlug = pu.UserID
	}
	writeJSON(w, resp)
}

// scopeRoot resolves the ?root= query parameter into a partner user_id that
// the caller is allowed to view. Super-admins may pass any root or leave it
// empty (whole org). Everyone else defaults to their own partner user_id; a
// non-empty root that differs from their own must pass PartnerInSubtree.
// Returns the resolved root and true, or writes an error response and returns
// false.
func (h *PartnerOrgHandler) scopeRoot(w http.ResponseWriter, r *http.Request) (string, bool) {
	me := caller(r, h.cfg)
	if me == "" {
		http.Error(w, "who are you?", http.StatusUnauthorized)
		return "", false
	}

	root := strings.TrimSpace(r.URL.Query().Get("root"))

	if IsPartnerSuperAdmin(r.Context(), h.cfg, h.store, r) {
		return root, true
	}

	pu, err := h.store.PartnerUserByMaaSUsername(r.Context(), me)
	if err != nil {
		if errors.Is(err, storage.ErrPartnerUserNotFound) {
			http.Error(w, "no partner identity", http.StatusForbidden)
			return "", false
		}
		slog.Error("partner user lookup failed", "user", me, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return "", false
	}

	myRoot := pu.UserID
	if root == "" || root == myRoot {
		return myRoot, true
	}

	ok, err := h.store.PartnerInSubtree(r.Context(), myRoot, root)
	if err != nil {
		slog.Error("subtree check failed", "user", me, "root", root, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return "", false
	}
	if !ok {
		http.Error(w, "root outside your visibility scope", http.StatusForbidden)
		return "", false
	}
	return root, true
}

// HandleOrgUsage returns per-person usage rollups for the manager table.
// GET /api/v1/org/usage?range=&root=
func (h *PartnerOrgHandler) HandleOrgUsage(w http.ResponseWriter, r *http.Request) {
	root, ok := h.scopeRoot(w, r)
	if !ok {
		return
	}
	since, until := parseTimeWindow(r)
	rows, err := h.store.GetPartnerOrgUsage(r.Context(), root, since, until)
	if err != nil {
		slog.Error("org usage query failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []storage.OrgUsageRow{}
	}
	writeJSON(w, rows)
}

// orgChartsResponse bundles the analytics data the manager charts need in a
// single round-trip.
type orgChartsResponse struct {
	Overview storage.DashboardOverview `json:"overview"`
	Models   []storage.ModelSummary    `json:"models"`
	Users    []storage.UserSummary     `json:"users"`
	Timeline []storage.TimelineBucket  `json:"timeline"`
}

// orgChartsUserFilter turns a resolved root into the dashboard user filter.
// A non-empty root with no logins must not collapse to an empty filter: the
// dashboard queries interpret "" as whole-organisation, which would leak data
// outside the selected person's scope. The bool is false when charts must be
// empty instead.
func orgChartsUserFilter(root string, usernames []string) (string, bool) {
	if root != "" && len(usernames) == 0 {
		return "", false
	}
	return strings.Join(usernames, ","), true
}

func emptyOrgChartsResponse() orgChartsResponse {
	return orgChartsResponse{
		Overview: storage.DashboardOverview{},
		Models:   []storage.ModelSummary{},
		Users:    []storage.UserSummary{},
		Timeline: []storage.TimelineBucket{},
	}
}

// HandleOrgCharts returns the analytics bundle for the manager page charts.
// GET /api/v1/org/charts?range=&root=&ref=
func (h *PartnerOrgHandler) HandleOrgCharts(w http.ResponseWriter, r *http.Request) {
	root, ok := h.scopeRoot(w, r)
	if !ok {
		return
	}
	since, until := parseTimeWindow(r)
	ctx := r.Context()

	usernames, err := h.store.PartnerSubtreeUsernames(ctx, root)
	if err != nil {
		slog.Error("subtree usernames failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Join usernames with "," for the dashboard user filter; nil (whole org)
	// becomes "" which the dashboard queries treat as unfiltered.
	userFilter, ok := orgChartsUserFilter(root, usernames)
	if !ok {
		writeJSON(w, emptyOrgChartsResponse())
		return
	}
	refModel := r.URL.Query().Get("ref")

	overview, err := h.store.GetDashboardOverview(ctx, since, until, "", userFilter, "")
	if err != nil {
		slog.Error("org charts overview failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	saved, ratio, applied, serr := h.store.GetHostedSavings(ctx, since, until, "", userFilter, "", refModel)
	if serr != nil {
		slog.Error("org charts savings failed", "error", serr)
	} else {
		overview.SavedUSD, overview.SavingsRatio, overview.RatioApplied = saved, ratio, applied
	}

	models, err := h.store.GetDashboardModels(ctx, since, until, "", userFilter, "")
	if err != nil {
		slog.Error("org charts models failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if models == nil {
		models = []storage.ModelSummary{}
	}

	users, err := h.store.GetDashboardUsers(ctx, since, until, "", userFilter, "", "", "", 200, 0, refModel, "", true)
	if err != nil {
		slog.Error("org charts users failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if users == nil {
		users = []storage.UserSummary{}
	}

	timeline, err := h.store.GetDashboardTimeline(ctx, since, until, "", userFilter, "", "model")
	if err != nil {
		slog.Error("org charts timeline failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if timeline == nil {
		timeline = []storage.TimelineBucket{}
	}

	writeJSON(w, orgChartsResponse{
		Overview: overview,
		Models:   models,
		Users:    users,
		Timeline: timeline,
	})
}

// orgPersonResponse is the per-person drill-down payload.
type orgPersonResponse struct {
	FullName  string                      `json:"full_name"`
	Usernames []string                    `json:"usernames"`
	Models    []storage.OrgPersonModelRow `json:"models"`
}

// HandleOrgPerson returns the per-person model breakdown for the manager
// drill-down. The ?slug= parameter is a partner user_id.
// GET /api/v1/org/person?slug=&range=&ref=
func (h *PartnerOrgHandler) HandleOrgPerson(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimSpace(r.URL.Query().Get("slug"))
	if slug == "" {
		http.Error(w, "slug parameter required", http.StatusBadRequest)
		return
	}

	// Authorize: the caller must be able to see this person.
	root, ok := h.scopeRoot(w, r)
	if !ok {
		return
	}
	// When root is non-empty, verify the target is within the subtree.
	if root != "" {
		inTree, err := h.store.PartnerInSubtree(r.Context(), root, slug)
		if err != nil {
			slog.Error("person subtree check failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if !inTree {
			http.Error(w, "person outside your visibility scope", http.StatusForbidden)
			return
		}
	}

	ctx := r.Context()
	fullName, usernames, err := h.store.PartnerPersonDetail(ctx, slug)
	if err != nil {
		slog.Error("person detail failed", "slug", slug, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	since, until := parseTimeWindow(r)
	refModel := r.URL.Query().Get("ref")

	models, err := h.store.GetPersonModelUsage(ctx, usernames, since, until, refModel)
	if err != nil {
		slog.Error("person model usage failed", "slug", slug, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if models == nil {
		models = []storage.OrgPersonModelRow{}
	}

	writeJSON(w, orgPersonResponse{
		FullName:  fullName,
		Usernames: usernames,
		Models:    models,
	})
}
