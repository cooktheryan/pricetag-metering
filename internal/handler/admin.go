package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/dashboard"
	"github.com/redhat-et/pricetag-metering/internal/k8s"
	"github.com/redhat-et/pricetag-metering/internal/maasapi"
	"github.com/redhat-et/pricetag-metering/internal/metrics"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

type AdminHandler struct {
	k8sClient  *k8s.Client
	maasClient *maasapi.Client
	cfg        config.Config
	store      *storage.Store
}

func NewAdminHandler(k8sClient *k8s.Client, maasClient *maasapi.Client, cfg config.Config) *AdminHandler {
	return &AdminHandler{k8sClient: k8sClient, maasClient: maasClient, cfg: cfg}
}

// SetStore wires the Partner identity store used by the admin handler. A nil
// store keeps the handler constructible in tests and leaves only break-glass
// authorization available.
func (h *AdminHandler) SetStore(store *storage.Store) { h.store = store }

// IsAdmin is retained for compatibility with small, database-free handlers and
// tests. Runtime authorization should use IsPartnerAdmin instead.
func IsAdmin(cfg config.Config, r *http.Request) bool {
	return isBreakGlassAdminUsername(cfg, r.Header.Get(cfg.UserHeader))
}

// IsSuperAdmin is retained for compatibility with database-free handlers and
// tests. Runtime authorization should use IsPartnerSuperAdmin instead.
func IsSuperAdmin(cfg config.Config, r *http.Request) bool {
	return isBreakGlassSuperAdminUsername(cfg, r.Header.Get(cfg.UserHeader))
}

func isBreakGlassAdminUsername(cfg config.Config, username string) bool {
	username = strings.TrimSpace(username)
	if username == "" {
		return cfg.AllowUnauthenticatedAdmin
	}
	return configuredIdentity(cfg.AdminUsers, username) || configuredIdentity(cfg.SuperAdminUsers, username)
}

func isBreakGlassSuperAdminUsername(cfg config.Config, username string) bool {
	username = strings.TrimSpace(username)
	if username == "" {
		return cfg.AllowUnauthenticatedAdmin
	}
	if configuredIdentity(cfg.SuperAdminUsers, username) {
		return true
	}
	for _, admin := range cfg.SuperAdminUsers {
		if i := strings.IndexByte(admin, '@'); i > 0 && strings.EqualFold(username, strings.TrimSpace(admin[:i])) {
			return true
		}
	}
	return false
}

func configuredIdentity(identities []string, username string) bool {
	for _, identity := range identities {
		if strings.EqualFold(username, strings.TrimSpace(identity)) {
			return true
		}
	}
	return false
}

// IsSuperAdminUsername is the break-glass-only compatibility helper. New
// callers with a Partner store must use IsPartnerSuperAdminUsername.
func IsSuperAdminUsername(cfg config.Config, username string) bool {
	return isBreakGlassSuperAdminUsername(cfg, username)
}

// RequireAdmin gates a handler behind IsAdmin, sending everyone else to
// their own account page.
func RequireAdmin(cfg config.Config, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !IsAdmin(cfg, r) {
			slog.Debug("admin access denied", "path", r.URL.Path)
			http.Redirect(w, r, "/me", http.StatusFound)
			return
		}
		next(w, r)
	}
}

// RequireAdminDashboard gates dashboard pages while giving regular signed-in
// users a neutral holding page rather than exposing usage data or redirecting
// them into another dashboard surface.
func RequireAdminDashboard(cfg config.Config, next, comingSoon http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !IsAdmin(cfg, r) {
			comingSoon(w, r)
			return
		}
		next(w, r)
	}
}

// RequireAdminAPI protects dashboard data endpoints from direct access by
// regular users. API callers receive 403 rather than an HTML redirect.
func RequireAdminAPI(cfg config.Config, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !IsAdmin(cfg, r) {
			http.Error(w, "administrator access required", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// IsPartnerAdmin makes partner_users.role the normal authorization source. The
// configured lists are used only when the Partner store is unavailable, so a
// role change in partner_users can demote a previously listed identity.
func IsPartnerAdmin(ctx context.Context, cfg config.Config, store *storage.Store, r *http.Request) bool {
	return IsPartnerAdminUsername(ctx, cfg, store, r.Header.Get(cfg.UserHeader))
}

func IsPartnerAdminUsername(ctx context.Context, cfg config.Config, store *storage.Store, username string) bool {
	if strings.TrimSpace(username) == "" && cfg.AllowUnauthenticatedAdmin {
		return true
	}
	if store != nil {
		role, err := store.GetPartnerRoleByUsername(ctx, username)
		if err == nil {
			return role == storage.PartnerRoleAdmin || role == storage.PartnerRoleSuperAdmin
		}
		slog.Warn("Partner role lookup failed; using break-glass authorization", "error", err)
	}
	return isBreakGlassAdminUsername(cfg, username)
}

func RequirePartnerAdminPage(cfg config.Config, store *storage.Store, next, comingSoon http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !IsPartnerAdmin(r.Context(), cfg, store, r) {
			comingSoon(w, r)
			return
		}
		next(w, r)
	}
}

func RequirePartnerAdminAPI(cfg config.Config, store *storage.Store, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !IsPartnerAdmin(r.Context(), cfg, store, r) {
			http.Error(w, "administrator access required", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func IsPartnerSuperAdmin(ctx context.Context, cfg config.Config, store *storage.Store, r *http.Request) bool {
	return IsPartnerSuperAdminUsername(ctx, cfg, store, r.Header.Get(cfg.UserHeader))
}

// partnerSuperAdminVerdict resolves the super-admin verdict and reports whether
// it is safe to cache. A successful directory lookup is authoritative; the
// break-glass fallback after a failed lookup is not cacheable so the next
// request retries the directory instead of serving the fallback for the TTL.
func partnerSuperAdminVerdict(ctx context.Context, cfg config.Config, store *storage.Store, username string) (superAdmin bool, resolved bool) {
	if strings.TrimSpace(username) == "" && cfg.AllowUnauthenticatedAdmin {
		return true, true
	}
	if store != nil {
		role, err := store.GetPartnerRoleByUsername(ctx, username)
		if err == nil {
			return role == storage.PartnerRoleSuperAdmin, true
		}
		slog.Warn("Partner super-admin role lookup failed; using break-glass authorization", "error", err)
		return isBreakGlassSuperAdminUsername(cfg, username), false
	}
	return isBreakGlassSuperAdminUsername(cfg, username), true
}

func IsPartnerSuperAdminUsername(ctx context.Context, cfg config.Config, store *storage.Store, username string) bool {
	superAdmin, _ := partnerSuperAdminVerdict(ctx, cfg, store, username)
	return superAdmin
}

func RequirePartnerSuperAdmin(cfg config.Config, store *storage.Store, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !IsPartnerSuperAdmin(r.Context(), cfg, store, r) {
			http.Error(w, "super administrator access required", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// RequireSuperAdmin gates the operator-only surface (admin console, routing,
// admin APIs). An admin who is not a super-admin lands on the
// usage dashboard — the one page they should be looking at anyway.
func RequireSuperAdmin(cfg config.Config, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !IsSuperAdmin(cfg, r) {
			slog.Debug("super-admin access denied", "path", r.URL.Path)
			if IsAdmin(cfg, r) {
				http.Redirect(w, r, "/dashboard", http.StatusFound)
			} else {
				http.Redirect(w, r, "/me", http.StatusFound)
			}
			return
		}
		next(w, r)
	}
}

func (h *AdminHandler) ServeAdmin(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(dashboard.FS, "admin.html")
	if err != nil {
		http.Error(w, "admin page not found", http.StatusInternalServerError)
		return
	}
	if h.cfg.ManagementAPISecret != "" {
		data = []byte(strings.ReplaceAll(string(data), "data-managed hidden", "data-managed"))
		for marker, file := range map[string]string{
			"MANAGED_KEYS":    "management-admin-keys.html",
			"MANAGED_USERS":   "management-admin-users.html",
			"MANAGED_BUDGETS": "management-admin-budgets.html",
			"MANAGED_PRICES":  "management-admin-prices.html",
			"MANAGED_SCRIPT":  "management-admin-script.html",
		} {
			fragment, err := fs.ReadFile(dashboard.FS, file)
			if err != nil {
				http.Error(w, "administration controls unavailable", http.StatusInternalServerError)
				return
			}
			if marker == "MANAGED_SCRIPT" {
				controls, err := fs.ReadFile(dashboard.FS, "management-key-controls.js")
				if err == nil {
					var tables []byte
					tables, err = fs.ReadFile(dashboard.FS, "management-table-controls.js")
					controls = append(append(controls, '\n'), tables...)
				}
				if err != nil {
					http.Error(w, "key controls unavailable", 500)
					return
				}
				fragment = []byte(strings.Replace(string(fragment), "/* KEY_CONTROLS */", string(controls), 1))
			}
			data = []byte(strings.Replace(string(data), "<!-- "+marker+" -->", string(fragment), 1))
		}
	}
	if h.cfg.ManagementAPISecret != "" {
		data = dashboard.WithSessionDialog(data)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(data)
}

func (h *AdminHandler) ServeRouting(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(dashboard.FS, "routing.html")
	if err != nil {
		http.Error(w, "routing page not found", http.StatusInternalServerError)
		return
	}
	if h.cfg.ManagementAPISecret != "" {
		data = dashboard.WithSessionDialog(data)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(data)
}

func (h *AdminHandler) HandleProviders(w http.ResponseWriter, r *http.Request) {
	if h.k8sClient == nil {
		writeJSON(w, []k8s.ProviderInfo{})
		return
	}
	providers, err := h.k8sClient.ListProviders(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if providers == nil {
		providers = []k8s.ProviderInfo{}
	}
	writeJSON(w, providers)
}

func (h *AdminHandler) HandleModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	if h.cfg.GatewayModelsFile != "" {
		w.Header().Set("Cache-Control", "no-store")
		file, err := os.Open(h.cfg.GatewayModelsFile)
		if err != nil {
			http.Error(w, "gateway catalog unavailable", 503)
			return
		}
		defer file.Close()
		if info, err := file.Stat(); err != nil || info.Size() > 1<<20 {
			http.Error(w, "gateway catalog too large", 503)
			return
		}
		var configured []struct {
			ID       string `json:"id"`
			Model    string `json:"model"`
			Provider string `json:"provider"`
		}
		decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
		if decoder.Decode(&configured) != nil || decoder.Decode(new(any)) != io.EOF {
			http.Error(w, "invalid gateway catalog", 503)
			return
		}
		models := []k8s.ModelInfo{}
		for _, m := range configured {
			if strings.TrimSpace(m.ID) == "" || strings.TrimSpace(m.Model) == "" || len(m.Model) > 256 {
				http.Error(w, "invalid gateway model", 503)
				return
			}
			models = append(models, k8s.ModelInfo{Name: m.ID, TargetModel: m.Model, Provider: m.Provider, ProviderRefs: []k8s.ProviderRef{{ProviderName: m.Provider, TargetModel: m.Model}}})
		}
		writeJSON(w, models)
		return
	}
	if h.k8sClient == nil {
		writeJSON(w, []k8s.ModelInfo{})
		return
	}
	models, err := h.k8sClient.ListModels(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if models == nil {
		models = []k8s.ModelInfo{}
	}
	writeJSON(w, models)
}

func (h *AdminHandler) HandleConfig(w http.ResponseWriter, r *http.Request) {
	if h.k8sClient == nil {
		writeJSON(w, &k8s.PipelineConfig{Profiles: []k8s.ProfileInfo{}, ActiveProfile: "default"})
		return
	}
	pipeline, err := h.k8sClient.GetPipelineConfig(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, pipeline)
}

func (h *AdminHandler) HandleUpdateProvider(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.k8sClient == nil {
		http.Error(w, "k8s client not available", http.StatusServiceUnavailable)
		return
	}

	// Path: /api/v1/admin/models/provider/{modelName}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 6 {
		http.Error(w, "invalid path — expected /api/v1/admin/models/provider/{name}", http.StatusBadRequest)
		return
	}
	modelName := parts[5]

	var body struct {
		ProviderName string `json:"providerName"`
		TargetModel  string `json:"targetModel"`
		APIFormat    string `json:"apiFormat"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if err := h.k8sClient.UpdateModelProvider(r.Context(), modelName, body.ProviderName, body.TargetModel, body.APIFormat); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

func (h *AdminHandler) HandleUpdateWeights(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.k8sClient == nil {
		http.Error(w, "k8s client not available", http.StatusServiceUnavailable)
		return
	}

	// Extract model name from path: /api/v1/admin/models/{name}/weights
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	modelName := parts[4]

	var weights map[string]int64
	if err := json.NewDecoder(r.Body).Decode(&weights); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if err := h.k8sClient.UpdateModelWeights(r.Context(), modelName, weights); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

// sessionGroups returns the caller's groups from the header the login flow
// stored (JSON array string, with a CSV fallback).
func sessionGroups(r *http.Request, cfg config.Config) []string {
	var gs []string
	if raw := r.Header.Get(cfg.GroupsHeader); raw != "" {
		if err := json.Unmarshal([]byte(raw), &gs); err != nil {
			for _, g := range strings.Split(raw, ",") {
				if g = strings.TrimSpace(g); g != "" {
					gs = append(gs, g)
				}
			}
		}
	}
	return gs
}

func (h *AdminHandler) HandleUsers(w http.ResponseWriter, r *http.Request) {
	if h.k8sClient == nil {
		writeJSON(w, []k8s.OpenShiftUser{})
		return
	}
	users, err := h.k8sClient.GetOpenShiftUsers(r.Context())
	if err != nil {
		writeJSON(w, []k8s.OpenShiftUser{})
		return
	}
	writeJSON(w, users)
}

func (h *AdminHandler) HandleGroupMember(w http.ResponseWriter, r *http.Request) {
	if h.k8sClient == nil {
		http.Error(w, "k8s not available", http.StatusServiceUnavailable)
		return
	}

	var body struct {
		Group    string `json:"group"`
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	var err error
	switch r.Method {
	case http.MethodPost:
		err = h.k8sClient.AddUserToGroup(r.Context(), body.Group, body.Username)
	case http.MethodDelete:
		err = h.k8sClient.RemoveUserFromGroup(r.Context(), body.Group, body.Username)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (h *AdminHandler) HandleGroups(w http.ResponseWriter, r *http.Request) {
	if h.k8sClient == nil {
		writeJSON(w, []k8s.GroupInfo{})
		return
	}
	groups, err := h.k8sClient.GetOpenShiftGroups(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if groups == nil {
		groups = []k8s.GroupInfo{}
	}
	writeJSON(w, groups)
}

func (h *AdminHandler) HandleAuthPolicies(w http.ResponseWriter, r *http.Request) {
	if h.k8sClient == nil {
		writeJSON(w, []k8s.AuthPolicyInfo{})
		return
	}
	policies, err := h.k8sClient.GetAuthPolicies(r.Context(), "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if policies == nil {
		policies = []k8s.AuthPolicyInfo{}
	}
	writeJSON(w, policies)
}

func (h *AdminHandler) HandleSubscriptions(w http.ResponseWriter, r *http.Request) {
	if h.k8sClient == nil {
		writeJSON(w, []k8s.SubscriptionInfo{})
		return
	}
	subs, err := h.k8sClient.GetSubscriptions(r.Context(), "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if subs == nil {
		subs = []k8s.SubscriptionInfo{}
	}
	writeJSON(w, subs)
}

// HandleValidGroups returns the canonical, live list of org groups the
// gateway actually grants a model subscription to — spec.owner.groups on
// the configured MaaSSubscription CR — for the People & Org group picker.
func (h *AdminHandler) HandleValidGroups(w http.ResponseWriter, r *http.Request) {
	if h.k8sClient == nil {
		writeJSON(w, map[string][]string{"groups": {}})
		return
	}
	groups, err := h.k8sClient.GetMaaSSubscriptionGroups(r.Context(), h.cfg.Kubernetes.Namespace, h.cfg.Kubernetes.SubscriptionName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sort.Strings(groups)
	writeJSON(w, map[string][]string{"groups": groups})
}

// HandleRoles returns active Partner identities grouped by their Partner role.
// This endpoint is read-only and exists for the legacy People & Org table.
func (h *AdminHandler) HandleRoles(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		http.Error(w, "partner identity store unavailable", http.StatusServiceUnavailable)
		return
	}
	users, err := h.store.ListAllPartnerUsers(r.Context())
	if err != nil {
		http.Error(w, "partner role lookup failed", http.StatusInternalServerError)
		return
	}
	admins, supers := partnerRoleLists(users)
	writeJSON(w, map[string][]string{"admins": admins, "superAdmins": supers})
}

func partnerRoleLists(users []storage.PartnerUser) (admins, supers []string) {
	for _, user := range users {
		email, _ := user.Tags["email"].(string)
		email = strings.TrimSpace(email)
		if email == "" {
			continue
		}
		switch user.Role {
		case storage.PartnerRoleSuperAdmin:
			supers = append(supers, email)
		case storage.PartnerRoleAdmin:
			admins = append(admins, email)
		}
	}
	sort.Strings(admins)
	sort.Strings(supers)
	return admins, supers
}

// platformGroups returns the group set to scope maas-api v1 calls with: the
// configured MaaSSubscription's live groups — the same source the gateway
// enforces and the valid-groups endpoint serves. maas-api requires a
// non-empty X-MaaS-Group (it scopes the internal token it mints), so an
// empty or unreadable list is an error; OpenShift Group objects are not a
// valid substitute — they are empty on every real deployment.
func (h *AdminHandler) platformGroups(ctx context.Context) ([]string, error) {
	if h.k8sClient == nil {
		return nil, fmt.Errorf("kubernetes client not configured")
	}
	groups, err := h.k8sClient.GetMaaSSubscriptionGroups(ctx, h.cfg.Kubernetes.Namespace, h.cfg.Kubernetes.SubscriptionName)
	if err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("MaaSSubscription %s/%s lists no groups", h.cfg.Kubernetes.Namespace, h.cfg.Kubernetes.SubscriptionName)
	}
	return groups, nil
}

func (h *AdminHandler) HandleKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listKeys(w, r)
	case http.MethodPost:
		h.createKey(w, r)
	case http.MethodDelete:
		h.revokeKey(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *AdminHandler) listKeys(w http.ResponseWriter, r *http.Request) {
	if h.maasClient == nil {
		writeJSON(w, &maasapi.SearchResult{Data: []maasapi.APIKeyResponse{}})
		return
	}
	username := r.URL.Query().Get("username")
	// Non-admins are pinned to their own keys regardless of the query.
	if !IsPartnerAdmin(r.Context(), h.cfg, h.store, r) {
		username = r.Header.Get(h.cfg.UserHeader)
	}
	groups, err := h.platformGroups(r.Context())
	if err != nil {
		slog.Error("key search skipped: no platform groups", "error", err)
		writeJSON(w, &maasapi.SearchResult{Data: []maasapi.APIKeyResponse{}})
		return
	}
	result, err := h.maasClient.SearchAPIKeys(r.Context(), username, groups)
	if err != nil {
		slog.Error("key search failed", "error", err)
		writeJSON(w, &maasapi.SearchResult{Data: []maasapi.APIKeyResponse{}})
		return
	}
	writeJSON(w, result)
}

func (h *AdminHandler) createKey(w http.ResponseWriter, r *http.Request) {
	if h.maasClient == nil {
		http.Error(w, "maas-api client not available", http.StatusServiceUnavailable)
		return
	}
	var body struct {
		Username string `json:"username"`
		Group    string `json:"group"`
		KeyName  string `json:"keyName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	// Self-service: a regular user may only create a key for themselves, in
	// one of their own groups (the redesigned user dashboard's create form).
	// Align this legacy route with /api/v1/me/keys: a requested group that the
	// caller is not a member of is rejected, never silently replaced.
	if !IsPartnerAdmin(r.Context(), h.cfg, h.store, r) {
		username, group, groups, ok := h.myKeyIdentity(w, r)
		if !ok {
			return
		}
		body.Username = username
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
		body.Group = group
	}
	if body.Username == "" || body.KeyName == "" {
		http.Error(w, "username and keyName are required", http.StatusBadRequest)
		return
	}

	result, err := h.maasClient.CreateAPIKey(r.Context(), body.Username, body.Group, body.KeyName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	metrics.KeysMintedTotal.Inc()
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, result)
}

func (h *AdminHandler) revokeKey(w http.ResponseWriter, r *http.Request) {
	if h.maasClient == nil {
		http.Error(w, "maas-api client not available", http.StatusServiceUnavailable)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 {
		http.Error(w, "key ID required in path", http.StatusBadRequest)
		return
	}
	keyID := parts[4]

	groups, err := h.platformGroups(r.Context())
	if err != nil {
		slog.Error("key revoke blocked: no platform groups", "key", keyID, "error", err)
		http.Error(w, "group scope unavailable for key operations", http.StatusServiceUnavailable)
		return
	}

	// Non-admins may only revoke a key that belongs to them.
	if !IsPartnerAdmin(r.Context(), h.cfg, h.store, r) {
		caller := r.Header.Get(h.cfg.UserHeader)
		own, err := h.maasClient.SearchAPIKeys(r.Context(), caller, groups)
		if err != nil {
			http.Error(w, "unable to verify key ownership", http.StatusInternalServerError)
			return
		}
		owns := false
		for _, k := range own.Data {
			if k.ID == keyID {
				owns = true
				break
			}
		}
		if !owns {
			http.Error(w, "can only revoke your own keys", http.StatusForbidden)
			return
		}
	}

	if err := h.maasClient.RevokeAPIKey(r.Context(), keyID, groups); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
}
