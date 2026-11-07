package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redhat-et/pricetag-metering/internal/storage"
)

// ModelAccessHandler serves the AuthZEN-shaped policy decision endpoint and
// the model-access admin surface. v1 keeps them separate from the legacy
// entitlement endpoint, which remains a compatibility adapter.
type ModelAccessHandler struct {
	store *storage.Store
}

func NewModelAccessHandler(store *storage.Store) *ModelAccessHandler {
	return &ModelAccessHandler{store: store}
}

type authZENSubject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type authZENResource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type authZENAction struct {
	Name string `json:"name"`
}

type authZENContext struct {
	Tenant  string `json:"tenant"`
	Path    string `json:"path"`
	Dialect string `json:"dialect"`
}

type authZENRequest struct {
	Subject  authZENSubject  `json:"subject"`
	Resource authZENResource `json:"resource"`
	Action   authZENAction   `json:"action"`
	Context  authZENContext  `json:"context"`
}

// HandleDecision implements POST /api/v2/policy/decide.
func (h *ModelAccessHandler) HandleDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req authZENRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Subject.ID) == "" {
		http.Error(w, "subject.id is required", http.StatusBadRequest)
		return
	}
	if req.Resource.Type != "" && req.Resource.Type != "model" {
		http.Error(w, "resource.type must be model", http.StatusBadRequest)
		return
	}
	if req.Action.Name == "" {
		req.Action.Name = "invoke"
	}
	if req.Action.Name != "invoke" && req.Action.Name != "list" {
		http.Error(w, "unsupported action", http.StatusBadRequest)
		return
	}

	tenant := strings.TrimSpace(req.Context.Tenant)
	if tenant == "" || tenant == storage.DefaultTenantSlug {
		id, err := h.store.EnsureDefaultTenant(r.Context())
		if err != nil {
			http.Error(w, "tenant unavailable", http.StatusInternalServerError)
			return
		}
		tenant = id
	}

	decision, err := h.store.DecideModelAccess(
		r.Context(), tenant, req.Subject.ID, req.Resource.ID, req.Action.Name, false)
	if err != nil {
		status, reason := policyError(err)
		writeJSONStatus(w, status, storage.PolicyDecision{
			TenantID:  tenant,
			SubjectID: req.Subject.ID,
			ModelID:   req.Resource.ID,
			Action:    req.Action.Name,
			Decision:  storage.PolicyDecisionDeny,
			Reason:    reason,
		})
		return
	}
	writeJSON(w, decision)
}

func policyError(err error) (int, string) {
	switch {
	case errors.Is(err, storage.ErrModelAccessTenantNotFound):
		return http.StatusForbidden, storage.PolicyReasonTenantNotFound
	case errors.Is(err, storage.ErrModelAccessTenantSuspended):
		return http.StatusForbidden, storage.PolicyReasonTenantSuspended
	case errors.Is(err, storage.ErrModelAccessSubjectNotFound),
		errors.Is(err, storage.ErrModelAccessSubjectInactive):
		return http.StatusForbidden, storage.PolicyReasonAuthentication
	default:
		return http.StatusServiceUnavailable, storage.PolicyReasonUnavailable
	}
}

func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type createModelAccessRoleRequest struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Models         []string `json:"models"`
	IsDefault      bool     `json:"is_default"`
	ReplaceDefault bool     `json:"replace_default"`
	MonthlyUSD     float64  `json:"monthly_usd"`
}

type setModelAccessRoleModelsRequest struct {
	Models []string `json:"models"`
}

type assignModelAccessRoleRequest struct {
	SubjectID string `json:"subject_id"`
}

type assignModelAccessRoleSubjectsRequest struct {
	SubjectIDs []string `json:"subject_ids"`
}

type policySubjectFilterRequest struct {
	Field  string   `json:"field"`
	Value  string   `json:"value"`
	Values []string `json:"values"`
}

type setSubjectModelsRequest struct {
	Models []string `json:"models"`
}

type setSubjectRestrictionRequest struct {
	Enabled bool     `json:"enabled"`
	Models  []string `json:"models"`
}

type setRoleBudgetRequest struct {
	MonthlyUSD float64 `json:"monthly_usd"`
}

type addQuotaCreditRequest struct {
	AmountUSD float64    `json:"amount_usd"`
	ExpiresAt *time.Time `json:"expires_at"`
	Reason    string     `json:"reason"`
}

type excludeDefaultRequest struct {
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// HandleAdmin serves the tenant-scoped model-access admin API. The v1 UI
// exposes only the default tenant, but every query is tenant-scoped.
func (h *ModelAccessHandler) HandleAdmin(w http.ResponseWriter, r *http.Request) {
	const prefix = "/api/v2/tenants/"
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) < 3 || parts[1] != "model-access" {
		http.NotFound(w, r)
		return
	}
	tenant := parts[0]
	if tenant == storage.DefaultTenantSlug {
		id, err := h.store.EnsureDefaultTenant(r.Context())
		if err != nil {
			http.Error(w, "tenant unavailable", http.StatusInternalServerError)
			return
		}
		tenant = id
	}
	actor := quotaAdminActor(r)

	switch parts[2] {
	case "roles":
		h.handleRoles(w, r, tenant, actor, parts[3:])
	case "subjects":
		h.handleSubjects(w, r, tenant, actor, parts[3:])
	case "catalog":
		h.handleCatalog(w, r, tenant, parts[3:])
	case "cost-centers":
		if len(parts) > 3 || r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		facets, err := h.store.ListCostCenterFacets(r.Context(), tenant)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, facets)
	default:
		http.NotFound(w, r)
	}
}

func (h *ModelAccessHandler) handleCatalog(w http.ResponseWriter, r *http.Request, tenant string, rest []string) {
	if len(rest) == 0 {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		models, err := h.store.ListCatalogModels(r.Context(), tenant)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, models)
		return
	}
	if len(rest) == 1 && rest[0] == "sync" {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path := strings.TrimSpace(os.Getenv("MODEL_CATALOG_FILE"))
		if path == "" {
			http.Error(w, "MODEL_CATALOG_FILE is not configured", http.StatusServiceUnavailable)
			return
		}
		count, err := h.store.SyncCatalogFromPraxisConfig(r.Context(), tenant, path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, map[string]any{"synced": count})
		return
	}
	http.NotFound(w, r)
}

func (h *ModelAccessHandler) handleRoles(w http.ResponseWriter, r *http.Request, tenant, actor string, rest []string) {
	if len(rest) == 0 {
		switch r.Method {
		case http.MethodGet:
			roles, err := h.store.ListModelAccessRoles(r.Context(), tenant)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if roles == nil {
				roles = []storage.ModelAccessRole{}
			}
			writeJSON(w, roles)
		case http.MethodPost:
			var body createModelAccessRoleRequest
			if !decodeJSON(w, r, &body) {
				return
			}
			if body.IsDefault && !body.ReplaceDefault {
				existing, err := h.store.GetDefaultModelAccessRole(r.Context(), tenant)
				if err == nil {
					http.Error(w, "default role already exists: "+existing.Name+"; confirm replace_default to replace it", http.StatusConflict)
					return
				}
				if !errors.Is(err, storage.ErrModelAccessRoleNotFound) {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
			role, err := h.store.CreateModelAccessRole(r.Context(), tenant, actor,
				body.Name, body.Description, body.Models, body.IsDefault, body.MonthlyUSD)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSONStatus(w, http.StatusCreated, role)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	roleID := rest[0]
	if len(rest) == 1 {
		switch r.Method {
		case http.MethodGet:
			role, err := h.store.GetModelAccessRole(r.Context(), tenant, roleID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			writeJSON(w, role)
		case http.MethodDelete:
			if err := h.store.RetireModelAccessRole(r.Context(), tenant, roleID, actor); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.Header().Set("Allow", "GET, DELETE")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	switch rest[1] {
	case "budget":
		if r.Method != http.MethodPut {
			w.Header().Set("Allow", "PUT")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body setRoleBudgetRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		if err := h.store.SetModelAccessRoleBudget(r.Context(), tenant, roleID, actor, body.MonthlyUSD); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		role, err := h.store.GetModelAccessRole(r.Context(), tenant, roleID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, role)
	case "models":
		if r.Method != http.MethodPut {
			w.Header().Set("Allow", "PUT")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body setModelAccessRoleModelsRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		if err := h.store.SetModelAccessRoleModels(r.Context(), tenant, roleID, actor, body.Models); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		role, err := h.store.GetModelAccessRole(r.Context(), tenant, roleID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, role)
	case "subjects":
		if len(rest) == 2 && r.Method == http.MethodGet {
			subjects, err := h.store.ListModelAccessRoleSubjects(r.Context(), tenant, roleID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, subjects)
			return
		}
		if len(rest) == 3 && rest[2] == "bulk" && r.Method == http.MethodPost {
			var body assignModelAccessRoleSubjectsRequest
			if !decodeJSON(w, r, &body) {
				return
			}
			assigned, err := h.store.AssignModelAccessRoleSubjects(r.Context(), tenant, roleID, body.SubjectIDs, actor)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]any{"assigned": assigned, "requested": len(body.SubjectIDs)})
			return
		}
		if len(rest) == 3 && rest[2] == "preview" && r.Method == http.MethodPost {
			var body policySubjectFilterRequest
			if !decodeJSON(w, r, &body) {
				return
			}
			count, err := h.store.CountPolicySubjectsByFilter(r.Context(), tenant, body.Field, body.Value)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			sample, err := h.store.ListPolicySubjectsByFilter(r.Context(), tenant, body.Field, body.Value, 20)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]any{"count": count, "sample": sample})
			return
		}
		if len(rest) == 3 && rest[2] == "filter" && r.Method == http.MethodPost {
			var body policySubjectFilterRequest
			if !decodeJSON(w, r, &body) {
				return
			}
			if body.Field != "" && body.Field != "cost_center" {
				http.Error(w, "only cost_center assignment is supported", http.StatusBadRequest)
				return
			}
			values := body.Values
			if len(values) == 0 && strings.TrimSpace(body.Value) != "" {
				values = []string{body.Value}
			}
			assigned, err := h.store.AssignModelAccessRoleByCostCenters(r.Context(), tenant, roleID, values, actor)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]any{"assigned": assigned, "field": "cost_center", "values": values})
			return
		}
		if len(rest) == 2 && r.Method == http.MethodPost {
			var body assignModelAccessRoleRequest
			if !decodeJSON(w, r, &body) {
				return
			}
			if err := h.store.AssignModelAccessRole(r.Context(), tenant, roleID, body.SubjectID, actor); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if len(rest) == 3 && r.Method == http.MethodDelete {
			if err := h.store.RemoveModelAccessRoleSubject(r.Context(), tenant, roleID, rest[2], actor); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	default:
		http.NotFound(w, r)
	}
}

func (h *ModelAccessHandler) handleSubjects(w http.ResponseWriter, r *http.Request, tenant, actor string, rest []string) {
	if len(rest) == 0 {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		subjects, err := h.store.ListPolicySubjects(r.Context(), tenant, r.URL.Query().Get("q"), limit, offset)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if subjects == nil {
			subjects = []storage.PolicySubjectRecord{}
		}
		writeJSON(w, subjects)
		return
	}
	subjectID := rest[0]
	if len(rest) == 1 {
		http.NotFound(w, r)
		return
	}
	switch rest[1] {
	case "effective":
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		effective, err := h.store.GetEffectiveModelAccess(r.Context(), tenant, subjectID, false)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, effective)
	case "grants":
		if r.Method != http.MethodPut {
			w.Header().Set("Allow", "PUT")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body setSubjectModelsRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		if err := h.store.SetSubjectGrants(r.Context(), tenant, subjectID, actor, body.Models); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "restriction":
		if r.Method != http.MethodPut {
			w.Header().Set("Allow", "PUT")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body setSubjectRestrictionRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		if err := h.store.SetSubjectRestriction(r.Context(), tenant, subjectID, actor, body.Enabled, body.Models); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "credits":
		if len(rest) == 2 && r.Method == http.MethodGet {
			credits, err := h.store.ListQuotaCredits(r.Context(), tenant, subjectID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, credits)
			return
		}
		if len(rest) == 2 && r.Method == http.MethodPost {
			var body addQuotaCreditRequest
			if !decodeJSON(w, r, &body) {
				return
			}
			credit, err := h.store.AddQuotaCredit(r.Context(), tenant, subjectID, body.AmountUSD, body.ExpiresAt, body.Reason, actor)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSONStatus(w, http.StatusCreated, credit)
			return
		}
		if len(rest) == 3 && r.Method == http.MethodDelete {
			if err := h.store.DeleteQuotaCredit(r.Context(), tenant, subjectID, rest[2], actor); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	case "exclude-default":
		if r.Method == http.MethodDelete {
			if err := h.store.ClearDefaultExclusion(r.Context(), tenant, subjectID, actor); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST, DELETE")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body excludeDefaultRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		if err := h.store.ExcludeSubjectFromDefault(r.Context(), tenant, subjectID, actor, body.Reason, body.ExpiresAt); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}
