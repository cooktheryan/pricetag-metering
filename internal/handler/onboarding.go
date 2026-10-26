package handler

import (
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/redhat-et/pricetag-metering/internal/dashboard"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

// OnboardingHandler serves the authenticated first-run wizard, the account
// shell, the Terms document, and the gate status/acceptance API.
type OnboardingHandler struct {
	gate  *AccessGate
	store *storage.Store
}

func NewOnboardingHandler(gate *AccessGate, store *storage.Store) *OnboardingHandler {
	return &OnboardingHandler{gate: gate, store: store}
}

// ServeOnboarding renders the checklist. The page fetches the real state
// from /api/v1/me/onboarding; the HTML carries no policy.
func (h *OnboardingHandler) ServeOnboarding(w http.ResponseWriter, r *http.Request) {
	h.servePage(w, "onboarding.html")
}

// ServeAccount renders the user account shell (Usage + API Keys tabs). The
// gateway host is injected at serve time, exactly like /welcome, so no
// cluster-specific URL enters the repository.
func (h *OnboardingHandler) ServeAccount(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(dashboard.FS, "account.html")
	if err != nil {
		http.Error(w, "page not found", http.StatusInternalServerError)
		return
	}
	gateway := h.gate.cfg.Welcome.GatewayURL
	if gateway == "" {
		gateway = welcomeGatewayFallback
	}
	page := strings.NewReplacer("{{GATEWAY_URL}}", htmlEscape(gateway)).Replace(string(data))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write([]byte(page))
}

// ServeAccessPolicyPage renders the super-admin country/group policy form.
func (h *OnboardingHandler) ServeAccessPolicyPage(w http.ResponseWriter, r *http.Request) {
	h.servePage(w, "access-policy.html")
}

// ServeTerms renders the versioned Terms document. The text is intentionally
// a clearly marked draft until Legal supplies the approved copy.
func (h *OnboardingHandler) ServeTerms(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(dashboard.FS, "terms.html")
	if err != nil {
		http.Error(w, "terms page not found", http.StatusInternalServerError)
		return
	}
	version := h.gate.cfg.Onboarding.TermsVersion
	page := strings.NewReplacer(
		"{{TERMS_VERSION}}", htmlEscape(version),
		"{{TERMS_STATUS}}", termsStatus(version),
	).Replace(string(data))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write([]byte(page))
}

func (h *OnboardingHandler) servePage(w http.ResponseWriter, name string) {
	data, err := fs.ReadFile(dashboard.FS, name)
	if err != nil {
		http.Error(w, "page not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}

// HandleState returns the gate verdict for the signed-in caller.
func (h *OnboardingHandler) HandleState(w http.ResponseWriter, r *http.Request) {
	state, err := h.gate.StateForRequest(r)
	if err != nil {
		slog.Error("onboarding state failed", "error", err)
		http.Error(w, "could not evaluate onboarding", http.StatusInternalServerError)
		return
	}
	h.audit(r, state)
	writeJSON(w, state)
}

// HandleAcceptTerms records acceptance of the current Terms version. It is
// idempotent and refuses to act while a super-admin is impersonating.
func (h *OnboardingHandler) HandleAcceptTerms(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	if r.Header.Get(realUserHeader) != "" {
		http.Error(w, "cannot accept terms while viewing as another user", http.StatusForbidden)
		return
	}
	var body struct {
		Version  string `json:"version"`
		Accepted bool   `json:"accepted"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if !body.Accepted {
		http.Error(w, "you must accept the terms to continue", http.StatusBadRequest)
		return
	}
	current := h.gate.cfg.Onboarding.TermsVersion
	if body.Version != "" && body.Version != current {
		http.Error(w, "the terms have changed; reload the page", http.StatusConflict)
		return
	}

	state, err := h.gate.StateForRequest(r)
	if err != nil {
		slog.Error("onboarding state failed before acceptance", "error", err)
		http.Error(w, "could not evaluate onboarding", http.StatusInternalServerError)
		return
	}
	if state.UserID == "" {
		http.Error(w, "no provisioned user for this identity", http.StatusForbidden)
		return
	}
	if !state.Allowed && state.BlockedReason != "" && state.BlockedReason != "terms_required" {
		// Group/country failures are not fixable by accepting terms.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(state)
		return
	}

	inserted, err := h.store.RecordAgreement(r.Context(), storage.Agreement{
		UserID:    state.UserID,
		DocType:   "terms",
		Version:   current,
		IP:        clientIP(r),
		UserAgent: truncate(r.UserAgent(), 512),
		Method:    loginMethod(r),
	})
	if err != nil {
		slog.Error("record terms acceptance failed", "error", err)
		http.Error(w, "could not record acceptance", http.StatusInternalServerError)
		return
	}
	if inserted {
		_ = h.store.RecordAccessAudit(r.Context(), state.UserID, state.Username, "terms_accepted", GateTerms, current, map[string]any{
			"version": current,
			"method":  loginMethod(r),
		})
		slog.Info("terms accepted", "user", state.Username, "version", current)
	}

	next, err := h.gate.StateForRequest(r)
	if err != nil {
		http.Error(w, "could not evaluate onboarding", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"ok":       true,
		"state":    next,
		"redirect": "/account?tab=keys&first=1",
	})
}

// audit writes one gate decision per page/API load. Best-effort: a failed
// audit never breaks the page.
func (h *OnboardingHandler) audit(r *http.Request, state OnboardingState) {
	event := "gate_pass"
	if state.State != OnboardingReady {
		event = "gate_denied"
	}
	_ = h.store.RecordAccessAudit(r.Context(), state.UserID, state.Username, event, "", state.BlockedReason, map[string]any{
		"mode":   state.Mode,
		"state":  state.State,
		"groups": len(state.Groups),
		// Country is recorded as the normalised ISO3 for the audit trail but
		// is never returned in the API response.
		"country": state.Country,
	})
}

// --- Admin policy endpoints -------------------------------------------------

// HandleAccessPolicy lets a super admin read and update the country/group
// policy without a redeploy. Country entries must be ISO 3166-1 alpha-3.
func (h *OnboardingHandler) HandleAccessPolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		policy := h.gate.EffectivePolicy(r.Context())
		if h.store != nil {
			if stored, err := h.store.GetAccessPolicy(r.Context()); err == nil {
				if stored.Configured {
					policy = stored
				}
			} else {
				http.Error(w, "could not read policy", http.StatusInternalServerError)
				return
			}
		}
		writeJSON(w, policy)
	case http.MethodPut:
		if !sameOrigin(r) {
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
		var body struct {
			AllowedGroups       []string `json:"allowed_groups"`
			BlockedCountries    []string `json:"blocked_countries"`
			AllowUnknownCountry bool     `json:"allow_unknown_country"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 32<<10)).Decode(&body); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		for i := range body.BlockedCountries {
			code := normalizeCountry(body.BlockedCountries[i])
			if code == "" || !knownISO3(code) {
				http.Error(w, "blocked countries must be ISO 3166-1 alpha-3 codes", http.StatusBadRequest)
				return
			}
			body.BlockedCountries[i] = code
		}
		saved, err := h.store.SaveAccessPolicy(r.Context(), storage.AccessPolicy{
			AllowedGroups:       body.AllowedGroups,
			BlockedCountries:    body.BlockedCountries,
			AllowUnknownCountry: body.AllowUnknownCountry,
		}, caller(r, h.gate.cfg))
		if err != nil {
			slog.Error("save access policy failed", "error", err)
			http.Error(w, "could not save policy", http.StatusInternalServerError)
			return
		}
		_ = h.store.RecordAccessAudit(r.Context(), "", caller(r, h.gate.cfg), "access_policy_updated", "", "", map[string]any{
			"allowed_groups":        saved.AllowedGroups,
			"blocked_countries":     saved.BlockedCountries,
			"allow_unknown_country": saved.AllowUnknownCountry,
		})
		writeJSON(w, saved)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func knownISO3(code string) bool {
	for _, v := range iso2ToISO3 {
		if v == code {
			return true
		}
	}
	return false
}

func sameOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		// Tests and non-browser clients omit Origin. The session cookie is
		// SameSite=Lax and HMAC-signed, so this is not an open write path.
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first := strings.TrimSpace(strings.Split(xff, ",")[0]); net.ParseIP(first) != nil {
			return first
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	if net.ParseIP(host) == nil {
		return ""
	}
	return host
}

func loginMethod(r *http.Request) string {
	if r.Header.Get("X-Auth-Method") == "oidc" {
		return "oidc"
	}
	return "session"
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

func htmlEscape(s string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return replacer.Replace(s)
}

func termsStatus(version string) string {
	if strings.HasPrefix(strings.ToLower(version), "draft") {
		return "DRAFT — pending Legal approval. Do not treat this text as the final agreement."
	}
	return "Version " + version
}
