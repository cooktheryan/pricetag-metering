package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

// Gate check identifiers and statuses. The onboarding page renders these
// literally, so the IDs are part of the API contract.
const (
	GateIdentity = "identity"
	GateGroup    = "group"
	GateCountry  = "country"
	GateTerms    = "terms"

	GatePass    = "pass"
	GateFail    = "fail"
	GatePending = "pending"
	GateSkipped = "skipped"

	OnboardingReady      = "ready"
	OnboardingNeedsTerms = "needs_terms"
	OnboardingBlocked    = "blocked"
)

// GateCheck is one row of the onboarding checklist.
type GateCheck struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Status string `json:"status"`
	// Detail is a short, non-sensitive explanation used by the UI. It never
	// contains claims, country values, or other policy internals.
	Detail string `json:"detail,omitempty"`
}

// OnboardingState is the server's complete verdict on one person. The page
// is a renderer of this struct; no gate is ever evaluated client-side.
type OnboardingState struct {
	Mode          string      `json:"mode"`
	State         string      `json:"state"`
	Allowed       bool        `json:"allowed"`
	Checks        []GateCheck `json:"checks"`
	Terms         TermsInfo   `json:"terms"`
	BlockedReason string      `json:"blocked_reason,omitempty"`
	Username      string      `json:"username"`
	UserID        string      `json:"user_id,omitempty"`
	Groups        []string    `json:"groups"`
	DisplayName   string      `json:"display_name,omitempty"`
	Country       string      `json:"-"` // never serialised
	CountryState  string      `json:"-"`
	GroupState    string      `json:"-"`
}

// TermsInfo describes the document the user must accept.
type TermsInfo struct {
	Version   string `json:"version"`
	URL       string `json:"url"`
	Accepted  bool   `json:"accepted"`
	AcceptURL string `json:"accept_url"`
}

// AccessGate evaluates the identity/group/country/terms gates. It is shared
// by the login redirect, the page middleware, and the API middleware so the
// three can never disagree.
type AccessGate struct {
	cfg   config.Config
	store *storage.Store
}

func NewAccessGate(cfg config.Config, store *storage.Store) *AccessGate {
	return &AccessGate{cfg: cfg, store: store}
}

// technicalGroups are IdP plumbing that must never count as business
// authorization. The Stage realm currently ships these in the groups claim
// because the mapper is a User Realm Role mapper.
var technicalGroups = map[string]struct{}{
	"offline_access":    {},
	"uma_authorization": {},
	"account":           {},
}

// NormalizeGroups trims, drops technical roles, de-duplicates, and sorts.
func NormalizeGroups(groups []string) []string {
	seen := make(map[string]struct{}, len(groups))
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		lower := strings.ToLower(g)
		if _, technical := technicalGroups[lower]; technical {
			continue
		}
		if strings.HasPrefix(lower, "default-roles-") || strings.HasSuffix(lower, "_authorization") {
			continue
		}
		if _, ok := seen[lower]; ok {
			continue
		}
		seen[lower] = struct{}{}
		out = append(out, g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return strings.ToLower(out[i]) < strings.ToLower(out[j])
	})
	return out
}

// EffectivePolicy returns the database policy when a super admin has saved
// one, otherwise the deployment defaults. A database error falls back to the
// environment rather than opening access.
func (g *AccessGate) EffectivePolicy(ctx context.Context) storage.AccessPolicy {
	if g.store != nil {
		if p, err := g.store.GetAccessPolicy(ctx); err == nil && p.Configured {
			return p
		} else if err != nil {
			slog.Warn("access policy lookup failed; using deployment defaults", "error", err)
		}
	}
	return storage.AccessPolicy{
		AllowedGroups:       g.cfg.Access.AllowedGroups,
		BlockedCountries:    g.cfg.Access.BlockedCountries,
		AllowUnknownCountry: g.cfg.Access.AllowUnknownCountry,
	}
}

// Evaluate resolves every gate for the given identity. It returns an error
// only for infrastructure failures; a denied person is a normal state.
func (g *AccessGate) Evaluate(ctx context.Context, username string, groups []string) (OnboardingState, error) {
	mode := g.cfg.Onboarding.Mode
	state := OnboardingState{
		Mode:     mode,
		Username: username,
		Groups:   NormalizeGroups(groups),
		Terms: TermsInfo{
			Version:   g.cfg.Onboarding.TermsVersion,
			URL:       g.cfg.Onboarding.TermsURL,
			AcceptURL: "/api/v1/me/onboarding/accept",
		},
	}

	identity := GateCheck{ID: GateIdentity, Label: "Red Hat identity", Status: GateFail}
	group := GateCheck{ID: GateGroup, Label: "EnMaaS access group", Status: GateFail}
	country := GateCheck{ID: GateCountry, Label: "Region eligibility", Status: GateFail}
	terms := GateCheck{ID: GateTerms, Label: "Terms & Conditions", Status: GatePending}

	if g.store == nil {
		identity.Detail = "The user directory is unavailable."
		state.Checks = []GateCheck{identity, group, country, terms}
		state.State = OnboardingBlocked
		state.BlockedReason = "directory_unavailable"
		state.CountryState, state.GroupState = GateFail, GateFail
		return state, nil
	}

	user, err := g.store.PartnerUserByMaaSUsername(ctx, username)
	if err != nil {
		if !errors.Is(err, storage.ErrPartnerUserNotFound) {
			return state, err
		}
		identity.Detail = "This identity is not provisioned in EnMaaS."
		state.Checks = []GateCheck{identity, group, country, terms}
		state.State = OnboardingBlocked
		state.BlockedReason = "not_provisioned"
		state.CountryState, state.GroupState = GateFail, GateFail
		return state, nil
	}
	state.UserID = user.UserID
	if user.Tags != nil {
		if first, _ := user.Tags["first_name"].(string); first != "" {
			state.DisplayName = strings.TrimSpace(first)
			if last, _ := user.Tags["last_name"].(string); last != "" {
				state.DisplayName += " " + strings.TrimSpace(last)
			}
		}
	}
	if !user.Active {
		identity.Detail = "This account is not active."
		state.Checks = []GateCheck{identity, group, country, terms}
		state.State = OnboardingBlocked
		state.BlockedReason = "inactive"
		state.CountryState, state.GroupState = GateFail, GateFail
		return state, nil
	}
	identity.Status = GatePass
	identity.Detail = ""
	state.GroupState = GatePass
	state.CountryState = GatePass

	// Temporary dev-login scaffolding: explicitly allowlisted dev_test
	// identities exercise the enforced gates even when this deployment ships
	// with onboarding off. Real users keep the deployment's mode.
	if g.devEnforcedIdentity(username, user.Tags) {
		mode = config.OnboardingEnforce
		state.Mode = mode
	}

	// --- Group gate -------------------------------------------------------
	// Source of truth is the OIDC groups claim carried in the signed session.
	// The allowlist is case-insensitive; an empty allowlist accepts any
	// non-technical group ("whatever group the user has").
	policy := g.EffectivePolicy(ctx)
	if len(state.Groups) == 0 {
		group.Status = GateFail
		group.Detail = "No EnMaaS group was returned by your identity provider."
		state.GroupState = GateFail
	} else if len(policy.AllowedGroups) > 0 {
		allowed := make(map[string]struct{}, len(policy.AllowedGroups))
		for _, a := range policy.AllowedGroups {
			allowed[strings.ToLower(strings.TrimSpace(a))] = struct{}{}
		}
		matched := false
		for _, ug := range state.Groups {
			if _, ok := allowed[strings.ToLower(ug)]; ok {
				matched = true
				break
			}
		}
		if matched {
			group.Status = GatePass
		} else {
			group.Status = GateFail
			group.Detail = "Your account is not in an authorized EnMaaS group."
			state.GroupState = GateFail
		}
	} else {
		group.Status = GatePass
	}

	// --- Country gate -----------------------------------------------------
	// The blocklist is ISO-3166 alpha-3. The directory stores alpha-2 (LDAP
	// feed), so both are normalised before comparison. The raw country value
	// is deliberately not serialised.
	rawCountry := ""
	if user.Tags != nil {
		rawCountry, _ = user.Tags["country"].(string)
	}
	iso3 := normalizeCountry(rawCountry)
	state.Country = iso3
	if iso3 == "" {
		if policy.AllowUnknownCountry || g.cfg.Access.AllowUnknownCountry {
			country.Status = GatePass
			country.Detail = "Region could not be verified; access is allowed by policy."
		} else {
			country.Status = GateFail
			country.Detail = "We could not verify your region. Contact the EnMaaS team."
			state.CountryState = GateFail
		}
	} else {
		blocked := false
		for _, b := range policy.BlockedCountries {
			if normalizeCountry(b) == iso3 {
				blocked = true
				break
			}
		}
		if blocked {
			country.Status = GateFail
			country.Detail = "EnMaaS is not available in your region."
			state.CountryState = GateFail
		} else {
			country.Status = GatePass
		}
	}

	// --- Terms gate -------------------------------------------------------
	accepted, err := g.store.HasAgreement(ctx, user.UserID, "terms", g.cfg.Onboarding.TermsVersion)
	if err != nil {
		return state, err
	}
	state.Terms.Accepted = accepted
	if accepted {
		terms.Status = GatePass
	} else {
		terms.Status = GatePending
	}

	state.Checks = []GateCheck{identity, group, country, terms}

	// A blocked identity/group/country short-circuits terms.
	switch {
	case state.GroupState == GateFail:
		state.State = OnboardingBlocked
		state.BlockedReason = "group_required"
	case state.CountryState == GateFail:
		state.State = OnboardingBlocked
		if iso3 == "" {
			state.BlockedReason = "country_unknown"
		} else {
			state.BlockedReason = "country_blocked"
		}
	case !accepted:
		state.State = OnboardingNeedsTerms
	default:
		state.State = OnboardingReady
	}

	// Off/observe never block traffic. Observe still reports the real state
	// so operators can see the would-be decision in the UI and logs.
	switch mode {
	case config.OnboardingOff:
		state.State = OnboardingReady
		for i := range state.Checks {
			if state.Checks[i].Status == GateFail {
				state.Checks[i].Status = GateSkipped
			}
			if state.Checks[i].ID == GateTerms {
				state.Checks[i].Status = GateSkipped
			}
		}
		state.Allowed = true
	case config.OnboardingObserve:
		state.Allowed = true
	default:
		state.Allowed = state.State == OnboardingReady
	}
	return state, nil
}

// StateForRequest evaluates the identity the auth middleware placed on the
// request. The impersonated identity is intentionally used here: a
// super-admin "viewing as" should see exactly what that person sees.
func (g *AccessGate) StateForRequest(r *http.Request) (OnboardingState, error) {
	return g.Evaluate(r.Context(), caller(r, g.cfg), sessionGroups(r, g.cfg))
}

// RequireAccount page gate. Unready users are sent to /onboarding, which is
// the only authenticated page that renders the checklist.
func (g *AccessGate) RequireAccount(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := g.StateForRequest(r)
		if err != nil {
			slog.Error("onboarding gate failed", "error", err)
			http.Error(w, "onboarding check failed", http.StatusInternalServerError)
			return
		}
		if !state.Allowed {
			http.Redirect(w, r, "/onboarding", http.StatusFound)
			return
		}
		next(w, r)
	}
}

// RequireOnboardedAPI returns 403 with the machine-readable state instead of
// redirecting, so the account page can render the reason.
func (g *AccessGate) RequireOnboardedAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := g.StateForRequest(r)
		if err != nil {
			slog.Error("onboarding gate failed", "error", err)
			http.Error(w, "onboarding check failed", http.StatusInternalServerError)
			return
		}
		if !state.Allowed || state.State != OnboardingReady {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":  "onboarding_required",
				"state":  state.State,
				"reason": state.BlockedReason,
			})
			return
		}
		next(w, r)
	}
}

// NeedsOnboarding reports whether a just-authenticated user must be sent to
// the wizard instead of their normal landing page.
func (g *AccessGate) NeedsOnboarding(ctx context.Context, username string, groups []string) bool {
	// Without dev identities there is nothing to override, so avoid the
	// directory lookup entirely when onboarding is disabled.
	if g.cfg.Onboarding.Mode != config.OnboardingEnforce && len(g.cfg.DevLoginUsers) == 0 {
		return false
	}
	state, err := g.Evaluate(ctx, username, groups)
	if err != nil {
		slog.Error("onboarding evaluation failed at login", "error", err)
		return false
	}
	if state.Mode != config.OnboardingEnforce {
		return false
	}
	return !state.Allowed || state.State != OnboardingReady
}

// devEnforcedIdentity reports whether the temporary dev-login scaffolding
// should apply the enforced onboarding gates to this identity. It requires the
// deployment to have dev identities configured, the username to be explicitly
// allowlisted, and the directory row to carry dev_test=true.
func (g *AccessGate) devEnforcedIdentity(username string, tags map[string]any) bool {
	if len(g.cfg.DevLoginUsers) == 0 || !isDevTestUser(tags) {
		return false
	}
	for _, allowed := range g.cfg.DevLoginUsers {
		if strings.EqualFold(strings.TrimSpace(allowed), username) {
			return true
		}
	}
	return false
}
