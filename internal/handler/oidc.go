package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const oidcStateCookie = "metering_oidc_state"

var errOIDCUnavailable = errors.New("oidc is not enabled")

// testLoginPanel is injected into the login page only when OIDC_TEST_LOGIN is
// enabled. It is intentionally separate from <!-- OIDC_LOGIN --> so the real
// SSO button stays untouched while the provider integration is in progress.
var testLoginPanel = []byte(`<div class="test-login">
  <div class="divider"><span>Test sign-in</span></div>
  <p>Local demo only. Choose a seeded persona to simulate a user.</p>
  <div class="persona-grid">
    <a class="persona" href="/oauth/login?persona=new-user"><strong>Nina New</strong><span>First-time user</span></a>
    <a class="persona" href="/oauth/login?persona=returning-user"><strong>Ravi Return</strong><span>Returning user</span></a>
    <a class="persona" href="/oauth/login?persona=manager-user"><strong>Maya Manager</strong><span>Team manager</span></a>
    <a class="persona" href="/oauth/login?persona=blocked-country"><strong>Bea Blocked</strong><span>Blocked country</span></a>
    <a class="persona" href="/oauth/login?persona=no-group"><strong>Noah Nogroup</strong><span>No access group</span></a>
    <a class="persona admin" href="/oauth/login?persona=admin"><strong>Noy Itzikowitz</strong><span>Super admin</span></a>
  </div>
</div>`)

// validTestPersona keeps the optional login hint to the safe persona-key
// alphabet used by the local mock IdP. Real deployments never enable it.
func validTestPersona(key string) bool {
	if key == "" || len(key) > 32 {
		return false
	}
	for _, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return false
	}
	return true
}

type oidcState struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
	Persona      string `json:"persona,omitempty"`
	Exp          int64  `json:"exp"`
}

type oidcClaims struct {
	Subject               string   `json:"sub"`
	RhatUUID              string   `json:"rhatUUID"`
	Username              string   `json:"preferred_username"`
	Email                 string   `json:"email"`
	GivenName             string   `json:"given_name"`
	FamilyName            string   `json:"family_name"`
	Groups                []string `json:"groups"`
	Nonce                 string   `json:"nonce"`
	Country               string   `json:"country"`
	State                 string   `json:"state"`
	Region                string   `json:"region"`
	Manager               string   `json:"manager_rhatUUID"`
	CostCenter            string   `json:"cost_center"`
	CostCenterDescription string   `json:"cost_center_description"`
	EmployeeType          string   `json:"employee_type"`
	Organization          string   `json:"organization"`
	Active                any      `json:"active"`
	TerminationDate       string   `json:"termination_date"`
}

type oidcProvider struct {
	config   *oauth2.Config
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

func (h *AuthHandler) InitOIDC(ctx context.Context) error {
	if !h.cfg.OIDC.Enabled {
		return nil
	}
	if !h.cfg.OIDC.EnabledAndConfigured() {
		return fmt.Errorf("OIDC_ENABLED is true but OIDC issuer, client ID, secret, and redirect URL are not all configured")
	}
	provider, err := oidc.NewProvider(ctx, h.cfg.OIDC.IssuerURL)
	if err != nil {
		return fmt.Errorf("discover OIDC provider: %w", err)
	}
	h.oidc = &oidcProvider{
		config: &oauth2.Config{
			ClientID:     h.cfg.OIDC.ClientID,
			ClientSecret: h.cfg.OIDC.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  h.cfg.OIDC.RedirectURL,
			Scopes:       h.cfg.OIDC.Scopes,
		},
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: h.cfg.OIDC.ClientID}),
	}
	return nil
}

func randomURLValue() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (h *AuthHandler) setOIDCState(w http.ResponseWriter, state oidcState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	value := base64.RawURLEncoding.EncodeToString(data) + "." + h.sign(data)
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   10 * 60,
		HttpOnly: true,
		Secure:   h.cfg.SessionCookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (h *AuthHandler) readOIDCState(r *http.Request) (oidcState, error) {
	cookie, err := r.Cookie(oidcStateCookie)
	if err != nil {
		return oidcState{}, fmt.Errorf("oidc state cookie: %w", err)
	}
	parts := strings.SplitN(cookie.Value, ".", 2)
	if len(parts) != 2 {
		return oidcState{}, errors.New("malformed oidc state cookie")
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || !h.verify(data, parts[1]) {
		return oidcState{}, errors.New("invalid oidc state cookie")
	}
	var state oidcState
	if err := json.Unmarshal(data, &state); err != nil || state.State == "" || state.Nonce == "" || state.CodeVerifier == "" {
		return oidcState{}, errors.New("invalid oidc state")
	}
	if time.Now().Unix() > state.Exp {
		return oidcState{}, errors.New("expired oidc state")
	}
	return state, nil
}

func (h *AuthHandler) clearOIDCState(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: oidcStateCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: h.cfg.SessionCookieSecure, SameSite: http.SameSiteLaxMode,
	})
}

// HandleOIDCLogin starts Authorization Code + PKCE. It is unreachable unless
// OIDC_ENABLED=true and provider discovery succeeded during startup.
func (h *AuthHandler) HandleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if h.oidc == nil {
		http.Error(w, errOIDCUnavailable.Error(), http.StatusNotFound)
		return
	}
	stateValue, err := randomURLValue()
	if err != nil {
		http.Error(w, "unable to start SSO", http.StatusInternalServerError)
		return
	}
	nonce, err := randomURLValue()
	if err != nil {
		http.Error(w, "unable to start SSO", http.StatusInternalServerError)
		return
	}
	verifier := oauth2.GenerateVerifier()
	testPersona := ""
	if h.cfg.OIDC.TestLogin {
		if persona := r.URL.Query().Get("persona"); validTestPersona(persona) {
			testPersona = persona
		}
	}
	if err := h.setOIDCState(w, oidcState{
		State: stateValue, Nonce: nonce, CodeVerifier: verifier,
		Persona: testPersona,
		Exp:     time.Now().Add(10 * time.Minute).Unix(),
	}); err != nil {
		http.Error(w, "unable to start SSO", http.StatusInternalServerError)
		return
	}
	options := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", pkceChallenge(verifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	if testPersona != "" {
		// The local mock IdP reads login_hint as its persona key. Real
		// providers would simply treat it as a username hint, but this
		// branch is only reachable with OIDC_TEST_LOGIN enabled.
		options = append(options, oauth2.SetAuthURLParam("login_hint", testPersona))
	}
	url := h.oidc.config.AuthCodeURL(stateValue, options...)
	http.Redirect(w, r, url, http.StatusFound)
}

// HandleOIDCCallback validates the provider response and then uses the
// existing signed PriceTag session cookie. OIDC claims never grant a PriceTag
// role; the active partner directory remains the authorization source.
func (h *AuthHandler) HandleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if h.oidc == nil {
		http.Error(w, errOIDCUnavailable.Error(), http.StatusNotFound)
		return
	}
	state, err := h.readOIDCState(r)
	h.clearOIDCState(w)
	if err != nil || r.URL.Query().Get("state") != state.State {
		http.Error(w, "invalid SSO state", http.StatusBadRequest)
		return
	}
	if providerErr := r.URL.Query().Get("error"); providerErr != "" {
		description := r.URL.Query().Get("error_description")
		slog.Warn("OIDC provider denied authorization", "error", providerErr, "description", description)
		if h.cfg.OIDC.ClaimsDebug {
			h.renderOIDCProviderError(w, providerErr, description)
			return
		}
		http.Error(w, "SSO authorization was denied", http.StatusUnauthorized)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing SSO authorization code", http.StatusBadRequest)
		return
	}
	token, err := h.oidc.config.Exchange(r.Context(), code, oauth2.VerifierOption(state.CodeVerifier))
	if err != nil {
		slog.Warn("OIDC code exchange failed", "error", err)
		http.Error(w, "SSO authorization failed", http.StatusUnauthorized)
		return
	}
	idToken, ok := token.Extra("id_token").(string)
	if !ok || idToken == "" {
		http.Error(w, "SSO response did not contain an ID token", http.StatusUnauthorized)
		return
	}
	verified, err := h.oidc.verifier.Verify(r.Context(), idToken)
	if err != nil {
		http.Error(w, "invalid SSO identity token", http.StatusUnauthorized)
		return
	}
	var claims oidcClaims
	if err := verified.Claims(&claims); err != nil || claims.Subject == "" || claims.Nonce != state.Nonce {
		http.Error(w, "invalid SSO identity claims", http.StatusUnauthorized)
		return
	}
	rawClaims := map[string]map[string]json.RawMessage{}
	var idTokenClaims map[string]json.RawMessage
	if err := verified.Claims(&idTokenClaims); err == nil {
		rawClaims["id_token"] = idTokenClaims
	}
	if h.cfg.OIDC.ClaimsDebug {
		if accessTokenClaims, decodeErr := decodeJWTClaims(token.AccessToken); decodeErr == nil {
			rawClaims["access_token_unverified"] = accessTokenClaims
		}
	}
	// Providers may put custom profile claims in UserInfo rather than the ID
	// token. Merge those claims without allowing them to replace verified token
	// identity fields such as sub, nonce, or rhatUUID.
	if h.oidc.provider != nil && h.oidc.provider.UserInfoEndpoint() != "" {
		if info, infoErr := h.oidc.provider.UserInfo(r.Context(), oauth2.StaticTokenSource(token)); infoErr != nil {
			slog.Warn("OIDC UserInfo request failed", "error", infoErr)
		} else {
			var userInfoClaims oidcClaims
			if infoErr := info.Claims(&userInfoClaims); infoErr != nil {
				slog.Warn("OIDC UserInfo claims decode failed", "error", infoErr)
			} else {
				var rawUserInfo map[string]json.RawMessage
				if rawErr := info.Claims(&rawUserInfo); rawErr == nil {
					rawClaims["userinfo"] = rawUserInfo
				}
				mergeOIDCClaims(&claims, &userInfoClaims)
			}
		}
	}
	if claims.RhatUUID == "" {
		if h.cfg.OIDC.ClaimsDebug {
			h.renderOIDCClaims(w, claims, "/login", "The provider did not return rhatUUID.", rawClaims)
			return
		}
		http.Error(w, "SSO identity is missing rhatUUID", http.StatusUnauthorized)
		return
	}
	username := strings.TrimSpace(claims.Email)
	if username == "" {
		username = strings.TrimSpace(claims.Username)
	}
	if username == "" {
		if h.cfg.OIDC.ClaimsDebug {
			h.renderOIDCClaims(w, claims, "/login", "The provider did not return an email or preferred_username.", rawClaims)
			return
		}
		http.Error(w, "SSO identity is missing email/username", http.StatusUnauthorized)
		return
	}
	if h.orgStore == nil {
		http.Error(w, "SSO directory is unavailable", http.StatusServiceUnavailable)
		return
	}
	user, lookupErr := h.orgStore.PartnerUserByMaaSUsername(r.Context(), username)
	if lookupErr != nil || !user.Active {
		// Do not provision, elevate, or authorize a user from claims alone.
		if h.cfg.OIDC.ClaimsDebug {
			h.renderOIDCClaims(w, claims, "/login", "No active provisioned partner user matched the returned email/username.", rawClaims)
			return
		}
		http.Error(w, "SSO identity is not provisioned in EnMaaS", http.StatusForbidden)
		return
	}
	if !strings.EqualFold(user.UserID, claims.RhatUUID) {
		if h.cfg.OIDC.ClaimsDebug {
			h.renderOIDCClaims(w, claims, "/login", "The returned rhatUUID does not match the provisioned partner user UUID.", rawClaims)
			return
		}
		http.Error(w, "SSO identity does not match the provisioned user", http.StatusForbidden)
		return
	}
	if email, ok := user.Tags["email"].(string); ok && strings.TrimSpace(email) != "" {
		username = email
	}
	// The directory is the authorization source, but the IdP is the freshest
	// source for profile attributes. Persist every returned claim as a merged
	// tag so group membership, state, cost center and the rest are available
	// to the dashboard without waiting for the next LDAP sync. Omitted claims
	// leave the existing tag untouched; login still never provisions or
	// elevates a user from claims alone.
	if err := h.persistOIDCProfile(r.Context(), user.UserID, claims); err != nil {
		slog.Error("persist OIDC profile failed", "username", username, "user_id", user.UserID, "error", err)
		http.Error(w, "SSO profile could not be saved", http.StatusInternalServerError)
		return
	}
	if h.cfg.OIDC.TestLogin && state.Persona == "new-user" {
		if resetErr := h.orgStore.ResetAgreement(r.Context(), user.UserID, "terms", h.cfg.Onboarding.TermsVersion); resetErr != nil {
			slog.Warn("local test persona agreement reset failed", "username", username, "error", resetErr)
		}
	}
	h.setCookie(w, username, claims.Groups, "")
	slog.Info("user logged in with OIDC", "username", username)
	if h.cfg.OIDC.ClaimsDebug {
		h.renderOIDCClaims(w, claims, h.loginDestination(r, username, claims.Groups), "", rawClaims)
		return
	}
	http.Redirect(w, r, h.loginDestination(r, username, claims.Groups), http.StatusFound)
}

// persistOIDCProfile merges the IdP's profile claims into partner-user tags.
// The stable identity fields are still validated before this is called; this
// only enriches the directory record. Tag keys use the directory's snake_case
// convention (the raw camelCase rhatUUID claim maps to rhat_uuid).
func (h *AuthHandler) persistOIDCProfile(ctx context.Context, userID string, claims oidcClaims) error {
	tags := oidcProfileTags(claims)
	if len(tags) == 0 {
		return nil
	}
	_, err := h.orgStore.PatchPartnerUser(ctx, "oidc", userID, tags)
	return err
}

func oidcProfileTags(claims oidcClaims) map[string]any {
	tags := make(map[string]any, 20)
	add := func(key, value string) {
		if value = strings.TrimSpace(value); value != "" {
			tags[key] = value
		}
	}
	add("email", claims.Email)
	add("first_name", claims.GivenName)
	add("last_name", claims.FamilyName)
	add("preferred_username", claims.Username)
	add("oidc_sub", claims.Subject)
	add("rhat_uuid", claims.RhatUUID)
	// Country and state are rendered on the usage map, so normalize their
	// casing here rather than at every read site.
	add("country", strings.ToUpper(strings.TrimSpace(claims.Country)))
	add("state", strings.ToUpper(strings.TrimSpace(claims.State)))
	add("region", claims.Region)
	add("manager_rhat_uuid", claims.Manager)
	add("cost_center", claims.CostCenter)
	add("cost_center_description", claims.CostCenterDescription)
	add("employee_type", claims.EmployeeType)
	add("organization", claims.Organization)
	add("termination_date", claims.TerminationDate)
	switch active := claims.Active.(type) {
	case nil:
	case string:
		add("oidc_active", active)
	default:
		add("oidc_active", fmt.Sprint(active))
	}
	groups := make([]string, 0, len(claims.Groups))
	seen := make(map[string]bool, len(claims.Groups))
	for _, group := range claims.Groups {
		group = strings.TrimSpace(group)
		if group == "" || seen[group] {
			continue
		}
		seen[group] = true
		groups = append(groups, group)
	}
	if len(groups) > 0 {
		tags["groups"] = groups
	}
	return tags
}

func mergeOIDCClaims(dst, src *oidcClaims) {
	if dst.Subject == "" {
		dst.Subject = src.Subject
	}
	if dst.RhatUUID == "" {
		dst.RhatUUID = src.RhatUUID
	}
	if dst.Username == "" {
		dst.Username = src.Username
	}
	if dst.Email == "" {
		dst.Email = src.Email
	}
	if dst.GivenName == "" {
		dst.GivenName = src.GivenName
	}
	if dst.FamilyName == "" {
		dst.FamilyName = src.FamilyName
	}
	if len(dst.Groups) == 0 {
		dst.Groups = src.Groups
	}
	if dst.Country == "" {
		dst.Country = src.Country
	}
	if dst.State == "" {
		dst.State = src.State
	}
	if dst.Region == "" {
		dst.Region = src.Region
	}
	if dst.Manager == "" {
		dst.Manager = src.Manager
	}
	if dst.CostCenter == "" {
		dst.CostCenter = src.CostCenter
	}
	if dst.CostCenterDescription == "" {
		dst.CostCenterDescription = src.CostCenterDescription
	}
	if dst.EmployeeType == "" {
		dst.EmployeeType = src.EmployeeType
	}
	if dst.Organization == "" {
		dst.Organization = src.Organization
	}
	if dst.Active == nil {
		dst.Active = src.Active
	}
	if dst.TerminationDate == "" {
		dst.TerminationDate = src.TerminationDate
	}
}

// decodeJWTClaims is diagnostic-only. The access token is never used as an
// identity source; this only tells a developer whether a provider placed
// additional claims in a JWT access token. Opaque access tokens produce no
// diagnostic section.
func decodeJWTClaims(raw string) (map[string]json.RawMessage, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("access token is opaque")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func (h *AuthHandler) renderOIDCProviderError(w http.ResponseWriter, providerError, description string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>OIDC diagnostic</title>
<style>body{font:16px system-ui;max-width:800px;margin:40px auto;padding:0 20px;background:#0b0e11;color:#e0e3e8}code{color:#f5a97f}</style></head><body>
<h1>OIDC provider denied authorization</h1><p>This is a development-only diagnostic. No token or secret was displayed.</p>
<p><strong>error:</strong> <code>%s</code></p><p><strong>error_description:</strong> <code>%s</code></p>
</body></html>`, html.EscapeString(providerError), html.EscapeString(description))
}

// renderOIDCClaims is intentionally opt-in and intended only for a
// development/stage integration test. It renders decoded claims, never the
// raw ID token or client secret. Keep OIDC_CLAIMS_DEBUG=false in production.
func (h *AuthHandler) renderOIDCClaims(w http.ResponseWriter, claims oidcClaims, destination, diagnosticMessage string, rawClaims map[string]map[string]json.RawMessage) {
	value := func(v string) string {
		if v == "" {
			return "<em>not returned</em>"
		}
		return html.EscapeString(v)
	}
	active := "<em>not returned</em>"
	if claims.Active != nil {
		active = html.EscapeString(fmt.Sprint(claims.Active))
	}
	groups := "<em>not returned</em>"
	if len(claims.Groups) > 0 {
		items := make([]string, 0, len(claims.Groups))
		for _, group := range claims.Groups {
			items = append(items, "<li>"+html.EscapeString(group)+"</li>")
		}
		groups = "<ul>" + strings.Join(items, "") + "</ul>"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	note := ""
	if diagnosticMessage != "" {
		note = `<p style="color:#f5a97f"><strong>Mapping result:</strong> ` + html.EscapeString(diagnosticMessage) + `</p>`
	}
	rawJSON, _ := json.MarshalIndent(rawClaims, "", "  ")
	rawBlock := "<pre>" + html.EscapeString(string(rawJSON)) + "</pre>"
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>OIDC claim diagnostic</title>
<style>body{font:16px system-ui;max-width:1000px;margin:40px auto;padding:0 20px;background:#0b0e11;color:#e0e3e8}table{border-collapse:collapse;width:100%%}td{border-bottom:1px solid #333;padding:8px}td:first-child{font-family:monospace;color:#8ab4f8;width:260px}pre{white-space:pre-wrap;background:#161b22;padding:16px;overflow:auto}a{color:#58a6ff}</style></head><body>
<h1>OIDC claim diagnostic</h1><p>Development/stage only. The raw token was not displayed.</p>%s<table>
<tr><td>sub</td><td>%s</td></tr><tr><td>rhatUUID</td><td>%s</td></tr><tr><td>preferred_username</td><td>%s</td></tr><tr><td>email</td><td>%s</td></tr><tr><td>given_name</td><td>%s</td></tr><tr><td>family_name</td><td>%s</td></tr><tr><td>groups</td><td>%s</td></tr><tr><td>country</td><td>%s</td></tr><tr><td>state</td><td>%s</td></tr><tr><td>region</td><td>%s</td></tr><tr><td>manager_rhatUUID</td><td>%s</td></tr><tr><td>cost_center</td><td>%s</td></tr><tr><td>cost_center_description</td><td>%s</td></tr><tr><td>employee_type</td><td>%s</td></tr><tr><td>organization</td><td>%s</td></tr><tr><td>active</td><td>%s</td></tr><tr><td>termination_date</td><td>%s</td></tr>

</table><h2>Decoded claim structure</h2>%s<p><a href="%s">Continue to PriceTag</a></p></body></html>`,
		note, value(claims.Subject), value(claims.RhatUUID), value(claims.Username), value(claims.Email), value(claims.GivenName), value(claims.FamilyName), groups,
		value(claims.Country), value(claims.State), value(claims.Region), value(claims.Manager), value(claims.CostCenter), value(claims.CostCenterDescription), value(claims.EmployeeType), value(claims.Organization), active, value(claims.TerminationDate), rawBlock, html.EscapeString(destination))
}
