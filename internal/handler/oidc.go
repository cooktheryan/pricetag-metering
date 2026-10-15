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

type oidcState struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
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
	if err := h.setOIDCState(w, oidcState{
		State: stateValue, Nonce: nonce, CodeVerifier: verifier,
		Exp: time.Now().Add(10 * time.Minute).Unix(),
	}); err != nil {
		http.Error(w, "unable to start SSO", http.StatusInternalServerError)
		return
	}
	url := h.oidc.config.AuthCodeURL(stateValue,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", pkceChallenge(verifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
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
	if claims.RhatUUID == "" {
		if h.cfg.OIDC.ClaimsDebug {
			h.renderOIDCClaims(w, claims, "/login", "The provider did not return rhatUUID.")
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
			h.renderOIDCClaims(w, claims, "/login", "The provider did not return an email or preferred_username.")
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
			h.renderOIDCClaims(w, claims, "/login", "No active provisioned partner user matched the returned email/username.")
			return
		}
		http.Error(w, "SSO identity is not provisioned in EnMaaS", http.StatusForbidden)
		return
	}
	if !strings.EqualFold(user.UserID, claims.RhatUUID) {
		if h.cfg.OIDC.ClaimsDebug {
			h.renderOIDCClaims(w, claims, "/login", "The returned rhatUUID does not match the provisioned partner user UUID.")
			return
		}
		http.Error(w, "SSO identity does not match the provisioned user", http.StatusForbidden)
		return
	}
	if email, ok := user.Tags["email"].(string); ok && strings.TrimSpace(email) != "" {
		username = email
	}
	h.setCookie(w, username, claims.Groups, "")
	slog.Info("user logged in with OIDC", "username", username)
	if h.cfg.OIDC.ClaimsDebug {
		h.renderOIDCClaims(w, claims, h.loginDestination(r, username), "")
		return
	}
	http.Redirect(w, r, h.loginDestination(r, username), http.StatusFound)
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
func (h *AuthHandler) renderOIDCClaims(w http.ResponseWriter, claims oidcClaims, destination, diagnosticMessage string) {
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
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>OIDC claim diagnostic</title>
<style>body{font:16px system-ui;max-width:900px;margin:40px auto;padding:0 20px;background:#0b0e11;color:#e0e3e8}table{border-collapse:collapse;width:100%%}td{border-bottom:1px solid #333;padding:8px}td:first-child{font-family:monospace;color:#8ab4f8;width:260px}a{color:#58a6ff}</style></head><body>
<h1>OIDC claim diagnostic</h1><p>Development/stage only. The raw token was not displayed.</p>%s<table>
<tr><td>sub</td><td>%s</td></tr><tr><td>rhatUUID</td><td>%s</td></tr><tr><td>preferred_username</td><td>%s</td></tr><tr><td>email</td><td>%s</td></tr><tr><td>given_name</td><td>%s</td></tr><tr><td>family_name</td><td>%s</td></tr><tr><td>groups</td><td>%s</td></tr><tr><td>country</td><td>%s</td></tr><tr><td>state</td><td>%s</td></tr><tr><td>region</td><td>%s</td></tr><tr><td>manager_rhatUUID</td><td>%s</td></tr><tr><td>cost_center</td><td>%s</td></tr><tr><td>cost_center_description</td><td>%s</td></tr><tr><td>employee_type</td><td>%s</td></tr><tr><td>organization</td><td>%s</td></tr><tr><td>active</td><td>%s</td></tr><tr><td>termination_date</td><td>%s</td></tr>
</table><p><a href="%s">Continue to PriceTag</a></p></body></html>`,
		note, value(claims.Subject), value(claims.RhatUUID), value(claims.Username), value(claims.Email), value(claims.GivenName), value(claims.FamilyName), groups,
		value(claims.Country), value(claims.State), value(claims.Region), value(claims.Manager), value(claims.CostCenter), value(claims.CostCenterDescription), value(claims.EmployeeType), value(claims.Organization), active, value(claims.TerminationDate), html.EscapeString(destination))
}
