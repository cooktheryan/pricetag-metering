package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
	Subject    string   `json:"sub"`
	RhatUUID   string   `json:"rhatUUID"`
	Username   string   `json:"preferred_username"`
	Email      string   `json:"email"`
	GivenName  string   `json:"given_name"`
	FamilyName string   `json:"family_name"`
	Groups     []string `json:"groups"`
	Nonce      string   `json:"nonce"`
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
		http.Error(w, "SSO identity is missing rhatUUID", http.StatusUnauthorized)
		return
	}
	username := strings.TrimSpace(claims.Email)
	if username == "" {
		username = strings.TrimSpace(claims.Username)
	}
	if username == "" {
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
		http.Error(w, "SSO identity is not provisioned in EnMaaS", http.StatusForbidden)
		return
	}
	if !strings.EqualFold(user.UserID, claims.RhatUUID) {
		http.Error(w, "SSO identity does not match the provisioned user", http.StatusForbidden)
		return
	}
	if email, ok := user.Tags["email"].(string); ok && strings.TrimSpace(email) != "" {
		username = email
	}
	h.setCookie(w, username, claims.Groups, "")
	slog.Info("user logged in with OIDC", "username", username)
	http.Redirect(w, r, h.loginDestination(r, username), http.StatusFound)
}
