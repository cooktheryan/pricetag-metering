package handler

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/dashboard"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

const (
	cookieName   = "metering_session"
	cookieMaxAge = 7 * 24 * time.Hour

	// realUserHeader carries the true session identity while an admin is
	// "viewing as" another user, so the UI can render a banner and the
	// whoami endpoint can report both identities.
	realUserHeader = "X-Forwarded-Real-User"
)

type sessionPayload struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
	// As, when set by an admin via HandleImpersonate, swaps the identity
	// header to this user for the rest of the session.
	As  string `json:"as,omitempty"`
	Exp int64  `json:"exp"`
}

type AuthHandler struct {
	cfg        config.Config
	secret     []byte
	httpClient *http.Client
	oidc       *oidcProvider
	// orgStore backs the post-login manager redirect: people whose directory
	// record has reports land on /manager, the view they actually came for.
	// Optional — a nil store (or a lookup failure) keeps the old behaviour
	// and lands everyone on /dashboard.
	orgStore  *storage.Store
	oidcStore oidcPartnerStore
}

type oidcPartnerStore interface {
	GetPartnerUser(context.Context, string) (storage.PartnerUser, error)
	CurrentPartnerUserLogin(context.Context, string) (string, error)
	PatchPartnerUser(context.Context, string, string, map[string]any) (storage.PartnerUser, error)
}

// SetOrgStore wires the directory lookup used by the login redirect. Kept a
// setter so login stays constructible without a database (tests, lite
// deployments).
func (h *AuthHandler) SetOrgStore(s *storage.Store) {
	h.orgStore = s
	h.oidcStore = s
}

func (h *AuthHandler) setOIDCPartnerStore(s oidcPartnerStore) { h.oidcStore = s }

func NewAuthHandler(cfg config.Config) *AuthHandler {
	secret := []byte(os.Getenv("SESSION_SECRET"))
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			panic("failed to generate session secret: " + err.Error())
		}
		slog.Warn("SESSION_SECRET not set — using random secret (sessions won't survive restarts)")
	}
	return &AuthHandler{
		cfg:    cfg,
		secret: secret,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (h *AuthHandler) sign(data []byte) string {
	mac := hmac.New(sha256.New, h.secret)
	mac.Write(data)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (h *AuthHandler) verify(data []byte, sig string) bool {
	expected := h.sign(data)
	return hmac.Equal([]byte(expected), []byte(sig))
}

func (h *AuthHandler) setCookie(w http.ResponseWriter, username string, groups []string, as string) {
	payload := sessionPayload{
		Username: username,
		Groups:   groups,
		As:       as,
		Exp:      time.Now().Add(cookieMaxAge).Unix(),
	}
	data, _ := json.Marshal(payload)
	sig := h.sign(data)
	value := base64.RawURLEncoding.EncodeToString(data) + "." + sig

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(cookieMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   h.cfg.SessionCookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *AuthHandler) readCookie(r *http.Request) *sessionPayload {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	parts := strings.SplitN(c.Value, ".", 2)
	if len(parts) != 2 {
		return nil
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}
	if !h.verify(data, parts[1]) {
		return nil
	}
	var payload sessionPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil
	}
	if time.Now().Unix() > payload.Exp {
		return nil
	}
	return &payload
}

func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		data, err := fs.ReadFile(dashboard.FS, "login.html")
		if err != nil {
			http.Error(w, "login page not found", http.StatusInternalServerError)
			return
		}
		if h.oidc != nil {
			data = bytes.Replace(data, []byte("<!-- OIDC_LOGIN -->"), []byte(`<a class="sso-button" href="/oauth/login">Sign in with Red Hat SSO</a>`), 1)
		} else {
			data = bytes.Replace(data, []byte("<!-- OIDC_LOGIN -->"), nil, 1)
		}
		// Local/demo shortcuts only: the mock IdP picker is shown below the
		// production SSO link when explicitly enabled.
		if h.oidcTestLoginAllowed(r) {
			data = bytes.Replace(data, []byte("<!-- TEST_LOGIN -->"), testLoginPanel, 1)
		} else {
			data = bytes.Replace(data, []byte("<!-- TEST_LOGIN -->"), nil, 1)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(data)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Login changes the browser's identity, so it needs CSRF protection even
	// before a session exists. Keep legacy deployments unchanged.
	if h.cfg.ManagementAPISecret != "" && (h.cfg.ManagementPublicOrigin == "" ||
		r.Header.Get("Origin") != h.cfg.ManagementPublicOrigin || r.Header.Get("Sec-Fetch-Site") == "cross-site") {
		http.Error(w, "same-origin request required", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid login form", http.StatusBadRequest)
		return
	}
	apiKey := strings.TrimSpace(r.FormValue("api_key"))
	if apiKey == "" {
		http.Redirect(w, r, "/login?error=invalid", http.StatusFound)
		return
	}

	validateURL := os.Getenv("MAAS_VALIDATE_URL")
	if validateURL == "" {
		validateURL = "http://maas-api:8080/internal/v1/api-keys/validate"
	}

	body, _ := json.Marshal(map[string]string{"key": apiKey})
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, validateURL, bytes.NewReader(body))
	if err != nil {
		slog.Error("failed to build validate request", "error", err)
		http.Redirect(w, r, "/login?error=invalid", http.StatusFound)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		slog.Error("maas-api validate failed", "error", err)
		http.Redirect(w, r, "/login?error=invalid", http.StatusFound)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Redirect(w, r, "/login?error=invalid", http.StatusFound)
		return
	}

	var result struct {
		Valid    bool     `json:"valid"`
		Username string   `json:"username"`
		Groups   []string `json:"groups"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || !result.Valid || result.Username == "" {
		http.Redirect(w, r, "/login?error=invalid", http.StatusFound)
		return
	}

	slog.Info("user logged in", "username", result.Username)
	h.setCookie(w, result.Username, result.Groups, "")
	http.Redirect(w, r, h.loginDestination(r, result.Username), http.StatusFound)
}

// loginDestination is where a successful login lands. Admins land on the
// org-wide Usage page; a manager (someone with direct reports in
// partner_users) goes straight to their team view; everyone else lands on
// their personal My usage page (which also carries the API Keys tab). The
// legacy org directory is intentionally not consulted: partner_users is the
// single identity source. Fails closed to /dashboard.
func (h *AuthHandler) loginDestination(r *http.Request, username string) string {
	if h.orgStore == nil {
		return "/dashboard"
	}
	if IsPartnerAdminUsername(r.Context(), h.cfg, h.orgStore, username) {
		return "/dashboard"
	}
	// Manager routing is derived from the partner hierarchy only.
	if _, isManager, err := h.orgStore.PartnerManagerScope(r.Context(), username); err == nil && isManager {
		return "/manager"
	}
	return "/account"
}

// HandleImpersonate lets a super-admin open another user's view. With
// ?as=USER the target is stored in the signed session and the browser is
// sent to that user's account page; without it any active impersonation is
// cleared and the browser returns to the dashboard. The check uses the real
// session identity (not the swapped header), so it still works
// mid-impersonation. "View as" is an operator tool — regular admins get the
// org-wide usage view instead, not another person's personal page.
func (h *AuthHandler) HandleImpersonate(w http.ResponseWriter, r *http.Request) {
	session := h.readCookie(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	isSuperAdmin := IsPartnerSuperAdminUsername(r.Context(), h.cfg, h.orgStore, session.Username)
	if !isSuperAdmin {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	if !h.confirmSessionChange(w, r, "Change dashboard view") {
		return
	}

	target := strings.TrimSpace(r.URL.Query().Get("as"))
	if target == "" {
		h.setCookie(w, session.Username, session.Groups, "")
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	if h.cfg.ManagementAPISecret != "" {
		if h.orgStore == nil {
			http.Error(w, "account directory unavailable", 503)
			return
		}
		profile, err := h.orgStore.PartnerUserByMaaSUsername(r.Context(), target)
		if err != nil || !profile.Active || profile.KeyRevocationPending {
			http.Error(w, "active target account required", 403)
			return
		}
	}
	slog.Info("admin viewing as user", "admin", session.Username, "as", target)
	h.setCookie(w, session.Username, session.Groups, target)
	// The upstream account page is always personal, including administrator
	// self-view; never route an impersonated session to organization usage.
	// ?to= lets the admin land on /manager instead, to see exactly what a
	// manager on their team sees. Strict allowlist — never an open redirect.
	dest := "/account"
	switch r.URL.Query().Get("to") {
	case "/manager", "manager":
		dest = "/manager"
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// Session-changing links remain navigable, but GET only renders a confirmation.
// A browser POST supplies Origin and cannot be triggered by cross-site navigation.
func (h *AuthHandler) confirmSessionChange(w http.ResponseWriter, r *http.Request, title string) bool {
	if h.cfg.ManagementAPISecret == "" {
		return true
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		renderSessionConfirmation(w, r, title)
		return false
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if h.cfg.ManagementPublicOrigin == "" || r.Header.Get("Origin") != h.cfg.ManagementPublicOrigin || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		http.Error(w, "same-origin request required", http.StatusForbidden)
		return false
	}
	return true
}

func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if !h.confirmSessionChange(w, r, "Sign out") {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cfg.SessionCookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	if h.oidc != nil && h.oidc.endSessionURL != "" {
		if target, err := h.oidcLogoutURL(); err == nil {
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

// oidcLogoutURL is the provider's RP-initiated logout endpoint. The return
// URI comes from configuration, not the request Host, so it cannot become an
// open redirect.
func (h *AuthHandler) oidcLogoutURL() (string, error) {
	target, err := url.Parse(h.oidc.endSessionURL)
	if err != nil {
		return "", err
	}
	query := target.Query()
	if h.cfg.OIDC.ClientID != "" {
		query.Set("client_id", h.cfg.OIDC.ClientID)
	}
	if redirect := strings.TrimSpace(h.cfg.OIDC.PostLogoutRedirectURL); redirect != "" {
		query.Set("post_logout_redirect_uri", redirect)
	}
	target.RawQuery = query.Encode()
	return target.String(), nil
}

// RequireAuth gates a handler behind a valid session cookie. On success it
// sets the identity headers so downstream handlers (Partner role checks,
// whoami, etc.)
// work unchanged.
func (h *AuthHandler) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := h.readCookie(r)
		if session == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if h.cfg.ManagementAPISecret != "" {
			if h.orgStore == nil {
				http.Error(w, "account directory unavailable", http.StatusServiceUnavailable)
				return
			}
			profile, err := h.orgStore.PartnerUserByMaaSUsername(r.Context(), session.Username)
			if errors.Is(err, storage.ErrPartnerUserNotFound) {
				http.Error(w, "account is not provisioned", http.StatusForbidden)
				return
			}
			if err != nil {
				http.Error(w, "account directory unavailable", http.StatusServiceUnavailable)
				return
			}
			if !profile.Active || profile.KeyRevocationPending {
				http.Error(w, "account is inactive", http.StatusForbidden)
				return
			}
		}
		// Never trust identity headers supplied by the client. Clear every
		// identity header this layer sets, then rebuild it from the signed
		// session. Without the deletes, a valid session with no groups could
		// smuggle a group through to the key-minting path.
		r.Header.Del(h.cfg.UserHeader)
		r.Header.Del(h.cfg.GroupsHeader)
		r.Header.Del(realUserHeader)
		r.Header.Set(h.cfg.UserHeader, session.Username)
		if len(session.Groups) > 0 {
			groups, err := json.Marshal(session.Groups)
			if err != nil {
				http.Error(w, "invalid session groups", http.StatusInternalServerError)
				return
			}
			r.Header.Set(h.cfg.GroupsHeader, string(groups))
		}
		// Admin "view as" mode: swap the identity header to the target user
		// so every downstream handler (per-user scoping, Partner role checks) behaves
		// exactly as it would for that user. The real identity is preserved
		// in realUserHeader for the UI banner and the impersonate-clear
		// endpoint. Only super-admins can hold or activate this claim —
		// HandleImpersonate writes it for super-admins only, and the cookie
		// is HMAC-signed, so a signed-out admin cannot forge one.
		if session.As != "" && IsPartnerSuperAdminUsername(r.Context(), h.cfg, h.orgStore, session.Username) {
			if h.cfg.ManagementAPISecret != "" && r.URL.Path != "/admin/impersonate" {
				profile, err := h.orgStore.PartnerUserByMaaSUsername(r.Context(), session.As)
				if err != nil || !profile.Active || profile.KeyRevocationPending {
					http.Error(w, "target account unavailable; return to your administrator view", 403)
					return
				}
				// Read-only means GET/HEAD only. OPTIONS is deliberately
				// excluded: browser preflights never carry the session
				// cookie, so an authenticated OPTIONS under impersonation is
				// a non-browser client and must not reach a downstream
				// handler with the impersonated identity.
				if r.Method != http.MethodGet && r.Method != http.MethodHead {
					http.Error(w, "impersonated views are read-only", 403)
					return
				}
			}
			r.Header.Set(realUserHeader, session.Username)
			r.Header.Set(h.cfg.UserHeader, session.As)
		}
		next(w, r)
	}
}

// AuthenticatedUser returns the username from the session cookie, or "".
func (h *AuthHandler) AuthenticatedUser(r *http.Request) string {
	if s := h.readCookie(r); s != nil {
		return s.Username
	}
	return ""
}
