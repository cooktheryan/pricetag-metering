package handler

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
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
	orgStore *storage.Store
}

// SetOrgStore wires the directory lookup used by the login redirect. Kept a
// setter so login stays constructible without a database (tests, lite
// deployments).
func (h *AuthHandler) SetOrgStore(s *storage.Store) { h.orgStore = s }

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
		cfg:        cfg,
		secret:     secret,
		httpClient: &http.Client{Timeout: 10 * time.Second},
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
		// Local/demo shortcuts only. The production SSO link above is never
		// modified; this is a separate, env-gated section below it. When the
		// direct dev identities are configured they replace this mock-IdP
		// picker; the mock picker is still reachable through the SSO button.
		if h.oidc != nil && h.cfg.OIDC.TestLogin && len(h.cfg.DevLoginUsers) == 0 {
			data = bytes.Replace(data, []byte("<!-- TEST_LOGIN -->"), testLoginPanel, 1)
		} else {
			data = bytes.Replace(data, []byte("<!-- TEST_LOGIN -->"), nil, 1)
		}
		// Deployment-scoped test identities. Unlike the mock-IdP personas
		// above, these issue a local session directly and are only enabled by
		// an explicit allowlist plus a dev_test tag on the directory row.
		if panel := h.devLoginPanel(r); len(panel) > 0 {
			data = bytes.Replace(data, []byte("<!-- DEV_LOGIN -->"), panel, 1)
		} else {
			data = bytes.Replace(data, []byte("<!-- DEV_LOGIN -->"), nil, 1)
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

	r.ParseForm()
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
	http.Redirect(w, r, h.loginDestination(r, result.Username, result.Groups), http.StatusFound)
}

// devLoginPanel renders the explicitly allowlisted test identities. It is
// empty unless DEV_LOGIN_USERS is set, so the login page is unchanged in
// every normal deployment.
func (h *AuthHandler) devLoginPanel(r *http.Request) []byte {
	if len(h.cfg.DevLoginUsers) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString(`<div class="test-login">
  <div class="divider"><span>Dev test sign-in</span></div>
  <p>Development environment only. Seeded demo accounts with sample usage.</p>
  <div class="persona-grid">`)
	for _, username := range h.cfg.DevLoginUsers {
		label, detail := username, username
		if h.orgStore != nil {
			if pu, err := h.orgStore.PartnerUserByMaaSUsername(r.Context(), username); err == nil {
				first, _ := pu.Tags["first_name"].(string)
				last, _ := pu.Tags["last_name"].(string)
				if name := strings.TrimSpace(first + " " + last); name != "" {
					label = name
				}
				if role, _ := pu.Tags["dev_label"].(string); role != "" {
					detail = role
				}
			}
		}
		fmt.Fprintf(&b, `<a class="persona" href="/dev-login?as=%s" title="%s"><strong>%s</strong><span>%s</span></a>`,
			url.QueryEscape(username), html.EscapeString(username), html.EscapeString(label), html.EscapeString(detail))
	}
	b.WriteString(`</div></div>`)
	return []byte(b.String())
}

// HandleDevLogin opens a local session for an explicitly configured test
// identity. It is disabled unless DEV_LOGIN_USERS is set, and the target must
// both appear in that allowlist and carry dev_test=true in the partner
// directory. It never issues a session for an admin or an untagged account.
func (h *AuthHandler) HandleDevLogin(w http.ResponseWriter, r *http.Request) {
	if len(h.cfg.DevLoginUsers) == 0 {
		http.NotFound(w, r)
		return
	}
	target := strings.TrimSpace(r.URL.Query().Get("as"))
	allowed := false
	for _, username := range h.cfg.DevLoginUsers {
		if strings.EqualFold(username, target) {
			allowed = true
			break
		}
	}
	if target == "" || !allowed {
		http.Error(w, "not a dev login user", http.StatusForbidden)
		return
	}
	if h.orgStore == nil {
		http.Error(w, "dev login requires the partner directory", http.StatusServiceUnavailable)
		return
	}
	pu, err := h.orgStore.PartnerUserByMaaSUsername(r.Context(), target)
	if err != nil || !pu.Active {
		http.Error(w, "unknown or inactive dev user", http.StatusForbidden)
		return
	}
	if !isDevTestUser(pu.Tags) {
		http.Error(w, "user is not enabled for dev login", http.StatusForbidden)
		return
	}
	// A direct login has no IdP claim set. Use the groups recorded on the
	// seeded directory row so the same access gates run as they would after
	// SSO; an empty list deliberately exercises the no-group gate.
	groups := devLoginGroups(pu.Tags)
	// The "new user" persona must start the first-run flow again on every
	// click, exactly like the local mock IdP does. Driven by a directory tag
	// so no test address is hardcoded here.
	if isDevResetUser(pu.Tags) {
		if err := h.orgStore.ResetAgreement(r.Context(), pu.UserID, "terms", h.cfg.Onboarding.TermsVersion); err != nil {
			slog.Warn("dev test persona reset failed", "username", target, "error", err)
		}
	}
	slog.Warn("dev test login used", "username", target, "remote", r.RemoteAddr)
	h.setCookie(w, target, groups, "")
	// The access gate forces "enforce" for these dev identities, so the
	// country/group/terms failures are visible without flipping the whole
	// deployment to ONBOARDING_MODE=enforce, which would affect real users.
	http.Redirect(w, r, h.loginDestination(r, target, groups), http.StatusFound)
}

func isDevResetUser(tags map[string]any) bool {
	value, ok := tags["dev_reset_on_login"]
	if !ok {
		return false
	}
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	}
	return false
}

// devLoginGroups reads the optional dev_groups tag (JSON array or
// comma-separated string) used to stand in for IdP group claims.
func devLoginGroups(tags map[string]any) []string {
	value, ok := tags["dev_groups"]
	if !ok {
		return nil
	}
	switch v := value.(type) {
	case []any:
		groups := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				groups = append(groups, strings.TrimSpace(s))
			}
		}
		return groups
	case []string:
		return v
	case string:
		var groups []string
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				groups = append(groups, s)
			}
		}
		return groups
	}
	return nil
}

func isDevTestUser(tags map[string]any) bool {
	value, ok := tags["dev_test"]
	if !ok {
		return false
	}
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	}
	return false
}

// loginDestination is where a successful login lands. Admins keep the Usage
// page; a manager (someone with direct reports in partner_users) goes straight
// to their team view. The legacy org directory is intentionally not consulted:
// partner_users is the single identity source. Users without a partner role
// land on /account. Fails closed to /dashboard.
func (h *AuthHandler) loginDestination(r *http.Request, username string, groups []string) string {
	if h.orgStore == nil {
		return "/dashboard"
	}
	if IsPartnerAdminUsername(r.Context(), h.cfg, h.orgStore, username) {
		return "/dashboard"
	}
	// Incomplete onboarding always wins over the role-based landing page:
	// nothing else is usable until the three gates pass.
	if NewAccessGate(h.cfg, h.orgStore).NeedsOnboarding(r.Context(), username, groups) {
		return "/onboarding"
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

	target := strings.TrimSpace(r.URL.Query().Get("as"))
	if target == "" {
		h.setCookie(w, session.Username, session.Groups, "")
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	slog.Info("admin viewing as user", "admin", session.Username, "as", target)
	h.setCookie(w, session.Username, session.Groups, target)
	// /dashboard serves the personal user page while impersonating (the
	// operator dashboard is only shown for a real, non-swapped admin view).
	// ?to= lets the admin land on /manager instead, to see exactly what a
	// manager on their team sees. Strict allowlist — never an open redirect.
	dest := "/dashboard"
	switch r.URL.Query().Get("to") {
	case "/manager", "manager":
		dest = "/manager"
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cfg.SessionCookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
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
		r.Header.Set(h.cfg.UserHeader, session.Username)
		if len(session.Groups) > 0 {
			r.Header.Set(h.cfg.GroupsHeader, fmt.Sprintf(`["%s"]`, strings.Join(session.Groups, `","`)))
		}
		// Admin "view as" mode: swap the identity header to the target user
		// so every downstream handler (per-user scoping, Partner role checks) behaves
		// exactly as it would for that user. The real identity is preserved
		// in realUserHeader for the UI banner and the impersonate-clear
		// endpoint. Only super-admins can hold or activate this claim —
		// HandleImpersonate writes it for super-admins only, and the cookie
		// is HMAC-signed, so a signed-out admin cannot forge one.
		if session.As != "" && IsPartnerSuperAdminUsername(r.Context(), h.cfg, h.orgStore, session.Username) {
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
