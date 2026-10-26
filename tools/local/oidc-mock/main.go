// Command oidc-mock is a local-only OIDC provider for testing the PriceTag
// Authorization Code + PKCE callback. It is not an identity provider and
// must never be exposed outside a developer workstation.
//
// Personas let a developer exercise the onboarding gates without editing
// environment variables between logins. The provider shows a picker at
// /authorize and issues claims for the chosen persona.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type persona struct {
	Key          string
	Label        string
	Note         string
	Subject      string
	RhatUUID     string
	Email        string
	First        string
	Last         string
	Groups       []string
	Country      string // ISO2 in the directory, as LDAP stores it
	ClaimCountry string
}

// Personas are deterministic so the local seed can provision matching
// partner_users rows and usage data.
var personas = []persona{
	{
		Key: "new-user", Label: "Nina New — first-time user", Note: "Access passes; Terms not accepted yet → onboarding",
		Subject: "mock-new-user", RhatUUID: "11111111-1111-4111-8111-111111111111",
		Email: "new-user@example.com", First: "Nina", Last: "New",
		Groups: []string{"GE"}, Country: "US", ClaimCountry: "US",
	},
	{
		Key: "returning-user", Label: "Ravi Return — returning user", Note: "Terms accepted, keys and usage already exist → account",
		Subject: "mock-returning-user", RhatUUID: "22222222-2222-4222-8222-222222222222",
		Email: "returning-user@example.com", First: "Ravi", Last: "Return",
		Groups: []string{"GE"}, Country: "US", ClaimCountry: "US",
	},
	{
		Key: "manager-user", Label: "Maya Manager — team manager", Note: "Terms accepted, three-person team with seeded traffic → team view",
		Subject: "mock-manager-user", RhatUUID: "55555555-5555-4555-8555-555555555555",
		Email: "manager-user@example.com", First: "Maya", Last: "Manager",
		Groups: []string{"GE"}, Country: "US", ClaimCountry: "US",
	},
	{
		Key: "blocked-country", Label: "Bea Blocked — blocked country", Note: "Group passes, country is on the ISO3 blocklist → blocked",
		Subject: "mock-blocked-user", RhatUUID: "33333333-3333-4333-8333-333333333333",
		Email: "blocked-user@example.com", First: "Bea", Last: "Blocked",
		Groups: []string{"GE"}, Country: "IR", ClaimCountry: "IR",
	},
	{
		Key: "no-group", Label: "Noah Nogroup — no authorized group", Note: "Only technical realm roles in the claim → blocked",
		Subject: "mock-nogroup-user", RhatUUID: "44444444-4444-4444-8444-444444444444",
		Email: "nogroup-user@example.com", First: "Noah", Last: "Nogroup",
		Groups: []string{"offline_access", "uma_authorization"}, Country: "US", ClaimCountry: "US",
	},
	{
		Key: "admin", Label: "Noy Itzikowitz — super admin", Note: "Existing admin dashboard, unchanged",
		Subject: "mock-admin", RhatUUID: "00000000-0000-4000-8000-000000000001",
		Email: "nitzikow@redhat.com", First: "Noy", Last: "Itzikowitz",
		Groups: []string{"GE"}, Country: "US", ClaimCountry: "US",
	},
}

func personaByKey(key string) (persona, bool) {
	for _, p := range personas {
		if p.Key == key {
			return p, true
		}
	}
	return persona{}, false
}

func defaultPersona() persona {
	if key := strings.TrimSpace(os.Getenv("MOCK_OIDC_PERSONA")); key != "" {
		if p, ok := personaByKey(key); ok {
			return p
		}
	}
	return personas[0]
}

type authorizationCode struct {
	ClientID    string
	RedirectURI string
	Nonce       string
	Challenge   string
	Persona     string
}

type provider struct {
	issuer   string
	internal string
	key      *rsa.PrivateKey
	mu       sync.Mutex
	codes    map[string]authorizationCode
	tokens   map[string]string // access token -> persona key
}

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	p := &provider{
		issuer:   env("MOCK_OIDC_ISSUER", "http://localhost:9999"),
		internal: env("MOCK_OIDC_INTERNAL_URL", env("MOCK_OIDC_ISSUER", "http://localhost:9999")),
		key:      key,
		codes:    make(map[string]authorizationCode),
		tokens:   make(map[string]string),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/authorize", p.authorize)
	mux.HandleFunc("/token", p.token)
	mux.HandleFunc("/jwks", p.jwks)
	mux.HandleFunc("/userinfo", p.userinfo)
	mux.HandleFunc("/personas", p.personaList)
	addr := env("MOCK_OIDC_LISTEN", ":9999")
	log.Printf("local mock OIDC provider listening on %s (issuer %s)", addr, p.issuer)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func (p *provider) discovery(w http.ResponseWriter, _ *http.Request) {
	p.writeJSON(w, map[string]any{
		"issuer":                                p.issuer,
		"authorization_endpoint":                p.issuer + "/authorize",
		"token_endpoint":                        p.internal + "/token",
		"jwks_uri":                              p.internal + "/jwks",
		"userinfo_endpoint":                     p.internal + "/userinfo",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
	})
}

func (p *provider) personaList(w http.ResponseWriter, _ *http.Request) {
	p.writeJSON(w, map[string]any{"personas": personas})
}

func (p *provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI, clientID, state := q.Get("redirect_uri"), q.Get("client_id"), q.Get("state")
	if redirectURI == "" || clientID == "" || state == "" || q.Get("response_type") != "code" {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	key := q.Get("persona")
	if key == "" {
		key = q.Get("login_hint")
	}
	if _, ok := personaByKey(key); !ok {
		p.renderPicker(w, r)
		return
	}
	code, err := randomValue()
	if err != nil {
		http.Error(w, "randomness failure", http.StatusInternalServerError)
		return
	}
	p.mu.Lock()
	p.codes[code] = authorizationCode{
		ClientID: clientID, RedirectURI: redirectURI,
		Nonce: q.Get("nonce"), Challenge: q.Get("code_challenge"), Persona: key,
	}
	p.mu.Unlock()
	location, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect URI", http.StatusBadRequest)
		return
	}
	params := location.Query()
	params.Set("code", code)
	params.Set("state", state)
	location.RawQuery = params.Encode()
	http.Redirect(w, r, location.String(), http.StatusFound)
}

// renderPicker is the local "identity provider" login screen. In a real IdP
// this is where the user enters credentials; here it is a persona list.
func (p *provider) renderPicker(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	data := struct {
		Personas []persona
		Params   template.HTML
	}{Personas: personas}
	var hidden strings.Builder
	for _, name := range []string{"response_type", "client_id", "redirect_uri", "state", "nonce", "code_challenge", "code_challenge_method", "scope"} {
		if v := q.Get(name); v != "" {
			fmt.Fprintf(&hidden, `<input type="hidden" name="%s" value="%s">`, name, template.HTMLEscapeString(v))
		}
	}
	data.Params = template.HTML(hidden.String())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pickerTemplate.Execute(w, data); err != nil {
		log.Printf("render picker: %v", err)
	}
}

func (p *provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid token request", http.StatusBadRequest)
		return
	}
	codeValue := r.FormValue("code")
	clientID := r.FormValue("client_id")
	if basicID, _, ok := r.BasicAuth(); ok {
		clientID = basicID
	}
	p.mu.Lock()
	code, ok := p.codes[codeValue]
	if ok {
		delete(p.codes, codeValue)
	}
	p.mu.Unlock()
	if !ok || code.ClientID != clientID || code.RedirectURI != r.FormValue("redirect_uri") {
		http.Error(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	verifier := r.FormValue("code_verifier")
	verifierDigest := sha256.Sum256([]byte(verifier))
	if code.Challenge != "" && base64.RawURLEncoding.EncodeToString(verifierDigest[:]) != code.Challenge {
		http.Error(w, "invalid_code_verifier", http.StatusBadRequest)
		return
	}
	persona, ok := personaByKey(code.Persona)
	if !ok {
		persona = defaultPersona()
	}
	if strings.TrimSpace(os.Getenv("MOCK_OIDC_RHAT_UUID")) != "" {
		// Backwards-compatible override for the original single-user harness.
		persona.RhatUUID = strings.TrimSpace(os.Getenv("MOCK_OIDC_RHAT_UUID"))
	}
	claims := map[string]any{
		"iss": p.issuer, "sub": persona.Subject,
		"aud": code.ClientID, "exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(), "nonce": code.Nonce,
		"rhatUUID":           persona.RhatUUID,
		"preferred_username": persona.Email,
		"email":              persona.Email,
		"given_name":         persona.First,
		"family_name":        persona.Last,
		"groups":             persona.Groups,
		"country":            persona.ClaimCountry,
	}
	accessToken, _ := randomValue()
	p.mu.Lock()
	p.tokens[accessToken] = persona.Key
	p.mu.Unlock()
	log.Printf("issued claims for persona=%s sub=%v rhatUUID=%v email=%v groups=%v",
		persona.Key, claims["sub"], claims["rhatUUID"], claims["email"], claims["groups"])
	idToken, err := p.signJWT(claims)
	if err != nil {
		http.Error(w, "signing failure", http.StatusInternalServerError)
		return
	}
	p.writeJSON(w, map[string]any{"access_token": accessToken, "token_type": "Bearer", "expires_in": 300, "id_token": idToken})
}

func (p *provider) jwks(w http.ResponseWriter, _ *http.Request) {
	p.writeJSON(w, map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "mock-key",
		"n": base64.RawURLEncoding.EncodeToString(p.key.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.PublicKey.E)).Bytes()),
	}}})
}

func (p *provider) userinfo(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	p.mu.Lock()
	key := p.tokens[strings.TrimSpace(token)]
	p.mu.Unlock()
	persona, ok := personaByKey(key)
	if !ok {
		persona = defaultPersona()
	}
	p.writeJSON(w, map[string]any{
		"sub": persona.Subject, "rhatUUID": persona.RhatUUID,
		"email": persona.Email, "preferred_username": persona.Email,
		"given_name": persona.First, "family_name": persona.Last,
		"groups": persona.Groups, "country": persona.ClaimCountry,
	})
}

func (p *provider) signJWT(claims map[string]any) (string, error) {
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": "mock-key"}
	encode := func(v any) (string, error) {
		data, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(data), nil
	}
	h, err := encode(header)
	if err != nil {
		return "", err
	}
	b, err := encode(claims)
	if err != nil {
		return "", err
	}
	input := h + "." + b
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (p *provider) writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func randomValue() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

var pickerTemplate = template.Must(template.New("picker").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Local mock IdP</title>
<style>
body{font:15px system-ui;max-width:760px;margin:0 auto;padding:36px 20px;background:#0b0e11;color:#e2e6ec}
h1{font-size:22px;margin:0 0 6px}p.sub{color:#8090a8;margin:0 0 24px;font-size:13px}
.p{display:flex;gap:14px;align-items:center;width:100%;text-align:left;background:#141820;border:1px solid #2e3848;border-radius:10px;padding:14px 16px;margin-bottom:10px;cursor:pointer;color:inherit;font:inherit}
.p:hover{border-color:#4da0f8;background:#1a2030}
.badge{width:38px;height:38px;border-radius:50%;background:#1a2030;display:grid;place-items:center;font-weight:800;color:#4da0f8;flex:0 0 auto}
b{display:block;font-size:14px}small{color:#8090a8;font-size:12px}
</style></head><body>
<h1>Local mock IdP</h1><p class="sub">Choose a persona. This page exists only on a developer workstation.</p>
<form method="get" action="/authorize">{{.Params}}
{{range .Personas}}
<button class="p" type="submit" name="persona" value="{{.Key}}">
  <span class="badge">{{slice .First 0 1}}</span>
  <span><b>{{.Label}}</b><small>{{.Note}}</small></span>
</button>
{{end}}
</form></body></html>`))
