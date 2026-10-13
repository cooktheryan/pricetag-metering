// Command oidc-mock is a local-only OIDC provider for testing the PriceTag
// Authorization Code + PKCE callback. It is not an identity provider and
// must never be exposed outside a developer workstation.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type authorizationCode struct {
	ClientID    string
	RedirectURI string
	Nonce       string
	Challenge   string
}

type provider struct {
	issuer   string
	internal string
	key      *rsa.PrivateKey
	mu       sync.Mutex
	codes    map[string]authorizationCode
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
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/authorize", p.authorize)
	mux.HandleFunc("/token", p.token)
	mux.HandleFunc("/jwks", p.jwks)
	mux.HandleFunc("/userinfo", p.userinfo)
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

func (p *provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI, clientID, state := q.Get("redirect_uri"), q.Get("client_id"), q.Get("state")
	if redirectURI == "" || clientID == "" || state == "" || q.Get("response_type") != "code" {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	code, err := randomValue()
	if err != nil {
		http.Error(w, "randomness failure", http.StatusInternalServerError)
		return
	}
	p.mu.Lock()
	p.codes[code] = authorizationCode{ClientID: clientID, RedirectURI: redirectURI, Nonce: q.Get("nonce"), Challenge: q.Get("code_challenge")}
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
	claims := map[string]any{
		"iss": p.issuer, "sub": env("MOCK_OIDC_SUB", "mock-subject"),
		"aud": code.ClientID, "exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(), "nonce": code.Nonce,
		"rhatUUID":           env("MOCK_OIDC_RHAT_UUID", "00000000-0000-0000-0000-000000000001"),
		"preferred_username": env("MOCK_OIDC_USERNAME", "mock.user@redhat.com"),
		"email":              env("MOCK_OIDC_EMAIL", "mock.user@redhat.com"),
		"given_name":         env("MOCK_OIDC_GIVEN_NAME", "Mock"),
		"family_name":        env("MOCK_OIDC_FAMILY_NAME", "User"),
		"groups":             splitList(env("MOCK_OIDC_GROUPS", "enmaas-users,enmaas-managers")),
	}
	log.Printf("issued mock claims: sub=%v rhatUUID=%v username=%v email=%v given_name=%v family_name=%v groups=%v",
		claims["sub"], claims["rhatUUID"], claims["preferred_username"], claims["email"],
		claims["given_name"], claims["family_name"], claims["groups"])
	idToken, err := p.signJWT(claims)
	if err != nil {
		http.Error(w, "signing failure", http.StatusInternalServerError)
		return
	}
	p.writeJSON(w, map[string]any{"access_token": "mock-access-token", "token_type": "Bearer", "expires_in": 300, "id_token": idToken})
}

func (p *provider) jwks(w http.ResponseWriter, _ *http.Request) {
	p.writeJSON(w, map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "mock-key",
		"n": base64.RawURLEncoding.EncodeToString(p.key.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.PublicKey.E)).Bytes()),
	}}})
}

func (p *provider) userinfo(w http.ResponseWriter, _ *http.Request) {
	p.writeJSON(w, map[string]any{"sub": env("MOCK_OIDC_SUB", "mock-subject"), "rhatUUID": env("MOCK_OIDC_RHAT_UUID", "00000000-0000-0000-0000-000000000001")})
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

func splitList(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
