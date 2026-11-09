package handler

import (
	"github.com/redhat-et/pricetag-metering/internal/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoginValidationDoesNotForwardKeysOnRedirect(t *testing.T) {
	var forwarded bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer destination.Close()
	validator := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer validator.Close()
	t.Setenv("MAAS_VALIDATE_URL", validator.URL)
	t.Setenv("SESSION_SECRET", "test-session-secret")
	h := NewAuthHandler(config.Config{})
	req := httptest.NewRequest("POST", "/login", strings.NewReader("api_key=synthetic-test-key"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.HandleLogin(w, req)
	if forwarded {
		t.Fatal("validation redirect forwarded the submitted key")
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("redirect created a session")
	}
}
