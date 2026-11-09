package maasapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRejectUntrustedTLS(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"id":"x"}`)) }))
	defer s.Close()
	if _, err := NewClient(s.URL, "").CreateAPIKey(context.Background(), "alice", "users", "test"); err == nil {
		t.Fatal("accepted untrusted TLS")
	}
}
func TestRejectKeyRedirect(t *testing.T) {
	forwarded := false
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded = true }))
	defer dest.Close()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, dest.URL, 307) }))
	defer src.Close()
	_, err := NewClient(src.URL, "").CreateAPIKey(context.Background(), "alice", "users", "test")
	if err == nil || forwarded {
		t.Fatal("followed credential redirect")
	}
}
