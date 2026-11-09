package handler

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"

	"github.com/redhat-et/pricetag-metering/internal/dashboard"
)

var sessionConfirmation = template.Must(template.New("session-confirm").Parse(dashboard.SessionConfirmation))

func renderSessionConfirmation(w http.ResponseWriter, r *http.Request, title string) {
	target := strings.TrimSpace(r.URL.Query().Get("as"))
	description := "Sign out of this browser session?"
	readOnly := r.URL.Path == "/admin/impersonate" && target != ""
	if r.URL.Path == "/admin/impersonate" {
		description = "Return to your administrator dashboard?"
		if target != "" {
			view := "personal usage"
			if to := r.URL.Query().Get("to"); to == "manager" || to == "/manager" {
				view = "team usage"
			}
			description = "View " + view + " as " + target + "?"
		}
	}
	data := struct {
		Title, Description, Action string
		ReadOnly                   bool
	}{title, description, r.URL.RequestURI(), readOnly}
	var body bytes.Buffer
	if err := sessionConfirmation.Execute(&body, data); err != nil {
		http.Error(w, "confirmation unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	_, _ = w.Write(body.Bytes())
}
