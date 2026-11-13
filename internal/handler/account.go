package handler

import (
	"html"
	"io/fs"
	"net/http"
	"strings"

	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/dashboard"
)

// AccountHandler renders the personal Usage + API Keys shell. The gateway host
// is injected at serve time, exactly like /welcome, so no cluster-specific URL
// enters the repository.
type AccountHandler struct {
	cfg config.Config
}

func NewAccountHandler(cfg config.Config) *AccountHandler {
	return &AccountHandler{cfg: cfg}
}

func (h *AccountHandler) ServeAccount(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(dashboard.FS, "account.html")
	if err != nil {
		http.Error(w, "page not found", http.StatusInternalServerError)
		return
	}
	gateway := h.cfg.Welcome.GatewayURL
	if gateway == "" {
		gateway = welcomeGatewayFallback
	}
	controls, err := fs.ReadFile(dashboard.FS, "management-key-controls.js")
	if err != nil {
		http.Error(w, "key controls unavailable", 500)
		return
	}
	tables, err := fs.ReadFile(dashboard.FS, "management-table-controls.js")
	if err != nil {
		http.Error(w, "table controls unavailable", 500)
		return
	}
	data = []byte(strings.Replace(string(data), "/* ACCOUNT_KEY_CONTROLS */", string(controls)+"\n"+string(tables), 1))
	page := strings.NewReplacer("{{GATEWAY_URL}}", html.EscapeString(gateway)).Replace(string(data))
	if h.cfg.ManagementAPISecret != "" {
		page = string(dashboard.WithSessionDialog([]byte(page)))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write([]byte(page))
}
