package handler

import (
	"github.com/redhat-et/pricetag-metering/internal/config"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStandaloneConfiguredCatalog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "models.json")
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`[{"id":"gateway/unused","model":"billed-model","provider":"mock","secret":"must-not-escape"}]`, 200},
		{`[{"id":"alias"}]`, 503}, {`not json`, 503},
	} {
		os.WriteFile(path, []byte(tc.body), 0600)
		h := NewAdminHandler(nil, nil, config.Config{GatewayModelsFile: path})
		w := httptest.NewRecorder()
		h.HandleModels(w, httptest.NewRequest("GET", "/api/v1/admin/models", nil))
		if w.Code != tc.status {
			t.Fatalf("status %d", w.Code)
		}
		if strings.Contains(w.Body.String(), "must-not-escape") {
			t.Fatal("catalog leaked unrelated fields")
		}
		if tc.status == 200 && (!strings.Contains(w.Body.String(), `"name":"gateway/unused"`) || !strings.Contains(w.Body.String(), `"targetModel":"billed-model"`)) {
			t.Fatal("lost alias/enforcement mapping")
		}
	}
}
