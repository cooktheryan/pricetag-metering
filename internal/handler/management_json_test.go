package handler

import (
	"encoding/json"
	"fmt"
	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/storage"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestManagementJSONSingleBoundedObject(t *testing.T) {
	for _, body := range []string{`{"name":"alice"} {"name":"admin"}`, `{"name":"` + strings.Repeat("x", 65<<10) + `"}`, `{"unexpected":"value"}`} {
		r := httptest.NewRequest("PUT", "/api/v1/management/users", strings.NewReader(body))
		w := httptest.NewRecorder()
		var value struct {
			Name string `json:"name"`
		}
		if decodeJSON(w, r, &value) || w.Code != 400 {
			t.Fatal("invalid body accepted")
		}
	}
}

func TestBudgetPaginationRejectsInvalidLimits(t *testing.T) {
	// Invalid inputs must fail before querying storage or accepting arbitrary
	// unbounded result sizes. Existing callers retain the default of 20.
	for _, query := range []string{"limit=0", "limit=-1", "limit=5000", "limit=word", "limit=5&limit=20"} {
		w := httptest.NewRecorder()
		NewManagementHandler(nil, config.Config{})(w, httptest.NewRequest("GET", "/api/v1/management/budgets?"+query, nil))
		if w.Code != 400 {
			t.Fatalf("%s: status=%d", query, w.Code)
		}
	}
}

func TestBudgetPaginationSizesAndSearch(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	for i := 0; i < 7; i++ {
		if err := store.UpsertQuotaOverride(t.Context(), "test", "user", fmt.Sprintf("table-member-%d", i), 5); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		query string
		count int
		more  bool
	}{
		{"limit=5&offset=0", 5, true}, {"limit=5&offset=5", 2, false},
		{"limit=20&offset=0", 7, false}, {"limit=50&offset=0", 7, false},
		{"offset=0", 7, false}, {"limit=5&search=member-6", 1, false},
		{"limit=5&search=missing", 0, false},
	} {
		w := httptest.NewRecorder()
		NewManagementHandler(store, config.Config{})(w, httptest.NewRequest("GET", "/api/v1/management/budgets?"+tc.query, nil))
		var result struct {
			Data []storage.QuotaOverride `json:"data"`
			More bool                    `json:"has_more"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil {
			t.Fatalf("%s: status=%d", tc.query, w.Code)
		}
		if len(result.Data) != tc.count || result.More != tc.more {
			t.Fatalf("%s: count=%d more=%v", tc.query, len(result.Data), result.More)
		}
	}
}
