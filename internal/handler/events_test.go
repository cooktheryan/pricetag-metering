package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestHandleEvent_ParsesCloudEvent(t *testing.T) {
	event := cloudEvent{
		SpecVersion:     "1.0",
		ID:              "evt-test-123",
		Source:          "maas-gateway",
		Type:            "inference.tokens.used",
		Subject:         "testuser",
		Time:            "2026-05-28T10:30:00Z",
		DataContentType: "application/json",
		Data: cloudEventData{
			User:             "testuser",
			Group:            "engineering",
			Subscription:     "premium",
			Provider:         "anthropic",
			Model:            "claude-opus-4-6",
			PromptTokens:     100,
			CompletionTokens: 50,
			TotalTokens:      150,
		},
	}

	body, _ := json.Marshal(event)

	var parsed cloudEvent
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if parsed.Data.User != "testuser" {
		t.Errorf("user: got %q, want %q", parsed.Data.User, "testuser")
	}
	if parsed.Data.PromptTokens != 100 {
		t.Errorf("prompt_tokens: got %d, want %d", parsed.Data.PromptTokens, 100)
	}
	if parsed.Data.Provider != "anthropic" {
		t.Errorf("provider: got %q, want %q", parsed.Data.Provider, "anthropic")
	}
	if parsed.ID != "evt-test-123" {
		t.Errorf("id: got %q, want %q", parsed.ID, "evt-test-123")
	}
}

func TestCloudEventData_StatusCode(t *testing.T) {
	// Success/usage events omit status_code -> nil (rendered as 200).
	var success cloudEventData
	if err := json.Unmarshal([]byte(`{"user":"u","model":"m","total_tokens":10}`), &success); err != nil {
		t.Fatalf("unmarshal success: %v", err)
	}
	if success.StatusCode != nil {
		t.Errorf("success status_code: got %v, want nil", *success.StatusCode)
	}

	// Error events carry status_code with zero tokens.
	var errored cloudEventData
	if err := json.Unmarshal([]byte(`{"user":"u","model":"m","status_code":429}`), &errored); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if errored.StatusCode == nil || *errored.StatusCode != 429 {
		t.Errorf("error status_code: got %v, want 429", errored.StatusCode)
	}
}

func TestHandleEvent_RejectsGet(t *testing.T) {
	h := &EventsHandler{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	w := httptest.NewRecorder()
	h.HandleEvent(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleEvent_RejectsInvalidJSON(t *testing.T) {
	h := &EventsHandler{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()
	h.HandleEvent(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleEvent_RejectsNegativeTokenCounts(t *testing.T) {
	h := &EventsHandler{}
	body := []byte(`{"specversion":"1.0","id":"evt-negative","source":"gateway","type":"inference.tokens.used","data":{"user":"u","model":"m","prompt_tokens":-1}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleEvent(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleEvent_RejectsInvalidCloudEventTime(t *testing.T) {
	h := &EventsHandler{}
	body := []byte(`{"specversion":"1.0","id":"evt-time","source":"gateway","type":"inference.tokens.used","time":"not-a-time","data":{"user":"u","model":"m"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleEvent(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestValidateTokenCountsRejectsPostgresIntegerOverflow(t *testing.T) {
	if err := validateTokenCounts(cloudEventData{PromptTokens: int(maxPostgresInt) + 1}); err == nil {
		t.Fatal("expected PostgreSQL INTEGER overflow to be rejected")
	}
	if err := validateTokenCounts(cloudEventData{PromptTokens: int(maxPostgresInt)}); err != nil {
		t.Fatalf("maximum PostgreSQL INTEGER should be accepted: %v", err)
	}
	if err := validateTokenCounts(cloudEventData{
		PromptTokens:     int(maxPostgresInt),
		CompletionTokens: 1,
	}); err == nil {
		t.Fatal("expected derived total overflow to be rejected")
	}
}

func TestHandleEvent_AcceptsValidEvent_NoStore(t *testing.T) {
	h := &EventsHandler{store: nil, modelAliases: map[string]string{"gateway/fixture": "fixture"}}
	event := cloudEvent{
		SpecVersion: "1.0",
		ID:          "evt-001",
		Source:      "test",
		Type:        "inference.tokens.used",
		Subject:     "user1",
		Data: cloudEventData{
			User:         "user1",
			Model:        "gateway/fixture",
			PromptTokens: 10,
		},
	}
	body, _ := json.Marshal(event)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandleEvent(w, req)

	// Without a store, handler should parse successfully but fail on insert (or return 204 if store is nil)
	// This tests the parsing path at minimum
	if w.Code != http.StatusNoContent && w.Code != http.StatusInternalServerError {
		t.Errorf("status: got %d, want 204 or 500", w.Code)
	}
}

func TestNormalizeGatewayModelAlias(t *testing.T) {
	h := &EventsHandler{modelAliases: map[string]string{
		"gateway/fixture":    "fixture",
		"gateway/demo-cheap": "fixture-cheap",
	}}
	if got := h.normalizeModel("gateway/fixture"); got != "fixture" {
		t.Fatalf("alias: got %q", got)
	}
	if got := h.normalizeModel("unknown"); got != "unknown" {
		t.Fatalf("unknown model: got %q", got)
	}
}

func TestLoadGatewayModelAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "models.json")
	os.WriteFile(path, []byte(`[
	  {"id":"gateway/fixture","model":"fixture","provider":"mock"},
	  {"id":"gateway/demo-cheap","model":"fixture-cheap","provider":"mock"}
	]`), 0600)

	aliases, err := LoadGatewayModelAliases(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"gateway/fixture":    "fixture",
		"gateway/demo-cheap": "fixture-cheap",
	}
	if len(aliases) != len(want) {
		t.Fatalf("aliases = %v, want %v", aliases, want)
	}
	for alias, target := range want {
		if aliases[alias] != target {
			t.Fatalf("aliases[%q] = %q, want %q", alias, aliases[alias], target)
		}
	}
}
