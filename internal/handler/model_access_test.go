package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestDecideRejectsInvalidSubjectUUID(t *testing.T) {
	h := NewModelAccessHandler(nil)
	body := `{"subject":{"type":"partner_user","id":"not-a-uuid"},"resource":{"type":"model","id":"model-a"},"action":{"name":"invoke"},"context":{"tenant":"default"}}`
	rec := httptest.NewRecorder()
	h.HandleDecision(rec, httptest.NewRequest(http.MethodPost, "/api/v2/policy/decide", bytes.NewBufferString(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestDecideDenyBodyUsesEmptyAllowedModels(t *testing.T) {
	store, _ := openHandlerTestStore(t)
	h := NewModelAccessHandler(store)
	body := `{"subject":{"type":"partner_user","id":"` + uuid.NewString() + `"},"resource":{"type":"model","id":"model-a"},"action":{"name":"invoke"},"context":{"tenant":"default"}}`
	rec := httptest.NewRecorder()
	h.HandleDecision(rec, httptest.NewRequest(http.MethodPost, "/api/v2/policy/decide", bytes.NewBufferString(body)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	models, ok := payload["allowedModels"].([]any)
	if !ok || len(models) != 0 {
		t.Fatalf("allowedModels = %#v, want []", payload["allowedModels"])
	}
}
