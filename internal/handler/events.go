package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/redhat-et/pricetag-metering/internal/storage"
)

type cloudEvent struct {
	SpecVersion     string         `json:"specversion"`
	ID              string         `json:"id"`
	Source          string         `json:"source"`
	Type            string         `json:"type"`
	Subject         string         `json:"subject"`
	Time            string         `json:"time"`
	DataContentType string         `json:"datacontenttype"`
	Data            cloudEventData `json:"data"`
}

type cloudEventData struct {
	User                string `json:"user"`
	Group               string `json:"group"`
	Subscription        string `json:"subscription"`
	Provider            string `json:"provider"`
	Model               string `json:"model"`
	PromptTokens        int    `json:"prompt_tokens"`
	CompletionTokens    int    `json:"completion_tokens"`
	TotalTokens         int    `json:"total_tokens"`
	CachedInputTokens   int    `json:"cached_input_tokens"`
	CacheCreationTokens int    `json:"cache_creation_tokens"`
	ReasoningTokens     int    `json:"reasoning_tokens"`
	UserAgent           string `json:"user_agent"`
	// StatusCode is the upstream HTTP status. The gateway sets it only on
	// error events (inference.request.error); success/usage events omit it,
	// so a nil pointer means the request succeeded (HTTP 200).
	StatusCode *int `json:"status_code"`
}

type EventsHandler struct {
	store        *storage.Store
	modelAliases map[string]string
}

const maxEventBodyBytes = 1 << 20

const maxPostgresInt = int64(1<<31 - 1)

func validateTokenCounts(data cloudEventData) error {
	counts := []int{
		data.PromptTokens,
		data.CompletionTokens,
		data.TotalTokens,
		data.CachedInputTokens,
		data.CacheCreationTokens,
		data.ReasoningTokens,
	}
	for _, count := range counts {
		if count < 0 || int64(count) > maxPostgresInt {
			return fmt.Errorf("token count outside PostgreSQL INTEGER range")
		}
	}
	if data.TotalTokens == 0 && int64(data.PromptTokens)+int64(data.CompletionTokens) > maxPostgresInt {
		return fmt.Errorf("derived total token count outside PostgreSQL INTEGER range")
	}
	return nil
}

func NewEventsHandler(store *storage.Store, modelAliases map[string]string) *EventsHandler {
	return &EventsHandler{store: store, modelAliases: modelAliases}
}

func LoadGatewayModelAliases(path string) (map[string]string, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var configured []struct {
		ID    string `json:"id"`
		Model string `json:"model"`
	}
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	if err := decoder.Decode(&configured); err != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, fmt.Errorf("invalid gateway catalog")
	}

	aliases := make(map[string]string, len(configured))
	for _, model := range configured {
		if strings.TrimSpace(model.ID) == "" || strings.TrimSpace(model.Model) == "" ||
			len(model.ID) > 512 || len(model.Model) > 512 {
			return nil, fmt.Errorf("invalid gateway model mapping %q", model.ID)
		}
		if existing, exists := aliases[model.ID]; exists && existing != model.Model {
			return nil, fmt.Errorf("conflicting gateway model mapping %q", model.ID)
		}
		aliases[model.ID] = model.Model
	}
	return aliases, nil
}

func (h *EventsHandler) normalizeModel(model string) string {
	if target, exists := h.modelAliases[model]; exists {
		return target
	}
	return model
}

func (h *EventsHandler) HandleEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxEventBodyBytes)
	dec := json.NewDecoder(r.Body)
	var event cloudEvent
	if err := dec.Decode(&event); err != nil {
		slog.Error("failed to decode event", "error", err)
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		http.Error(w, "request body must contain exactly one JSON event", http.StatusBadRequest)
		return
	}

	if event.SpecVersion != "1.0" || event.Source == "" || event.Type == "" || event.ID == "" ||
		event.Data.User == "" || event.Data.Model == "" {
		http.Error(w, "missing or invalid required CloudEvent fields", http.StatusBadRequest)
		return
	}
	event.Data.Model = h.normalizeModel(event.Data.Model)
	if len(event.ID) > 256 || len(event.Data.User) > 512 || len(event.Data.Model) > 512 {
		http.Error(w, "CloudEvent field too long", http.StatusBadRequest)
		return
	}
	if err := validateTokenCounts(event.Data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if event.Data.StatusCode != nil && (*event.Data.StatusCode < 100 || *event.Data.StatusCode > 599) {
		http.Error(w, "invalid status_code", http.StatusBadRequest)
		return
	}

	ts, err := time.Parse(time.RFC3339, event.Time)
	if err != nil {
		if event.Time != "" {
			http.Error(w, "invalid CloudEvent time", http.StatusBadRequest)
			return
		}
		ts = time.Now().UTC()
	}

	total := event.Data.TotalTokens
	if total == 0 {
		total = event.Data.PromptTokens + event.Data.CompletionTokens
	}

	// HTTP status: the gateway carries status_code only on error events
	// (which is why those rows show 0/0/0/0 tokens). A success/usage event
	// has no status_code, so it is a 200. Store a concrete value on every
	// new row; historical rows predating this column stay NULL (unknown).
	status := http.StatusOK
	if event.Data.StatusCode != nil {
		status = *event.Data.StatusCode
	}

	usageEvent := storage.UsageEvent{
		EventID:             event.ID,
		Timestamp:           ts,
		Username:            event.Data.User,
		GroupName:           event.Data.Group,
		Subscription:        event.Data.Subscription,
		Provider:            event.Data.Provider,
		Model:               event.Data.Model,
		PromptTokens:        event.Data.PromptTokens,
		CompletionTokens:    event.Data.CompletionTokens,
		TotalTokens:         total,
		CachedInputTokens:   event.Data.CachedInputTokens,
		CacheCreationTokens: event.Data.CacheCreationTokens,
		ReasoningTokens:     event.Data.ReasoningTokens,
		Source:              event.Source,
		UserAgent:           event.Data.UserAgent,
		StatusCode:          &status,
	}

	if h.store == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := h.store.InsertEvent(r.Context(), usageEvent); err != nil {
		slog.Error("failed to insert event", "error", err, "event_id", event.ID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	slog.Info("event recorded", "user", event.Data.User, "model", event.Data.Model, "tokens", total)
	w.WriteHeader(http.StatusNoContent)
}
