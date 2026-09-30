package handler

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/redhat-et/pricetag-metering/internal/storage"
)

type UserModelPolicyHandler struct {
	store *storage.Store
}

func NewUserModelPolicyHandler(store *storage.Store) *UserModelPolicyHandler {
	return &UserModelPolicyHandler{store: store}
}

// HandleUserModelPolicy manages one user's explicit model allowlist. A PUT
// replaces the whole list; an empty list denies every model. DELETE removes
// the restriction and returns the user to baseline gateway policy.
func (h *UserModelPolicyHandler) HandleUserModelPolicy(w http.ResponseWriter, r *http.Request) {
	const prefix = "/api/v1/model-policies/users/"
	username, err := parseUserModelPolicyUsername(r.URL.EscapedPath(), prefix)
	if err != nil {
		if errors.Is(err, errModelPolicyPathNotFound) {
			http.NotFound(w, r)
		} else {
			http.Error(w, "invalid username path segment", http.StatusBadRequest)
		}
		return
	}
	w.Header().Set("Cache-Control", "no-store")

	switch r.Method {
	case http.MethodGet:
		policy, err := h.store.GetUserModelAllowlist(r.Context(), username)
		if err != nil {
			http.Error(w, "model policy unavailable", http.StatusInternalServerError)
			return
		}
		writeJSON(w, policy)
	case http.MethodPut:
		var body struct {
			Models *[]string `json:"models"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		if body.Models == nil {
			http.Error(w, "models is required; use [] to block all models", http.StatusBadRequest)
			return
		}
		policy, err := h.store.SetUserModelAllowlist(r.Context(), "partner-m2m", username, *body.Models)
		if err != nil {
			if errors.Is(err, storage.ErrInvalidUserModelAllowlist) {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			http.Error(w, "model policy update failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, policy)
	case http.MethodDelete:
		if err := h.store.DeleteUserModelAllowlist(r.Context(), "partner-m2m", username); err != nil {
			http.Error(w, "model policy delete failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"username": username, "enabled": false, "models": []string{}})
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

var errModelPolicyPathNotFound = errors.New("model policy path not found")

func parseUserModelPolicyUsername(path, prefix string) (string, error) {
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, "/allowlist") {
		return "", errModelPolicyPathNotFound
	}
	escapedUsername := strings.TrimSuffix(strings.TrimPrefix(path, prefix), "/allowlist")
	if escapedUsername == "" || strings.Contains(escapedUsername, "/") {
		return "", errors.New("invalid model policy username path")
	}
	username, err := url.PathUnescape(escapedUsername)
	if err != nil || strings.TrimSpace(username) == "" || strings.Contains(username, "/") {
		return "", errors.New("invalid model policy username path")
	}
	return username, nil
}
