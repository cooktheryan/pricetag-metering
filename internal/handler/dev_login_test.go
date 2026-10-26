package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/redhat-et/pricetag-metering/internal/config"
)

func TestDevLoginIsUnavailableWhenNotConfigured(t *testing.T) {
	h := NewAuthHandler(config.Config{})
	response := httptest.NewRecorder()
	h.HandleDevLogin(response, httptest.NewRequest(http.MethodGet, "/dev-login?as=maya.manager@example.invalid", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}

	response = httptest.NewRecorder()
	h.HandleLogin(response, httptest.NewRequest(http.MethodGet, "/login", nil))
	body := response.Body.String()
	if strings.Contains(body, "Dev test sign-in") || strings.Contains(body, "<!-- DEV_LOGIN -->") {
		t.Fatalf("dev login panel leaked when unconfigured:\n%s", body)
	}
}

func TestDevLoginRejectsUsersOutsideTheAllowlist(t *testing.T) {
	h := NewAuthHandler(config.Config{DevLoginUsers: []string{"maya.manager@example.invalid"}})
	response := httptest.NewRecorder()
	h.HandleDevLogin(response, httptest.NewRequest(http.MethodGet, "/dev-login?as=alice.team@example.invalid", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestDevLoginRequiresThePartnerDirectory(t *testing.T) {
	h := NewAuthHandler(config.Config{DevLoginUsers: []string{"maya.manager@example.invalid"}})
	response := httptest.NewRecorder()
	h.HandleDevLogin(response, httptest.NewRequest(http.MethodGet, "/dev-login?as=maya.manager@example.invalid", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func TestDevLoginPanelListsConfiguredUsers(t *testing.T) {
	h := NewAuthHandler(config.Config{DevLoginUsers: []string{
		"maya.manager@example.invalid",
		"alice.team@example.invalid",
	}})
	response := httptest.NewRecorder()
	h.HandleLogin(response, httptest.NewRequest(http.MethodGet, "/login", nil))
	body := response.Body.String()
	for _, want := range []string{
		"Dev test sign-in",
		"/dev-login?as=maya.manager%40example.invalid",
		"/dev-login?as=alice.team%40example.invalid",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("dev login panel missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "<!-- DEV_LOGIN -->") {
		t.Fatal("dev login placeholder was not replaced")
	}
}

func TestDevLoginGroups(t *testing.T) {
	cases := []struct {
		name string
		tags map[string]any
		want []string
	}{
		{"missing", map[string]any{}, nil},
		{"json array", map[string]any{"dev_groups": []any{"GE", "platform"}}, []string{"GE", "platform"}},
		{"string list", map[string]any{"dev_groups": "GE, platform"}, []string{"GE", "platform"}},
		{"wrong type", map[string]any{"dev_groups": 3}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := devLoginGroups(tc.tags)
			if len(got) != len(tc.want) {
				t.Fatalf("devLoginGroups(%v) = %v, want %v", tc.tags, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("devLoginGroups(%v) = %v, want %v", tc.tags, got, tc.want)
				}
			}
		})
	}
}

func TestIsDevResetUser(t *testing.T) {
	cases := []struct {
		name string
		tags map[string]any
		want bool
	}{
		{"missing", map[string]any{}, false},
		{"bool true", map[string]any{"dev_reset_on_login": true}, true},
		{"bool false", map[string]any{"dev_reset_on_login": false}, false},
		{"string true", map[string]any{"dev_reset_on_login": "true"}, true},
		{"other type", map[string]any{"dev_reset_on_login": 1}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDevResetUser(tc.tags); got != tc.want {
				t.Fatalf("isDevResetUser(%v) = %v, want %v", tc.tags, got, tc.want)
			}
		})
	}
}

func TestIsDevTestUser(t *testing.T) {
	cases := []struct {
		name string
		tags map[string]any
		want bool
	}{
		{"missing", map[string]any{}, false},
		{"bool true", map[string]any{"dev_test": true}, true},
		{"bool false", map[string]any{"dev_test": false}, false},
		{"string true", map[string]any{"dev_test": "true"}, true},
		{"string false", map[string]any{"dev_test": "no"}, false},
		{"other type", map[string]any{"dev_test": 1}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDevTestUser(tc.tags); got != tc.want {
				t.Fatalf("isDevTestUser(%v) = %v, want %v", tc.tags, got, tc.want)
			}
		})
	}
}
