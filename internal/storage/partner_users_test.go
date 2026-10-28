package storage

import (
	"errors"
	"testing"
)

func TestNormalizePartnerUserTags(t *testing.T) {
	valid := map[string]any{
		"email":        " alice@example.com ",
		"first_name":   " Alice ",
		"last_name":    "Example",
		"manager_uuid": "123E4567-E89B-12D3-A456-426614174000",
		"department":   "engineering",
	}
	got, username, err := normalizePartnerUserTags(valid)
	if err != nil {
		t.Fatalf("normalizePartnerUserTags(valid) error = %v", err)
	}
	if username != "alice@example.com" || got["first_name"] != "Alice" || got["manager_uuid"] != "123e4567-e89b-12d3-a456-426614174000" {
		t.Fatalf("unexpected normalized identity/tags: username=%q tags=%#v", username, got)
	}

	rootManager := map[string]any{
		"email": "alice@example.com", "first_name": "Alice", "last_name": "Example", "manager_uuid": nil,
	}
	if _, _, err := normalizePartnerUserTags(rootManager); err != nil {
		t.Fatalf("null manager_uuid should be valid: %v", err)
	}
}

func TestNormalizePartnerUserTagsRejectsInvalidIdentityAndValues(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"email": "alice@example.com", "first_name": "Alice", "last_name": "Example"}
	}
	tests := []struct {
		name string
		tags map[string]any
	}{
		{name: "missing email", tags: map[string]any{"first_name": "Alice", "last_name": "Example"}},
		{name: "display name email", tags: map[string]any{"email": "Alice <alice@example.com>", "first_name": "Alice", "last_name": "Example"}},
		{name: "non-string additional tag", tags: map[string]any{"email": "alice@example.com", "first_name": "Alice", "last_name": "Example", "employee_number": 123}},
		{name: "invalid manager uuid", tags: map[string]any{"email": "alice@example.com", "first_name": "Alice", "last_name": "Example", "manager_uuid": "not-a-uuid"}},
		{name: "invalid tag key", tags: map[string]any{"email": "alice@example.com", "first_name": "Alice", "last_name": "Example", "Department": "engineering"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := normalizePartnerUserTags(tc.tags)
			if !errors.Is(err, ErrInvalidPartnerUser) {
				t.Fatalf("error = %v, want ErrInvalidPartnerUser", err)
			}
		})
	}
	if _, _, err := normalizePartnerUserTags(base()); err != nil {
		t.Fatalf("valid minimal tags: %v", err)
	}
}

func TestNormalizePartnerUserTagsAcceptsGroupArrays(t *testing.T) {
	tags := map[string]any{
		"email":      "alice@example.com",
		"first_name": "Alice",
		"last_name":  "Example",
		"groups":     []any{"GE", "platform"},
		"dev_groups": []string{"local"},
	}
	got, _, err := normalizePartnerUserTags(tags)
	if err != nil {
		t.Fatalf("group arrays should be valid: %v", err)
	}
	if groups, ok := got["groups"].([]string); !ok || len(groups) != 2 || groups[0] != "GE" {
		t.Fatalf("unexpected groups normalization: %#v", got["groups"])
	}
}
