package handler

import "testing"

func TestOrgChartsUserFilterNoKeyRoot(t *testing.T) {
	tests := []struct {
		name      string
		root      string
		usernames []string
		want      string
		wantOK    bool
	}{
		{
			name:   "whole org stays unfiltered",
			root:   "",
			want:   "",
			wantOK: true,
		},
		{
			name:      "no-key person must not become whole org",
			root:      "123e4567-e89b-12d3-a456-426614174020",
			usernames: nil,
			want:      "",
			wantOK:    false,
		},
		{
			name:      "no-key person with empty slice must not become whole org",
			root:      "123e4567-e89b-12d3-a456-426614174020",
			usernames: []string{},
			want:      "",
			wantOK:    false,
		},
		{
			name:      "person with a login stays scoped",
			root:      "123e4567-e89b-12d3-a456-426614174020",
			usernames: []string{"alice@example.com"},
			want:      "alice@example.com",
			wantOK:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := orgChartsUserFilter(tt.root, tt.usernames)
			if got != tt.want || ok != tt.wantOK {
				t.Fatalf("orgChartsUserFilter(%q, %v) = (%q, %v), want (%q, %v)",
					tt.root, tt.usernames, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestEmptyOrgChartsResponseIsEmpty(t *testing.T) {
	got := emptyOrgChartsResponse()
	if got.Overview.TotalRequests != 0 ||
		got.Overview.TotalTokens != 0 ||
		got.Overview.ActiveUsers != 0 ||
		got.Overview.TotalCostUSD != 0 ||
		len(got.Models) != 0 ||
		len(got.Users) != 0 ||
		len(got.Timeline) != 0 {
		t.Fatalf("empty org charts response contains data: %+v", got)
	}
}
