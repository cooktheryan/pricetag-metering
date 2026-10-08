package storage

import "testing"

func TestDashboardTool(t *testing.T) {
	tests := []struct {
		userAgent string
		want      string
	}{
		{"claude-code/2.1.0", "Claude Code"},
		{"claude-cli/1.0", "Claude Code"},
		{"codex-tui/0.1", "Codex"},
		{"codex/1.2", "Codex"},
		{"opencode/1.0", "OpenCode"},
		{"opencode-nightly/1.0", "OpenCode"},
		{"opencode.custom", "OpenCode"},
		{"pi-coding-agent/0.1", "Pi"},
		{"pi.something/1.0", "Pi"},
		{"curl/8.0", "curl"},
		{"python-requests/2.0", "Other"},
		{"", "Other"},
	}
	for _, tt := range tests {
		if got := dashboardTool(tt.userAgent); got != tt.want {
			t.Errorf("dashboardTool(%q) = %q, want %q", tt.userAgent, got, tt.want)
		}
	}
}
