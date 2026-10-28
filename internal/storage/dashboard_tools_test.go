package storage

import "testing"

func TestDashboardTool(t *testing.T) {
	tests := []struct {
		userAgent string
		want      string
	}{
		{"claude-code/2.1.0", "Claude Code"},
		{"  claude-code/2.1.0  ", "Claude Code"},
		{"claude-cli/1.0", "Claude Code"},
		{"codex-tui/0.1", "Codex"},
		{"codex/1.2", "Codex"},
		{"opencode/1.0", "OpenCode"},
		{"opencode-nightly/1.0", "OpenCode"},
		{"opencode.custom", "OpenCode"},
		{"pi-coding-agent/0.1", "Pi"},
		{"pi.something/1.0", "Pi"},
		{"pi (darwin 25.6.0; arm64)", "Pi"},
		{"OpenAI/Python 2.43.0", "OpenAI"},
		{"gemini-cli/0.7.0", "Gemini CLI"},
		{"aider/0.86.1", "Aider"},
		{"Charm-Crush/v0.0.0-20261012010324-03f5dcbe64e8 (https://charm.land/crush)", "Charm-Crush"},
		{"omp/18.10.2", "omp"},
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
