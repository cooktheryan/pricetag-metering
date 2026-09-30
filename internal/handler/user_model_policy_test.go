package handler

import "testing"

func TestParseUserModelPolicyUsername(t *testing.T) {
	const prefix = "/api/v1/model-policies/users/"
	tests := []struct {
		name    string
		path    string
		want    string
		wantErr bool
	}{
		{name: "encoded username and documented suffix", path: prefix + "alice%40example.com/allowlist", want: "alice@example.com"},
		{name: "missing suffix", path: prefix + "alice", wantErr: true},
		{name: "empty username", path: prefix + "/allowlist", wantErr: true},
		{name: "multiple path segments", path: prefix + "alice/other/allowlist", wantErr: true},
		{name: "encoded slash", path: prefix + "alice%2Fother/allowlist", wantErr: true},
		{name: "wrong endpoint", path: "/api/v1/usage/users/alice/allowlist", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseUserModelPolicyUsername(tt.path, prefix)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseUserModelPolicyUsername(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("parseUserModelPolicyUsername(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
