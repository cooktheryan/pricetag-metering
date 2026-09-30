package storage

import "testing"

// --- Post-cap allowance (issue #22) ---

func TestModelAllowedOverLimit(t *testing.T) {
	base := QuotaDecision{
		Enforced: true, LimitUSD: 300, SpentUSD: 301,
		OverLimitModels: []string{"Inferact/Qwen3.8-Flash-Next-NVFP4", "gpt-5.6-luna"},
	}
	cases := []struct {
		name   string
		mutate func(*QuotaDecision)
		model  string
		want   bool
	}{
		{"exact match over cap", func(*QuotaDecision) {}, "gpt-5.6-luna", true},
		{"case mismatch denies (fail closed)", func(*QuotaDecision) {}, "GPT-5.6-LUNA", false},
		{"prefix does not match (no wildcards)", func(*QuotaDecision) {}, "gpt-5.6-luna-v2", false},
		{"empty model never matches", func(*QuotaDecision) {}, "", false},
		{"unknown model denies", func(*QuotaDecision) {}, "claude-opus-4-8", false},
		{"under limit: Allowed covers it, this returns false", func(d *QuotaDecision) { d.SpentUSD = 10 }, "gpt-5.6-luna", false},
		{"spend exactly at limit is over cap", func(d *QuotaDecision) { d.SpentUSD = 300 }, "gpt-5.6-luna", true},
		{"enforcement off", func(d *QuotaDecision) { d.Enforced = false }, "gpt-5.6-luna", false},
		{"exempt super-admin", func(d *QuotaDecision) { d.Exempt = true }, "gpt-5.6-luna", false},
		{"empty list disables", func(d *QuotaDecision) { d.OverLimitModels = nil }, "gpt-5.6-luna", false},
		{"ceiling not reached", func(d *QuotaDecision) { d.OverCapCeilingUSD = 50 }, "gpt-5.6-luna", true},
		{"ceiling exactly reached denies", func(d *QuotaDecision) { d.OverCapCeilingUSD = 1 }, "gpt-5.6-luna", false},
		{"ceiling exceeded denies", func(d *QuotaDecision) { d.OverCapCeilingUSD = 0.5 }, "gpt-5.6-luna", false},
		{"zero ceiling means unlimited", func(d *QuotaDecision) { d.SpentUSD = 100000; d.OverCapCeilingUSD = 0 }, "gpt-5.6-luna", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := base
			d.OverLimitModels = append([]string{}, base.OverLimitModels...)
			tc.mutate(&d)
			if got := d.ModelAllowedOverLimit(tc.model); got != tc.want {
				t.Errorf("ModelAllowedOverLimit(%q) = %v, want %v", tc.model, got, tc.want)
			}
		})
	}
}

func TestUserModelAllowlistDecision(t *testing.T) {
	tests := []struct {
		name     string
		decision QuotaDecision
		model    string
		want     bool
	}{
		{name: "no policy preserves baseline", decision: QuotaDecision{}, model: "any-model", want: true},
		{name: "allowlisted exact id", decision: QuotaDecision{ModelPolicyActive: true, UserAllowedModels: []string{"model-a"}}, model: "model-a", want: true},
		{name: "not listed is denied", decision: QuotaDecision{ModelPolicyActive: true, UserAllowedModels: []string{"model-a"}}, model: "model-b", want: false},
		{name: "exact case match", decision: QuotaDecision{ModelPolicyActive: true, UserAllowedModels: []string{"model-a"}}, model: "Model-A", want: false},
		{name: "missing request model fails closed", decision: QuotaDecision{ModelPolicyActive: true, UserAllowedModels: []string{"model-a"}}, model: "", want: false},
		{name: "empty active list blocks all", decision: QuotaDecision{ModelPolicyActive: true, UserAllowedModels: []string{}}, model: "model-a", want: false},
		{name: "superadmin exempt", decision: QuotaDecision{Exempt: true, ModelPolicyActive: true, UserAllowedModels: []string{}}, model: "model-a", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.decision.ModelAllowed(tt.model); got != tt.want {
				t.Fatalf("ModelAllowed(%q) = %v, want %v", tt.model, got, tt.want)
			}
		})
	}
}
