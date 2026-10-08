package config

import (
	"os"
	"reflect"
	"testing"
)

// envList backs ADMIN_USERS / SUPERADMIN_USERS, which gate the admin and
// super-admin surfaces. The deployment sets one comma-separated and one
// space-separated, so both forms (and a mix) must parse into individual
// identities — a whole list collapsed into one entry silently denies access.
func TestEnvList_Separators(t *testing.T) {
	cases := map[string][]string{
		"a@x.com,b@x.com":            {"a@x.com", "b@x.com"},
		"a@x.com b@x.com":            {"a@x.com", "b@x.com"},
		"a@x.com, b@x.com   c@x.com": {"a@x.com", "b@x.com", "c@x.com"},
		"  ":                         nil,
		"":                           nil,
	}
	for raw, want := range cases {
		t.Setenv("TEST_ENV_LIST", raw)
		if got := envList("TEST_ENV_LIST"); !reflect.DeepEqual(got, want) {
			t.Errorf("envList(%q) = %v, want %v", raw, got, want)
		}
	}
}

// The read switch follows the cache-flag rule (PR #19 review, part B
// condition 1): deploying a build and enabling behavior are separate
// decisions, so the read default is OFF / 300s. Live writes follow the read
// default unless the deployment explicitly overrides them, which avoids the
// ingestion lock when the dashboard still serves raw events.
func TestRollupReadSwitchDefaults(t *testing.T) {
	t.Setenv("DASHBOARD_USE_ROLLUPS", "")
	t.Setenv("LIVE_ROLLUPS_ENABLED", "")
	t.Setenv("ROLLUP_REFRESH_SECONDS", "")
	cfg := Load()
	if cfg.DashboardUseRollups {
		t.Error("DashboardUseRollups must default OFF — rollup reads are enabled per deployment, not by shipping the code")
	}
	if cfg.LiveRollupsEnabled {
		t.Error("LiveRollupsEnabled must default OFF — synchronous rollup writes are enabled per deployment")
	}
	if cfg.RollupRefreshSeconds != 300 {
		t.Errorf("RollupRefreshSeconds default = %d, want 300 (bounds refresh and parity-check latency)", cfg.RollupRefreshSeconds)
	}
}

func TestRollupConfigurationMatrix(t *testing.T) {
	tests := []struct {
		name       string
		reads      string
		live       string
		wantReads  bool
		wantWrites bool
	}{
		{name: "raw reads and live writes off", reads: "false", live: "false", wantReads: false, wantWrites: false},
		{name: "raw reads and live writes on", reads: "false", live: "true", wantReads: false, wantWrites: true},
		{name: "rollup reads and live writes off", reads: "true", live: "false", wantReads: true, wantWrites: false},
		{name: "rollup reads and live writes on", reads: "true", live: "true", wantReads: true, wantWrites: true},
		{name: "rollup reads default to live writes", reads: "true", live: "", wantReads: true, wantWrites: true},
		{name: "raw reads default to live writes off", reads: "false", live: "", wantReads: false, wantWrites: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("DASHBOARD_USE_ROLLUPS", tt.reads)
			if tt.live == "" {
				t.Setenv("LIVE_ROLLUPS_ENABLED", "")
			} else {
				t.Setenv("LIVE_ROLLUPS_ENABLED", tt.live)
			}
			cfg := Load()
			if cfg.DashboardUseRollups != tt.wantReads {
				t.Errorf("DashboardUseRollups = %v, want %v", cfg.DashboardUseRollups, tt.wantReads)
			}
			if cfg.LiveRollupsEnabled != tt.wantWrites {
				t.Errorf("LiveRollupsEnabled = %v, want %v", cfg.LiveRollupsEnabled, tt.wantWrites)
			}
		})
	}
}

func TestQuotaEnforcementDefaultsEnabled(t *testing.T) {
	os.Unsetenv("QUOTA_ENFORCEMENT_ENABLED")
	if cfg := Load(); !cfg.QuotaEnforcementEnabled {
		t.Fatal("quota enforcement must default enabled for the safety net")
	}
	t.Setenv("QUOTA_ENFORCEMENT_ENABLED", "true")
	if cfg := Load(); !cfg.QuotaEnforcementEnabled {
		t.Fatal("explicit quota enforcement enablement was ignored")
	}
}

func TestPartnerAPISecretsLoadFromEnvironment(t *testing.T) {
	t.Setenv("USAGE_REPORT_API_SECRET", "usage")
	t.Setenv("MODEL_POLICY_API_SECRET", "policy")
	t.Setenv("USER_MANAGEMENT_API_SECRET", "users")
	t.Setenv("MODEL_CATALOG_API_SECRET", "catalog")
	cfg := Load()
	if cfg.UsageReportAPISecret != "usage" || cfg.ModelPolicyAPISecret != "policy" ||
		cfg.UserManagementAPISecret != "users" || cfg.ModelCatalogAPISecret != "catalog" {
		t.Fatalf("partner API secrets did not load from environment")
	}
}

func TestPartnerAPIAdditionalSecretsLoadFromEnvironment(t *testing.T) {
	t.Setenv("USAGE_REPORT_API_SECRET", "legacy-usage")
	t.Setenv("USAGE_REPORT_API_SECRET_AIR", "air-usage")
	t.Setenv("USAGE_REPORT_API_SECRET_AIBT", "aibt-usage")
	t.Setenv("MODEL_POLICY_API_SECRET", "legacy-policy")
	t.Setenv("MODEL_POLICY_API_SECRET_AIBT", "aibt-policy")
	t.Setenv("MODEL_CATALOG_API_SECRET", "legacy-catalog")
	t.Setenv("MODEL_CATALOG_API_SECRET_AIBT", "aibt-catalog")
	cfg := Load()
	wantUsage := []string{"legacy-usage", "air-usage", "aibt-usage"}
	wantPolicy := []string{"legacy-policy", "aibt-policy"}
	wantCatalog := []string{"legacy-catalog", "aibt-catalog"}
	if !reflect.DeepEqual(cfg.UsageReportAPISecrets, wantUsage) ||
		!reflect.DeepEqual(cfg.ModelPolicyAPISecrets, wantPolicy) ||
		!reflect.DeepEqual(cfg.ModelCatalogAPISecrets, wantCatalog) {
		t.Fatalf("additional partner API secrets loaded incorrectly: usage=%v policy=%v catalog=%v", cfg.UsageReportAPISecrets, cfg.ModelPolicyAPISecrets, cfg.ModelCatalogAPISecrets)
	}
}

// DB pool envs control database/sql pool sizing. Unset values must fall
// back to the defaults that lift metering off the 5s gateway deadline
// under distinct-user bursts; set values must win.
func TestDBPoolEnv(t *testing.T) {
	os.Unsetenv("DB_MAX_OPEN_CONNS")
	os.Unsetenv("DB_MAX_IDLE_CONNS")
	os.Unsetenv("DB_CONN_MAX_LIFETIME_SECONDS")
	cfg := Load()
	if cfg.DBMaxOpenConns != 50 {
		t.Errorf("DBMaxOpenConns default = %d, want 50", cfg.DBMaxOpenConns)
	}
	if cfg.DBMaxIdleConns != 10 {
		t.Errorf("DBMaxIdleConns default = %d, want 10", cfg.DBMaxIdleConns)
	}
	if cfg.DBConnMaxLifetimeSeconds != 14400 {
		t.Errorf("DBConnMaxLifetimeSeconds default = %d, want 14400", cfg.DBConnMaxLifetimeSeconds)
	}
	t.Setenv("DB_MAX_OPEN_CONNS", "37")
	t.Setenv("DB_MAX_IDLE_CONNS", "9")
	t.Setenv("DB_CONN_MAX_LIFETIME_SECONDS", "3600")
	cfg = Load()
	if cfg.DBMaxOpenConns != 37 || cfg.DBMaxIdleConns != 9 || cfg.DBConnMaxLifetimeSeconds != 3600 {
		t.Errorf("DB pool env overrides not honored: %+v", cfg)
	}
}
