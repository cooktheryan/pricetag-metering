package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/handler"
	"github.com/redhat-et/pricetag-metering/internal/k8s"
	"github.com/redhat-et/pricetag-metering/internal/maasapi"
	"github.com/redhat-et/pricetag-metering/internal/pricing"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

func main() {
	cfg := config.Load()
	if cfg.DatabaseURL == "" {
		slog.Error("DATABASE_URL is required")
		os.Exit(1)
	}
	if cfg.M2MAuthRequired && cfg.M2MSharedSecret == "" {
		slog.Error("M2M_AUTH_REQUIRED is enabled but M2M_SHARED_SECRET is empty")
		os.Exit(1)
	}

	// MonthlyTokenQuota is the per-user monthly token budget the entitlement
	// endpoint reports against. Enforcement of actual traffic belongs in the
	// gateway (praxis-proxy/ai#121); here it only shapes the reported balance.
	store, err := storage.New(cfg.DatabaseURL, int64(cfg.MonthlyTokenQuota), storage.PoolConfig{
		MaxOpenConns:    cfg.DBMaxOpenConns,
		MaxIdleConns:    cfg.DBMaxIdleConns,
		ConnMaxLifetime: time.Duration(cfg.DBConnMaxLifetimeSeconds) * time.Second,
	})
	if err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer store.Close()
	store.SetQuotaEnforcement(cfg.QuotaEnforcementEnabled)
	store.SetLiveRollups(cfg.LiveRollupsEnabled)
	if cfg.DashboardUseRollups && !cfg.LiveRollupsEnabled {
		slog.Warn("dashboard rollups are eventually consistent because live writes are disabled", "refresh_interval_seconds", cfg.RollupRefreshSeconds)
	} else if cfg.DashboardUseRollups && cfg.LiveRollupsEnabled {
		slog.Warn("dashboard rollups have transactional freshness but ingestion shares hourly rollup locks")
	} else if !cfg.DashboardUseRollups && cfg.LiveRollupsEnabled {
		slog.Warn("live rollup writes are enabled while dashboard reads are raw; ingestion still takes hourly rollup locks")
	}
	// Repair manager links imported before the manager's Partner identity was
	// provisioned. This is a bounded, idempotent startup repair; normal writes
	// reconcile only the manager affected by that write.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		updated, err := store.ReconcilePartnerManagerLinks(ctx)
		if err != nil {
			slog.Error("partner manager-link reconciliation failed", "error", err)
			return
		}
		if updated > 0 {
			slog.Info("partner manager links reconciled", "updated", updated)
		}
	}()

	// Read replica (Phase 2 scaling plan): dashboard/report reads only,
	// enforcement paths ignore this pool. A replica that can't be pinged
	// is a loud config error, not a boot failure — reads stay on primary.
	if cfg.ReadDatabaseURL != "" {
		if err := store.UseReadReplica(cfg.ReadDatabaseURL, storage.PoolConfig{
			MaxOpenConns:    cfg.DBMaxOpenConns,
			MaxIdleConns:    cfg.DBMaxIdleConns,
			ConnMaxLifetime: time.Duration(cfg.DBConnMaxLifetimeSeconds) * time.Second,
		}); err != nil {
			slog.Error("read replica unavailable — all reads stay on the primary", "error", err)
		} else {
			slog.Info("read replica enabled for dashboard/report reads")
		}
	}

	// Phase 3 groundwork: freeze cost at insert (live path), and bring the
	// historical ledger + hourly rollups up to date in the background —
	// resumable and idempotent, steady-state it checks one meta row.
	go store.EnsureRollupsBackfilled(context.Background())

	// Phase 3 part B: maintenance loop (refresh recent hours, standing
	// parity check) runs REGARDLESS of the read switch — keeping the
	// table reconciled and the parity signal warm is what makes
	// DASHBOARD_USE_ROLLUPS a risk-free flip and a red check an
	// automatic fallback to raw. Reads switch only when flag + ready +
	// parity-green all hold; see /api/v1/admin/rollups for state.
	store.UseRollups(cfg.DashboardUseRollups)
	go store.RunRollupMaintenance(context.Background(), time.Duration(cfg.RollupRefreshSeconds)*time.Second)

	// Seed model pricing from LiteLLM (try fetch latest, fall back to bundled)
	ctx := context.Background()
	litellmPrices, pricingSource := pricing.LoadPrices(ctx)
	if len(litellmPrices) > 0 {
		storePrices := make([]storage.ModelPrice, len(litellmPrices))
		for i, p := range litellmPrices {
			storePrices[i] = storage.ModelPrice{
				Model: p.Model, Provider: p.Provider,
				InputCost: p.InputCost, OutputCost: p.OutputCost,
				CacheWriteCost: p.CacheWriteCost, CacheReadCost: p.CacheReadCost,
			}
		}
		updated, seedErr := store.SeedPricing(ctx, storePrices)
		if seedErr != nil {
			slog.Warn("pricing seed failed — dashboard costs may be stale", "error", seedErr)
		} else {
			slog.Info("model pricing seeded", "models", len(storePrices), "updated", updated, "source", pricingSource)
		}
	}

	// Seed self-hosted ("hosted") model pricing at OpenRouter parity. These
	// are not in LiteLLM's catalog, so they must be seeded independently —
	// even when the LiteLLM load above fails — or the cost query reprices
	// hosted traffic at the paid default. Seeded last so these rows always
	// win the upsert.
	localPrices := pricing.LocalPrices()
	storeLocal := make([]storage.ModelPrice, len(localPrices))
	for i, p := range localPrices {
		storeLocal[i] = storage.ModelPrice{
			Model: p.Model, Provider: p.Provider,
			InputCost: p.InputCost, OutputCost: p.OutputCost,
			CacheWriteCost: p.CacheWriteCost, CacheReadCost: p.CacheReadCost,
			Deprecated: p.Deprecated,
		}
	}
	if updated, seedErr := store.SeedPricing(ctx, storeLocal); seedErr != nil {
		slog.Warn("local pricing seed failed — hosted models may reprice at the paid default", "error", seedErr)
	} else {
		slog.Info("local model pricing seeded", "models", len(storeLocal), "updated", updated)
	}

	// Vendor list prices (for the dashboard's cost-saved column) — a second
	// rate set on the same rows, seeded independently. Best-effort: a failed
	// fetch leaves previously seeded list prices in place (SeedListPricing is
	// UPDATE-only and skips zero rates), so the column goes stale, not wrong.
	if listPrices, listErr := pricing.LoadListPrices(ctx); listErr != nil {
		slog.Warn("list pricing fetch failed — cost-saved column may be stale", "error", listErr)
	} else {
		listSeed := make([]storage.ModelPrice, 0, len(listPrices)+len(pricing.LocalListPrices()))
		for _, p := range listPrices {
			listSeed = append(listSeed, storage.ModelPrice{
				Model: p.Model, Provider: p.Provider,
				ListInputCost: p.ListInputCost, ListOutputCost: p.ListOutputCost,
				ListCacheWriteCost: p.ListCacheWriteCost, ListCacheReadCost: p.ListCacheReadCost,
			})
		}
		for _, p := range pricing.LocalListPrices() {
			listSeed = append(listSeed, storage.ModelPrice{
				Model: p.Model, Provider: p.Provider,
				ListInputCost: p.ListInputCost, ListOutputCost: p.ListOutputCost,
				ListCacheWriteCost: p.ListCacheWriteCost, ListCacheReadCost: p.ListCacheReadCost,
			})
		}
		if updated, seedErr := store.SeedListPricing(ctx, listSeed); seedErr != nil {
			slog.Warn("list pricing seed failed — cost-saved column may be stale", "error", seedErr)
		} else {
			slog.Info("list pricing seeded", "models", len(listSeed), "updated", updated)
		}
	}

	eventsHandler := handler.NewEventsHandler(store)
	entitlementsHandler := handler.NewEntitlementsHandler(store, cfg)
	dashboardHandler := handler.NewDashboardHandler(store, cfg)

	// Kubernetes adapter — optional. It stays disabled until model/provider
	// CRD coordinates are configured, and even when enabled it degrades
	// gracefully to empty data if the cluster is unreachable, so the service
	// runs anywhere the CloudEvents contract holds.
	var k8sClient *k8s.Client
	if cfg.Kubernetes.Enabled() {
		k8sClient, err = k8s.NewClient(cfg.Kubernetes)
		if err != nil {
			slog.Warn("kubernetes adapter unavailable — admin API will return empty data", "error", err)
			k8sClient = nil
		}
	} else {
		slog.Info("kubernetes adapter disabled — set MODEL_CRD_GROUP/PROVIDER_CRD_GROUP to enable")
	}

	// maas-api client for key management (create/list/revoke). The base URL
	// defaults to the same maas-api the login flow validates against, so a
	// fresh cluster needs no extra configuration.
	maasAPIURL := os.Getenv("MAAS_API_URL")
	if maasAPIURL == "" {
		validateURL := os.Getenv("MAAS_VALIDATE_URL")
		if validateURL == "" {
			validateURL = "http://maas-api:8080/internal/v1/api-keys/validate"
		}
		maasAPIURL = strings.TrimSuffix(validateURL, "/internal/v1/api-keys/validate")
	}
	maasTenant := os.Getenv("MAAS_TENANT")
	if maasTenant == "" {
		maasTenant = "models-as-a-service"
	}
	maasClient := maasapi.NewClient(maasAPIURL, maasTenant)

	adminHandler := handler.NewAdminHandler(k8sClient, maasClient, cfg)
	adminHandler.SetStore(store)
	authHandler := handler.NewAuthHandler(cfg)
	authHandler.SetOrgStore(store) // managers land on /manager after login
	keysHandler := handler.NewKeysHandler(k8sClient, cfg, store)
	usageReportHandler := handler.NewUsageReportHandler(store)
	partnerUsersHandler := handler.NewPartnerUsersHandler(store, maasClient, cfg.PartnerUserKeyGroup)
	partnerUsersHandler.SetUserHeader(cfg.UserHeader)
	partnerUserUsageHandler := handler.NewPartnerUserUsageHandler(store)
	modelCatalogHandler := handler.NewModelCatalogHandler(k8sClient)
	userModelPolicyHandler := handler.NewUserModelPolicyHandler(store)
	quotaAdminHandler := handler.NewQuotaAdminHandler(store)
	modelPolicyAdminHandler := handler.NewModelPolicyAdminHandler(store)
	auth := authHandler.RequireAuth

	mux := http.NewServeMux()

	// Machine-to-machine APIs — no session required
	m2mAuth := func(next http.HandlerFunc) http.HandlerFunc { return handler.RequireM2MAuth(cfg, next) }
	mux.HandleFunc("/api/v1/events", m2mAuth(eventsHandler.HandleEvent))
	mux.HandleFunc("/api/v1/customers/", m2mAuth(entitlementsHandler.HandleEntitlement))
	// Partner APIs use endpoint-specific bearer credentials in addition to any
	// Route/AuthPolicy. This protects direct Service and port-forward access.
	mux.HandleFunc("/api/v1/usage/users/", handler.RequirePartnerAPIAuthAny(cfg.UsageReportAPISecrets, usageReportHandler.HandleUserUsage))
	mux.HandleFunc("/api/v1/usage/reports", handler.RequirePartnerAPIAuthAny(cfg.UsageReportAPISecrets, partnerUserUsageHandler.HandleBatchUserUsage))
	mux.HandleFunc("/api/v1/models", handler.RequirePartnerAPIAuthAny(cfg.ModelCatalogAPISecrets, modelCatalogHandler.Handle))
	mux.HandleFunc("/api/v1/users", handler.RequirePartnerAPIAuth(cfg.UserManagementAPISecret, partnerUsersHandler.HandleUsers))
	mux.HandleFunc("/api/v1/users/", handler.RequirePartnerAPIAuth(cfg.UserManagementAPISecret, partnerUsersHandler.HandleUsers))
	mux.HandleFunc("/api/v1/admin/partner-users/", auth(handler.RequirePartnerSuperAdmin(cfg, store, partnerUsersHandler.HandleAdminAccess)))
	mux.HandleFunc("/api/v1/admin/partner-users", auth(handler.RequirePartnerSuperAdmin(cfg, store, partnerUsersHandler.HandleAdminUsers)))
	mux.HandleFunc("/api/v1/model-policies/users/", handler.RequirePartnerAPIAuthAny(cfg.ModelPolicyAPISecrets, userModelPolicyHandler.HandleUserModelPolicy))
	// /api/v1/team-usage was REMOVED on purpose: it sat outside auth, took
	// the group from the query string, and defaulted to a hard-coded team.
	// Its replacement is /api/v1/org/usage below, which is authenticated
	// and scope-enforced. Do not re-add a sibling.

	// Auth endpoints — unauthenticated by definition
	mux.HandleFunc("/login", authHandler.HandleLogin)
	mux.HandleFunc("/logout", authHandler.HandleLogout)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := store.Ping(ctx); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	// Public onboarding page — no session by design: it is the link you
	// send someone before they have a key. Its gateway URLs are substituted
	// at serve time from WELCOME_*_URL env vars, so the repo template stays
	// host-free. Root sends newcomers here; signed-in users navigate on.
	mux.HandleFunc("/welcome", dashboardHandler.ServeWelcome)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/welcome", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})

	// User pages — session required. /whoami backs both the legacy pages and
	// the redesigned user dashboard (name, groups, admin flag, impersonation).
	// The legacy "My account" page is retired — its tab is gone from every
	// page and old bookmarks redirect to the main dashboard instead of 404.
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/me/keys", auth(keysHandler.HandleKeys))
	mux.HandleFunc("/me/keys/", auth(keysHandler.HandleKeys))
	mux.HandleFunc("/me/whoami", auth(keysHandler.HandleWhoAmI))
	mux.HandleFunc("/api/v1/whoami", auth(keysHandler.HandleWhoAmI))
	mux.HandleFunc("/whoami", auth(keysHandler.HandleWhoAmI))

	// Dashboard — session required, per-user scoping in handlers. The API
	// and page are administrator-only while user dashboard access is pending
	// legal approval. The API handlers ride the response cache (inside auth:
	// a hit still pays session validation, and the cache key contains the
	// resolved scope).
	dashCache := handler.NewDashboardCache(cfg, store)
	dashboardPage := func(next http.HandlerFunc) http.HandlerFunc {
		return auth(handler.RequirePartnerAdminPage(cfg, store, next, dashboardHandler.ServeComingSoon))
	}
	dashboardAPI := func(next http.HandlerFunc) http.HandlerFunc {
		return auth(handler.RequirePartnerAdminAPI(cfg, store, next))
	}
	mux.HandleFunc("/dashboard", dashboardPage(dashboardHandler.ServeDashboard))
	mux.HandleFunc("/api/v1/dashboard/overview", dashboardAPI(dashCache.Wrap(dashboardHandler.HandleOverview)))
	mux.HandleFunc("/api/v1/dashboard/groups", dashboardAPI(dashCache.Wrap(dashboardHandler.HandleGroups)))
	mux.HandleFunc("/api/v1/dashboard/users", dashboardAPI(dashCache.Wrap(dashboardHandler.HandleUsers)))
	mux.HandleFunc("/api/v1/dashboard/directory-users", dashboardAPI(dashboardHandler.HandleDirectoryUsers))
	mux.HandleFunc("/api/v1/dashboard/models", dashboardAPI(dashCache.Wrap(dashboardHandler.HandleModels)))
	mux.HandleFunc("/api/v1/dashboard/tools", dashboardAPI(dashCache.Wrap(dashboardHandler.HandleTools)))
	mux.HandleFunc("/api/v1/dashboard/timeline", dashboardAPI(dashCache.Wrap(dashboardHandler.HandleTimeline)))
	mux.HandleFunc("/api/v1/dashboard/recent", dashboardAPI(dashCache.Wrap(dashboardHandler.HandleRecent)))

	// Pricing modal rate card — readable by any logged-in user: the rates
	// are the same numbers every request is billed at, no user data.
	mux.HandleFunc("/api/v1/pricing", dashboardAPI(handler.NewPricingRefreshHandler(store).HandleList))

	// Operator pages (admin console, routing) are SUPER-ADMIN
	// only. Regular admins get the org-wide Usage view on /dashboard and
	// nothing else — most of them only ever want to look at usage, and the
	// pages below mutate platform state. Gated server-side, not just in the
	// nav, so deep links and direct API calls are refused too.
	mux.HandleFunc("/admin", auth(handler.RequirePartnerSuperAdmin(cfg, store, adminHandler.ServeAdmin)))
	mux.HandleFunc("/routing", auth(handler.RequirePartnerSuperAdmin(cfg, store, adminHandler.ServeRouting)))
	mux.HandleFunc("/admin2", auth(handler.RequirePartnerSuperAdmin(cfg, store, adminHandler.ServeRouting)))
	// Admin APIs are gated by RequirePartnerSuperAdmin (auth() alone is not enough —
	// otherwise any signed-in user could change weights/config).
	// Cache hit/miss counters — the Phase 1 verify step: hit ratio should
	// approach (polls − filter-combos-per-TTL) / polls once the fleet
	// settles. Read-only, super-admin page material.
	mux.HandleFunc("/api/v1/admin/cache-stats", auth(handler.RequirePartnerSuperAdmin(cfg, store, dashCache.ServeStats)))
	rollupHandler := handler.NewRollupHandler(store, cfg.RollupRefreshSeconds)
	mux.HandleFunc("/api/v1/admin/rollups", auth(handler.RequirePartnerSuperAdmin(cfg, store, rollupHandler.HandleStatus)))
	mux.HandleFunc("/api/v1/admin/providers", auth(handler.RequirePartnerSuperAdmin(cfg, store, adminHandler.HandleProviders)))
	mux.HandleFunc("/api/v1/admin/models", auth(handler.RequirePartnerSuperAdmin(cfg, store, adminHandler.HandleModels)))
	mux.HandleFunc("/api/v1/admin/models/", auth(handler.RequirePartnerSuperAdmin(cfg, store, adminHandler.HandleUpdateWeights)))
	mux.HandleFunc("/api/v1/admin/config", auth(handler.RequirePartnerSuperAdmin(cfg, store, adminHandler.HandleConfig)))
	mux.HandleFunc("/api/v1/admin/models/provider/", auth(handler.RequirePartnerSuperAdmin(cfg, store, adminHandler.HandleUpdateProvider)))
	mux.HandleFunc("/api/v1/admin/pricing/refresh", auth(handler.RequirePartnerSuperAdmin(cfg, store, handler.NewPricingRefreshHandler(store).HandleRefresh)))
	mux.HandleFunc("/api/v1/admin/safety-net", auth(handler.RequirePartnerSuperAdmin(cfg, store, quotaAdminHandler.HandlePolicy)))
	mux.HandleFunc("/api/v1/admin/model-policies", auth(handler.RequirePartnerSuperAdmin(cfg, store, modelPolicyAdminHandler.HandleList)))
	// OpenShift users/entitlements management (redesigned admin page).

	// Key APIs are reachable by any signed-in user: the user dashboard manages
	// the caller's own keys. The handlers scope non-admins to their own
	// identity, so a regular user can only ever see or create their own keys.
	mux.HandleFunc("/api/v1/admin/keys", auth(adminHandler.HandleKeys))
	mux.HandleFunc("/api/v1/admin/keys/", auth(adminHandler.HandleKeys))
	// Admin "view as user" — the handler checks admin against the real
	// session identity, not the swapped header, so it also clears itself.
	mux.HandleFunc("/admin/impersonate", auth(authHandler.HandleImpersonate))

	// Manager view — session required; the page adapts to the caller's
	// scope (plain user sees self, manager sees subtree, super-admin sees
	// all). Backed entirely by partner_users.
	orgHandler := handler.NewPartnerOrgHandler(store, cfg)
	mux.HandleFunc("/manager", dashboardPage(orgHandler.ServeManager))
	mux.HandleFunc("/api/v1/org/scope", dashboardAPI(orgHandler.HandleScope))
	mux.HandleFunc("/api/v1/org/usage", dashboardAPI(orgHandler.HandleOrgUsage))
	mux.HandleFunc("/api/v1/org/charts", dashboardAPI(orgHandler.HandleOrgCharts))
	mux.HandleFunc("/api/v1/org/person", dashboardAPI(orgHandler.HandleOrgPerson))

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	go func() {
		slog.Info("metering service starting", "port", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	<-stop

	slog.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)
}
