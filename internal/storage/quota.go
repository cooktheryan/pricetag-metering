package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
)

// Quota management: monthly dollar budgets per user, resolved through the
// partner directory, enforced at the gateway via the entitlement endpoint's
// hasAccess flag.
//
// The design guarantees that hold across this file:
//   - The calendar month is computed in SQL (date_trunc('month', NOW())),
//     never in Go, so the spend window can never disagree across the
//     app/server timezone boundary.
//   - Nothing here writes usage_events except RecordQuotaDenial. Spend is
//     derived at query time with the shared costUSDExpr — the same number the
//     dashboard shows — over every login linked to the partner user.

// quotaMigrations create the policy and override tables. Every statement is
// idempotent.
var quotaMigrations = []string{
	// Single-row table: the boolean PK that must be true is the classic
	// Postgres singleton trick — there is exactly one row and no way to add
	// a second. The safety net is enabled by default; operators can turn it
	// off from the super-admin Safety Net tab if needed.
	`CREATE TABLE IF NOT EXISTS quota_policy (
		id BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
		default_monthly_usd NUMERIC(12,2) NOT NULL DEFAULT 600,
		enforced BOOLEAN NOT NULL DEFAULT true,
		updated_by TEXT NOT NULL DEFAULT '',
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,
	`INSERT INTO quota_policy (id) VALUES (true) ON CONFLICT DO NOTHING`,
	// Existing installations created by the first quota implementation have
	// the old untouched $300/dark defaults. Upgrade only those rows; never
	// overwrite an operator-edited policy.
	// Per-scope limits. Only the 'user' scope is consulted now (keyed by the
	// MaaS login); the legacy 'group' scope is retained in the schema for
	// historical rows but no longer resolved. A NULL lookup result is "no
	// override" — resolution order user → policy default happens in one query.
	`CREATE TABLE IF NOT EXISTS quota_overrides (
		scope TEXT NOT NULL CHECK (scope IN ('user','group')),
		principal TEXT NOT NULL,
		monthly_usd NUMERIC(12,2) NOT NULL,
		updated_by TEXT NOT NULL DEFAULT '',
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		PRIMARY KEY (scope, principal)
	)`,
	// Post-cap model allowance (issue #22): exact, case-sensitive model
	// identifiers that still pass the entitlement check when the dollar
	// gate would deny. Exact matching is
	// the security contract: the compared string is chosen by the capped
	// user, so every entry must name the literal identifier that will be
	// routed and billed. Empty list = feature off — which is also the
	// provably-inert state until the gateway can report the model
	// (upstream sends an empty one today, see the issue).
	`ALTER TABLE quota_policy ADD COLUMN IF NOT EXISTS allowed_over_limit_models TEXT[] NOT NULL DEFAULT ARRAY['rits/zai-org/glm-5-3']`,
	// Kept only for compatibility with databases created by the old design;
	// the application no longer reads or writes this legacy column.
	`ALTER TABLE quota_policy ADD COLUMN IF NOT EXISTS over_cap_ceiling_usd NUMERIC(12,2)`,
	// Existing installations created by the first quota implementation have
	// the old untouched $300/dark defaults. Upgrade only those rows; never
	// overwrite an operator-edited policy. The allowance default is set after
	// the column exists so old rows also get the initial GLM bypass.
	`UPDATE quota_policy SET default_monthly_usd = 600, enforced = true,
	        allowed_over_limit_models = CASE WHEN cardinality(allowed_over_limit_models) = 0
	          THEN ARRAY['rits/zai-org/glm-5-3'] ELSE allowed_over_limit_models END
	 WHERE default_monthly_usd = 300 AND updated_by = ''`,
	// The entitlement endpoint now runs a month-scoped SUM per username on
	// every gateway request inside its 5s subrequest budget; the best
	// existing index was username-only with a timestamp recheck.
	`CREATE INDEX IF NOT EXISTS idx_usage_events_user_ts ON usage_events (username, timestamp)`,
	// Blocked requests live in usage_events themselves — one row per denial,
	// exactly like the 4xx rows the gateway's usage report carries (see
	// RecordQuotaDenial). The earlier aggregated quota_denials counter table
	// is retired: fresh installs never create it, existing databases drop it.
	`DROP TABLE IF EXISTS quota_denials`,
}

func (s *Store) migrateQuota(ctx context.Context) error {
	for _, stmt := range quotaMigrations {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("quota migration failed: %w", err)
		}
	}
	return nil
}

// --- Policy & overrides (admin surface) ---

type QuotaPolicy struct {
	DefaultMonthlyUSD float64 `json:"default_monthly_usd"`
	Enforced          bool    `json:"enforced"`
	// AllowedOverLimitModels: the post-cap allowance list (issue #22).
	// Exact, case-sensitive model identifiers; empty disables the feature.
	AllowedOverLimitModels []string  `json:"allowed_over_limit_models"`
	UpdatedBy              string    `json:"updated_by"`
	UpdatedAt              time.Time `json:"updated_at"`
}

type QuotaOverride struct {
	Scope      string    `json:"scope"` // "user" (person slug) | "group"
	Principal  string    `json:"principal"`
	MonthlyUSD float64   `json:"monthly_usd"`
	UpdatedBy  string    `json:"updated_by"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (s *Store) GetQuotaPolicy(ctx context.Context) (QuotaPolicy, error) {
	var p QuotaPolicy
	err := s.db.QueryRowContext(ctx,
		`SELECT default_monthly_usd, enforced, allowed_over_limit_models,
		        updated_by, updated_at FROM quota_policy WHERE id = true`,
	).Scan(&p.DefaultMonthlyUSD, &p.Enforced, pq.Array(&p.AllowedOverLimitModels),
		&p.UpdatedBy, &p.UpdatedAt)
	return p, err
}

// QuotaPolicyUpdate carries optional policy fields; nil means "leave
// untouched". Models replaces the whole list when non-nil (empty list =
// feature off).
type QuotaPolicyUpdate struct {
	DefaultMonthlyUSD *float64
	Enforced          *bool
	Models            *[]string
}

// UpdateQuotaPolicy applies every present field in ONE transaction with
// ONE audit record and ONE cache invalidation, so a partial failure can
// never leave policy, audit and cache inconsistent with each other
// (issue #22 review gate 3 — the earlier two-step write could half-apply
// a policy+allowance PATCH).
func (s *Store) UpdateQuotaPolicy(ctx context.Context, actor string, u QuotaPolicyUpdate) (QuotaPolicy, error) {
	if u.DefaultMonthlyUSD != nil && *u.DefaultMonthlyUSD <= 0 {
		return QuotaPolicy{}, fmt.Errorf("default_monthly_usd must be > 0")
	}
	var clean []string
	if u.Models != nil {
		// Exact identifiers only: the compared string is chosen by the
		// capped user, so entries must name the literal identifier that
		// will be routed and billed (issue #22 security contract). Trim,
		// dedupe keeping case, reject wildcards/spaces.
		seen := map[string]bool{}
		clean = make([]string, 0, len(*u.Models))
		for _, m := range *u.Models {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			if len(m) > 100 {
				return QuotaPolicy{}, fmt.Errorf("model identifier too long: %s", m)
			}
			if strings.ContainsAny(m, "*?[ ") {
				return QuotaPolicy{}, fmt.Errorf("exact identifiers only (no wildcards or spaces): %s", m)
			}
			if seen[m] {
				continue
			}
			seen[m] = true
			clean = append(clean, m)
		}
		if len(clean) > quotaAllowanceMax {
			return QuotaPolicy{}, fmt.Errorf("at most %d models on the allowance list", quotaAllowanceMax)
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return QuotaPolicy{}, err
	}
	defer func() { _ = tx.Rollback() }()

	setClauses := []string{"updated_by = $1", "updated_at = NOW()"}
	args := []any{actor}
	add := func(clause string, val any) {
		args = append(args, val)
		setClauses = append(setClauses, fmt.Sprintf(clause, len(args)))
	}
	if u.DefaultMonthlyUSD != nil {
		add("default_monthly_usd = $%d", *u.DefaultMonthlyUSD)
	}
	if u.Enforced != nil {
		add("enforced = $%d", *u.Enforced)
	}
	if u.Models != nil {
		add("allowed_over_limit_models = $%d", pq.Array(clean))
	}
	if _, err := tx.ExecContext(ctx,
		"UPDATE quota_policy SET "+strings.Join(setClauses, ", ")+" WHERE id = true", args...); err != nil {
		return QuotaPolicy{}, err
	}

	audit := map[string]any{}
	if u.DefaultMonthlyUSD != nil {
		audit["default_monthly_usd"] = *u.DefaultMonthlyUSD
	}
	if u.Enforced != nil {
		audit["enforced"] = *u.Enforced
	}
	if u.Models != nil {
		audit["allowed_over_limit_models"] = clean
	}
	if err := s.auditTx(ctx, tx, actor, "quota.policy_update", "policy", audit); err != nil {
		return QuotaPolicy{}, err
	}
	if err := tx.Commit(); err != nil {
		return QuotaPolicy{}, err
	}
	s.invalidateQuotaCache()
	return s.GetQuotaPolicy(ctx)
}

func (s *Store) ListQuotaOverrides(ctx context.Context) ([]QuotaOverride, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT scope, principal, monthly_usd, updated_by, updated_at FROM quota_overrides ORDER BY scope, principal`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QuotaOverride
	for rows.Next() {
		var o QuotaOverride
		if err := rows.Scan(&o.Scope, &o.Principal, &o.MonthlyUSD, &o.UpdatedBy, &o.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) UpsertQuotaOverride(ctx context.Context, actor, scope, principal string, monthlyUSD float64) error {
	if scope != "user" && scope != "group" {
		return fmt.Errorf("scope must be 'user' or 'group'")
	}
	principal = strings.TrimSpace(principal)
	if principal == "" {
		return fmt.Errorf("principal required")
	}
	if monthlyUSD <= 0 {
		return fmt.Errorf("monthly_usd must be > 0 (delete the override to fall back to the default)")
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO quota_overrides (scope, principal, monthly_usd, updated_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (scope, principal) DO UPDATE SET
			monthly_usd = EXCLUDED.monthly_usd,
			updated_by = EXCLUDED.updated_by,
			updated_at = NOW()`,
		scope, principal, monthlyUSD, actor); err != nil {
		return err
	}
	if err := s.Audit(ctx, actor, "quota.override_set", scope+":"+principal, map[string]any{"monthly_usd": monthlyUSD}); err != nil {
		return err
	}
	s.invalidateQuotaCache()
	return nil
}

func (s *Store) DeleteQuotaOverride(ctx context.Context, actor, scope, principal string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM quota_overrides WHERE scope = $1 AND principal = $2`, scope, principal); err != nil {
		return err
	}
	if err := s.Audit(ctx, actor, "quota.override_delete", scope+":"+principal, nil); err != nil {
		return err
	}
	s.invalidateQuotaCache()
	return nil
}

// quotaAllowanceMax caps the allowance list size; entries are model ids.
const quotaAllowanceMax = 50

// --- Decision core (the enforcement hot path) ---

// QuotaDecision is one person's month evaluated against the quota policy.
// SpentUSD is the same number the dashboard shows: all spend (hosted
// included), priced by the shared costUSDExpr, summed across every login
// linked to the person.
type QuotaDecision struct {
	Enforced bool `json:"enforced"` // the policy flag
	Exempt   bool `json:"exempt"`   // super-admin — never gated
	// User model allowlist is enforcement state internal to the entitlement
	// decision; the dedicated model-policy endpoint owns its public schema.
	ModelPolicyActive bool     `json:"-"`
	UserAllowedModels []string `json:"-"`
	BaseUSD           float64  `json:"base_usd"`  // user override or policy default
	LimitUSD          float64  `json:"limit_usd"` // effective monthly limit
	SpentUSD          float64  `json:"spent_usd"`
	// Post-cap allowance (issue #22): admin-listed exact model identifiers
	// that pass when the dollar gate denies.
	OverLimitModels []string  `json:"over_limit_models,omitempty"`
	Month           string    `json:"month"`
	MonthEnds       time.Time `json:"month_ends"`
}

// EffectiveEnforced reports whether gating actually applies to this caller.
func (d QuotaDecision) EffectiveEnforced() bool { return d.Enforced && !d.Exempt }

// Allowed is the hasAccess answer: dollars under limit (or gating off /
// exempt). An error is NOT Allowed's problem — callers fail-open on error
// like they already do for the whole endpoint.
func (d QuotaDecision) Allowed() bool {
	return !d.EffectiveEnforced() || d.SpentUSD < d.LimitUSD
}

// ModelAllowedOverLimit is the post-cap exception (issue #22), consulted
// only when Allowed() would deny. Matching is exact and case-sensitive:
// the compared string is chosen by the capped user, so every list entry
// must name the literal identifier that will be routed and billed, and a
// case mismatch denies (fail-closed). An empty or unresolvable model never
// matches. The legacy token gate is NOT bypassed here — callers AND it on top,
// so runaway loops stay guarded.
func (d QuotaDecision) ModelAllowedOverLimit(model string) bool {
	if !d.EffectiveEnforced() || model == "" || len(d.OverLimitModels) == 0 {
		return false
	}
	if d.SpentUSD < d.LimitUSD {
		return false // under limit: Allowed() already covers it
	}
	for _, m := range d.OverLimitModels {
		if m == model {
			return true
		}
	}
	return false
}

// quotaDecision computes the full decision in two queries: one for policy +
// the per-username override + month bounds, one for month-to-date spend across
// the partner user's logins. A username absent from the partner directory
// resolves to just itself and the policy default.
func (s *Store) quotaDecision(ctx context.Context, username string, exempt bool) (QuotaDecision, error) {
	d := QuotaDecision{Exempt: exempt}

	// Identity resolution is partner-user based: logins aggregate a person's
	// spend across their MaaS logins. Group- and grant-based resolution were
	// removed with the legacy org directory; only a per-username override and
	// the policy default remain until the quota model is rewritten.
	logins, err := s.PartnerLoginsForUsername(ctx, username)
	if err != nil {
		return d, err
	}

	var userOv, defaultUSD float64
	err = s.db.QueryRowContext(ctx, `
		SELECT pol.default_monthly_usd, pol.enforced,
			pol.allowed_over_limit_models,
			COALESCE(ou.monthly_usd, -1),
			to_char(date_trunc('month', NOW()), 'YYYY-MM'),
			date_trunc('month', NOW()) + interval '1 month'
		FROM (SELECT default_monthly_usd, enforced, allowed_over_limit_models
			FROM quota_policy WHERE id = true) pol
		LEFT JOIN quota_overrides ou ON ou.scope = 'user' AND ou.principal = $1`,
		username,
	).Scan(&defaultUSD, &d.Enforced, pq.Array(&d.OverLimitModels),
		&userOv, &d.Month, &d.MonthEnds)
	if err != nil {
		return d, fmt.Errorf("quota policy lookup: %w", err)
	}

	// Resolution order: user override → policy default.
	// -1 marks "no override row" (NUMERIC is never negative for a real row).
	if userOv >= 0 {
		d.BaseUSD = userOv
	} else {
		d.BaseUSD = defaultUSD
	}
	d.LimitUSD = d.BaseUSD

	err = s.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT COALESCE(SUM(%s), 0)
		FROM usage_events e
		LEFT JOIN model_pricing p ON e.model = p.model
		WHERE e.username = ANY($1) AND e.timestamp >= date_trunc('month', NOW())`, costUSDExpr),
		logins,
	).Scan(&d.SpentUSD)
	if err != nil {
		return d, fmt.Errorf("quota spend lookup: %w", err)
	}
	modelPolicy, err := s.GetUserModelAllowlist(ctx, username)
	if err != nil {
		return d, fmt.Errorf("model allowlist lookup: %w", err)
	}
	d.ModelPolicyActive = modelPolicy.Enabled
	d.UserAllowedModels = modelPolicy.Models
	return d, nil
}

// --- Decision cache (the gateway's synchronous dependency) ---

const quotaCacheTTL = 15 * time.Second

type quotaCacheEntry struct {
	decision QuotaDecision
	expires  time.Time
}

// QuotaDecisionCached is the entitlement hot path: every gateway request
// asks this before forwarding. 15s of staleness costs at most a few requests
// of overshoot on a $300 budget — the alternative is a per-request directory
// walk + usage scan on the critical latency path of every inference call.
// Any quota mutation invalidates the whole cache (it holds at most a few
// hundred entries; a map clear is cheaper than per-person bookkeeping).
func (s *Store) QuotaDecisionCached(ctx context.Context, username string, exempt bool) (QuotaDecision, error) {
	key := username
	if exempt {
		key += "|x"
	}
	s.quotaMu.Lock()
	e, ok := s.quotaCache[key]
	s.quotaMu.Unlock()
	if ok && time.Now().Before(e.expires) {
		return e.decision, nil
	}
	d, err := s.quotaDecision(ctx, username, exempt)
	if err != nil {
		return d, err
	}
	s.quotaMu.Lock()
	if s.quotaCache == nil {
		s.quotaCache = map[string]quotaCacheEntry{}
	}
	s.quotaCache[key] = quotaCacheEntry{decision: d, expires: time.Now().Add(quotaCacheTTL)}
	s.quotaMu.Unlock()
	return d, nil
}

func (s *Store) invalidateQuotaCache() {
	s.quotaMu.Lock()
	s.quotaCache = nil
	s.quotaMu.Unlock()
}

// --- Denial counters (who has been 429'd, and how often) ---

// RecordQuotaDenial writes one blocked request into usage_events — the
// same ledger the gateway's usage report lands in, so a 429 reads like any
// other error row (404s included): exact timestamp, zero tokens, zero cost,
// every retry its own line. provider='gateway' marks it as OUR refusal
// (an upstream 429 arrives via the normal event report with a real
// provider). Callers must never block on it: it runs off the request path
// (the answer has already been written to the gateway), and its failure
// costs only a missing data point, never a wrong entitlement.
func (s *Store) RecordQuotaDenial(ctx context.Context, username, model string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Group attribution was removed with the legacy org directory; denial
	// rows carry a NULL group_name. The row's hour comes back from the
	// insert so the rollup lands in the same bucket.
	var ts time.Time
	var group sql.NullString
	err = tx.QueryRowContext(ctx, `
		INSERT INTO usage_events (event_id, username, model, provider, group_name, status_code, source, cost_usd)
		VALUES ('deny-' || gen_random_uuid()::text, $1, $2, 'gateway',
			NULL, 429, 'metering-quota', 0)
		RETURNING timestamp, group_name`,
		username, model).Scan(&ts, &group)
	if err != nil {
		return err
	}
	// Denials ride the rollup as requests+1 at zero usage/cost — the plan
	// rev2 parity definition counts them; whether dashboards show them is
	// a display filter, not a rollup question.
	if s.liveRollups.Load() {
		if err := upsertRollup(ctx, tx, ts, username, group.String, model, "gateway",
			1, 0, 0, 0, 0, 0, "0"); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// sumQuotaDenials counts this month's gateway refusals across a partner
// user's logins (denials are keyed by the ledger username the gateway used,
// which is only one of several logins a partner user may hold). Covered by
// idx_usage_events_user_ts like the spend query itself.
func (s *Store) sumQuotaDenials(ctx context.Context, logins []string) int {
	var n int
	_ = s.db.QueryRowContext(ctx, `
		SELECT count(*) FROM usage_events
		WHERE username = ANY($1) AND provider = 'gateway' AND status_code = 429
		  AND timestamp >= date_trunc('month', NOW())`,
		logins).Scan(&n)
	return n
}

// QuotaDenialStat is one username's blocked-request tally for the admin view.
type QuotaDenialStat struct {
	Username string    `json:"username"`
	Count    int       `json:"count"`
	LastAt   time.Time `json:"last_at"`
}

// QuotaDenialTotals: this month's blocked-request total plus the per-user
// breakdown (newest activity per user, most-blocked first), read straight
// from the usage ledger (gateway refusals carry provider='gateway').
func (s *Store) QuotaDenialTotals(ctx context.Context) (int, []QuotaDenialStat, error) {
	var total int
	if err := s.db.QueryRowContext(ctx, `
		SELECT count(*) FROM usage_events
		WHERE provider = 'gateway' AND status_code = 429
		  AND timestamp >= date_trunc('month', NOW())`).Scan(&total); err != nil {
		return 0, nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT username, count(*), MAX(timestamp) FROM usage_events
		WHERE provider = 'gateway' AND status_code = 429
		  AND timestamp >= date_trunc('month', NOW())
		GROUP BY username ORDER BY count(*) DESC LIMIT 50`)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	var out []QuotaDenialStat
	for rows.Next() {
		var st QuotaDenialStat
		if err := rows.Scan(&st.Username, &st.Count, &st.LastAt); err != nil {
			return 0, nil, err
		}
		out = append(out, st)
	}
	return total, out, rows.Err()
}

// --- Status view (whoami / me carrier) ---

// QuotaView is the quota picture for one login: what the dashboard popup and
// banner render. Quota request/approval was removed in phase one; only the
// decision and this month's denial count remain.
type QuotaView struct {
	Username string `json:"username"`
	QuotaDecision
	// DenialsThisMonth: how many of this person's gateway requests were
	// blocked this calendar month (across all their partner logins).
	DenialsThisMonth int `json:"denials_this_month"`
}

// GetQuotaView assembles the decision plus this month's denial count. Fresh
// (uncached) — this backs interactive pages, not the gateway hot path.
func (s *Store) GetQuotaView(ctx context.Context, username string, exempt bool) (QuotaView, error) {
	d, err := s.quotaDecision(ctx, username, exempt)
	if err != nil {
		return QuotaView{}, err
	}
	v := QuotaView{Username: username, QuotaDecision: d}
	logins, err := s.PartnerLoginsForUsername(ctx, username)
	if err != nil || len(logins) == 0 {
		logins = []string{username}
	}
	v.DenialsThisMonth = s.sumQuotaDenials(ctx, logins)
	return v, nil
}
