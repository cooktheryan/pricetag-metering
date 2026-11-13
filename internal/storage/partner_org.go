package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Partner-backed manager views. The org hierarchy is derived dynamically from
// partner_users.manager_user_id; a user's "slug" on these surfaces is their
// partner user_id (UUID). Spend aggregates across every login a partner user
// holds in partner_user_logins. Budget gauges use calendar-month spending
// independently of the selected chart window.

// partnerFullNameExpr resolves "First Last" from the partner tags, aliasing the
// partner_users row as `pu`. Empty when neither name is set.
const partnerFullNameExpr = `NULLIF(TRIM(COALESCE(pu.tags->>'first_name','') || ' ' || COALESCE(pu.tags->>'last_name','')), '')`

// OrgUsageRow is one partner user's rolled-up usage for the manager table.
type OrgUsageRow struct {
	Slug        string  `json:"slug"` // partner user_id
	FullName    string  `json:"full_name"`
	Username    string  `json:"username,omitempty"`
	ManagerSlug string  `json:"manager_slug,omitempty"`
	IsManager   bool    `json:"is_manager"`
	Requests    int     `json:"requests"`
	TotalTokens int64   `json:"total_tokens"`
	CostUSD     float64 `json:"cost_usd"`
	LastUsed    *string `json:"last_used,omitempty"`
	NoIdentity  bool    `json:"no_identity,omitempty"`

	// Read-only monthly budget summary; managers cannot change policy here.
	QuotaExempt   bool    `json:"quota_exempt"`
	QuotaEnforced bool    `json:"quota_enforced"`
	QuotaUSD      float64 `json:"quota_usd"`
	QuotaSpentUSD float64 `json:"quota_spent_usd"`
	OverLimit     bool    `json:"over_limit"`
}

// ceilToHour moves a non-hour-aligned timestamp forward to the next hour.
// Hourly rollups cannot represent a partial boundary bucket: using
// `hour >= since` would include up to 59 minutes of pre-window data. The
// rollup path starts at the next complete hour; the raw path keeps the exact
// requested window.
func ceilToHour(t time.Time) time.Time {
	truncated := t.Truncate(time.Hour)
	if truncated.Equal(t) {
		return t
	}
	return truncated.Add(time.Hour)
}

// GetPartnerOrgUsage rolls usage up per partner user for the subtree under
// rootUserID over a window. An empty rootUserID means the whole organisation
// (every active partner user). It reuses costUSDExpr — one cost model shared
// with every other dashboard number — and never writes.
//
// When live rollups are available it aggregates usage_hourly instead of the
// raw ledger. That matters for the manager page: an all-organisation November
// window is ~1.3M raw rows and takes seconds on the shared primary, while the
// same window is ~25K hourly rows and answers in tens of milliseconds. The
// hourly path reports LastUsed at hour granularity (the rollup's finest
// resolution) and starts at the next full hour so it never counts the whole
// boundary hour before `since`; the raw path is kept only for the
// parity-fallback case.
func (s *Store) GetPartnerOrgUsage(ctx context.Context, rootUserID string, since, until time.Time) ([]OrgUsageRow, error) {
	from := `partner_user_logins l ON l.user_id = st.user_id
			JOIN usage_events e ON e.username = l.username
			LEFT JOIN model_pricing p ON e.model = p.model`
	window := `e.timestamp >= $2 AND e.timestamp < $3`
	requests := `COUNT(*)`
	cost := fmt.Sprintf(`COALESCE(ROUND(SUM(%s)::numeric,2),0)`, costUSDExpr)
	lastUsed := `MAX(e.timestamp)`
	if s.rollupsLive() {
		since = ceilToHour(since)
		from = `partner_user_logins l ON l.user_id = st.user_id
			JOIN usage_hourly e ON e.username = l.username`
		window = `e.hour >= $2 AND e.hour < $3`
		requests = `COALESCE(SUM(e.requests),0)`
		cost = `COALESCE(ROUND(SUM(e.cost_usd)::numeric,2),0)`
		lastUsed = `MAX(e.hour)`
	}
	monthly := fmt.Sprintf(`SELECT l.user_id, COALESCE(SUM(%s),0) AS spent
        FROM (SELECT DISTINCT user_id FROM subtree) st
        JOIN partner_user_logins l ON l.user_id=st.user_id
        JOIN usage_events e ON e.username=l.username
        LEFT JOIN model_pricing p ON p.model=e.model
        WHERE e.timestamp>=date_trunc('month',NOW()) GROUP BY l.user_id`, costUSDExpr)
	if s.monthSpendEnabled.Load() {
		monthly = `SELECT l.user_id, COALESCE(SUM(m.spent_usd),0) AS spent
        FROM (SELECT DISTINCT user_id FROM subtree) st JOIN partner_user_logins l ON l.user_id=st.user_id
        JOIN user_month_spend m ON m.username=l.username
        WHERE m.month=date_trunc('month',NOW())::date GROUP BY l.user_id`
	}
	query := fmt.Sprintf(`
		WITH RECURSIVE subtree(user_id, depth, path) AS (
			SELECT p.user_id, 0, ARRAY[p.user_id]
			FROM partner_users p
			WHERE p.active AND ($1 = '' OR p.user_id = $1::uuid)
			UNION ALL
			SELECT p.user_id, st.depth + 1, st.path || p.user_id
			FROM partner_users p JOIN subtree st ON p.manager_user_id = st.user_id
			WHERE $1 <> '' AND p.active AND st.depth < 1000 AND NOT p.user_id = ANY(st.path)
		),
		u AS (
			SELECT l.user_id,
				%s AS requests,
				COALESCE(SUM(e.total_tokens),0) AS total_tokens,
				%s AS cost_usd,
				%s AS last_used
			FROM (SELECT DISTINCT user_id FROM subtree) st
			JOIN %s
			WHERE %s
			GROUP BY l.user_id
		),
		managers AS (
			SELECT DISTINCT manager_user_id AS user_id
			FROM partner_users
			WHERE active AND manager_user_id IS NOT NULL
		), monthly AS (%s)
		SELECT DISTINCT st.user_id::text,
			COALESCE(%s, cl.username, '') AS full_name,
			COALESCE(cl.username,''),
			COALESCE(pu.manager_user_id::text,''),
			(m.user_id IS NOT NULL),
			COALESCE(u.requests,0), COALESCE(u.total_tokens,0), COALESCE(u.cost_usd,0),
			to_char(u.last_used, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
COALESCE(ov.monthly_usd,pol.default_monthly_usd,0), COALESCE(monthly.spent,0), COALESCE(pol.enforced,false), pu.role='super_admin'
		FROM (SELECT DISTINCT user_id FROM subtree) st
		JOIN partner_users pu ON pu.user_id = st.user_id
		LEFT JOIN managers m ON m.user_id = st.user_id
		LEFT JOIN LATERAL (
			SELECT username FROM partner_user_logins WHERE user_id = st.user_id
			ORDER BY is_current DESC, username LIMIT 1
		) cl ON true
		LEFT JOIN u ON u.user_id = st.user_id
		LEFT JOIN monthly ON monthly.user_id=st.user_id
		-- A missing quota_policy singleton must not empty the whole view;
		-- default to no override, no default allowance, not enforced. Read the
		-- singleton through a one-row subquery so corrupt multi-row data can
		-- not duplicate every user either.
		LEFT JOIN (SELECT default_monthly_usd, enforced FROM quota_policy ORDER BY id LIMIT 1) pol ON true
		LEFT JOIN quota_overrides ov ON ov.scope='user' AND ov.principal=cl.username
		ORDER BY 8 DESC, 2`, requests, cost, lastUsed, from, window, monthly, partnerFullNameExpr)
	rows, err := s.db.QueryContext(ctx, query, rootUserID, since, until)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OrgUsageRow
	for rows.Next() {
		var r OrgUsageRow
		var lastUsed sql.NullString
		if err := rows.Scan(&r.Slug, &r.FullName, &r.Username, &r.ManagerSlug,
			&r.IsManager, &r.Requests, &r.TotalTokens, &r.CostUSD, &lastUsed, &r.QuotaUSD, &r.QuotaSpentUSD, &r.QuotaEnforced, &r.QuotaExempt); err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			r.LastUsed = &lastUsed.String
		}
		r.NoIdentity = r.Username == ""
		r.OverLimit = r.QuotaEnforced && !r.QuotaExempt && r.QuotaSpentUSD >= r.QuotaUSD
		out = append(out, r)
	}
	return out, rows.Err()
}

// PartnerSubtreeUsernames returns every login under rootUserID (inclusive),
// used to scope the manager charts to a subtree. An empty rootUserID returns
// nil, which the caller reads as "the whole organisation".
func (s *Store) PartnerSubtreeUsernames(ctx context.Context, rootUserID string) ([]string, error) {
	if rootUserID == "" {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		WITH RECURSIVE subtree(user_id, depth, path) AS (
			SELECT $1::uuid, 0, ARRAY[$1::uuid]
			UNION ALL
			SELECT p.user_id, st.depth + 1, st.path || p.user_id
			FROM partner_users p JOIN subtree st ON p.manager_user_id = st.user_id
			WHERE p.active AND st.depth < 1000 AND NOT p.user_id = ANY(st.path)
		)
		SELECT DISTINCT l.username
		FROM subtree st JOIN partner_user_logins l ON l.user_id = st.user_id
		ORDER BY l.username`, rootUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// PartnerInSubtree reports whether targetUserID is rootUserID itself or sits
// under it in the manager hierarchy — the drill-down permission check.
func (s *Store) PartnerInSubtree(ctx context.Context, rootUserID, targetUserID string) (bool, error) {
	var found bool
	err := s.db.QueryRowContext(ctx, `
		WITH RECURSIVE subtree(user_id, depth, path) AS (
			SELECT $1::uuid, 0, ARRAY[$1::uuid]
			UNION ALL
			SELECT p.user_id, st.depth + 1, st.path || p.user_id
			FROM partner_users p JOIN subtree st ON p.manager_user_id = st.user_id
			WHERE p.active AND st.depth < 1000 AND NOT p.user_id = ANY(st.path)
		)
		SELECT EXISTS (SELECT 1 FROM subtree WHERE user_id = $2::uuid)`,
		rootUserID, targetUserID).Scan(&found)
	return found, err
}

// PartnerPersonDetail returns a partner user's display name and all their
// logins, for the manager page's per-person drill-down.
func (s *Store) PartnerPersonDetail(ctx context.Context, userID string) (fullName string, usernames []string, err error) {
	var name sql.NullString
	err = s.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT %s FROM partner_users pu WHERE pu.user_id = $1::uuid`, partnerFullNameExpr),
		userID).Scan(&name)
	if err != nil {
		return "", nil, err
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT username FROM partner_user_logins WHERE user_id = $1::uuid ORDER BY is_current DESC, username`, userID)
	if err != nil {
		return "", nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return "", nil, err
		}
		usernames = append(usernames, u)
	}
	if err := rows.Err(); err != nil {
		return "", nil, err
	}
	full := name.String
	if full == "" && len(usernames) > 0 {
		full = usernames[0]
	}
	return full, usernames, nil
}

// OrgPersonModelRow is one model's usage for a single person — the same
// granularity the Usage view shows, narrowed to one member so a manager can
// open a person and see where their spend went.
type OrgPersonModelRow struct {
	Model            string  `json:"model"`
	Provider         string  `json:"provider"`
	Hosted           bool    `json:"hosted"`
	Requests         int     `json:"requests"`
	PromptTokens     int64   `json:"prompt_tokens"`
	CompletionTokens int64   `json:"completion_tokens"`
	CachedTokens     int64   `json:"cached_tokens"`
	TotalTokens      int64   `json:"total_tokens"`
	CostUSD          float64 `json:"cost_usd"`
	SavedUSD         float64 `json:"saved_usd"`
	LastUsed         *string `json:"last_used,omitempty"`
}

// GetPersonModelUsage breaks a set of logins' window down by model, reusing
// costUSDExpr and the dashboard's saved_usd arithmetic: for each hosted model,
// what its traffic would have cost on the reference model's rates minus what it
// was actually billed, floored at zero. The reference-model cache ratio is
// observed over the given logins, so a manager's drill-down reflects their
// team's traffic. The estimate-vs-literal cache decision is the same
// per-MODEL verdict the dashboard uses, so the drill-down and the main table
// never disagree about whether a model reports cache telemetry.
func (s *Store) GetPersonModelUsage(ctx context.Context, usernames []string, since, until time.Time, refModel string) ([]OrgPersonModelRow, error) {
	if len(usernames) == 0 {
		return nil, nil
	}
	if refModel == "" {
		refModel = "claude-opus-4-8"
	}
	userList := strings.Join(usernames, ",")
	from := `usage_events e LEFT JOIN model_pricing p ON e.model = p.model`
	when := `e.timestamp >= $1 AND e.timestamp < $2`
	cost := costUSDExpr
	positive := fmt.Sprintf(`(%s) > 0`, cost)
	mcFrom := `usage_events e`
	requests := `COUNT(*)`
	lastUsed := `MAX(e.timestamp)`
	if s.rollupsLive() {
		since = ceilToHour(since)
		from = `usage_hourly e LEFT JOIN model_pricing p ON e.model = p.model`
		when = `e.hour >= $1 AND e.hour < $2`
		cost = `e.cost_usd`
		positive = `(e.cost_usd) > 0`
		mcFrom = `usage_hourly e`
		requests = `COALESCE(SUM(e.requests),0)`
		lastUsed = `MAX(e.hour)`
	}
	query := fmt.Sprintf(`
		WITH r_ref AS (
			SELECT COALESCE(SUM(e.cached_input_tokens)::float / NULLIF(SUM(e.prompt_tokens), 0), 0) as r
			FROM %s
			WHERE %s AND e.model = $4
			  AND e.username = ANY(string_to_array($3, ',')) AND %s
			  AND NOT (`+hostedProviderCond+`)
		),
		r_all AS (
			SELECT COALESCE(SUM(e.cached_input_tokens)::float / NULLIF(SUM(e.prompt_tokens), 0), 0) as r
			FROM %s
			WHERE %s
			  AND e.username = ANY(string_to_array($3, ',')) AND %s
			  AND NOT (`+hostedProviderCond+`)
		),
		rat AS (
			SELECT CASE WHEN (SELECT r FROM r_ref) > 0 THEN (SELECT r FROM r_ref)
			            WHEN (SELECT r FROM r_all) > 0 THEN (SELECT r FROM r_all)
			            ELSE 0 END as r
		),
		pr AS (
			SELECT COALESCE(MAX(input_cost_per_mtok), 0) as i, COALESCE(MAX(output_cost_per_mtok), 0) as o,
			       COALESCE(MAX(cache_read_cost_per_mtok), 0) as cr, COALESCE(MAX(cache_write_cost_per_mtok), 0) as cw
			FROM model_pricing WHERE model = $4
		),
		model_cache AS (
			SELECT e.model,
			       (SUM(COALESCE(e.cached_input_tokens, 0) + COALESCE(e.cache_creation_tokens, 0))::float
			         / NULLIF(SUM(e.prompt_tokens), 0)) > 0.01 AS has_cache
			FROM %s
			WHERE %s
			GROUP BY e.model
		),
		fm AS (
			SELECT e.model,
				MAX(COALESCE(e.provider, '')) as provider,
				%s as reqs,
				SUM(e.prompt_tokens) as prompt, SUM(e.completion_tokens) as completion,
				SUM(COALESCE(e.cached_input_tokens, 0)) as cached, SUM(COALESCE(e.cache_creation_tokens, 0)) as cwrite,
				SUM(e.total_tokens) as tot, SUM(%s) as cost,
				bool_or(`+hostedProviderCond+`) as hosted,
				BOOL_OR(COALESCE(mc.has_cache, false)) as model_has_cache,
				%s as last_used
			FROM %s
			LEFT JOIN model_cache mc ON mc.model = e.model
			WHERE %s AND e.username = ANY(string_to_array($3, ','))
			GROUP BY e.model
		)
		SELECT fm.model, fm.provider, fm.hosted, fm.reqs,
			fm.prompt, fm.completion, fm.cached, fm.tot,
			COALESCE(ROUND(fm.cost::numeric, 2), 0),
			CASE WHEN (fm.hosted OR fm.cost = 0) AND fm.tot > 0 THEN COALESCE(ROUND(GREATEST(
				(GREATEST(fm.prompt
					- CASE WHEN NOT fm.model_has_cache AND fm.prompt > 0 AND rat.r > 0
					       THEN LEAST(ROUND(fm.prompt * rat.r), fm.prompt)
					       ELSE fm.cached END
					- fm.cwrite, 0) * pr.i
				+ CASE WHEN NOT fm.model_has_cache AND fm.prompt > 0 AND rat.r > 0
				       THEN LEAST(ROUND(fm.prompt * rat.r), fm.prompt)
				       ELSE fm.cached END * pr.cr
				+ fm.cwrite * pr.cw
				+ fm.completion * pr.o) / 1000000.0 - fm.cost, 0)::numeric, 2), 0)
				ELSE 0 END,
			to_char(fm.last_used, 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		FROM fm CROSS JOIN pr CROSS JOIN rat
		ORDER BY fm.cost DESC, fm.tot DESC`, from, when, positive, from, when, positive, mcFrom, when, requests, cost, lastUsed, from, when)

	rows, err := s.reader().QueryContext(ctx, query, since, until, userList, refModel)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OrgPersonModelRow
	for rows.Next() {
		var r OrgPersonModelRow
		var lastUsed sql.NullString
		if err := rows.Scan(&r.Model, &r.Provider, &r.Hosted, &r.Requests,
			&r.PromptTokens, &r.CompletionTokens, &r.CachedTokens, &r.TotalTokens,
			&r.CostUSD, &r.SavedUSD, &lastUsed); err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			r.LastUsed = &lastUsed.String
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
