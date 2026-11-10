package storage

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/lib/pq"
)

// OverLimitUser is one person at or above their effective monthly budget.
// The fields mirror the entitlement composition: additive role budgets (or a
// permanent per-person override) plus active temporary credits.
type OverLimitUser struct {
	UserID         string   `json:"user_id"`
	SubjectID      string   `json:"subject_id,omitempty"`
	DisplayName    string   `json:"display_name"`
	Email          string   `json:"email"`
	Username       string   `json:"username"`
	CostCenter     string   `json:"cost_center,omitempty"`
	Roles          []string `json:"roles"`
	BudgetSource   string   `json:"budget_source"`
	LimitUSD       float64  `json:"limit_usd"`
	SpentUSD       float64  `json:"spent_usd"`
	OverByUSD      float64  `json:"over_by_usd"`
	UsedPct        float64  `json:"used_pct"`
	LastActivityAt *string  `json:"last_activity_at,omitempty"`
}

// OverLimitPage is the admin read-only budget overage listing.
type OverLimitPage struct {
	Users       []OverLimitUser `json:"users"`
	Total       int             `json:"total"`
	Enforced    bool            `json:"enforced"`
	GeneratedAt time.Time       `json:"generated_at"`
}

// ListUsersOverLimit lists active people whose current-month spend is at or
// above their effective budget. It uses the same composition as quotaDecision
// (override replaces the role sum; credits add on top; no role budget falls
// back to the global default) and the same spend source, so the page cannot
// disagree with what the gateway enforces.
func (s *Store) ListUsersOverLimit(ctx context.Context, tenantID, query string, limit, offset int) (OverLimitPage, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	query = strings.TrimSpace(query)
	cte := s.overLimitCTE()

	rows, err := s.db.QueryContext(ctx, cte+`
		SELECT user_id::text, full_name, email, cost_center, username, roles,
		       subject_id, budget_source, limit_usd, spent_usd, last_at
		FROM base
		WHERE spent_usd >= limit_usd
		  AND ($2 = '' OR full_name ILIKE '%' || $2 || '%'
		       OR email ILIKE '%' || $2 || '%'
		       OR username ILIKE '%' || $2 || '%'
		       OR cost_center ILIKE '%' || $2 || '%')
		ORDER BY (spent_usd - limit_usd) DESC, email
		LIMIT $3 OFFSET $4`, tenantID, query, limit, offset)
	if err != nil {
		return OverLimitPage{}, fmt.Errorf("over-limit listing: %w", err)
	}
	defer rows.Close()

	users := []OverLimitUser{}
	for rows.Next() {
		var u OverLimitUser
		var roles []string
		var lastAt sql.NullTime
		if err := rows.Scan(&u.UserID, &u.DisplayName, &u.Email, &u.CostCenter,
			&u.Username, pq.Array(&roles), &u.SubjectID, &u.BudgetSource,
			&u.LimitUSD, &u.SpentUSD, &lastAt); err != nil {
			return OverLimitPage{}, err
		}
		u.Roles = roles
		if u.Roles == nil {
			u.Roles = []string{}
		}
		u.OverByUSD = roundUSD(u.SpentUSD - u.LimitUSD)
		if u.LimitUSD > 0 {
			u.UsedPct = math.Round(u.SpentUSD / u.LimitUSD * 100)
		}
		if lastAt.Valid {
			formatted := lastAt.Time.UTC().Format(time.RFC3339)
			u.LastActivityAt = &formatted
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return OverLimitPage{}, err
	}

	var total int
	if err := s.db.QueryRowContext(ctx, cte+`
		SELECT COUNT(*)
		FROM base
		WHERE spent_usd >= limit_usd
		  AND ($2 = '' OR full_name ILIKE '%' || $2 || '%'
		       OR email ILIKE '%' || $2 || '%'
		       OR username ILIKE '%' || $2 || '%'
		       OR cost_center ILIKE '%' || $2 || '%')`,
		tenantID, query).Scan(&total); err != nil {
		return OverLimitPage{}, fmt.Errorf("over-limit count: %w", err)
	}

	var enforced bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE((SELECT enforced FROM quota_policy WHERE id = true), false)`).Scan(&enforced); err != nil {
		return OverLimitPage{}, fmt.Errorf("quota policy lookup: %w", err)
	}

	return OverLimitPage{
		Users:       users,
		Total:       total,
		Enforced:    enforced,
		GeneratedAt: time.Now().UTC(),
	}, nil
}

// overLimitCTE builds the shared per-person budget/spend CTE. The spend
// source matches quotaDecision's source for this process.
func (s *Store) overLimitCTE() string {
	return fmt.Sprintf(`
		WITH pol AS (
			SELECT COALESCE((SELECT default_monthly_usd FROM quota_policy WHERE id = true), 0) AS default_usd
		),
		people AS (
			SELECT pu.user_id,
			       COALESCE(%s, '') AS full_name,
			       COALESCE(pu.tags->>'email', '') AS email,
			       COALESCE(pu.tags->>'cost_center', '') AS cost_center,
			       COALESCE(cl.username, '') AS username
			FROM partner_users pu
			LEFT JOIN LATERAL (
				SELECT l.username
				FROM partner_user_logins l
				WHERE l.user_id = pu.user_id
				ORDER BY l.is_current DESC, l.username
				LIMIT 1
			) cl ON true
			WHERE pu.active
		),
		subjects AS (
			SELECT ps.external_id::uuid AS user_id, ps.subject_id
			FROM policy_subjects ps
			WHERE ps.tenant_id = $1 AND ps.principal_type = 'partner_user'
		),
		role_rows AS (
			SELECT sb.subject_id, r.name, r.monthly_usd
			FROM subjects sb
			JOIN model_access_roles r
			  ON r.tenant_id = $1 AND r.is_default AND r.retired_at IS NULL
			WHERE NOT EXISTS (
				SELECT 1 FROM model_access_default_exclusions e
				WHERE e.tenant_id = $1 AND e.subject_id = sb.subject_id
				  AND (e.expires_at IS NULL OR e.expires_at > NOW())
			)
			  AND NOT EXISTS (
				SELECT 1 FROM model_access_role_assignments a
				WHERE a.tenant_id = $1 AND a.role_id = r.role_id AND a.subject_id = sb.subject_id
			)
			UNION ALL
			SELECT a.subject_id, r.name, r.monthly_usd
			FROM model_access_role_assignments a
			JOIN model_access_roles r
			  ON r.role_id = a.role_id AND r.tenant_id = a.tenant_id
			WHERE a.tenant_id = $1 AND r.retired_at IS NULL
		),
		role_budget AS (
			SELECT subject_id, SUM(monthly_usd) AS usd,
			       array_agg(name ORDER BY name) AS roles
			FROM role_rows
			GROUP BY subject_id
		),
		credits AS (
			SELECT subject_id, SUM(amount_usd) AS usd
			FROM quota_credits
			WHERE tenant_id = $1 AND (expires_at IS NULL OR expires_at > NOW())
			GROUP BY subject_id
		),
		%s,
		base AS (
			SELECT p.user_id, p.full_name, p.email, p.cost_center, p.username,
			       COALESCE(rb.roles, ARRAY[]::text[]) AS roles,
			       COALESCE(sb.subject_id::text, '') AS subject_id,
			       CASE
			         WHEN ov.monthly_usd IS NOT NULL THEN 'user_override'
			         WHEN COALESCE(rb.usd, 0) > 0 THEN 'role'
			         ELSE 'default'
			       END AS budget_source,
			       (CASE
			          WHEN ov.monthly_usd IS NOT NULL THEN ov.monthly_usd
			          WHEN COALESCE(rb.usd, 0) > 0 THEN rb.usd
			          ELSE pol.default_usd
			        END) + COALESCE(cr.usd, 0) AS limit_usd,
			       COALESCE(sp.usd, 0) AS spent_usd,
			       sp.last_at
			FROM people p
			LEFT JOIN subjects sb ON sb.user_id = p.user_id
			LEFT JOIN role_budget rb ON rb.subject_id = sb.subject_id
			LEFT JOIN credits cr ON cr.subject_id = sb.subject_id
			LEFT JOIN quota_overrides ov
			  ON ov.scope = 'user' AND ov.principal = p.username
			CROSS JOIN pol
			LEFT JOIN spend sp ON sp.user_id = p.user_id
		)`,
		partnerFullNameExpr, s.overLimitSpendCTE())
}

func (s *Store) overLimitSpendCTE() string {
	switch {
	case s.monthSpendEnabled.Load():
		return `spend AS (
			SELECT l.user_id, SUM(ums.spent_usd) AS usd, MAX(ums.updated_at) AS last_at
			FROM partner_user_logins l
			JOIN user_month_spend ums ON ums.username = l.username
			  AND ums.month = date_trunc('month', NOW())::date
			GROUP BY l.user_id
		)`
	case s.rollupsLive():
		return `spend AS (
			SELECT l.user_id, SUM(h.cost_usd) AS usd, MAX(h.hour) AS last_at
			FROM partner_user_logins l
			JOIN usage_hourly h ON h.username = l.username
			WHERE h.hour >= date_trunc('month', NOW())
			GROUP BY l.user_id
		)`
	default:
		return fmt.Sprintf(`spend AS (
			SELECT l.user_id, SUM(%s) AS usd, MAX(e.timestamp) AS last_at
			FROM partner_user_logins l
			JOIN usage_events e ON e.username = l.username
			LEFT JOIN model_pricing p ON e.model = p.model
			WHERE e.timestamp >= date_trunc('month', NOW())
			GROUP BY l.user_id
		)`, costUSDExpr)
	}
}

func roundUSD(v float64) float64 {
	return math.Round(v*100) / 100
}
