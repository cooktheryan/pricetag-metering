package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// UsageTotals is a calendar-month aggregate. PromptTokens includes cached and
// cache-creation tokens, matching the provider event contract; the two cache
// fields are also broken out so consumers can report their composition.
type UsageTotals struct {
	Requests            int64   `json:"requests"`
	PromptTokens        int64   `json:"promptTokens"`
	CompletionTokens    int64   `json:"completionTokens"`
	TotalTokens         int64   `json:"totalTokens"`
	CachedInputTokens   int64   `json:"cachedInputTokens"`
	CacheCreationTokens int64   `json:"cacheCreationTokens"`
	ReasoningTokens     int64   `json:"reasoningTokens"`
	EstimatedCostUSD    float64 `json:"estimatedCostUsd"`
}

// ModelUsageReport is one provider/model row in a user's usage report.
type ModelUsageReport struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	UsageTotals
}

// UserUsageReport is a read-only report for the current calendar month.
type UserUsageReport struct {
	Username string             `json:"username"`
	Month    string             `json:"month"`
	AsOf     time.Time          `json:"asOf"`
	Totals   UsageTotals        `json:"totals"`
	Models   []ModelUsageReport `json:"models"`
}

// GetUserUsageReport returns a read-only month-to-date usage report. It does
// not invoke entitlement logic or record quota denials. If PriceTag has linked
// multiple MaaS logins to one person, those logins are aggregated together,
// matching the dollar-quota spend calculation.
func (s *Store) GetUserUsageReport(ctx context.Context, username string) (UserUsageReport, error) {
	logins := []string{username}
	person, err := s.GetPersonByUsername(ctx, username)
	switch {
	case err == nil:
		linked, linkedErr := s.PersonUsernames(ctx, person.Slug)
		if linkedErr != nil {
			return UserUsageReport{}, fmt.Errorf("resolve linked usernames: %w", linkedErr)
		}
		if len(linked) > 0 {
			logins = linked
		}
	case err != sql.ErrNoRows:
		return UserUsageReport{}, fmt.Errorf("resolve usage identity: %w", err)
	}

	report := UserUsageReport{
		Username: username,
		Models:   []ModelUsageReport{},
	}
	if err := s.db.QueryRowContext(ctx, `
		SELECT to_char(date_trunc('month', NOW()), 'YYYY-MM'), NOW()
	`).Scan(&report.Month, &report.AsOf); err != nil {
		return UserUsageReport{}, fmt.Errorf("read report period: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT COALESCE(e.provider, ''), COALESCE(e.model, ''),
			COUNT(*)::bigint,
			COALESCE(SUM(e.prompt_tokens), 0)::bigint,
			COALESCE(SUM(e.completion_tokens), 0)::bigint,
			COALESCE(SUM(e.total_tokens), 0)::bigint,
			COALESCE(SUM(e.cached_input_tokens), 0)::bigint,
			COALESCE(SUM(e.cache_creation_tokens), 0)::bigint,
			COALESCE(SUM(e.reasoning_tokens), 0)::bigint,
			COALESCE(SUM(%s), 0)
		FROM usage_events e
		LEFT JOIN model_pricing p ON e.model = p.model
		WHERE e.username = ANY($1)
			AND e.timestamp >= date_trunc('month', NOW())
		GROUP BY COALESCE(e.provider, ''), COALESCE(e.model, '')
		ORDER BY COALESCE(e.provider, ''), COALESCE(e.model, '')`, costUSDExpr), logins)
	if err != nil {
		return UserUsageReport{}, fmt.Errorf("query user usage report: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var model ModelUsageReport
		if err := rows.Scan(
			&model.Provider, &model.Model,
			&model.Requests, &model.PromptTokens, &model.CompletionTokens,
			&model.TotalTokens, &model.CachedInputTokens, &model.CacheCreationTokens,
			&model.ReasoningTokens, &model.EstimatedCostUSD,
		); err != nil {
			return UserUsageReport{}, fmt.Errorf("scan user usage report: %w", err)
		}
		report.Models = append(report.Models, model)
		report.Totals.Requests += model.Requests
		report.Totals.PromptTokens += model.PromptTokens
		report.Totals.CompletionTokens += model.CompletionTokens
		report.Totals.TotalTokens += model.TotalTokens
		report.Totals.CachedInputTokens += model.CachedInputTokens
		report.Totals.CacheCreationTokens += model.CacheCreationTokens
		report.Totals.ReasoningTokens += model.ReasoningTokens
		report.Totals.EstimatedCostUSD += model.EstimatedCostUSD
	}
	if err := rows.Err(); err != nil {
		return UserUsageReport{}, fmt.Errorf("iterate user usage report: %w", err)
	}
	return report, nil
}
