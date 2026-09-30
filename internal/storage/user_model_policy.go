package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"
)

var ErrInvalidUserModelAllowlist = errors.New("invalid user model allowlist")

const userModelAllowlistMax = 50
const userModelIdentifierMaxBytes = 100

// UserModelAllowlist is a per-person exact-match allowlist. Enabled=false
// means no additional Metering model restriction is configured. Enabled=true
// with an empty Models slice deliberately blocks every model for that person.
type UserModelAllowlist struct {
	Username  string    `json:"username"`
	Enabled   bool      `json:"enabled"`
	Models    []string  `json:"models"`
	UpdatedBy string    `json:"updatedBy,omitempty"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
}

func (s *Store) migrateUserModelPolicy(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS user_model_allowlists (
			username TEXT PRIMARY KEY,
			models TEXT[] NOT NULL DEFAULT '{}',
			updated_by TEXT NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`)
	if err != nil {
		return fmt.Errorf("create user model allowlists: %w", err)
	}
	return nil
}

// userLogins returns the requested login plus other non-service logins linked
// to the same directory person. A policy applied to one login therefore cannot
// be bypassed by using another linked MaaS key.
func (s *Store) userLogins(ctx context.Context, username string) ([]string, error) {
	person, err := s.GetPersonByUsername(ctx, username)
	if errors.Is(err, sql.ErrNoRows) {
		return []string{username}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("resolve username: %w", err)
	}
	logins, err := s.PersonUsernames(ctx, person.Slug)
	if err != nil {
		return nil, fmt.Errorf("list linked usernames: %w", err)
	}
	found := false
	for _, login := range logins {
		if login == username {
			found = true
			break
		}
	}
	if !found {
		logins = append(logins, username)
	}
	sort.Strings(logins)
	return logins, nil
}

func normalizeUserModelAllowlist(models []string) ([]string, error) {
	clean := make([]string, 0, len(models))
	seen := make(map[string]struct{}, len(models))
	for _, model := range models {
		model = strings.TrimSpace(model)
		if model == "" {
			return nil, fmt.Errorf("%w: model identifiers must not be empty", ErrInvalidUserModelAllowlist)
		}
		if len(model) > userModelIdentifierMaxBytes {
			return nil, fmt.Errorf("%w: model identifier exceeds %d bytes", ErrInvalidUserModelAllowlist, userModelIdentifierMaxBytes)
		}
		if strings.ContainsAny(model, "*?[ \t\r\n") {
			return nil, fmt.Errorf("%w: exact model identifiers only; wildcards and whitespace are not allowed", ErrInvalidUserModelAllowlist)
		}
		if _, ok := seen[model]; ok {
			continue
		}
		seen[model] = struct{}{}
		clean = append(clean, model)
	}
	if len(clean) > userModelAllowlistMax {
		return nil, fmt.Errorf("%w: at most %d model identifiers are allowed", ErrInvalidUserModelAllowlist, userModelAllowlistMax)
	}
	sort.Strings(clean)
	return clean, nil
}

// SetUserModelAllowlist replaces the user's entire allowlist atomically. The
// update and audit row commit together. An empty list is a configured deny-all
// policy; DeleteUserModelAllowlist clears the restriction.
func (s *Store) SetUserModelAllowlist(ctx context.Context, actor, username string, models []string) (UserModelAllowlist, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return UserModelAllowlist{}, errors.New("username is required")
	}
	clean, err := normalizeUserModelAllowlist(models)
	if err != nil {
		return UserModelAllowlist{}, err
	}
	logins, err := s.userLogins(ctx, username)
	if err != nil {
		return UserModelAllowlist{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return UserModelAllowlist{}, err
	}
	defer func() { _ = tx.Rollback() }()
	for _, login := range logins {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO user_model_allowlists (username, models, updated_by)
			VALUES ($1, $2, $3)
			ON CONFLICT (username) DO UPDATE SET
				models = EXCLUDED.models,
				updated_by = EXCLUDED.updated_by,
				updated_at = NOW()`, login, pq.Array(clean), actor); err != nil {
			return UserModelAllowlist{}, fmt.Errorf("upsert model allowlist: %w", err)
		}
	}
	if err := s.auditTx(ctx, tx, actor, "user.model_allowlist_set", username,
		map[string]any{"models": clean, "linked_usernames": len(logins)}); err != nil {
		return UserModelAllowlist{}, err
	}
	if err := tx.Commit(); err != nil {
		return UserModelAllowlist{}, err
	}
	s.invalidateQuotaCache()
	return s.GetUserModelAllowlist(ctx, username)
}

// GetUserModelAllowlist reads the effective policy for a user. If legacy data
// contains differing policies for linked logins, use their intersection so an
// alternate login cannot gain models.
func (s *Store) GetUserModelAllowlist(ctx context.Context, username string) (UserModelAllowlist, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return UserModelAllowlist{}, errors.New("username is required")
	}
	logins, err := s.userLogins(ctx, username)
	if err != nil {
		return UserModelAllowlist{}, err
	}
	policy := UserModelAllowlist{Username: username, Models: []string{}}
	rows, err := s.db.QueryContext(ctx, `
		SELECT models, updated_by, updated_at
		FROM user_model_allowlists
		WHERE username = ANY($1)
		ORDER BY username`, pq.Array(logins))
	if err != nil {
		return UserModelAllowlist{}, err
	}
	defer rows.Close()
	var intersection map[string]struct{}
	for rows.Next() {
		var models []string
		var updatedBy string
		var updatedAt time.Time
		if err := rows.Scan(pq.Array(&models), &updatedBy, &updatedAt); err != nil {
			return UserModelAllowlist{}, err
		}
		policy.Enabled = true
		if updatedAt.After(policy.UpdatedAt) {
			policy.UpdatedAt = updatedAt
			policy.UpdatedBy = updatedBy
		}
		current := make(map[string]struct{}, len(models))
		for _, model := range models {
			current[model] = struct{}{}
		}
		if intersection == nil {
			intersection = current
			continue
		}
		for model := range intersection {
			if _, ok := current[model]; !ok {
				delete(intersection, model)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return UserModelAllowlist{}, err
	}
	for model := range intersection {
		policy.Models = append(policy.Models, model)
	}
	sort.Strings(policy.Models)
	return policy, nil
}

// DeleteUserModelAllowlist removes restrictions and restores the service's
// baseline model-access policy for the user's linked MaaS logins.
func (s *Store) DeleteUserModelAllowlist(ctx context.Context, actor, username string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}
	logins, err := s.userLogins(ctx, username)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_model_allowlists WHERE username = ANY($1)`, pq.Array(logins)); err != nil {
		return fmt.Errorf("delete model allowlist: %w", err)
	}
	if err := s.auditTx(ctx, tx, actor, "user.model_allowlist_clear", username,
		map[string]any{"linked_usernames": len(logins)}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.invalidateQuotaCache()
	return nil
}

func (d QuotaDecision) ModelAllowed(model string) bool {
	if d.Exempt || !d.ModelPolicyActive {
		return true
	}
	if model == "" {
		return false
	}
	for _, allowed := range d.UserAllowedModels {
		if allowed == model {
			return true
		}
	}
	return false
}
