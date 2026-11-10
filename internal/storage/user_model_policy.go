package storage

import (
	"context"
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

// userLogins returns the requested login plus other logins mapped to the same
// partner user. A policy applied to one login therefore cannot be bypassed by
// using another linked MaaS key. A login with no partner record resolves to
// just itself.
func (s *Store) userLogins(ctx context.Context, username string) ([]string, error) {
	logins, err := s.PartnerLoginsForUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("resolve username: %w", err)
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

// GetUserModelAllowlist reads the effective policy for a user. If legacy data
// contains differing policies for linked logins, use their intersection so an
// alternate login cannot gain models.
func (s *Store) GetUserModelAllowlist(ctx context.Context, username string) (UserModelAllowlist, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return UserModelAllowlist{}, errors.New("username is required")
	}
	// SSO partner identities are keyed by stable UUID in their public policy
	// API. Resolve the MaaS login through the retained login map so policies
	// follow email changes and inactive users fail closed.
	partnerUser, partnerErr := s.PartnerUserByLoginAlias(ctx, username)
	if partnerErr == nil {
		partnerPolicy, err := s.GetPartnerUserModelAllowlist(ctx, partnerUser.UserID)
		if err != nil {
			return UserModelAllowlist{}, err
		}
		return UserModelAllowlist{
			Username:  username,
			Enabled:   partnerPolicy.Enabled,
			Models:    partnerPolicy.Models,
			UpdatedBy: partnerPolicy.UpdatedBy,
			UpdatedAt: partnerPolicy.UpdatedAt,
		}, nil
	}
	if !errors.Is(partnerErr, ErrPartnerUserNotFound) {
		return UserModelAllowlist{}, fmt.Errorf("resolve partner MaaS username: %w", partnerErr)
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
