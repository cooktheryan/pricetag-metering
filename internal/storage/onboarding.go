package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
)

// This file owns the two pieces of state behind self-service onboarding:
//
//   - user_agreements: the durable, per-user, per-version record of Terms
//     acceptance. It is the only source of truth for "has this person
//     accepted the current terms?" and is never inferred from the session.
//   - access_policy: a single row that a super admin edits to change the
//     group allowlist and the ISO-3166 alpha-3 country blocklist without a
//     redeploy. Environment configuration remains the fallback when no row
//     exists, so a fresh database behaves exactly like the deployment spec.

const agreementDocTerms = "terms"

// Agreement is one accepted legal document version.
type Agreement struct {
	UserID     string    `json:"user_id"`
	DocType    string    `json:"doc_type"`
	Version    string    `json:"version"`
	AcceptedAt time.Time `json:"accepted_at"`
	IP         string    `json:"ip,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
	Method     string    `json:"method"`
}

// AccessPolicy is the super-admin-managed gate policy. The zero value means
// "no database override": callers fall back to environment configuration.
type AccessPolicy struct {
	AllowedGroups       []string  `json:"allowed_groups"`
	BlockedCountries    []string  `json:"blocked_countries"`
	AllowUnknownCountry bool      `json:"allow_unknown_country"`
	UpdatedBy           string    `json:"updated_by,omitempty"`
	UpdatedAt           time.Time `json:"updated_at,omitempty"`
	// Configured reports whether the row exists. It is not serialised.
	Configured bool `json:"-"`
}

func (s *Store) migrateOnboarding(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS user_agreements (
			user_id     UUID NOT NULL,
			doc_type    TEXT NOT NULL,
			version     TEXT NOT NULL,
			accepted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			ip          INET,
			user_agent  TEXT NOT NULL DEFAULT '',
			method      TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (user_id, doc_type, version)
		)`,
		`CREATE INDEX IF NOT EXISTS user_agreements_doc_version
			ON user_agreements (doc_type, version)`,
		`CREATE TABLE IF NOT EXISTS access_audit (
			id         BIGSERIAL PRIMARY KEY,
			user_id    UUID,
			username   TEXT NOT NULL DEFAULT '',
			event      TEXT NOT NULL,
			check_name TEXT NOT NULL DEFAULT '',
			reason     TEXT NOT NULL DEFAULT '',
			detail     JSONB NOT NULL DEFAULT '{}'::jsonb,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS access_audit_user_time
			ON access_audit (user_id, created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS access_policy (
			id                    SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
			allowed_groups        TEXT[] NOT NULL DEFAULT '{}',
			blocked_countries     TEXT[] NOT NULL DEFAULT '{}',
			allow_unknown_country BOOLEAN NOT NULL DEFAULT FALSE,
			updated_by            TEXT NOT NULL DEFAULT '',
			updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
	}
	for _, stmt := range statements {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("onboarding migration failed: %w", err)
		}
	}
	return nil
}

// GetAccessPolicy returns the stored policy, or Configured=false when the
// deployment has never saved one.
func (s *Store) GetAccessPolicy(ctx context.Context) (AccessPolicy, error) {
	var p AccessPolicy
	var groups, countries pq.StringArray
	err := s.db.QueryRowContext(ctx, `
		SELECT allowed_groups, blocked_countries, allow_unknown_country, updated_by, updated_at
		FROM access_policy WHERE id = 1`).Scan(&groups, &countries, &p.AllowUnknownCountry, &p.UpdatedBy, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AccessPolicy{}, nil
	}
	if err != nil {
		return AccessPolicy{}, fmt.Errorf("read access policy: %w", err)
	}
	p.AllowedGroups = cleanStringList(groups)
	p.BlockedCountries = upperStringList(countries)
	p.Configured = true
	return p, nil
}

// SaveAccessPolicy upserts the singleton policy row.
func (s *Store) SaveAccessPolicy(ctx context.Context, p AccessPolicy, updatedBy string) (AccessPolicy, error) {
	groups := cleanStringList(p.AllowedGroups)
	countries := upperStringList(p.BlockedCountries)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO access_policy (id, allowed_groups, blocked_countries, allow_unknown_country, updated_by, updated_at)
		VALUES (1, $1, $2, $3, $4, NOW())
		ON CONFLICT (id) DO UPDATE SET
			allowed_groups = EXCLUDED.allowed_groups,
			blocked_countries = EXCLUDED.blocked_countries,
			allow_unknown_country = EXCLUDED.allow_unknown_country,
			updated_by = EXCLUDED.updated_by,
			updated_at = NOW()`,
		pq.Array(groups), pq.Array(countries), p.AllowUnknownCountry, updatedBy)
	if err != nil {
		return AccessPolicy{}, fmt.Errorf("save access policy: %w", err)
	}
	p.AllowedGroups = groups
	p.BlockedCountries = countries
	p.UpdatedBy = updatedBy
	p.UpdatedAt = time.Now().UTC()
	p.Configured = true
	return p, nil
}

// HasAgreement reports whether the user accepted this exact document version.
func (s *Store) HasAgreement(ctx context.Context, userID, docType, version string) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM user_agreements
			WHERE user_id = $1 AND doc_type = $2 AND version = $3
		)`, userID, docType, version).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check agreement: %w", err)
	}
	return exists, nil
}

// ResetAgreement removes one agreement version. It is used only by the
// explicitly enabled local demo persona reset flow.
func (s *Store) ResetAgreement(ctx context.Context, userID, docType, version string) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM user_agreements
		WHERE user_id = $1 AND doc_type = $2 AND version = $3`, userID, docType, version)
	if err != nil {
		return fmt.Errorf("reset agreement: %w", err)
	}
	return nil
}

// RecordAgreement stores an acceptance. It is idempotent: re-accepting the
// same version returns inserted=false and leaves the original timestamp.
func (s *Store) RecordAgreement(ctx context.Context, a Agreement) (bool, error) {
	if strings.TrimSpace(a.UserID) == "" {
		return false, fmt.Errorf("agreement requires a user id")
	}
	if a.DocType == "" {
		a.DocType = agreementDocTerms
	}
	var ip any
	if strings.TrimSpace(a.IP) != "" {
		ip = strings.TrimSpace(a.IP)
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO user_agreements (user_id, doc_type, version, ip, user_agent, method)
		VALUES ($1, $2, $3, $4::inet, $5, $6)
		ON CONFLICT (user_id, doc_type, version) DO NOTHING`,
		a.UserID, a.DocType, a.Version, ip, a.UserAgent, a.Method)
	if err != nil {
		return false, fmt.Errorf("record agreement: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// RecordAccessAudit appends a gate decision. Failure to audit must not fail
// the request path; callers log the error instead of returning it.
func (s *Store) RecordAccessAudit(ctx context.Context, userID, username, event, check, reason string, detail map[string]any) error {
	if detail == nil {
		detail = map[string]any{}
	}
	payload, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	var uid any
	if strings.TrimSpace(userID) != "" {
		uid = userID
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO access_audit (user_id, username, event, check_name, reason, detail)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
		uid, username, event, check, reason, payload)
	return err
}

func cleanStringList(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		key := strings.ToLower(v)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, v)
	}
	return out
}

func upperStringList(values []string) []string {
	out := cleanStringList(values)
	for i := range out {
		out[i] = strings.ToUpper(out[i])
	}
	return out
}
