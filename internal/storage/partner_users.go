package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/lib/pq"
)

var (
	ErrPartnerUserNotFound          = errors.New("partner user not found")
	ErrPartnerUserConflict          = errors.New("partner user conflicts with an existing record")
	ErrPartnerUserInactive          = errors.New("partner user is inactive")
	ErrPartnerUserRevocationPending = errors.New("partner user key revocation is pending")
	ErrInvalidPartnerUser           = errors.New("invalid partner user")
	ErrInvalidPartnerUserQuery      = errors.New("invalid partner user query")
)

const (
	partnerUserMaxTags      = 100
	partnerUserMaxTagValue  = 2048
	partnerUserMaxListLimit = 100
)

var (
	partnerUserIDPattern  = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	partnerUserTagPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
)

// PartnerUser is the partner/SSO-facing user record. MaaS usernames and other
// attributes live in Tags; UserID is the stable external UUID and is not the
// MaaS username or a MaaS API-key UUID.
type PartnerUser struct {
	UserID               string         `json:"user_id"`
	Tags                 map[string]any `json:"tags"`
	Active               bool           `json:"active"`
	KeyRevocationPending bool           `json:"key_revocation_pending,omitempty"`
	CreatedAt            time.Time      `json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at"`
}

type PartnerUserPage struct {
	Users    []PartnerUser `json:"users"`
	HasMore  bool          `json:"-"`
	NextPage *string       `json:"next_page"`
}

// PartnerUserModelAllowlist is the UUID-keyed external policy representation.
type PartnerUserModelAllowlist struct {
	UserID    string    `json:"user_id"`
	Enabled   bool      `json:"enabled"`
	Models    []string  `json:"models"`
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// PartnerUserDeletion contains the durable inactive state and the
// partner-minted keys that must be revoked before deletion is complete.
type PartnerUserDeletion struct {
	UserID string
	Keys   []PartnerUserKey
}

func (s *Store) migratePartnerUsers(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS partner_users (
			user_id UUID PRIMARY KEY,
			tags JSONB NOT NULL CHECK (jsonb_typeof(tags) = 'object'),
			active BOOLEAN NOT NULL DEFAULT TRUE,
			key_revocation_pending BOOLEAN NOT NULL DEFAULT FALSE,
			created_by TEXT NOT NULL,
			updated_by TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			revoked_at TIMESTAMPTZ
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS partner_users_email_unique ON partner_users (LOWER(tags->>'email'))`,
		`CREATE INDEX IF NOT EXISTS partner_users_tags_gin ON partner_users USING GIN (tags jsonb_path_ops)`,
		`CREATE TABLE IF NOT EXISTS partner_user_logins (
			username TEXT PRIMARY KEY,
			user_id UUID NOT NULL REFERENCES partner_users(user_id),
			is_current BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS partner_user_logins_user_idx ON partner_user_logins (user_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS partner_user_logins_one_current ON partner_user_logins (user_id) WHERE is_current`,
		// Keys minted through the partner API. Deactivation revokes exactly
		// these; keys a user obtained through the dashboard or MaaS directly
		// are never touched by partner operations.
		`CREATE TABLE IF NOT EXISTS partner_user_keys (
			key_id TEXT PRIMARY KEY,
			user_id UUID NOT NULL REFERENCES partner_users(user_id),
			username TEXT NOT NULL,
			name TEXT NOT NULL,
			created_by TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			revoked_at TIMESTAMPTZ
		)`,
		`CREATE INDEX IF NOT EXISTS partner_user_keys_user_idx ON partner_user_keys (user_id)`,
		`CREATE TABLE IF NOT EXISTS partner_user_model_allowlists (
			user_id UUID PRIMARY KEY REFERENCES partner_users(user_id),
			models TEXT[] NOT NULL DEFAULT '{}',
			updated_by TEXT NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("partner user migration failed: %w", err)
		}
	}
	return nil
}

func normalizePartnerUserID(userID string) (string, error) {
	userID = strings.ToLower(strings.TrimSpace(userID))
	if !partnerUserIDPattern.MatchString(userID) {
		return "", fmt.Errorf("%w: user_id must be a UUID", ErrInvalidPartnerUser)
	}
	return userID, nil
}

// normalizePartnerUserTags validates required identity/display tags while
// preserving additional string-valued tags for future SSO attributes.
func normalizePartnerUserTags(tags map[string]any) (map[string]any, string, error) {
	if len(tags) == 0 || len(tags) > partnerUserMaxTags {
		return nil, "", fmt.Errorf("%w: tags must contain 1-%d entries", ErrInvalidPartnerUser, partnerUserMaxTags)
	}
	clean := make(map[string]any, len(tags))
	for key, raw := range tags {
		if !partnerUserTagPattern.MatchString(key) {
			return nil, "", fmt.Errorf("%w: invalid tag key %q", ErrInvalidPartnerUser, key)
		}
		switch value := raw.(type) {
		case nil:
			if key != "manager_uuid" {
				return nil, "", fmt.Errorf("%w: only manager_uuid may be null", ErrInvalidPartnerUser)
			}
			clean[key] = nil
		case string:
			if len(value) > partnerUserMaxTagValue {
				return nil, "", fmt.Errorf("%w: tag %q exceeds %d bytes", ErrInvalidPartnerUser, key, partnerUserMaxTagValue)
			}
			for _, r := range value {
				if unicode.IsControl(r) {
					return nil, "", fmt.Errorf("%w: tag %q contains a control character", ErrInvalidPartnerUser, key)
				}
			}
			clean[key] = value
		default:
			return nil, "", fmt.Errorf("%w: tag %q must be a string", ErrInvalidPartnerUser, key)
		}
	}

	for _, required := range []string{"email", "first_name", "last_name"} {
		value, ok := clean[required].(string)
		if !ok || strings.TrimSpace(value) == "" {
			return nil, "", fmt.Errorf("%w: tags.%s is required", ErrInvalidPartnerUser, required)
		}
		clean[required] = strings.TrimSpace(value)
	}
	email := clean["email"].(string)
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email || !strings.Contains(email, "@") {
		return nil, "", fmt.Errorf("%w: tags.email must be a bare email address", ErrInvalidPartnerUser)
	}
	if raw, ok := clean["manager_uuid"]; ok && raw != nil {
		managerID, ok := raw.(string)
		if !ok {
			return nil, "", fmt.Errorf("%w: tags.manager_uuid must be a UUID or null", ErrInvalidPartnerUser)
		}
		managerID = strings.ToLower(strings.TrimSpace(managerID))
		if managerID != "" && !partnerUserIDPattern.MatchString(managerID) {
			return nil, "", fmt.Errorf("%w: tags.manager_uuid must be a UUID or null", ErrInvalidPartnerUser)
		}
		if managerID == "" {
			clean["manager_uuid"] = nil
		} else {
			clean["manager_uuid"] = managerID
		}
	}
	return clean, email, nil
}

func scanPartnerUser(row interface{ Scan(...any) error }) (PartnerUser, error) {
	var user PartnerUser
	var tagsJSON []byte
	if err := row.Scan(&user.UserID, &tagsJSON, &user.Active, &user.KeyRevocationPending, &user.CreatedAt, &user.UpdatedAt); err != nil {
		return PartnerUser{}, err
	}
	if err := json.Unmarshal(tagsJSON, &user.Tags); err != nil {
		return PartnerUser{}, fmt.Errorf("decode partner user tags: %w", err)
	}
	return user, nil
}

const partnerUserSelect = `SELECT p.user_id::text, p.tags, p.active, p.key_revocation_pending, p.created_at, p.updated_at FROM partner_users p`

func (s *Store) GetPartnerUser(ctx context.Context, userID string) (PartnerUser, error) {
	id, err := normalizePartnerUserID(userID)
	if err != nil {
		return PartnerUser{}, err
	}
	user, err := scanPartnerUser(s.db.QueryRowContext(ctx, partnerUserSelect+` WHERE p.user_id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return PartnerUser{}, ErrPartnerUserNotFound
	}
	return user, err
}

// GetActivePartnerUser is the pre-mint check. It deliberately takes no lock:
// the mint itself is an outbound HTTP call and must not pin a pool connection.
func (s *Store) GetActivePartnerUser(ctx context.Context, userID string) (PartnerUser, error) {
	user, err := s.GetPartnerUser(ctx, userID)
	if err != nil {
		return PartnerUser{}, err
	}
	if !user.Active || user.KeyRevocationPending {
		return PartnerUser{}, ErrPartnerUserInactive
	}
	return user, nil
}

// PartnerUserKey is a key minted through the partner API.
type PartnerUserKey struct {
	KeyID     string     `json:"key_id"`
	UserID    string     `json:"user_id"`
	Username  string     `json:"username"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// RecordPartnerUserKey stores a freshly minted key in one short transaction
// that re-checks the user under the row lock. ErrPartnerUserInactive means the
// user was deactivated while the mint was in flight; the caller must revoke
// the key it just received.
func (s *Store) RecordPartnerUserKey(ctx context.Context, actor, userID, keyID, username, name string) error {
	id, err := normalizePartnerUserID(userID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(keyID) == "" {
		return fmt.Errorf("%w: MaaS returned no key id", ErrInvalidPartnerUser)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var active, revocationPending bool
	if err := tx.QueryRowContext(ctx, `SELECT active,key_revocation_pending FROM partner_users WHERE user_id=$1 FOR UPDATE`, id).Scan(&active, &revocationPending); errors.Is(err, sql.ErrNoRows) {
		return ErrPartnerUserNotFound
	} else if err != nil {
		return err
	}
	if !active || revocationPending {
		return ErrPartnerUserInactive
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO partner_user_keys (key_id,user_id,username,name,created_by) VALUES ($1,$2,$3,$4,$5)`, keyID, id, username, name, actor); err != nil {
		return fmt.Errorf("record partner key: %w", err)
	}
	if err := s.auditTx(ctx, tx, actor, "partner_user.key_mint", id, map[string]any{"key_id": keyID, "name": name}); err != nil {
		return err
	}
	return tx.Commit()
}

// ListPartnerUserKeys returns the keys minted through the partner API for a
// user, most recent first, including revoked ones.
func (s *Store) ListPartnerUserKeys(ctx context.Context, userID string) ([]PartnerUserKey, error) {
	id, err := normalizePartnerUserID(userID)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT key_id,user_id::text,username,name,created_at,revoked_at FROM partner_user_keys WHERE user_id=$1 ORDER BY created_at DESC,key_id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := []PartnerUserKey{}
	for rows.Next() {
		var k PartnerUserKey
		var revoked sql.NullTime
		if err := rows.Scan(&k.KeyID, &k.UserID, &k.Username, &k.Name, &k.CreatedAt, &revoked); err != nil {
			return nil, err
		}
		if revoked.Valid {
			t := revoked.Time
			k.RevokedAt = &t
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// MarkPartnerUserKeyRevoked records that MaaS has revoked a tracked key.
func (s *Store) MarkPartnerUserKeyRevoked(ctx context.Context, actor, userID, keyID string) error {
	id, err := normalizePartnerUserID(userID)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE partner_user_keys SET revoked_at=COALESCE(revoked_at,NOW()) WHERE key_id=$1 AND user_id=$2`, keyID, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return ErrPartnerUserNotFound
	}
	if err := s.auditTx(ctx, tx, actor, "partner_user.key_revoke", id, map[string]any{"key_id": keyID}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GetPartnerUserModelAllowlist(ctx context.Context, userID string) (PartnerUserModelAllowlist, error) {
	id, err := normalizePartnerUserID(userID)
	if err != nil {
		return PartnerUserModelAllowlist{}, err
	}
	user, err := s.GetPartnerUser(ctx, id)
	if err != nil {
		return PartnerUserModelAllowlist{}, err
	}
	policy := PartnerUserModelAllowlist{UserID: id, Models: []string{}}
	if !user.Active || user.KeyRevocationPending {
		// If key revocation is incomplete, fail closed at the entitlement layer.
		policy.Enabled = true
		return policy, nil
	}
	err = s.db.QueryRowContext(ctx, `
		SELECT models, updated_by, updated_at
		FROM partner_user_model_allowlists WHERE user_id=$1`, id,
	).Scan(pq.Array(&policy.Models), &policy.UpdatedBy, &policy.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return policy, nil
	}
	if err != nil {
		return PartnerUserModelAllowlist{}, err
	}
	policy.Enabled = true
	return policy, nil
}

func (s *Store) SetPartnerUserModelAllowlist(ctx context.Context, actor, userID string, models []string) (PartnerUserModelAllowlist, error) {
	id, err := normalizePartnerUserID(userID)
	if err != nil {
		return PartnerUserModelAllowlist{}, err
	}
	clean, err := normalizeUserModelAllowlist(models)
	if err != nil {
		return PartnerUserModelAllowlist{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PartnerUserModelAllowlist{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var active, revocationPending bool
	if err := tx.QueryRowContext(ctx, `SELECT active,key_revocation_pending FROM partner_users WHERE user_id=$1 FOR UPDATE`, id).Scan(&active, &revocationPending); errors.Is(err, sql.ErrNoRows) {
		return PartnerUserModelAllowlist{}, ErrPartnerUserNotFound
	} else if err != nil {
		return PartnerUserModelAllowlist{}, err
	}
	if !active || revocationPending {
		return PartnerUserModelAllowlist{}, ErrPartnerUserInactive
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO partner_user_model_allowlists (user_id,models,updated_by)
		VALUES ($1,$2,$3)
		ON CONFLICT (user_id) DO UPDATE SET
			models=EXCLUDED.models,updated_by=EXCLUDED.updated_by,updated_at=NOW()`,
		id, pq.Array(clean), actor); err != nil {
		return PartnerUserModelAllowlist{}, err
	}
	if err := s.auditTx(ctx, tx, actor, "partner_user.model_allowlist_set", id, map[string]any{"models": clean}); err != nil {
		return PartnerUserModelAllowlist{}, err
	}
	if err := tx.Commit(); err != nil {
		return PartnerUserModelAllowlist{}, err
	}
	s.invalidateQuotaCache()
	return s.GetPartnerUserModelAllowlist(ctx, id)
}

func (s *Store) DeletePartnerUserModelAllowlist(ctx context.Context, actor, userID string) error {
	id, err := normalizePartnerUserID(userID)
	if err != nil {
		return err
	}
	if _, err := s.GetPartnerUser(ctx, id); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM partner_user_model_allowlists WHERE user_id=$1`, id); err != nil {
		return err
	}
	if err := s.auditTx(ctx, tx, actor, "partner_user.model_allowlist_clear", id, nil); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.invalidateQuotaCache()
	return nil
}

func (s *Store) PartnerUserByMaaSUsername(ctx context.Context, username string) (PartnerUser, error) {
	user, err := scanPartnerUser(s.db.QueryRowContext(ctx, partnerUserSelect+`
		JOIN partner_user_logins l ON l.user_id = p.user_id
		WHERE l.username = $1`, strings.TrimSpace(username)))
	if errors.Is(err, sql.ErrNoRows) {
		return PartnerUser{}, ErrPartnerUserNotFound
	}
	return user, err
}

func partnerTagKeys(tags map[string]any) []string {
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func syncPartnerUserProfiles(ctx context.Context, tx *sql.Tx, userID string, firstName, lastName string) error {
	rows, err := tx.QueryContext(ctx, `SELECT username FROM partner_user_logins WHERE user_id = $1`, userID)
	if err != nil {
		return err
	}
	var usernames []string
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			rows.Close()
			return err
		}
		usernames = append(usernames, username)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	// Fill-only, like the roster import: a display name an admin already set
	// in the dashboard is never overwritten by partner tag updates.
	for _, username := range usernames {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO user_profiles (username, first_name, last_name, updated_at)
			VALUES ($1,$2,$3,NOW())
			ON CONFLICT (username) DO UPDATE SET
				first_name=EXCLUDED.first_name, last_name=EXCLUDED.last_name, updated_at=NOW()
			WHERE user_profiles.first_name = '' AND user_profiles.last_name = ''`,
			username, firstName, lastName); err != nil {
			return fmt.Errorf("sync dashboard profile for %s: %w", username, err)
		}
	}
	return nil
}

func (s *Store) CreatePartnerUser(ctx context.Context, actor, userID string, tags map[string]any) (PartnerUser, error) {
	id, err := normalizePartnerUserID(userID)
	if err != nil {
		return PartnerUser{}, err
	}
	cleanTags, email, err := normalizePartnerUserTags(tags)
	if err != nil {
		return PartnerUser{}, err
	}
	tagsJSON, err := json.Marshal(cleanTags)
	if err != nil {
		return PartnerUser{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PartnerUser{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO partner_users (user_id,tags,created_by,updated_by) VALUES ($1,$2,$3,$3)`, id, string(tagsJSON), actor); err != nil {
		if isUniqueViolation(err) {
			return PartnerUser{}, ErrPartnerUserConflict
		}
		return PartnerUser{}, fmt.Errorf("create partner user: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO partner_user_logins (username,user_id,is_current) VALUES ($1,$2,TRUE)`, email, id); err != nil {
		if isUniqueViolation(err) {
			return PartnerUser{}, ErrPartnerUserConflict
		}
		return PartnerUser{}, fmt.Errorf("link partner MaaS username: %w", err)
	}
	if err := syncPartnerUserProfiles(ctx, tx, id, cleanTags["first_name"].(string), cleanTags["last_name"].(string)); err != nil {
		return PartnerUser{}, err
	}
	if err := s.auditTx(ctx, tx, actor, "partner_user.create", id, map[string]any{"tag_keys": partnerTagKeys(cleanTags)}); err != nil {
		return PartnerUser{}, err
	}
	if err := tx.Commit(); err != nil {
		return PartnerUser{}, err
	}
	return s.GetPartnerUser(ctx, id)
}

func isUniqueViolation(err error) bool {
	var pgErr *pq.Error
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// UpdatePartnerUser replaces the complete tag set. It is the storage path for
// PUT, whose handler may upsert a missing user.
func (s *Store) UpdatePartnerUser(ctx context.Context, actor, userID string, tags map[string]any) (PartnerUser, error) {
	return s.updatePartnerUser(ctx, actor, userID, tags, false)
}

// PatchPartnerUser merges supplied tags into an existing user. Omitted tags
// are preserved; supplied values replace the old value. manager_uuid may be
// null to clear it, matching the full-tag contract. PATCH never creates a user.
// The merge happens while holding the user row lock so concurrent Atlas/SSO
// refreshes cannot overwrite one another with stale reads.
func (s *Store) PatchPartnerUser(ctx context.Context, actor, userID string, tags map[string]any) (PartnerUser, error) {
	if len(tags) == 0 {
		return PartnerUser{}, fmt.Errorf("%w: tags must contain at least one entry", ErrInvalidPartnerUser)
	}
	return s.updatePartnerUser(ctx, actor, userID, tags, true)
}

func (s *Store) updatePartnerUser(ctx context.Context, actor, userID string, tags map[string]any, merge bool) (PartnerUser, error) {
	id, err := normalizePartnerUserID(userID)
	if err != nil {
		return PartnerUser{}, err
	}
	var cleanTags map[string]any
	var email string
	if !merge {
		cleanTags, email, err = normalizePartnerUserTags(tags)
		if err != nil {
			return PartnerUser{}, err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PartnerUser{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var currentTagsJSON []byte
	var active, revocationPending bool
	if err := tx.QueryRowContext(ctx, `SELECT tags,active,key_revocation_pending FROM partner_users WHERE user_id=$1 FOR UPDATE`, id).Scan(&currentTagsJSON, &active, &revocationPending); errors.Is(err, sql.ErrNoRows) {
		return PartnerUser{}, ErrPartnerUserNotFound
	} else if err != nil {
		return PartnerUser{}, err
	}
	if !active || revocationPending {
		return PartnerUser{}, ErrPartnerUserInactive
	}
	if merge {
		var merged map[string]any
		if err := json.Unmarshal(currentTagsJSON, &merged); err != nil {
			return PartnerUser{}, fmt.Errorf("decode current partner user tags: %w", err)
		}
		for key, value := range tags {
			merged[key] = value
		}
		cleanTags, email, err = normalizePartnerUserTags(merged)
		if err != nil {
			return PartnerUser{}, err
		}
	}
	tagsJSON, err := json.Marshal(cleanTags)
	if err != nil {
		return PartnerUser{}, err
	}
	var currentEmail string
	if err := tx.QueryRowContext(ctx, `SELECT username FROM partner_user_logins WHERE user_id=$1 AND is_current`, id).Scan(&currentEmail); err != nil {
		return PartnerUser{}, err
	}
	if email != currentEmail {
		if _, err := tx.ExecContext(ctx, `UPDATE partner_user_logins SET is_current=FALSE WHERE user_id=$1 AND is_current`, id); err != nil {
			return PartnerUser{}, err
		}
		result, err := tx.ExecContext(ctx, `UPDATE partner_user_logins SET is_current=TRUE WHERE username=$1 AND user_id=$2`, email, id)
		if err != nil {
			return PartnerUser{}, err
		}
		reactivated, err := result.RowsAffected()
		if err != nil {
			return PartnerUser{}, err
		}
		if reactivated == 0 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO partner_user_logins (username,user_id,is_current) VALUES ($1,$2,TRUE)`, email, id); err != nil {
				if isUniqueViolation(err) {
					return PartnerUser{}, ErrPartnerUserConflict
				}
				return PartnerUser{}, fmt.Errorf("link updated MaaS username: %w", err)
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE partner_users SET tags=$2,updated_by=$3,updated_at=NOW() WHERE user_id=$1`, id, string(tagsJSON), actor); err != nil {
		if isUniqueViolation(err) {
			return PartnerUser{}, ErrPartnerUserConflict
		}
		return PartnerUser{}, err
	}
	if err := syncPartnerUserProfiles(ctx, tx, id, cleanTags["first_name"].(string), cleanTags["last_name"].(string)); err != nil {
		return PartnerUser{}, err
	}
	action := "partner_user.update"
	auditTags := cleanTags
	if merge {
		action = "partner_user.patch"
		auditTags = tags
	}
	if err := s.auditTx(ctx, tx, actor, action, id, map[string]any{"tag_keys": partnerTagKeys(auditTags), "email_changed": email != currentEmail}); err != nil {
		return PartnerUser{}, err
	}
	if err := tx.Commit(); err != nil {
		return PartnerUser{}, err
	}
	s.invalidateQuotaCache()
	return s.GetPartnerUser(ctx, id)
}

func (s *Store) ListPartnerUsernames(ctx context.Context, userID string) ([]string, error) {
	id, err := normalizePartnerUserID(userID)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT username FROM partner_user_logins WHERE user_id=$1 ORDER BY is_current DESC,username`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var usernames []string
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			return nil, err
		}
		usernames = append(usernames, username)
	}
	return usernames, rows.Err()
}

func (s *Store) ListPartnerUsers(ctx context.Context, tagFilters map[string]string, includeInactive bool, limit, offset int) (PartnerUserPage, error) {
	if limit < 1 || limit > partnerUserMaxListLimit || offset < 0 {
		return PartnerUserPage{}, fmt.Errorf("%w: limit must be 1-%d and offset non-negative", ErrInvalidPartnerUserQuery, partnerUserMaxListLimit)
	}
	filters := make(map[string]any, len(tagFilters))
	for key, value := range tagFilters {
		if !partnerUserTagPattern.MatchString(key) {
			return PartnerUserPage{}, fmt.Errorf("%w: invalid tag filter %q", ErrInvalidPartnerUserQuery, key)
		}
		filters[key] = value
	}
	filterJSON, err := json.Marshal(filters)
	if err != nil {
		return PartnerUserPage{}, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT user_id::text,tags,active,key_revocation_pending,created_at,updated_at
		FROM partner_users
		WHERE ($1 OR active=TRUE) AND tags @> $2::jsonb
		ORDER BY created_at,user_id LIMIT $3 OFFSET $4`, includeInactive, string(filterJSON), limit+1, offset)
	if err != nil {
		return PartnerUserPage{}, err
	}
	defer rows.Close()
	page := PartnerUserPage{Users: []PartnerUser{}}
	for rows.Next() {
		user, err := scanPartnerUser(rows)
		if err != nil {
			return PartnerUserPage{}, err
		}
		page.Users = append(page.Users, user)
	}
	if err := rows.Err(); err != nil {
		return PartnerUserPage{}, err
	}
	page.HasMore = len(page.Users) > limit
	if page.HasMore {
		page.Users = page.Users[:limit]
	}
	return page, nil
}

func (s *Store) BeginPartnerUserDeactivation(ctx context.Context, actor, userID string) (PartnerUserDeletion, error) {
	id, err := normalizePartnerUserID(userID)
	if err != nil {
		return PartnerUserDeletion{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PartnerUserDeletion{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var active bool
	if err := tx.QueryRowContext(ctx, `SELECT active FROM partner_users WHERE user_id=$1 FOR UPDATE`, id).Scan(&active); errors.Is(err, sql.ErrNoRows) {
		return PartnerUserDeletion{}, ErrPartnerUserNotFound
	} else if err != nil {
		return PartnerUserDeletion{}, err
	}
	if active {
		if _, err := tx.ExecContext(ctx, `UPDATE partner_users SET active=FALSE,key_revocation_pending=TRUE,updated_by=$2,updated_at=NOW() WHERE user_id=$1`, id, actor); err != nil {
			return PartnerUserDeletion{}, err
		}
		if err := s.auditTx(ctx, tx, actor, "partner_user.deactivate", id, nil); err != nil {
			return PartnerUserDeletion{}, err
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT key_id,username,name,created_at FROM partner_user_keys WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at,key_id`, id)
	if err != nil {
		return PartnerUserDeletion{}, err
	}
	keys := []PartnerUserKey{}
	for rows.Next() {
		k := PartnerUserKey{UserID: id}
		if err := rows.Scan(&k.KeyID, &k.Username, &k.Name, &k.CreatedAt); err != nil {
			rows.Close()
			return PartnerUserDeletion{}, err
		}
		keys = append(keys, k)
	}
	if err := rows.Close(); err != nil {
		return PartnerUserDeletion{}, err
	}
	if err := tx.Commit(); err != nil {
		return PartnerUserDeletion{}, err
	}
	s.invalidateQuotaCache()
	return PartnerUserDeletion{UserID: id, Keys: keys}, nil
}

func (s *Store) CompletePartnerUserKeyRevocation(ctx context.Context, actor, userID string) error {
	id, err := normalizePartnerUserID(userID)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE partner_users SET key_revocation_pending=FALSE,revoked_at=COALESCE(revoked_at,NOW()),updated_by=$2,updated_at=NOW() WHERE user_id=$1`, id, actor)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated == 0 {
		return ErrPartnerUserNotFound
	}
	if err := s.auditTx(ctx, tx, actor, "partner_user.key_revocation_complete", id, nil); err != nil {
		return err
	}
	return tx.Commit()
}

// ReactivatePartnerUser restores a soft-deactivated user after every MaaS key
// has been revoked. Existing tags and historical username mappings are kept.
func (s *Store) ReactivatePartnerUser(ctx context.Context, actor, userID string) (PartnerUser, error) {
	id, err := normalizePartnerUserID(userID)
	if err != nil {
		return PartnerUser{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PartnerUser{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var active, revocationPending bool
	if err := tx.QueryRowContext(ctx, `SELECT active,key_revocation_pending FROM partner_users WHERE user_id=$1 FOR UPDATE`, id).Scan(&active, &revocationPending); errors.Is(err, sql.ErrNoRows) {
		return PartnerUser{}, ErrPartnerUserNotFound
	} else if err != nil {
		return PartnerUser{}, err
	}
	if revocationPending {
		return PartnerUser{}, ErrPartnerUserRevocationPending
	}
	if !active {
		if _, err := tx.ExecContext(ctx, `UPDATE partner_users SET active=TRUE,revoked_at=NULL,updated_by=$2,updated_at=NOW() WHERE user_id=$1`, id, actor); err != nil {
			return PartnerUser{}, err
		}
		if err := s.auditTx(ctx, tx, actor, "partner_user.reactivate", id, nil); err != nil {
			return PartnerUser{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return PartnerUser{}, err
	}
	s.invalidateQuotaCache()
	return s.GetPartnerUser(ctx, id)
}
