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
	PartnerRoleUser       = "user"
	PartnerRoleAdmin      = "admin"
	PartnerRoleSuperAdmin = "super_admin"
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
	UserID string         `json:"user_id"`
	Tags   map[string]any `json:"tags"`
	// Operator-only fields are intentionally excluded from the existing partner
	// API response contract; dashboard/admin DTOs expose them separately.
	Role                 string    `json:"-"`
	ManagerUserID        *string   `json:"-"`
	Active               bool      `json:"active"`
	KeyRevocationPending bool      `json:"key_revocation_pending,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
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
			role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin', 'super_admin')),
			manager_user_id UUID REFERENCES partner_users(user_id) ON DELETE SET NULL,
			active BOOLEAN NOT NULL DEFAULT TRUE,
			key_revocation_pending BOOLEAN NOT NULL DEFAULT FALSE,
			created_by TEXT NOT NULL,
			updated_by TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			revoked_at TIMESTAMPTZ
		)`,
		`ALTER TABLE partner_users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user'`,
		`ALTER TABLE partner_users ADD COLUMN IF NOT EXISTS manager_user_id UUID REFERENCES partner_users(user_id) ON DELETE SET NULL`,
		`CREATE INDEX IF NOT EXISTS partner_users_manager_idx ON partner_users (manager_user_id)`,
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
	if err := row.Scan(&user.UserID, &tagsJSON, &user.Role, &user.ManagerUserID, &user.Active, &user.KeyRevocationPending, &user.CreatedAt, &user.UpdatedAt); err != nil {
		return PartnerUser{}, err
	}
	if err := json.Unmarshal(tagsJSON, &user.Tags); err != nil {
		return PartnerUser{}, fmt.Errorf("decode partner user tags: %w", err)
	}
	return user, nil
}

const partnerUserSelect = `SELECT p.user_id::text, p.tags, p.role, p.manager_user_id::text, p.active, p.key_revocation_pending, p.created_at, p.updated_at FROM partner_users p`

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

func (s *Store) GetPartnerRoleByUsername(ctx context.Context, username string) (string, error) {
	var role string
	err := s.db.QueryRowContext(ctx, `
		SELECT p.role
		FROM partner_user_logins l
		JOIN partner_users p ON p.user_id = l.user_id
		WHERE LOWER(l.username) = LOWER($1) AND l.is_current AND p.active`, strings.TrimSpace(username)).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return PartnerRoleUser, nil
	}
	return role, err
}

func (s *Store) ListAllPartnerUsers(ctx context.Context) ([]PartnerUser, error) {
	rows, err := s.db.QueryContext(ctx, partnerUserSelect+` WHERE p.active ORDER BY p.created_at, p.user_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []PartnerUser
	for rows.Next() {
		user, err := scanPartnerUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

// ListPartnerUsersPage returns one active Partner-user page, the total number
// of active users matching the (optional) search, and whether a later page
// exists. search is a case-insensitive substring matched against email, first
// and last name, and the stable Partner user id; an empty search returns the
// normal unfiltered page. The offset is used only by the admin table; the full
// list method remains available for internal manager and role lookups.
func (s *Store) ListPartnerUsersPage(ctx context.Context, search string, limit, offset int) ([]PartnerUser, int, bool, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	// $1 holds the search term. An empty term disables the filter so the
	// clause stays a no-op (every active row matches). user_id is cast to
	// text so a partial UUID search works. All comparisons are lower-cased
	// for case-insensitivity.
	where := `WHERE p.active AND ($1 = '' OR (
		lower(COALESCE(p.tags->>'email','')) LIKE '%' || lower($1) || '%'
		OR lower(COALESCE(p.tags->>'first_name','')) LIKE '%' || lower($1) || '%'
		OR lower(COALESCE(p.tags->>'last_name','')) LIKE '%' || lower($1) || '%'
		OR lower(TRIM(CONCAT_WS(' ', p.tags->>'first_name', p.tags->>'last_name'))) LIKE '%' || lower($1) || '%'
		OR lower(p.user_id::text) LIKE '%' || lower($1) || '%'
	))`

	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM partner_users p `+where, search).Scan(&total); err != nil {
		return nil, 0, false, err
	}

	rows, err := s.db.QueryContext(ctx, partnerUserSelect+`
		`+where+` ORDER BY p.created_at, p.user_id LIMIT $2 OFFSET $3`, search, limit+1, offset)
	if err != nil {
		return nil, 0, false, err
	}
	defer rows.Close()
	users := make([]PartnerUser, 0, limit+1)
	for rows.Next() {
		user, err := scanPartnerUser(rows)
		if err != nil {
			return nil, 0, false, err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, false, err
	}
	hasMore := len(users) > limit
	if hasMore {
		users = users[:limit]
	}
	return users, total, hasMore, nil
}

// PartnerManagerScope returns the set of MaaS login usernames a caller may
// see: themselves plus every descendant in the partner_users manager tree.
// The hierarchy is derived dynamically from partner_users.manager_user_id, so
// a user created before their manager appears as a root until the manager
// joins, after which the tree resolves automatically. isManager is true when
// the caller has at least one direct report. A username with no partner record
// resolves to just itself.
func (s *Store) PartnerManagerScope(ctx context.Context, username string) (usernames []string, isManager bool, err error) {
	var rootID string
	err = s.db.QueryRowContext(ctx, `
		SELECT p.user_id::text
		FROM partner_user_logins l
		JOIN partner_users p ON p.user_id = l.user_id
		WHERE l.username = $1 AND p.active`, username).Scan(&rootID)
	if errors.Is(err, sql.ErrNoRows) {
		return []string{username}, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	// depth is capped and the path is tracked so cyclic or corrupt manager
	// data (a user who transitively reports to themselves) can never cause
	// unbounded recursion. A node already on the path is not re-expanded.
	rows, err := s.db.QueryContext(ctx, `
		WITH RECURSIVE subtree(user_id, depth, path) AS (
			SELECT $1::uuid, 0, ARRAY[$1::uuid]
			UNION ALL
			SELECT p.user_id, st.depth + 1, st.path || p.user_id
			FROM partner_users p
			JOIN subtree st ON p.manager_user_id = st.user_id
			WHERE p.active AND st.depth < 1000 AND NOT p.user_id = ANY(st.path)
		)
		SELECT DISTINCT l.username
		FROM subtree st
		JOIN partner_user_logins l ON l.user_id = st.user_id
		ORDER BY l.username`, rootID)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	seen := map[string]bool{username: true}
	out := []string{username}
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, false, err
		}
		if !seen[u] {
			out = append(out, u)
			seen[u] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	var reports int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM partner_users WHERE active AND manager_user_id = $1::uuid`, rootID).Scan(&reports); err != nil {
		return nil, false, err
	}
	return out, reports > 0, nil
}

// PartnerLoginsForUsername returns every MaaS login mapped to the same partner
// user as the given username, so usage and spend aggregate across a person's
// logins (for example after an email change). A username with no partner record
// resolves to just itself, which keeps tool-facing reports working for logins
// that predate the partner directory.
func (s *Store) PartnerLoginsForUsername(ctx context.Context, username string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT other.username
		FROM partner_user_logins self
		JOIN partner_user_logins other ON other.user_id = self.user_id
		WHERE self.username = $1
		ORDER BY other.username`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]bool{username: true}
	out := []string{username}
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		if !seen[u] {
			out = append(out, u)
			seen[u] = true
		}
	}
	return out, rows.Err()
}

// PartnerIdentityForUsername resolves the canonical partner user behind a MaaS
// login and returns the configured tag value in the same round trip. A login
// with no partner record returns found=false; callers treat it as an unknown
// subject rather than hashing the username.
func (s *Store) PartnerIdentityForUsername(ctx context.Context, username, tagKey string) (subject, tagValue string, found bool, err error) {
	err = s.db.QueryRowContext(ctx, `
		SELECT p.user_id::text, COALESCE(p.tags->>$2, '')
		FROM partner_user_logins l
		JOIN partner_users p ON p.user_id = l.user_id
		WHERE l.username = $1
		LIMIT 1`, username, tagKey).Scan(&subject, &tagValue)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return subject, tagValue, true, nil
}

// UpdatePartnerUserAccess changes operator-controlled authorization fields.
// It is intentionally separate from Atlas profile PATCH so external callers
// cannot grant themselves dashboard roles.
func (s *Store) UpdatePartnerUserAccess(ctx context.Context, actor, userID, role string, managerUserID *string) (PartnerUser, error) {
	id, err := normalizePartnerUserID(userID)
	if err != nil {
		return PartnerUser{}, err
	}
	if role != PartnerRoleUser && role != PartnerRoleAdmin && role != PartnerRoleSuperAdmin {
		return PartnerUser{}, fmt.Errorf("%w: invalid role", ErrInvalidPartnerUser)
	}
	var manager *string
	var managerTag *string
	if managerUserID != nil && strings.TrimSpace(*managerUserID) != "" {
		clean, err := normalizePartnerUserID(*managerUserID)
		if err != nil || clean == id {
			return PartnerUser{}, fmt.Errorf("%w: manager_user_id must be another valid user", ErrInvalidPartnerUser)
		}
		managerTag = &clean
		manager = &clean
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PartnerUser{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM partner_users WHERE user_id=$1)`, id).Scan(&exists); err != nil {
		return PartnerUser{}, err
	}
	if !exists {
		return PartnerUser{}, ErrPartnerUserNotFound
	}
	if manager != nil {
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM partner_users WHERE user_id=$1 AND active)`, *manager).Scan(&exists); err != nil {
			return PartnerUser{}, err
		}
		if !exists {
			return PartnerUser{}, ErrPartnerUserNotFound
		}
		// Reject cycles: the proposed manager must not already report (directly
		// or transitively) to this user, which would make the hierarchy loop.
		var cycle bool
		if err := tx.QueryRowContext(ctx, `
			WITH RECURSIVE up(user_id, depth, path) AS (
				SELECT $1::uuid, 0, ARRAY[$1::uuid]
				UNION ALL
				SELECT p.manager_user_id, u.depth + 1, u.path || p.manager_user_id
				FROM partner_users p
				JOIN up u ON p.user_id = u.user_id
				WHERE p.manager_user_id IS NOT NULL AND u.depth < 1000 AND NOT p.manager_user_id = ANY(u.path)
			)
			SELECT EXISTS(SELECT 1 FROM up WHERE user_id = $2::uuid)`, *manager, id).Scan(&cycle); err != nil {
			return PartnerUser{}, err
		}
		if cycle {
			return PartnerUser{}, fmt.Errorf("%w: manager assignment would create a cycle", ErrInvalidPartnerUser)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE partner_users
		SET role=$2,
		    manager_user_id=$3,
		    tags=CASE WHEN $4::text IS NULL THEN tags - 'manager_uuid'
	              ELSE jsonb_set(tags, '{manager_uuid}', to_jsonb($4::text), true) END,
		    updated_by=$5, updated_at=NOW()
		WHERE user_id=$1`, id, role, manager, managerTag, actor); err != nil {
		return PartnerUser{}, err
	}
	if err := s.auditTx(ctx, tx, actor, "partner_user.access.update", id, map[string]any{"role": role, "manager_user_id": manager}); err != nil {
		return PartnerUser{}, err
	}
	if err := tx.Commit(); err != nil {
		return PartnerUser{}, err
	}
	return s.GetPartnerUser(ctx, id)
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
	if _, err := tx.ExecContext(ctx, `INSERT INTO partner_users (user_id,tags,manager_user_id,created_by,updated_by)
		VALUES ($1,$2,(SELECT p.user_id FROM partner_users p WHERE p.active AND p.user_id = NULLIF($2::jsonb->>'manager_uuid','')::uuid),$3,$3)`, id, string(tagsJSON), actor); err != nil {
		if isUniqueViolation(err) {
			return PartnerUser{}, ErrPartnerUserConflict
		}
		return PartnerUser{}, fmt.Errorf("create partner user: %w", err)
	}
	if _, err := reconcilePartnerManagerLinksForManagerTx(ctx, tx, id, actor); err != nil {
		return PartnerUser{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO partner_user_logins (username,user_id,is_current) VALUES ($1,$2,TRUE)`, email, id); err != nil {
		if isUniqueViolation(err) {
			return PartnerUser{}, ErrPartnerUserConflict
		}
		return PartnerUser{}, fmt.Errorf("link partner MaaS username: %w", err)
	}
	if err := s.auditTx(ctx, tx, actor, "partner_user.create", id, map[string]any{"tag_keys": partnerTagKeys(cleanTags)}); err != nil {
		return PartnerUser{}, err
	}
	if err := tx.Commit(); err != nil {
		return PartnerUser{}, err
	}
	return s.GetPartnerUser(ctx, id)
}

// reconcilePartnerManagerLinksForManagerTx repairs only reports for the
// manager affected by the current write. It keeps normal SSO writes narrow and
// uses text UUID comparison so malformed legacy tags do not abort the repair.
func reconcilePartnerManagerLinksForManagerTx(ctx context.Context, tx *sql.Tx, managerID, actor string) (int64, error) {
	result, err := tx.ExecContext(ctx, `
		UPDATE partner_users child
		SET manager_user_id = manager.user_id, updated_by = $2, updated_at = NOW()
		FROM partner_users manager
		WHERE manager.user_id = $1::uuid
		  AND manager.active
		  AND child.user_id <> manager.user_id
		  AND lower(child.tags->>'manager_uuid') = lower(manager.user_id::text)
		  AND child.manager_user_id IS DISTINCT FROM manager.user_id`, managerID, actor)
	if err != nil {
		return 0, fmt.Errorf("reconcile partner manager links: %w", err)
	}
	return result.RowsAffected()
}

// reconcilePartnerManagerLinksTx repairs all existing rows from imported
// manager_uuid tags. It is reserved for the bounded startup repair and takes a
// transaction advisory lock so multiple replicas do not perform the scan at
// the same time.
func reconcilePartnerManagerLinksTx(ctx context.Context, tx *sql.Tx, actor string) (int64, error) {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('pricetag.partner.manager.reconcile'))`); err != nil {
		return 0, fmt.Errorf("lock manager-link reconciliation: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE partner_users child
		SET manager_user_id = manager.user_id, updated_by = $1, updated_at = NOW()
		FROM partner_users manager
		WHERE manager.active
		  AND child.user_id <> manager.user_id
		  AND lower(child.tags->>'manager_uuid') = lower(manager.user_id::text)
		  AND child.manager_user_id IS DISTINCT FROM manager.user_id`, actor)
	if err != nil {
		return 0, fmt.Errorf("reconcile partner manager links: %w", err)
	}
	return result.RowsAffected()
}

// ReconcilePartnerManagerLinks repairs existing rows whose manager was
// provisioned after the employee. It is safe to run repeatedly.
func (s *Store) ReconcilePartnerManagerLinks(ctx context.Context) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	updated, err := reconcilePartnerManagerLinksTx(ctx, tx, "partner-reconcile")
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return updated, nil
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
	if _, err := tx.ExecContext(ctx, `
		UPDATE partner_users SET tags=$2,
		manager_user_id=(SELECT p.user_id FROM partner_users p WHERE p.active AND p.user_id = NULLIF($2::jsonb->>'manager_uuid','')::uuid),
			updated_by=$3,updated_at=NOW() WHERE user_id=$1`, id, string(tagsJSON), actor); err != nil {
		if isUniqueViolation(err) {
			return PartnerUser{}, ErrPartnerUserConflict
		}
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
	rows, err := s.db.QueryContext(ctx, partnerUserSelect+`
		WHERE ($1 OR p.active=TRUE) AND p.tags @> $2::jsonb
		ORDER BY p.created_at,p.user_id LIMIT $3 OFFSET $4`, includeInactive, string(filterJSON), limit+1, offset)
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
