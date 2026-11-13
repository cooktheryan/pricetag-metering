package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
)

// LoginProvision is an operator-owned profile contract for non-email identities.
// Partner/SSO profile validation remains unchanged.
type LoginProvision struct {
	Subject string `json:"subject"`
	Name    string `json:"name"`
	Role    string `json:"role,omitempty"`
	Active  *bool  `json:"active,omitempty"`
}

var loginSubjectPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$`)

// ManagedUserByLogin resolves a target for authorized administrative operations,
// including suspended identities and retained logins. Never use this to
// authenticate a caller; PartnerUserByMaaSUsername enforces current + active.
func (s *Store) ManagedUserByLogin(ctx context.Context, username string) (PartnerUser, error) {
	return s.partnerUserForPolicy(ctx, username)
}

// ProvisionLogin preserves an existing login's UUID and all usage records.
// It does not create keys or change budgets. Those are separate API operations.
func (s *Store) ProvisionLogin(ctx context.Context, actor string, p LoginProvision) (PartnerUser, error) {
	// Logins resolve case-insensitively everywhere (LOWER(username) =
	// LOWER($1)); provisioning must not be able to mint a second case-variant
	// identity for a person whose login already exists. Canonicalize the
	// subject first so the advisory lock, the duplicate check, and the stored
	// spelling all use one form.
	p.Subject = strings.ToLower(strings.TrimSpace(p.Subject))
	if !loginSubjectPattern.MatchString(p.Subject) || len(p.Name) > 256 {
		return PartnerUser{}, fmt.Errorf("invalid subject or name")
	}
	if p.Role != "" && p.Role != PartnerRoleUser && p.Role != PartnerRoleAdmin && p.Role != PartnerRoleSuperAdmin {
		return PartnerUser{}, fmt.Errorf("invalid role")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PartnerUser{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('metering-login'),hashtext($1))`, p.Subject); err != nil {
		return PartnerUser{}, err
	}
	var id string
	// Match case-insensitively so a differently spelled provision reuses the
	// existing account instead of creating a case-variant twin. The ORDER BY
	// keeps the pick stable on databases that still carry rows provisioned
	// before this normalization.
	err = tx.QueryRowContext(ctx, `SELECT user_id FROM partner_user_logins WHERE LOWER(username)=$1 ORDER BY is_current DESC, username LIMIT 1`, p.Subject).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		var b [16]byte
		if _, err = rand.Read(b[:]); err != nil {
			return PartnerUser{}, err
		}
		b[6] = (b[6] & 15) | 64
		b[8] = (b[8] & 63) | 128
		id = fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
		name := p.Name
		if name == "" {
			name = p.Subject
		}
		tags, _ := json.Marshal(map[string]string{"first_name": name})
		if _, err = tx.ExecContext(ctx, `INSERT INTO partner_users(user_id,tags,created_by,updated_by) VALUES($1,$2,$3,$3)`, id, string(tags), actor); err != nil {
			return PartnerUser{}, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO partner_user_logins(username,user_id,is_current) VALUES($1,$2,true)`, p.Subject, id); err != nil {
			return PartnerUser{}, err
		}
	} else if err != nil {
		return PartnerUser{}, err
	}
	if p.Name != "" {
		if _, err = tx.ExecContext(ctx, `UPDATE partner_users SET tags=tags||jsonb_build_object('first_name',$2::text),updated_by=$3,updated_at=now() WHERE user_id=$1`, id, p.Name, actor); err != nil {
			return PartnerUser{}, err
		}
	}
	if p.Role != "" {
		if _, err = tx.ExecContext(ctx, `UPDATE partner_users SET role=$2,updated_by=$3,updated_at=now() WHERE user_id=$1`, id, p.Role, actor); err != nil {
			return PartnerUser{}, err
		}
	}
	if p.Active != nil {
		result, updateErr := tx.ExecContext(ctx, `UPDATE partner_users SET active=$2,updated_by=$3,updated_at=now() WHERE user_id=$1 AND NOT key_revocation_pending`, id, *p.Active, actor)
		if updateErr != nil {
			return PartnerUser{}, updateErr
		}
		changed, updateErr := result.RowsAffected()
		if updateErr != nil {
			return PartnerUser{}, updateErr
		}
		if changed != 1 {
			return PartnerUser{}, fmt.Errorf("profile activation cannot change while key revocation is pending")
		}
	}
	detail, _ := json.Marshal(p)
	if _, err = tx.ExecContext(ctx, `INSERT INTO org_audit(actor,action,target,detail) VALUES($1,'login.provision',$2,$3)`, actor, p.Subject, string(detail)); err != nil {
		return PartnerUser{}, err
	}
	if err = tx.Commit(); err != nil {
		return PartnerUser{}, err
	}
	s.invalidateQuotaCache()
	return s.GetPartnerUser(ctx, id)
}

// PartnerUserIDByLogin resolves any login spelling, current or retained, to
// its stable user ID with the exact resolution ProvisionLogin applies. The
// management self-protection guard uses it to compare stable identities:
// login spellings change when an account is renamed, and a retained login
// still resolves to the renamed account.
func (s *Store) PartnerUserIDByLogin(ctx context.Context, username string) (string, error) {
	var id string
	// The exact resolution ProvisionLogin applies — normalized and
	// case-insensitive over every spelling, current or retained — so the
	// management self-guard cannot be bypassed with a case or whitespace
	// variant of a login. The ORDER BY keeps the pick stable on databases
	// that still carry pre-normalization case variants.
	username = strings.ToLower(strings.TrimSpace(username))
	err := s.db.QueryRowContext(ctx, `SELECT user_id FROM partner_user_logins WHERE LOWER(username)=$1 ORDER BY is_current DESC, username LIMIT 1`, username).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrPartnerUserNotFound
	}
	return id, err
}

// ManagedPrice sets a future rate or snapshots a reviewed source under an alias.
// Existing event charges are immutable; historical repricing is a separate API.
type ManagedPrice struct {
	Model       string   `json:"model"`
	Provider    string   `json:"provider"`
	SourceModel string   `json:"source_model,omitempty"`
	Input       *float64 `json:"input_cost_per_mtok,omitempty"`
	Output      *float64 `json:"output_cost_per_mtok,omitempty"`
	CacheWrite  *float64 `json:"cache_write_cost_per_mtok,omitempty"`
	CacheRead   *float64 `json:"cache_read_cost_per_mtok,omitempty"`
}

func (s *Store) SetManagedPrice(ctx context.Context, actor string, p ManagedPrice) error {
	if strings.TrimSpace(p.Model) == "" || len(p.Model) > 256 || len(p.Provider) > 128 {
		return fmt.Errorf("invalid model/provider")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('model-price'),hashtext($1))`, p.Model); err != nil {
		return err
	}
	var rates [4]float64
	if p.SourceModel != "" {
		if p.Input != nil || p.Output != nil || p.CacheWrite != nil || p.CacheRead != nil {
			return fmt.Errorf("choose source_model or explicit rates")
		}
		if p.SourceModel == p.Model {
			return fmt.Errorf("source model must differ from the target model")
		}
		if err = tx.QueryRowContext(ctx, `SELECT input_cost_per_mtok,output_cost_per_mtok,cache_write_cost_per_mtok,cache_read_cost_per_mtok FROM model_pricing WHERE model=$1`, p.SourceModel).Scan(&rates[0], &rates[1], &rates[2], &rates[3]); err != nil {
			return err
		}
		// Rates copied from another row get the same validation as explicit
		// ones; a malformed legacy source row must not install bad rates.
		for _, v := range rates {
			if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1000000 {
				return fmt.Errorf("source model rates are not four nonnegative finite values")
			}
		}
	} else {
		for i, v := range []*float64{p.Input, p.Output, p.CacheWrite, p.CacheRead} {
			if v == nil || math.IsNaN(*v) || math.IsInf(*v, 0) || *v < 0 || *v > 1000000 {
				return fmt.Errorf("four nonnegative finite rates are required")
			}
			rates[i] = *v
		}
	}
	// Preserve charges from older, not-yet-backfilled ledger rows before changing rates.
	if _, err = tx.ExecContext(ctx, fmt.Sprintf(`UPDATE usage_events u SET cost_usd=q.cost FROM (SELECT e.id,%s AS cost FROM usage_events e LEFT JOIN model_pricing p ON p.model=e.model WHERE e.model=$1 AND e.cost_usd IS NULL) q WHERE u.id=q.id`, currentPriceUSDExpr), p.Model); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO model_pricing(model,provider,input_cost_per_mtok,output_cost_per_mtok,cache_write_cost_per_mtok,cache_read_cost_per_mtok,managed_rate) VALUES($1,$2,$3,$4,$5,$6,true) ON CONFLICT(model) DO UPDATE SET provider=EXCLUDED.provider,input_cost_per_mtok=EXCLUDED.input_cost_per_mtok,output_cost_per_mtok=EXCLUDED.output_cost_per_mtok,cache_write_cost_per_mtok=EXCLUDED.cache_write_cost_per_mtok,cache_read_cost_per_mtok=EXCLUDED.cache_read_cost_per_mtok,managed_rate=true`, p.Model, p.Provider, rates[0], rates[1], rates[2], rates[3]); err != nil {
		return err
	}
	detail, _ := json.Marshal(map[string]any{"request": p, "resolved_rates": rates})
	if _, err = tx.ExecContext(ctx, `INSERT INTO org_audit(actor,action,target,detail) VALUES($1,'pricing.rate_set',$2,$3)`, actor, p.Model, string(detail)); err != nil {
		return err
	}
	return tx.Commit()
}
