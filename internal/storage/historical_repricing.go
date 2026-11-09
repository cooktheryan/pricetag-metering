package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/redhat-et/pricetag-metering/internal/pricing"
)

// HistoricalRepriceRequest scopes a deterministic recomputation from token
// counts and the current effective model_pricing rows. It never multiplies an
// existing cost_usd value, so repeating the operation is idempotent.
type HistoricalRepriceRequest struct {
	Provider    string    `json:"provider"`
	Model       string    `json:"model"`
	ModelPrefix string    `json:"model_prefix"`
	From        time.Time `json:"from"`
	Until       time.Time `json:"until"`
	Policy      string    `json:"policy_version"`
	Confirm     bool      `json:"confirm"`
	OperationID string    `json:"operation_id"`
	PolicyHash  string    `json:"policy_hash"`
}

type HistoricalRepriceResult struct {
	Rows            int64     `json:"rows"`
	OldTotal        float64   `json:"old_total_usd"`
	NewTotal        float64   `json:"new_total_usd"`
	From            time.Time `json:"from"`
	Until           time.Time `json:"until"`
	Applied         bool      `json:"applied"`
	Policy          string    `json:"policy_version,omitempty"`
	OperationID     string    `json:"operation_id,omitempty"`
	PolicyHash      string    `json:"policy_hash,omitempty"`
	Status          string    `json:"status,omitempty"`
	CompletedChunks int       `json:"completed_chunks,omitempty"`
	TotalChunks     int       `json:"total_chunks,omitempty"`
}

// discountPolicyHash is retained as a stable policy-only fingerprint for
// callers/tests; operation.PolicyHash additionally binds the model_pricing
// snapshot selected by the request.
func discountPolicyHash(policy pricing.DiscountPolicy) (string, error) {
	raw, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("marshal discount policy: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

type repriceOperation struct {
	ID, Actor, Provider, Model, ModelPrefix string
	From, Until                             time.Time
	PolicyVersion, PolicyHash, Status       string
	TotalChunks, CompletedChunks            int
}

func newOperationID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Store) pricingSnapshotHash(ctx context.Context, where string, args []any, policyVersion string) (string, error) {
	q := fmt.Sprintf(`SELECT COALESCE(p.model,''), COALESCE(p.provider,''),
		COALESCE(p.input_cost_per_mtok,0), COALESCE(p.output_cost_per_mtok,0),
		COALESCE(p.cache_read_cost_per_mtok,0), COALESCE(p.cache_write_cost_per_mtok,0)
		FROM usage_events e LEFT JOIN model_pricing p ON p.model=e.model
		WHERE %s GROUP BY p.model,p.provider,p.input_cost_per_mtok,p.output_cost_per_mtok,p.cache_read_cost_per_mtok,p.cache_write_cost_per_mtok
		ORDER BY p.model,p.provider`, where[5:])
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	h := sha256.New()
	_, _ = h.Write([]byte(policyVersion + "\n"))
	for rows.Next() {
		var model, provider string
		var in, out, read, write float64
		if err := rows.Scan(&model, &provider, &in, &out, &read, &write); err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s\x00%s\x00%.12g\x00%.12g\x00%.12g\x00%.12g\n", model, provider, in, out, read, write)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *Store) createRepriceOperation(ctx context.Context, op repriceOperation, result HistoricalRepriceResult) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO pricing_reprice_operations
		(operation_id,actor,provider,model,model_prefix,from_ts,until_ts,policy_version,policy_hash,status,total_chunks,rows,old_total_usd,new_total_usd)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		op.ID, op.Actor, op.Provider, op.Model, op.ModelPrefix, op.From, op.Until, op.PolicyVersion, op.PolicyHash, op.Status, op.TotalChunks, result.Rows, result.OldTotal, result.NewTotal)
	return err
}

func (s *Store) loadRepriceOperation(ctx context.Context, id string) (repriceOperation, error) {
	var op repriceOperation
	err := s.db.QueryRowContext(ctx, `SELECT operation_id,actor,provider,model,model_prefix,from_ts,until_ts,policy_version,policy_hash,status,total_chunks,completed_chunks FROM pricing_reprice_operations WHERE operation_id=$1`, id).Scan(
		&op.ID, &op.Actor, &op.Provider, &op.Model, &op.ModelPrefix, &op.From, &op.Until, &op.PolicyVersion, &op.PolicyHash, &op.Status, &op.TotalChunks, &op.CompletedChunks)
	return op, err
}

func (s *Store) updateRepriceProgress(ctx context.Context, id, status, problem string, completed int) error {
	_, err := s.db.ExecContext(ctx, `UPDATE pricing_reprice_operations SET status=$2, completed_chunks=$3, error=$4, updated_at=now() WHERE operation_id=$1`, id, status, completed, problem)
	return err
}

func (s *Store) RepriceOperationStatus(ctx context.Context, id string) (HistoricalRepriceResult, error) {
	op, err := s.loadRepriceOperation(ctx, id)
	if err != nil {
		return HistoricalRepriceResult{}, err
	}
	var result HistoricalRepriceResult
	result.OperationID, result.PolicyHash, result.Policy = op.ID, op.PolicyHash, op.PolicyVersion
	result.From, result.Until = op.From, op.Until
	result.Status, result.CompletedChunks, result.TotalChunks = op.Status, op.CompletedChunks, op.TotalChunks
	return result, nil
}

func buildRepriceWhere(req HistoricalRepriceRequest) (string, []any, error) {
	if req.From.IsZero() || req.Until.IsZero() || !req.From.Before(req.Until) {
		return "", nil, fmt.Errorf("from and until are required and until must be after from")
	}
	if req.Until.Sub(req.From) > 366*24*time.Hour {
		return "", nil, fmt.Errorf("repricing range cannot exceed 366 days")
	}
	if req.Provider == "" && req.Model == "" && req.ModelPrefix == "" {
		return "", nil, fmt.Errorf("provider, model, or model_prefix is required")
	}
	where := []string{"e.timestamp >= $1", "e.timestamp < $2"}
	args := []any{req.From, req.Until}
	if req.Provider != "" {
		args = append(args, req.Provider)
		where = append(where, fmt.Sprintf("e.provider = $%d", len(args)))
	}
	if req.Model != "" {
		args = append(args, req.Model)
		where = append(where, fmt.Sprintf("e.model = $%d", len(args)))
	}
	if req.ModelPrefix != "" {
		// Compare the prefix literally; LIKE would interpret user-supplied
		// '%' and '_' as wildcards and could reprice unintended models.
		args = append(args, req.ModelPrefix)
		where = append(where, fmt.Sprintf("LEFT(e.model, LENGTH($%d)) = $%d", len(args), len(args)))
	}
	return " AND " + joinSQL(where), args, nil
}

func joinSQL(parts []string) string {
	out := ""
	for i, part := range parts {
		if i > 0 {
			out += " AND "
		}
		out += part
	}
	return out
}

func (s *Store) RepriceHistorical(ctx context.Context, actor string, req HistoricalRepriceRequest) (HistoricalRepriceResult, error) {
	if req.Policy == "" {
		return HistoricalRepriceResult{}, fmt.Errorf("policy_version is required")
	}
	activePolicy, err := s.GetPricingDiscountPolicy(ctx)
	if err != nil {
		return HistoricalRepriceResult{}, fmt.Errorf("load active pricing policy: %w", err)
	}
	if req.Policy != activePolicy.Version {
		return HistoricalRepriceResult{}, fmt.Errorf("policy_version %q is not the active policy %q", req.Policy, activePolicy.Version)
	}
	where, args, err := buildRepriceWhere(req)
	if err != nil {
		return HistoricalRepriceResult{}, err
	}
	query := fmt.Sprintf(`SELECT COUNT(*), COALESCE(SUM(e.cost_usd),0), COALESCE(SUM(%s),0)
		FROM usage_events e LEFT JOIN model_pricing p ON p.model=e.model
		WHERE %s`, currentPriceUSDExpr, where[5:])
	var result HistoricalRepriceResult
	result.From, result.Until, result.Policy = req.From, req.Until, req.Policy
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&result.Rows, &result.OldTotal, &result.NewTotal); err != nil {
		return HistoricalRepriceResult{}, err
	}
	snapshotHash, err := s.pricingSnapshotHash(ctx, where, args, req.Policy)
	if err != nil {
		return HistoricalRepriceResult{}, fmt.Errorf("create pricing snapshot: %w", err)
	}
	result.PolicyHash = snapshotHash
	if !req.Confirm {
		id, err := newOperationID()
		if err != nil {
			return HistoricalRepriceResult{}, err
		}
		_, _, totalChunks := repriceHourBounds(req.From, req.Until)
		if err := s.createRepriceOperation(ctx, repriceOperation{ID: id, Actor: actor, Provider: req.Provider, Model: req.Model, ModelPrefix: req.ModelPrefix, From: req.From, Until: req.Until, PolicyVersion: req.Policy, PolicyHash: snapshotHash, Status: "dry_run", TotalChunks: totalChunks}, result); err != nil {
			return HistoricalRepriceResult{}, err
		}
		result.OperationID, result.Status, result.TotalChunks = id, "dry_run", totalChunks
		return result, nil
	}
	if req.OperationID == "" || req.PolicyHash == "" {
		return HistoricalRepriceResult{}, fmt.Errorf("operation_id and policy_hash are required for confirmation")
	}
	if req.PolicyHash != snapshotHash {
		return HistoricalRepriceResult{}, fmt.Errorf("pricing snapshot changed; run a new dry-run")
	}
	op, err := s.loadRepriceOperation(ctx, req.OperationID)
	if err != nil {
		return HistoricalRepriceResult{}, fmt.Errorf("load repricing operation: %w", err)
	}
	if op.PolicyHash != req.PolicyHash || op.PolicyVersion != req.Policy || op.Provider != req.Provider || op.Model != req.Model || op.ModelPrefix != req.ModelPrefix || !op.From.Equal(req.From) || !op.Until.Equal(req.Until) {
		return HistoricalRepriceResult{}, fmt.Errorf("confirmation does not match repricing operation")
	}
	if op.Status == "completed" {
		result.OperationID, result.Status, result.CompletedChunks, result.TotalChunks = op.ID, op.Status, op.CompletedChunks, op.TotalChunks
		result.Applied = true
		return result, nil
	}
	if err := s.updateRepriceProgress(ctx, op.ID, "running", "", op.CompletedChunks); err != nil {
		return HistoricalRepriceResult{}, err
	}

	fromHour, untilHour, _ := repriceHourBounds(req.From, req.Until)
	// Apply one UTC hour per transaction. This bounds locks, WAL, and rollback
	// scope even when an operator requests a long historical range.
	for i, hour := 0, fromHour.Add(time.Duration(op.CompletedChunks)*time.Hour); hour.Before(untilHour); i, hour = i+1, hour.Add(time.Hour) {
		chunkUntil := hour.Add(time.Hour)
		if chunkUntil.After(untilHour) {
			chunkUntil = untilHour
		}
		chunkReq := req
		if chunkReq.From.Before(hour) {
			chunkReq.From = hour
		}
		if chunkReq.Until.After(chunkUntil) {
			chunkReq.Until = chunkUntil
		}
		chunkWhere, chunkArgs, err := buildRepriceWhere(chunkReq)
		if err != nil {
			return HistoricalRepriceResult{}, err
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return HistoricalRepriceResult{}, err
		}
		update := fmt.Sprintf(`UPDATE usage_events u SET cost_usd = r.new_cost
			FROM (SELECT e.id, %s AS new_cost FROM usage_events e LEFT JOIN model_pricing p ON p.model=e.model WHERE %s) r
			WHERE u.id=r.id`, currentPriceUSDExpr, chunkWhere[5:])
		if _, err = tx.ExecContext(ctx, update, chunkArgs...); err == nil {
			_, err = tx.ExecContext(ctx, rebuildHourLockSQL, hour, chunkUntil)
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, `DELETE FROM usage_hourly WHERE hour >= $1 AND hour < $2`, hour, chunkUntil)
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, rebuildHourSQL, hour, chunkUntil)
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, rebuildToolHourLockSQL, hour, chunkUntil)
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, rebuildToolHourSQL, hour, chunkUntil)
		}
		if err == nil {
			err = s.auditTx(ctx, tx, actor, "pricing.historical_reprice", "usage_events", map[string]any{
				"provider": req.Provider, "model": req.Model, "model_prefix": req.ModelPrefix,
				"from": chunkReq.From, "until": chunkReq.Until, "policy_version": req.Policy,
				"rows": result.Rows, "old_total_usd": result.OldTotal, "new_total_usd": result.NewTotal,
			})
		}
		if err != nil {
			_ = tx.Rollback()
			_ = s.updateRepriceProgress(ctx, op.ID, "failed", err.Error(), op.CompletedChunks+i)
			return HistoricalRepriceResult{}, fmt.Errorf("reprice hour %s: %w", hour.Format(time.RFC3339), err)
		}
		if err = tx.Commit(); err != nil {
			_ = s.updateRepriceProgress(ctx, op.ID, "failed", err.Error(), op.CompletedChunks+i)
			return HistoricalRepriceResult{}, fmt.Errorf("commit reprice hour %s: %w", hour.Format(time.RFC3339), err)
		}
		if err := s.updateRepriceProgress(ctx, op.ID, "running", "", op.CompletedChunks+i+1); err != nil {
			return HistoricalRepriceResult{}, err
		}
	}
	if err := s.updateRepriceProgress(ctx, op.ID, "completed", "", op.TotalChunks); err != nil {
		return HistoricalRepriceResult{}, err
	}
	result.Applied = true
	result.OperationID, result.Status, result.CompletedChunks, result.TotalChunks = op.ID, "completed", op.TotalChunks, op.TotalChunks
	s.parityHealthy.Store(false)
	s.servingRollups.Store(false)
	// Publish the invalidation so the worker's next parity pass rechecks and
	// the parity metric turns red. This is not a read-gate switch: a deployment
	// that already confirmed parity keeps serving the continuously rebuilt
	// rollups under the documented serve-stale policy (parityConfirmed is
	// deliberately not cleared here). Use a detached context: the HTTP request
	// may be cancelled after a long repricing run, and losing this signal would
	// leave the metric green until the next scheduled pass.
	metaCtx, cancelMeta := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelMeta()
	if _, err := s.metaSetParity(metaCtx, false, time.Now().UTC(), time.Time{}); err != nil {
		slog.Warn("failed to invalidate shared rollup parity state", "error", err)
	}
	return result, nil
}

// repriceHourBounds returns UTC hour buckets covering the request. The
// mutation chunks are clipped back to the exact request interval below, so a
// partial first/last hour never expands the scope of the update.
func repriceHourBounds(from, until time.Time) (time.Time, time.Time, int) {
	fromHour := from.UTC().Truncate(time.Hour)
	untilHour := until.UTC().Truncate(time.Hour)
	if until.After(untilHour) {
		untilHour = untilHour.Add(time.Hour)
	}
	chunks := int(untilHour.Sub(fromHour) / time.Hour)
	if chunks < 1 {
		chunks = 1
	}
	return fromHour, untilHour, chunks
}
