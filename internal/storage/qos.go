package storage

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/lib/pq"
	"github.com/redhat-et/pricetag-metering/internal/metrics"
)

// QoS classes reported by the entitlement endpoint. They are additive to the
// existing quota response: the deployed gateway ignores unknown fields.
const (
	QosPremium   = "premium"
	QosMain      = "main"
	QosRatelimit = "ratelimit"
)

const qosRatelimitRetrySeconds = 30

// QosConfig is the runtime policy for weighted-token classification. It is
// deliberately separate from the monthly quota policy: this controls priority
// and local admission, not billing.
type QosConfig struct {
	Enabled             bool
	WindowSeconds       int
	HoldWindowSeconds   int
	PremiumMaxTokens    int64
	RatelimitMinTokens  int64
	HoldMainTokens      int64
	HoldRatelimitTokens int64
	CacheReadWeight     float64
	ClassCacheTTL       time.Duration
	HoldCacheTTL        time.Duration
	Providers           []string
	ExemptTagKey        string
	ExemptTagValue      string
}

// QosStatus is the per-request classification result. Subject is the
// canonical partner user UUID and stays internal to EnMaaS.
type QosStatus struct {
	Class             string
	WindowSeconds     int
	WindowTokens      int64
	HoldWindowTokens  int64
	RetryAfterSeconds int
	Subject           string
	Exempt            bool
}

type qosWindowEntry struct {
	tokens    int64
	lastClass string
	expires   time.Time
}

type qosHoldEntry struct {
	tokens  int64
	expires time.Time
}

// SetQosConfig installs the process-wide QoS policy. Call it once during
// startup, before serving traffic.
func (s *Store) SetQosConfig(cfg QosConfig) {
	if cfg.WindowSeconds <= 0 {
		cfg.WindowSeconds = 60
	}
	if cfg.HoldWindowSeconds <= 0 {
		cfg.HoldWindowSeconds = 300
	}
	if cfg.ClassCacheTTL <= 0 {
		cfg.ClassCacheTTL = 15 * time.Second
	}
	if cfg.HoldCacheTTL <= 0 {
		cfg.HoldCacheTTL = 60 * time.Second
	}
	if cfg.CacheReadWeight <= 0 || !isFinite(cfg.CacheReadWeight) {
		cfg.CacheReadWeight = 0.05
	}
	if len(cfg.Providers) == 0 {
		cfg.Providers = []string{"cb-glm"}
	}
	cfg.Providers = append([]string(nil), cfg.Providers...)

	s.qosMu.Lock()
	s.qosConfig = cfg
	s.qosWindow = make(map[string]qosWindowEntry)
	s.qosHold = make(map[string]qosHoldEntry)
	s.qosMu.Unlock()
	s.qosEnabled.Store(cfg.Enabled)
}

// GetQosStatus classifies the caller from weighted token usage over the short
// and hold windows. It returns premium for exempt or unknown-subject users
// without querying usage_events.
func (s *Store) GetQosStatus(ctx context.Context, username string, decision QuotaDecision, exempt bool) (QosStatus, error) {
	cfg := s.qosConfig
	status := QosStatus{
		Class:             QosPremium,
		WindowSeconds:     cfg.WindowSeconds,
		RetryAfterSeconds: 0,
		Subject:           decision.Subject,
		Exempt:            exempt || decision.TagExempt,
	}
	if !cfg.Enabled {
		return status, nil
	}
	if status.Exempt {
		metrics.QosClassDecisionsTotal.WithLabelValues(QosPremium, "false").Inc()
		return status, nil
	}
	if decision.Subject == "" {
		// No canonical partner identity means we cannot key per-person
		// state. Use the conservative main class instead of premium.
		metrics.QosUnmatchedUsersTotal.Inc()
		status.Class = QosMain
		metrics.QosClassDecisionsTotal.WithLabelValues(QosMain, "false").Inc()
		return status, nil
	}

	key := decision.Subject
	now := time.Now()

	s.qosMu.Lock()
	windowEntry, windowFound := s.qosWindow[key]
	holdEntry, holdFound := s.qosHold[key]
	s.qosMu.Unlock()

	windowValid := windowFound && now.Before(windowEntry.expires)
	holdValid := holdFound && now.Before(holdEntry.expires)
	cached := windowValid && holdValid

	windowTokens := windowEntry.tokens
	holdTokens := holdEntry.tokens
	if !cached {
		needWindow := !windowValid
		needHold := !holdValid
		start := time.Now()
		queriedWindow, queriedHold, err := s.queryQosTokens(ctx, username, decision.Logins, cfg, needWindow, needHold)
		metrics.QosQueryDurationSeconds.Observe(time.Since(start).Seconds())
		if err != nil {
			return status, err
		}
		metrics.QosCacheMissesTotal.Inc()
		if needWindow {
			windowTokens = queriedWindow
		}
		if needHold {
			holdTokens = queriedHold
		}
		if needWindow {
			s.qosMu.Lock()
			s.qosWindow[key] = qosWindowEntry{
				tokens:  windowTokens,
				expires: now.Add(cfg.ClassCacheTTL),
			}
			s.qosMu.Unlock()
		}
		if needHold {
			s.qosMu.Lock()
			s.qosHold[key] = qosHoldEntry{
				tokens:  holdTokens,
				expires: now.Add(cfg.HoldCacheTTL),
			}
			s.qosMu.Unlock()
		}
	} else {
		metrics.QosCacheHitsTotal.Inc()
	}

	class := classifyQos(windowTokens, holdTokens, cfg)
	if windowFound && windowEntry.lastClass != "" && windowEntry.lastClass != class {
		metrics.QosClassTransitionsTotal.WithLabelValues(windowEntry.lastClass, class).Inc()
	}
	s.qosMu.Lock()
	if entry, ok := s.qosWindow[key]; ok {
		entry.lastClass = class
		s.qosWindow[key] = entry
	}
	s.qosMu.Unlock()

	status.Class = class
	status.WindowTokens = windowTokens
	status.HoldWindowTokens = holdTokens
	if class == QosRatelimit {
		status.RetryAfterSeconds = qosRatelimitRetrySeconds
		metrics.QosRatelimitedTotal.Inc()
	}
	cachedLabel := "false"
	if cached {
		cachedLabel = "true"
	}
	metrics.QosClassDecisionsTotal.WithLabelValues(class, cachedLabel).Inc()
	metrics.QosWindowTokens.Observe(float64(windowTokens))
	return status, nil
}

func (s *Store) queryQosTokens(ctx context.Context, username string, logins []string, cfg QosConfig, needWindow, needHold bool) (int64, int64, error) {
	if len(logins) == 0 {
		logins = []string{username}
	}
	whereSeconds := cfg.WindowSeconds
	if needHold {
		whereSeconds = cfg.HoldWindowSeconds
	}
	providerClause := "provider = ANY($3)"
	var providerArg any = pq.Array(cfg.Providers)
	if len(cfg.Providers) == 1 {
		// A constant equality lets PostgreSQL use the partial cb-glm
		// covering index; ANY() does not prove the partial predicate.
		providerClause = "provider = $3"
		providerArg = cfg.Providers[0]
	}
	query := fmt.Sprintf(`
		SELECT
			COALESCE(SUM(
				GREATEST(prompt_tokens - cached_input_tokens - cache_creation_tokens, 0)
				+ cache_creation_tokens + completion_tokens
				+ $5::float8 * cached_input_tokens
			) FILTER (WHERE timestamp >= now() - make_interval(secs => $2::int)), 0)::bigint,
			COALESCE(SUM(
				GREATEST(prompt_tokens - cached_input_tokens - cache_creation_tokens, 0)
				+ cache_creation_tokens + completion_tokens
				+ $5::float8 * cached_input_tokens
			), 0)::bigint
		FROM usage_events
		WHERE username = ANY($1)
		  AND %s
		  AND timestamp >= now() - make_interval(secs => $4::int)`, providerClause)
	var windowTokens, holdTokens int64
	err := s.db.QueryRowContext(ctx, query,
		pq.Array(logins),
		cfg.WindowSeconds,
		providerArg,
		whereSeconds,
		cfg.CacheReadWeight,
	).Scan(&windowTokens, &holdTokens)
	return windowTokens, holdTokens, err
}

func classifyQos(windowTokens, holdTokens int64, cfg QosConfig) string {
	if windowTokens >= cfg.RatelimitMinTokens || holdTokens >= cfg.HoldRatelimitTokens {
		return QosRatelimit
	}
	if windowTokens >= cfg.PremiumMaxTokens || holdTokens >= cfg.HoldMainTokens {
		return QosMain
	}
	return QosPremium
}

func isFinite(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0)
}
