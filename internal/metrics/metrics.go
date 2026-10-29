// Package metrics exposes the metering service's Prometheus instrumentation.
//
// Every collector is registered on one package-level registry served at /metrics on a
// dedicated listener (METRICS_PORT, default 9902) so the application listener
// on 8080 carries zero scrape load.
package metrics

import (
	"math"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	reg = prometheus.NewRegistry()

	// RequestsTotal counts every HTTP request the application listener serves.
	RequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "metering_requests_total",
		Help: "Total HTTP requests served by the metering application listener.",
	}, []string{"path", "code"})

	// HTTPRequestDurationSeconds observes the latency of application requests.
	HTTPRequestDurationSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "metering_http_request_duration_seconds",
		Help:    "HTTP request latency for the metering application listener.",
		Buckets: prometheus.DefBuckets,
	}, []string{"path", "code"})

	// EventsIngestedTotal counts CloudEvents written to the ledger, keyed by the
	// outcome of Store.InsertEvent.
	EventsIngestedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "metering_events_ingested_total",
		Help: "CloudEvents written to the ledger, keyed by outcome (accepted, replayed, error).",
	}, []string{"result"})

	// UsageEventInsertDurationSeconds observes the hot-path insert (drives RDS
	// write IOPS on stage).
	UsageEventInsertDurationSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "metering_usage_event_insert_duration_seconds",
		Help:    "Duration of Store.InsertEvent (ledger row + hourly rollup in one transaction).",
		Buckets: prometheus.DefBuckets,
	})

	// UsageEventInsertErrorsTotal counts failed inserts.
	UsageEventInsertErrorsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "metering_usage_event_insert_errors_total",
		Help: "Failed Store.InsertEvent calls.",
	})

	// DBPoolOpenConns, DBPoolInUseConns and DBPoolIdleConns are gauges
	// from sql.DBStats for the primary pool.
	DBPoolOpenConns = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "metering_db_pool_open_conns",
		Help: "Open connections in the primary database pool.",
	})
	DBPoolInUseConns = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "metering_db_pool_in_use_conns",
		Help: "In-use connections in the primary database pool.",
	})
	DBPoolIdleConns = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "metering_db_pool_idle_conns",
		Help: "Idle connections in the primary database pool.",
	})

	// DBPoolWaitCountTotal and DBPoolWaitSecondsTotal observe pool waits
	// (queued balance checks signal that MaxOpenConns is too low).
	DBPoolWaitCountTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "metering_db_pool_wait_count_total",
		Help: "Total number of connections the pool had to wait for.",
	})
	DBPoolWaitSecondsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "metering_db_pool_wait_seconds_total",
		Help: "Total time blocked waiting for a free connection in the primary pool.",
	})

	// QuotaChecksTotal counts entitlement quota decisions, keyed by result
	// (allowed/denied) and whether the decision came from the in-memory cache.
	QuotaChecksTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "metering_quota_checks_total",
		Help: "Entitlement quota decisions, keyed by result and cache hit.",
	}, []string{"result", "cached"})

	// QuotaDenialsTotal counts recorded quota denials.
	QuotaDenialsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "metering_quota_denials_total",
		Help: "Quota denials recorded via RecordQuotaDenial.",
	})

	// QosClassDecisionsTotal counts QoS classification decisions by class
	// and whether the result was served from the process-local cache.
	QosClassDecisionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "metering_qos_class_decisions_total",
		Help: "QoS class decisions, keyed by class and cache hit.",
	}, []string{"class", "cached"})

	// QosWindowTokens observes weighted tokens in the short classification
	// window.
	QosWindowTokens = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "metering_qos_window_tokens",
		Help:    "Weighted tokens in the short QoS classification window.",
		Buckets: []float64{10_000, 50_000, 100_000, 500_000, 1_000_000, 2_000_000, 5_000_000, 10_000_000},
	})

	// QosClassTransitionsTotal counts class transitions observed by this
	// process. The label pair is bounded by the three class values.
	QosClassTransitionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "metering_qos_class_transitions_total",
		Help: "Observed QoS class transitions, keyed by previous and next class.",
	}, []string{"from", "to"})

	// QosRatelimitedTotal counts decisions that entered ratelimit.
	QosRatelimitedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "metering_qos_ratelimited_total",
		Help: "QoS decisions that classified the caller as ratelimit.",
	})

	// QosUnmatchedUsersTotal counts entitlement decisions for callers with
	// no partner-user identity. These are treated as premium and are
	// expected to be zero in normal operation.
	QosUnmatchedUsersTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "metering_qos_unmatched_users_total",
		Help: "QoS decisions for callers without a partner-user identity.",
	})

	// QosQueryDurationSeconds observes the usage_events classification query.
	QosQueryDurationSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "metering_qos_query_duration_seconds",
		Help:    "Duration of the weighted-token classification query.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
	})

	// QosCacheHitsTotal and QosCacheMissesTotal split class decisions by
	// whether they required a usage_events query.
	QosCacheHitsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "metering_qos_cache_hits_total",
		Help: "QoS class decisions served from the process-local cache.",
	})
	QosCacheMissesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "metering_qos_cache_misses_total",
		Help: "QoS class decisions that required a usage_events query.",
	})

	// KeysMintedTotal counts API keys minted through the keys handler.
	KeysMintedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "metering_keys_minted_total",
		Help: "API keys minted.",
	})

	// UsageReportDurationSeconds observes partner usage report generation.
	UsageReportDurationSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "metering_usage_report_duration_seconds",
		Help:    "Duration of partner user usage report generation.",
		Buckets: prometheus.DefBuckets,
	})

	// RollupRefreshDurationSeconds observes one rollup maintenance pass.
	RollupRefreshDurationSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "metering_rollup_refresh_duration_seconds",
		Help:    "Duration of a rollup maintenance refresh (recent hours + parity check).",
		Buckets: prometheus.DefBuckets,
	})

	// RollupParityGreen is 1 while the standing rollup parity check is green.
	RollupParityGreen = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "metering_rollup_parity_green",
		Help: "1 when the standing rollup parity check is green, 0 when red, NaN when the last check failed.",
	})

	// RollupParityCheckedAtSeconds is the unix time of the last COMPLETED
	// parity pass. It advances only on success, so a stale value alongside NaN
	// (or a stale green) is distinguishable from a current result.
	RollupParityCheckedAtSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "metering_rollup_parity_checked_at_seconds",
		Help: "Unix time of the last completed rollup parity check.",
	})

	// RollupBackfillDurationSeconds observes one rollup backfill pass.
	RollupBackfillDurationSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "metering_rollup_backfill_duration_seconds",
		Help:    "Duration of a rollup backfill pass.",
		Buckets: prometheus.DefBuckets,
	})

	collectors = []prometheus.Collector{
		RequestsTotal,
		HTTPRequestDurationSeconds,
		EventsIngestedTotal,
		UsageEventInsertDurationSeconds,
		UsageEventInsertErrorsTotal,
		DBPoolOpenConns,
		DBPoolInUseConns,
		DBPoolIdleConns,
		DBPoolWaitCountTotal,
		DBPoolWaitSecondsTotal,
		QuotaChecksTotal,
		QuotaDenialsTotal,
		QosClassDecisionsTotal,
		QosWindowTokens,
		QosClassTransitionsTotal,
		QosRatelimitedTotal,
		QosUnmatchedUsersTotal,
		QosQueryDurationSeconds,
		QosCacheHitsTotal,
		QosCacheMissesTotal,
		KeysMintedTotal,
		UsageReportDurationSeconds,
		RollupRefreshDurationSeconds,
		RollupParityGreen,
		RollupParityCheckedAtSeconds,
		RollupBackfillDurationSeconds,
	}
)

func init() {
	reg.MustRegister(collectors...)
	// A fresh process has not checked parity yet — "unknown" (NaN), not
	// "red" (0), so an alert on parity_green == 0 cannot fire before the
	// first completed check.
	RollupParityGreen.Set(math.NaN())
}

// Handler returns the /metrics handler served on the dedicated metrics listener.
func Handler() http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}
