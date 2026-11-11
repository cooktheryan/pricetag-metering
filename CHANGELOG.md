# Changelog

Release notes for the EnMaaS PriceTag metering service.

The `Unreleased` section is updated as changes land. When a release is
published, move its completed entries into a dated version section and link
the section to the corresponding GitHub tag.

## [Unreleased]

### Added

- Zero-rate pricing for the Curvebender-hosted Muse Spark Open model `rits/meta-models/Muse-Spark-Open-816B-A42B-NVFP4` ([PR #148](https://github.com/redhat-et/pricetag-metering/pull/148)).

### Changed

Nothing yet.

### Fixed

Nothing yet.

## [0.3.0] - 2026-10-09

This release is the EnMaaS metering source of truth for the coordinated
PriceTag deployment. It includes all metering changes merged after `v0.2.1`.

### Added

- Inline expansion of user details in the dashboard ([PR #60](https://github.com/redhat-et/pricetag-metering/pull/60)).
- Server-side user search and page-size selection for paginated user views ([PR #56](https://github.com/redhat-et/pricetag-metering/pull/56)).

### Changed

- Dashboard user charts now rank independently by Cost, Tokens, and Requests ([PR #62](https://github.com/redhat-et/pricetag-metering/pull/62)).

### Fixed

- Rollup ingestion no longer takes an hour-wide lock, reducing contention with event writes ([PR #59](https://github.com/redhat-et/pricetag-metering/pull/59)).
- Retired Qwen models are excluded from pricing and model views ([PR #54](https://github.com/redhat-et/pricetag-metering/pull/54)).

### Coordinated EnMaaS deployment changes

The matching deployment and operations changes are tracked in the PriceTag
repository release `v0.3.0`, including model routing/catalog updates, Vertex
integration, rollout scaling, database-pool configuration, TLS, RDS, staging,
load-test, and operational documentation work:

- [PriceTag PR #53](https://github.com/redhat-et/pricetag/pull/53), [#54](https://github.com/redhat-et/pricetag/pull/54), [#55](https://github.com/redhat-et/pricetag/pull/55), [#56](https://github.com/redhat-et/pricetag/pull/56), [#57](https://github.com/redhat-et/pricetag/pull/57), [#58](https://github.com/redhat-et/pricetag/pull/58), [#60](https://github.com/redhat-et/pricetag/pull/60), [#61](https://github.com/redhat-et/pricetag/pull/61), [#62](https://github.com/redhat-et/pricetag/pull/62), [#63](https://github.com/redhat-et/pricetag/pull/63), [#64](https://github.com/redhat-et/pricetag/pull/64), [#65](https://github.com/redhat-et/pricetag/pull/65), [#66](https://github.com/redhat-et/pricetag/pull/66), [#69](https://github.com/redhat-et/pricetag/pull/69), [#70](https://github.com/redhat-et/pricetag/pull/70), [#74](https://github.com/redhat-et/pricetag/pull/74), and [#76](https://github.com/redhat-et/pricetag/pull/76).

## [0.2.0] - 2026-10-07

This is the first tagged EnMaaS release of the metering service.

### Added

- A super-admin Safety Net control with a `$600` monthly per-user default.
- Exact-model over-limit allowance for `rits/zai-org/glm-5-3`.
- Read-only Model Restrictions visibility backed by partner-user model
  allowlists.
- Partner-user identity, role, login, key metadata, and model-policy APIs.
- Paginated administrator and usage-user views.
- Local-only Compose fixtures for synthetic users, usage, MaaS validation, and
  Praxis/LLM-Katan testing.
- Pi setup guidance for OpenAI-compatible, Anthropic-compatible, and hosted GLM
  models.
- Separate OpenCode v1 and v2 setup examples.

### Changed

- Partner users are now the canonical dashboard and authorization identity
  source.
- Dashboard access and administrative actions are restricted to administrators
  and super-administrators where appropriate.
- The welcome and operations documentation now describes EnMaaS gateway URLs,
  authentication dialects, model discovery, and model limits.
- The welcome-page smoke test now uses the routable GLM model, and the GLM
  examples document a 262144-token context window with a 65536-token output
  limit.

### Removed

- The legacy Quotas UI.
- The optional soft bypass ceiling; the legacy database column is retained only
  for migration compatibility and is no longer read or written.

### Fixed

- Usage-report handling for partner users.
- Initial administrator-table pagination behavior.
- Partner API authentication and partner-role resolution across dashboard
  requests.

## Links

- [Unreleased]: https://github.com/redhat-et/pricetag-metering/compare/v0.3.0...HEAD
- [0.3.0]: https://github.com/redhat-et/pricetag-metering/releases/tag/v0.3.0
- [0.2.0]: https://github.com/redhat-et/pricetag-metering/releases/tag/v0.2.0
