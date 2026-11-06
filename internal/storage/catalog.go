package storage

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/lib/pq"
	"gopkg.in/yaml.v3"
)

// CatalogModel is the admin-facing model registry row. It is a control-plane
// snapshot of what the gateway advertises; it is never consulted on the
// entitlement hot path.
type CatalogModel struct {
	ModelID        string   `json:"id"`
	DisplayName    string   `json:"display_name,omitempty"`
	Provider       string   `json:"provider,omitempty"`
	ProviderTarget string   `json:"provider_target,omitempty"`
	Dialects       []string `json:"dialects,omitempty"`
	Paths          []string `json:"paths,omitempty"`
	Aliases        []string `json:"aliases,omitempty"`
	Lifecycle      string   `json:"lifecycle"`
	Region         string   `json:"region,omitempty"`
	CostClass      string   `json:"cost_class,omitempty"`
}

type praxisCatalogModel struct {
	ID          string
	DisplayName string
	OwnedBy     string
}

// UnmarshalYAML accepts both catalog forms used across deployments:
//   - id: claude-sonnet-4-5
//     display_name: Claude Sonnet 4.5
//     owned_by: vertex
//   - claude-sonnet-4-5
func (m *praxisCatalogModel) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		m.ID = strings.TrimSpace(value.Value)
		return nil
	}
	var raw struct {
		ID          string `yaml:"id"`
		DisplayName string `yaml:"display_name"`
		OwnedBy     string `yaml:"owned_by"`
	}
	if err := value.Decode(&raw); err != nil {
		return err
	}
	m.ID = strings.TrimSpace(raw.ID)
	m.DisplayName = strings.TrimSpace(raw.DisplayName)
	m.OwnedBy = strings.TrimSpace(raw.OwnedBy)
	return nil
}

type praxisCatalogConfig struct {
	FilterChains []struct {
		Filters []struct {
			Filter string               `yaml:"filter"`
			Format string               `yaml:"format"`
			Path   string               `yaml:"path"`
			Models []praxisCatalogModel `yaml:"models"`
		} `yaml:"filters"`
	} `yaml:"filter_chains"`
}

// SyncCatalogFromPraxisConfig imports the static model_catalog lists from a
// mounted Praxis config. Overlay-based catalogs are a subsequent source; this
// covers the current PriceTag/EnMaaS static catalog.
func (s *Store) SyncCatalogFromPraxisConfig(ctx context.Context, tenantID, path string) (int, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return 0, fmt.Errorf("catalog file path is empty")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read catalog config: %w", err)
	}
	var cfg praxisCatalogConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return 0, fmt.Errorf("parse catalog config: %w", err)
	}
	type entry struct {
		model    CatalogModel
		dialects map[string]struct{}
		paths    map[string]struct{}
	}
	merged := map[string]*entry{}
	for _, chain := range cfg.FilterChains {
		for _, filter := range chain.Filters {
			if filter.Filter != "model_catalog" {
				continue
			}
			dialect := strings.TrimSpace(filter.Format)
			pathValue := strings.TrimSpace(filter.Path)
			for _, m := range filter.Models {
				id := strings.TrimSpace(m.ID)
				if id == "" {
					continue
				}
				e, ok := merged[id]
				if !ok {
					e = &entry{
						model: CatalogModel{
							ModelID:     id,
							DisplayName: strings.TrimSpace(m.DisplayName),
							Provider:    strings.TrimSpace(m.OwnedBy),
							Lifecycle:   "active",
						},
						dialects: map[string]struct{}{},
						paths:    map[string]struct{}{},
					}
					merged[id] = e
				}
				if e.model.DisplayName == "" {
					e.model.DisplayName = strings.TrimSpace(m.DisplayName)
				}
				if e.model.Provider == "" {
					e.model.Provider = strings.TrimSpace(m.OwnedBy)
				}
				if dialect != "" {
					e.dialects[dialect] = struct{}{}
				}
				if pathValue != "" {
					e.paths[pathValue] = struct{}{}
				}
			}
		}
	}
	if len(merged) == 0 {
		return 0, fmt.Errorf("no model_catalog entries with static models found in %s", path)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	ids := make([]string, 0, len(merged))
	for id := range merged {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		e := merged[id]
		dialects := sortedKeys(e.dialects)
		paths := sortedKeys(e.paths)
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO catalog_models
				(tenant_id, model_id, display_name, provider, dialects, paths, aliases, lifecycle, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, '{}', 'active', NOW())
			ON CONFLICT (tenant_id, model_id) DO UPDATE SET
				display_name = EXCLUDED.display_name,
				provider = EXCLUDED.provider,
				dialects = EXCLUDED.dialects,
				paths = EXCLUDED.paths,
				updated_at = NOW()`,
			tenantID, e.model.ModelID, e.model.DisplayName, e.model.Provider,
			pq.Array(dialects), pq.Array(paths)); err != nil {
			return 0, fmt.Errorf("upsert catalog model %s: %w", id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(merged), nil
}

func (s *Store) ListCatalogModels(ctx context.Context, tenantID string) ([]CatalogModel, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT model_id, display_name, provider, COALESCE(provider_target, ''),
		       dialects, paths, aliases, lifecycle, COALESCE(region, ''), COALESCE(cost_class, '')
		FROM catalog_models
		WHERE tenant_id = $1
		ORDER BY provider, display_name, model_id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list catalog models: %w", err)
	}
	defer rows.Close()
	out := []CatalogModel{}
	for rows.Next() {
		var m CatalogModel
		if err := rows.Scan(&m.ModelID, &m.DisplayName, &m.Provider, &m.ProviderTarget,
			pq.Array(&m.Dialects), pq.Array(&m.Paths), pq.Array(&m.Aliases), &m.Lifecycle,
			&m.Region, &m.CostClass); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
