package storage

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestSyncCatalogFromPraxisConfig(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant, err := s.EnsureDefaultTenant(ctx)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "praxis.yaml")
	content := `filter_chains:
  - name: anthropic
    filters:
      - filter: model_catalog
        format: anthropic
        path: /v1/messages
        models:
          - id: claude-opus-5
            display_name: Claude Opus 5
            owned_by: vertex
          - id: shared-model
            display_name: Shared
            owned_by: cb-glm
  - name: openai
    filters:
      - filter: model_catalog
        format: openai
        path: /v1/chat/completions
        models:
          - id: gpt-6.1-sol
            display_name: GPT 6.1 Sol
            owned_by: openai
          - bare-string-model
          - id: shared-model
            display_name: Shared
            owned_by: cb-glm
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	count, err := s.SyncCatalogFromPraxisConfig(ctx, tenant, path)
	if err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Fatalf("synced = %d, want 4", count)
	}
	models, err := s.ListCatalogModels(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 4 {
		t.Fatalf("catalog = %#v", models)
	}
	var shared CatalogModel
	for _, m := range models {
		if m.ModelID == "shared-model" {
			shared = m
		}
	}
	if shared.ModelID == "" {
		t.Fatal("shared-model missing")
	}
	if !slices.Equal(shared.Dialects, []string{"anthropic", "openai"}) {
		t.Fatalf("shared dialects = %v", shared.Dialects)
	}
	if !slices.Equal(shared.Paths, []string{"/v1/chat/completions", "/v1/messages"}) {
		t.Fatalf("shared paths = %v", shared.Paths)
	}

	// Re-sync is idempotent.
	count, err = s.SyncCatalogFromPraxisConfig(ctx, tenant, path)
	if err != nil || count != 4 {
		t.Fatalf("resync = %d, err %v", count, err)
	}
	models, err = s.ListCatalogModels(ctx, tenant)
	if err != nil || len(models) != 4 {
		t.Fatalf("catalog after resync = %#v, err %v", models, err)
	}
}
