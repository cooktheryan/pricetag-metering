package storage

import (
	"strings"
	"testing"
)

func TestDashboardToolsCountDistinctUsers(t *testing.T) {
	body := funcBody(t, "postgres.go", "func (s *Store) GetDashboardTools(")
	for _, want := range []string{
		"COUNT(DISTINCT NULLIF(e.username, ''))",
		"GROUP BY COALESCE(e.user_agent, ''), e.username",
		"item.Users = len(usersByTool[item.Tool])",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("GetDashboardTools lost distinct-user accounting %q", want)
		}
	}
}
