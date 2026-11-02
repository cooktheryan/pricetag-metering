package dashboard

import (
	"bytes"
	"testing"
)

func TestDashboardToolMetricToggle(t *testing.T) {
	data, err := FS.ReadFile("dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"let modelMetric='tokens', userPieMetric='cost', toolMetric='tokens';",
		"id=\"tool-metric-toggle\"",
		"<span id=\"tool-metric-label\">Tokens</span>",
		"metric==='users'?(d.users||0)",
		"metric==='users'?' users'",
		"metric==='users'?'':' ('",
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("dashboard.html no longer contains %q", want)
		}
	}
}
