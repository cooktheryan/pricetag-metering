package dashboard

import (
	"bytes"
	"testing"
)

// The manager picker lives in a single embedded HTML file, so these are
// source-level guards for the behavior that has no browser test harness in
// this repository. The backend no-key scope guard has its own unit tests.
func TestManagerPickerReviewGuards(t *testing.T) {
	data, err := FS.ReadFile("manager.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"const TEAM_SEARCH_LIMIT=200;",
		"ranked.slice(0,TEAM_SEARCH_LIMIT)",
		"username:r.username||''",
		"no key yet",
		"manager outside this view",
		"PageDown",
		"PageUp",
		"aria-expanded=\"false\"",
		"e.button!==0",
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("manager.html no longer contains %q", want)
		}
	}
}

func TestManagerTimelineRanksByUsage(t *testing.T) {
	data, err := FS.ReadFile("manager.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"const ranked=[...totals.entries()].filter(([,v])=>v>0).sort((a,b)=>b[1]-a[1]);",
		"const top=ranked.slice(0,7).map(([n])=>n);",
		"const tail=ranked.slice(7).map(([n])=>n);",
		"tail.length?['__other__']",
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("manager timeline no longer contains %q", want)
		}
	}
}
