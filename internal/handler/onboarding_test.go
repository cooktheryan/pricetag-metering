package handler

import (
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestNormalizeGroupsDropsTechnicalRoles(t *testing.T) {
	got := NormalizeGroups([]string{
		"GE", " offline_access ", "uma_authorization", "default-roles-stage",
		"enmaas_authorization", "ge", "", "Platform",
	})
	want := []string{"GE", "Platform"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeGroups = %#v, want %#v", got, want)
	}
}

func TestNormalizeCountry(t *testing.T) {
	cases := map[string]string{
		"US":   "USA",
		"us":   "USA",
		" IR ": "IRN",
		"IRN":  "IRN",
		"":     "",
		"U":    "",
		"GB":   "GBR",
		"ZZ":   "",
	}
	for in, want := range cases {
		if got := normalizeCountry(in); got != want {
			t.Errorf("normalizeCountry(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestKnownISO3(t *testing.T) {
	if !knownISO3("IRN") || !knownISO3("USA") {
		t.Fatal("expected IRN and USA to be known ISO3 codes")
	}
	if knownISO3("IR") || knownISO3("ZZZ") {
		t.Fatal("alpha-2 or unknown codes must not validate as ISO3")
	}
}

func TestSameOrigin(t *testing.T) {
	r := httptest.NewRequest("POST", "http://dashboard.example/api", nil)
	r.Host = "dashboard.example"
	if !sameOrigin(r) {
		t.Fatal("missing Origin should be allowed for non-browser clients")
	}
	r.Header.Set("Origin", "http://dashboard.example")
	if !sameOrigin(r) {
		t.Fatal("matching Origin should be allowed")
	}
	r.Header.Set("Origin", "http://evil.example")
	if sameOrigin(r) {
		t.Fatal("cross-origin request must be refused")
	}
}

func TestGateGroupsPrefersDirectoryRoverGroups(t *testing.T) {
	tags := map[string]any{
		"rover_groups": []any{"enmaas-users", "other-group"},
		"groups":       []string{"GE", "platform"},
	}
	got := gateGroups([]string{"GE"}, tags)
	want := []string{"enmaas-users", "other-group"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("gateGroups = %#v, want %#v", got, want)
	}
}

func TestGateGroupsEmptyDirectoryListDoesNotFallBack(t *testing.T) {
	tags := map[string]any{
		"rover_groups": []any{},
		"groups":       []string{"GE"},
	}
	if got := gateGroups([]string{"GE"}, tags); len(got) != 0 {
		t.Fatalf("gateGroups = %#v, want no groups", got)
	}
}

func TestGateGroupsFallsBackToOIDCClaim(t *testing.T) {
	tags := map[string]any{"groups": []any{"GE", " offline_access ", "platform"}}
	got := gateGroups([]string{"session-group"}, tags)
	want := []string{"GE", "platform", "session-group"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("gateGroups = %#v, want %#v", got, want)
	}
}

func TestTagStringListEncodings(t *testing.T) {
	cases := map[string]any{
		"array":       []any{"GE", "platform"},
		"json string": `["GE","platform"]`,
		"csv":         "GE, platform",
	}
	for name, value := range cases {
		got := tagStringList(value)
		if len(got) != 2 || got[0] != "GE" || got[1] != "platform" {
			t.Errorf("%s: tagStringList = %#v", name, got)
		}
	}
}

func TestWorksCouncilOverride(t *testing.T) {
	for _, tags := range []map[string]any{
		{"works_council_override": true},
		{"works_council_override": "true"},
		{"has_works_council_override": "yes"},
	} {
		if !hasWorksCouncilOverride(tags) {
			t.Errorf("expected override for %#v", tags)
		}
	}
	if hasWorksCouncilOverride(map[string]any{"works_council_override": "false"}) {
		t.Fatal("false override must not pass")
	}
}
