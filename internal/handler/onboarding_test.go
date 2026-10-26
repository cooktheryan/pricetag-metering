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
