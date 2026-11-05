package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestToolPieShowsTopNinePlusOther(t *testing.T) {
	data, err := FS.ReadFile("dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("function(d){return d.tool;},9)")) {
		t.Error("tool pie no longer limits to the top 9 tools plus an Other row")
	}
}

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

func TestDashboardEscapesUserControlledIdentityFields(t *testing.T) {
	data, err := FS.ReadFile("dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"pmEsc(nameByUser[n])",
		"${pmEsc(r.model||'—')}",
		"${pmEsc(r.provider||'—')}",
		"var name=pmEsc(m.model);",
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("dashboard.html no longer escapes user-controlled field with %q", want)
		}
	}
}

func TestTopUsersRankShowsCountryCostCenterAndDemoPrivacy(t *testing.T) {
	data, err := FS.ReadFile("dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"function userCostCenter(tags)",
		"var country=item.tags&&item.tags.country;",
		"var costCenter=userCostCenter(item.tags);",
		`countryFlag(country)+'<span class="ur-name demo-pii">'`,
		`<span class="ur-sub demo-pii">`,
		`<span class="ur-cc">`,
		`var title=demoPrivacyEnabled()?'':' title="'`,
		// The user pie (and its tooltip) is gone: renderUserCostChart renders
		// only the ranked legend, with no unreachable chart code after it.
		"renderUserRank(data,userPieMetric);\n}",
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("dashboard.html no longer contains %q", want)
		}
	}
}

// Yossi's review flagged two stored-XSS sinks reachable from OIDC profile data:
// esc() in admin.html was text-safe but not attribute-safe, and the pie legend's
// local html() helper left double quotes intact inside a title="..." attribute.
func TestDashboardPieLegendTitleEscapesQuotes(t *testing.T) {
	data, err := FS.ReadFile("dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`function pmEsc(s){return String(s==null?'':s).replace(/[&<>"]/g,`,
		"var text=pmEsc(label);",
		"var title=redactName?'':' title=\"'+text+'\"';",
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("dashboard.html no longer escapes pie legend titles with %q", want)
		}
	}
	// The removed local helper escaped only &, < and > and was unsafe inside
	// title="...".
	if bytes.Contains(data, []byte("function html(s){return String(s??'').replace(/&/g,'&amp;')")) {
		t.Error("pie legend still uses the unquoted local html() helper")
	}
}

func TestAdminEscapesAttributesAndInlineHandlerStrings(t *testing.T) {
	data, err := FS.ReadFile("admin.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		// esc() must escape both quote characters so value="..." and data-* are safe.
		`'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'`,
		"function jsq(s)",
		"jsq(p.name)",
		"jsq(name)",
		"jsq(u)",
		"jsq(p.slug)",
		"value=\"' + esc(p.first_name || '') + '\"",
		"value=\"' + esc(p.last_name || '') + '\"",
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("admin.html no longer contains %q", want)
		}
	}
	// A textContent/innerHTML round-trip does not escape quotes.
	if bytes.Contains(data, []byte("escDiv.textContent = String(s);")) {
		t.Error("admin.html esc() regressed to the quote-unsafe textContent helper")
	}
	// User-controlled values must not be spliced into inline JS string literals
	// through the HTML-only encoder.
	for _, bad := range []string{
		"approvePendingUser('\\'' + esc(p.name)",
		"removeFromGroup('\\'' + esc(name)",
		"addToGroup('\\'' + esc(name)",
		"openInviteFor('\\'' + esc(p.slug)",
		"setPersonField('\\'' + esc(p.slug)",
	} {
		if bytes.Contains(data, []byte(bad)) {
			t.Errorf("admin.html still interpolates %q into an inline handler", bad)
		}
	}
}

// jsq() is splices into inline JS string literals inside HTML attributes, so it
// must neutralise the entity opener as well as quotes: the HTML parser would
// otherwise decode "&#39;" back into a quote before JavaScript runs.
func TestAdminJsqEncodingIsEntityAndQuoteSafe(t *testing.T) {
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not available; jsq behaviour is exercised in CI where node exists")
	}
	data, err := FS.ReadFile("admin.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(data)
	start := strings.Index(src, "function jsq(s)")
	if start < 0 {
		t.Fatal("admin.html no longer defines jsq()")
	}
	depth, end := 0, -1
	for i := start; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				end = i + 1
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		t.Fatal("could not extract jsq() body")
	}
	fn := src[start:end]

	cases := []struct{ in, want string }{
		{`&#39;);alert(document.domain);//`, `\x26#39;);alert(document.domain);//`},
		{`it's "quoted" & <tag>`, `it\x27s \x22quoted\x22 \x26 \x3ctag>`},
		{`a\b`, `a\x5cb`},
		{"line\nbreak", `line\x0abreak`},
	}
	for _, tc := range cases {
		lit, err := json.Marshal(tc.in)
		if err != nil {
			t.Fatal(err)
		}
		script := fmt.Sprintf("%s;process.stdout.write(jsq(%s));", fn, lit)
		out, err := exec.Command(nodePath, "-e", script).Output()
		if err != nil {
			t.Fatalf("node failed: %v", err)
		}
		if string(out) != tc.want {
			t.Errorf("jsq(%q) = %q, want %q", tc.in, out, tc.want)
		}
		for _, raw := range []string{"&", "'", "\"", "<"} {
			if strings.Contains(string(out), raw) {
				t.Errorf("jsq(%q) left raw %q in the encoded output %q", tc.in, raw, out)
			}
		}
	}
}

// The cost-center legend must name both the directory code and its human
// label, with the share of spend first.
func TestCostCenterChartShowsPercentAndDirectoryCode(t *testing.T) {
	data, err := FS.ReadFile("dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"function costCenterSliceMeta(d,total)",
		"String(d.item.cost_center||'').trim()",
		"function costCenterSliceLabel(meta)",
		"meta.pct+'% — '+id+meta.desc",
		"'% spent — '",
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("dashboard.html no longer contains %q", want)
		}
	}
}

// Structural string checks cannot catch a misplaced brace: one syntax error
// makes the browser discard the entire inline script, so the dashboard renders
// its skeletons but never issues a single API request. Parse every inline
// script with the same engine the page runs in.
func TestDashboardInlineScriptsParse(t *testing.T) {
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not available; inline dashboard scripts are parsed in CI where node exists")
	}
	data, err := FS.ReadFile("dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(data)
	checked := 0
	for {
		start := strings.Index(src, "<script")
		if start < 0 {
			break
		}
		openEnd := strings.Index(src[start:], ">")
		if openEnd < 0 {
			t.Fatal("unterminated <script> tag")
		}
		openEnd += start
		closeRel := strings.Index(src[openEnd+1:], "</script>")
		if closeRel < 0 {
			t.Fatal("unterminated inline <script> block")
		}
		body := src[openEnd+1 : openEnd+1+closeRel]
		src = src[openEnd+1+closeRel+len("</script>"):]
		if strings.TrimSpace(body) == "" {
			continue
		}
		path := filepath.Join(t.TempDir(), fmt.Sprintf("inline-%d.js", checked))
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(nodePath, "--check", path).CombinedOutput(); err != nil {
			t.Fatalf("inline script %d does not parse: %v\n%s", checked, err, out)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("dashboard.html has no inline scripts to parse")
	}
}
