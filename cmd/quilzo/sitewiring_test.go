package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// A field on public.Site that nothing sets is a feature nobody can turn on.
//
// This is here because of Licence. internal/public had a complete, tested RSL
// and TDMRep implementation — document builders, a vocabulary, a TDMRep
// derivation with its own tests — and `quilzo site` never assigned
// st.Licence. So /license.xml and /.well-known/tdmrep.json returned 404 on
// every deployment there has ever been, while the README listed the feature as
// shipped.
//
// Both halves had passing tests. The builder was tested against what it
// writes; nothing was tested against whether anybody called it. That gap is
// invisible from either side, and it is the same shape as the surface-coverage
// table in coverage_test.go: a capability built correctly and reachable from
// nowhere.
//
// So this walks the fields of public.Site and requires each one to be either
// assigned in site.go or listed below with a reason. A gap with a written
// reason is a decision; a gap with nothing next to it is an oversight, and
// this test cannot tell them apart unless somebody writes the reason down.
var notWiredBySite = map[string]string{
	// Set by public.New from its arguments rather than assigned afterwards.
	// Ref is not here: site.go assigns it as well, from the environment being
	// served, and an assignment beats an exemption.
	"Template": "public.New takes it, because a site with no template cannot serve",
	"Store":    "public.New takes it, because a site with no store has nothing to serve",
}

func TestEverySiteFieldIsEitherWiredOrExplainedAway(t *testing.T) {
	fields := exportedFieldsOf(t, "../../internal/public/public.go", "Site")
	if len(fields) < 5 {
		t.Fatalf("found %d fields on public.Site; the parse is wrong and this "+
			"test would pass by checking almost nothing", len(fields))
	}
	wiring := mustRead(t, "site.go")

	// Only the assignment form counts. Mentioning a field in a comment, or
	// reading it, is not wiring it — and the original bug read st.Licence in
	// three places while nothing ever assigned it.
	assigned := map[string]bool{}
	for _, m := range regexp.MustCompile(`st\.([A-Z]\w*)\s*=`).
		FindAllStringSubmatch(wiring, -1) {
		assigned[m[1]] = true
	}

	var missing []string
	wired, explained := 0, 0
	for _, f := range fields {
		switch {
		case assigned[f]:
			wired++
		case notWiredBySite[f] != "":
			explained++
		default:
			missing = append(missing, f)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("public.Site has %d field(s) that `quilzo site` never "+
			"assigns: %s\n"+
			"  Each is a feature an operator cannot turn on, however well it "+
			"is implemented and tested.\n"+
			"  Wire it in site.go, or add it to notWiredBySite with the "+
			"reason it does not belong there.",
			len(missing), strings.Join(missing, ", "))
	}
	// Counted over the fields actually examined, not over the two maps. An
	// earlier version logged len(assigned) and len(notWiredBySite), which
	// summed to more than the number of fields and would have read as a pass
	// covering more than it did.
	t.Logf("%d field(s) on public.Site: %d wired by site.go, %d explained away",
		len(fields), wired, explained)
}

// And the specific one, named, so somebody removing the wiring reads why
// rather than a generic complaint about a field.
func TestTheCrawlLicenceIsWiredIntoTheSiteProcess(t *testing.T) {
	wiring := mustRead(t, "site.go")
	if !strings.Contains(wiring, "st.Licence = ") {
		t.Error("`quilzo site` does not assign st.Licence, so /license.xml " +
			"and /.well-known/tdmrep.json return 404 no matter what the " +
			"operator configures")
	}
	if !strings.Contains(wiring, "licenceFrom(") {
		t.Error("nothing calls licenceFrom, so the configured terms are read " +
			"by nobody")
	}

	// And the refusal has to reach the operator.
	//
	// A sabotage that dropped the error return left every check inside
	// licenceFrom intact and passing — contradictory terms, a typo in the
	// vocabulary, a half-configured licence — while the site started anyway
	// and served whatever came back. The validation was tested; acting on it
	// was not. That is the same shape as the bug this whole file exists for,
	// one level down.
	//
	// Checked in the source because the call sits inside a long startup
	// function that opens a store and binds a port. A regex is a cruder tool
	// than running the thing, and it is the one that fits where this lives.
	call := regexp.MustCompile(
		`(?s)licenceFrom\(cfg\);\s*lerr\s*!=\s*nil\s*\{\s*return\s+lerr`)
	if !call.MatchString(wiring) {
		t.Error("site.go does not return the error from licenceFrom, so " +
			"contradictory or misspelled crawl terms would be accepted at " +
			"startup and published to crawlers that act on them")
	}
}

// A reason for a field that no longer exists is a stale reason, and it makes
// the exemption list look more considered than it is.
func TestEveryExemptionNamesARealField(t *testing.T) {
	fields := map[string]bool{}
	for _, f := range exportedFieldsOf(t, "../../internal/public/public.go", "Site") {
		fields[f] = true
	}
	for name := range notWiredBySite {
		if !fields[name] {
			t.Errorf("notWiredBySite explains %q, which is not a field on "+
				"public.Site. Either the field was renamed and the exemption "+
				"was not, or it never existed.", name)
		}
	}
}

// exportedFieldsOf pulls the exported field names out of a struct declaration.
//
// Text rather than go/ast: the declaration is in another package's file and
// this only needs the names. A parse that finds nothing is caught by the
// count check in the caller rather than passing quietly.
func exportedFieldsOf(t *testing.T, path, name string) []string {
	t.Helper()
	src := mustRead(t, path)
	start := strings.Index(src, "type "+name+" struct {")
	if start < 0 {
		t.Fatalf("no `type %s struct` in %s", name, path)
	}
	body := src[start:]
	if end := strings.Index(body, "\n}"); end > 0 {
		body = body[:end]
	}

	var out []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		m := regexp.MustCompile(`^([A-Z]\w*)\s+[\*\[\]\w]`).FindStringSubmatch(line)
		if m != nil {
			out = append(out, m[1])
		}
	}
	sort.Strings(out)
	return out
}

// mustRead reads a source file the test reasons about. Named apart from the
// package's other readFile helper rather than reusing it, because this one is
// allowed to fail the test and that one is not.
func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
