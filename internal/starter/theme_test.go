package starter

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/codescan"
	renderpkg "github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/section"
	"github.com/quilzo/quilzo/internal/theme"
	"github.com/quilzo/quilzo/internal/tmpl"
)

// A starter's own design has to pass the gate the tool enforces, in both colour
// schemes. This is the check that makes the token split safe: the components are
// shared and unchangeable, so if every shipped token set is legible then every
// shipped starter is legible — and a palette somebody thought looked good in
// light mode cannot ship unreadable in dark.
func TestEveryStarterThemeIsLegibleInBothSchemes(t *testing.T) {
	for _, st := range All() {
		t.Run(st.Name, func(t *testing.T) {
			th, problems := st.Theme()
			for _, p := range problems {
				if p.Blocking {
					t.Errorf("%s declares an unusable token: %s", st.Name, p)
				}
			}
			for _, f := range th.Check() {
				if f.Blocking {
					t.Errorf("%s: %s", st.Name, f)
				}
			}
		})
	}
}

// Every colour a starter sets has to be set for both schemes. A palette that
// changes the ground in light mode and not in dark is not a design, it is half
// of one, and it is the half nobody looks at.
func TestStarterThemesSetBothSchemes(t *testing.T) {
	for _, st := range All() {
		th, _ := st.Theme()
		for _, f := range th.Check() {
			if !f.Blocking {
				t.Errorf("%s: %s", st.Name, f)
			}
		}
	}
}

// The tokens a starter names have to exist, and the closed set is the point.
func TestStarterTokensAreAllKnown(t *testing.T) {
	for _, st := range All() {
		for name := range st.Tokens {
			base := name
			for _, suffix := range []string{".dark", ".light"} {
				if trimmed, cut := cutSuffix(base, suffix); cut {
					base = trimmed
				}
			}
			if _, ok := theme.Lookup(base); !ok {
				t.Errorf("%s sets unknown token %q", st.Name, name)
			}
		}
	}
}

func cutSuffix(s, suffix string) (string, bool) {
	if len(s) > len(suffix) && s[len(s)-len(suffix):] == suffix {
		return s[:len(s)-len(suffix)], true
	}
	return s, false
}

// Every section kind the layout can render has to appear in some starter's
// sample content.
//
// A kind nobody renders is a kind nobody tested: it is not parsed against real
// data, it is not put through the accessibility gate, and it is not in the
// output the hostile-content test greps. The first person to use it is the
// person who finds out — and this file is where that stops being true.
func TestEverySectionKindIsExercisedBySomeSample(t *testing.T) {
	src, err := Get("sections")
	if !err {
		t.Fatal("the sections starter is missing")
	}
	layout, herr := src.HTML()
	if herr != nil {
		t.Fatal(herr)
	}
	kinds := sectionKinds(layout)
	if len(kinds) < 10 {
		t.Fatalf("found only %d section kinds; the parse is wrong and this "+
			"test would pass by checking almost nothing", len(kinds))
	}

	used := map[string]bool{}
	for _, st := range All() {
		sections, ok := st.Sample["sections"].([]any)
		if !ok {
			continue
		}
		for _, section := range sections {
			m, isMap := section.(map[string]any)
			if !isMap {
				continue
			}
			for key := range m {
				used[key] = true
			}
		}
	}

	var missing []string
	for _, kind := range kinds {
		if !used[kind] {
			missing = append(missing, kind)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d section kind(s) are in the layout and in no sample: %s\n"+
			"  Each renders untested: not parsed against real data, not put "+
			"through the accessibility gate, and not in the output the "+
			"hostile-content test greps.",
			len(missing), strings.Join(missing, ", "))
	}
}

// sectionKinds reads the kinds out of the layout, so the list cannot drift from
// the markup that implements it.
func sectionKinds(layout string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile(`\{%\s*if\s+s\.([a-z_]+)\s*%\}`).
		FindAllStringSubmatch(layout, -1) {
		if seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		out = append(out, m[1])
	}
	sort.Strings(out)
	return out
}

// The shipped layouts have to pass the scanner this product ships.
//
// The interesting one is the CSS rule: every chart in these layouts sets a
// custom property from content, which is only safe because the value goes
// through a filter that cannot return anything but a number. If somebody
// simplifies one of those away, this is what says so — rather than a reader
// discovering that a page fetches an image from a host nobody chose.
func TestTheShippedLayoutsPassTheScanner(t *testing.T) {
	layouts, err := Layouts()
	if err != nil {
		t.Fatal(err)
	}
	if len(layouts) == 0 {
		t.Fatal("no layouts to scan; this test would pass by checking nothing")
	}
	var inputs []codescan.Input
	for name, body := range layouts {
		inputs = append(inputs, codescan.Input{
			Name: name + ".html", Kind: codescan.Template, Body: body,
		})
	}
	for _, f := range codescan.Scan(inputs) {
		t.Errorf("%s line %d [%s] %s\n  %s\n  fix: %s",
			f.Where, f.Line, f.Rule, f.Detail, f.Excerpt, f.Fix)
	}
}

// The section catalogue and the layout that renders sections have to agree.
//
// A kind in the catalogue the layout does not implement is a section somebody
// can add and never see. A kind the layout implements and the catalogue does not
// list is a feature nobody can reach from a screen. Neither is visible by
// reading one file, which is exactly the shape of drift this project keeps
// finding: two halves of one capability, each correct on its own.
func TestTheSectionCatalogueMatchesTheLayout(t *testing.T) {
	st, ok := Get("sections")
	if !ok {
		t.Fatal("the sections starter is missing")
	}
	layout, err := st.HTML()
	if err != nil {
		t.Fatal(err)
	}
	implemented := map[string]bool{}
	for _, name := range sectionKinds(layout) {
		implemented[name] = true
	}
	catalogued := map[string]bool{}
	for _, k := range section.Kinds() {
		catalogued[k.Name] = true
	}

	for name := range implemented {
		if !catalogued[name] {
			t.Errorf("the layout renders a %q section and the catalogue does "+
				"not list it, so nobody can add one from a screen", name)
		}
	}
	for name := range catalogued {
		if !implemented[name] {
			t.Errorf("the catalogue offers a %q section and the layout does "+
				"not render it, so adding one puts invisible content on a page",
				name)
		}
	}
}

// Every stub has to render, and render into something the gate accepts. A stub
// that produces an empty heading or an unlabelled image is one that fails the
// publish the moment somebody adds it — from a button that said "added".
func TestEveryStubRendersAndPassesTheGate(t *testing.T) {
	st, _ := Get("sections")
	layout, err := st.HTML()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range section.Kinds() {
		t.Run(k.Name, func(t *testing.T) {
			body, ierr := section.Insert(
				map[string]any{"title": "A page"}, k.Name, 0)
			if ierr != nil {
				t.Fatal(ierr)
			}
			out, rerr := tmpl.Render(layout, map[string]any{
				"page": decorated(body), "site": map[string]any{"name": "Example"},
			})
			if rerr != nil {
				t.Fatalf("the %s stub does not render: %v", k.Name, rerr)
			}
			if len(out) < 400 {
				t.Errorf("the %s stub rendered %d bytes; it is not visible on "+
					"the page", k.Name, len(out))
			}
			for _, f := range a11y.Check(k.Name, out).Findings {
				if f.Severity == a11y.Blocking {
					t.Errorf("the %s stub fails the gate: %s", k.Name, f)
				}
			}
		})
	}
}

// decorated applies the derived companions the renderer adds, so a stub is
// rendered here the way it is rendered in production. Without this the test
// would pass on markup nobody is served — which is the exact failure
// internal/render was written to prevent.
func decorated(body map[string]any) map[string]any {
	ctx, err := renderpkg.Sources{Name: "Example"}.For("index", body, nil)
	if err != nil {
		return body
	}
	out, _ := ctx["page"].(map[string]any)
	return out
}

// No shipped sample may reference a media file.
//
// The sections sample pointed at /media/placeholder.png in three places and
// /media/placeholder.mp4 in one. Nothing puts those in a store, so `template
// use sections` followed by `publish` produced a page with three broken
// pictures — and the accessibility gate passed it, correctly, because a broken
// image with alt text is a described image that happens to 404.
//
// Found by recording a walkthrough and watching the gallery load as three grey
// boxes. A sample is the first page most people publish, so it has to be a page
// that works with nothing else set up.
func TestNoSampleReferencesAFileTheStoreWillNotHave(t *testing.T) {
	for _, st := range All() {
		encoded, err := json.Marshal(st.Sample)
		if err != nil {
			t.Fatal(err)
		}
		for _, ref := range regexp.MustCompile(`/media/[^"]+`).
			FindAllString(string(encoded), -1) {
			t.Errorf("the %s sample points at %s, which no store has. A "+
				"sample is the first page somebody publishes; it has to work "+
				"with nothing else set up.", st.Name, ref)
		}
	}
}

// The arrangement queries have to have something to measure.
//
// The breakpoint rules are @container queries — deliberately, so a split inside
// a narrow column stacks because its column is narrow rather than because the
// window is. A container query with no containment context in the document
// matches nothing at all, and .wrap had none: a hero with an image rendered its
// picture underneath its own heading at any width, which is the shape the
// container query exists to fix.
//
// Found in a screenshot at 1440 pixels. The rule and the thing it measures live
// in different files — one generated, one shipped — which is why nothing caught
// it.
func TestTheArrangementQueriesHaveAContainerToMeasure(t *testing.T) {
	css := CSS()
	if !strings.Contains(css, "@container") {
		t.Skip("no container queries in this build")
	}
	if !strings.Contains(css, "container-type: inline-size") {
		t.Fatal("the stylesheet has @container queries and nothing declares " +
			"container-type, so not one of those rules can ever apply")
	}

	// Specifically on the content column, because that is what every layout
	// puts a hero, a split and a detail grid inside.
	wrap := regexp.MustCompile(`(?s)\n\.wrap \{(.*?)\}`).FindStringSubmatch(css)
	if wrap == nil {
		t.Fatal("no .wrap rule; every layout puts its content in one")
	}
	if !strings.Contains(wrap[1], "container-type") {
		t.Error("the .wrap rule declares no container-type, so anything " +
			"arranged by a container query and not inside a .section is stuck " +
			"in its narrow arrangement forever")
	}

	// And every class those queries arrange must appear inside a wrap in the
	// layouts that use it, or the query still measures the wrong element.
	layouts, err := Layouts()
	if err != nil {
		t.Fatal(err)
	}
	arranged := []string{"hero-split", "split", "detail-grid", "with-side",
		"grid-bento"}
	for name, src := range layouts {
		for _, class := range arranged {
			at := strings.Index(src, `class="`+class)
			if at < 0 {
				continue
			}
			before := src[:at]
			if !strings.Contains(before, `class="wrap`) &&
				!strings.Contains(before, `class="section`) &&
				!strings.Contains(before, `"section"`) {
				t.Errorf("%s.html uses %s with no wrap or section above it, so "+
					"the container query that arranges it has nothing to "+
					"measure", name, class)
			}
		}
	}
}

// A shipped layout can render every kind of field a form declares.
//
// The form block handled a text input and a textarea. internal/form has six
// kinds, two of which — choice and agree — are the ones a lawful form needs: a
// consent box is an agree field, and Form.Notice is mandatory precisely because
// consent is. A page declaring either rendered nothing for it, and the server
// then refused the submission with "this submission was not accepted", which is
// deliberately uninformative because it is what a spam script is told.
//
// Found by declaring a wholesale form with a choice and a consent box, and
// getting a page with one hidden honeypot on it.
func TestAFormLayoutCanRenderEveryKindOfField(t *testing.T) {
	layouts, err := Layouts()
	if err != nil {
		t.Fatal(err)
	}
	for name, src := range layouts {
		if !strings.Contains(src, "page.fields") {
			continue
		}
		for control, why := range map[string]string{
			"<textarea":       "a para field",
			"<select":         "a choice field, which is refused when it arrives empty",
			`type="checkbox"`: "an agree field, which is how consent is given",
		} {
			if !strings.Contains(src, control) {
				t.Errorf("%s.html renders a form and has no %s, so %s cannot "+
					"be filled in on a page using it", name, control, why)
			}
		}
		// The two undeclared fields every form needs.
		if !strings.Contains(src, "website_url") {
			t.Errorf("%s.html has no honeypot; every submission is refused", name)
		}
		if !strings.Contains(src, "form_started") {
			t.Errorf("%s.html carries no timing stamp; every submission is "+
				"refused", name)
		}
	}
}
