package admin

import (
	"sort"
	"strings"
	"testing"
)

// Every Help link has to land somewhere.
//
// The footer on every screen points at a section of the manual, named in the
// navigation table. A link that lands on a heading somebody renamed is worse
// than no link at all: the person following it concludes the feature was
// removed, which is exactly the belief this whole documentation effort exists
// to correct.
func TestEveryScreenPointsAtASectionThatExists(t *testing.T) {
	have := anchors()
	if len(have) < 15 {
		t.Fatalf("found %d sections; the parse is wrong", len(have))
	}
	for _, d := range destinations {
		if d.Doc == "" {
			t.Errorf("%q names no documentation section. Every screen has to "+
				"be explained somewhere, and the Help link in its footer is "+
				"where somebody looks.", d.Key)
			continue
		}
		if !have[d.Doc] {
			t.Errorf("%q sends Help to #%s and the manual has no such section",
				d.Key, d.Doc)
		}
	}
}

// And every section has to be reachable.
//
// The other direction. A section nothing links to is one nobody arrives at
// except by reading the contents top to bottom, which is not how anybody uses
// a manual — so it should be either linked from a screen or deliberately part
// of the reading order.
func TestEverySectionIsEitherLinkedOrStandalone(t *testing.T) {
	linked := map[string]bool{}
	for _, d := range destinations {
		linked[d.Doc] = true
	}
	// Sections that no screen owns, because they explain a concept rather than
	// a destination. Each is named, so a section that quietly stops being
	// linked shows up here rather than becoming unreachable.
	standalone := map[string]bool{
		"setup":     true, // the walkthrough, reached from the contents
		"concepts":  true, // the glossary
		"privacy":   true, // a statement, not a screen
		"cli":       true, // a surface with no screen, by definition
		"mcp":       true, // the same
		"history":   true, // reached from the History screen via its own key
		"templates": true, // deliberately has no screen; the section says why
	}
	var orphan []string
	for _, c := range manual {
		for _, sec := range c.Sections {
			if !linked[sec.ID] && !standalone[sec.ID] {
				orphan = append(orphan, sec.ID)
			}
		}
	}
	if len(orphan) > 0 {
		sort.Strings(orphan)
		t.Errorf("these sections are in the manual and nothing points at "+
			"them:\n  %s\nEither link a screen to it or list it as "+
			"standalone.", strings.Join(orphan, "\n  "))
	}
}

// The manual has to actually say something.
//
// A crude measure, deliberately. It is not asserting quality — nothing can —
// it is asserting that the documentation did not get gutted into a stub by
// somebody making a refactor compile, which is how documentation usually dies.
func TestTheManualIsSubstantial(t *testing.T) {
	if n := words(); n < 3000 {
		t.Errorf("the manual is %d words; it was written at several times "+
			"that, so something has been removed", n)
	}
	for _, c := range manual {
		for _, sec := range c.Sections {
			if len(sec.Body) == 0 {
				t.Errorf("section %q has a title and no body", sec.ID)
			}
			if strings.TrimSpace(sec.Summary) == "" {
				t.Errorf("section %q has no summary, so the contents cannot "+
					"say what it is for", sec.ID)
			}
		}
	}
}

// The two chapters a customer asks for by name exist and are specific.
//
// "We have a security page" is a sentence any product can say. This checks the
// one here names what it does not do, because a security page listing only
// strengths is marketing, and a privacy page that does not enumerate what is
// stored is not a privacy page.
func TestSecurityAndPrivacySayTheHardPart(t *testing.T) {
	sec, ok := findSection("security")
	if !ok {
		t.Fatal("there is no security section")
	}
	if !mentions(sec, "does not") {
		t.Error("the security section never says what this does not do. A " +
			"page listing only strengths is marketing.")
	}

	priv, ok := findSection("privacy")
	if !ok {
		t.Fatal("there is no privacy section")
	}
	for _, want := range []string{"pseudonym", "retention", "stored"} {
		if !mentions(priv, want) {
			t.Errorf("the privacy section never mentions %q", want)
		}
	}
}

func mentions(s section, want string) bool {
	if strings.Contains(strings.ToLower(s.Summary), want) {
		return true
	}
	for _, b := range s.Body {
		if strings.Contains(strings.ToLower(b.Text), want) {
			return true
		}
		for _, i := range b.Items {
			if strings.Contains(strings.ToLower(i), want) {
				return true
			}
		}
		for _, row := range b.Rows {
			for _, cell := range row {
				if strings.Contains(strings.ToLower(cell), want) {
					return true
				}
			}
		}
	}
	return false
}

// Every navigation destination is served, and every screen is in the table.
//
// The navigation is data now, so the link test cannot see its hrefs — they are
// template expressions. This is the replacement, and it is stronger: it checks
// the table rather than the rendered output.
func TestEveryDestinationIsServedAndEveryScreenIsADestination(t *testing.T) {
	served := servedRoutes(t)
	for _, d := range destinations {
		if !resolves(served, d.Path) {
			t.Errorf("the navigation offers %q at %s and nothing serves it",
				d.Label, d.Path)
		}
	}

	// The other direction: a screen registered in the mux and absent from the
	// table is a screen nobody can navigate to. Sub-paths and write endpoints
	// are not destinations, so only top-level GET screens are required.
	inNav := map[string]bool{}
	for _, d := range destinations {
		inNav[d.Path] = true
	}
	for route := range served {
		if strings.Count(route, "/") != 1 || strings.HasSuffix(route, "/") {
			continue // a sub-path, or the root pattern
		}
		if _, excused := notADestination[route]; inNav[route] || excused {
			continue
		}
		t.Errorf("%s is served and is not in the navigation table, so nobody "+
			"can reach it by clicking. Add a row, or list it as not a "+
			"destination with a reason.", route)
	}
}

// notADestination is every top-level route that is not a place to navigate to.
var notADestination = map[string]string{
	"/save":         "a form target",
	"/publish":      "a form target",
	"/rollback":     "a form target",
	"/nav":          "a preference toggle",
	"/theme":        "a preference toggle",
	"/signin":       "reached when not signed in",
	"/signout":      "a form target",
	"/style.css":    "a stylesheet",
	"/preview":      "a subtree",
	"/docs":         "in the table, listed here only if the shape changes",
	"/media":        "in the table",
	"/languages":    "in the table",
	"/transfer":     "in the table",
	"/assist":       "in the table",
	"/types":        "in the table",
	"/publishing":   "in the table",
	"/integrations": "in the table",
	"/profile":      "in the table",
}
