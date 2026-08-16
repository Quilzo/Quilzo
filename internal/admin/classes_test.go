package admin

import (
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// A class in the markup with no rule in the stylesheet is a decoration nobody
// applied.
//
// Found by looking at the screens rather than at the tests. `.grid2` was on
// three forms and in no stylesheet, so a two-column layout rendered as one tall
// column of controls. `.lead` was on a dozen paragraphs and styled nothing.
// `.hint` — the most used class in this package — had exactly one rule, for its
// warning variant, so every piece of secondary text on every screen was body
// text at body weight.
//
// None of it broke. That is the point: an unstyled class produces a page that
// works, reads acceptably, and is not what anybody designed, so it survives
// every functional test and every accessibility check. Only a person looking at
// the screen notices, and only if they are looking for it.
//
// A missing rule is now a failing test, and a class that is deliberately
// unstyled needs a line in the exemption list below saying so.
func TestEveryClassInTheMarkupIsStyled(t *testing.T) {
	styled := styledClasses(t)
	if len(styled) < 30 {
		t.Fatalf("found %d classes in the stylesheet; the parse is wrong and "+
			"a test that checks nothing passes", len(styled))
	}

	var missing []string
	for class, files := range markupClasses(t) {
		if styled[class] || unstyled[class] != "" {
			continue
		}
		sort.Strings(files)
		missing = append(missing, class+"  ("+strings.Join(files, ", ")+")")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("these classes are in the markup and nothing styles them:\n  %s"+
			"\nAn unstyled class renders a page that works and is not the one "+
			"anybody designed, which is why it survives every other test here.",
			strings.Join(missing, "\n  "))
	}

	// And the exemptions have to be real, or the list becomes the place things
	// go to stop being checked.
	inMarkup := markupClasses(t)
	for class := range unstyled {
		if _, used := inMarkup[class]; !used {
			t.Errorf("%q is excused from needing a rule and is not in any "+
				"template; the exemption is stale", class)
		}
	}
}

// unstyled is every class that is deliberately not styled, and why.
//
// Empty, and worth keeping as an empty map rather than deleting: the first
// version of this test had fourteen entries in it, written from guesses about
// which classes did not need a rule, and twelve of those turned out to be
// styled already. The exemption list is where a real decision goes, and it is
// also where a test quietly stops checking things — so it starts at nothing
// and anything added to it has to carry an argument.
var unstyled = map[string]string{}

var (
	reClassAttr = regexp.MustCompile(`class="([a-z0-9 -]+)"`)
	reCSSClass  = regexp.MustCompile(`\.([a-z][a-z0-9-]*)`)
)

// markupClasses maps each class to the templates using it.
func markupClasses(t *testing.T) map[string][]string {
	t.Helper()
	names, err := fs.Glob(assets, "assets/*.html")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, name := range names {
		b, err := assets.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		short := strings.TrimPrefix(name, "assets/")
		for _, m := range reClassAttr.FindAllStringSubmatch(string(b), -1) {
			for _, c := range strings.Fields(m[1]) {
				out[c] = append(out[c], short)
			}
		}
	}
	return out
}

// styledClasses is every class name appearing in a selector.
//
// Text inside comments and strings is excluded, because the stylesheet in this
// package carries more prose than most programs and a class named in a comment
// is not a rule.
func styledClasses(t *testing.T) map[string]bool {
	t.Helper()
	b, err := assets.ReadFile("assets/style.css")
	if err != nil {
		t.Fatal(err)
	}
	css := stripComments(string(b))

	out := map[string]bool{}
	for _, block := range strings.Split(css, "}") {
		i := strings.Index(block, "{")
		if i < 0 {
			continue
		}
		for _, m := range reCSSClass.FindAllStringSubmatch(block[:i], -1) {
			out[m[1]] = true
		}
	}
	return out
}

func stripComments(css string) string {
	var b strings.Builder
	for {
		i := strings.Index(css, "/*")
		if i < 0 {
			b.WriteString(css)
			return b.String()
		}
		b.WriteString(css[:i])
		j := strings.Index(css[i:], "*/")
		if j < 0 {
			return b.String()
		}
		css = css[i+j+2:]
	}
}
