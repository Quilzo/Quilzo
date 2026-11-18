// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/theme"
	"github.com/quilzo/quilzo/internal/tmpl"
)

// What a reader is shown, measured.
//
// `theme check` measures the pairs the theme declares, and the stylesheet
// the site serves is what decides which colour is drawn on which. It faded
// the hero's standfirst with an opacity, tinted the hero's chip with a mix no
// pair held, faded a featured plan's "/month", and left a closing band's
// standfirst in the secondary text colour over the hero's own container,
// a pair the theme never checks. Every site `site new` built, and every
// palette `theme generate` made, passed the check and the publish gate and
// served words down to 2.59:1.
//
// So this renders every page `site new` builds, for every kind of site, and
// reads the stylesheet the site serves as a browser reads it: its selectors,
// the cascade, inheritance, var(), color-mix(), opacity, and every
// background behind each word, gradients and translucent ones included. It
// measures every word against what is behind it, in each scheme, for the
// look each kind is built with and for palettes `theme generate` makes in
// every scheme and contrast level, on every style. A word over a picture is
// left to the backdrop's own check, which judges it against the worst
// picture its veil can cover.
//
// What it does not read: the states a reader has to bring about (hover,
// focus, a selection), generated content, and the rules for printing,
// forced colours and asking for more contrast, each of which draws in the
// reader's colours or ones that only add contrast.

// drawnSite is a site `site new` built, its pages rendered and read.
type drawnSite struct {
	kind   string
	design string
	pages  map[string]*dnode
}

// renderedSites builds a site of every kind as `site new` does, with no
// model, and renders every page through the design it installed.
func renderedSites(t *testing.T) []drawnSite {
	t.Helper()
	var out []drawnSite
	for _, k := range feature.SiteKinds() {
		root, design := siteStore(t)
		builtAndInstalled(t, root, feature.SiteBrief{Kind: k.Name, Name: "Sample " + k.Name,
			Description: "A " + k.Name + " site for a small team in Leeds"}, false)
		pages := map[string]*dnode{}
		for name, html := range renderDraft(t, root, design) {
			pages[name] = parsePage(html)
		}
		out = append(out, drawnSite{kind: k.Name, design: design, pages: pages})
	}
	return out
}

// renderDraft renders every draft page as the publish gate renders it.
func renderDraft(t *testing.T, root, dir string) map[string]string {
	t.Helper()
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	commit := s.GetRef(site.RefDraft)
	pages, err := site.PagesAt(s, commit)
	if err != nil {
		t.Fatal(err)
	}
	design, err := loadDesign(dir)
	if err != nil {
		t.Fatal(err)
	}
	src := sourcesFor(root, s, commit, siteName(root), pages)
	src.IconStyle = design.Theme.IconStyle()
	out := map[string]string{}
	for name, body := range pages {
		ctx, err := src.For(name, body, nil)
		if err != nil {
			t.Fatalf("assembling %s: %v", name, err)
		}
		_, layout, err := design.Layouts.For(body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		html, err := tmpl.Render(layout, ctx)
		if err != nil {
			t.Fatalf("rendering %s: %v", name, err)
		}
		out[name] = html
	}
	return out
}

// drawnFailure is a word below its ratio.
type drawnFailure struct {
	where, text string
	ratio, need float64
}

// measureSite measures every word on every page of a site, with the
// stylesheet the design in dir serves, in the colours of th.
func measureSite(ds drawnSite, sheet *drawnSheet, th *theme.Theme) []drawnFailure {
	var out []drawnFailure
	schemes := []bool{false, true}
	switch th.Scheme() {
	case "light":
		schemes = []bool{false}
	case "dark":
		schemes = []bool{true}
	}
	names := make([]string, 0, len(ds.pages))
	for n := range ds.pages {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, dark := range schemes {
		tokens := map[string]string{}
		for _, tok := range theme.Tokens() {
			v, _ := th.Value(tok.Name, dark)
			tokens[tok.Name] = v
		}
		for _, name := range names {
			c := sheet.cascade(name, ds.pages[name], dark)
			for _, f := range c.measure(tokens) {
				f.where = fmt.Sprintf("/%s %s (%s)", name, f.where, schemeName(dark))
				out = append(out, f)
			}
		}
	}
	return out
}

// Every word on every page of every kind of site `site new` builds is at
// its ratio against what is drawn behind it, in the look it is built with.
func TestEveryWordSiteNewDrawsIsReadable(t *testing.T) {
	for _, ds := range renderedSites(t) {
		d, err := loadDesign(ds.design)
		if err != nil {
			t.Fatal(err)
		}
		sheet := newDrawnSheet(d.Stylesheet)
		reportDrawn(t, ds.kind+" as built", measureSite(ds, sheet, d.Theme))
	}
}

// And in every palette `theme generate` makes, in every scheme and at every
// contrast level, on every style: the generated text is chosen against the
// pairs with nothing to spare, so whatever the stylesheet does to a pair it
// does not check shows here first.
func TestEveryWordIsReadableInEveryGeneratedPalette(t *testing.T) {
	sites := renderedSites(t)
	var palettes []map[string]string
	var named []string
	// Standard contrast is the one with nothing to spare, so every scheme is
	// measured at it; the higher levels once, as they only add contrast.
	add := func(seed, scheme, level string) {
		p, err := theme.GenerateWith(seed, theme.Options{Scheme: scheme, Contrast: level})
		if err != nil {
			t.Fatalf("%s %s %s: %v", seed, scheme, level, err)
		}
		palettes = append(palettes, p)
		named = append(named, seed+" "+scheme+" "+level)
	}
	for _, seed := range []string{"#7b2ff7", "#e4572e", "#3b6ea5"} {
		for _, scheme := range theme.Schemes {
			add(seed, scheme, "standard")
		}
	}
	add("#7b2ff7", "tonal", "medium")
	add("#7b2ff7", "tonal", "high")
	for _, style := range theme.Styles {
		for _, ds := range sites {
			// The stylesheet for this style, read once; each palette is then
			// only its colours.
			if err := writeThemeFile(ds.design, map[string]string{"style": style}); err != nil {
				t.Fatal(err)
			}
			d, err := loadDesign(ds.design)
			if err != nil {
				t.Fatal(err)
			}
			sheet := newDrawnSheet(d.Stylesheet)
			for i, p := range palettes {
				over := map[string]string{"style": style}
				for k, v := range p {
					over[k] = v
				}
				th, problems := theme.New(over, nil)
				if theme.Blocks(problems) || theme.Blocks(th.Check()) {
					t.Fatalf("%s on %s does not pass theme check: %v", named[i], style, problems)
				}
				reportDrawn(t, fmt.Sprintf("%s, %s style, %s", ds.kind, style, named[i]), measureSite(ds, sheet, th))
			}
		}
	}
}

// reportDrawn says each word below its ratio, a few to a site.
func reportDrawn(t *testing.T, what string, fails []drawnFailure) {
	t.Helper()
	seen := map[string]bool{}
	n := 0
	for _, f := range fails {
		key := f.where
		if i := strings.Index(key, " ("); i >= 0 {
			key = key[strings.Index(key, " ")+1 : i]
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		if n++; n > 6 {
			t.Errorf("%s: and more", what)
			return
		}
		t.Errorf("%s: %s %q is %.2f:1 and needs %.1f:1", what, f.where, f.text, f.ratio, f.need)
	}
}

// -- a page, as a tree --------------------------------------------------------

// dnode is one element of a rendered page.
type dnode struct {
	tag     string
	attrs   map[string]string
	classes []string
	parent  *dnode
	kids    []*dnode
	text    string
	id      int
}

var (
	voidTags = map[string]bool{"area": true, "base": true, "br": true, "col": true, "embed": true,
		"hr": true, "img": true, "input": true, "link": true, "meta": true, "source": true,
		"track": true, "wbr": true}
	rawTags   = map[string]bool{"script": true, "style": true, "textarea": true, "title": true}
	autoClose = map[string][]string{"p": {"p"}, "li": {"li"}, "dt": {"dt", "dd"}, "dd": {"dt", "dd"},
		"tr": {"tr"}, "td": {"td", "th"}, "th": {"td", "th"}, "option": {"option"}}
)

// parsePage reads rendered HTML into a tree: enough of the parsing rules for
// what the layouts write, which is well formed.
func parsePage(src string) *dnode {
	doc := &dnode{tag: "#document", attrs: map[string]string{}}
	cur, count := doc, 0
	for i := 0; i < len(src); {
		lt := strings.IndexByte(src[i:], '<')
		if lt < 0 {
			cur.text += src[i:]
			break
		}
		cur.text += src[i : i+lt]
		i += lt
		rest := src[i:]
		switch {
		case strings.HasPrefix(rest, "<!--"):
			end := strings.Index(rest, "-->")
			if end < 0 {
				return doc
			}
			i += end + 3
		case strings.HasPrefix(rest, "<!"), strings.HasPrefix(rest, "<?"):
			end := strings.IndexByte(rest, '>')
			if end < 0 {
				return doc
			}
			i += end + 1
		case strings.HasPrefix(rest, "</"):
			end := strings.IndexByte(rest, '>')
			if end < 0 {
				return doc
			}
			name := strings.ToLower(strings.TrimSpace(rest[2:end]))
			i += end + 1
			for n := cur; n != doc; n = n.parent {
				if n.tag == name {
					cur = n.parent
					break
				}
			}
		default:
			name, attrs, selfClose, used := readTag(rest)
			if name == "" {
				cur.text += "<"
				i++
				continue
			}
			i += used
			for _, c := range autoClose[name] {
				if cur.tag == c {
					cur = cur.parent
					break
				}
			}
			count++
			n := &dnode{tag: name, attrs: attrs, parent: cur, classes: strings.Fields(attrs["class"]), id: count}
			cur.kids = append(cur.kids, n)
			if rawTags[name] {
				end := strings.Index(strings.ToLower(src[i:]), "</"+name)
				if end < 0 {
					return doc
				}
				i += end
				continue
			}
			if !voidTags[name] && !selfClose {
				cur = n
			}
		}
	}
	return doc
}

// readTag reads a start tag: its name, its attributes, whether it closes
// itself, and how much of s it was.
func readTag(s string) (string, map[string]string, bool, int) {
	i := 1
	for i < len(s) && (cssNameChar(s[i]) || s[i] == ':') {
		i++
	}
	name := strings.ToLower(s[1:i])
	if name == "" {
		return "", nil, false, 0
	}
	attrs := map[string]string{}
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\n' || s[i] == '\t' || s[i] == '\r') {
			i++
		}
		if i >= len(s) {
			break
		}
		if s[i] == '>' {
			return name, attrs, false, i + 1
		}
		if s[i] == '/' && i+1 < len(s) && s[i+1] == '>' {
			return name, attrs, true, i + 2
		}
		start := i
		for i < len(s) && s[i] != '=' && s[i] != '>' && s[i] != ' ' && s[i] != '/' && s[i] != '\n' && s[i] != '\t' {
			i++
		}
		key := strings.ToLower(s[start:i])
		if key == "" {
			i++
			continue
		}
		val := ""
		if i < len(s) && s[i] == '=' {
			i++
			if i < len(s) && (s[i] == '"' || s[i] == '\'') {
				q := s[i]
				end := strings.IndexByte(s[i+1:], q)
				if end < 0 {
					return name, attrs, false, len(s)
				}
				val = s[i+1 : i+1+end]
				i += end + 2
			} else {
				start := i
				for i < len(s) && s[i] != ' ' && s[i] != '>' {
					i++
				}
				val = s[start:i]
			}
		}
		attrs[key] = val
	}
	return name, attrs, false, len(s)
}

// -- a stylesheet, as rules ---------------------------------------------------

type ddecl struct {
	prop, value string
	important   bool
}

type drule struct {
	sels  []dsel
	decls []ddecl
	order int
	// dark and light say which scheme an @media around the rule is for;
	// neither is a rule for both.
	dark, light bool
}

type dsel struct {
	parts []dcompound
	combs []byte
	spec  int
}

type dcompound struct {
	tag     string
	id      string
	classes []string
	attrs   [][3]string
	pseudos []dpseudo
}

type dpseudo struct {
	name string
	args []dsel
}

// drawnSheet is a served stylesheet, read once, and the cascade of each page
// it has been asked about, kept for each scheme.
type drawnSheet struct {
	rules []drule
	pages map[string]*drawnCascade
	// byKey are the rules each selector's last part could match, by a class
	// it names, else its element, else "*": an element is asked only about
	// the rules that could be its.
	byKey map[string][]int
}

func newDrawnSheet(css string) *drawnSheet {
	sh := &drawnSheet{pages: map[string]*drawnCascade{}}
	var body strings.Builder
	for i := 0; i < len(css); i++ {
		if strings.HasPrefix(css[i:], "/*") {
			end := strings.Index(css[i+2:], "*/")
			if end < 0 {
				break
			}
			i += end + 3
			continue
		}
		body.WriteByte(css[i])
	}
	sh.read(body.String(), false, false)
	sh.byKey = map[string][]int{}
	for i, r := range sh.rules {
		keys := map[string]bool{}
		for _, sel := range r.sels {
			last := sel.parts[len(sel.parts)-1]
			switch {
			case len(last.classes) > 0:
				keys["."+last.classes[0]] = true
			case last.tag != "":
				keys[last.tag] = true
			default:
				keys["*"] = true
			}
		}
		for k := range keys {
			sh.byKey[k] = append(sh.byKey[k], i)
		}
	}
	return sh
}

// candidates are the rules that could match n, in order.
func (sh *drawnSheet) candidates(n *dnode) []int {
	seen := map[int]bool{}
	var out []int
	add := func(key string) {
		for _, i := range sh.byKey[key] {
			if !seen[i] {
				seen[i] = true
				out = append(out, i)
			}
		}
	}
	add("*")
	add(n.tag)
	for _, c := range n.classes {
		add("." + c)
	}
	sort.Ints(out)
	return out
}

// read reads a block of rules. An at-rule whose rules a resting page on a
// wide screen does not draw with is left out.
func (sh *drawnSheet) read(s string, dark, light bool) {
	for {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		open := strings.IndexAny(s, "{;")
		if open < 0 {
			return
		}
		if s[open] == ';' {
			s = s[open+1:]
			continue
		}
		prelude := strings.TrimSpace(s[:open])
		depth, end := 0, -1
		for i := open; i < len(s); i++ {
			if s[i] == '{' {
				depth++
			} else if s[i] == '}' {
				depth--
				if depth == 0 {
					end = i
					break
				}
			}
		}
		if end < 0 {
			return
		}
		inner := s[open+1 : end]
		s = s[end+1:]
		if strings.HasPrefix(prelude, "@") {
			cond := strings.ToLower(prelude)
			switch {
			case strings.HasPrefix(cond, "@media"):
				switch {
				case strings.Contains(cond, "print"), strings.Contains(cond, "forced-colors"),
					strings.Contains(cond, "prefers-contrast"), strings.Contains(cond, "no-preference"),
					strings.Contains(cond, "max-width"):
					continue
				case strings.Contains(cond, "prefers-color-scheme: dark"):
					sh.read(inner, true, false)
				case strings.Contains(cond, "prefers-color-scheme: light"):
					sh.read(inner, false, true)
				default:
					sh.read(inner, dark, light)
				}
			case strings.HasPrefix(cond, "@supports"):
				if !strings.Contains(cond, "animation-timeline") {
					sh.read(inner, dark, light)
				}
			case strings.HasPrefix(cond, "@container"), strings.HasPrefix(cond, "@layer"),
				strings.HasPrefix(cond, "@scope"):
				sh.read(inner, dark, light)
			}
			continue
		}
		var sels []dsel
		for _, one := range splitTop(prelude, ',') {
			if sel, ok := parseSel(strings.TrimSpace(one)); ok {
				sels = append(sels, sel)
			}
		}
		if len(sels) == 0 {
			continue
		}
		r := drule{sels: sels, order: len(sh.rules), dark: dark, light: light}
		for _, d := range splitTop(inner, ';') {
			prop, value, found := strings.Cut(d, ":")
			if !found {
				continue
			}
			value = strings.TrimSpace(value)
			important := false
			if v, cut := strings.CutSuffix(value, "!important"); cut {
				value, important = strings.TrimSpace(v), true
			}
			r.decls = append(r.decls, ddecl{prop: strings.ToLower(strings.TrimSpace(prop)), value: value, important: important})
		}
		sh.rules = append(sh.rules, r)
	}
}

// splitTop splits s at sep outside brackets and quotes.
func splitTop(s string, sep byte) []string {
	var out []string
	depth, start := 0, 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '(' || c == '[':
			depth++
		case c == ')' || c == ']':
			depth--
		case c == sep && depth == 0:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// staticPseudo are the pseudo-classes a page at rest can be matched against.
var staticPseudo = map[string]bool{"root": true, "first-child": true, "last-child": true,
	"only-child": true, "first-of-type": true, "last-of-type": true, "checked": true,
	"not": true, "is": true, "where": true, "link": true, "any-link": true}

// parseSel reads one selector. ok is false for one that names a
// pseudo-element, which draws generated content and not the page's words.
func parseSel(s string) (dsel, bool) {
	var sel dsel
	cur := dcompound{}
	have := false
	pendingComb := byte(0)
	flush := func() {
		if !have {
			return
		}
		if len(sel.parts) > 0 {
			c := pendingComb
			if c == 0 {
				c = ' '
			}
			sel.combs = append(sel.combs, c)
		}
		sel.parts = append(sel.parts, cur)
		cur, have, pendingComb = dcompound{}, false, 0
	}
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\n' || c == '\t':
			flush()
			i++
		case c == '>' || c == '+' || c == '~':
			flush()
			pendingComb = c
			i++
		case c == '*':
			have = true
			i++
		case c == '.' || c == '#':
			j := i + 1
			for j < len(s) && cssNameChar(s[j]) {
				j++
			}
			if c == '.' {
				cur.classes = append(cur.classes, s[i+1:j])
			} else {
				cur.id = s[i+1 : j]
			}
			have, i = true, j
		case c == '[':
			end := strings.IndexByte(s[i:], ']')
			if end < 0 {
				return sel, false
			}
			body := s[i+1 : i+end]
			attr := [3]string{strings.ToLower(strings.TrimSpace(body)), "", ""}
			for _, op := range []string{"~=", "^=", "$=", "*=", "|=", "="} {
				if k, v, found := strings.Cut(body, op); found {
					attr = [3]string{strings.ToLower(strings.TrimSpace(k)), op, strings.Trim(strings.TrimSpace(v), `"'`)}
					break
				}
			}
			cur.attrs = append(cur.attrs, attr)
			have, i = true, i+end+1
		case c == ':':
			if strings.HasPrefix(s[i:], "::") {
				return sel, false
			}
			j := i + 1
			for j < len(s) && cssNameChar(s[j]) {
				j++
			}
			name := strings.ToLower(s[i+1 : j])
			if name == "before" || name == "after" || name == "marker" || name == "first-line" || name == "first-letter" {
				return sel, false
			}
			p := dpseudo{name: name}
			if j < len(s) && s[j] == '(' {
				depth, k := 0, j
				for ; k < len(s); k++ {
					if s[k] == '(' {
						depth++
					} else if s[k] == ')' {
						depth--
						if depth == 0 {
							break
						}
					}
				}
				if name == "not" || name == "is" || name == "where" {
					for _, a := range splitTop(s[j+1:k], ',') {
						arg, ok := parseSel(strings.TrimSpace(a))
						if !ok {
							return sel, false
						}
						p.args = append(p.args, arg)
					}
				}
				j = k + 1
			}
			cur.pseudos = append(cur.pseudos, p)
			have, i = true, j
		default:
			j := i
			for j < len(s) && cssNameChar(s[j]) {
				j++
			}
			if j == i {
				return sel, false
			}
			cur.tag = strings.ToLower(s[i:j])
			have, i = true, j
		}
	}
	flush()
	if len(sel.parts) == 0 {
		return sel, false
	}
	sel.spec = specificity(sel)
	return sel, true
}

func specificity(sel dsel) int {
	n := 0
	for _, c := range sel.parts {
		if c.id != "" {
			n += 10000
		}
		n += 100 * (len(c.classes) + len(c.attrs))
		if c.tag != "" {
			n++
		}
		for _, p := range c.pseudos {
			switch p.name {
			case "where":
			case "not", "is":
				most := 0
				for _, a := range p.args {
					most = max(most, a.spec)
				}
				n += most
			default:
				n += 100
			}
		}
	}
	return n
}

func (sel dsel) matches(n *dnode) bool { return matchFrom(sel, len(sel.parts)-1, n) }

func matchFrom(sel dsel, i int, n *dnode) bool {
	if n == nil || n.tag == "#document" || !matchCompound(sel.parts[i], n) {
		return false
	}
	if i == 0 {
		return true
	}
	switch sel.combs[i-1] {
	case '>':
		return matchFrom(sel, i-1, n.parent)
	case '+':
		return matchFrom(sel, i-1, prevSibling(n))
	case '~':
		for p := prevSibling(n); p != nil; p = prevSibling(p) {
			if matchFrom(sel, i-1, p) {
				return true
			}
		}
		return false
	default:
		for p := n.parent; p != nil && p.tag != "#document"; p = p.parent {
			if matchFrom(sel, i-1, p) {
				return true
			}
		}
		return false
	}
}

func prevSibling(n *dnode) *dnode {
	if n.parent == nil {
		return nil
	}
	var prev *dnode
	for _, k := range n.parent.kids {
		if k == n {
			return prev
		}
		prev = k
	}
	return nil
}

func matchCompound(c dcompound, n *dnode) bool {
	if c.tag != "" && c.tag != n.tag {
		return false
	}
	if c.id != "" && n.attrs["id"] != c.id {
		return false
	}
	for _, want := range c.classes {
		found := false
		for _, have := range n.classes {
			if have == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for _, a := range c.attrs {
		v, ok := n.attrs[a[0]]
		if !ok {
			return false
		}
		switch a[1] {
		case "=":
			ok = v == a[2]
		case "~=":
			ok = false
			for _, w := range strings.Fields(v) {
				ok = ok || w == a[2]
			}
		case "^=":
			ok = strings.HasPrefix(v, a[2])
		case "$=":
			ok = strings.HasSuffix(v, a[2])
		case "*=":
			ok = strings.Contains(v, a[2])
		case "|=":
			ok = v == a[2] || strings.HasPrefix(v, a[2]+"-")
		}
		if !ok {
			return false
		}
	}
	for _, p := range c.pseudos {
		if !staticPseudo[p.name] {
			return false
		}
		sibs := n.parent.kids
		switch p.name {
		case "root":
			if n.parent.tag != "#document" {
				return false
			}
		case "first-child":
			if sibs[0] != n {
				return false
			}
		case "last-child":
			if sibs[len(sibs)-1] != n {
				return false
			}
		case "only-child":
			if len(sibs) != 1 {
				return false
			}
		case "first-of-type", "last-of-type":
			var same []*dnode
			for _, k := range sibs {
				if k.tag == n.tag {
					same = append(same, k)
				}
			}
			if p.name == "first-of-type" && same[0] != n || p.name == "last-of-type" && same[len(same)-1] != n {
				return false
			}
		case "checked":
			if _, ok := n.attrs["checked"]; !ok {
				if _, ok := n.attrs["selected"]; !ok {
					return false
				}
			}
		case "link", "any-link":
			if _, ok := n.attrs["href"]; n.tag != "a" || !ok {
				return false
			}
		case "not":
			for _, a := range p.args {
				if a.matches(n) {
					return false
				}
			}
		case "is", "where":
			found := false
			for _, a := range p.args {
				found = found || a.matches(n)
			}
			if !found {
				return false
			}
		}
	}
	return true
}

// -- the cascade --------------------------------------------------------------

// drawnCascade is one page, each element's declarations in the order the
// cascade applies them.
type drawnCascade struct {
	doc   *dnode
	decls map[*dnode][]ddecl
}

// cascade is a page's declarations, matched once per scheme.
func (sh *drawnSheet) cascade(name string, doc *dnode, dark bool) *drawnCascade {
	key := fmt.Sprintf("%s %p %v", name, doc, dark)
	if c, ok := sh.pages[key]; ok {
		return c
	}
	c := &drawnCascade{doc: doc, decls: map[*dnode][]ddecl{}}
	type hit struct {
		important bool
		spec      int
		order     int
		n         int
		d         ddecl
	}
	var walk func(n *dnode)
	walk = func(n *dnode) {
		if n.tag != "#document" {
			var hits []hit
			for _, ri := range sh.candidates(n) {
				r := sh.rules[ri]
				if r.dark && !dark || r.light && dark {
					continue
				}
				best := -1
				for _, sel := range r.sels {
					if sel.spec > best && sel.matches(n) {
						best = sel.spec
					}
				}
				if best < 0 {
					continue
				}
				for i, d := range r.decls {
					hits = append(hits, hit{d.important, best, r.order, i, d})
				}
			}
			if style := n.attrs["style"]; style != "" {
				for i, d := range splitTop(style, ';') {
					if prop, value, found := strings.Cut(d, ":"); found {
						hits = append(hits, hit{false, 1 << 30, 1 << 30, i,
							ddecl{prop: strings.ToLower(strings.TrimSpace(prop)), value: strings.TrimSpace(value)}})
					}
				}
			}
			sort.SliceStable(hits, func(i, j int) bool {
				a, b := hits[i], hits[j]
				if a.important != b.important {
					return !a.important
				}
				if a.spec != b.spec {
					return a.spec < b.spec
				}
				if a.order != b.order {
					return a.order < b.order
				}
				return a.n < b.n
			})
			for _, h := range hits {
				c.decls[n] = append(c.decls[n], h.d)
			}
		}
		for _, k := range n.kids {
			walk(k)
		}
	}
	walk(doc)
	sh.pages[key] = c
	return c
}

// rgba is a colour and how much of what is under it it covers.
type rgba struct{ r, g, b, a float64 }

func (c rgba) over(under rgba) rgba {
	return rgba{c.r*c.a + under.r*(1-c.a), c.g*c.a + under.g*(1-c.a), c.b*c.a + under.b*(1-c.a), 1}
}

func (c rgba) hex() string {
	ch := func(f float64) int { return int(math.Round(math.Max(0, math.Min(1, f)) * 255)) }
	return fmt.Sprintf("#%02x%02x%02x", ch(c.r), ch(c.g), ch(c.b))
}

// bgLayer is one layer of an element's background: the colours it can be,
// or a picture.
type bgLayer struct {
	colours []rgba
	picture bool
}

// drawn is what the cascade gave one element, in one palette.
type drawn struct {
	colour  rgba
	known   bool
	layers  []bgLayer // the bottom one first
	clip    bool      // the background is clipped to the text
	opacity float64
	hidden  bool
	custom  map[string]string
}

// measure is every word on the page, measured in a palette's tokens.
func (c *drawnCascade) measure(tokens map[string]string) []drawnFailure {
	var out []drawnFailure
	computed := map[*dnode]*drawn{}
	var visit func(n *dnode, stack []*dnode)
	visit = func(n *dnode, stack []*dnode) {
		if n.tag != "#document" {
			if n.tag == "head" || n.tag == "svg" || n.tag == "template" || n.tag == "noscript" {
				return
			}
			if _, hidden := n.attrs["hidden"]; hidden {
				return
			}
			d := c.compute(n, computed, tokens)
			computed[n] = d
			if d.hidden {
				return
			}
			stack = append(stack, n)
			if text := strings.TrimSpace(strings.ReplaceAll(n.text, "&nbsp;", " ")); text != "" {
				if f, bad := c.judge(stack, computed, text); bad {
					out = append(out, f)
				}
			}
		}
		for _, k := range n.kids {
			visit(k, stack)
		}
	}
	visit(c.doc, nil)
	return out
}

// compute applies an element's declarations over what it inherits.
func (c *drawnCascade) compute(n *dnode, computed map[*dnode]*drawn, tokens map[string]string) *drawn {
	parent := computed[n.parent]
	d := &drawn{opacity: 1, custom: map[string]string{}}
	if parent != nil {
		d.colour, d.known = parent.colour, parent.known
	} else {
		d.colour, d.known = rgba{0, 0, 0, 1}, true
	}
	lookup := func(name string) (string, bool) {
		if v, ok := d.custom[name]; ok {
			return v, true
		}
		for p := n.parent; p != nil; p = p.parent {
			pd := computed[p]
			if pd == nil {
				continue
			}
			if v, ok := pd.custom[name]; ok {
				return v, true
			}
		}
		v, ok := tokens[name]
		return v, ok
	}
	isRoot := n.parent != nil && n.parent.tag == "#document"
	var bgColour, bgImage string
	for _, decl := range c.decls[n] {
		if name, custom := strings.CutPrefix(decl.prop, "--"); custom {
			// The tokens are the palette being measured, whatever the
			// stylesheet was generated with.
			if _, token := tokens[name]; token && isRoot {
				continue
			}
			d.custom[name] = decl.value
			continue
		}
		switch decl.prop {
		case "color":
			v := substitute(decl.value, lookup, 0)
			switch strings.ToLower(v) {
			case "inherit", "unset", "currentcolor":
				if parent != nil {
					d.colour, d.known = parent.colour, parent.known
				}
			default:
				cur := rgba{0, 0, 0, 1}
				if parent != nil {
					cur = parent.colour
				}
				if col, ok := parseColour(v, cur); ok {
					d.colour, d.known = col, true
				} else {
					d.known = false
				}
			}
		case "background":
			bgColour, bgImage = decl.value, decl.value
		case "background-color":
			bgColour = decl.value
		case "background-image":
			bgImage = decl.value
		case "background-clip", "-webkit-background-clip":
			d.clip = strings.Contains(decl.value, "text")
		case "opacity":
			v := strings.TrimSpace(decl.value)
			if pct, isPct := strings.CutSuffix(v, "%"); isPct {
				if f, err := strconv.ParseFloat(pct, 64); err == nil {
					d.opacity = f / 100
				}
			} else if f, err := strconv.ParseFloat(v, 64); err == nil {
				d.opacity = f
			}
		case "display":
			d.hidden = d.hidden || strings.TrimSpace(decl.value) == "none"
		case "visibility":
			d.hidden = d.hidden || strings.TrimSpace(decl.value) == "hidden"
		case "clip-path":
			d.hidden = d.hidden || strings.Contains(decl.value, "inset(50%)")
		}
	}
	d.layers = backgroundLayers(substitute(bgColour, lookup, 0), substitute(bgImage, lookup, 0), d.colour, bgColour == bgImage)
	return d
}

// substitute puts each var() in a value in place, from the element's custom
// properties and then the palette's tokens.
func substitute(v string, lookup func(string) (string, bool), depth int) string {
	if depth > 12 {
		return v
	}
	for {
		i := strings.Index(v, "var(")
		if i < 0 {
			return v
		}
		depthP, end := 0, -1
		for j := i + 3; j < len(v); j++ {
			if v[j] == '(' {
				depthP++
			} else if v[j] == ')' {
				depthP--
				if depthP == 0 {
					end = j
					break
				}
			}
		}
		if end < 0 {
			return v
		}
		args := splitTop(v[i+4:end], ',')
		name := strings.TrimPrefix(strings.TrimSpace(args[0]), "--")
		got, ok := lookup(name)
		if !ok && len(args) > 1 {
			got, ok = strings.Join(args[1:], ","), true
		}
		if !ok {
			got = ""
		}
		v = v[:i] + substitute(strings.TrimSpace(got), lookup, depth+1) + v[end+1:]
	}
}

// backgroundLayers reads an element's background: its colour at the bottom
// and its images over it, each a gradient's colours or a picture.
func backgroundLayers(colour, image string, current rgba, shorthand bool) []bgLayer {
	var out []bgLayer
	if shorthand {
		parts := splitTop(colour, ',')
		for i := len(parts) - 1; i >= 0; i-- {
			if l, ok := layerOf(parts[i], current, i == len(parts)-1); ok {
				out = append(out, l)
			}
		}
		return out
	}
	if l, ok := layerOf(colour, current, true); ok {
		out = append(out, l)
	}
	parts := splitTop(image, ',')
	for i := len(parts) - 1; i >= 0; i-- {
		if l, ok := layerOf(parts[i], current, false); ok && (len(l.colours) > 0 || l.picture) {
			out = append(out, l)
		}
	}
	return out
}

// layerOf is one background layer; withColour says the layer may hold the
// background colour, which only the last of a shorthand does.
func layerOf(v string, current rgba, withColour bool) (bgLayer, bool) {
	v = strings.TrimSpace(v)
	lv := strings.ToLower(v)
	if lv == "" || lv == "none" || lv == "transparent" || lv == "initial" || lv == "unset" {
		return bgLayer{}, false
	}
	if strings.Contains(lv, "url(") {
		return bgLayer{picture: true}, true
	}
	if i := strings.Index(lv, "gradient("); i >= 0 {
		open := i + len("gradient(")
		depth, end := 1, len(v)
		for j := open; j < len(v); j++ {
			if v[j] == '(' {
				depth++
			} else if v[j] == ')' {
				depth--
				if depth == 0 {
					end = j
					break
				}
			}
		}
		var l bgLayer
		for _, stop := range splitTop(v[open:end], ',') {
			for _, word := range splitTop(strings.TrimSpace(stop), ' ') {
				if col, ok := parseColour(word, current); ok {
					l.colours = append(l.colours, col)
					break
				}
			}
		}
		rest := strings.TrimSpace(v[end+1:])
		if withColour && rest != "" {
			for _, word := range splitTop(rest, ' ') {
				if col, ok := parseColour(word, current); ok {
					return bgLayer{colours: []rgba{col}}, true
				}
			}
		}
		return l, len(l.colours) > 0
	}
	if !withColour {
		return bgLayer{}, false
	}
	for _, word := range splitTop(v, ' ') {
		if col, ok := parseColour(word, current); ok {
			if col.a == 0 {
				return bgLayer{}, false
			}
			return bgLayer{colours: []rgba{col}}, true
		}
	}
	return bgLayer{}, false
}

// parseColour reads a colour as the stylesheet writes one.
func parseColour(v string, current rgba) (rgba, bool) {
	v = strings.TrimSpace(v)
	lv := strings.ToLower(v)
	switch lv {
	case "transparent":
		return rgba{}, true
	case "currentcolor":
		return current, true
	case "white":
		return rgba{1, 1, 1, 1}, true
	case "black":
		return rgba{0, 0, 0, 1}, true
	}
	if strings.HasPrefix(lv, "#") {
		h := lv[1:]
		if len(h) == 3 || len(h) == 4 {
			var b strings.Builder
			for _, ch := range h {
				b.WriteRune(ch)
				b.WriteRune(ch)
			}
			h = b.String()
		}
		if len(h) != 6 && len(h) != 8 {
			return rgba{}, false
		}
		n, err := strconv.ParseUint(h, 16, 64)
		if err != nil {
			return rgba{}, false
		}
		a := 1.0
		if len(h) == 8 {
			a = float64(n&0xff) / 255
			n >>= 8
		}
		return rgba{float64(n>>16&0xff) / 255, float64(n>>8&0xff) / 255, float64(n&0xff) / 255, a}, true
	}
	if strings.HasPrefix(lv, "color-mix(") && strings.HasSuffix(lv, ")") {
		args := splitTop(v[len("color-mix("):len(v)-1], ',')
		if len(args) != 3 {
			return rgba{}, false
		}
		var cols [2]rgba
		var pcts [2]float64
		var given [2]bool
		for i, arg := range args[1:] {
			words := splitTop(strings.TrimSpace(arg), ' ')
			colour := strings.TrimSpace(arg)
			if n := len(words); n > 1 && strings.HasSuffix(words[n-1], "%") {
				if f, err := strconv.ParseFloat(strings.TrimSuffix(words[n-1], "%"), 64); err == nil {
					pcts[i], given[i] = f, true
					colour = strings.Join(words[:n-1], " ")
				}
			}
			col, ok := parseColour(colour, current)
			if !ok {
				return rgba{}, false
			}
			cols[i] = col
		}
		p1, p2 := pcts[0], pcts[1]
		switch {
		case !given[0] && !given[1]:
			p1, p2 = 50, 50
		case !given[1]:
			p2 = 100 - p1
		case !given[0]:
			p1 = 100 - p2
		}
		sum := p1 + p2
		if sum <= 0 {
			return rgba{}, false
		}
		scale := math.Min(1, sum/100)
		p1, p2 = p1/sum, p2/sum
		a := cols[0].a*p1 + cols[1].a*p2
		m := rgba{a: a * scale}
		if a > 0 {
			m.r = (cols[0].r*cols[0].a*p1 + cols[1].r*cols[1].a*p2) / a
			m.g = (cols[0].g*cols[0].a*p1 + cols[1].g*cols[1].a*p2) / a
			m.b = (cols[0].b*cols[0].a*p1 + cols[1].b*cols[1].a*p2) / a
		}
		return m, true
	}
	return rgba{}, false
}

// large is text the 3:1 ratio is enough for: the headings, and the figures
// set as large.
func large(stack []*dnode) bool {
	for _, n := range stack {
		switch n.tag {
		case "h1", "h2", "h3":
			return true
		}
		for _, c := range n.classes {
			if c == "amount" {
				return true
			}
		}
	}
	return false
}

// judge measures the words of the last element of stack against what is
// drawn behind them.
func (c *drawnCascade) judge(stack []*dnode, computed map[*dnode]*drawn, text string) (drawnFailure, bool) {
	el := computed[stack[len(stack)-1]]
	if !el.known {
		return drawnFailure{}, false
	}
	need := 4.5
	if large(stack) {
		need = 3
	}
	// The choices: one colour for each layer that can be more than one, at
	// most 64 ways, and the text's own colours where a background is
	// clipped to it.
	var multi [][2]int // element index, layer index
	for i, n := range stack {
		d := computed[n]
		for j, l := range d.layers {
			if len(l.colours) > 1 && !(d.clip && i == len(stack)-1) {
				multi = append(multi, [2]int{i, j})
			}
		}
	}
	texts := []rgba{el.colour}
	if el.clip {
		texts = nil
		for _, l := range el.layers {
			texts = append(texts, l.colours...)
		}
		if len(texts) == 0 {
			return drawnFailure{}, false
		}
	}
	combos := 1
	for _, m := range multi {
		combos *= len(computed[stack[m[0]]].layers[m[1]].colours)
		if combos > 64 {
			combos = 64
			break
		}
	}
	worst := math.Inf(1)
	for combo := 0; combo < combos; combo++ {
		pick := map[[2]int]int{}
		rest := combo
		for _, m := range multi {
			n := len(computed[stack[m[0]]].layers[m[1]].colours)
			pick[m] = rest % n
			rest /= n
		}
		for _, tc := range texts {
			fg, okF := c.paint(stack, computed, pick, &tc)
			bg, okB := c.paint(stack, computed, pick, nil)
			if !okF || !okB {
				return drawnFailure{}, false
			}
			worst = math.Min(worst, theme.Contrast(fg.hex(), bg.hex()))
		}
	}
	if worst >= need-0.005 {
		return drawnFailure{}, false
	}
	return drawnFailure{where: describe(stack), text: clipText(text), ratio: worst, need: need}, true
}

// paint is the colour of one pixel of the last element: under its words, or
// of a word, with each group's opacity laid over what is behind it. ok is
// false where a picture shows through, which the backdrop's check judges.
func (c *drawnCascade) paint(stack []*dnode, computed map[*dnode]*drawn, pick map[[2]int]int, text *rgba) (rgba, bool) {
	picture := false
	var from func(k int, under rgba) rgba
	from = func(k int, under rgba) rgba {
		cur := under
		for i := k; i < len(stack); i++ {
			d := computed[stack[i]]
			if i > k && d.opacity < 1 {
				inner := from(i, cur)
				o := d.opacity
				return rgba{cur.r*(1-o) + inner.r*o, cur.g*(1-o) + inner.g*o, cur.b*(1-o) + inner.b*o, 1}
			}
			if d.clip && i == len(stack)-1 {
				continue
			}
			for j, l := range d.layers {
				if l.picture {
					picture = true
					continue
				}
				col := l.colours[0]
				if len(l.colours) > 1 {
					col = l.colours[pick[[2]int{i, j}]]
				}
				if col.a >= 0.999 {
					picture = false
				}
				cur = col.over(cur)
			}
		}
		if text != nil {
			cur = text.over(cur)
		}
		return cur
	}
	got := from(0, rgba{1, 1, 1, 1})
	return got, !picture
}

func describe(stack []*dnode) string {
	var parts []string
	for _, n := range stack[max(0, len(stack)-3):] {
		p := n.tag
		for _, c := range n.classes {
			p += "." + c
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, " > ")
}

// cssNameChar is a character of a name in CSS or HTML.
func cssNameChar(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' ||
		ch == '-' || ch == '_' || ch >= 0x80
}

func clipText(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 40 {
		return trim(s, 40)
	}
	return s
}
