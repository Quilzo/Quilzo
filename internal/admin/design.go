// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"github.com/quilzo/quilzo/internal/icons"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/starter"
	"github.com/quilzo/quilzo/internal/theme"
	"github.com/quilzo/quilzo/internal/webfont"
)

// The design screen: the tokens, the layouts and the typefaces, in the browser.
//
// # Why this screen exists rather than a stylesheet field
//
// Every capability in this program has to exist in all three interfaces or carry
// a written reason. Until now the design was the exception nobody had noticed:
// applying a starter in the browser wrote its sample content and left the markup
// alone, so somebody who only ever used the admin got the fields of a design
// they were not being served. The screen and the command are the same operation
// now.
//
// # Why there is no live drag-and-drop editor here
//
// The admin's own policy forbids script entirely — not "discourages", forbids;
// the header says script-src 'none' and a test asserts it. A drag-and-drop
// canvas is a JavaScript application, so building one means either an exception
// for the most attacker-interesting surface in the system or a second admin that
// does not have the property this one is built on.
//
// So the editing model is different rather than worse: named tokens with a value
// each, a contrast number beside every text pair, and section order as content
// that moves with buttons. It is less fluid than dragging a box, and it is
// legible without a mouse, works with a screen reader, and cannot be turned into
// a payload by anybody who gets one string into the page.

// Design is how the admin reads and changes a site's design.
//
// Function fields rather than a directory path, for the same reason the rest of
// this package takes them: this package does not know where anything lives and
// deliberately must not. The host wires it, and a build that does not wire it
// gets a screen that says so instead of a screen that half works.
type Design struct {
	// Dir is shown, so somebody editing the files by hand knows which
	// directory this screen is about.
	Dir string
	// Tokens returns the overrides this site has set.
	Tokens func() (map[string]string, error)
	// Save replaces them.
	Save func(map[string]string) error
	// Layouts lists the layouts a page may name.
	Layouts func() []string
	// Fonts lists the typefaces served from this origin.
	Fonts func() []string
	// FontFile is one of those typefaces, by the name a stylesheet asks
	// for, so the preview draws a page in the site's own type.
	FontFile func(name string) ([]byte, bool)
	// OwnStylesheet reports whether a hand-written site.css is being served, in
	// which case none of the tokens are in effect and the screen has to say so
	// rather than showing values nobody gets.
	OwnStylesheet func() bool
	// InstallLayout writes a starter's markup and returns what it wrote. This
	// is the half the browser used to be missing.
	InstallLayout func(starterName string) ([]string, error)
	// AddFont makes a typeface this site serves out of an uploaded file: a
	// .ttf or an .otf made into a WOFF, or a .woff or .woff2 checked as it
	// is. name, when given, is the served name's contract (Family-400-700);
	// replace says a face already served under that name may be overwritten.
	// The same operation as `quilzo theme font add`, so the screen and the
	// command cannot accept different fonts.
	AddFont func(filename string, body []byte, name string, replace bool) (FontAdded, error)
}

// FontAdded is what AddFont wrote.
type FontAdded struct {
	// File is the name it is served under, at /fonts/.
	File string `json:"file"`
	// Family, Weight and Style are what the filename says, as the
	// stylesheet will declare them.
	Family string `json:"family"`
	Weight string `json:"weight"`
	Style  string `json:"style"`
	// From is what the upload was: truetype, opentype, woff or woff2.
	From string `json:"from"`
	// Replaced says a face already served under that name was overwritten,
	// which changes every page that names it without anybody naming it
	// again, so the record has to be able to say so.
	Replaced bool `json:"replaced,omitempty"`
}

func (s *Server) handleDesign(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	// The same authority as editing a draft: the design is what every page is
	// rendered through, so changing it is a content change with a very wide
	// blast radius rather than a preference.
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	data := map[string]any{
		"Title": "Design", "Principal": p, "Nav": "design",
		"Message": r.URL.Query().Get("m"),
		"Error":   r.URL.Query().Get("e"),
	}
	if s.DesignSet == nil || s.DesignSet.Tokens == nil {
		data["Unavailable"] = "this server was started without a template " +
			"directory, so there is no design to show"
		s.render(w, r, "design.html", data)
		return
	}

	overrides, err := s.DesignSet.Tokens()
	if err != nil {
		data["Unavailable"] = err.Error()
		s.render(w, r, "design.html", data)
		return
	}
	th, problems := theme.New(overrides, s.siteFamilies())

	type item struct {
		Token      string
		Kind       string
		Summary    string
		Light      string
		Dark       string
		Overridden bool
		IsColour   bool
		Stacks     []string
	}
	// Counted so each group can be a disclosure that says what is inside it.
	//
	// Eight token groups, a hundred and seven inputs, forty-seven forms, all
	// expanded — thirty-five kilobytes of controls on one screen. A group
	// opens itself when something in it has been changed from the theme's
	// default, because that is the part somebody came back to look at.
	type group struct {
		Name    string
		Label   string
		Items   []item
		Changed int
	}
	var groups []group
	index := map[string]int{}
	for _, tok := range theme.Tokens() {
		if tok.Kind == theme.Choice {
			continue // chosen in the Look section, not typed into a table
		}
		light, setLight := th.Value(tok.Name, false)
		dark, setDark := th.Value(tok.Name, true)
		it := item{
			Token: tok.Name, Kind: string(tok.Kind), Summary: tok.Summary,
			Light: light, Dark: dark,
			Overridden: setLight || setDark,
			IsColour:   tok.Kind == theme.Colour,
		}
		if tok.Kind == theme.FontStack {
			it.Stacks = append(theme.StackNames(), s.designFonts()...)
		}
		i, seen := index[tok.Group]
		if !seen {
			groups = append(groups, group{
				Name: tok.Group, Label: designGroupLabel(tok.Group)})
			i = len(groups) - 1
			index[tok.Group] = i
		}
		groups[i].Items = append(groups[i].Items, it)
		if it.Overridden {
			groups[i].Changed++
		}
	}

	var blocking, advisory []theme.Finding
	for _, f := range th.Check() {
		if f.Blocking {
			blocking = append(blocking, f)
		} else {
			advisory = append(advisory, f)
		}
	}

	type choice struct {
		Name, Label, Words string
		On                 bool
	}
	var styles, motions, schemes, levels []choice
	// Each choice is named once. Style, motion and colour scheme all had an
	// option called Expressive, and the default style was called Classic
	// while this admin is drawn in Material 3 Expressive, so the look a
	// person was looking at seemed to be a second option rather than the
	// one they had.
	styleLabels := map[string]string{"expressive": "Material 3 Expressive"}
	for _, st := range theme.Styles {
		label := styleLabels[st]
		if label == "" {
			label = strings.ToUpper(st[:1]) + st[1:]
		}
		styles = append(styles, choice{Name: st, Label: label, Words: theme.StyleWords[st], On: th.Style() == st})
	}
	motionLabels := map[string]string{"subtle": "Subtle", "expressive": "Springy", "none": "None"}
	motionWords := map[string]string{"subtle": "Short, gentle transitions. The default.", "expressive": "Movement that overshoots a little and settles, as Material 3 Expressive's springs do.", "none": "Nothing moves."}
	for _, m := range theme.Motions {
		motions = append(motions, choice{Name: m, Label: motionLabels[m], Words: motionWords[m], On: th.Motion() == m})
	}
	schemeLabels := map[string]string{"tonal": "Tonal", "vibrant": "Vibrant", "expressive": "Playful", "neutral": "Neutral", "monochrome": "Monochrome"}
	schemeWords := map[string]string{"tonal": "Calm containers and related accents. The default.", "vibrant": "Fuller colour, accents close to the seed.",
		"expressive": "Accents far round the colour wheel.", "neutral": "Barely tinted.", "monochrome": "Greys only."}
	for i, sc := range theme.Schemes {
		schemes = append(schemes, choice{Name: sc, Label: schemeLabels[sc], Words: schemeWords[sc], On: i == 0})
	}
	levelWords := map[string]string{"standard": "WCAG AA, which publishing requires.", "medium": "Text at 6:1.", "high": "Text at 7:1, WCAG AAA."}
	for i, l := range theme.ContrastLevels {
		levels = append(levels, choice{Name: l, Label: strings.ToUpper(l[:1]) + l[1:], Words: levelWords[l], On: i == 0})
	}
	data["Styles"], data["Motions"], data["Schemes"], data["Levels"] = styles, motions, schemes, levels
	type iconChoice struct {
		Name, Label string
		Preview     template.HTML
		On          bool
	}
	var iconChoices []iconChoice
	for _, st := range icons.Styles {
		var b strings.Builder
		for _, n := range []string{"bolt", "shield", "schedule", "favorite"} {
			b.WriteString(icons.SVG(n, st))
		}
		label := strings.ToUpper(st[:1]) + strings.ReplaceAll(st[1:], "-", ", ")
		// Path data from the generated set only: see internal/icons.
		iconChoices = append(iconChoices, iconChoice{Name: st, Label: label,
			Preview: template.HTML(b.String()), On: th.IconStyle() == st})
	}
	data["IconChoices"] = iconChoices
	seed, _ := th.Value("primary", false)
	data["Seed"] = seed
	data["Groups"] = groups
	data["Blocking"] = blocking
	data["Advisory"] = advisory
	data["Problems"] = problems
	data["Dir"] = s.DesignSet.Dir
	data["Layouts"] = s.designLayouts()
	data["Fonts"] = s.designFonts()
	data["Starters"] = starter.All()
	data["Own"] = s.DesignSet.OwnStylesheet != nil && s.DesignSet.OwnStylesheet()
	data["CanInstall"] = s.DesignSet.InstallLayout != nil
	data["CanAddFont"] = s.DesignSet.AddFont != nil
	s.render(w, r, "design.html", data)
}

func (s *Server) designLayouts() []string {
	if s.DesignSet == nil || s.DesignSet.Layouts == nil {
		return nil
	}
	return s.DesignSet.Layouts()
}

// siteFamilies are the typefaces this site serves, as the theme checks them.
//
// Checked against none, a token naming the site's own font was reported as
// one it does not serve, and saving it from this screen was refused — while
// `quilzo theme set` accepted the same value, because the terminal passed
// the families and this did not.
func (s *Server) siteFamilies() []theme.Family {
	var out []theme.Family
	for _, name := range s.designFonts() {
		out = append(out, theme.Family{Name: name})
	}
	return out
}

func (s *Server) designFonts() []string {
	if s.DesignSet == nil || s.DesignSet.Fonts == nil {
		return nil
	}
	return s.DesignSet.Fonts()
}

// handleDesignSave changes one token, or resets it.
//
// One at a time, and refused when the result is unreadable. The refusal is the
// point: a colour picker that lets somebody set grey on grey and tells them at
// publish time has moved the discovery to the least convenient moment.
func (s *Server) handleDesignSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "post only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	if s.DesignSet == nil || s.DesignSet.Save == nil {
		s.designRedirect(w, r, "", "the design is not writable in this build")
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	overrides, err := s.DesignSet.Tokens()
	if err != nil {
		s.designRedirect(w, r, "", err.Error())
		return
	}
	next := map[string]string{}
	for k, v := range overrides {
		next[k] = v
	}

	token := strings.TrimSpace(r.FormValue("token"))
	if _, known := theme.Lookup(baseToken(token)); !known {
		s.designRedirect(w, r, "", "there is no "+token+" token")
		return
	}
	if r.FormValue("reset") != "" {
		delete(next, token)
		delete(next, token+".dark")
		if err := s.DesignSet.Save(next); err != nil {
			s.designRedirect(w, r, "", err.Error())
			return
		}
		s.auditPub(p, "theme.unset", "/", map[string]string{"setting": token})
		s.designRedirect(w, r, token+" is back to the shipped value", "")
		return
	}

	light := strings.TrimSpace(r.FormValue("light"))
	dark := strings.TrimSpace(r.FormValue("dark"))
	if light != "" {
		next[token] = light
	}
	if dark != "" {
		next[token+".dark"] = dark
	}

	th, problems := theme.New(next, s.siteFamilies())
	for _, pr := range problems {
		if pr.Blocking {
			s.designRedirect(w, r, "", pr.Detail)
			return
		}
	}
	// Only the pairs this token is part of. Refusing a change because a colour
	// somebody set last week is too low would make the screen unusable while
	// they fix it — and the whole palette is checked at publish anyway.
	for _, f := range th.Check() {
		if f.Blocking && f.Token == token {
			s.designRedirect(w, r, "", f.Detail)
			return
		}
	}
	if err := s.DesignSet.Save(next); err != nil {
		s.designRedirect(w, r, "", err.Error())
		return
	}
	s.auditPub(p, "theme.set", "/", map[string]string{"setting": token})
	s.designRedirect(w, r, token+" saved", "")
}

// handleDesignGenerate replaces the palette with one built from a colour,
// a scheme and a contrast level. Every colour it writes is chosen against
// the pairs the gate checks, so it cannot produce an unpublishable theme.
func (s *Server) handleDesignGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "post only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	if s.DesignSet == nil || s.DesignSet.Save == nil {
		s.designRedirect(w, r, "", "the design is not writable in this build")
		return
	}
	seed := strings.TrimSpace(r.FormValue("seed"))
	generated, err := theme.GenerateWith(seed, theme.Options{Scheme: r.FormValue("scheme"), Contrast: r.FormValue("contrast")})
	if err != nil {
		s.designRedirect(w, r, "", err.Error())
		return
	}
	overrides, err := s.DesignSet.Tokens()
	if err != nil {
		s.designRedirect(w, r, "", err.Error())
		return
	}
	next := map[string]string{}
	for k, v := range overrides {
		// The colours are replaced whole: a generated palette with last
		// month's hand-set link colour left in it is not the palette chosen.
		if tok, ok := theme.Lookup(baseToken(k)); ok && tok.Kind == theme.Colour {
			continue
		}
		next[k] = v
	}
	for k, v := range generated {
		next[k] = v
	}
	th, problems := theme.New(next, s.siteFamilies())
	if theme.Blocks(problems) || theme.Blocks(th.Check()) {
		s.designRedirect(w, r, "", "the generated palette did not pass the checks; nothing was changed")
		return
	}
	if err := s.DesignSet.Save(next); err != nil {
		s.designRedirect(w, r, "", err.Error())
		return
	}
	s.auditPub(p, "theme.generate", "/", map[string]string{"seed": seed, "scheme": r.FormValue("scheme"), "contrast": r.FormValue("contrast")})
	s.designRedirect(w, r, "A new palette from "+seed+" is in place", "")
}

// handleDesignInstall writes a starter's markup and its palette.
//
// The operation the browser was missing. Applying a starter used to write its
// sample content and nothing else, so the fields of a design arrived without the
// design — and there was no way to get the markup without a shell.
func (s *Server) handleDesignInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "post only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	// Publisher rather than author. Replacing the markup changes every page at
	// once, including pages this person may not edit, so it needs the authority
	// that covers the whole site rather than the one that covers a draft.
	if !s.can(w, r, p, auth.ActPublish, "/") {
		return
	}
	if s.DesignSet == nil || s.DesignSet.InstallLayout == nil {
		s.designRedirect(w, r, "", "this build cannot write template files")
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("starter"))
	st, found := starter.Get(name)
	if !found {
		s.designRedirect(w, r, "", "there is no starter called "+name)
		return
	}
	written, err := s.DesignSet.InstallLayout(name)
	if err != nil {
		s.designRedirect(w, r, "", err.Error())
		return
	}
	s.auditPub(p, "template.install", "/", map[string]string{
		"starter": st.Name, "layout": st.LayoutName(),
	})
	sort.Strings(written)
	s.designRedirect(w, r, "installed the "+st.Name+" design: "+
		strings.Join(written, ", ")+". A page renders through it with "+
		`"layout": "`+st.LayoutName()+`"`, "")
}

// handleDesignFont adds a typeface from a file somebody has.
//
// The route in for a customer whose foundry sent a TrueType or OpenType
// file, which there was none of: the screen said to put a .woff2 in a
// directory, and nothing here could make one.
//
// Publisher rather than author, as installing a layout is. It took the
// authority of setting a token, on the reasoning that a face nobody names
// changes no page; but a replaced face is already named, and an added one is
// named by a token an author may set. A face is the glyphs every page that
// names it is drawn with, and they are whatever its maker drew: one whose
// digits are drawn as other digits changes every price and telephone number
// at once. No gate reads a glyph, and a publisher reviewing an author's
// draft sees its words, not the shapes the next publish draws them in.
func (s *Server) handleDesignFont(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "post only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActPublish, "/") {
		return
	}
	if s.DesignSet == nil || s.DesignSet.AddFont == nil {
		s.designRedirect(w, r, "", "this build cannot add typefaces")
		return
	}
	// The form's own 2 MiB limit holds (limitBody): a face larger than that
	// cannot become one under the half megabyte a site serves.
	if err := r.ParseMultipartForm(4 << 20); err != nil {
		s.designRedirect(w, r, "", fmt.Sprintf("that file could not be read: %v. "+
			"The most a typeface can be before it is made smaller is %d KiB", err,
			webfont.MaxSourceBytes>>10))
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()
	file, header, err := r.FormFile("file")
	if err != nil {
		s.designRedirect(w, r, "", "choose a .ttf, .otf, .woff or .woff2 file")
		return
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, webfont.MaxSourceBytes+1))
	if err != nil {
		s.designRedirect(w, r, "", err.Error())
		return
	}
	added, err := s.DesignSet.AddFont(header.Filename, body,
		strings.TrimSpace(r.FormValue("name")), r.FormValue("replace") == "1")
	if err != nil {
		s.designRedirect(w, r, "", err.Error())
		return
	}
	detail := map[string]string{"file": added.File, "family": added.Family, "from": added.From}
	if added.Replaced {
		detail["replaced"] = "true"
	}
	s.auditPub(p, "theme.font.add", "/", detail)
	s.designRedirect(w, r, fmt.Sprintf("The typeface is served from this origin at "+
		"/fonts/%s: family %s, weight %s, %s. Choose %s for a font token below; the "+
		"site serves it from its next publish", added.File, added.Family,
		added.Weight, added.Style, added.Family), "")
}

func (s *Server) designRedirect(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	u := "/design"
	switch {
	case errMsg != "":
		u += "?e=" + url.QueryEscape(errMsg)
	case msg != "":
		u += "?m=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

// baseToken strips the scheme suffix, so "primary.dark" is looked up as
// "primary".
func baseToken(name string) string {
	if base, cut := strings.CutSuffix(name, ".dark"); cut {
		return base
	}
	if base, cut := strings.CutSuffix(name, ".light"); cut {
		return base
	}
	return name
}

// designGroupLabel names a token group in words.
//
// The headings on this screen were the group keys themselves — `surfaces`,
// `accents`, `gradient`, `breakpoints`, `lines`, `semantics`, `type`, `shape`.
// Three of those say what they hold and the rest need opening to find out,
// which is the opposite of what a summary is for.
//
// An unknown group keeps its own key rather than being guessed at, so a group
// added later reads as itself instead of as something else.
func designGroupLabel(key string) string {
	switch key {
	case "surfaces":
		return "Backgrounds and text"
	case "accents":
		return "Accent colours"
	case "semantics":
		return "Success, warning and error"
	case "gradient":
		return "Gradient"
	case "lines":
		return "Borders and rules"
	case "type":
		return "Typography"
	case "shape":
		return "Corners and spacing"
	case "breakpoints":
		return "Breakpoints"
	}
	return key
}

// handleSiteFont serves the site's own typefaces to the preview.
//
// The preview renders a page with the site's stylesheet, and that
// stylesheet names /fonts/FAMILY.woff2 — an address the published site
// answers and this server did not, so every preview fell back to a system
// face and showed a page in a typeface its readers never see. Looked up by
// name in the set the site loaded, as the published site does, so there is
// no path to traverse; and behind sign-in, like the preview that asks.
func (s *Server) handleSiteFont(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAuth(w, r); !ok {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/fonts/")
	if s.DesignSet == nil || s.DesignSet.FontFile == nil || name == "" ||
		strings.Contains(name, "/") {
		http.NotFound(w, r)
		return
	}
	body, found := s.DesignSet.FontFile(name)
	if !found {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", webfont.ContentType(name))
	w.Header().Set("Cache-Control", "private, max-age=3600")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	_, _ = w.Write(body)
}
