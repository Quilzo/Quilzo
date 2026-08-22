package admin

import (
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/starter"
	"github.com/quilzo/quilzo/internal/theme"
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
	// OwnStylesheet reports whether a hand-written site.css is being served, in
	// which case none of the tokens are in effect and the screen has to say so
	// rather than showing values nobody gets.
	OwnStylesheet func() bool
	// InstallLayout writes a starter's markup and returns what it wrote. This
	// is the half the browser used to be missing.
	InstallLayout func(starterName string) ([]string, error)
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
	th, problems := theme.New(overrides, nil)

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
	type group struct {
		Name  string
		Items []item
	}
	var groups []group
	index := map[string]int{}
	for _, tok := range theme.Tokens() {
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
			groups = append(groups, group{Name: tok.Group})
			i = len(groups) - 1
			index[tok.Group] = i
		}
		groups[i].Items = append(groups[i].Items, it)
	}

	var blocking, advisory []theme.Finding
	for _, f := range th.Check() {
		if f.Blocking {
			blocking = append(blocking, f)
		} else {
			advisory = append(advisory, f)
		}
	}

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
	s.render(w, r, "design.html", data)
}

func (s *Server) designLayouts() []string {
	if s.DesignSet == nil || s.DesignSet.Layouts == nil {
		return nil
	}
	return s.DesignSet.Layouts()
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

	th, problems := theme.New(next, nil)
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
