package admin

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rsh1k/scrivet/internal/auth"
	"github.com/rsh1k/scrivet/internal/i18n"
)

// Languages, in the interface.
//
// The interesting column is not the list of locales, it is what each page in
// each locale currently is: current, stale, missing, or present with no record
// of what it was made from. A stale translation is the failure this package
// exists to make visible — content that was translated from a source that has
// since changed, which reads perfectly and is wrong — and it was only ever
// visible by running a command.

// Languages gives the admin the locale set.
type Languages struct {
	Load func() (*i18n.Config, error)
	Save func(*i18n.Config) error
	// Hashes returns every stored page name mapped to its content hash, which
	// is what makes staleness checkable rather than a matter of trust.
	Hashes func() (map[string]string, error)
}

func (s *Server) handleLanguages(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActView, "/") {
		return
	}
	if s.Languages == nil {
		s.unwired(w, r, p, "Languages", "the locale set")
		return
	}
	cfg, err := s.Languages.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"Nav": "languages", "Title": "Languages", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"CanWrite": s.Policy.Evaluate(p.Name, auth.ActEditDraft, "/").Allowed,
	}

	// No default language yet is a real state, not an empty list: a site that
	// has never declared one is monolingual and working, and the screen offers
	// the one action that applies rather than a table with nothing in it.
	if cfg == nil || cfg.Default == "" {
		data["Uninitialised"] = true
		s.render(w, r, "languages.html", data)
		return
	}

	states, counts := s.translationStates(cfg)
	// Each locale carries its own writing direction, which is a property of the
	// language and not a setting. Showing it here is what stops somebody
	// discovering at launch that their Arabic pages render left to right.
	type localeRow struct {
		Locale  i18n.Locale
		Dir     string
		Default bool
	}
	rows := make([]localeRow, 0, len(cfg.Locales))
	for _, l := range cfg.Locales {
		rows = append(rows, localeRow{Locale: l, Dir: l.Dir(),
			Default: l == cfg.Default})
	}

	data["Default"] = cfg.Default
	data["Locales"] = rows
	data["States"] = states
	data["Stale"] = counts[i18n.Stale]
	data["Missing"] = counts[i18n.Missing]
	data["Untracked"] = counts[i18n.Untracked]
	data["Current"] = counts[i18n.Current]
	s.render(w, r, "languages.html", data)
}

// translationStates answers "what is each page in each language, right now".
func (s *Server) translationStates(cfg *i18n.Config) ([]i18n.State, map[i18n.Status]int) {
	if s.Languages.Hashes == nil {
		return nil, nil
	}
	tree, err := s.Languages.Hashes()
	if err != nil {
		return nil, nil
	}
	sources := map[string]string{}
	present := map[string]bool{}
	for stored, oid := range tree {
		present[stored] = true
		if l, page := cfg.Split(stored); l == cfg.Default {
			sources[page] = oid
		}
	}
	states := cfg.Check(sources, present)
	return states, i18n.Counts(states)
}

// handleLanguageAdd declares a language, or the first one.
func (s *Server) handleLanguageAdd(w http.ResponseWriter, r *http.Request) {
	p, ok := s.langWriter(w, r)
	if !ok {
		return
	}
	raw := strings.TrimSpace(r.FormValue("locale"))
	l, err := i18n.ParseLocale(raw)
	if err != nil {
		s.langRedirect(w, r, "", err.Error())
		return
	}
	cfg, err := s.Languages.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if cfg == nil || cfg.Default == "" {
		cfg = i18n.NewConfig(l)
		if err := s.Languages.Save(cfg); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.auditPub(p, "lang.init", "/", map[string]string{"locale": string(l)})
		s.langRedirect(w, r, string(l)+" is the default language. Pages stay "+
			"where they are; a second language goes under a prefix.", "")
		return
	}

	if err := cfg.Add(l); err != nil {
		s.langRedirect(w, r, "", err.Error())
		return
	}
	if err := s.Languages.Save(cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditPub(p, "lang.add", "/", map[string]string{"locale": string(l)})
	s.langRedirect(w, r, "added "+string(l)+". Its pages go under "+
		string(l)+"/, and it reads "+l.Dir()+".", "")
}

// handleLanguageTranslated records that a page was translated from the source
// as it currently stands.
//
// This is what makes staleness mean something. Without a record of which
// version a translation was made from, "is this up to date" cannot be answered
// at all — and the honest answer for an unrecorded translation is "nothing can
// be said", which is what the untracked state is.
func (s *Server) handleLanguageTranslated(w http.ResponseWriter, r *http.Request) {
	p, ok := s.langWriter(w, r)
	if !ok {
		return
	}
	cfg, err := s.Languages.Load()
	if err != nil || cfg == nil {
		s.langRedirect(w, r, "", "no languages are configured yet")
		return
	}
	page := strings.TrimSpace(r.FormValue("page"))
	l, err := i18n.ParseLocale(strings.TrimSpace(r.FormValue("locale")))
	if err != nil {
		s.langRedirect(w, r, "", err.Error())
		return
	}
	if !cfg.Has(l) {
		s.langRedirect(w, r, "", string(l)+" is not one of this site's languages")
		return
	}
	if s.Languages.Hashes == nil {
		s.langRedirect(w, r, "", "this build cannot read page hashes, so a "+
			"translation record would not be checkable")
		return
	}
	tree, err := s.Languages.Hashes()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sourceHash, there := tree[page]
	if !there {
		// The source, not the translation. Recording against a page that is not
		// the default-language original would produce a record that can never
		// go stale, because nothing would ever change the thing it names.
		s.langRedirect(w, r, "", page+" is not a page in the default language, "+
			"so there is nothing for a translation to be made from")
		return
	}
	cfg.Record(page, l, sourceHash, p.Name, time.Now())
	if err := s.Languages.Save(cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditPub(p, "lang.translated", "/"+page, map[string]string{
		"locale": string(l), "source": shortHash(sourceHash)})
	s.langRedirect(w, r, page+" in "+string(l)+" is recorded as translated from "+
		shortHash(sourceHash)+". It becomes stale when that source changes.", "")
}

func (s *Server) langWriter(w http.ResponseWriter, r *http.Request) (principal, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return principal{}, false
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return principal{}, false
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return principal{}, false
	}
	if s.Languages == nil {
		s.unwired(w, r, p, "Languages", "the locale set")
		return principal{}, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return principal{}, false
	}
	return p, true
}

func (s *Server) langRedirect(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	u := "/languages"
	switch {
	case errMsg != "":
		u += "?e=" + url.QueryEscape(errMsg)
	case msg != "":
		u += "?m=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}
