package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/lithoform/lithoform/internal/auth"
	"github.com/lithoform/lithoform/internal/menu"
	"github.com/lithoform/lithoform/internal/site"
	"github.com/lithoform/lithoform/internal/taxonomy"
)

// Classification and navigation — the two features every CMS has and neither
// of the big ones gets right.
//
// They are one screen because they are one idea: structure that refers to
// content, and therefore structure that can end up referring to content which
// is not there. A tag whose term was deleted and a menu entry whose page was
// deleted are the same bug wearing different clothes, and both are normal in
// products with far more engineers than this one.
//
// What is different here is where the check happens. Not a cron job, not a
// contributed module, not a link checker somebody runs before a launch — at
// the point of the edit, and again at the publish gate, in the same place the
// accessibility and provenance gates already live.

// Structure gives the admin the vocabularies and menus.
type Structure struct {
	Vocabularies     func() (*taxonomy.Set, error)
	SaveVocabularies func(*taxonomy.Set) error
	Menus            func() (*menu.Set, error)
	SaveMenus        func(*menu.Set) error
}

func (s *Server) handleStructure(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActView, "/") {
		return
	}
	if s.Structure == nil {
		s.unwired(w, r, p, "Structure", "vocabularies and menus")
		return
	}

	draft, _ := site.PagesAt(s.Store, site.RefDraft)
	live, _ := site.PagesAt(s.Store, site.RefLive)

	data := map[string]any{
		"Nav": "structure", "Title": "Structure", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"CanWrite": s.Policy.Evaluate(p.Name, auth.ActEditDraft, "/").Allowed,
	}

	// -- vocabularies, with usage so a term's deletability is visible --------
	type termRow struct {
		taxonomy.Row
		Count int
		Used  []string
	}
	type vocabRow struct {
		Name, Label string
		Open        bool
		Terms       []termRow
	}
	var vocabs []vocabRow
	if s.Structure.Vocabularies != nil {
		set, err := s.Structure.Vocabularies()
		if err != nil {
			data["Error"] = err.Error()
		} else {
			for _, name := range set.Names() {
				v, _ := set.Get(name)
				usage := taxonomy.Count(draft, name)
				row := vocabRow{Name: v.Name, Label: v.Label, Open: v.Open}
				for _, t := range v.Sorted() {
					row.Terms = append(row.Terms, termRow{
						Row: t, Count: usage.Count[t.ID], Used: usage.Items[t.ID],
					})
				}
				vocabs = append(vocabs, row)
			}
		}
	}
	data["Vocabularies"] = vocabs

	// -- menus, each entry carrying whether it resolves ----------------------
	type menuRow struct {
		Name, Label string
		Items       []menu.Rendered
		Broken      int
	}
	var menus []menuRow
	if s.Structure.Menus != nil {
		set, err := s.Structure.Menus()
		if err != nil {
			data["Error"] = err.Error()
		} else {
			for _, name := range set.Names() {
				m, _ := set.Get(name)
				row := menuRow{Name: m.Name, Label: m.Label,
					Items: m.Render(draft, live)}
				for _, it := range row.Items {
					if !it.Resolves || !it.Live {
						row.Broken++
					}
				}
				menus = append(menus, row)
			}
			// The publish-gate view: what would be broken for a reader right
			// now. Shown here as well as enforced at publish, because being
			// told at the gate is being told at the worst moment.
			data["WouldBreak"] = set.Broken(live)
		}
	}
	data["Menus"] = menus

	names := make([]string, 0, len(draft))
	for n := range draft {
		names = append(names, n)
	}
	sort.Strings(names)
	data["Pages"] = names
	data["Kinds"] = []menu.Kind{menu.Page, menu.External, menu.Heading}

	s.render(w, r, "structure.html", data)
}

// -- vocabularies -----------------------------------------------------------

// handleVocabularySave declares a vocabulary, or adds a term to one.
//
// One handler, because naming a vocabulary that does not exist creates it —
// the same shape the types screen uses, for the same reason: a two-step
// create-then-populate flow is two chances to abandon halfway.
func (s *Server) handleVocabularySave(w http.ResponseWriter, r *http.Request) {
	p, ok := s.structureWriter(w, r)
	if !ok {
		return
	}
	set, err := s.Structure.Vocabularies()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	name := strings.TrimSpace(r.FormValue("vocabulary"))
	v, exists := set.Get(name)
	if !exists {
		if err := set.Add(taxonomy.Vocabulary{
			Name:  name,
			Label: strings.TrimSpace(r.FormValue("label")),
			Open:  r.FormValue("open") != "",
		}); err != nil {
			s.structRedirect(w, r, "", err.Error())
			return
		}
		v, _ = set.Get(name)
	}

	// A term, if one was given. Creating an empty vocabulary is legitimate —
	// unlike a content type, a vocabulary with no terms is a meaningful state
	// while somebody works out what the terms should be.
	if id := strings.TrimSpace(r.FormValue("term")); id != "" {
		if err := taxonomy.ValidTerm(id); err != nil {
			s.structRedirect(w, r, "", err.Error())
			return
		}
		t := taxonomy.Term{
			ID:          id,
			Label:       strings.TrimSpace(r.FormValue("term_label")),
			Description: strings.TrimSpace(r.FormValue("description")),
			Parent:      strings.TrimSpace(r.FormValue("parent")),
		}
		for _, sy := range strings.Split(r.FormValue("synonyms"), ",") {
			if sy = strings.ToLower(strings.TrimSpace(sy)); sy != "" {
				t.Synonyms = append(t.Synonyms, sy)
			}
		}
		replaced := false
		for i := range v.Terms {
			if v.Terms[i].ID == id {
				v.Terms[i], replaced = t, true
				break
			}
		}
		if !replaced {
			v.Terms = append(v.Terms, t)
		}
	}

	if err := v.Validate(); err != nil {
		s.structRedirect(w, r, "", err.Error())
		return
	}
	if err := s.Structure.SaveVocabularies(set); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditPub(p, "taxonomy.save", "/", map[string]string{
		"vocabulary": name, "term": r.FormValue("term")})
	s.structRedirect(w, r, "saved "+name, "")
}

// handleTermRemove deletes a term, refusing while content carries it.
func (s *Server) handleTermRemove(w http.ResponseWriter, r *http.Request) {
	p, ok := s.structureWriter(w, r)
	if !ok {
		return
	}
	set, err := s.Structure.Vocabularies()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name, id := r.FormValue("vocabulary"), r.FormValue("term")
	v, exists := set.Get(name)
	if !exists {
		s.structRedirect(w, r, "", "there is no vocabulary "+name)
		return
	}

	// Usage is computed from the content, here, rather than from a counter
	// somebody has to keep true. A cached count that drifts is how a term gets
	// deleted while three pages still carry it.
	draft, _ := site.PagesAt(s.Store, site.RefDraft)
	usage := taxonomy.Count(draft, name)

	if err := v.Remove(id, usage.Items[id]); err != nil {
		s.structRedirect(w, r, "", err.Error())
		return
	}
	if err := s.Structure.SaveVocabularies(set); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditPub(p, "taxonomy.term.remove", "/", map[string]string{
		"vocabulary": name, "term": id})
	s.structRedirect(w, r, "removed "+id, "")
}

// -- menus ------------------------------------------------------------------

// handleMenuSave declares a menu, or adds an entry to one.
func (s *Server) handleMenuSave(w http.ResponseWriter, r *http.Request) {
	p, ok := s.structureWriter(w, r)
	if !ok {
		return
	}
	set, err := s.Structure.Menus()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	name := strings.TrimSpace(r.FormValue("menu"))
	m, exists := set.Get(name)
	if !exists {
		if err := set.Add(menu.Menu{
			Name: name, Label: strings.TrimSpace(r.FormValue("label")),
		}); err != nil {
			s.structRedirect(w, r, "", err.Error())
			return
		}
		m, _ = set.Get(name)
	}

	if label := strings.TrimSpace(r.FormValue("item_label")); label != "" {
		order, _ := strconv.Atoi(r.FormValue("order"))
		it := menu.Item{
			ID:     strings.TrimSpace(r.FormValue("id")),
			Label:  label,
			Kind:   menu.Kind(r.FormValue("kind")),
			Target: strings.TrimSpace(r.FormValue("target")),
			Parent: strings.TrimSpace(r.FormValue("parent")),
			Order:  order,
			Note:   strings.TrimSpace(r.FormValue("note")),
		}
		if it.ID == "" {
			it.ID = nextID(m)
		}
		replaced := false
		for i := range m.Items {
			if m.Items[i].ID == it.ID {
				m.Items[i], replaced = it, true
				break
			}
		}
		if !replaced {
			m.Items = append(m.Items, it)
		}
	}

	// Validated against the draft, so an entry pointing at nothing is refused
	// at the point somebody writes it rather than discovered by a reader.
	draft, _ := site.PagesAt(s.Store, site.RefDraft)
	if err := m.Validate(draft); err != nil {
		s.structRedirect(w, r, "", err.Error())
		return
	}
	if err := s.Structure.SaveMenus(set); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditPub(p, "menu.save", "/", map[string]string{
		"menu": name, "item": r.FormValue("item_label")})
	s.structRedirect(w, r, "saved "+name, "")
}

// handleMenuItemRemove deletes one entry.
func (s *Server) handleMenuItemRemove(w http.ResponseWriter, r *http.Request) {
	p, ok := s.structureWriter(w, r)
	if !ok {
		return
	}
	set, err := s.Structure.Menus()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name, id := r.FormValue("menu"), r.FormValue("id")
	m, exists := set.Get(name)
	if !exists {
		s.structRedirect(w, r, "", "there is no menu "+name)
		return
	}
	kept := m.Items[:0]
	found := false
	for _, it := range m.Items {
		if it.ID == id {
			found = true
			continue
		}
		// An entry nested under the one being removed would be orphaned, so
		// it comes up a level rather than disappearing with its parent.
		if it.Parent == id {
			it.Parent = ""
		}
		kept = append(kept, it)
	}
	if !found {
		s.structRedirect(w, r, "", "that entry is not in "+name)
		return
	}
	m.Items = kept
	if err := s.Structure.SaveMenus(set); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditPub(p, "menu.item.remove", "/", map[string]string{
		"menu": name, "item": id})
	s.structRedirect(w, r, "removed the entry", "")
}

// nextID mints an identifier for a new entry.
//
// Sequential rather than random, because these appear in a form and a person
// reading the markup should be able to tell two apart. Uniqueness within one
// menu is all that is needed.
func nextID(m *menu.Menu) string {
	n := len(m.Items) + 1
	for {
		id := "i" + strconv.Itoa(n)
		if _, taken := m.Item(id); !taken {
			return id
		}
		n++
	}
}

func (s *Server) structureWriter(w http.ResponseWriter, r *http.Request) (principal, bool) {
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
	if s.Structure == nil {
		s.unwired(w, r, p, "Structure", "vocabularies and menus")
		return principal{}, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return principal{}, false
	}
	return p, true
}

func (s *Server) structRedirect(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	u := "/structure"
	switch {
	case errMsg != "":
		u += "?e=" + url.QueryEscape(errMsg)
	case msg != "":
		u += "?m=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

// brokenLinks is the publish gate.
//
// Called from the publish handler alongside the accessibility and provenance
// checks. A menu entry pointing at a page that is not going live is not a
// warning here — it is the same class of refusal, because the link works for
// the person who made it and 404s for every reader, which is the version of
// this that ships.
func (s *Server) brokenLinks(pages map[string]any) []string {
	if s.Structure == nil || s.Structure.Menus == nil {
		return nil
	}
	set, err := s.Structure.Menus()
	if err != nil {
		return nil
	}
	var out []string
	for _, p := range set.Broken(pages) {
		out = append(out, p.String())
	}
	return out
}

func plural3(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

var _ = fmt.Sprintf
