package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/rsh1k/scrivet/internal/auth"
	"github.com/rsh1k/scrivet/internal/schema"
)

// Content types, in the interface.
//
// This was the largest of the twenty-six gaps and the one that mattered most,
// because a content type is the thing that says what an application holds. A
// person building something in the browser could edit pages, and could not
// declare what a page was — so every site built from the interface alone was
// unconstrained, and the validation the rest of the product is built around
// applied to nothing.
//
// The editor already knew about types: a bound page gets a form built from its
// declaration rather than from whatever keys happen to be in the JSON. It
// simply had no way to declare one. That is the whole shape of the problem
// this screen closes — the feature was finished, and the door to it was not.

// Types gives the admin the site's content types.
//
// A pair of functions rather than a path, for the same reason Settings and Data
// are: this package does not know where the store keeps its files and should
// not learn.
type Types struct {
	Load func() (*schema.Store, error)
	Save func(*schema.Store) error
	// Pages lists what is in the draft, so binding is a choice from a list
	// rather than a page name somebody types and misspells.
	Pages func() (map[string]any, error)
}

// typeRow is one type as the screen shows it.
type typeRow struct {
	Type  schema.Type
	Hash  string
	Bound []string
	// Failing pages are bound to this type and do not currently satisfy it.
	// Shown next to the type rather than only at save time, because a binding
	// whose effect is felt at the next write is a binding somebody discovers at
	// the worst possible moment.
	Failing []schema.Failure
}

func (s *Server) handleTypes(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActView, "/") {
		return
	}
	if s.Types == nil {
		s.unwired(w, r, p, "Types", "content types")
		return
	}

	st, err := s.Types.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var pages map[string]any
	if s.Types.Pages != nil {
		pages, _ = s.Types.Pages()
	}
	failures := map[string][]schema.Failure{}
	for _, f := range st.Gate(pages) {
		typeName := st.Bound[f.Page]
		failures[typeName] = append(failures[typeName], f)
	}

	rows := make([]typeRow, 0, len(st.Registry.Types))
	for _, name := range st.Registry.Names() {
		t, _ := st.Registry.Get(name)
		row := typeRow{Type: t, Hash: shortHash(schema.Hash(t)),
			Failing: failures[name]}
		for page, bound := range st.Bound {
			if bound == name {
				row.Bound = append(row.Bound, page)
			}
		}
		sort.Strings(row.Bound)
		rows = append(rows, row)
	}

	// Pages with no type at all. Listed because "unconstrained" is a state
	// somebody chose or forgot, and the two look identical until they are
	// counted.
	var unbound []string
	for name := range pages {
		if _, bound := st.Bound[name]; !bound {
			unbound = append(unbound, name)
		}
	}
	sort.Strings(unbound)

	// A binding can point at a type that no longer exists. schema.Check fails
	// closed on that, which is right, and it presents as every page under that
	// type failing for a reason that is not about the page.
	var orphans []string
	for page, name := range st.Bound {
		if _, ok := st.Registry.Get(name); !ok {
			orphans = append(orphans, page+" → "+name)
		}
	}
	sort.Strings(orphans)

	s.render(w, r, "types.html", map[string]any{
		"Nav": "types", "Title": "Types", "Principal": p,
		"Rows": rows, "Unbound": unbound, "Orphans": orphans,
		"Kinds":    schema.Kinds(),
		"Message":  r.URL.Query().Get("m"),
		"Error":    r.URL.Query().Get("e"),
		"CanWrite": s.Policy.Evaluate(p.Name, auth.ActEditDraft, "/").Allowed,
	})
}

// handleTypeSave creates a type, or adds a field to one that exists.
//
// One handler for both because they are one operation: a type is a list of
// fields, Registry.Add replaces by name, and a type with no fields cannot be
// stored at all — Compile refuses it, on the grounds that it describes nothing.
// So creating a type means creating its first field, and the form says so
// rather than offering an empty type that cannot be saved.
func (s *Server) handleTypeSave(w http.ResponseWriter, r *http.Request) {
	p, ok := s.typeWriter(w, r)
	if !ok {
		return
	}
	st, err := s.Types.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	name := strings.TrimSpace(r.FormValue("type"))
	t, exists := st.Registry.Get(name)
	if !exists {
		t = schema.Type{Name: name,
			Description: strings.TrimSpace(r.FormValue("description"))}
	}

	f, err := fieldFromForm(r)
	if err != nil {
		s.typeRedirect(w, r, "", err.Error())
		return
	}
	// A field that is already there is replaced rather than duplicated. Compile
	// refuses a repeated name, so appending would produce a type that cannot be
	// saved and an error about a name the person had just typed once.
	replaced := false
	for i := range t.Fields {
		if t.Fields[i].Name == f.Name {
			t.Fields[i], replaced = f, true
			break
		}
	}
	if !replaced {
		t.Fields = append(t.Fields, f)
	}

	if err := st.Registry.Add(t); err != nil {
		s.typeRedirect(w, r, "", err.Error())
		return
	}
	if err := s.Types.Save(st); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditType(p, "type.save", name, map[string]string{
		"field": f.Name, "kind": string(f.Kind),
		"hash": shortHash(schema.Hash(t))})

	verb := "added"
	if replaced {
		verb = "replaced"
	}
	s.typeRedirect(w, r, fmt.Sprintf("%s %s on %s", verb, f.Name, name), "")
}

// handleTypeFieldRemove drops a field.
func (s *Server) handleTypeFieldRemove(w http.ResponseWriter, r *http.Request) {
	p, ok := s.typeWriter(w, r)
	if !ok {
		return
	}
	st, err := s.Types.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name, field := r.FormValue("type"), r.FormValue("field")
	t, exists := st.Registry.Get(name)
	if !exists {
		s.typeRedirect(w, r, "", "there is no type "+name)
		return
	}
	kept := make([]schema.Field, 0, len(t.Fields))
	for _, f := range t.Fields {
		if f.Name != field {
			kept = append(kept, f)
		}
	}
	if len(kept) == len(t.Fields) {
		s.typeRedirect(w, r, "", name+" has no field "+field)
		return
	}
	t.Fields = kept
	if err := st.Registry.Add(t); err != nil {
		// Removing the last field is refused here, by the same rule that
		// refuses creating an empty one. Deleting the type is the operation
		// that was meant, and it is a different button.
		s.typeRedirect(w, r, "", err.Error())
		return
	}
	if err := s.Types.Save(st); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditType(p, "type.field.remove", name, map[string]string{"field": field})
	s.typeRedirect(w, r, "removed "+field+" from "+name, "")
}

// handleTypeDelete removes a type.
//
// Refused while anything is bound to it. schema.Check fails closed on a
// dangling binding — which is correct, and means deleting a type in use would
// break every page under it with an error about the configuration rather than
// about the content. Unbind first, deliberately.
func (s *Server) handleTypeDelete(w http.ResponseWriter, r *http.Request) {
	p, ok := s.typeWriter(w, r)
	if !ok {
		return
	}
	st, err := s.Types.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name := r.FormValue("type")
	var used []string
	for page, bound := range st.Bound {
		if bound == name {
			used = append(used, page)
		}
	}
	if len(used) > 0 {
		sort.Strings(used)
		s.typeRedirect(w, r, "", fmt.Sprintf(
			"%s is still what %s must satisfy. Unbind %s first — deleting a "+
				"type in use would fail every one of those pages with an error "+
				"about the type rather than about the page.",
			name, strings.Join(used, ", "), plural2(len(used), "it", "them")))
		return
	}
	if _, ok := st.Registry.Get(name); !ok {
		s.typeRedirect(w, r, "", "there is no type "+name)
		return
	}
	delete(st.Registry.Types, name)
	if err := s.Types.Save(st); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditType(p, "type.delete", name, nil)
	s.typeRedirect(w, r, "deleted "+name, "")
}

// handleTypeBind declares that a page must satisfy a type, or stops requiring
// it.
func (s *Server) handleTypeBind(w http.ResponseWriter, r *http.Request) {
	p, ok := s.typeWriter(w, r)
	if !ok {
		return
	}
	st, err := s.Types.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	page := strings.TrimSpace(r.FormValue("page"))
	name := strings.TrimSpace(r.FormValue("type"))
	if page == "" {
		s.typeRedirect(w, r, "", "no page given")
		return
	}

	if name == "" || r.FormValue("unbind") != "" {
		if _, bound := st.Bound[page]; !bound {
			s.typeRedirect(w, r, "", page+" was not bound to anything")
			return
		}
		delete(st.Bound, page)
		if err := s.Types.Save(st); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.auditType(p, "type.unbind", page, nil)
		s.typeRedirect(w, r, page+" no longer has to satisfy a type", "")
		return
	}

	if err := st.Bind(page, name); err != nil {
		s.typeRedirect(w, r, "", err.Error())
		return
	}
	if err := s.Types.Save(st); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditType(p, "type.bind", page, map[string]string{"type": name})

	// Say immediately whether it currently satisfies the type. The CLI does
	// this and the browser did not, which is the same asymmetry this whole
	// screen exists to close.
	msg := page + " must now satisfy " + name
	if s.Types.Pages != nil {
		if pages, err := s.Types.Pages(); err == nil {
			if body, there := pages[page]; there {
				if problems := st.Check(page, body); len(problems) > 0 {
					var parts []string
					for _, pr := range problems {
						parts = append(parts, pr.String())
					}
					s.typeRedirect(w, r, "", fmt.Sprintf(
						"%s. It does not yet, and the next write to it will be "+
							"refused until it does: %s",
						msg, strings.Join(parts, "; ")))
					return
				}
			}
		}
	}
	s.typeRedirect(w, r, msg, "")
}

// fieldFromForm builds one field out of a submitted form.
//
// Everything arrives as a string, so this is where a string becomes a bound. An
// unparseable number is refused rather than dropped: a max length that silently
// became zero is a constraint the person thinks they set.
func fieldFromForm(r *http.Request) (schema.Field, error) {
	f := schema.Field{
		Name:     strings.TrimSpace(r.FormValue("field")),
		Kind:     schema.Kind(strings.TrimSpace(r.FormValue("kind"))),
		Required: r.FormValue("required") != "",
		Label:    strings.TrimSpace(r.FormValue("label")),
		Help:     strings.TrimSpace(r.FormValue("help")),
		AltFor:   strings.TrimSpace(r.FormValue("alt_for")),
	}
	if raw := strings.TrimSpace(r.FormValue("choices")); raw != "" {
		for _, c := range strings.Split(raw, ",") {
			if c = strings.TrimSpace(c); c != "" {
				f.Choices = append(f.Choices, c)
			}
		}
	}
	if raw := strings.TrimSpace(r.FormValue("max_len")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return f, fmt.Errorf("maximum length: %q is not a whole number", raw)
		}
		f.MaxLen = n
	}
	if raw := strings.TrimSpace(r.FormValue("min")); raw != "" {
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return f, fmt.Errorf("minimum: %q is not a number", raw)
		}
		f.Min = &v
	}
	if raw := strings.TrimSpace(r.FormValue("max")); raw != "" {
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return f, fmt.Errorf("maximum: %q is not a number", raw)
		}
		f.Max = &v
	}
	return f, nil
}

// typeWriter is the shared preamble: POST, signed in, allowed, and wired.
func (s *Server) typeWriter(w http.ResponseWriter, r *http.Request) (principal, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return principal{}, false
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return principal{}, false
	}
	// Editing a type changes what every author may store from now on, so it is
	// gated on editing the draft rather than on viewing it.
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return principal{}, false
	}
	if s.Types == nil {
		s.unwired(w, r, p, "Types", "content types")
		return principal{}, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return principal{}, false
	}
	return p, true
}

func (s *Server) auditType(p principal, action, resource string, detail map[string]string) {
	if s.Audit == nil {
		return
	}
	if detail == nil {
		detail = map[string]string{}
	}
	detail["by"] = p.Name
	s.Audit(action, resource, detail)
}

// typeRedirect returns to the screen with a message, rather than rendering one.
//
// Redirect-after-post, so a refresh does not repeat the write and the back
// button behaves the way the person expects.
func (s *Server) typeRedirect(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	u := "/types"
	switch {
	case errMsg != "":
		u += "?e=" + url.QueryEscape(errMsg)
	case msg != "":
		u += "?m=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

// unwired says a capability was not connected, rather than rendering an empty
// screen.
//
// An empty list and an absent feature look identical and mean opposite things:
// one is "you have none of these" and the other is "this build cannot tell
// you". Every screen in this package that depends on a host-supplied function
// says which one it is.
func (s *Server) unwired(w http.ResponseWriter, r *http.Request, p principal,
	title, what string) {

	w.WriteHeader(http.StatusServiceUnavailable)
	s.render(w, r, "message.html", map[string]any{
		"Title": title, "Principal": p,
		"Heading": "This build has no access to " + what,
		"Body": "The server was started without wiring " + what + " in, so " +
			"this screen cannot tell you anything. An empty page would read " +
			"as \"there are none\", which is a different statement.",
	})
}

func plural2(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
