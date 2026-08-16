package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/lithoform/lithoform/internal/auth"
	"github.com/lithoform/lithoform/internal/collection"
	"github.com/lithoform/lithoform/internal/listing"
	"github.com/lithoform/lithoform/internal/render"
	"github.com/lithoform/lithoform/internal/site"
)

// Listings: the feature people leave for Drupal to get.
//
// A listing is declared here and embedded in a page by naming it in the page's
// `listings` field. The screen shows what each one currently returns, because a
// query somebody cannot see the result of is a query they will get wrong twice
// before noticing.

// Listings gives the admin the declared queries.
type Listings struct {
	Load func() (*listing.Set, error)
	Save func(*listing.Set) error
}

func (s *Server) handleListings(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActView, "/") {
		return
	}
	if s.Listings == nil {
		s.unwired(w, r, p, "Listings", "declared listings")
		return
	}
	set, err := s.Listings.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tree, _ := draftTreeOf(s)
	collections, _ := collection.Names(s.Store, tree)

	// A preview per listing, run against the draft. Cheap, because the index
	// is built once and every listing after the first is a filter in memory.
	type row struct {
		listing.Listing
		Total, Shown int
		Sample       []listing.Row
		Problem      string
		Unrestricted bool
	}
	var rows []row
	for _, name := range set.Names() {
		l, _ := set.Get(name)
		item := row{Listing: *l, Unrestricted: l.Exposes()}
		if err := l.Validate(); err != nil {
			item.Problem = err.Error()
			rows = append(rows, item)
			continue
		}
		idx, ierr := s.Records.For(s.Store, tree, l.Collection)
		if ierr != nil {
			item.Problem = ierr.Error()
			rows = append(rows, item)
			continue
		}
		res, rerr := listing.Resolve(l, idx, previewArgs(l))
		if rerr != nil {
			item.Problem = rerr.Error()
		} else {
			item.Total, item.Shown = res.Total, len(res.Rows)
			item.Sample = res.Rows
			if len(item.Sample) > 3 {
				item.Sample = item.Sample[:3]
			}
		}
		rows = append(rows, item)
	}

	// Which pages embed which listing, so removing one can say what breaks.
	used := map[string][]string{}
	if pages, perr := site.PagesAt(s.Store, site.RefDraft); perr == nil {
		for page, body := range pages {
			for _, n := range listing.On(body) {
				used[n] = append(used[n], page)
			}
		}
	}
	for n := range used {
		sort.Strings(used[n])
	}

	s.render(w, r, "listings.html", map[string]any{
		"Nav": "listings", "Title": "Listings", "Principal": p,
		"Listings": rows, "Collections": collections, "UsedBy": used,
		"Kinds":   []listing.Kind{listing.Text, listing.Number, listing.Slug},
		"Matches": []listing.Match{listing.Is, listing.Has},
		"MaxRows": listing.MaxRows,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"CanWrite": s.Policy.Evaluate(p.Name, auth.ActEditDraft, "/").Allowed,
	})
}

// templateExample is what showing a listing looks like in a page template.
const templateExample = `{% for row in listings.unmet_controls.rows %}
  <li>{{ row.title }} — {{ row.owner }}</li>
{% end %}
<p>{{ listings.unmet_controls.total }} in total</p>`

// previewArgs supplies each parameter its default, so a listing with a
// contextual filter shows something on this screen rather than the empty
// result a missing argument correctly produces on a page.
func previewArgs(l *listing.Listing) map[string]string {
	out := map[string]string{}
	for _, p := range l.Params {
		if p.Default != "" {
			out[p.Name] = p.Default
		}
	}
	return out
}

// handleListingSave declares a listing, or adds a condition or parameter to one.
func (s *Server) handleListingSave(w http.ResponseWriter, r *http.Request) {
	p, ok := s.listingWriter(w, r)
	if !ok {
		return
	}
	set, err := s.Listings.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	l, exists := set.Get(name)
	if !exists {
		rows, _ := strconv.Atoi(r.FormValue("rows"))
		fresh := listing.Listing{
			Name:        name,
			Label:       strings.TrimSpace(r.FormValue("label")),
			Description: strings.TrimSpace(r.FormValue("description")),
			Collection:  strings.TrimSpace(r.FormValue("collection")),
			Sort:        strings.TrimSpace(r.FormValue("sort")),
			Descending:  r.FormValue("descending") != "",
			Rows:        rows,
		}
		for _, f := range strings.Split(r.FormValue("fields"), ",") {
			if f = strings.TrimSpace(f); f != "" {
				fresh.Fields = append(fresh.Fields, f)
			}
		}
		if err := set.Add(fresh); err != nil {
			s.listingRedirect(w, r, "", err.Error())
			return
		}
		l, _ = set.Get(name)
	}

	// A parameter, if one was given. Declared before the condition that uses
	// it, which is why both are on one form: two forms would let somebody
	// declare a condition on a parameter that does not exist yet and be told
	// off for it.
	if pname := strings.TrimSpace(r.FormValue("param")); pname != "" {
		l.Params = append(l.Params, listing.Param{
			Name:    pname,
			Kind:    listing.Kind(r.FormValue("param_kind")),
			Default: strings.TrimSpace(r.FormValue("param_default")),
			Help:    strings.TrimSpace(r.FormValue("param_help")),
		})
	}
	if field := strings.TrimSpace(r.FormValue("where_field")); field != "" {
		l.Where = append(l.Where, listing.Condition{
			Field: field,
			Match: listing.Match(r.FormValue("where_match")),
			Value: strings.TrimSpace(r.FormValue("where_value")),
			Param: strings.TrimSpace(r.FormValue("where_param")),
		})
	}

	if err := l.Validate(); err != nil {
		s.listingRedirect(w, r, "", err.Error())
		return
	}
	if err := s.Listings.Save(set); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditPub(p, "listing.save", "/", map[string]string{"listing": name})
	s.listingRedirect(w, r, "saved "+name, "")
}

// handleListingRemove deletes one, refusing while a page embeds it.
//
// The same rule as a taxonomy term and a menu target: structure that content
// refers to cannot vanish out from under it. A page naming a listing that is
// gone fails to render, which is a site outage caused by a tidy-up.
func (s *Server) handleListingRemove(w http.ResponseWriter, r *http.Request) {
	p, ok := s.listingWriter(w, r)
	if !ok {
		return
	}
	set, err := s.Listings.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name := r.FormValue("name")

	var used []string
	if pages, perr := site.PagesAt(s.Store, site.RefDraft); perr == nil {
		for page, body := range pages {
			for _, n := range listing.On(body) {
				if n == name {
					used = append(used, page)
				}
			}
		}
	}
	if len(used) > 0 {
		sort.Strings(used)
		s.listingRedirect(w, r, "", fmt.Sprintf(
			"%s is embedded by %s. Removing it would make those pages fail to "+
				"render — take it off them first.",
			name, strings.Join(used, ", ")))
		return
	}
	if err := set.Remove(name); err != nil {
		s.listingRedirect(w, r, "", err.Error())
		return
	}
	if err := s.Listings.Save(set); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditPub(p, "listing.remove", "/", map[string]string{"listing": name})
	s.listingRedirect(w, r, "removed "+name, "")
}

func (s *Server) listingWriter(w http.ResponseWriter, r *http.Request) (principal, bool) {
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
	if s.Listings == nil {
		s.unwired(w, r, p, "Listings", "declared listings")
		return principal{}, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return principal{}, false
	}
	return p, true
}

func (s *Server) listingRedirect(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	u := "/listings"
	switch {
	case errMsg != "":
		u += "?e=" + url.QueryEscape(errMsg)
	case msg != "":
		u += "?m=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

// draftTreeOf is the tree the draft commit points at.
func draftTreeOf(s *Server) (string, error) {
	commit := s.Store.GetRef(site.RefDraft)
	if commit == "" {
		return "", nil
	}
	c, err := s.Store.GetCommit(commit)
	if err != nil {
		return "", err
	}
	return c.Tree, nil
}

// resolver builds the listing resolver for a render.
func (s *Server) resolver(ref string) *listing.Resolver {
	return s.resolverAt(s.Store.GetRef(ref))
}

// resolverAt is the same thing for a commit that has already been resolved.
//
// The accessibility gate holds a commit id rather than a ref name, and passing
// one to the version above quietly produced a resolver with no tree — so every
// listing on every page came back empty and the check ran against a page with
// its main content missing.
func (s *Server) resolverAt(commit string) *listing.Resolver {
	if s.Listings == nil {
		return nil
	}
	set, err := s.Listings.Load()
	if err != nil {
		return nil
	}
	tree := ""
	if commit != "" {
		if c, cerr := s.Store.GetCommit(commit); cerr == nil {
			tree = c.Tree
		}
	}
	return &listing.Resolver{Store: s.Store, Index: s.Records, Tree: tree,
		Set: set}
}

// sources is what a template may see, built the way the public server builds
// it so that anything rendering here judges the same document readers get.
//
// ref is the commit being rendered and pages is its content — passed in rather
// than re-read, because the caller already has them and a second read could
// answer differently.
func (s *Server) sources(commit string, pages map[string]any) render.Sources {
	src := render.Sources{Name: s.SiteName, Pages: pages,
		Listings: s.resolverAt(commit)}
	if s.Structure != nil && s.Structure.Menus != nil {
		if set, err := s.Structure.Menus(); err == nil {
			src.Menus = set
		}
	}
	return src
}
