package admin

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/section"
	"github.com/quilzo/quilzo/internal/site"
)

// The page builder, without a canvas.
//
// # What this is instead of drag and drop
//
// A page's shape is a list of typed sections, and until now the browser could
// not touch it: the terminal could edit the JSON and somebody who only ever
// opens the admin had no way to move a block down. That is the gap this screen
// closes, and the reason it is buttons rather than a canvas is not taste.
//
// The admin serves script-src 'none' and a test asserts it. A drag-and-drop
// editor is a JavaScript application, so building one means an exception for the
// most attacker-interesting surface in the system. So the operation is a form
// post per move: less fluid than dragging a box, and it works without a mouse,
// reads correctly to a screen reader, survives the back button, and cannot be
// turned into a payload by anybody who gets one string into the page.
//
// # Why every move is a commit
//
// Each button writes a draft commit with a message naming what happened. That
// is not extra machinery — it is the only way this store writes anything — and
// it means an accidental reorder is undone by rolling the draft back rather than
// by remembering what the order used to be.

func (s *Server) handleSections(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	// The whole screen is for editing, including the list of pages you could
	// edit — so the authority is checked before that branch rather than only on
	// a named page. A reader who could open the index would be able to reach a
	// screen the navigation never offers them, which is the mismatch the roles
	// test exists to catch.
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("page"))
	if name == "" {
		s.render(w, r, "sections.html", map[string]any{
			"Title": "Sections", "Principal": p, "Nav": "design",
			"Pages": s.pagesWithSections(),
		})
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/"+name) {
		return
	}

	pages, err := site.PagesAt(s.Store, site.RefDraft)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	body, exists := pages[name]
	if !exists {
		http.NotFound(w, r)
		return
	}

	// Grouped in catalogue order, because "what a page opens with, what carries
	// data, what carries media, what closes it" is how somebody building a page
	// thinks — and an alphabetical list puts bars next to carousel.
	type kindRow struct {
		Name    string
		Summary string
	}
	type kindGroup struct {
		Name  string
		Items []kindRow
	}
	var groups []kindGroup
	index := map[string]int{}
	for _, k := range section.Kinds() {
		i, seen := index[k.Group]
		if !seen {
			groups = append(groups, kindGroup{Name: k.Group})
			i = len(groups) - 1
			index[k.Group] = i
		}
		groups[i].Items = append(groups[i].Items, kindRow{k.Name, k.Summary})
	}

	// First and last are computed here rather than in the template, so the
	// screen offers Move up on everything except the top and Move down on
	// everything except the bottom. A button that is present and refuses is
	// worse than one that is not offered.
	type row struct {
		section.Placed
		First bool
		Last  bool
	}
	placed := section.On(body)
	rows := make([]row, 0, len(placed))
	for i, pl := range placed {
		rows = append(rows, row{Placed: pl, First: i == 0, Last: i == len(placed)-1})
	}

	s.render(w, r, "sections.html", map[string]any{
		"Title": "Sections", "Principal": p, "Nav": "design",
		"Page":     name,
		"Sections": rows,
		"Count":    len(placed),
		"Groups":   groups,
		"Base":     s.Store.GetRef(site.RefDraft),
		"Message":  r.URL.Query().Get("m"),
		"Error":    r.URL.Query().Get("e"),
		"Layout":   layoutOf(body),
	})
}

// layoutOf is shown so somebody reordering sections on a page that renders
// through a layout with no section loop finds out here rather than by looking at
// the published page and seeing nothing change.
func layoutOf(body any) string {
	m, ok := body.(map[string]any)
	if !ok {
		return ""
	}
	name, _ := m["layout"].(string)
	return name
}

// pagesWithSections lists the pages that have any, so the screen reached with no
// page argument is a way in rather than a dead end.
func (s *Server) pagesWithSections() []map[string]any {
	pages, err := site.PagesAt(s.Store, site.RefDraft)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(pages))
	for name := range pages {
		names = append(names, name)
	}
	sort.Strings(names)

	out := []map[string]any{}
	for _, name := range names {
		placed := section.On(pages[name])
		out = append(out, map[string]any{
			"Name": name, "Count": len(placed),
		})
	}
	return out
}

// handleSectionEdit is add, move and remove, which are one handler because they
// are one operation with a different verb: read the draft, change the list, save
// a commit that says what happened.
func (s *Server) handleSectionEdit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "post only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("page"))
	if name == "" {
		http.Error(w, "no page", http.StatusBadRequest)
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/"+name) {
		return
	}

	pages, err := site.PagesAt(s.Store, site.RefDraft)
	if err != nil {
		s.sectionsRedirect(w, r, name, "", err.Error())
		return
	}
	body, exists := pages[name]
	if !exists {
		http.NotFound(w, r)
		return
	}

	at, _ := strconv.Atoi(r.FormValue("at"))
	var next map[string]any
	var msg string

	switch strings.TrimSpace(r.FormValue("do")) {
	case "add":
		kind := strings.TrimSpace(r.FormValue("kind"))
		next, err = section.Insert(body, kind, at)
		msg = fmt.Sprintf("add a %s section to %s", kind, name)
	case "remove":
		removed := "a"
		if placed := section.On(body); at >= 0 && at < len(placed) {
			removed = placed[at].Kind
		}
		next, err = section.Remove(body, at)
		msg = fmt.Sprintf("remove the %s section from %s", removed, name)
	case "up":
		next, err = section.Move(body, at, -1)
		msg = fmt.Sprintf("move a section up on %s", name)
	case "down":
		next, err = section.Move(body, at, 1)
		msg = fmt.Sprintf("move a section down on %s", name)
	default:
		s.sectionsRedirect(w, r, name, "", "that is not something to do to a section")
		return
	}
	if err != nil {
		s.sectionsRedirect(w, r, name, "", err.Error())
		return
	}

	pages[name] = next
	// The type gate, because sections are content and content is typed. This
	// project has twice shipped a rule the terminal honoured and the browser
	// did not, and the browser is where most editing happens.
	if s.CheckTypes != nil {
		if failures := s.CheckTypes(map[string]any{name: next}); len(failures) > 0 {
			s.renderTypeFailures(w, r, p, name, failures)
			return
		}
	}
	if _, err := site.SaveDraftFrom(s.Store, pages, msg, p.Name,
		r.FormValue("base")); err != nil {

		var c *site.Conflict
		if errors.As(err, &c) {
			s.renderConflict(w, r, p, name, c)
			return
		}
		s.sectionsRedirect(w, r, name, "", err.Error())
		return
	}
	s.auditPub(p, "section.edit", "/"+name, map[string]string{
		"did": strings.TrimSpace(r.FormValue("do")),
	})
	s.sectionsRedirect(w, r, name, msg, "")
}

func (s *Server) sectionsRedirect(w http.ResponseWriter, r *http.Request,
	page, msg, errMsg string) {

	u := "/sections?page=" + url.QueryEscape(page)
	switch {
	case errMsg != "":
		u += "&e=" + url.QueryEscape(errMsg)
	case msg != "":
		u += "&m=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

// handleSectionFields shows one section's values as a form, and saves them.
//
// # Why not a JSON textarea
//
// Because that makes changing a card's title a task that can produce a parse
// error, so the people this screen exists for are exactly the people it fails.
// Every value gets its own labelled input instead, which is also the only
// version a screen reader can announce.
//
// The paths are computed from the section that is already there, and the save
// writes only where a leaf already exists — see internal/section/fields.go for
// why a form whose names an attacker chooses may not create structure.
func (s *Server) handleSectionFields(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.FormValue("page"))
	if name == "" {
		name = strings.TrimSpace(r.URL.Query().Get("page"))
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	// Reached with no page, or on a store with nothing in it. Both are the
	// state a new installation is in, and a screen that answers a new
	// installation with an error is the first thing somebody sees.
	unavailable := func(why string) {
		s.render(w, r, "sectionfields.html", map[string]any{
			"Title": "Edit section", "Principal": p, "Nav": "sections",
			"Unavailable": why,
		})
	}
	if name == "" {
		unavailable("no section was named. Sections are reached from a page — " +
			"start at the sections screen and choose one.")
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/"+name) {
		return
	}

	pages, err := site.PagesAt(s.Store, site.RefDraft)
	if err != nil {
		unavailable("there is no draft yet, so there is nothing to arrange. " +
			"Write a page first.")
		return
	}
	body, exists := pages[name]
	if !exists {
		unavailable("there is no page called " + name + " in the draft.")
		return
	}
	at, _ := strconv.Atoi(firstNonEmpty(r.FormValue("at"), r.URL.Query().Get("at")))

	if r.Method == http.MethodPost {
		s.saveSectionFields(w, r, p, pages, name, at)
		return
	}

	fields, ferr := section.Fields(body, at)
	if ferr != nil {
		unavailable(ferr.Error())
		return
	}
	kind, _ := section.KindAt(body, at)

	// One block per list entry, so a features section reads as three cards
	// rather than as nine inputs with dotted names.
	type block struct {
		Group  string
		Label  string
		List   string
		Index  int
		Fields []section.Editable
	}
	var own []section.Editable
	var blocks []block
	index := map[string]int{}
	for _, f := range fields {
		if f.Group == "" {
			own = append(own, f)
			continue
		}
		i, seen := index[f.Group]
		if !seen {
			list, idx := splitGroup(f.Group)
			blocks = append(blocks, block{
				Group: f.Group, Label: labelOfGroup(f.Group),
				List: list, Index: idx,
			})
			i = len(blocks) - 1
			index[f.Group] = i
		}
		blocks[i].Fields = append(blocks[i].Fields, f)
	}

	s.render(w, r, "sectionfields.html", map[string]any{
		"Title": "Edit section", "Principal": p, "Nav": "sections",
		"Page":    name,
		"At":      at,
		"Kind":    kind,
		"Own":     own,
		"Blocks":  blocks,
		"Lists":   section.Lists(body, at),
		"Base":    s.Store.GetRef(site.RefDraft),
		"Message": r.URL.Query().Get("m"),
		"Error":   r.URL.Query().Get("e"),
	})
}

// saveSectionFields is the write half: values, or a list entry added or removed.
func (s *Server) saveSectionFields(w http.ResponseWriter, r *http.Request,
	p principal, pages map[string]any, name string, at int) {

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	body := pages[name]

	var next map[string]any
	var err error
	var msg string
	kind, _ := section.KindAt(body, at)

	switch strings.TrimSpace(r.FormValue("do")) {
	case "additem":
		list := strings.TrimSpace(r.FormValue("list"))
		next, err = section.AddItem(body, at, list)
		msg = fmt.Sprintf("add an entry to %s on the %s section of %s", list, kind, name)
	case "removeitem":
		list := strings.TrimSpace(r.FormValue("list"))
		i, _ := strconv.Atoi(r.FormValue("index"))
		next, err = section.RemoveItem(body, at, list, i)
		msg = fmt.Sprintf("remove an entry from %s on the %s section of %s", list, kind, name)
	default:
		values := map[string]string{}
		for key, submitted := range r.Form {
			// The form carries its own controls as well as the section's
			// values. They are prefixed so that a section can have a field
			// called "page" without the two colliding.
			path, isValue := strings.CutPrefix(key, "v.")
			if !isValue || len(submitted) == 0 {
				continue
			}
			values[path] = submitted[0]
		}
		next, err = section.Apply(body, at, values)
		msg = fmt.Sprintf("edit the %s section on %s", kind, name)
	}
	if err != nil {
		s.sectionsRedirect(w, r, name, "", err.Error())
		return
	}

	pages[name] = next
	if s.CheckTypes != nil {
		if failures := s.CheckTypes(map[string]any{name: next}); len(failures) > 0 {
			s.renderTypeFailures(w, r, p, name, failures)
			return
		}
	}
	if _, serr := site.SaveDraftFrom(s.Store, pages, msg, p.Name,
		r.FormValue("base")); serr != nil {

		var c *site.Conflict
		if errors.As(serr, &c) {
			s.renderConflict(w, r, p, name, c)
			return
		}
		s.sectionsRedirect(w, r, name, "", serr.Error())
		return
	}
	s.auditPub(p, "section.edit", "/"+name, map[string]string{
		"did": strings.TrimSpace(r.FormValue("do")),
	})
	// Back to the same section rather than to the list, because somebody
	// editing a card's text is usually about to edit the next one.
	http.Redirect(w, r, fmt.Sprintf("/sections/fields?page=%s&at=%d&m=%s",
		url.QueryEscape(name), at, url.QueryEscape(msg)), http.StatusSeeOther)
}

// splitGroup reads a group path — "items.2" — into its list and index.
func splitGroup(group string) (string, int) {
	list, idx, found := strings.Cut(group, ".")
	if !found {
		return group, 0
	}
	n, err := strconv.Atoi(idx)
	if err != nil {
		return list, 0
	}
	return list, n
}

// labelOfGroup writes a group the way somebody reads it: items.2 is the third
// one, because a person counting cards starts at one.
func labelOfGroup(group string) string {
	list, idx := splitGroup(group)
	return fmt.Sprintf("%s %d", strings.ReplaceAll(list, "_", " "), idx+1)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
