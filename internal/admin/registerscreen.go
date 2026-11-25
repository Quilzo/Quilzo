// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/seckit"
	"github.com/quilzo/quilzo/internal/waiting"
)

// The register's screens: what kinds of record it holds and how many of
// each, one kind's records, one record with the hash it is stored under,
// and what waits on its proposals ref for a person.
//
// Read-only, as `quilzo register` is, and asked about the register's area.
// Built from the security kit and nothing else, and registered from this
// file, so it is the example a module's screens copy: one call to
// registerScreens in an init, templates of its own (assets/register*.html),
// and no line changed in Handler or the navigation.

func init() {
	registerScreens(screens{
		module: "register",
		routes: []screenRoute{
			{path: "/register", handle: (*Server).handleRegister},
			{path: "/register/kind/", handle: (*Server).handleRegisterKind},
			{path: "/register/record/", handle: (*Server).handleRegisterRecord},
			{path: "/register/proposals", handle: (*Server).handleRegisterProposals},
			{path: "/register/export/", handle: (*Server).handleRegisterExport},
			{path: "/register/inventory", handle: (*Server).handleRegisterInventory},
			{path: "/register/erase", handle: (*Server).handleRegisterErase},
		},
		nav: []navEntry{{
			destination: destination{Key: "register", Label: "Register", Path: "/register", Group: "Assurance",
				Doc: "compliance", Needs: auth.ActView},
			icon: "verified", area: register.Area,
			also: []string{"controls", "evidence", "risks", "exceptions", "decisions", "vendors", "ai systems",
				"incidents", "policies", "security record", "proposals", "data inventory", "erase a person",
				"personal data", "export csv", "top risks"},
		}},
	})
}

// registerReady is a signed-in person who may read the register, and the
// register of this server's store.
func (s *Server) registerReady(w http.ResponseWriter, r *http.Request) (principal, *register.Register, bool) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return p, nil, false
	}
	if !s.can(w, r, p, auth.ActView, register.Area) {
		return p, nil, false
	}
	return p, register.Open(s.Store), true
}

// registerAt is the moment the register's head was written, and the head:
// what every count on these screens is as of, and is checked against.
func (s *Server) registerAt(reg *register.Register) (time.Time, string) {
	head := reg.Head()
	if head == "" {
		return time.Time{}, ""
	}
	c, err := s.Store.GetCommit(head)
	if err != nil {
		return time.Time{}, head
	}
	return time.Unix(c.At, 0).UTC(), head
}

// registerCount is a count of the register's own records, as a figure.
func registerCount(n int, unit string, at time.Time, head string, now time.Time) seckit.Figure {
	if head == "" {
		return seckit.Figure{}
	}
	f, err := seckit.New(seckit.FigureOf{N: int64(n), Count: true, Unit: unit,
		Sources: []seckit.Source{seckit.TheRegister}, At: at, Hash: head, Now: now})
	if err != nil {
		return seckit.Figure{}
	}
	return f
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/register" {
		http.NotFound(w, r)
		return
	}
	p, reg, ok := s.registerReady(w, r)
	if !ok {
		return
	}
	counts, err := reg.Counts()
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	proposals, _ := reg.Proposals()
	at, head := s.registerAt(reg)
	now := time.Now()
	var rows []seckit.Row
	for _, k := range register.Kinds() {
		rows = append(rows, seckit.Row{Head: seckit.LinkCell("/register/kind/"+strings.TrimPrefix(k.Collection, register.Prefix), string(k.Kind)),
			Cells: []seckit.Cell{seckit.FigureCell(registerCount(counts[k.Kind], "records", at, head, now)),
				seckit.TextCell(k.Summary), seckit.TextCell(string(k.Class))}})
	}
	table, err := seckit.NewTable("The kinds of record the register holds",
		[]string{"Kind", "Records", "What a record of it is", "How far it may travel"}, rows)
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	data := map[string]any{"Title": "Register", "Nav": "register", "Principal": p,
		"Header": seckit.Header{Title: "Register", Lead: "The security record: typed records on a ref of their own, " +
			"each written one way, through the policy gate and the kind's own rules, into the audit log."},
		"Table": table, "Head": head, "Waiting": len(proposals),
		"MayErase": s.allows(p, auth.ActApprove, erasureResource())}
	if head == "" {
		data["Empty"] = seckit.Empty{Title: "Nothing has been written to the register yet",
			Body: "Records arrive from the modules that own them: sources and their facts, controls and their tests, " +
				"risks and the decisions about them. Each kind below is ready for its records."}
	}
	s.render(w, r, "register.html", data)
}

func (s *Server) handleRegisterKind(w http.ResponseWriter, r *http.Request) {
	p, reg, ok := s.registerReady(w, r)
	if !ok {
		return
	}
	spec, found := register.SpecOf(strings.TrimPrefix(r.URL.Path, "/register/kind/"))
	if !found {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))
	if offset < 0 {
		offset = 0
	}
	const limit = 50
	slug := strings.TrimPrefix(spec.Collection, register.Prefix)
	filters, problem := filtersOf(q)
	data := map[string]any{"Title": string(spec.Kind), "Nav": "register", "Principal": p,
		"Header": seckit.Header{Title: string(spec.Kind), Lead: spec.Summary}, "Spec": spec,
		"Fields": register.FilterFields(spec), "Field": q.Get("field"), "Value": q.Get("value"),
		"Action": "/register/kind/" + slug}
	if problem == "" {
		entries, total, err := reg.Find(spec.Kind, filters, offset, limit)
		switch {
		case errors.Is(err, register.ErrInvalid):
			problem = err.Error()
		case err != nil:
			s.registerUnreadable(w, r, p, err)
			return
		default:
			s.registerKindTable(w, r, p, data, spec, slug, filters, entries, offset, limit, total)
			if data["Table"] == nil {
				return
			}
			s.render(w, r, "register_kind.html", data)
			return
		}
	}
	// A filter that is not one is said beside the field and at the top, and
	// the page is the form again with nothing listed.
	pr := seckit.Problem{Field: "filter-field", Label: "Field", Message: problem}
	data["Problems"], data["FieldProblem"] = []seckit.Problem{pr}, pr
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, r, "register_kind.html", data)
}

// filtersOf is the filters a request asks for: each filter=FIELD=VALUE of
// a link, and the field and value of the form. What is wrong with one is
// said in words.
func filtersOf(q url.Values) ([]register.Filter, string) {
	var out []register.Filter
	for _, raw := range q["filter"] {
		f, err := register.ParseFilter(raw)
		if err != nil {
			return nil, err.Error()
		}
		out = append(out, f)
	}
	if field := strings.TrimSpace(q.Get("field")); field != "" {
		out = append(out, register.Filter{Field: field, Value: q.Get("value")})
	}
	return out, ""
}

// filterQuery is filters as a query, for the links that keep them.
func filterQuery(filters []register.Filter) url.Values {
	v := url.Values{}
	for _, f := range filters {
		v.Add("filter", f.String())
	}
	return v
}

// registerKindTable puts a page of a kind's records in data, with the
// links that page through them and export them, filters kept. On a table
// that cannot be made it writes the page that says so and leaves Table
// unset.
func (s *Server) registerKindTable(w http.ResponseWriter, r *http.Request, p principal, data map[string]any,
	spec register.Spec, slug string, filters []register.Filter, entries []register.Entry, offset, limit, total int) {
	var rows []seckit.Row
	for _, e := range entries {
		label := register.Label(e.Record)
		if label == "" {
			label = string(e.ID)
		}
		rows = append(rows, seckit.Row{Head: seckit.LinkCell("/register/record/"+string(e.ID), label),
			Cells: []seckit.Cell{seckit.TextCell(string(e.ID)), seckit.TimeCell(e.Updated.At()), seckit.HashCell(e.Object)}})
	}
	caption := fmt.Sprintf("%s records, %d to %d of %d", spec.Kind, min(offset+1, total), offset+len(entries), total)
	if len(filters) > 0 {
		caption = fmt.Sprintf("%s records with %s, %d to %d of %d", spec.Kind, filterWords(filters),
			min(offset+1, total), offset+len(entries), total)
	}
	table, err := seckit.NewTable(caption, []string{"Record", "Identifier", "Last changed", "Stored as"}, rows)
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	data["Table"], data["Filters"], data["FilterWords"] = table, filters, filterWords(filters)
	if total == 0 {
		empty := seckit.Empty{Title: "The register holds no " + string(spec.Kind) + " records",
			Body: "Its fields are listed below, as every record of the kind will have them."}
		if len(filters) > 0 {
			empty = seckit.Empty{Title: "No " + string(spec.Kind) + " record has " + filterWords(filters),
				Href: "/register/kind/" + slug, Action: "Show every " + string(spec.Kind) + " record"}
		}
		data["Empty"] = empty
	}
	page := func(at int) string {
		v := filterQuery(filters)
		v.Set("offset", strconv.Itoa(at))
		return "/register/kind/" + slug + "?" + v.Encode()
	}
	if next := offset + len(entries); next < total {
		data["Next"] = page(next)
	}
	if offset > 0 {
		data["Previous"] = page(max(offset-limit, 0))
	}
	export := "/register/export/" + slug + ".csv"
	if q := filterQuery(filters).Encode(); q != "" {
		export += "?" + q
	}
	data["Export"] = export
	if _, rated := register.Rating(spec.New().(register.Record)); rated {
		data["Top"] = "/register/export/" + slug + ".csv?top=10"
	}
}

// filterWords is filters as a caption says them.
func filterWords(filters []register.Filter) string {
	var parts []string
	for _, f := range filters {
		parts = append(parts, f.Field+" "+strconv.Quote(f.Value))
	}
	return strings.Join(parts, " and ")
}

func (s *Server) handleRegisterRecord(w http.ResponseWriter, r *http.Request) {
	p, reg, ok := s.registerReady(w, r)
	if !ok {
		return
	}
	e, err := reg.Get(register.ID(strings.TrimPrefix(r.URL.Path, "/register/record/")))
	if errors.Is(err, register.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	spec, _ := register.SpecOf(string(e.Kind))
	table, err := seckit.NewTable("Its fields, as the kind's schema has them",
		[]string{"Field", "Value", "What it is for"}, fieldRows(spec.Fields, e.Record))
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	title := register.Label(e.Record)
	if title == "" {
		title = string(e.Kind) + " " + seckit.Short(string(e.ID))
	}
	changes, err := reg.History(e.ID, 50)
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	events := make([]seckit.Event, 0, len(changes))
	for _, c := range changes {
		what := "Changed: " + c.Why
		if c.New {
			what = "Written: " + c.Why
		}
		by := string(c.By)
		if by == "" {
			by = "a service"
		}
		events = append(events, seckit.Event{At: c.At.At(), What: what, By: by, Hash: c.Object})
	}
	data := map[string]any{"Title": title, "Nav": "register", "Principal": p,
		"Header": seckit.Header{Title: title, Lead: string(e.Kind) + ": " + spec.Summary},
		"Entry":  e, "Spec": spec, "Table": table,
		"Kind":   seckit.LinkCell("/register/kind/"+strings.TrimPrefix(spec.Collection, register.Prefix), string(e.Kind)),
		"Events": events}
	if named := reg.Named(e.Record); len(named) > 0 {
		t, err := seckit.NewTable("What it names beside the register: people by pseudonym, text and files by digest",
			[]string{"Field", "Pseudonym or digest", "Beside the register", "Words"}, namedRows(named))
		if err != nil {
			s.registerUnreadable(w, r, p, err)
			return
		}
		data["Named"] = t
	}
	s.render(w, r, "register_record.html", data)
}

// namedRows is what a record names beside the register, a row each, with
// what the side store holds of it as a status in words: "Subject erased",
// "Text held".
func namedRows(named []register.Named) []seckit.Row {
	var rows []seckit.Row
	for _, n := range named {
		tone := seckit.Neutral
		switch n.State {
		case register.TextErased:
			tone = seckit.Warn
		case register.TextUnreadable:
			tone = seckit.Bad
		}
		word := strings.ToUpper(n.Said[:1]) + n.Said[1:]
		if n.Erased != nil {
			word += " " + n.Erased.At.Format("2 Jan 2006")
		}
		status := seckit.BadgeCell(seckit.MustBadge(tone, word))
		value := seckit.HashCell(n.Value)
		if n.What == "subject" {
			value = seckit.TextCell(n.Value)
		}
		rows = append(rows, seckit.Row{Head: seckit.TextCell(n.Field), Cells: []seckit.Cell{value, status, seckit.TextCell(n.Words)}})
	}
	return rows
}

// fieldRows is a record's fields as rows: each value as the schema types
// it, an identifier as a link to its record, a digest as a hash, a time as
// a time, and the rest as the JSON it is stored as.
func fieldRows(fields []register.Field, rec register.Record) []seckit.Row {
	raw, _ := json.Marshal(rec)
	var values map[string]json.RawMessage
	_ = json.Unmarshal(raw, &values)
	var rows []seckit.Row
	for _, f := range fields {
		v, set := values[f.Name]
		about := seckit.TextCell(f.About)
		head := seckit.TextCell(f.Name)
		switch {
		case !set || string(v) == "null":
			rows = append(rows, seckit.Row{Head: head, Cells: []seckit.Cell{{}, about}})
		case f.Type == "id":
			var id string
			_ = json.Unmarshal(v, &id)
			rows = append(rows, seckit.Row{Head: head, Cells: []seckit.Cell{seckit.LinkCell("/register/record/"+id, id), about}})
		case f.Type == "digest" || f.Type == "text" || f.Type == "object-id":
			var d string
			_ = json.Unmarshal(v, &d)
			rows = append(rows, seckit.Row{Head: head, Cells: []seckit.Cell{seckit.HashCell(d), about}})
		case f.Type == "time":
			var n int64
			_ = json.Unmarshal(v, &n)
			rows = append(rows, seckit.Row{Head: head, Cells: []seckit.Cell{seckit.TimeCell(register.Time(n).At()), about}})
		default:
			// A string as its words, and anything else as the JSON it is
			// stored as.
			text := string(v)
			var str string
			if json.Unmarshal(v, &str) == nil {
				text = str
			}
			rows = append(rows, seckit.Row{Head: head, Cells: []seckit.Cell{seckit.TextCell(text), about}})
		}
	}
	return rows
}

func (s *Server) handleRegisterProposals(w http.ResponseWriter, r *http.Request) {
	p, reg, ok := s.registerReady(w, r)
	if !ok {
		return
	}
	list, err := reg.Proposals()
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	type item struct {
		ID, Kind, By, Why string
		At                time.Time
	}
	var items []item
	for _, pr := range list {
		by := pr.Agent
		if by == "" {
			by = string(pr.Subject)
		}
		items = append(items, item{ID: string(pr.ID), Kind: string(pr.Kind), By: by, Why: pr.Why, At: pr.At.At()})
	}
	data := map[string]any{"Title": "Proposals", "Nav": "register", "Principal": p,
		"Header": seckit.Header{Title: "Proposals", Lead: "Records a crew, a model or a person proposed for the register. " +
			"None of them is in the register, and no figure reads them, until a person accepts it."},
		"Items": items}
	if len(items) == 0 {
		data["Empty"] = seckit.Empty{Title: "Nothing is waiting", Body: "What a crew proposes waits here, and in Approvals, for a person."}
	}
	s.render(w, r, "register_proposals.html", data)
}

// registerUnreadable says the register could not be read, which is not the
// same as its being empty.
func (s *Server) registerUnreadable(w http.ResponseWriter, r *http.Request, p principal, err error) {
	s.render(w, r, "message.html", map[string]any{"Status": http.StatusServiceUnavailable,
		"Title": "Register", "Principal": p, "Heading": "The register could not be read",
		"Body": "Nothing on this screen would be true until it can: " + err.Error()})
}

// registerWaiting is what waits on the register's proposals ref, for the
// one list of what waits (approvals.go), on a server not handed the command
// line's list.
func (s *Server) registerWaiting() ([]waiting.Proposed, error) {
	list, err := register.Open(s.Store).Proposals()
	var out []waiting.Proposed
	for _, pr := range list {
		spec, _ := register.SpecOf(string(pr.Kind))
		by := pr.Agent
		if by == "" {
			by = string(pr.Subject)
		}
		out = append(out, waiting.Proposed{ID: string(pr.ID), Kind: string(pr.Kind), By: by, Why: pr.Why,
			Resource: spec.Resource(), At: pr.At.At()})
	}
	return out, err
}
