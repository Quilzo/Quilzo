// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
		},
		nav: []navEntry{{
			destination: destination{Key: "register", Label: "Register", Path: "/register", Group: "Assurance",
				Doc: "compliance", Needs: auth.ActView},
			icon: "verified", area: register.Area,
			also: []string{"controls", "evidence", "risks", "exceptions", "decisions", "vendors", "ai systems",
				"incidents", "policies", "security record", "proposals"},
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
		"Table": table, "Head": head, "Waiting": len(proposals)}
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
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	const limit = 50
	entries, total, err := reg.List(spec.Kind, offset, limit)
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	var rows []seckit.Row
	for _, e := range entries {
		label := register.Label(e.Record)
		if label == "" {
			label = string(e.ID)
		}
		rows = append(rows, seckit.Row{Head: seckit.LinkCell("/register/record/"+string(e.ID), label),
			Cells: []seckit.Cell{seckit.TextCell(string(e.ID)), seckit.TimeCell(e.Updated.At()), seckit.HashCell(e.Object)}})
	}
	table, err := seckit.NewTable(fmt.Sprintf("%s records, %d to %d of %d", spec.Kind, min(offset+1, total), offset+len(entries), total),
		[]string{"Record", "Identifier", "Last changed", "Stored as"}, rows)
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	data := map[string]any{"Title": string(spec.Kind), "Nav": "register", "Principal": p,
		"Header": seckit.Header{Title: string(spec.Kind), Lead: spec.Summary}, "Spec": spec, "Table": table}
	if total == 0 {
		data["Empty"] = seckit.Empty{Title: "The register holds no " + string(spec.Kind) + " records",
			Body: "Its fields are listed below, as every record of the kind will have them."}
	}
	if next := offset + len(entries); next < total {
		data["Next"] = fmt.Sprintf("/register/kind/%s?offset=%d", strings.TrimPrefix(spec.Collection, register.Prefix), next)
	}
	if offset > 0 {
		data["Previous"] = fmt.Sprintf("/register/kind/%s?offset=%d", strings.TrimPrefix(spec.Collection, register.Prefix), max(offset-limit, 0))
	}
	s.render(w, r, "register_kind.html", data)
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
	s.render(w, r, "register_record.html", map[string]any{"Title": title, "Nav": "register", "Principal": p,
		"Header": seckit.Header{Title: title, Lead: string(e.Kind) + ": " + spec.Summary},
		"Entry":  e, "Spec": spec, "Table": table,
		"Kind":   seckit.LinkCell("/register/kind/"+strings.TrimPrefix(spec.Collection, register.Prefix), string(e.Kind)),
		"Events": []seckit.Event{{At: e.Created.At(), What: "First written"}, {At: e.Updated.At(), What: "Last changed", Hash: e.Object}}})
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
