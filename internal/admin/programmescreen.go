// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/programme"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/seckit"
)

// The security programme's screens: the starters and the requirements they
// brought (Requirements), the statement of applicability for each scope
// (Applicability), the controls with how each stands and the runs of their
// tests explained (Controls), and the populations every figure is counted
// against (Populations). Four modules, each registered from this file, as
// `quilzo requirement`, `quilzo soa`, `quilzo control` and `quilzo
// population` are from theirs.
//
// Each screen reads, built from the security kit and nothing else, and a
// decision waiting for somebody is shown with the hash of exactly what is
// approved and who may approve it. It is decided with a passkey bound to
// that hash, which the approvals module brings; until then the screen says
// it cannot be decided here and names the command that decides it.

func init() {
	nav := func(key, label, path, icon string, also ...string) []navEntry {
		return []navEntry{{destination: destination{Key: key, Label: label, Path: path, Group: "Assurance",
			Doc: "compliance", Needs: auth.ActView}, icon: icon, area: register.Area, also: also}}
	}
	registerScreens(screens{module: "requirement",
		routes: []screenRoute{{path: "/programme/requirements", handle: (*Server).handleRequirements}},
		nav: nav("requirements", "Requirements", "/programme/requirements", "description",
			"frameworks", "starters", "iso 27001", "nis2", "soc 2", "dora", "nist csf", "iso 42001", "annex a")})
	registerScreens(screens{module: "soa",
		routes: []screenRoute{{path: "/programme/soa", handle: (*Server).handleScopes},
			{path: "/programme/soa/", handle: (*Server).handleStatement},
			{path: "/programme/soa-csv/", handle: (*Server).handleStatementCSV}},
		nav: nav("applicability", "Applicability", "/programme/soa", "done_all",
			"statement of applicability", "soa", "scope", "applies", "excluded")})
	registerScreens(screens{module: "control",
		routes: []screenRoute{{path: "/programme/controls", handle: (*Server).handleProgrammeControls},
			{path: "/programme/controls/run/", handle: (*Server).handleProgrammeRun}},
		nav: nav("control-tests", "Control tests", "/programme/controls", "check_circle",
			"programme controls", "tests", "runs", "evidence", "replay", "failures")})
	registerScreens(screens{module: "population",
		routes: []screenRoute{{path: "/programme/populations", handle: (*Server).handlePopulations}},
		nav: nav("populations", "Populations", "/programme/populations", "groups",
			"denominator", "cross-check", "links", "unexplained", "coverage")})
}

// programmeSection is one part of a programme screen: a heading, a line
// about it, and what it shows.
type programmeSection struct {
	Heading   string
	Lead      string
	Lines     []string
	Table     *seckit.Table
	Approvals []seckit.Approval
	// Decide is where each waiting decision is decided: Sign-off, with a
	// passkey bound to its hash.
	Decide  []decideLink
	Empty   *seckit.Empty
	Command string
}

// programmeReady is a signed-in person who may read the register, the
// programme of this server's store, and the register at its head.
func (s *Server) programmeReady(w http.ResponseWriter, r *http.Request) (principal, *programme.Programme, *register.View, bool) {
	p, reg, ok := s.registerReady(w, r)
	if !ok {
		return p, nil, nil, false
	}
	v, err := reg.At("")
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return p, nil, nil, false
	}
	return p, &programme.Programme{Reg: reg}, v, true
}

// renderProgramme draws a programme screen.
func (s *Server) renderProgramme(w http.ResponseWriter, r *http.Request, p principal, nav string, h seckit.Header,
	tiles []seckit.Tile, sections []programmeSection, links map[string]string) {
	var hrefs []struct{ Href, Text string }
	for href, text := range links {
		hrefs = append(hrefs, struct{ Href, Text string }{href, text})
	}
	sort.Slice(hrefs, func(i, j int) bool { return hrefs[i].Href < hrefs[j].Href })
	s.render(w, r, "programme.html", map[string]any{"Title": h.Title, "Nav": nav, "Principal": p, "Header": h,
		"Tiles": tiles, "Sections": sections, "Links": hrefs})
}

// table is a kit table, or the screen saying it could not be drawn.
func table(caption string, columns []string, rows []seckit.Row) *seckit.Table {
	t, err := seckit.NewTable(caption, columns, rows)
	if err != nil {
		return nil
	}
	return &t
}

// waitingFor is the decisions of some kinds that wait on the proposals
// ref, as the approvals module asks them of their approvers: each with the
// hash of exactly what would be approved, who may approve it and how many,
// and where on Sign-off it is decided. It is the one list of what waits,
// read through the one engine, so the hash shown here is the hash the
// passkey signs there and the register holds the record to.
func (s *Server) waitingFor(p principal, kinds ...register.Kind) ([]seckit.Approval, []decideLink) {
	m := s.approvalsFor()
	waiting, err := m.Waiting()
	if err != nil {
		return nil, nil
	}
	me, _ := m.Known(p.Name)
	var out []seckit.Approval
	var links []decideLink
	for _, a := range waiting {
		for _, k := range kinds {
			if a.Proposal.Kind != k {
				continue
			}
			what := decisionWhat(a.Proposal.Record)
			out = append(out, seckit.Approval{What: what + ", raised " + seckit.When(a.Proposal.At.At()), Hash: a.Hash,
				Who: a.Rule.Describe(), Needed: a.Needed, Of: a.Of, Alone: a.Yours(p.Name, me)})
			links = append(links, decideLink{Href: "/register/approvals/item/" + string(a.Proposal.ID),
				Text: "Decide on Sign-off: " + what})
		}
	}
	return out, links
}

// decideLink is where on Sign-off a waiting decision is decided.
type decideLink struct{ Href, Text string }

// decisionWhat is what a decision decides, in a line code writes from its
// typed fields.
func decisionWhat(rec register.Record) string {
	switch d := rec.(type) {
	case register.Starter:
		if d.Installed {
			return "Take the " + d.Framework + " starter into the programme"
		}
		return "Take the " + d.Framework + " starter out of the programme"
	case register.Scope:
		return "The scope " + d.Name
	case register.Applicability:
		word := "applies"
		if !d.Applicable {
			word = "does not apply"
		}
		return "A requirement " + word + " within a scope"
	case register.ControlTest:
		return "The control test " + d.Name
	}
	return string(rec.Kind())
}

func badgeOf(o register.Outcome) seckit.Badge {
	switch o {
	case register.Pass:
		return seckit.Passing
	case register.Fail:
		return seckit.Failing
	case register.Errored:
		return seckit.MustBadge(seckit.Warn, "Could not finish")
	}
	return seckit.NoEvidence
}

func (s *Server) handleRequirements(w http.ResponseWriter, r *http.Request) {
	p, _, v, ok := s.programmeReady(w, r)
	if !ok {
		return
	}
	installed, err := programme.Installed(v)
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	var rows []seckit.Row
	for _, st := range programme.Starters() {
		status := seckit.MustBadge(seckit.Neutral, "Not installed")
		decision := seckit.Cell{}
		if d, in := installed[st.Framework]; in {
			status = seckit.MustBadge(seckit.Good, "Installed")
			if d.Approval != nil && d.Approval.Alone {
				status = seckit.Alone
			}
			if id, err := register.IDOf(d); err == nil {
				decision = seckit.LinkCell("/register/record/"+string(id), "The decision")
			}
		}
		rows = append(rows, seckit.Row{Head: seckit.LinkCell("/programme/requirements?framework="+st.Framework, st.Name+" "+st.Version),
			Cells: []seckit.Cell{seckit.TextCell(fmt.Sprintf("%d %s", len(st.Clauses), st.Level)), seckit.BadgeCell(status), decision}})
	}
	sections := []programmeSection{{Heading: "Starters",
		Lead: "Each starter is a framework's requirements by the framework's own identifiers, each with a line in " +
			"Quilzo's own words; no standard's text is copied. Taking one in or out is one decision.",
		Table:   table("The frameworks there are starters for", []string{"Framework", "What it brings", "In the programme", "Decided by"}, rows),
		Command: "quilzo requirement install FRAMEWORK"}}
	if waiting, decide := s.waitingFor(p, register.KindStarter); len(waiting) > 0 {
		sections = append(sections, programmeSection{Heading: "Waiting for a decision", Approvals: waiting, Decide: decide,
			Lead: "Each waits for a person who did not raise it. It is decided on Sign-off, with a passkey bound to its " +
				"hash; from a terminal, by typing the hash back.", Command: "quilzo requirement approve ID --surface HASH"})
	}
	if f := r.URL.Query().Get("framework"); f != "" {
		st, found := programme.StarterNamed(f)
		if !found {
			http.NotFound(w, r)
			return
		}
		var reqs []seckit.Row
		if _, in := installed[f]; in {
			for _, c := range st.Clauses {
				id, _ := programme.RequirementID(f, c.Ref)
				reqs = append(reqs, seckit.Row{Head: seckit.LinkCell("/register/record/"+string(id), c.Ref),
					Cells: []seckit.Cell{seckit.TextCell(c.Line)}})
			}
		}
		sec := programmeSection{Heading: st.Name + " " + st.Version, Lead: st.About}
		if len(reqs) > 0 {
			sec.Table = table("Its "+st.Level+", in Quilzo's own words", []string{"Identifier", "What it is about"}, reqs)
		} else {
			sec.Empty = &seckit.Empty{Title: "This starter is not in the programme",
				Body: "Its requirements are listed here once a person takes it in."}
		}
		sections = append(sections, sec)
	}
	s.renderProgramme(w, r, p, "requirements", seckit.Header{Title: "Requirements",
		Lead: "What the organisation has to do: the frameworks it answers to, by identifier, in Quilzo's own words."},
		nil, sections, map[string]string{"/programme/soa": "The statement of applicability"})
}

func (s *Server) handleScopes(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/programme/soa" {
		http.NotFound(w, r)
		return
	}
	p, _, v, ok := s.programmeReady(w, r)
	if !ok {
		return
	}
	var rows []seckit.Row
	if err := v.Each(register.KindScope, func(e register.Entry, _ map[string]any) error {
		sc := e.Record.(register.Scope)
		status := seckit.MustBadge(seckit.Good, "Approved")
		if sc.Approval != nil && sc.Approval.Alone {
			status = seckit.Alone
		}
		frameworks := "Every installed framework"
		if len(sc.Frameworks) > 0 {
			frameworks = strings.Join(sc.Frameworks, ", ")
		}
		rows = append(rows, seckit.Row{Head: seckit.LinkCell("/programme/soa/"+sc.Name, sc.Title),
			Cells: []seckit.Cell{seckit.TextCell(frameworks), seckit.BadgeCell(status)}})
		return nil
	}); err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	sec := programmeSection{Heading: "Scopes", Command: "quilzo soa scope NAME --title T --domains D,D"}
	if len(rows) > 0 {
		sec.Table = table("The scopes the programme is decided for", []string{"Scope", "Frameworks", "Decision"}, rows)
	} else {
		sec.Empty = &seckit.Empty{Title: "No scope is decided yet",
			Body: "A scope is what the programme covers, decided by a person: its domains, populations and frameworks."}
	}
	sections := []programmeSection{sec}
	if waiting, decide := s.waitingFor(p, register.KindScope, register.KindApplicability); len(waiting) > 0 {
		sections = append(sections, programmeSection{Heading: "Waiting for a decision", Approvals: waiting, Decide: decide,
			Lead: "Each waits for a person who did not raise it. It is decided on Sign-off, with a passkey bound to its hash.",
			Command: "quilzo soa approve ID --surface HASH"})
	}
	s.renderProgramme(w, r, p, "applicability", seckit.Header{Title: "Applicability",
		Lead: "The statement of applicability: within each scope, whether each requirement applies, and why."},
		nil, sections, map[string]string{"/programme/requirements": "Requirements"})
}

func (s *Server) handleStatement(w http.ResponseWriter, r *http.Request) {
	p, prog, v, ok := s.programmeReady(w, r)
	if !ok {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/programme/soa/")
	st, err := programme.StatementAt(v, prog.Words, name)
	if errors.Is(err, register.ErrNotFound) || strings.Contains(name, "/") {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	at, head := s.registerAt(prog.Reg)
	now := time.Now()
	// Each is a count of the register's own decisions, which are people's
	// and have no grade of facts; the requirements within the scope are
	// counted beside them, so each is read against the whole.
	figure := func(n int, unit string) seckit.Figure {
		f, err := seckit.New(seckit.FigureOf{N: int64(n), Count: true, Unit: unit, Sources: []seckit.Source{seckit.TheRegister},
			At: at, Hash: head, Now: now})
		if err != nil {
			return seckit.Figure{}
		}
		return f
	}
	tiles := []seckit.Tile{{Label: "Within the scope", Figure: figure(len(st.Lines), "requirements")},
		{Label: "Apply", Figure: figure(st.Applying, "decided to apply")},
		{Label: "Do not apply", Figure: figure(st.NotApplying, "decided not to apply")},
		{Label: "Undecided", Figure: figure(st.Undecided, "nobody has decided")}}
	byFramework := map[string][]seckit.Row{}
	for _, l := range st.Lines {
		state := seckit.MustBadge(seckit.Neutral, "Undecided")
		switch l.State {
		case programme.Applies:
			state = seckit.MustBadge(seckit.Info, "Applies")
		case programme.Excluded:
			state = seckit.MustBadge(seckit.Info, "Does not apply")
		}
		why := l.Justification
		if l.Decision != "" && !l.Kept {
			why = "The words are not kept here; the line holds their digest."
		}
		var evidence []string
		for _, c := range l.Controls {
			evidence = append(evidence, fmt.Sprintf("%s (%s): %s", c.Ref, c.Relation, standingWords(c.Standing)))
		}
		for _, rel := range l.Related {
			if rel.From {
				evidence = append(evidence, fmt.Sprintf("%s %s is %s this", rel.Framework, rel.Ref, rel.Relation))
			} else {
				evidence = append(evidence, fmt.Sprintf("is %s %s %s", rel.Relation, rel.Framework, rel.Ref))
			}
		}
		decided := seckit.Cell{}
		if l.Decision != "" {
			word := "Approved"
			if l.Approval != nil && l.Approval.Alone {
				word = "Approved alone"
			}
			decided = seckit.LinkCell("/register/record/"+string(l.Decision), word)
		}
		byFramework[l.Framework] = append(byFramework[l.Framework], seckit.Row{Head: seckit.TextCell(l.Ref),
			Cells: []seckit.Cell{seckit.TextCell(l.Title), seckit.BadgeCell(state), seckit.TextCell(why),
				seckit.TextCell(strings.Join(evidence, "; ")), decided}})
	}
	var sections []programmeSection
	for _, f := range st.Frameworks {
		name := f
		if s, ok := programme.StarterNamed(f); ok {
			name = s.Name + " " + s.Version
		}
		sections = append(sections, programmeSection{Heading: name,
			Table: table(name+": each requirement within the scope", []string{"Requirement", "What it is about", "Applicability",
				"Why", "Evidence towards it", "Decision"}, byFramework[f])})
	}
	if len(sections) == 0 {
		sections = append(sections, programmeSection{Heading: "Requirements", Empty: &seckit.Empty{
			Title: "No framework this scope answers to is installed", Href: "/programme/requirements", Action: "Requirements"}})
	}
	sections = append(sections, programmeSection{Heading: "Reading it",
		Lead: "Evidence towards a requirement is not the requirement met: each control's relation says how much of the " +
			"requirement it is, and a requirement nobody decided is counted as neither applying nor not.",
		Command: "quilzo soa show " + st.Scope.Name + " --csv"})
	s.renderProgramme(w, r, p, "applicability", seckit.Header{Title: st.Scope.Title,
		Lead: "The statement of applicability for the scope " + st.Scope.Name + ", at the register's commit " + seckit.Short(st.Commit) + "."},
		tiles, sections, map[string]string{"/programme/soa-csv/" + st.Scope.Name: "Download the statement as CSV",
			"/programme/soa": "Every scope"})
}

func (s *Server) handleStatementCSV(w http.ResponseWriter, r *http.Request) {
	p, prog, v, ok := s.programmeReady(w, r)
	if !ok {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/programme/soa-csv/")
	st, err := programme.StatementAt(v, prog.Words, name)
	if errors.Is(err, register.ErrNotFound) || strings.Contains(name, "/") {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="statement-of-applicability-`+name+`.csv"`)
	_ = st.WriteCSV(w)
}

// standingWords is how a control stood, as a screen says it.
func standingWords(st programme.Standing) string {
	switch st.Outcome {
	case register.Pass:
		return "passing at its newest run, " + seckit.When(st.At.At())
	case register.Fail:
		return "failing at its newest run, " + seckit.When(st.At.At())
	}
	return "no evidence from a run"
}

func (s *Server) handleProgrammeControls(w http.ResponseWriter, r *http.Request) {
	p, _, v, ok := s.programmeReady(w, r)
	if !ok {
		return
	}
	standing, err := programme.Standings(v)
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	var controls []seckit.Row
	if err := v.Each(register.KindControl, func(e register.Entry, _ map[string]any) error {
		c := e.Record.(register.Control)
		st := standing[e.ID]
		newest := seckit.Cell{}
		if st.Run != "" {
			newest = seckit.LinkCell("/programme/controls/run/"+string(st.Run), "Its newest run, "+seckit.When(st.At.At()))
		}
		controls = append(controls, seckit.Row{Head: seckit.TextCell(c.Ref),
			Cells: []seckit.Cell{seckit.TextCell(c.Title), seckit.TextCell(string(c.Domain)), seckit.BadgeCell(badgeOf(st.Outcome)), newest}})
		return nil
	}); err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	sort.Slice(controls, func(i, j int) bool { return controls[i].Head.Text() < controls[j].Head.Text() })
	sec := programmeSection{Heading: "Controls", Command: "quilzo control list",
		Lead: "A control's status moves on a run of one of its tests, and on nothing else."}
	if len(controls) > 0 {
		sec.Table = table("The controls, each as its newest run left it", []string{"Control", "What it is", "Domain", "Status", "Evidence"}, controls)
	} else {
		sec.Empty = &seckit.Empty{Title: "No control yet", Body: "A control is something the organisation does to meet a requirement."}
	}
	var tests []seckit.Row
	if err := v.Each(register.KindControlTest, func(e register.Entry, _ map[string]any) error {
		t := e.Record.(register.ControlTest)
		every := programme.DefaultEvery
		if t.Every > 0 {
			every = time.Duration(t.Every) * time.Second
		}
		approved := "Approved"
		if t.Approval != nil && t.Approval.Alone {
			approved = "Approved alone"
		}
		tests = append(tests, seckit.Row{Head: seckit.LinkCell("/register/record/"+string(e.ID), t.Name),
			Cells: []seckit.Cell{seckit.TextCell(string(t.Assertion)), seckit.TextCell("every " + seckit.Age(every)),
				seckit.TextCell(approved), seckit.HashCell(string(t.Query))}})
		return nil
	}); err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	testSec := programmeSection{Heading: "Control tests", Command: "quilzo control draft FILE",
		Lead: "Each test is a typed query and an assertion over a population, approved by a person and run by the scheduler."}
	if len(tests) > 0 {
		testSec.Table = table("The approved tests", []string{"Test", "Asserts", "Runs", "Approval", "Query"}, tests)
	} else {
		testSec.Empty = &seckit.Empty{Title: "No approved test yet",
			Body: "A draft, a person's or a model's, waits for somebody who did not draft it before anything runs it."}
	}
	sections := []programmeSection{sec, testSec}
	if waiting, decide := s.waitingFor(p, register.KindControlTest); len(waiting) > 0 {
		sections = append(sections, programmeSection{Heading: "Waiting for a decision", Approvals: waiting, Decide: decide,
			Lead: "Each draft waits for a person who did not draft it; nothing runs it until then. It is decided on " +
				"Sign-off, with a passkey bound to its hash.", Command: "quilzo control approve ID --surface HASH"})
	}
	s.renderProgramme(w, r, p, "control-tests", seckit.Header{Title: "Control tests",
		Lead: "What the organisation does, and what shows it working: each control as its tests' runs left it."},
		nil, sections, map[string]string{"/programme/populations": "Populations"})
}

func (s *Server) handleProgrammeRun(w http.ResponseWriter, r *http.Request) {
	p, prog, _, ok := s.programmeReady(w, r)
	if !ok {
		return
	}
	id := register.ID(strings.TrimPrefix(r.URL.Path, "/programme/controls/run/"))
	e, err := prog.Reg.Get(id)
	rec, isRun := e.Record.(register.TestRun)
	if errors.Is(err, register.ErrNotFound) || err == nil && (!isRun || rec.Commit == "") {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	at, err := prog.Reg.At(rec.Commit)
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	run, err := programme.Evaluate(at, rec.Test, rec.Ran.At())
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	run.Record = rec
	replay, err := prog.Replay(id)
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	same := seckit.MustBadge(seckit.Good, "Replays the same")
	replayLines := []string{"Read again at the commit it named, it gives the run that was recorded."}
	if !replay.Same {
		same = seckit.MustBadge(seckit.Bad, "Replays otherwise")
		replayLines = replay.Differences
	}
	rows := []seckit.Row{
		{Head: seckit.TextCell("Outcome"), Cells: []seckit.Cell{seckit.BadgeCell(badgeOf(rec.Outcome))}},
		{Head: seckit.TextCell("Ran"), Cells: []seckit.Cell{seckit.TimeCell(rec.Ran.At())}},
		{Head: seckit.TextCell("Read the register at"), Cells: []seckit.Cell{seckit.HashCell(rec.Commit)}},
		{Head: seckit.TextCell("Members, as a digest"), Cells: []seckit.Cell{seckit.HashCell(string(rec.Population))}},
		{Head: seckit.TextCell("What it read, as a digest"), Cells: []seckit.Cell{seckit.HashCell(string(rec.Snapshot))}},
		{Head: seckit.TextCell("Replay"), Cells: []seckit.Cell{seckit.BadgeCell(same)}},
	}
	sections := []programmeSection{
		{Heading: "Why it came out as it did", Lines: programme.Explain(run),
			Lead: "Written by code from the test's assertion, its query's terms and the members that failed, by identifier."},
		{Heading: "The run", Table: table("The run as it was recorded", []string{"Of the run", "Value"}, rows)},
		{Heading: "Done again", Lines: replayLines, Command: "quilzo control replay " + string(id)},
	}
	s.renderProgramme(w, r, p, "control-tests", seckit.Header{Title: "A run of " + run.Test.Name,
		Lead: "One run of a control test, explained, and done again from the commit it read."},
		nil, sections, map[string]string{"/programme/controls": "Every control test"})
}

// labelBadge is a population's label as a status.
func labelBadge(l programme.Label) seckit.Badge {
	switch l {
	case programme.Unchecked:
		return seckit.MustBadge(seckit.Warn, "Single source, unchecked")
	case programme.Circular:
		return seckit.MustBadge(seckit.Warn, "Circular")
	case programme.Stale:
		return seckit.Stale
	}
	return seckit.MustBadge(seckit.Neutral, "Not yet counted")
}

func (s *Server) handlePopulations(w http.ResponseWriter, r *http.Request) {
	p, _, v, ok := s.programmeReady(w, r)
	if !ok {
		return
	}
	now := time.Now()
	var rows []seckit.Row
	if err := v.Each(register.KindPopulation, func(e register.Entry, _ map[string]any) error {
		pop := e.Record.(register.Population)
		// Each count names the sources it was made from, and is graded as
		// the weakest of them: the disagreement is made from both.
		count := func(n int64, unit string, srcs ...register.ID) seckit.Cell {
			if pop.Counted == 0 {
				return seckit.Cell{}
			}
			var sources []seckit.Source
			grade := register.GradeConnector
			for _, src := range srcs {
				sources = append(sources, seckit.Source{Name: sourceLabel(v, src), ID: src, Href: "/register/record/" + string(src)})
				if g := sourceGrade(v, src); g.Rank() > grade.Rank() {
					grade = g
				}
			}
			f, err := seckit.New(seckit.FigureOf{N: n, Count: true, Unit: unit, Sources: sources,
				At: pop.Counted.At(), Hash: pop.Commit, Grade: grade, Now: now,
				Window: time.Duration(pop.Fresh) * time.Second})
			if err != nil {
				return seckit.TextCell(fmt.Sprintf("%d %s", n, unit))
			}
			return seckit.FigureCell(f)
		}
		var labels []string
		for _, l := range programme.Labels(pop, now) {
			labels = append(labels, labelBadge(l).Word())
		}
		cross, unexplained := seckit.TextCell("None: single source"), seckit.Cell{}
		if pop.CrossCheck != "" {
			cross = count(pop.CrossSize, "known to the cross-check", pop.CrossCheck)
			unexplained = count(pop.Unexplained, "unexplained", pop.Source, pop.CrossCheck)
		}
		rows = append(rows, seckit.Row{Head: seckit.LinkCell("/register/record/"+string(e.ID), pop.Name),
			Cells: []seckit.Cell{count(pop.Size, "members", pop.Source), cross, unexplained, seckit.TextCell(strings.Join(labels, "; "))}})
		return nil
	}); err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	sec := programmeSection{Heading: "Populations", Command: "quilzo population count NAME",
		Lead: "Each population says where its count comes from and is compared with a second source where there is one; " +
			"what either has that the other has no counterpart for is a number of its own."}
	if len(rows) > 0 {
		sec.Table = table("The populations, as last counted", []string{"Population", "Members", "Cross-check", "Unexplained", "Labels"}, rows)
	} else {
		sec.Empty = &seckit.Empty{Title: "No population yet",
			Body: "A population is the N of every n of N: every member of staff, every laptop, with where it is counted from."}
	}
	s.renderProgramme(w, r, p, "populations", seckit.Header{Title: "Populations",
		Lead: "The denominators every coverage figure is counted against, each with its source and a cross-check."},
		nil, []programmeSection{sec}, map[string]string{"/programme/controls": "Control tests"})
}

// sourceLabel is what a source is called, and sourceGrade the grade of the
// facts it yields.
func sourceLabel(v *register.View, id register.ID) string {
	if e, err := v.Get(id); err == nil {
		if s, ok := e.Record.(register.Source); ok {
			if s.Title != "" {
				return s.Title
			}
			return s.Name
		}
	}
	return "A source not in the register"
}

func sourceGrade(v *register.View, id register.ID) register.Grade {
	if e, err := v.Get(id); err == nil {
		if s, ok := e.Record.(register.Source); ok {
			return s.Grade
		}
	}
	return register.GradeScreenshot
}
