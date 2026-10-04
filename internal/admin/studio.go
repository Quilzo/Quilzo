// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/auth"
)

// The studio: declaring an agent, seeing what it may reach, trying it, and
// reading what it did.
//
// Every visual builder draws an agent as a canvas of nodes, and the canvas
// is the agent: what runs is whatever the drawing says, stored in the
// builder's own format. Here the agent is its declaration — one reviewable
// document — and the picture is drawn from it. The form edits the
// declaration, the map is rendered from the declaration, and the text of
// the declaration is on the same page, so there is never a drawing that
// says one thing and a file that says another.
//
// The map is the point of the page. It shows what the agent reads on the
// left and what it may do on the right, with the writes marked and the
// place a person stands marked, because that is the question somebody
// reviewing an agent is asking and a list of capability names does not
// answer it at a glance.

var agentName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)

// mapBox is one box of the map, in the drawing's own units.
type mapBox struct {
	X, Y, W, H int
	// TX and TY are where its label sits.
	TX, TY     int
	Label, Sub string
	Class      string
}

// mapLine joins two boxes.
type mapLine struct {
	X1, Y1, X2, Y2 int
	Class          string
}

// agentMap is a declaration drawn.
type agentMap struct {
	W, H  int
	Boxes []mapBox
	Lines []mapLine
	// Heads are the three column headings.
	Heads []mapBox
	// Says describes the drawing in a sentence, for whoever cannot see it.
	Says string
}

func clipText(s string, n int) string {
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

// drawAgent lays a declaration out: what it reads, the agent, what it may
// do. Positions are computed here so the template only places them.
func drawAgent(m agent.Manifest) agentMap {
	const (
		colW, boxH, gap = 210, 36, 10
		leftX, midX     = 10, 275
		rightX, top     = 540, 40
	)
	type item struct{ label, sub, class string }
	var reads, does []item

	ref := m.Retrieval.Ref
	if ref == "" {
		ref = "live"
	}
	scope := "the " + ref + " site"
	if m.Retrieval.Path != "" {
		scope += " under " + m.Retrieval.Path
	}
	reads = append(reads, item{scope, "published content", "read"})
	if len(m.Retrieval.Types) > 0 {
		reads = append(reads, item{"only " + strings.Join(m.Retrieval.Types, ", "),
			"content types", "read"})
	}
	if len(m.Retrieval.Locales) > 0 {
		reads = append(reads, item{"only " + strings.Join(m.Retrieval.Locales, ", "),
			"languages", "read"})
	}
	if m.Memory.Any() {
		reads = append(reads, item{"its own memory",
			memoryTiers(m.Memory) + ", kept " + m.Memory.Retain.String(), "read"})
	}

	writes := 0
	for _, c := range m.Capabilities {
		if agent.IsWrite(c) {
			writes++
			does = append(does, item{c, "changes the site", "write"})
		}
	}
	for _, c := range m.Capabilities {
		if !agent.IsWrite(c) {
			does = append(does, item{c, "", "cap"})
		}
	}
	for _, t := range m.Tools {
		sub := "reaches " + t.Host
		class := "tool"
		if t.Writes {
			sub, class = "writes to "+t.Host, "write"
			writes++
		}
		does = append(does, item{t.Name, sub, class})
	}
	asks := map[string]bool{}
	for _, a := range m.AskFirst {
		asks[a] = true
	}
	asked := 0
	for i := range does {
		if asks[does[i].label] {
			asked++
			does[i].sub, does[i].class = "asks a person first", "ask"
		}
	}
	for _, d := range m.Delegates {
		does = append(does, item{d, "another agent", "deleg"})
	}
	if len(does) == 0 {
		does = append(does, item{"nothing", "no capability is granted", "none"})
	}

	rows := len(reads)
	if len(does) > rows {
		rows = len(does)
	}
	height := top + rows*(boxH+gap) + 20
	if height < 200 {
		height = 200
	}
	out := agentMap{W: 760, H: height}
	for _, h := range []struct {
		x     int
		label string
	}{{leftX, "Reads"}, {midX, "The agent"}, {rightX, "May do"}} {
		out.Heads = append(out.Heads, mapBox{TX: h.x, TY: 22, Label: h.label})
	}
	coreH := 96
	coreY := top + (height-top-20-coreH)/2
	if coreY < top {
		coreY = top
	}
	core := mapBox{X: midX, Y: coreY, W: colW, H: coreH, TX: midX + 12,
		TY: coreY + 26, Label: clipText(m.Name, 24),
		Sub: string(m.Kind) + " · " + string(m.Autonomy), Class: "core"}
	for n, it := range reads {
		y := top + n*(boxH+gap)
		out.Boxes = append(out.Boxes, mapBox{X: leftX, Y: y, W: colW, H: boxH,
			TX: leftX + 10, TY: y + 15, Label: clipText(it.label, 30),
			Sub: clipText(it.sub, 36), Class: it.class})
		out.Lines = append(out.Lines, mapLine{leftX + colW, y + boxH/2,
			midX, coreY + coreH/2, "edge"})
	}
	for n, it := range does {
		y := top + n*(boxH+gap)
		out.Boxes = append(out.Boxes, mapBox{X: rightX, Y: y, W: colW, H: boxH,
			TX: rightX + 10, TY: y + 15, Label: clipText(it.label, 30),
			Sub: clipText(it.sub, 36), Class: it.class})
		class := "edge"
		if it.class == "write" {
			class = "edge write"
		}
		out.Lines = append(out.Lines, mapLine{midX + colW, coreY + coreH/2,
			rightX, y + boxH/2, class})
	}
	out.Boxes = append(out.Boxes, core)
	if m.HumanApproval || m.Autonomy == agent.AutonomyPropose {
		// Where a person stands: between the agent and what it does.
		gx := midX + colW + 12
		out.Boxes = append(out.Boxes, mapBox{X: gx, Y: top, W: 30,
			H: height - top - 20, TX: gx + 19, TY: top + (height-top-20)/2,
			Label: "a person", Class: "gate"})
	}
	person := "nothing it does waits for a person"
	switch {
	case m.Autonomy == agent.AutonomyPropose:
		person = "it proposes and a person decides"
	case m.HumanApproval:
		person = "a person approves before anything it did is public"
	}
	out.Says = fmt.Sprintf("%s reads %s and may do %s, "+
		"%d of which write; %s.", m.Name, countOf(len(reads), "source", "sources"),
		countOf(len(does), "thing", "things"), writes, person)
	if asked > 0 {
		if m.Autonomy != agent.AutonomyPropose && !m.HumanApproval {
			person = "the rest goes ahead without one"
		}
		out.Says = fmt.Sprintf("%s reads %s and may do %s, "+
			"%d of which write. It stops and asks a person before %d of "+
			"them; %s.", m.Name, countOf(len(reads), "source", "sources"),
			countOf(len(does), "thing", "things"), writes, asked, person)
	}
	return out
}

// capRow is one capability as a checkbox.
type capRow struct {
	Name          string
	On, Risk, Ask bool
}

func (s *Server) studioAllowed(w http.ResponseWriter, r *http.Request) (principal, bool) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return p, false
	}
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return p, false
	}
	w.Header().Set("Cache-Control", "no-store")
	return p, true
}

// editData fills the builder page for one manifest, saved or not.
func (s *Server) editData(data map[string]any, m agent.Manifest, isNew bool,
	declared map[string]agent.Manifest) {

	data["M"], data["New"] = m, isNew
	data["Map"] = drawAgent(m)
	var known []string
	if s.Agents.Known != nil {
		known = s.Agents.Known()
	}
	held := map[string]bool{}
	for _, c := range m.Capabilities {
		held[c] = true
	}
	asks := map[string]bool{}
	for _, a := range m.AskFirst {
		asks[a] = true
	}
	var caps []capRow
	for _, c := range known {
		caps = append(caps, capRow{c, held[c], agent.IsWrite(c), asks[c]})
		delete(held, c)
	}
	// A capability the declaration holds and nothing offers is shown, and
	// shown as wrong, rather than dropped on the next save.
	var unknown []string
	for c := range held {
		unknown = append(unknown, c)
	}
	sort.Strings(unknown)
	sort.SliceStable(caps, func(i, j int) bool {
		if caps[i].Risk != caps[j].Risk {
			return caps[i].Risk
		}
		return caps[i].Name < caps[j].Name
	})
	data["Caps"], data["UnknownCaps"] = caps, unknown
	data["Types"] = strings.Join(m.Retrieval.Types, ", ")
	data["Locales"] = strings.Join(m.Retrieval.Locales, ", ")
	data["Retain"] = ""
	if m.Memory.Retain > 0 {
		data["Retain"] = m.Memory.Retain.String()
	}
	data["Duration"] = m.Budget.Duration.String()
	var others []capRow
	delegated := map[string]bool{}
	for _, d := range m.Delegates {
		delegated[d] = true
	}
	for name := range declared {
		if name != m.Name {
			others = append(others, capRow{Name: name, On: delegated[name]})
		}
	}
	sort.Slice(others, func(i, j int) bool { return others[i].Name < others[j].Name })
	data["Others"] = others
	data["Kinds"] = agent.Catalogue()
	if b, err := json.MarshalIndent(m, "", "  "); err == nil {
		data["Definition"] = string(b)
	}
	var known2 map[string]bool
	if len(known) > 0 {
		known2 = map[string]bool{}
		for _, c := range known {
			known2[c] = true
		}
	}
	check := m
	if err := check.Validate(known2); err != nil {
		data["Invalid"] = err.Error()
	}
}

func (s *Server) handleAgentEdit(w http.ResponseWriter, r *http.Request) {
	p, ok := s.studioAllowed(w, r)
	if !ok {
		return
	}
	data := map[string]any{"Title": "Agent", "Principal": p, "Nav": "agents",
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e")}
	if s.Agents == nil || s.Agents.Load == nil {
		http.Error(w, "this build was started without the agent declarations, "+
			"so there is nothing here to edit", http.StatusServiceUnavailable)
		return
	}
	declared, err := s.Agents.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if r.URL.Path == "/agents/new" {
		kind := agent.Kind(r.URL.Query().Get("kind"))
		t, known := agent.For(kind)
		if !known {
			t, _ = agent.For(agent.KindRetrieval)
		}
		m := t.Manifest
		m.Name = ""
		data["Summary"], data["When"] = t.Summary, t.When
		s.editData(data, m, true, declared)
		s.render(w, r, "agent_edit.html", data)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/agents/edit/")
	m, found := declared[name]
	if !found || !agentName.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	data["Title"] = name
	s.editData(data, m, false, declared)
	if s.Agents.Runs != nil {
		if runs, rerr := s.Agents.Runs(name); rerr == nil {
			if len(runs) > 5 {
				runs = runs[:5]
			}
			data["Runs"] = runRows(runs, time.Now().UTC())
		}
	}
	s.render(w, r, "agent_edit.html", data)
}

func list(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// manifestFromForm is the declaration a submitted form describes, starting
// from what was there so that what the form does not show is not lost.
func manifestFromForm(r *http.Request, base agent.Manifest) (agent.Manifest, error) {
	m := base
	m.Purpose = strings.TrimSpace(r.FormValue("purpose"))
	m.Autonomy = agent.Autonomy(r.FormValue("autonomy"))
	m.Capabilities = append([]string(nil), r.Form["cap"]...)
	sort.Strings(m.Capabilities)
	// Asking first: what the form ticked, and whatever was set on a tool,
	// which the form does not show. Ticked for a capability that was not
	// granted is dropped here rather than refused: the two boxes sit side
	// by side and unticking one should not need the other unticked first.
	granted := map[string]bool{}
	for _, c := range m.Capabilities {
		granted[c] = true
	}
	var ask []string
	for _, a := range r.Form["ask"] {
		if granted[a] {
			ask = append(ask, a)
		}
	}
	for _, a := range base.AskFirst {
		for _, t := range base.Tools {
			if t.Name == a {
				ask = append(ask, a)
			}
		}
	}
	sort.Strings(ask)
	m.AskFirst = ask
	m.Retrieval.Ref = strings.TrimSpace(r.FormValue("ref"))
	m.Retrieval.Path = strings.TrimSpace(r.FormValue("path"))
	m.Retrieval.Types = list(r.FormValue("types"))
	m.Retrieval.Locales = list(r.FormValue("locales"))
	m.Memory.Episodic = r.FormValue("episodic") != ""
	m.Memory.Semantic = r.FormValue("semantic") != ""
	m.Memory.Procedural = r.FormValue("procedural") != ""
	m.Memory.Retain = 0
	if v := strings.TrimSpace(r.FormValue("retain")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return m, fmt.Errorf("how long memory is kept is a duration like 720h")
		}
		m.Memory.Retain = agent.Duration(d)
	}
	steps, err1 := strconv.Atoi(strings.TrimSpace(r.FormValue("steps")))
	tools, err2 := strconv.Atoi(strings.TrimSpace(r.FormValue("tool_calls")))
	d, err3 := time.ParseDuration(strings.TrimSpace(r.FormValue("duration")))
	if err1 != nil || err2 != nil || err3 != nil {
		return m, fmt.Errorf("a budget is a number of steps, a number of " +
			"tool calls and a duration like 5m")
	}
	m.Budget = agent.Budget{Steps: steps, Tools: tools, Duration: agent.Duration(d)}
	m.Delegates = append([]string(nil), r.Form["delegate"]...)
	sort.Strings(m.Delegates)
	m.HumanApproval = r.FormValue("human_approval") != ""
	return m, nil
}

func (s *Server) handleAgentsAct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "use the form", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.studioAllowed(w, r)
	if !ok {
		return
	}
	if s.Agents == nil || s.Agents.Load == nil || s.Agents.Save == nil {
		http.Error(w, "this build cannot change the agents",
			http.StatusServiceUnavailable)
		return
	}
	back := func(to, msg string, err error) {
		v := url.Values{}
		if err != nil {
			v.Set("e", err.Error())
		} else {
			v.Set("m", msg)
		}
		sep := "?"
		if strings.Contains(to, "?") {
			sep = "&"
		}
		http.Redirect(w, r, to+sep+v.Encode(), http.StatusSeeOther)
	}
	declared, err := s.Agents.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	do := r.FormValue("do")
	if do == "answer" || do == "resume" || do == "replay" {
		s.handleRunAct(w, r, p, do, back)
		return
	}
	if !agentName.MatchString(name) {
		back("/agents", "", fmt.Errorf("an agent's name is lower-case "+
			"letters, digits and hyphens"))
		return
	}
	existing, exists := declared[name]
	page := "/agents/edit/" + url.PathEscape(name)
	isNew := r.FormValue("new") != ""
	fresh := "/agents/new?kind=" + url.QueryEscape(r.FormValue("kind"))
	switch do {
	case "save":
		base := existing
		if isNew {
			if exists {
				back(fresh, "", fmt.Errorf("an agent called %s is already "+
					"declared", name))
				return
			}
			t, known := agent.For(agent.Kind(r.FormValue("kind")))
			if !known {
				back("/agents", "", fmt.Errorf("that is not a kind of agent"))
				return
			}
			base = t.Manifest
			base.Name = name
		} else if !exists {
			http.NotFound(w, r)
			return
		}
		m, ferr := manifestFromForm(r, base)
		if ferr == nil {
			ferr = s.Agents.Save(m, isNew, p.Name)
		}
		if ferr != nil {
			if isNew {
				back(fresh, "", ferr)
			} else {
				back(page, "", ferr)
			}
			return
		}
		back(page, "Saved. The map below is the declaration as it now stands.", nil)
	case "define":
		// The declaration as text. It is the same document the form edits,
		// for whoever would rather read and paste it.
		var m agent.Manifest
		raw := r.FormValue("definition")
		if len(raw) > 64<<10 {
			back(page, "", fmt.Errorf("a declaration is not that long"))
			return
		}
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		if derr := dec.Decode(&m); derr != nil {
			back(page, "", fmt.Errorf("that is not a declaration: %w", derr))
			return
		}
		if m.Name != name {
			back(page, "", fmt.Errorf("the declaration names %q and this is "+
				"%s. Renaming is declaring a new agent", m.Name, name))
			return
		}
		if !exists {
			http.NotFound(w, r)
			return
		}
		if serr := s.Agents.Save(m, false, p.Name); serr != nil {
			back(page, "", serr)
			return
		}
		back(page, "Saved from the text.", nil)
	case "remove":
		if !exists || s.Agents.Remove == nil {
			http.NotFound(w, r)
			return
		}
		back("/agents", name+" is no longer declared. Its past runs are kept.",
			s.Agents.Remove(name, p.Name))
	case "run":
		if !exists || s.Agents.Run == nil {
			http.NotFound(w, r)
			return
		}
		goal := strings.TrimSpace(r.FormValue("goal"))
		if len(goal) > 2000 {
			back(page, "", fmt.Errorf("say what it should do in a few lines"))
			return
		}
		id, rerr := s.Agents.Run(name, goal, r.FormValue("model") != "", p.Name)
		if id == "" {
			back(page, "", rerr)
			return
		}
		// Kept even when it ended badly: that is the run worth reading.
		http.Redirect(w, r, "/agents/run/"+id, http.StatusSeeOther)
	default:
		http.Error(w, "nothing to do", http.StatusBadRequest)
	}
}

// runRow is one kept run in a list.
type runRow struct {
	ID, Agent, Goal, By, Model, When, Outcome, Tone, Took string
	Did, Refused, Failed, Steps                           int
	Tainted                                               bool
}

func runRows(in []agent.Record, now time.Time) []runRow {
	var out []runRow
	for _, r := range in {
		row := runRow{ID: r.ID, Agent: r.Agent, Goal: clipText(r.Goal, 120),
			By: r.By, Model: r.Model, When: agoText(now.Sub(r.Started)),
			Outcome: r.OutcomeAt(now), Did: r.Receipt.Did,
			Refused: r.Receipt.Refused, Failed: r.Receipt.Failed,
			Steps: len(r.Trace.Steps), Tainted: r.Trace.Tainted,
			Took: r.Trace.Spent.Elapsed.Round(time.Millisecond).String()}
		row.Tone = map[string]string{"complete": "good", "refused": "warning",
			"failed": "critical", "stopped": "serious", "waiting": "warning",
			"running": "info", "interrupted": "serious"}[row.Outcome]
		out = append(out, row)
	}
	return out
}

func (s *Server) handleAgentRuns(w http.ResponseWriter, r *http.Request) {
	p, ok := s.studioAllowed(w, r)
	if !ok {
		return
	}
	data := map[string]any{"Title": "Agent runs", "Principal": p, "Nav": "agents"}
	if s.Agents == nil || s.Agents.Runs == nil {
		data["Unavailable"] = "This build was started without the run store."
		s.render(w, r, "agent_runs.html", data)
		return
	}
	only := r.URL.Query().Get("agent")
	if only != "" && !agentName.MatchString(only) {
		only = ""
	}
	runs, err := s.Agents.Runs(only)
	if err != nil {
		data["Unavailable"] = "The runs could not be read: " + err.Error()
		s.render(w, r, "agent_runs.html", data)
		return
	}
	data["Only"] = only
	if len(runs) > 200 {
		data["More"] = len(runs) - 200
		runs = runs[:200]
	}
	data["Runs"] = runRows(runs, time.Now().UTC())
	s.render(w, r, "agent_runs.html", data)
}

func (s *Server) handleAgentRun(w http.ResponseWriter, r *http.Request) {
	p, ok := s.studioAllowed(w, r)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/agents/run/")
	if s.Agents == nil || s.Agents.RunGet == nil || !agent.ValidRecordID(id) {
		http.NotFound(w, r)
		return
	}
	rec, err := s.Agents.RunGet(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	now := time.Now().UTC()
	row := runRows([]agent.Record{rec}, now)[0]
	data := map[string]any{"Title": "Run of " + rec.Agent, "Principal": p,
		"Nav": "agents", "R": rec, "Row": row,
		"Started": rec.Started.Format("Mon 2 Jan 2006 15:04:05 UTC"),
		"Message": r.URL.Query().Get("m")}
	type stepRow struct {
		N                                   int
		What, Kind, Input, Why, Result, Err string
		Allowed                             bool
		Word, Tone, Redirected              string
		// Fields is the input as a person reads it, when every value in
		// it is plain: each name with its text, line breaks kept.
		Fields []inputField
		// Took is how long the step took, and Bar its share of the
		// slowest, for the timeline.
		Took string
		Bar  int
	}
	var steps []stepRow
	prev := rec.Started
	var slowest time.Duration
	var took []time.Duration
	for _, st := range rec.Trace.Steps {
		d := time.Duration(0)
		if !st.At.IsZero() && !prev.IsZero() && st.At.After(prev) {
			d = st.At.Sub(prev)
		}
		if !st.At.IsZero() {
			prev = st.At
		}
		took = append(took, d)
		if d > slowest {
			slowest = d
		}
	}
	for i, st := range rec.Trace.Steps {
		sr := stepRow{N: st.N, Allowed: st.Allowed, Why: st.Why,
			Result: st.Result, Err: st.Err, Redirected: st.Redirected}
		sr.Took = took[i].Round(time.Millisecond).String()
		if slowest > 0 {
			sr.Bar = int(100*took[i]/slowest + 0)
			if sr.Bar < 2 {
				sr.Bar = 2
			}
		}
		switch {
		case st.Action.Op != "":
			sr.What, sr.Kind = st.Action.Op, "capability"
		case st.Action.Tool != "":
			sr.What, sr.Kind = st.Action.Tool, "tool"
		case st.Action.Delegate != "":
			sr.What, sr.Kind = st.Action.Delegate, "another agent"
		default:
			sr.What, sr.Kind = "finished", ""
		}
		if len(st.Action.Input) > 0 {
			if b, jerr := json.Marshal(st.Action.Input); jerr == nil {
				sr.Input = clipText(string(b), 600)
			}
		}
		switch {
		case !st.Allowed:
			sr.Word, sr.Tone = "refused", "warning"
		case st.Err != "":
			sr.Word, sr.Tone = "failed", "critical"
		default:
			sr.Word, sr.Tone = "done", "good"
		}
		steps = append(steps, sr)
	}
	data["Steps"] = steps
	data["State"] = rec.OutcomeAt(now)
	if s.Evals != nil && rec.Eval == "" && rec.Trace.Waiting == nil && rec.OutcomeAt(now) != agent.Running {
		data["Keep"] = keepData(rec)
	}
	row.Outcome = rec.OutcomeAt(now)
	if tone, ok := map[string]string{"waiting": "warning", "running": "info",
		"interrupted": "serious"}[row.Outcome]; ok {
		row.Tone = tone
	}
	data["Row"] = row
	if wt := rec.Trace.Waiting; wt != nil {
		pend := stepRow{N: wt.N}
		switch {
		case wt.Action.Tool != "":
			pend.What, pend.Kind = wt.Action.Tool, "tool"
		default:
			pend.What, pend.Kind = wt.Action.Op, "capability"
		}
		if len(wt.Action.Input) > 0 {
			if b, jerr := json.MarshalIndent(wt.Action.Input, "", "  "); jerr == nil {
				pend.Input = clipText(string(b), 8000)
			}
			pend.Fields = readableInput(wt.Action.Input)
		}
		data["Pending"] = pend
		data["Asked"] = agoText(now.Sub(wt.Since))
		data["Expired"] = now.Sub(wt.Since) > agent.PendingTTL
	}
	data["Answers"] = rec.Answers
	data["CanReplay"] = s.Agents.Replay != nil && rec.Trace.Waiting == nil &&
		rec.State != agent.Running
	data["Provenance"] = agent.Provenance(rec.Receipt.Sources, rec.Receipt.Omitted)
	data["Error"] = r.URL.Query().Get("e")
	data["Tokens"] = rec.Trace.Spent.Tokens
	data["Metered"] = rec.Trace.Spent.Metered
	s.render(w, r, "agent_run.html", data)
}

// handleRunAct is what a person does to a kept run: answer the action it is
// waiting on, continue one that was cut off, or run it again from a step.
func (s *Server) handleRunAct(w http.ResponseWriter, r *http.Request,
	p principal, do string, back func(to, msg string, err error)) {

	id := r.FormValue("run")
	if !agent.ValidRecordID(id) {
		http.NotFound(w, r)
		return
	}
	page := "/agents/run/" + id
	step, err := strconv.Atoi(r.FormValue("step"))
	switch do {
	case "answer":
		if s.Agents.Answer == nil {
			http.NotFound(w, r)
			return
		}
		verdict := r.FormValue("verdict")
		if err != nil || (verdict != "approve" && verdict != "decline") {
			back(page, "", fmt.Errorf("say which step, and whether it may go ahead"))
			return
		}
		if aerr := s.Agents.Answer(id, step, verdict == "approve", p.Name); aerr != nil {
			back(page, "", aerr)
			return
		}
		if verdict == "approve" {
			back(page, fmt.Sprintf("Step %d went ahead, as it was shown.", step), nil)
		} else {
			back(page, fmt.Sprintf("Step %d was declined, and the agent was told.", step), nil)
		}
	case "resume":
		if s.Agents.Resume == nil {
			http.NotFound(w, r)
			return
		}
		back(page, "Continued from where it was cut off.",
			s.Agents.Resume(id, p.Name))
	case "replay":
		if s.Agents.Replay == nil {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			back(page, "", fmt.Errorf("say which step to run it again from"))
			return
		}
		newID, rerr := s.Agents.Replay(id, step, p.Name)
		if newID == "" {
			back(page, "", rerr)
			return
		}
		back("/agents/run/"+newID, fmt.Sprintf("Run again from after step %d "+
			"of the earlier run.", step), nil)
	}
}

// inputField is one value an agent wants to use, by name.
type inputField struct{ Name, Value string }

// readableInput lays out what an agent asked to do the way a person reads
// it, for the one decision that depends on reading it.
//
// As JSON, a page body is one string with its line breaks written as \n,
// and the person asked to approve it is reading escapes rather than the
// text. So a plain input is shown field by field — a write's page fields
// under the page they belong to — and the JSON stays beside it, exact.
// Anything nested deeper than that, or not text, a number or a yes or no,
// returns nil and the JSON is all there is: a view that left something out
// would be worse than one that is hard to read.
func readableInput(in map[string]any) []inputField {
	var out []inputField
	plain := func(prefix string, m map[string]any) bool {
		names := make([]string, 0, len(m))
		for k := range m {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			var v string
			switch t := m[k].(type) {
			case string:
				v = t
			case bool, float64, int:
				v = fmt.Sprint(t)
			default:
				return false
			}
			out = append(out, inputField{Name: prefix + k, Value: v})
		}
		return true
	}
	top := map[string]any{}
	var fields map[string]any
	for k, v := range in {
		if f, ok := v.(map[string]any); ok && k == "fields" {
			fields = f
			continue
		}
		top[k] = v
	}
	if !plain("", top) {
		return nil
	}
	if fields != nil && !plain("fields › ", fields) {
		return nil
	}
	return out
}
