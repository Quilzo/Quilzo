// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/evals"
)

// Evaluations: each agent's test set, kept from runs, and how it did when
// each case was run k times and again with instructions planted. See
// internal/evals for the measurement.

// Evals is evaluation as the admin reaches it.
type Evals struct {
	Cases  func(agent string) ([]evals.Case, error)
	Add    func(agent string, c evals.Case, by string) (evals.Case, error)
	Remove func(agent, id, by string) error
	// Start begins an evaluation and returns at once; it runs on in the
	// background and Running says so until it ends.
	Start   func(agent string, k int, model bool, by string) error
	Running func(agent string) (time.Time, bool)
	Reports func(agent string, limit int) ([]evals.Report, error)
}

type evalRow struct {
	Agent, Verdict, Tone, When string
	Cases, K, Reliable         int
	Planted, Hijacked          int
	PassK                      int
	Running                    bool
}

var verdictTone = map[string]string{"passing": "good", "unreliable": "warning",
	"hijacked": "critical", "empty": "unknown", "not evaluated": "unknown"}

func (s *Server) handleEvals(w http.ResponseWriter, r *http.Request) {
	p, ok := s.studioAllowed(w, r)
	if !ok {
		return
	}
	name := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/agents/evals"), "/")
	if name != "" {
		s.renderEval(w, r, p, name)
		return
	}
	data := map[string]any{"Title": "Evaluations", "Principal": p, "Nav": "agents"}
	if s.Evals == nil || s.Agents == nil || s.Agents.Load == nil {
		data["Unavailable"] = "This build was started without evaluations."
		s.render(w, r, "agent_evals.html", data)
		return
	}
	set, err := s.Agents.Load()
	if err != nil {
		data["Unavailable"] = "The agents could not be read: " + err.Error()
		s.render(w, r, "agent_evals.html", data)
		return
	}
	var rows []evalRow
	for name := range set {
		rows = append(rows, s.evalSummary(name))
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Agent < rows[j].Agent })
	data["Rows"] = rows
	s.render(w, r, "agent_evals.html", data)
}

func (s *Server) evalSummary(name string) evalRow {
	row := evalRow{Agent: name, Verdict: "not evaluated"}
	if cases, err := s.Evals.Cases(name); err == nil {
		row.Cases = len(cases)
	}
	if _, running := s.Evals.Running(name); running {
		row.Running = true
	}
	if reps, err := s.Evals.Reports(name, 1); err == nil && len(reps) > 0 {
		rep := reps[0]
		row.Verdict, row.K, row.Reliable = rep.Verdict(), rep.K, rep.Reliable
		row.Planted, row.Hijacked = rep.Planted, rep.Hijacked
		row.PassK = int(rep.PassK*100 + 0.5)
		row.When = rep.At.Format("2 Jan 2006 15:04")
	}
	row.Tone = verdictTone[row.Verdict]
	return row
}

type evalCaseRow struct {
	evals.Case
	Says string
}

type evalRunDot struct {
	Run, Word, Tone, Why string
}

type evalResultRow struct {
	ID, Goal          string
	Runs, Planted     []evalRunDot
	Reliable, Hijack  bool
	ReliableWord      string
	ReliableTone      string
}

func (s *Server) renderEval(w http.ResponseWriter, r *http.Request, p principal, name string) {
	if !agentName.MatchString(name) || s.Evals == nil || s.Agents == nil {
		http.NotFound(w, r)
		return
	}
	set, err := s.Agents.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, ok := set[name]; !ok {
		http.NotFound(w, r)
		return
	}
	data := map[string]any{"Title": "Evaluation of " + name, "Principal": p, "Nav": "agents",
		"Agent": name, "Blank": map[string]any{"Key": "new"}, "Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"Summary": s.evalSummary(name)}
	if since, running := s.Evals.Running(name); running {
		data["RunningSince"] = since.Format("15:04:05")
		// To the plain address, so the message that it started does not
		// outlive it.
		data["Refresh"] = "5;url=/agents/evals/" + name
	}
	cases, err := s.Evals.Cases(name)
	if err != nil {
		data["Unavailable"] = err.Error()
	}
	var crows []evalCaseRow
	for _, c := range cases {
		crows = append(crows, evalCaseRow{Case: c, Says: says(c.Expect)})
	}
	data["Cases"] = crows
	reps, _ := s.Evals.Reports(name, 20)
	if len(reps) > 0 {
		rep := reps[0]
		data["Latest"] = rep
		var rows []evalResultRow
		for _, c := range rep.Results {
			row := evalResultRow{ID: c.ID, Goal: c.Goal, Reliable: c.Reliable, Hijack: c.Hijacked}
			row.ReliableWord, row.ReliableTone = "every run passed", "good"
			if !c.Reliable {
				row.ReliableWord, row.ReliableTone = "not every run passed", "warning"
			}
			for _, rr := range c.Runs {
				d := evalRunDot{Run: rr.Run, Word: "passed", Tone: "good"}
				if !rr.Pass {
					d.Word, d.Tone, d.Why = "failed", "critical", strings.Join(rr.Why, "; ")+rr.Error
				}
				row.Runs = append(row.Runs, d)
			}
			for _, rr := range c.Planted {
				d := evalRunDot{Run: rr.Run, Word: "held", Tone: "good"}
				switch {
				case rr.Hijacked != "":
					d.Word, d.Tone, d.Why = "followed it", "critical", rr.Hijacked
				case rr.Error != "":
					d.Word, d.Tone, d.Why = "did not run", "warning", rr.Error
				}
				row.Planted = append(row.Planted, d)
			}
			rows = append(rows, row)
		}
		data["Results"] = rows
		data["History"] = reps
	}
	s.render(w, r, "agent_eval.html", data)
}

// says is an expectation in words, for a list.
func says(e evals.Expect) string {
	var parts []string
	if e.Finishes {
		parts = append(parts, "finishes")
	}
	if len(e.Uses) > 0 {
		parts = append(parts, "uses "+strings.Join(e.Uses, ", "))
	}
	if len(e.Avoids) > 0 {
		parts = append(parts, "never tries "+strings.Join(e.Avoids, ", "))
	}
	if e.AsksBefore != "" {
		parts = append(parts, "asks before "+e.AsksBefore)
	}
	for _, h := range e.AnswerHas {
		parts = append(parts, fmt.Sprintf("says “%s”", h))
	}
	if e.MaxSteps > 0 {
		parts = append(parts, fmt.Sprintf("in at most %d steps", e.MaxSteps))
	}
	if e.NoRefusals {
		parts = append(parts, "nothing refused")
	}
	return strings.Join(parts, "; ")
}

// expectFromForm reads the closed list from a form: checkboxes for the
// names a run used and tried, and fields for the rest.
func expectFromForm(r *http.Request) evals.Expect {
	e := evals.Expect{Finishes: r.FormValue("finishes") == "on", NoRefusals: r.FormValue("no_refusals") == "on",
		AsksBefore: strings.TrimSpace(r.FormValue("asks_before"))}
	e.Uses = append(e.Uses, r.Form["uses"]...)
	e.Avoids = append(e.Avoids, r.Form["avoids"]...)
	for _, part := range strings.Split(r.FormValue("answer_has"), "|") {
		if part = strings.TrimSpace(part); part != "" {
			e.AnswerHas = append(e.AnswerHas, part)
		}
	}
	if n, err := strconv.Atoi(strings.TrimSpace(r.FormValue("max_steps"))); err == nil {
		e.MaxSteps = n
	}
	return e
}

func (s *Server) handleEvalsAct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "use the form", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.studioAllowed(w, r)
	if !ok {
		return
	}
	if p.Limits.ReadOnly {
		http.Error(w, "this token is read-only", http.StatusForbidden)
		return
	}
	if s.Evals == nil || s.Agents == nil {
		http.Error(w, "this build has no evaluations", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := r.FormValue("agent")
	back := func(key, msg string) {
		target := "/agents/evals"
		if agentName.MatchString(name) {
			target += "/" + name
		}
		http.Redirect(w, r, target+"?"+url.Values{key: {msg}}.Encode(), http.StatusSeeOther)
	}
	switch r.FormValue("do") {
	case "keep":
		id := r.FormValue("run")
		if !agent.ValidRecordID(id) || s.Agents.RunGet == nil {
			http.NotFound(w, r)
			return
		}
		rec, err := s.Agents.RunGet(id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if rec.Eval != "" {
			back("e", "That run was made by an evaluation. Keep a run a person started.")
			return
		}
		name = rec.Agent
		c := evals.Case{Goal: strings.TrimSpace(r.FormValue("goal")), From: rec.ID, Expect: expectFromForm(r)}
		if c.Goal == "" {
			c.Goal = rec.Goal
		}
		c, err = s.Evals.Add(name, c, p.Name)
		if err != nil {
			back("e", err.Error())
			return
		}
		back("m", "Kept as "+c.ID+". It is run with the others on the next evaluation.")
	case "add":
		if !agentName.MatchString(name) {
			http.NotFound(w, r)
			return
		}
		c, err := s.Evals.Add(name, evals.Case{Goal: strings.TrimSpace(r.FormValue("goal")), Expect: expectFromForm(r)}, p.Name)
		if err != nil {
			back("e", err.Error())
			return
		}
		back("m", "Added "+c.ID+".")
	case "remove":
		id := r.FormValue("case")
		if !agentName.MatchString(name) || !evals.ValidID(id) {
			http.NotFound(w, r)
			return
		}
		if err := s.Evals.Remove(name, id, p.Name); err != nil {
			back("e", err.Error())
			return
		}
		back("m", id+" is removed.")
	case "run":
		if !agentName.MatchString(name) {
			http.NotFound(w, r)
			return
		}
		k, _ := strconv.Atoi(r.FormValue("k"))
		if k < 1 || k > evals.MaxK {
			k = 3
		}
		if err := s.Evals.Start(name, k, r.FormValue("model") == "on", p.Name); err != nil {
			back("e", err.Error())
			return
		}
		back("m", "The evaluation has started. This page shows it running, and the report when it ends.")
	default:
		http.NotFound(w, r)
	}
}

// keepData is what the run page's "keep as a test case" form starts from:
// what the run did, ticked.
func keepData(rec agent.Record) map[string]any {
	c := evals.FromRun(rec)
	return map[string]any{"Key": "keep", "Goal": c.Goal, "Run": rec.ID, "Agent": rec.Agent,
		"Finishes": c.Expect.Finishes, "Used": c.Expect.Uses, "Avoided": c.Expect.Avoids,
		"AsksBefore": c.Expect.AsksBefore, "NoRefusals": len(c.Expect.Avoids) == 0 && rec.Receipt.Refused == 0}
}
