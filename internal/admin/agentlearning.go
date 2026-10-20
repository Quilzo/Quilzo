// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/lessons"
)

// Learning: whether an agent is getting better, from its kept runs week by
// week, and what it learnt from its mistakes: the lessons written from runs
// that went wrong, how each did when tried against the evaluations, and
// which a person adopted, for which model.

var (
	reLessonID  = regexp.MustCompile(`^ls_[0-9a-f]{12}$`)
	reAgentName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

type learningWeek struct {
	Week                 string
	Runs, WentWrong      int
	WrongShare, MeanStep string
	Cost                 string
}

func (s *Server) handleAgentLearning(w http.ResponseWriter, r *http.Request) {
	p, ok := s.studioAllowed(w, r)
	if !ok {
		return
	}
	name := r.URL.Query().Get("agent")
	data := map[string]any{"Title": "What " + name + " is learning", "Principal": p, "Nav": "agents", "Agent": name,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"), "Kinds": lessons.Kinds}
	if name == "" && s.Agents != nil && s.Agents.Load != nil {
		// No agent named: which one.
		declared, _ := s.Agents.Load()
		var names []string
		for n := range declared {
			names = append(names, n)
		}
		sort.Strings(names)
		data["Title"], data["Choose"] = "What agents are learning", names
		s.render(w, r, "agent_learning.html", data)
		return
	}
	if s.Agents == nil || s.Agents.Runs == nil || s.Agents.Lessons == nil || !reAgentName.MatchString(name) {
		data["Unavailable"] = "Name an agent, in a build with the run store."
		s.render(w, r, "agent_learning.html", data)
		return
	}
	runs, err := s.Agents.Runs(name)
	if err != nil {
		data["Unavailable"] = "The runs could not be read: " + err.Error()
		s.render(w, r, "agent_learning.html", data)
		return
	}
	currency := s.agentCurrency()
	// Eight weeks, newest first.
	now := time.Now().UTC()
	start := now.AddDate(0, 0, -int(now.Weekday())).Truncate(24 * time.Hour)
	type acc struct {
		runs, wrong, steps int
		cost               int64
	}
	weeks := make([]acc, 8)
	for _, rec := range runs {
		if rec.Eval != "" || rec.Agent != name {
			continue
		}
		i := int(start.Sub(rec.Started.Truncate(24*time.Hour)).Hours()/(24*7)) + 1
		if rec.Started.After(start) || rec.Started.Equal(start) {
			i = 0
		}
		if i < 0 || i >= len(weeks) {
			continue
		}
		weeks[i].runs++
		weeks[i].steps += len(rec.Trace.Steps)
		weeks[i].cost += rec.Trace.Spent.Cost
		if lessons.WentWrong(rec.Trace) != "" {
			weeks[i].wrong++
		}
	}
	var rows []learningWeek
	for i, a := range weeks {
		row := learningWeek{Week: start.AddDate(0, 0, -7*i).Format("2 Jan"), Runs: a.runs, WentWrong: a.wrong}
		if a.runs > 0 {
			row.WrongShare = fmt.Sprintf("%.0f%%", 100*float64(a.wrong)/float64(a.runs))
			row.MeanStep = fmt.Sprintf("%.1f", float64(a.steps)/float64(a.runs))
			row.Cost = agent.MoneyText(a.cost/int64(a.runs), currency)
		}
		rows = append(rows, row)
	}
	all, err := s.Agents.Lessons(name)
	if err != nil {
		data["Error"] = err.Error()
	}
	sort.SliceStable(all, func(i, j int) bool {
		order := map[string]int{lessons.Adopted: 0, lessons.Candidate: 1, lessons.Retired: 2}
		if order[all[i].State] != order[all[j].State] {
			return order[all[i].State] < order[all[j].State]
		}
		return all[i].Created.After(all[j].Created)
	})
	// How many kept runs read each lesson, and how many of those went wrong.
	read, wrong := map[string]int{}, map[string]int{}
	for _, rec := range runs {
		for _, id := range rec.Trace.Lessons {
			read[id]++
			if lessons.WentWrong(rec.Trace) != "" {
				wrong[id]++
			}
		}
	}
	data["Weeks"], data["Lessons"], data["Read"], data["Wrong"] = rows, all, read, wrong
	s.render(w, r, "agent_learning.html", data)
}

// handleAgentLearningAct adopts or retires a lesson.
func (s *Server) handleAgentLearningAct(w http.ResponseWriter, r *http.Request) {
	p, ok := s.studioAllowed(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "post", http.StatusMethodNotAllowed)
		return
	}
	name, id := r.FormValue("agent"), r.FormValue("id")
	back := func(msg string, err error) {
		v := url.Values{"agent": {name}}
		if err != nil {
			v.Set("e", err.Error())
		} else {
			v.Set("m", msg)
		}
		http.Redirect(w, r, "/agents/learning?"+v.Encode(), http.StatusSeeOther)
	}
	if s.Agents == nil || s.Agents.AdoptLesson == nil || s.Agents.RetireLesson == nil {
		http.NotFound(w, r)
		return
	}
	if !reAgentName.MatchString(name) || !reLessonID.MatchString(id) {
		back("", errors.New("that is not an agent's lesson"))
		return
	}
	switch r.FormValue("do") {
	case "adopt":
		if err := s.Agents.AdoptLesson(name, id, r.FormValue("tainted_ok") == "yes", p.actor()); err != nil {
			back("", err)
			return
		}
		back("Adopted. Runs with that model now read it.", nil)
	case "retire":
		if err := s.Agents.RetireLesson(name, id, r.FormValue("why"), p.actor()); err != nil {
			back("", err)
			return
		}
		back("Retired. No run reads it.", nil)
	default:
		back("", errors.New("say what to do"))
	}
}
