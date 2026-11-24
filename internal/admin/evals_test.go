// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"html"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/evals"
)

type evalFake struct {
	mu      sync.Mutex
	cases   map[string][]evals.Case
	started []string
	reports map[string][]evals.Report
}

func wireEvals(srv *Server) *evalFake {
	f := &evalFake{cases: map[string][]evals.Case{}, reports: map[string][]evals.Report{}}
	srv.Evals = &Evals{
		Cases: func(a string) ([]evals.Case, error) { f.mu.Lock(); defer f.mu.Unlock(); return f.cases[a], nil },
		Add: func(a string, c evals.Case, act Actor) (evals.Case, error) {
			by := act.Name
			if err := c.Validate(); err != nil {
				return c, err
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			c.ID, c.By = evals.NewID(), by
			f.cases[a] = append(f.cases[a], c)
			return c, nil
		},
		Remove: func(a, id string, _ Actor) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			for i, c := range f.cases[a] {
				if c.ID == id {
					f.cases[a] = append(f.cases[a][:i], f.cases[a][i+1:]...)
					return nil
				}
			}
			return fmt.Errorf("no case %s", id)
		},
		Start: func(a string, k int, model bool, act Actor) error {
			by := act.Name
			f.mu.Lock()
			defer f.mu.Unlock()
			f.started = append(f.started, fmt.Sprintf("%s k=%d model=%v by=%s", a, k, model, by))
			return nil
		},
		Running: func(string) (time.Time, bool) { return time.Time{}, false },
		Reports: func(a string, limit int) ([]evals.Report, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.reports[a], nil
		},
	}
	return f
}

func TestAKeptRunBecomesATestCase(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)
	f := wireEvals(srv)
	st.declared["answers"] = agent.Manifest{Name: "answers"}
	id, _ := srv.Agents.Run("answers", "find the refunds policy", false, Actor{Name: "editor"})

	page := get(t, srv, "/agents/run/"+id, token).Body.String()
	if !strings.Contains(page, "Keep as a test case") || !strings.Contains(page, `name="uses" value="search" checked`) ||
		!strings.Contains(page, `name="avoids" value="write_page" checked`) {
		t.Fatalf("the run page does not offer the run as a case, ticked:\n%s", firstLines(page, 5))
	}
	w := postForm(t, srv, "/agents/evals/act", token, url.Values{"do": {"keep"}, "run": {id},
		"goal": {"find the refunds policy"}, "uses": {"search"}, "avoids": {"write_page"}, "finishes": {"on"}}.Encode())
	if w.Code != 303 || !strings.Contains(w.Header().Get("Location"), "/agents/evals/answers?") || !strings.Contains(w.Header().Get("Location"), "m=") {
		t.Fatalf("%d %s", w.Code, w.Header().Get("Location"))
	}
	c := f.cases["answers"]
	if len(c) != 1 || c[0].From != id || !c[0].Expect.Finishes || c[0].Expect.Avoids[0] != "write_page" || c[0].By != "editor" {
		t.Fatalf("%+v", c)
	}
	// An evaluation's own run is not a case.
	rec := st.runs[id]
	rec.Eval = "eval-x"
	st.runs[id] = rec
	w = postForm(t, srv, "/agents/evals/act", token, url.Values{"do": {"keep"}, "run": {id}, "finishes": {"on"}}.Encode())
	if !strings.Contains(w.Header().Get("Location"), "e=") || len(f.cases["answers"]) != 1 {
		t.Error("an evaluation's run was kept as a case")
	}
	if strings.Contains(get(t, srv, "/agents/run/"+id, token).Body.String(), "Keep as a test case") {
		t.Error("an evaluation's run offers itself as a case")
	}
}

func TestAnEvaluationIsStartedRemovedAndShown(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)
	f := wireEvals(srv)
	st.declared["answers"] = agent.Manifest{Name: "answers"}
	act := func(v url.Values) string {
		return postForm(t, srv, "/agents/evals/act", token, v.Encode()).Header().Get("Location")
	}
	act(url.Values{"do": {"add"}, "agent": {"answers"}, "goal": {"Is there free delivery?"}, "answer_has": {"delivery | free"}})
	if c := f.cases["answers"]; len(c) != 1 || len(c[0].Expect.AnswerHas) != 2 {
		t.Fatalf("%+v", c)
	}
	if loc := act(url.Values{"do": {"add"}, "agent": {"answers"}, "goal": {"x"}}); !strings.Contains(loc, "e=") {
		t.Error("a case expecting nothing was added")
	}
	act(url.Values{"do": {"run"}, "agent": {"answers"}, "k": {"5"}, "model": {"on"}})
	act(url.Values{"do": {"run"}, "agent": {"answers"}, "k": {"999"}})
	if len(f.started) != 2 || f.started[0] != "answers k=5 model=true by=editor" || !strings.HasPrefix(f.started[1], "answers k=3 ") {
		t.Errorf("%v", f.started)
	}
	f.reports["answers"] = []evals.Report{{Agent: "answers", At: time.Now(), K: 3, Model: "m", Cases: 1, Planted: 1, Hijacked: 1,
		Results: []evals.CaseResult{{ID: "case-00000001", Goal: "Is there free delivery?", Hijacked: true,
			Runs:    []evals.RunResult{{Run: "run-20261004-00000001", Pass: true}},
			Planted: []evals.RunResult{{Run: "run-20261004-00000002", Hijacked: "repeated the planted code in its answer"}}}}}}
	page := get(t, srv, "/agents/evals/answers", token).Body.String()
	for _, want := range []string{"hijacked", "repeated the planted code", "/agents/run/run-20261004-00000002", "Is there free delivery?"} {
		if !strings.Contains(page, want) {
			t.Errorf("the report lacks %q", want)
		}
	}
	list := get(t, srv, "/agents/evals", token).Body.String()
	if !strings.Contains(list, `href="/agents/evals/answers"`) || !strings.Contains(list, "hijacked") {
		t.Error("the overview does not show the agent's last result")
	}
	id := f.cases["answers"][0].ID
	act(url.Values{"do": {"remove"}, "agent": {"answers"}, "case": {id}})
	if len(f.cases["answers"]) != 0 {
		t.Error("not removed")
	}
	if w := get(t, srv, "/agents/evals/nobody", token); w.Code != 404 {
		t.Errorf("an undeclared agent's page: %d", w.Code)
	}
}

// What an evaluation earned holds only on the model it measured. The
// screens said when an agent was last evaluated and not on which model,
// and nothing said an agent driven by another model since was due to be
// measured again, so it went on asking at propose with nobody told why.
// The list and the agent's page say what was measured and what is due,
// and Today counts the agents due, since nothing measures them again by
// itself.
func TestAnAgentDueToBeMeasuredAgainIsShown(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)
	f := wireEvals(srv)
	st.declared["answers"] = agent.Manifest{Name: "answers"}
	st.declared["tidy"] = agent.Manifest{Name: "tidy"}
	at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	f.reports["answers"] = []evals.Report{{Agent: "answers", At: at, K: 3, Model: "model-a", Route: "main", Cases: 3, Reliable: 3, Planted: 3}}
	due := "evaluated on model-a (route main); model-b (route main) is driving"
	srv.Evals.Due = func(a string) string {
		if a == "answers" {
			return due
		}
		return ""
	}
	list := get(t, srv, "/agents/evals", token).Body.String()
	for _, want := range []string{"on model-a (route main), 6 Oct 2026 12:00", "measure again", html.EscapeString(due)} {
		if !strings.Contains(list, want) {
			t.Errorf("the overview lacks %q", want)
		}
	}
	page := get(t, srv, "/agents/evals/answers", token).Body.String()
	for _, want := range []string{"measured on model-a (route main), 6 Oct 2026", "Measure it again: " + html.EscapeString(due)} {
		if !strings.Contains(page, want) {
			t.Errorf("the agent's page lacks %q", want)
		}
	}
	if tidy := get(t, srv, "/agents/evals/tidy", token).Body.String(); strings.Contains(tidy, "Measure it again") {
		t.Error("an agent with nothing due is told to measure again")
	}
	today := get(t, srv, "/today", token).Body.String()
	if !strings.Contains(today, `<dt>Agent to measure again: another model drives it now</dt><dd><a href="/agents/evals">1</a></dd>`) {
		t.Errorf("Today does not count the agent due:\n%s", firstLines(today[strings.Index(today, "happening"):], 12))
	}
}
