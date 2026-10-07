// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/auth"
)

// studio is the agents screen wired to a stand-in that keeps declarations
// and runs in memory, validating as the real one does.
type studio struct {
	declared map[string]agent.Manifest
	runs     map[string]agent.Record
	asked    []string
}

func wireStudio(srv *Server) *studio {
	st := &studio{declared: map[string]agent.Manifest{},
		runs: map[string]agent.Record{}}
	known := []string{"write_page", "search", "read_page"}
	srv.Agents = &Agents{
		Load:  func() (map[string]agent.Manifest, error) { return st.declared, nil },
		Known: func() []string { return known },
		Save: func(m agent.Manifest, isNew bool, by string) error {
			set := map[string]bool{}
			for _, k := range known {
				set[k] = true
			}
			if err := m.Validate(set); err != nil {
				return err
			}
			st.declared[m.Name] = m
			return nil
		},
		Remove: func(name, by string) error {
			delete(st.declared, name)
			return nil
		},
		Run: func(name, goal string, model bool, by string) (string, error) {
			st.asked = append(st.asked, fmt.Sprintf("%s|%s|%v|%s", name, goal, model, by))
			id := fmt.Sprintf("run-20260930-%08x", len(st.runs)+1)
			tr := agent.Trace{Agent: name, Goal: goal, Complete: true,
				Steps: []agent.Step{
					{N: 1, Action: agent.Action{Op: "search",
						Input: map[string]any{"q": "refunds"}}, Allowed: true,
						Result: `<script>alert(1)</script> three pages`},
					{N: 2, Action: agent.Action{Op: "write_page"},
						Why: "write_page is not in this agent's declaration"},
				}}
			st.runs[id] = agent.Keep(id, by, "", time.Now(), tr,
				agent.Receipt{Agent: name, Kind: agent.KindRetrieval, Did: 1, Refused: 1})
			return id, nil
		},
		Runs: func(name string) ([]agent.Record, error) {
			var out []agent.Record
			for _, r := range st.runs {
				if name == "" || r.Agent == name {
					out = append(out, r)
				}
			}
			return out, nil
		},
		RunGet: func(id string) (agent.Record, error) {
			r, ok := st.runs[id]
			if !ok {
				return r, fmt.Errorf("no such run")
			}
			return r, nil
		},
	}
	return st
}

func studioAct(t *testing.T, srv *Server, token string, v url.Values) (int, string) {
	t.Helper()
	w := postForm(t, srv, "/agents/act", token, v.Encode())
	return w.Code, w.Header().Get("Location")
}

func declareForm(name string) url.Values {
	return url.Values{"do": {"save"}, "new": {"1"}, "kind": {"retrieval"},
		"name": {name}, "purpose": {"Answer questions from the published docs"},
		"autonomy": {"propose"}, "cap": {"search", "read_page"},
		"steps": {"8"}, "tool_calls": {"4"}, "duration": {"2m"}}
}

func TestAnAgentIsDeclaredOnTheScreenAndTheMapIsDrawnFromIt(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)

	body := get(t, srv, "/agents/new?kind=retrieval", token).Body.String()
	whole(t, body)
	for _, want := range []string{"Declare an agent", `name="cap" value="search"`,
		`name="cap" value="write_page"`, "writes", `class="agmap"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the new-agent page is missing %q", want)
		}
	}

	code, loc := studioAct(t, srv, token, declareForm("answers"))
	if code != http.StatusSeeOther || !strings.HasPrefix(loc, "/agents/edit/answers?") ||
		!strings.Contains(loc, "m=Saved") {
		t.Fatalf("declaring answered %d to %s", code, loc)
	}
	m, ok := st.declared["answers"]
	if !ok {
		t.Fatal("nothing was declared")
	}
	if m.Kind != agent.KindRetrieval || m.Budget.Steps != 8 ||
		strings.Join(m.Capabilities, " ") != "read_page search" {
		t.Errorf("what was declared is not what the form said: %+v", m)
	}

	body = get(t, srv, "/agents/edit/answers", token).Body.String()
	whole(t, body)
	svg := body[strings.Index(body, "<svg class=\"agmap\""):]
	svg = svg[:strings.Index(svg, "</svg>")]
	for _, want := range []string{">search<", ">read_page<", ">answers<"} {
		if !strings.Contains(svg, want) {
			t.Errorf("the map does not show %q", want)
		}
	}
	// A capability it does not hold is on the form to tick and not on the
	// map: the map is what the declaration says, nothing more.
	if strings.Contains(svg, "write_page") {
		t.Error("the map shows a capability the agent does not hold")
	}

	// Granting a write changes the map, and marks it.
	f := declareForm("answers")
	f.Del("new")
	f.Set("autonomy", "draft")
	f["cap"] = []string{"search", "write_page"}
	if code, loc = studioAct(t, srv, token, f); code != http.StatusSeeOther ||
		!strings.Contains(loc, "m=") {
		t.Fatalf("saving answered %d to %s", code, loc)
	}
	body = get(t, srv, "/agents/edit/answers", token).Body.String()
	svg = body[strings.Index(body, "<svg class=\"agmap\""):]
	svg = svg[:strings.Index(svg, "</svg>")]
	if !strings.Contains(svg, "write_page") || !strings.Contains(svg, "write") ||
		strings.Contains(svg, ">read_page<") {
		t.Errorf("the map did not follow the declaration:\n%s", svg)
	}
}

func TestADeclarationThatWouldBeRefusedIsNotStored(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)

	// Propose-only, holding a write: the manifest's own rule refuses it.
	f := declareForm("answers")
	f["cap"] = []string{"search", "write_page"}
	code, loc := studioAct(t, srv, token, f)
	if code != http.StatusSeeOther || !strings.HasPrefix(loc, "/agents/new?e=") ||
		!strings.Contains(loc, "kind=retrieval") {
		t.Fatalf("an unenforceable declaration answered %d to %s", code, loc)
	}
	if len(st.declared) != 0 {
		t.Fatal("it was stored anyway")
	}
	for _, bad := range []string{"Bad Name", "../etc", "", "a/b"} {
		f := declareForm(bad)
		studioAct(t, srv, token, f)
		if len(st.declared) != 0 {
			t.Fatalf("an agent called %q was declared", bad)
		}
	}
	// A budget that is not a number is said so, not stored as zero.
	f = declareForm("answers")
	f.Set("steps", "many")
	if _, loc = studioAct(t, srv, token, f); !strings.Contains(loc, "e=") ||
		len(st.declared) != 0 {
		t.Errorf("a budget of 'many' steps went to %s", loc)
	}
	// Declaring over an existing name is refused rather than replacing it.
	studioAct(t, srv, token, declareForm("answers"))
	f = declareForm("answers")
	f.Set("purpose", "Something else entirely")
	if _, loc = studioAct(t, srv, token, f); !strings.Contains(loc, "e=") ||
		st.declared["answers"].Purpose == "Something else entirely" {
		t.Errorf("a second declaration replaced the first (%s)", loc)
	}
}

func TestTheDeclarationAsTextIsTheSameDocument(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)
	studioAct(t, srv, token, declareForm("answers"))

	text := func(def string) string {
		_, loc := studioAct(t, srv, token, url.Values{"do": {"define"},
			"name": {"answers"}, "definition": {def}})
		return loc
	}
	good := `{"name":"answers","kind":"retrieval","purpose":"Answer from the docs, briefly",
	 "autonomy":"propose","capabilities":["search"],
	 "budget":{"steps":3,"tool_calls":2,"duration":"1m"}}`
	if loc := text(good); !strings.Contains(loc, "m=") {
		t.Fatalf("a valid declaration as text went to %s", loc)
	}
	if st.declared["answers"].Budget.Steps != 3 {
		t.Error("the text was not what got stored")
	}
	for name, def := range map[string]string{
		"another name":     strings.Replace(good, `"answers"`, `"other"`, 1),
		"an unknown field": strings.Replace(good, `"kind"`, `"root":true,"kind"`, 1),
		"not a document":   "rm -rf /",
		"a capability nothing offers": strings.Replace(good, `["search"]`,
			`["search","shell.exec"]`, 1),
	} {
		if loc := text(def); !strings.Contains(loc, "e=") {
			t.Errorf("%s was accepted (%s)", name, loc)
		}
		if st.declared["answers"].Budget.Steps != 3 ||
			len(st.declared["answers"].Capabilities) != 1 || len(st.declared) != 1 {
			t.Fatalf("%s changed what is declared", name)
		}
	}
}

func TestARunFromTheScreenIsKeptAndReadStepByStep(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)
	studioAct(t, srv, token, declareForm("answers"))

	code, loc := studioAct(t, srv, token, url.Values{"do": {"run"},
		"name": {"answers"}, "goal": {"find <b>refunds</b>"}})
	if code != http.StatusSeeOther || loc != "/agents/run/run-20260930-00000001" {
		t.Fatalf("running answered %d to %s", code, loc)
	}
	// Who is signed in is who ran it; the form cannot say otherwise.
	if len(st.asked) != 1 || st.asked[0] != "answers|find <b>refunds</b>|false|editor" {
		t.Fatalf("the run was asked for as %v", st.asked)
	}
	body := get(t, srv, loc, token).Body.String()
	whole(t, body)
	for _, want := range []string{"search", "refused",
		"write_page is not in this agent", "three pages", "editor"} {
		if !strings.Contains(body, want) {
			t.Errorf("the run page is missing %q", want)
		}
	}
	// What a step returned came from content, and is shown as text.
	for _, bad := range []string{"<script>alert(1)", "<b>refunds</b>"} {
		if strings.Contains(body, bad) {
			t.Errorf("the run page carries %q unescaped", bad)
		}
	}
	list := get(t, srv, "/agents/runs?agent=answers", token).Body.String()
	whole(t, list)
	if !strings.Contains(list, "/agents/run/run-20260930-00000001") {
		t.Error("the run is not in the list")
	}
	if other := get(t, srv, "/agents/runs?agent=nobody", token).Body.String(); strings.Contains(other, "/agents/run/run-") {
		t.Error("another agent's list shows this run")
	}

	// A run id is a file name on the other side of the hook.
	for _, bad := range []string{"..%2f..%2fagents.json", "run-20260930-0000000g",
		"run-20260930-00000001x", "run-20260930-99999999"} {
		if w := get(t, srv, "/agents/run/"+bad, token); w.Code != http.StatusNotFound {
			t.Errorf("/agents/run/%s answered %d", bad, w.Code)
		}
	}
	// An agent that is not declared cannot be run by naming it.
	if code, _ = studioAct(t, srv, token, url.Values{"do": {"run"},
		"name": {"ghost"}}); code != http.StatusNotFound || len(st.asked) != 1 {
		t.Errorf("running an undeclared agent answered %d", code)
	}
}

func TestWithdrawingAnAgentKeepsItsRuns(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)
	studioAct(t, srv, token, declareForm("answers"))
	_, run := studioAct(t, srv, token, url.Values{"do": {"run"}, "name": {"answers"}})

	code, loc := studioAct(t, srv, token, url.Values{"do": {"remove"}, "name": {"answers"}})
	if code != http.StatusSeeOther || !strings.HasPrefix(loc, "/agents?") ||
		!strings.Contains(loc, "m=answers") {
		t.Fatalf("withdrawing answered %d to %s", code, loc)
	}
	if _, still := st.declared["answers"]; still {
		t.Fatal("it is still declared")
	}
	if w := get(t, srv, "/agents/edit/answers", token); w.Code != http.StatusNotFound {
		t.Errorf("the withdrawn agent's page answered %d", w.Code)
	}
	if w := get(t, srv, run, token); w.Code != http.StatusOK {
		t.Errorf("its run answered %d after it was withdrawn", w.Code)
	}
}

// Declaring an agent is writing a permission. Only whoever may grant one
// does it, reads the runs, or starts one.
func TestTheStudioIsForWhoeverMayGrant(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)
	studioAct(t, srv, token, declareForm("answers"))
	_, run := studioAct(t, srv, token, url.Values{"do": {"run"}, "name": {"answers"}})

	if err := srv.Policy.Grant(auth.Binding{Principal: "writer",
		Role: auth.RolePublisher, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	lesser, _, err := srv.Tokens.Issue("w", "writer", auth.RolePublisher, "/",
		time.Hour, auth.RolePublisher)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/agents/new?kind=retrieval",
		"/agents/edit/answers", "/agents/runs", run} {
		w := get(t, srv, path, lesser)
		if w.Code == http.StatusOK || strings.Contains(w.Body.String(), "agmap") ||
			strings.Contains(w.Body.String(), "three pages") {
			t.Errorf("%s answered %d to a publisher", path, w.Code)
		}
	}
	before := len(st.asked)
	for _, f := range []url.Values{declareForm("mine"),
		{"do": {"run"}, "name": {"answers"}},
		{"do": {"remove"}, "name": {"answers"}}} {
		if code, _ := studioAct(t, srv, lesser, f); code == http.StatusSeeOther {
			t.Errorf("a publisher's %s was carried out", f.Get("do"))
		}
	}
	if _, ok := st.declared["mine"]; ok || len(st.asked) != before ||
		len(st.declared) != 1 {
		t.Error("a publisher changed or ran an agent")
	}
	// And a request from another site is not the person's own.
	req := httptest.NewRequest(http.MethodPost, "/agents/act", strings.NewReader(
		url.Values{"do": {"remove"}, "name": {"answers"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code == http.StatusSeeOther || len(st.declared) != 1 {
		t.Errorf("a cross-site withdraw answered %d", w.Code)
	}
}

// wireDurable adds a run that is waiting on a write, and the three things
// a person can do to a kept run.
func wireDurable(srv *Server, st *studio) *[]string {
	calls := &[]string{}
	tr := agent.Trace{Agent: "answers", Goal: "tidy the about page",
		Tainted: true, Stopped: "waiting for a person to decide on write_page",
		Steps: []agent.Step{{N: 1, Action: agent.Action{Op: "read_page"},
			Allowed: true, Result: "the about page"}},
		Waiting: &agent.Pending{N: 2, Since: time.Now().Add(-time.Minute),
			Action: agent.Action{Op: "write_page", Input: map[string]any{
				"page": "about", "body": "<img src=x onerror=alert(1)>"}}}}
	st.runs["run-20260930-000000aa"] = agent.Keep("run-20260930-000000aa",
		"editor", "a-model", time.Now(), tr, agent.Receipt{Did: 1})
	cut := agent.Keep("run-20260930-000000bb", "editor", "", time.Now(),
		agent.Trace{Agent: "answers", Goal: "g", Steps: tr.Steps}, agent.Receipt{Did: 1})
	cut.State, cut.Beat = agent.Running, time.Now().Add(-time.Hour)
	st.runs[cut.ID] = cut

	srv.Agents.Answer = func(id string, step int, approve bool, by string) error {
		*calls = append(*calls, fmt.Sprintf("answer %s %d %v %s", id, step, approve, by))
		r := st.runs[id]
		if r.Trace.Waiting == nil || r.Trace.Waiting.N != step {
			return fmt.Errorf("the run is not waiting at step %d", step)
		}
		r.Trace.Waiting, r.Trace.Stopped, r.Trace.Complete = nil, "", true
		r.Answers = append(r.Answers, agent.Answer{N: step, Approve: approve, By: by})
		st.runs[id] = r
		return nil
	}
	srv.Agents.Resume = func(id, by string) error {
		*calls = append(*calls, "resume "+id+" "+by)
		return nil
	}
	srv.Agents.Replay = func(id string, step int, by string) (string, error) {
		*calls = append(*calls, fmt.Sprintf("replay %s %d %s", id, step, by))
		r := st.runs[id]
		r.ID, r.From = "run-20260930-000000cc", fmt.Sprintf("%s@%d", id, step)
		st.runs[r.ID] = r
		return r.ID, nil
	}
	return calls
}

func TestAWaitingRunShowsTheExactCallAndTakesOneAnswer(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)
	calls := wireDurable(srv, st)
	const id = "run-20260930-000000aa"

	body := get(t, srv, "/agents/run/"+id, token).Body.String()
	whole(t, body)
	for _, want := range []string{"It is asking before step 2", "write_page",
		"&#34;page&#34;: &#34;about&#34;", "Let it go ahead", "Decline",
		"as if a stranger had asked", "waiting"} {
		if !strings.Contains(body, want) {
			t.Errorf("the waiting run's page is missing %q", want)
		}
	}
	if strings.Contains(body, "<img src=x") {
		t.Error("what the agent wants to write is on the page as markup")
	}
	// Nothing to run again from while a question is open.
	if strings.Contains(body, "Run again from here") {
		t.Error("a waiting run offers to be run again")
	}
	if list := get(t, srv, "/agents/runs", token).Body.String(); !strings.Contains(list, "waiting") {
		t.Error("the list does not say it is waiting")
	}

	answer := func(v url.Values) (int, string) {
		v.Set("do", "answer")
		return studioAct(t, srv, token, v)
	}
	// An answer has to say which step and which way.
	for _, bad := range []url.Values{
		{"run": {id}, "verdict": {"approve"}},
		{"run": {id}, "step": {"2"}},
		{"run": {id}, "step": {"2"}, "verdict": {"yes"}},
		{"run": {id}, "step": {"two"}, "verdict": {"approve"}},
	} {
		if _, loc := answer(bad); !strings.Contains(loc, "e=") || len(*calls) != 0 {
			t.Fatalf("%v went to %s with %v", bad, loc, *calls)
		}
	}
	if code, _ := answer(url.Values{"run": {"../../agents"}, "step": {"2"},
		"verdict": {"approve"}}); code != http.StatusNotFound || len(*calls) != 0 {
		t.Errorf("a run that is not one answered %d", code)
	}
	// For a step it is not waiting at: what the hook says is shown.
	if _, loc := answer(url.Values{"run": {id}, "step": {"1"},
		"verdict": {"approve"}}); !strings.Contains(loc, "e=") {
		t.Errorf("an answer to another step went to %s", loc)
	}
	*calls = nil

	code, loc := answer(url.Values{"run": {id}, "step": {"2"}, "verdict": {"approve"},
		// Who answers is who is signed in.
		"by": {"somebody-else"}})
	if code != http.StatusSeeOther || !strings.Contains(loc, "m=Step+2+went+ahead") {
		t.Fatalf("approving answered %d to %s", code, loc)
	}
	if len(*calls) != 1 || (*calls)[0] != "answer "+id+" 2 true editor" {
		t.Fatalf("the answer arrived as %v", *calls)
	}
	body = get(t, srv, "/agents/run/"+id, token).Body.String()
	whole(t, body)
	if strings.Contains(body, "Let it go ahead") ||
		!strings.Contains(body, "Step 2 was let go ahead by editor") {
		t.Error("the answered run still asks, or does not say who answered")
	}
}

func TestDecliningFromTheScreen(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)
	calls := wireDurable(srv, st)
	const id = "run-20260930-000000aa"
	_, loc := studioAct(t, srv, token, url.Values{"do": {"answer"}, "run": {id},
		"step": {"2"}, "verdict": {"decline"}})
	if !strings.Contains(loc, "m=Step+2+was+declined") ||
		(*calls)[0] != "answer "+id+" 2 false editor" {
		t.Fatalf("declining went to %s as %v", loc, *calls)
	}
}

func TestAQuestionAskedTooLongAgoCannotBeAgreedToOnTheScreen(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)
	wireDurable(srv, st)
	const id = "run-20260930-000000aa"
	r := st.runs[id]
	r.Trace.Waiting.Since = time.Now().Add(-agent.PendingTTL - time.Hour)
	st.runs[id] = r
	body := get(t, srv, "/agents/run/"+id, token).Body.String()
	whole(t, body)
	if strings.Contains(body, "Let it go ahead") || !strings.Contains(body, "Decline") ||
		!strings.Contains(body, "too long ago") {
		t.Error("an expired question still offers to go ahead")
	}
}

func TestAnInterruptedRunIsContinuedAndAFinishedOneRunAgainFromAStep(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)
	calls := wireDurable(srv, st)
	const cut = "run-20260930-000000bb"

	body := get(t, srv, "/agents/run/"+cut, token).Body.String()
	whole(t, body)
	if !strings.Contains(body, "It was cut off") || !strings.Contains(body, "interrupted") {
		t.Fatal("a run whose process stopped does not say so")
	}
	if _, loc := studioAct(t, srv, token, url.Values{"do": {"resume"},
		"run": {cut}}); !strings.Contains(loc, "m=Continued") ||
		(*calls)[0] != "resume "+cut+" editor" {
		t.Fatalf("continuing went to %s as %v", loc, *calls)
	}

	// A run still being worked on is not one to run again from.
	live := st.runs[cut]
	live.Beat = time.Now()
	st.runs[cut] = live
	body = get(t, srv, "/agents/run/"+cut, token).Body.String()
	if strings.Contains(body, "It was cut off") || strings.Contains(body, "Run again from here") ||
		!strings.Contains(body, "running") {
		t.Error("a run in progress is shown as cut off, or as one to run again")
	}

	done := st.runs[cut]
	done.State, done.Trace.Complete = "", true
	st.runs[cut] = done
	body = get(t, srv, "/agents/run/"+cut, token).Body.String()
	whole(t, body)
	if !strings.Contains(body, "Run again from here") {
		t.Fatal("a finished run does not offer to be run again from a step")
	}
	code, loc := studioAct(t, srv, token, url.Values{"do": {"replay"},
		"run": {cut}, "step": {"1"}})
	if code != http.StatusSeeOther || !strings.HasPrefix(loc, "/agents/run/run-20260930-000000cc?") {
		t.Fatalf("running again answered %d to %s", code, loc)
	}
	body = get(t, srv, "/agents/run/run-20260930-000000cc", token).Body.String()
	if !strings.Contains(body, cut+"@1") {
		t.Error("the new run does not say where it was run again from")
	}
	if _, loc = studioAct(t, srv, token, url.Values{"do": {"replay"},
		"run": {cut}}); !strings.Contains(loc, "e=") {
		t.Errorf("running again with no step went to %s", loc)
	}
}

func TestAskingFirstIsSetOnTheFormAndDrawnOnTheMap(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)
	f := declareForm("answers")
	f.Set("autonomy", "draft")
	f["cap"] = []string{"search", "write_page"}
	// Ticked for something not granted as well: dropped, not stored.
	f["ask"] = []string{"write_page", "read_page"}
	if _, loc := studioAct(t, srv, token, f); !strings.Contains(loc, "m=") {
		t.Fatalf("declaring went to %s", loc)
	}
	if got := strings.Join(st.declared["answers"].AskFirst, ","); got != "write_page" {
		t.Fatalf("it asks first about %q", got)
	}
	body := get(t, srv, "/agents/edit/answers", token).Body.String()
	whole(t, body)
	if !strings.Contains(body, `name="ask" value="write_page" checked`) ||
		strings.Contains(body, `name="ask" value="search" checked`) {
		t.Error("the form does not show what it asks first about")
	}
	svg := body[strings.Index(body, "<svg class=\"agmap\""):]
	svg = svg[:strings.Index(svg, "</svg>")]
	if !strings.Contains(svg, "asks a person first") ||
		!strings.Contains(body, "stops and asks a person before 1 of them; the rest goes ahead without one") {
		t.Error("the map does not show that it asks first")
	}
}

// Answering is approving what a model wants to do. Only whoever may grant
// does, and not from another site.
func TestOnlyAnAdministratorAnswersARun(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)
	calls := wireDurable(srv, st)
	if err := srv.Policy.Grant(auth.Binding{Principal: "writer",
		Role: auth.RolePublisher, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	lesser, _, err := srv.Tokens.Issue("w", "writer", auth.RolePublisher, "/",
		time.Hour, auth.RolePublisher)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []url.Values{
		{"do": {"answer"}, "run": {"run-20260930-000000aa"}, "step": {"2"}, "verdict": {"approve"}},
		{"do": {"resume"}, "run": {"run-20260930-000000bb"}},
		{"do": {"replay"}, "run": {"run-20260930-000000bb"}, "step": {"1"}},
	} {
		if code, _ := studioAct(t, srv, lesser, f); code == http.StatusSeeOther {
			t.Errorf("a publisher's %s was carried out", f.Get("do"))
		}
		req := httptest.NewRequest(http.MethodPost, "/agents/act",
			strings.NewReader(f.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		if w.Code == http.StatusSeeOther {
			t.Errorf("a cross-site %s was carried out", f.Get("do"))
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("something was done: %v", *calls)
	}
}

// What a person approves is shown as text they can read, and exactly.
func TestAWaitingWriteIsShownFieldByField(t *testing.T) {
	got := readableInput(map[string]any{"page": "changelog",
		"fields": map[string]any{"title": "Changelog", "body": "One.\n\nTwo.", "draft": true}})
	want := []inputField{{"page", "changelog"}, {"fields › body", "One.\n\nTwo."},
		{"fields › draft", "true"}, {"fields › title", "Changelog"}}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("field %d is %v, want %v", i, got[i], want[i])
		}
	}
	// Anything it cannot show whole, it does not show at all: the JSON is
	// then the only view, rather than a tidy one with a part missing.
	for _, in := range []map[string]any{
		{"page": "x", "fields": map[string]any{"list": []any{"a"}}},
		{"page": map[string]any{"nested": "x"}},
	} {
		if f := readableInput(in); f != nil {
			t.Errorf("%v was laid out as %v", in, f)
		}
	}
}

// Described rather than ticked: the draft and the checker's answers are
// shown, the form holds the draft, and nothing is saved.
func TestADescribedAgentIsShownWithWhatItCouldDoAndNotSaved(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)
	if body := get(t, srv, "/agents/new", token).Body.String(); strings.Contains(body, `name="describe"`) {
		t.Fatal("a describe box with nothing to draft")
	}
	var asked string
	srv.Agents.Draft = func(desc, by string) (AgentDraft, error) {
		asked = desc + "|" + by
		return AgentDraft{
			Manifest: agent.Manifest{Name: "faq-helper", Kind: agent.KindTask, Purpose: "keep the FAQ tidy",
				Capabilities: []string{"read_page", "write_page"}, Autonomy: agent.AutonomyDraft,
				Budget: agent.Budget{Steps: 8, Tools: 4, Duration: agent.Duration(2 * time.Minute)}},
			Notes:   []string{"publish: a draft never publishes on its own"},
			Bounded: []string{"evaluations: never evaluated"},
			Would: []AgentWould{{What: "read_page", Could: true},
				{What: "write_page", Why: "write_page is not in this agent's capabilities"}},
		}, nil
	}
	if body := get(t, srv, "/agents/new", token).Body.String(); !strings.Contains(body, `name="describe"`) {
		t.Fatal("no describe box")
	}
	w := postForm(t, srv, "/agents/new", token, url.Values{"describe": {"Keep our FAQ tidy"}}.Encode())
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.HasPrefix(asked, "Keep our FAQ tidy|") {
		t.Fatalf("%d asked %q", w.Code, asked)
	}
	for _, want := range []string{`value="faq-helper"`, "keep the FAQ tidy", "evaluations: never evaluated",
		"publish: a draft never publishes", `<code>write_page</code>`, "Nothing is saved until you read it"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if len(st.declared) != 0 {
		t.Fatal("drafting saved it")
	}
	srv.Agents.Draft = func(string, string) (AgentDraft, error) { return AgentDraft{}, errors.New("no model is configured") }
	if body := postForm(t, srv, "/agents/new", token, url.Values{"describe": {"x"}}.Encode()).Body.String(); !strings.Contains(body, "no model is configured") {
		t.Fatal("a drafting error is not shown")
	}
}
