// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
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
