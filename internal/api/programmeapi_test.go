// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/programme"
	"github.com/quilzo/quilzo/internal/register"
)

// withProgramme is a small programme in a test server's store: ISO
// 27001's starter, a scope, a control with a test that has run once and
// failed, and the population it ran over. It returns the run.
func withProgramme(t *testing.T, s *Server) register.ID {
	t.Helper()
	r := register.Open(s.Store)
	r.Audit = func(audit.Record) error { return nil }
	r.Now = func() time.Time { return time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC) }
	allow := func(auth.Action, string) error { return nil }
	olu := register.Actor{Name: "olu", Subject: "d0000000000000000000000000000001", Kind: audit.KindHuman, Verified: true, May: allow}
	p := &programme.Programme{Reg: r, Now: r.Now,
		Keep: &programme.FileKeeper{Dir: filepath.Join(s.Store.Root(), "programme")}}
	alone := programme.Decider{By: olu, Eligible: 1, MayApprove: true, Proof: "a test"}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err := p.Install(alone, "iso-27001")
	must(err)
	_, err = p.DecideScope(alone, register.Scope{Name: "group", Title: "The group", Domains: []register.Domain{"identity"}})
	must(err)
	entra := register.Source{Name: "entra", Type: "import", Fresh: 86400, Grade: register.GradeConnector}
	eid, _ := register.IDOf(entra)
	recs := []register.Record{entra, register.Control{Ref: "AC-01", Title: "Second factor for every account", Domain: "identity", Owner: olu.Subject}}
	for i, enrolled := range []bool{true, false} {
		who := register.ID(strings.Repeat("0", 31) + string(rune('1'+i)))
		recs = append(recs, register.Observation{Source: eid, About: who, Fact: "mfa.registered", Value: register.BoolValue(enrolled),
			Grade: register.GradeConnector})
	}
	_, err = r.Put(olu, "facts", recs...)
	must(err)
	fact := []register.Term{{Field: "fact", Op: register.OpEquals, Values: []register.Scalar{register.TextValue("mfa.registered")}}}
	_, _, err = p.Define(olu, programme.Definition{Name: "accounts", Source: "entra",
		Query: register.Query{Of: "Observation", Member: "about", Terms: fact}, Fresh: time.Hour})
	must(err)
	d, err := p.ProposeDraft(olu, programme.Draft{Control: "AC-01", Name: "mfa", Population: "accounts", Assertion: "all",
		Query: programme.DraftQuery{Of: "Observation", Member: "about", Terms: append(fact,
			register.Term{Field: "value", Op: register.OpEquals, Values: []register.Scalar{register.BoolValue(true)}})}})
	must(err)
	lee := olu
	lee.Name, lee.Subject = "lee", "1ee00000000000000000000000000002"
	_, err = p.Approve(programme.Decider{By: lee, Eligible: 2, MayApprove: true, Proof: "a test"}, d.TestID)
	must(err)
	_, rc, err := p.RunTest(programme.Scheduler(), d.TestID)
	must(err)
	for _, w := range rc.Written {
		if w.Kind == register.KindTestRun {
			return w.ID
		}
	}
	t.Fatal("the run wrote no run")
	return ""
}

func init() {
	for path, example := range map[string]string{
		"/api/v1/requirements":          "/api/v1/requirements?framework=iso-27001",
		"/api/v1/requirements/starters": "/api/v1/requirements/starters",
		"/api/v1/soa":                   "/api/v1/soa",
		"/api/v1/soa/{scope}":           "/api/v1/soa/group",
		"/api/v1/controls":              "/api/v1/controls",
		"/api/v1/controls/tests":        "/api/v1/controls/tests",
		"/api/v1/populations":           "/api/v1/populations",
		"/api/v1/populations/{name}":    "/api/v1/populations/accounts",
		"/api/v1/controls/runs/{id}":    "",
	} {
		moduleExamples[path] = func(t *testing.T, s *Server) (string, string) {
			run := withProgramme(t, s)
			if example == "" {
				return "/api/v1/controls/runs/" + string(run), officer(t, s)
			}
			return example, officer(t, s)
		}
	}
}

// The programme's routes read what the command line reads: the statement
// lists every requirement within the scope, undecided until somebody
// decides it; a control stands as its newest run left it; a run is
// explained by code and replays as recorded; a population is counted with
// its labels; and what is not there is 404.
func TestTheProgrammeRoutesReadTheProgramme(t *testing.T) {
	s, _, _ := setup(t)
	run := withProgramme(t, s)
	tok := officer(t, s)
	var st programme.Statement
	w := req(t, s, "GET", "/api/v1/soa/group", tok, nil, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil || len(st.Lines) != 93 || st.Undecided != 93 {
		t.Fatalf("the statement: %d %v, %d lines", w.Code, err, len(st.Lines))
	}
	var got struct {
		Explanation []string           `json:"explanation"`
		Replay      programme.Replayed `json:"replay"`
	}
	w = req(t, s, "GET", "/api/v1/controls/runs/"+string(run), tok, nil, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || len(got.Explanation) < 3 || !got.Replay.Same ||
		!strings.Contains(got.Explanation[2], "1 of 2 members were not selected") {
		t.Errorf("the run: %d %v %s", w.Code, err, w.Body)
	}
	w = req(t, s, "GET", "/api/v1/populations/accounts", tok, nil, nil)
	if !strings.Contains(w.Body.String(), `"said":"entra 2: single source, unchecked"`) {
		t.Errorf("the population: %d %s", w.Code, w.Body)
	}
	for _, path := range []string{"/api/v1/soa/nowhere", "/api/v1/controls/runs/00000000000000000000000000000000",
		"/api/v1/populations/nobody", "/api/v1/soa/", "/api/v1/controls/runs/", "/api/v1/populations/"} {
		if w := req(t, s, "GET", path, tok, nil, nil); w.Code != http.StatusNotFound {
			t.Errorf("GET %s answered %d", path, w.Code)
		}
	}
	if strings.Contains(strings.ToLower(req(t, s, "GET", "/api/v1/soa/group", tok, nil, nil).Body.String()), "compliant") {
		t.Error("the statement calls something compliant")
	}
}
