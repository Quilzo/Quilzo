// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/programme"
	"github.com/quilzo/quilzo/internal/register"
)

// withProgramme is a programme in the server's store: the ISO 27001 and
// NIS2 starters, a scope over both with one line decided, a control mapped
// to a requirement with a test that ran and failed, a population, and a
// starter's installation waiting for somebody. It returns the run.
func withProgramme(t *testing.T, srv *Server) register.ID {
	t.Helper()
	r := register.Open(srv.Store)
	r.Audit = func(audit.Record) error { return nil }
	r.Now = func() time.Time { return time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC) }
	allow := func(auth.Action, string) error { return nil }
	olu := register.Actor{Name: "olu", Subject: "d0000000000000000000000000000001", Kind: audit.KindHuman, Verified: true, May: allow}
	lee := register.Actor{Name: "lee", Subject: "1ee00000000000000000000000000002", Kind: audit.KindHuman, Verified: true, May: allow}
	p := &programme.Programme{Reg: r, Now: r.Now, Keep: &programme.FileKeeper{Dir: filepath.Join(srv.Store.Root(), "programme")}}
	alone := programme.Decider{By: olu, Eligible: 1, MayApprove: true, Proof: "a test"}
	two := programme.Decider{By: olu, Eligible: 2, MayApprove: true, Proof: "a test"}
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err := p.Install(alone, "iso-27001")
	check(err)
	_, err = p.Install(alone, "nis2")
	check(err)
	_, err = p.Install(two, "soc2") // waits for somebody else
	check(err)
	_, err = p.DecideScope(alone, register.Scope{Name: "group", Title: "The group", Domains: []register.Domain{"identity"},
		Frameworks: []string{"iso-27001", "nis2"}})
	check(err)
	_, err = p.DecideLine(alone, "group", "iso-27001", "A.7.4", false, "We hold no premises of our own.")
	check(err)
	entra := register.Source{Name: "entra", Title: "Entra ID", Type: "import", Fresh: 86400, Grade: register.GradeConnector}
	eid, _ := register.IDOf(entra)
	recs := []register.Record{entra, register.Control{Ref: "AC-01", Title: "Second factor for every account", Domain: "identity", Owner: olu.Subject}}
	for i, enrolled := range []bool{true, false} {
		who := register.ID(strings.Repeat("0", 31) + string(rune('1'+i)))
		recs = append(recs, register.Observation{Source: eid, About: who, Fact: "mfa.registered", Value: register.BoolValue(enrolled),
			Grade: register.GradeConnector})
	}
	_, err = r.Put(olu, "facts", recs...)
	check(err)
	_, _, err = p.MapControl(olu, "AC-01", "iso-27001", "A.8.5", "subset-of", "Second factors are one part of signing in securely.")
	check(err)
	fact := []register.Term{{Field: "fact", Op: register.OpEquals, Values: []register.Scalar{register.TextValue("mfa.registered")}}}
	pop, _, err := p.Define(olu, programme.Definition{Name: "accounts", Title: "Accounts", Source: "entra",
		Query: register.Query{Of: "Observation", Member: "about", Terms: fact}, Fresh: time.Hour})
	check(err)
	_, _, err = p.Recount(olu, pop)
	check(err)
	d, err := p.ProposeDraft(olu, programme.Draft{Control: "AC-01", Name: "mfa", Population: "accounts", Assertion: "all",
		Query: programme.DraftQuery{Of: "Observation", Member: "about", Terms: append(fact,
			register.Term{Field: "value", Op: register.OpEquals, Values: []register.Scalar{register.BoolValue(true)}})}})
	check(err)
	_, err = p.Approve(programme.Decider{By: lee, Eligible: 2, MayApprove: true, Proof: "a test"}, d.TestID)
	check(err)
	_, rc, err := p.RunTest(programme.Scheduler(), d.TestID)
	check(err)
	for _, w := range rc.Written {
		if w.Kind == register.KindTestRun {
			return w.ID
		}
	}
	t.Fatal("the run wrote no run")
	return ""
}

// The statement of applicability's screen lists both frameworks a scope
// answers to, each requirement in its framework's own order, decided or
// undecided, and the relations between them.
func TestSoAScreenListsBoth(t *testing.T) {
	srv, token := setup(t)
	withProgramme(t, srv)
	w := get(t, srv, "/programme/soa/group", token)
	if w.Code != http.StatusOK {
		t.Fatalf("/programme/soa/group answered %d\n%s", w.Code, firstLines(w.Body.String(), 40))
	}
	body := w.Body.String()
	for _, want := range []string{"<h1>The group</h1>", "<h2>ISO/IEC 27001 2022, Annex A</h2>",
		"<h2>NIS2 Directive (EU) 2022/2555, Article 21(2)</h2>",
		`<th scope="row">A.5.1</th>`, `<th scope="row">Art. 21(2)(a)</th>`, "Does not apply", "We hold no premises of our own.",
		"AC-01 (subset-of): failing at its newest run", "nis2 Art. 21(2)(b) is superset-of this", `<span class="kit-n">103</span>`} {
		if !strings.Contains(body, want) {
			t.Errorf("the statement's screen does not show %q", want)
		}
	}
	if strings.Index(body, `<th scope="row">A.5.1</th>`) > strings.Index(body, `<th scope="row">A.5.2</th>`) {
		t.Error("ISO's controls are not in Annex A's order")
	}
	if strings.Contains(strings.ToLower(body), "compliant") {
		t.Error("the statement calls something compliant")
	}
	csv := get(t, srv, "/programme/soa-csv/group", token)
	if csv.Code != http.StatusOK || !strings.HasPrefix(csv.Header().Get("Content-Type"), "text/csv") ||
		!strings.Contains(csv.Body.String(), "iso-27001,A.7.4,") {
		t.Errorf("the statement's CSV answered %d %s", csv.Code, firstLines(csv.Body.String(), 3))
	}
}

// Every programme screen is drawn from the security kit and passes the
// accessibility checks: with records in it, and empty.
func TestTheProgrammeScreensAreAccessible(t *testing.T) {
	srv, token := setup(t)
	run := withProgramme(t, srv)
	// A page has one h1, which the checker only advises; the kit's rule
	// is that it is one, so it is held here as a failure.
	check := func(what, body string) {
		t.Helper()
		if n := strings.Count(body, "<h1"); n != 1 {
			t.Errorf("%s puts %d h1 on the page; a page has one", what, n)
		}
		for _, f := range a11y.Check(what, body).Findings {
			if f.Severity == a11y.Blocking || f.Rule == "multiple-h1" || f.Rule == "no-h1" {
				t.Errorf("%s: %s (%s): %s", what, f.Rule, f.Criterion, f.Detail)
			}
		}
	}
	paths := []string{"/programme/requirements", "/programme/requirements?framework=iso-27001",
		"/programme/requirements?framework=dora", "/programme/soa", "/programme/soa/group", "/programme/controls",
		"/programme/controls/run/" + string(run), "/programme/populations"}
	for _, path := range paths {
		w := get(t, srv, path, token)
		if w.Code != http.StatusOK {
			t.Errorf("%s answered %d", path, w.Code)
			continue
		}
		check(path, w.Body.String())
	}
	empty, tok := setup(t)
	for _, path := range []string{"/programme/requirements", "/programme/soa", "/programme/controls", "/programme/populations"} {
		w := get(t, empty, path, tok)
		if w.Code != http.StatusOK {
			t.Errorf("an empty %s answered %d", path, w.Code)
			continue
		}
		check("an empty "+path, w.Body.String())
	}
	for _, path := range []string{"/programme/soa/nowhere", "/programme/controls/run/00000000000000000000000000000000",
		"/programme/requirements?framework=nonsense", "/programme/soa/", "/programme/soa-csv/", "/programme/soa-csv/nowhere",
		"/programme/controls/run/"} {
		if w := get(t, srv, path, token); w.Code != http.StatusNotFound {
			t.Errorf("%s answered %d", path, w.Code)
		}
	}
}

// What each screen says is what the programme holds: a run explained in
// code's words and replayed, a population with its labels, a control with
// the status its run left, and a decision that waits shown with its hash
// and no button.
func TestTheProgrammeScreensSayWhatTheProgrammeHolds(t *testing.T) {
	srv, token := setup(t)
	run := withProgramme(t, srv)
	page := get(t, srv, "/programme/controls/run/"+string(run), token).Body.String()
	for _, want := range []string{"The test asserts that every member of the population accounts (Accounts) is selected by the query.",
		"1 of 2 members were not selected", "Replays the same", "Circular: the facts the test read"} {
		if !strings.Contains(page, want) {
			t.Errorf("the run's screen does not say %q", want)
		}
	}
	controls := get(t, srv, "/programme/controls", token).Body.String()
	if !strings.Contains(controls, "Failing") || !strings.Contains(controls, `href="/programme/controls/run/`+string(run)+`"`) {
		t.Errorf("the control is not shown failing with its run:\n%s", firstLines(controls, 60))
	}
	pops := get(t, srv, "/programme/populations", token).Body.String()
	for _, want := range []string{"Single source, unchecked", "Circular", `<span class="kit-n">2</span>`, "Entra ID"} {
		if !strings.Contains(pops, want) {
			t.Errorf("the populations screen does not show %q", want)
		}
	}
	reqs := get(t, srv, "/programme/requirements", token).Body.String()
	soc2, _ := programme.StarterNamed("soc2")
	if !strings.Contains(reqs, "Waiting for a decision") || !strings.Contains(reqs, string(register.SurfaceOf(soc2.Decision(true)))) ||
		!strings.Contains(reqs, "can't be decided from this page") || !strings.Contains(reqs, "Take the soc2 starter into the programme") {
		t.Errorf("the waiting installation is not shown with its hash and without a button:\n%s", reqs[strings.Index(reqs, "<main"):])
	}
}
