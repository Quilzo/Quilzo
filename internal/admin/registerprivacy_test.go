// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/csv"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/sheet"
)

// accessible fails the test for every blocking finding of the checker on
// a page.
func accessible(t *testing.T, path, body string) {
	t.Helper()
	for _, f := range a11y.Check(path, body).Findings {
		if f.Severity == a11y.Blocking {
			t.Errorf("%s: %s (%s): %s", path, f.Rule, f.Criterion, f.Detail)
		}
	}
}

// writerOn is the register of a server's store with an audit log kept in
// the test, and a person allowed everything.
func writerOn(t *testing.T, srv *Server) (*register.Register, register.Actor) {
	t.Helper()
	r := register.Open(srv.Store)
	r.Audit = func(audit.Record) error { return nil }
	allow := func(auth.Action, string) error { return nil }
	return r, register.Actor{Name: "editor", Subject: "d0000000000000000000000000000001", Kind: audit.KindHuman, May: allow}
}

// PLAN theme 28: a kind's screen filters by a field's value with a form
// whose controls have labels, keeps the filter across pages, and offers
// the kind as CSV, every cell safe for a spreadsheet; the risks offer the
// top risks by rating. A filter on a field the kind lacks is said beside
// the field and at the top.
func TestTheKindScreenFiltersAndExports(t *testing.T) {
	srv, token := setup(t)
	withRecords(t, srv)
	r, by := writerOn(t, srv)
	owner := register.ID("0123456789abcdef0123456789abcdef")
	if _, err := r.Put(by, "a formula",
		register.Control{Ref: "AC-04", Title: "=HYPERLINK(\"https://attacker.example\",\"x\")", Domain: "endpoints", Owner: owner}); err != nil {
		t.Fatal(err)
	}
	for i, li := range []int64{2, 5, 4} {
		if _, err := r.Put(by, "a risk", register.Risk{Ref: "R-" + string(rune('1'+i)), Title: "A risk", Owner: owner,
			Raised: owner, Likelihood: li, Impact: 4, Status: "open"}); err != nil {
			t.Fatal(err)
		}
	}

	path := "/register/kind/control?filter=" + url.QueryEscape("domain=endpoints")
	w := get(t, srv, path, token)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "AC-02 ·") || !strings.Contains(body, "AC-04 ·") ||
		strings.Contains(body, "AC-01 ·") {
		t.Fatalf("the filtered controls answered %d\n%s", w.Code, firstLines(body, 60))
	}
	for _, want := range []string{`<label for="filter-field"`, `<label for="filter-value"`, `name="field"`,
		`href="/register/export/control.csv?filter=domain%3Dendpoints"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the kind screen does not have %q", want)
		}
	}
	accessible(t, path, body)

	bad := get(t, srv, "/register/kind/control?field=colour&value=red", token)
	if bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), `class="kit-errors"`) ||
		!strings.Contains(bad.Body.String(), `id="filter-field-error"`) {
		t.Errorf("a filter on a field the kind lacks answered %d\n%s", bad.Code, firstLines(bad.Body.String(), 40))
	}
	accessible(t, "/register/kind/control (refused filter)", bad.Body.String())

	exp := get(t, srv, "/register/export/control.csv?filter="+url.QueryEscape("domain=endpoints"), token)
	if exp.Code != http.StatusOK || !strings.HasPrefix(exp.Header().Get("Content-Type"), "text/csv") ||
		!strings.Contains(exp.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("the export answered %d %v", exp.Code, exp.Header())
	}
	rows, err := csv.NewReader(strings.NewReader(exp.Body.String())).ReadAll()
	if err != nil || len(rows) != 3 {
		t.Fatalf("the export is %v (%v)", rows, err)
	}
	for _, row := range rows[1:] {
		for _, cell := range row {
			if sheet.IsFormula(cell) {
				t.Errorf("the cell %q would run as a formula", cell)
			}
		}
	}
	risks := get(t, srv, "/register/kind/risk", token).Body.String()
	if !strings.Contains(risks, `href="/register/export/risk.csv?top=10"`) {
		t.Error("the risks do not offer the top risks")
	}
	top := get(t, srv, "/register/export/risk.csv?top=2", token)
	rows, _ = csv.NewReader(strings.NewReader(top.Body.String())).ReadAll()
	if len(rows) != 3 || rows[1][len(rows[1])-1] != "20" || rows[2][len(rows[2])-1] != "16" {
		t.Errorf("the top two risks are %v", rows)
	}
	if w := get(t, srv, "/register/export/control.csv?top=2", token); w.Code != http.StatusBadRequest {
		t.Errorf("the top of controls answered %d", w.Code)
	}
	if w := get(t, srv, "/register/export/nonsense.csv", token); w.Code != http.StatusNotFound {
		t.Errorf("the export of a kind that does not exist answered %d", w.Code)
	}
}

// PLAN themes 7 and 28: a record's screen shows its history, a change a
// line, and what it names beside the register; after a person is erased
// the record still reads, and says "subject erased" and "text erased".
func TestTheRecordScreenShowsHistoryAndErasure(t *testing.T) {
	srv, token := setup(t)
	r, by := writerOn(t, srv)
	ada, err := r.SubjectFor("ada.lovelace@example.com", "person")
	if err != nil {
		t.Fatal(err)
	}
	words, err := r.PutText(by, register.KindRisk, "Ada Lovelace raised this", ada)
	if err != nil {
		t.Fatal(err)
	}
	risk := register.Risk{Ref: "R-1", Title: "Shared administrator accounts", Description: words, Owner: ada, Raised: ada,
		Likelihood: 3, Impact: 4, Status: "open"}
	if _, err := r.Put(by, "a risk raised", risk); err != nil {
		t.Fatal(err)
	}
	risk.Likelihood = 4
	if _, err := r.Put(by, "a risk rated again", risk); err != nil {
		t.Fatal(err)
	}
	id, _ := register.IDOf(risk)
	path := "/register/record/" + string(id)
	body := get(t, srv, path, token).Body.String()
	for _, want := range []string{"a risk raised", "a risk rated again", "Ada Lovelace raised this", "Subject in the map"} {
		if !strings.Contains(body, want) {
			t.Errorf("the record does not show %q", want)
		}
	}
	accessible(t, path, body)

	if _, err := r.Erase(by, register.ErasureRequest{Subject: ada, Basis: "request", RequestedBy: ada, Eligible: 2,
		Evidence: []byte("a test")}); err != nil {
		t.Fatal(err)
	}
	body = get(t, srv, path, token).Body.String()
	if !strings.Contains(body, "Subject erased") || !strings.Contains(body, "Text erased") ||
		strings.Contains(body, "Ada Lovelace") {
		t.Errorf("after the erasure the record shows\n%s", firstLines(body, 80))
	}
	accessible(t, path+" (erased)", body)
}

// PLAN theme 7: the erasure screen asks for the person, the basis and a
// confirmation, each control labelled; what is wrong is said beside its
// field and at the top; a person who may approve the register erases, and
// is shown the record it wrote; somebody who may not is refused.
func TestTheErasureScreen(t *testing.T) {
	srv, token := setup(t)
	var logged []string
	srv.Audit = func(action, resource string, detail map[string]string) { logged = append(logged, action) }
	r, _ := writerOn(t, srv)
	ada, err := r.SubjectFor("ada.lovelace@example.com", "person")
	if err != nil {
		t.Fatal(err)
	}
	form := get(t, srv, "/register/erase", token)
	if form.Code != http.StatusOK {
		t.Fatalf("the erasure form answered %d", form.Code)
	}
	for _, want := range []string{`<label for="erase-subject"`, `<label for="erase-basis"`, `<label for="erase-confirm"`,
		`method="post"`} {
		if !strings.Contains(form.Body.String(), want) {
			t.Errorf("the erasure form has no %q", want)
		}
	}
	accessible(t, "/register/erase", form.Body.String())

	w := postForm(t, srv, "/register/erase", token, url.Values{"subject": {""}, "basis": {"whim"}}.Encode())
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), `class="kit-errors"`) ||
		!strings.Contains(w.Body.String(), `id="erase-subject-error"`) || !strings.Contains(w.Body.String(), `id="erase-basis-error"`) ||
		!strings.Contains(w.Body.String(), `id="erase-confirm-error"`) {
		t.Fatalf("an incomplete erasure answered %d\n%s", w.Code, firstLines(w.Body.String(), 60))
	}
	accessible(t, "/register/erase (problems)", w.Body.String())
	if r.SubjectState(ada).State != register.SubjectHeld {
		t.Fatal("an incomplete erasure erased the person")
	}

	if err := srv.Policy.Grant(auth.Binding{Principal: "rita", Role: auth.RoleReader, Resource: auth.AreaCompliance}); err != nil {
		t.Fatal(err)
	}
	rita, _, err := srv.Tokens.IssueSession("rita", "rita", auth.RoleReader, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	// Somebody who may not decide an erasure is not shown the form to ask
	// for one, nor a link to it.
	if w := get(t, srv, "/register/erase", rita); w.Code != http.StatusForbidden {
		t.Errorf("a reader's erasure form answered %d", w.Code)
	}
	for _, page := range []string{"/register", "/register/inventory"} {
		if w := get(t, srv, page, rita); w.Code != http.StatusOK || strings.Contains(w.Body.String(), `href="/register/erase"`) {
			t.Errorf("a reader's %s answered %d, offering the erasure", page, w.Code)
		}
	}
	full := url.Values{"subject": {"ada.lovelace@example.com"}, "basis": {"request"}, "requested": {"subject"},
		"confirm": {"yes"}}.Encode()
	if w := postForm(t, srv, "/register/erase", rita, full); w.Code != http.StatusForbidden {
		t.Errorf("a reader's erasure answered %d", w.Code)
	}
	if r.SubjectState(ada).State != register.SubjectHeld {
		t.Fatal("a refused erasure erased the person")
	}
	w = postForm(t, srv, "/register/erase", token, full)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `role="status"`) ||
		!strings.Contains(w.Body.String(), `href="/register/record/`+string(register.ErasureID(ada))+`"`) {
		t.Fatalf("the erasure answered %d\n%s", w.Code, firstLines(w.Body.String(), 60))
	}
	accessible(t, "/register/erase (done)", w.Body.String())
	if r.SubjectState(ada).State != register.SubjectErased {
		t.Error("the person was not erased")
	}
	if !strings.Contains(strings.Join(logged, " "), register.EraseAction) {
		t.Errorf("the erasure is not in the audit log: %v", logged)
	}
	if w := postForm(t, srv, "/register/erase", token, url.Values{"subject": {string(ada)}, "basis": {"request"},
		"confirm": {"yes"}}.Encode()); w.Code != http.StatusConflict {
		t.Errorf("a second erasure answered %d", w.Code)
	}
}

// PLAN theme 7: the data inventory screen is generated from the schemas: a
// table a kind, with a caption and scoped headings, saying which fields
// name a person, which hold text and files, how long, and who reads them.
func TestTheDataInventoryScreen(t *testing.T) {
	srv, token := setup(t)
	w := get(t, srv, "/register/inventory", token)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "<h1>Data inventory</h1>") || !strings.Contains(body, "raised_by") ||
		!strings.Contains(body, "the subject map") || !strings.Contains(body, `<th scope="col">`) ||
		!strings.Contains(body, "<dt>The audit log</dt>") {
		t.Fatalf("the inventory answered %d\n%s", w.Code, firstLines(body, 60))
	}
	if strings.Count(body, "<caption>") < len(register.Kinds())/2 {
		t.Errorf("the inventory has %d tables for %d kinds", strings.Count(body, "<caption>"), len(register.Kinds()))
	}
	accessible(t, "/register/inventory", body)
	front := get(t, srv, "/register", token).Body.String()
	for _, want := range []string{`href="/register/inventory"`, `href="/register/erase"`} {
		if !strings.Contains(front, want) {
			t.Errorf("/register does not link %q", want)
		}
	}
}

// An erasure's approval names its decider by their pseudonym alone, as the
// command line's does (TestAnErasureIsBoundToItsDeciderByPseudonymAlone in
// cmd/quilzo): the session's evidence holds no name a guess could find in
// the hash the record keeps for good.
func TestAnErasureHereIsBoundToItsDeciderByPseudonymAlone(t *testing.T) {
	p := principal{Name: "dana.decider@example.com", TokenID: "5f0c", Methods: []string{"passkey"}}
	if ev := string(sessionEvidence(p)); strings.Contains(ev, p.Name) {
		t.Errorf("the evidence of a decision in the admin is %q", ev)
	}
}
