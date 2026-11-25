// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/approval"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/sheet"
)

// writerOn is the register of a server's store with an audit log kept in
// the test, and a person allowed everything.
func writerOn(t *testing.T, srv *Server) (*register.Register, register.Actor) {
	t.Helper()
	r := register.Open(srv.Store)
	r.Audit = func(audit.Record) error { return nil }
	allow := func(auth.Action, string) error { return nil }
	editor, err := r.SubjectFor("editor", "person")
	if err != nil {
		t.Fatal(err)
	}
	return r, register.Actor{Name: "editor", Subject: editor, Kind: audit.KindHuman, May: allow}
}

// withPasskey is somebody signed in here with a passkey of their own, as
// an administrator of the site, who decides on Sign-off.
func withPasskey(t *testing.T, srv *Server, name string) (string, *fakeAuthenticator) {
	t.Helper()
	if srv.Passkeys == nil {
		srv.Passkeys = &Passkeys{}
	}
	if err := srv.Policy.Grant(auth.Binding{Principal: name, Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	token, _, err := srv.Tokens.IssueSession(name, name, auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	key := newFake(t, name+"-key")
	key.register(t, srv, token)
	return token, key
}

// signOff is a person deciding a waiting decision on Sign-off, their
// passkey signing the challenge the page asks for.
func signOff(t *testing.T, srv *Server, token string, key *fakeAuthenticator, id register.ID) *httptest.ResponseRecorder {
	t.Helper()
	start := decodeBody(t, postJSON(t, srv, "/register/approvals/item/"+string(id)+"/challenge", token, nil))
	challenge, _ := start["challenge"].(string)
	return postJSON(t, srv, "/register/approvals/item/"+string(id)+"/approve", token, key.assert(t, challenge))
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

	_, eid, err := r.RaiseErasure(by, register.ErasureRequest{Subject: ada, Basis: "request", RequestedBy: ada})
	if err != nil {
		t.Fatal(err)
	}
	leeToken, leeKey := withPasskey(t, srv, "lee")
	if w := signOff(t, srv, leeToken, leeKey, eid); w.Code != http.StatusOK {
		t.Fatalf("lee deciding the erasure on Sign-off answered %d: %s", w.Code, w.Body.String())
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
	// Asked for, it waits on Sign-off, where the person who entered it is
	// refused deciding it and somebody else decides it.
	eid := register.ErasureID(ada)
	w = postForm(t, srv, "/register/erase", token, full)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `role="status"`) ||
		!strings.Contains(w.Body.String(), `href="/register/approvals/item/`+string(eid)+`"`) {
		t.Fatalf("asking for the erasure answered %d\n%s", w.Code, firstLines(w.Body.String(), 60))
	}
	accessible(t, "/register/erase (raised)", w.Body.String())
	if r.SubjectState(ada).State != register.SubjectHeld {
		t.Fatal("asking for the erasure erased the person before anybody decided it")
	}
	if srv.Passkeys == nil {
		srv.Passkeys = &Passkeys{}
	}
	editorKey := newFake(t, "editor-key")
	editorKey.register(t, srv, token)
	leeToken, leeKey := withPasskey(t, srv, "lee")
	if w := signOff(t, srv, token, editorKey, eid); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "raised or drafted") {
		t.Errorf("the person who entered the erasure deciding it answered %d: %s", w.Code, w.Body.String())
	}
	if w := signOff(t, srv, leeToken, leeKey, eid); w.Code != http.StatusOK {
		t.Fatalf("lee deciding the erasure answered %d: %s", w.Code, w.Body.String())
	}
	if r.SubjectState(ada).State != register.SubjectErased {
		t.Error("the person was not erased")
	}
	if !strings.Contains(strings.Join(logged, " "), register.EraseAction) {
		t.Errorf("the erasure is not in the audit log: %v", logged)
	}
	if page := get(t, srv, "/register/record/"+string(eid), token); page.Code != http.StatusOK {
		t.Errorf("the erasure's record answered %d", page.Code)
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

// An erasure's approval names its decider by their pseudonym alone: the
// record holds the pseudonym, and the authentication evidence its approval
// keeps beside the store holds no name a guess could find, nor any token's.
func TestAnErasureHereIsBoundToItsDeciderByPseudonymAlone(t *testing.T) {
	srv, _ := setup(t)
	srv.Audit = func(string, string, map[string]string) {}
	r, by := writerOn(t, srv)
	ada, err := r.SubjectFor("ada.lovelace@example.com", "person")
	if err != nil {
		t.Fatal(err)
	}
	_, eid, err := r.RaiseErasure(by, register.ErasureRequest{Subject: ada, Basis: "request", RequestedBy: ada})
	if err != nil {
		t.Fatal(err)
	}
	token, key := withPasskey(t, srv, "dana.decider@example.com")
	if w := signOff(t, srv, token, key, eid); w.Code != http.StatusOK {
		t.Fatalf("deciding the erasure answered %d: %s", w.Code, w.Body.String())
	}
	e, err := r.Get(eid)
	if err != nil {
		t.Fatal(err)
	}
	rec := e.Record.(register.Erasure)
	me, _ := srv.approvalsFor().Known("dana.decider@example.com")
	if rec.Decider != me || !me.Valid() {
		t.Errorf("the erasure was decided by %q, and the decider is %q", rec.Decider, me)
	}
	ev, err := approval.LoadEvidence(srv.Store.Root(), rec.Approval.Signers[0].Assertion)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(ev)
	if strings.Contains(string(raw), "dana") || ev.Subject != me {
		t.Errorf("the decider's evidence names them: %s", raw)
	}
}

// An erasure the person signed in asks for themselves waits for somebody
// else, as every decision does: it is not theirs to decide when anybody
// else may. Nor does anybody enter their own erasure: that is said beside
// the person, and at the top.
func TestAnErasureRaisedByItsDeciderIsSaidBesideWhoAsked(t *testing.T) {
	srv, token := setup(t)
	srv.Audit = func(string, string, map[string]string) {}
	r, _ := writerOn(t, srv)
	ada, err := r.SubjectFor("ada.lovelace@example.com", "person")
	if err != nil {
		t.Fatal(err)
	}
	leeToken, leeKey := withPasskey(t, srv, "lee")
	w := postForm(t, srv, "/register/erase", token, url.Values{"subject": {string(ada)}, "basis": {"no-longer-needed"},
		"requested": {""}, "confirm": {"yes"}}.Encode())
	body := w.Body.String()
	eid := register.ErasureID(ada)
	if w.Code != http.StatusOK || !strings.Contains(body, `href="/register/approvals/item/`+string(eid)+`"`) ||
		!strings.Contains(body, "It waits for somebody else") {
		t.Fatalf("an erasure its raiser asked for themselves answered %d\n%s", w.Code, firstLines(body, 60))
	}
	accessible(t, "/register/erase (raised by its decider)", body)
	if r.SubjectState(ada).State != register.SubjectHeld {
		t.Error("asking for the erasure erased the person")
	}
	p, err := r.Proposals()
	if err != nil || len(p) != 1 {
		t.Fatalf("%d proposals wait (%v)", len(p), err)
	}
	if e := p[0].Record.(register.Erasure); e.RequestedBy != p[0].Subject || e.EnteredBy != "" {
		t.Errorf("the erasure the editor asked for waits as %+v", e)
	}
	// Nor does anybody enter their own.
	w = postForm(t, srv, "/register/erase", token, url.Values{"subject": {"editor"}, "basis": {"request"},
		"requested": {"subject"}, "confirm": {"yes"}}.Encode())
	if body := w.Body.String(); w.Code != http.StatusUnprocessableEntity || !strings.Contains(body, `id="erase-subject-error"`) ||
		!strings.Contains(body, `class="kit-errors"`) {
		t.Errorf("an erasure of the person entering it answered %d\n%s", w.Code, firstLines(body, 60))
	}
	// Decided by somebody else, it is done.
	if w := signOff(t, srv, leeToken, leeKey, eid); w.Code != http.StatusOK || r.SubjectState(ada).State != register.SubjectErased {
		t.Errorf("lee deciding the erasure answered %d", w.Code)
	}
}
