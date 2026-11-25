// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/approval"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/oidc"
	"github.com/quilzo/quilzo/internal/register"
)

// approvalBench is the admin with somebody who may accept risks and has a
// passkey, a risk somebody else raised waiting for them, and every audit
// record the admin writes.
type approvalBench struct {
	srv   *Server
	token string
	key   *fakeAuthenticator
	risk  register.ID
	log   []map[string]string
}

func newApprovalBench(t *testing.T, methods ...string) *approvalBench {
	t.Helper()
	srv, _ := setup(t)
	srv.Passkeys = &Passkeys{}
	b := &approvalBench{srv: srv}
	srv.Audit = func(action, resource string, detail map[string]string) {
		d := map[string]string{"action": action}
		for k, v := range detail {
			d[k] = v
		}
		b.log = append(b.log, d)
	}
	for _, g := range []auth.Binding{
		{Principal: "ciso", Role: auth.RoleReader, Resource: auth.AreaCompliance},
		{Principal: "ciso", Permission: auth.ActAcceptRisk, Resource: register.Area},
	} {
		if err := srv.Policy.Grant(g); err != nil {
			t.Fatal(err)
		}
	}
	if len(methods) == 0 {
		methods = []string{auth.MethodPasskey}
	}
	secret, _, err := srv.Tokens.IssueSession("test", "ciso", auth.RoleReader, "/", time.Hour, auth.RoleAdmin, methods...)
	if err != nil {
		t.Fatal(err)
	}
	b.token = secret
	b.key = newFake(t, "ciso-key")
	if len(methods) == 1 && methods[0] == auth.MethodPasskey {
		b.key.register(t, srv, secret)
	}

	reg := register.Open(srv.Store)
	reg.Audit = func(audit.Record) error { return nil }
	people := approval.PeopleAt(srv.Store.Root())
	dana, err := people.Pseudonym("dana")
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := people.Pseudonym("owner")
	allow := func(auth.Action, string) error { return nil }
	rc, err := reg.Propose(register.Actor{Name: "dana", Subject: dana, Kind: audit.KindHuman, May: allow}, "raised at the risk review",
		register.Risk{Ref: "R-21", Title: "Payroll supplier outage", Owner: owner, Raised: dana, Likelihood: 3, Impact: 3, Status: "accepted"})
	if err != nil {
		t.Fatal(err)
	}
	b.risk = rc.Written[0].ID
	return b
}

// assert is the passkey answering a challenge.
func (f *fakeAuthenticator) assert(t *testing.T, challenge string) map[string]any {
	t.Helper()
	f.count++
	cd := f.clientData(t, "webauthn.get", challenge)
	ad := f.authData()
	sum := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), sum[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, f.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"id": enc(f.id), "challenge": challenge, "clientDataJSON": enc(cd),
		"authenticatorData": enc(ad), "signature": enc(sig)}
}

func (b *approvalBench) logged(action string) []map[string]string {
	var out []map[string]string
	for _, d := range b.log {
		if d["action"] == action {
			out = append(out, d)
		}
	}
	return out
}

// The hash beside the button is the hash the passkey signs, the hash the
// receipt carries and the hash the audit log records, for one approval
// made through the real routes with a virtual authenticator.
func TestPageHashEqualsAuditHash(t *testing.T) {
	b := newApprovalBench(t)
	page := get(t, b.srv, "/register/approvals/item/"+string(b.risk), b.token)
	if page.Code != http.StatusOK {
		t.Fatalf("the decision's page answered %d\n%s", page.Code, firstLines(page.Body.String(), 30))
	}
	m := b.srv.approvalsFor()
	ask, err := m.Ask(b.risk)
	if err != nil {
		t.Fatal(err)
	}
	hash := string(ask.Hash)
	body := page.Body.String()
	if !strings.Contains(body, `<code class="kit-hash">`+hash+`</code>`) || !strings.Contains(body, "Your passkey signs the hash") {
		t.Fatalf("the page does not show the hash beside the button\n%s", firstLines(body, 80))
	}
	if csp := page.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'nonce-") || !strings.Contains(csp, "connect-src 'self'") {
		t.Errorf("the page's policy does not let its ceremony run, and only it: %s", csp)
	}

	start := decodeBody(t, postJSON(t, b.srv, "/register/approvals/item/"+string(b.risk)+"/challenge", b.token, nil))
	challenge, _ := start["challenge"].(string)
	purpose, of, err := approval.ChallengeFor(challenge)
	if err != nil || purpose != approval.ForApproval || string(of) != hash || start["surface"] != hash {
		t.Fatalf("the challenge does not hold the page's hash: %v %v %v", of, start, err)
	}
	w := postJSON(t, b.srv, "/register/approvals/item/"+string(b.risk)+"/approve", b.token, b.key.assert(t, challenge))
	if w.Code != http.StatusOK {
		t.Fatalf("the approval answered %d: %s", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	receipt, _ := out["receipt"].(map[string]any)
	approved, _ := receipt["approved"].([]any)
	if out["done"] != true || len(approved) != 1 || approved[0] != hash || out["surface"] != hash {
		t.Fatalf("the receipt does not carry the page's hash: %v", out)
	}
	signed := b.logged(approval.AuditSigned)
	put := b.logged(register.AuditAction)
	if len(signed) != 1 || signed[0]["surface"] != hash || signed[0]["by"] != "ciso" {
		t.Fatalf("the audit log does not record the signature over the page's hash: %v", signed)
	}
	if len(put) != 1 || put[0]["approved"] != hash || put[0]["receipt"] != receipt["digest"] {
		t.Fatalf("the audit entry of the write does not carry the page's hash and the receipt's digest: %v", put)
	}
	// The record holds it, and its page shows it beside a signature that
	// checks.
	held := get(t, b.srv, "/register/approvals/held/"+string(b.risk), b.token).Body.String()
	if !strings.Contains(held, hash) || !strings.Contains(held, "The signature holds") {
		t.Errorf("the held decision does not show its hash and checked evidence\n%s", firstLines(held, 60))
	}
	// A challenge is used once.
	if w := postJSON(t, b.srv, "/register/approvals/item/"+string(b.risk)+"/approve", b.token, b.key.assert(t, challenge)); w.Code == http.StatusOK {
		t.Error("a challenge was used twice")
	}
}

// The admin's approvals work with the page's script off but for the
// passkey ceremony, which says so and names the console's way instead.
func TestApprovingWithTheScriptOffSaysHowTheConsoleApproves(t *testing.T) {
	b := newApprovalBench(t)
	ask, _ := b.srv.approvalsFor().Ask(b.risk)
	w := postFormAuth(t, b.srv, b.token, "/register/approvals/item/"+string(b.risk)+"/approve", url.Values{})
	body := w.Body.String()
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(body, "quilzo approval approve "+string(b.risk)+" --surface "+string(ask.Hash)) {
		t.Fatalf("approving without the script answered %d\n%s", w.Code, firstLines(body, 40))
	}
	if register.Open(b.srv.Store).Head() != "" {
		t.Fatal("approving without a passkey wrote the record")
	}
}

func postFormAuth(t *testing.T, srv *Server, token, path string, v url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// A person who may accept risks and signed in through single sign-on that
// said only "mfa" is asked for their passkey before anything else; said
// "hwk", or an acr the operator named, they are not.
func TestAmrMfaCannotApproveInTheAdmin(t *testing.T) {
	b := newApprovalBench(t, auth.MethodSSO)
	w := get(t, b.srv, "/register/approvals", b.token)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/signin/verify" {
		t.Fatalf("a single sign-on that said only mfa reached the approvals: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := postJSON(t, b.srv, "/register/approvals/item/"+string(b.risk)+"/challenge", b.token, nil); w.Code != http.StatusForbidden {
		t.Fatalf("a single sign-on that said only mfa was given a challenge to approve with: %d", w.Code)
	}
	if verify := get(t, b.srv, "/signin/verify", b.token).Body.String(); !strings.Contains(verify, "cannot be phished") {
		t.Errorf("the confirmation page does not say why\n%s", firstLines(verify, 40))
	}

	strong := newApprovalBench(t, auth.MethodSSO, auth.MethodSSOPhishingResistant)
	if w := get(t, strong.srv, "/register/approvals", strong.token); w.Code != http.StatusOK {
		t.Fatalf("a single sign-on its provider said resisted phishing was held back: %d", w.Code)
	}

	// Somebody who decides nothing is not held back by it.
	srv, _ := setup(t)
	if err := srv.Policy.Grant(auth.Binding{Principal: "writer", Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	secret, _, _ := srv.Tokens.IssueSession("test", "writer", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin, auth.MethodSSO)
	if w := get(t, srv, "/", secret); w.Code != http.StatusOK {
		t.Errorf("an author who decides nothing was asked for a passkey: %d", w.Code)
	}

	// What the provider says, read.
	now := time.Now()
	recent := float64(now.Add(-time.Minute).Unix())
	o := &OIDC{PhishingACR: []string{"phr-level"}}
	for _, c := range []struct {
		raw  map[string]any
		want bool
	}{
		{map[string]any{"auth_time": recent, "amr": []any{"pwd", "mfa"}}, false},
		{map[string]any{"auth_time": recent, "amr": []any{"hwk", "user"}}, true},
		{map[string]any{"auth_time": recent, "amr": []any{"phrh"}}, true},
		{map[string]any{"auth_time": recent, "acr": "phr-level"}, true},
		{map[string]any{"amr": []any{"hwk"}}, false},
	} {
		p := o.proof(&oidc.Claims{Raw: c.raw}, 0, now)
		if got := auth.PhishingResistant(p.methods()); got != c.want {
			t.Errorf("%v is phishing-resistant: %v, want %v (%v)", c.raw, got, c.want, p.methods())
		}
	}
}

// A batch through the admin: shown, refused until its sample is opened, and
// every page of it accessible.
func TestABatchInTheAdminWaitsForItsSample(t *testing.T) {
	b := newApprovalBench(t)
	reg := register.Open(b.srv.Store)
	reg.Audit = func(audit.Record) error { return nil }
	people := approval.PeopleAt(b.srv.Store.Root())
	dana, _ := people.Pseudonym("dana")
	allow := func(auth.Action, string) error { return nil }
	rc, err := reg.Propose(register.Actor{Name: "dana", Subject: dana, Kind: audit.KindHuman, May: allow}, "raised at the risk review",
		register.Risk{Ref: "R-22", Title: "Laptop theft", Owner: dana, Raised: dana, Likelihood: 2, Impact: 2, Status: "accepted"})
	if err != nil {
		t.Fatal(err)
	}
	list := get(t, b.srv, "/register/approvals", b.token).Body.String()
	if !strings.Contains(list, `name="id" value="`+string(b.risk)+`"`) {
		t.Fatalf("the list offers no way to batch the decision\n%s", firstLines(list, 60))
	}
	w := postFormAuth(t, b.srv, b.token, "/register/approvals/batch", url.Values{"id": {string(b.risk), string(rc.Written[0].ID)}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("starting a batch answered %d\n%s", w.Code, firstLines(w.Body.String(), 30))
	}
	at := w.Header().Get("Location")
	page := get(t, b.srv, at, b.token).Body.String()
	if !strings.Contains(page, "Open this first") || !strings.Contains(page, "Merkle root") {
		t.Fatalf("the batch does not say what must be opened first\n%s", firstLines(page, 60))
	}
	start := decodeBody(t, postJSON(t, b.srv, at+"/challenge", b.token, nil))
	challenge, _ := start["challenge"].(string)
	if w := postJSON(t, b.srv, at+"/approve", b.token, b.key.assert(t, challenge)); w.Code != http.StatusForbidden ||
		!strings.Contains(w.Body.String(), "not been opened") {
		t.Fatalf("a batch was approved with its sample unopened: %d %s", w.Code, w.Body.String())
	}
	for _, path := range []string{"/register/approvals", at, at + "/item/" + string(b.risk), "/register/approvals/item/" + string(b.risk),
		"/register/approvals/policy"} {
		for _, f := range a11y.Check(path, get(t, b.srv, path, b.token).Body.String()).Findings {
			if f.Severity == a11y.Blocking {
				t.Errorf("%s: %s", path, f)
			}
		}
	}
}

// A team of one approves alone, every screen that shows the decision says
// so in words, and the review it owes has a page of its own; each passes
// the accessibility checks.
func TestADecisionMadeAloneShowsItAndOffersItsReview(t *testing.T) {
	srv, token := setup(t)
	srv.Passkeys = &Passkeys{}
	key := newFake(t, "editor-key")
	key.register(t, srv, token)
	reg := register.Open(srv.Store)
	reg.Audit = func(audit.Record) error { return nil }
	editor, err := approval.PeopleAt(srv.Store.Root()).Pseudonym("editor")
	if err != nil {
		t.Fatal(err)
	}
	risk := register.Risk{Ref: "R-23", Title: "Single office network", Owner: editor, Raised: editor, Likelihood: 2, Impact: 2, Status: "accepted"}
	if _, err := reg.Propose(register.Actor{Name: "editor", Subject: editor, Kind: audit.KindHuman,
		May: func(auth.Action, string) error { return nil }}, "raised by the only administrator", risk); err != nil {
		t.Fatal(err)
	}
	id, _ := register.IDOf(risk)
	page := get(t, srv, "/register/approvals/item/"+string(id), token).Body.String()
	if !strings.Contains(page, "You are the only person eligible") {
		t.Fatalf("the page does not say the approval will be made alone\n%s", firstLines(page, 60))
	}
	start := decodeBody(t, postJSON(t, srv, "/register/approvals/item/"+string(id)+"/challenge", token, nil))
	challenge, _ := start["challenge"].(string)
	if w := postJSON(t, srv, "/register/approvals/item/"+string(id)+"/approve", token, key.assert(t, challenge)); w.Code != http.StatusOK {
		t.Fatalf("approving alone answered %d: %s", w.Code, w.Body.String())
	}
	for _, path := range []string{"/register/approvals", "/register/approvals/held/" + string(id), "/register/approvals/review/" + string(id)} {
		w := get(t, srv, path, token)
		body := w.Body.String()
		if w.Code != http.StatusOK {
			t.Fatalf("%s answered %d", path, w.Code)
		}
		if path != "/register/approvals/review/"+string(id) && !strings.Contains(body, "Approved alone") {
			t.Errorf("%s does not say the decision was approved alone\n%s", path, firstLines(body, 60))
		}
		for _, f := range a11y.Check(path, body).Findings {
			if f.Severity == a11y.Blocking {
				t.Errorf("%s: %s", path, f)
			}
		}
	}
	if review := get(t, srv, "/register/approvals/review/"+string(id), token).Body.String(); !strings.Contains(review, `name="outcome"`) {
		t.Errorf("the review page offers no review\n%s", firstLines(review, 60))
	}
}

// What an agent wrote about a decision it proposed is shown fenced and
// labelled as an agent's, never as the record's own words.
func TestModelTextFencedOnApprovalSurface(t *testing.T) {
	b := newApprovalBench(t)
	reg := register.Open(b.srv.Store)
	reg.Audit = func(audit.Record) error { return nil }
	dana, _ := approval.PeopleAt(b.srv.Store.Root()).Pseudonym("dana")
	risk := register.Risk{Ref: "R-24", Title: "Expired supplier report", Owner: dana, Raised: dana, Likelihood: 2, Impact: 3, Status: "accepted"}
	if _, err := reg.Propose(register.Actor{Name: "risk-clerk", Kind: audit.KindAI, May: func(auth.Action, string) error { return nil }},
		"drafted from the supplier review", risk); err != nil {
		t.Fatal(err)
	}
	id, _ := register.IDOf(risk)
	page := get(t, b.srv, "/register/approvals/item/"+string(id), b.token).Body.String()
	at := strings.Index(page, `<figure class="kit-fenced">`)
	if at < 0 || !strings.Contains(page[at:], "Written by the agent risk-clerk") ||
		!strings.Contains(page[at:], "drafted from the supplier review") || strings.Index(page, "drafted from the supplier review") < at {
		t.Fatalf("the agent's words are not fenced and labelled\n%s", firstLines(page, 60))
	}
}

// sessionFor is a passkey session, and a registered passkey, for somebody
// the test names.
func sessionFor(t *testing.T, srv *Server, who string) (string, *fakeAuthenticator) {
	t.Helper()
	secret, _, err := srv.Tokens.IssueSession("test", who, auth.RoleReader, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	key := newFake(t, who+"-key")
	key.register(t, srv, secret)
	return secret, key
}

// approveIn is one person approving a decision through the admin's routes
// with their passkey.
func approveIn(t *testing.T, srv *Server, token string, key *fakeAuthenticator, id register.ID) map[string]any {
	t.Helper()
	start := decodeBody(t, postJSON(t, srv, "/register/approvals/item/"+string(id)+"/challenge", token, nil))
	challenge, _ := start["challenge"].(string)
	w := postJSON(t, srv, "/register/approvals/item/"+string(id)+"/approve", token, key.assert(t, challenge))
	if w.Code != http.StatusOK {
		t.Fatalf("approving %s answered %d: %s", id, w.Code, w.Body.String())
	}
	return decodeBody(t, w)
}

// A second approver need hold no role here. The head of risk, named in the
// separation policy and granted nothing, and a risk manager granted
// accept-risk alone, each open the decisions that are theirs to approve and
// no others; the head of risk's passkey completes one that takes two
// people; and somebody who is neither is refused the approvals.
func TestASecondApproverWithNoRoleApprovesInTheAdmin(t *testing.T) {
	b := newApprovalBench(t)
	pol := approval.Default()
	pol.Seconds = []approval.Second{{Principal: "head-of-risk", As: "risk"}}
	if err := approval.SavePolicy(b.srv.Store.Root(), pol); err != nil {
		t.Fatal(err)
	}
	if err := b.srv.Policy.Grant(auth.Binding{Principal: "rm", Permission: auth.ActAcceptRisk, Resource: register.Area}); err != nil {
		t.Fatal(err)
	}
	reg := register.Open(b.srv.Store)
	reg.Audit = func(audit.Record) error { return nil }
	dana, _ := approval.PeopleAt(b.srv.Store.Root()).Pseudonym("dana")
	rc, err := reg.Propose(register.Actor{Name: "dana", Subject: dana, Kind: audit.KindHuman,
		May: func(auth.Action, string) error { return nil }}, "raised at the risk review",
		register.Risk{Ref: "R-25", Title: "Data centre flood", Owner: dana, Raised: dana, Likelihood: 2, Impact: 4, Status: "accepted"})
	if err != nil {
		t.Fatal(err)
	}
	big := rc.Written[0].ID

	head, headKey := sessionFor(t, b.srv, "head-of-risk")
	list := get(t, b.srv, "/register/approvals", head)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "/register/approvals/item/"+string(big)) {
		t.Fatalf("the head of risk cannot see what is theirs to approve: %d\n%s", list.Code, firstLines(list.Body.String(), 40))
	}
	if strings.Contains(list.Body.String(), "/register/approvals/item/"+string(b.risk)) {
		t.Error("the head of risk is shown a decision that takes no second approver")
	}
	if w := get(t, b.srv, "/register/approvals/item/"+string(b.risk), head); w.Code != http.StatusNotFound {
		t.Errorf("the head of risk opened a decision that is not theirs to approve: %d", w.Code)
	}
	if w := get(t, b.srv, "/register/approvals/item/"+string(big), head); w.Code != http.StatusOK {
		t.Fatalf("the head of risk cannot open what is theirs to approve: %d", w.Code)
	}

	rm, _ := sessionFor(t, b.srv, "rm")
	if body := get(t, b.srv, "/register/approvals", rm).Body.String(); !strings.Contains(body, "/register/approvals/item/"+string(big)) ||
		!strings.Contains(body, "/register/approvals/item/"+string(b.risk)) {
		t.Errorf("somebody granted accept-risk alone does not see the risks they may accept\n%s", firstLines(body, 40))
	}
	nobody, _ := sessionFor(t, b.srv, "nobody")
	if w := get(t, b.srv, "/register/approvals", nobody); w.Code != http.StatusForbidden {
		t.Errorf("somebody who may approve nothing was shown the approvals: %d", w.Code)
	}

	if out := approveIn(t, b.srv, b.token, b.key, big); out["done"] == true {
		t.Fatal("one approval of two wrote the decision")
	}
	if out := approveIn(t, b.srv, head, headKey, big); out["done"] != true {
		t.Fatalf("the head of risk's approval did not complete it: %v", out)
	}
	e, err := reg.Get(big)
	if err != nil {
		t.Fatal(err)
	}
	if ap := register.ApprovalOf(e.Record); len(ap.Signers) != 2 {
		t.Errorf("the decision holds %d approvers", len(ap.Signers))
	}
	if w := get(t, b.srv, "/register/approvals/held/"+string(big), head); w.Code != http.StatusOK {
		t.Errorf("the head of risk cannot see the decision they approved: %d", w.Code)
	}
}
