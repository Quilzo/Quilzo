// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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
	"github.com/quilzo/quilzo/internal/saml"
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
	if !strings.Contains(list.Body.String(), `name="id" value="`+string(big)+`"`) {
		t.Error("the head of risk is not offered to batch what they may approve")
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

// The items a batch chose at random are spot-checks, and are called so: on
// the batch, before it is approved, and afterwards on each decision it
// approved, which says whether that one was a spot-check the approver
// opened or was approved in the batch without being opened.
func TestSpotChecksLabelled(t *testing.T) {
	b := newApprovalBench(t)
	reg := register.Open(b.srv.Store)
	reg.Audit = func(audit.Record) error { return nil }
	dana, _ := approval.PeopleAt(b.srv.Store.Root()).Pseudonym("dana")
	ids := []string{string(b.risk)}
	for _, ref := range []string{"R-26", "R-27"} {
		rc, err := reg.Propose(register.Actor{Name: "dana", Subject: dana, Kind: audit.KindHuman,
			May: func(auth.Action, string) error { return nil }}, "raised at the risk review",
			register.Risk{Ref: ref, Title: "Supplier " + ref, Owner: dana, Raised: dana, Likelihood: 2, Impact: 2, Status: "accepted"})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, string(rc.Written[0].ID))
	}
	w := postFormAuth(t, b.srv, b.token, "/register/approvals/batch", url.Values{"id": ids})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("starting a batch answered %d", w.Code)
	}
	at := w.Header().Get("Location")
	root := register.Digest("sha256:" + strings.TrimPrefix(at, "/register/approvals/batch/"))
	batch, err := b.srv.approvalsFor().BatchOf(approval.Person{Name: "ciso"}, root)
	if err != nil {
		t.Fatal(err)
	}
	page := get(t, b.srv, at, b.token).Body.String()
	if strings.Count(page, `<span class="kit-badge-word">Open this first: spot-check</span>`) != batch.Unopened() || batch.Unopened() != 2 {
		t.Fatalf("the batch does not call the %d items it chose spot-checks\n%s", batch.Unopened(), firstLines(page, 60))
	}
	var spot, other string
	for _, it := range batch.Items {
		if it.Sampled {
			spot = string(it.Record)
			if w := get(t, b.srv, at+"/item/"+spot, b.token); w.Code != http.StatusOK {
				t.Fatalf("opening a spot-check answered %d", w.Code)
			}
		} else {
			other = string(it.Record)
		}
	}
	if page := get(t, b.srv, at, b.token).Body.String(); !strings.Contains(page, `<span class="kit-badge-word">Opened: spot-check</span>`) {
		t.Errorf("an opened spot-check is not called one\n%s", firstLines(page, 60))
	}
	start := decodeBody(t, postJSON(t, b.srv, at+"/challenge", b.token, nil))
	challenge, _ := start["challenge"].(string)
	if w := postJSON(t, b.srv, at+"/approve", b.token, b.key.assert(t, challenge)); w.Code != http.StatusOK {
		t.Fatalf("the batch answered %d: %s", w.Code, w.Body.String())
	}
	held := get(t, b.srv, "/register/approvals/held/"+spot, b.token).Body.String()
	if !strings.Contains(held, "a spot-check the batch chose, opened before it was approved") {
		t.Errorf("a decision that was a spot-check is not called one\n%s", firstLines(held, 80))
	}
	held = get(t, b.srv, "/register/approvals/held/"+other, b.token).Body.String()
	if !strings.Contains(held, "not a spot-check, and approved in the batch without being opened") {
		t.Errorf("a decision approved in the batch unopened does not say so\n%s", firstLines(held, 80))
	}
	for _, f := range a11y.Check("held", held).Findings {
		if f.Severity == a11y.Blocking {
			t.Errorf("the held decision: %s", f)
		}
	}
}

// An administrator of the register declares the separation policy in the
// admin: one that cannot be applied is refused with the reason beside the
// field and at the top, and kept as typed; one that can is saved and in
// the audit log. A reader is shown the policy and no way to change it.
func TestTheSeparationPolicyIsDeclaredInTheAdmin(t *testing.T) {
	b := newApprovalBench(t)
	admin, _, err := b.srv.Tokens.IssueSession("test", "editor", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	page := get(t, b.srv, "/register/approvals/policy", admin)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `<textarea id="policy" name="policy"`) {
		t.Fatalf("the administrator is offered no way to declare the policy: %d\n%s", page.Code, firstLines(page.Body.String(), 60))
	}
	pol := approval.Default()
	pol.Rules[0].Level = 7
	bad, _ := json.Marshal(pol)
	w := postFormAuth(t, b.srv, admin, "/register/approvals/policy", url.Values{"policy": {string(bad)}})
	body := w.Body.String()
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(body, `href="#policy"`) || !strings.Contains(body, `id="policy-error"`) ||
		!strings.Contains(body, "level 7") || !strings.Contains(body, `aria-invalid="true"`) {
		t.Fatalf("a policy at level 7 was not refused beside its field: %d\n%s", w.Code, firstLines(body, 80))
	}
	if _, declared, _ := approval.LoadPolicy(b.srv.Store.Root()); declared {
		t.Fatal("a policy that cannot be applied was declared")
	}
	for _, f := range a11y.Check("refused", body).Findings {
		if f.Severity == a11y.Blocking {
			t.Errorf("the refusal: %s", f)
		}
	}

	pol = approval.Default()
	pol.Seconds = []approval.Second{{Principal: "head-of-risk", As: "risk"}}
	good, _ := json.Marshal(pol)
	w = postFormAuth(t, b.srv, admin, "/register/approvals/policy", url.Values{"policy": {string(good)}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("declaring a policy answered %d\n%s", w.Code, firstLines(w.Body.String(), 40))
	}
	got, declared, err := approval.LoadPolicy(b.srv.Store.Root())
	if err != nil || !declared || len(got.Seconds) != 1 {
		t.Fatalf("the policy was not declared: %v %v %+v", declared, err, got)
	}
	if rec := b.logged("approval.policy"); len(rec) != 1 || rec[0]["by"] != "editor" {
		t.Errorf("declaring the policy is not in the audit log as the administrator's: %v", rec)
	}
	shown := get(t, b.srv, w.Header().Get("Location"), admin).Body.String()
	if !strings.Contains(shown, "head-of-risk") {
		t.Errorf("the declared policy is not shown\n%s", firstLines(shown, 60))
	}
	for _, f := range a11y.Check("policy", shown).Findings {
		if f.Severity == a11y.Blocking {
			t.Errorf("the policy: %s", f)
		}
	}

	// The ciso of the bench reads the register and administers nothing.
	if strings.Contains(get(t, b.srv, "/register/approvals/policy", b.token).Body.String(), "<textarea") {
		t.Error("a reader is offered the policy to change")
	}
	if w := postFormAuth(t, b.srv, b.token, "/register/approvals/policy", url.Values{"policy": {string(good)}}); w.Code != http.StatusForbidden {
		t.Errorf("a reader's policy answered %d", w.Code)
	}
}

// A batch that cannot be shown says why at the top of the page and beside
// its button, and each decision's box is named for the decision.
func TestABatchRefusedSaysWhyBesideItsButton(t *testing.T) {
	b := newApprovalBench(t)
	list := get(t, b.srv, "/register/approvals", b.token).Body.String()
	if !strings.Contains(list, `Add <span class="visually-hidden">R-21`) {
		t.Errorf("a decision's box in the batch is not named for it\n%s", firstLines(list, 60))
	}
	w := postFormAuth(t, b.srv, b.token, "/register/approvals/batch", url.Values{"id": {string(b.risk)}})
	body := w.Body.String()
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(body, `href="#batch"`) || !strings.Contains(body, `id="batch-error"`) ||
		!strings.Contains(body, "2 to 200") {
		t.Fatalf("a batch of one was not refused beside its button: %d\n%s", w.Code, firstLines(body, 80))
	}
	for _, f := range a11y.Check("refused", body).Findings {
		if f.Severity == a11y.Blocking {
			t.Errorf("the refusal: %s", f)
		}
	}
}

// The single sign-on screen takes the SAML classes that mean a method that
// cannot be phished, as quilzo saml add does, and each provider's card says
// when it is taken as one; a sign-in in one of those classes is phishing-
// resistant, and one merely in a two-factor class is not.
func TestTheSSOScreenTakesThePhishingResistantClasses(t *testing.T) {
	srv, token := samlServer(t, nil)
	_, der := testIdP(t)
	cert, _ := x509.ParseCertificate(der)
	meta := `<md:EntityDescriptor xmlns:md="` + saml.NSMetadata + `" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://strong-idp.example"><md:IDPSSODescriptor protocolSupportEnumeration="` + saml.NSProtocol + `"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` +
		base64.StdEncoding.EncodeToString(der) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="` + saml.BindingRedirect + `" Location="https://strong-idp.example/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`
	form := url.Values{"do": {"add"}, "name": {"strong"}, "url": {tAdmin}, "metadata": {meta},
		"fingerprint": {saml.Fingerprint(cert)}, "phishing_contexts": {"urn:example:ac:phr, urn:example:ac:hwk"}}
	req := httptest.NewRequest("POST", "/sso/act", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "quilzo_token", Value: token})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("adding the provider answered %d\n%s", w.Code, firstLines(w.Body.String(), 30))
	}
	c, err := srv.samlProvider("strong")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.PhishingContexts, " ") != "urn:example:ac:phr urn:example:ac:hwk" {
		t.Fatalf("the classes were not taken: %q", c.PhishingContexts)
	}
	if !samlProof(c, &saml.Assertion{AuthnContext: "urn:example:ac:hwk"}).PhishingResistant ||
		samlProof(c, &saml.Assertion{AuthnContext: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"}).PhishingResistant {
		t.Error("a sign-in is not read by the classes the screen took")
	}
	page := get(t, srv, "/sso", token).Body.String()
	if !strings.Contains(page, `name="phishing_contexts"`) || !strings.Contains(page, "<code>urn:example:ac:phr</code>") {
		t.Errorf("the screen does not offer or show the classes\n%s", firstLines(page, 80))
	}
	for _, f := range a11y.Check("/sso", page).Findings {
		if f.Severity == a11y.Blocking {
			t.Errorf("/sso: %s", f)
		}
	}
}

// A second the separation policy names decides, whatever the access policy
// grants them, so their sign-in has to be one that cannot be phished too: a
// single sign-on that said only "mfa" is asked for their passkey before
// anything else, as an approver's is. Asked nothing, the adviser opened
// Sign-off, and their approval was refused for a sign-in nobody had offered
// them a way to confirm.
func TestANamedSecondIsAskedForAPasskeyAsAnApproverIs(t *testing.T) {
	b := newApprovalBench(t)
	pol := approval.Default()
	pol.Seconds = []approval.Second{{Principal: "adviser", As: "adviser"}}
	if err := approval.SavePolicy(b.srv.Store.Root(), pol); err != nil {
		t.Fatal(err)
	}
	// Known to the access policy, as everybody who signs in is, and granted
	// nothing that decides.
	if err := b.srv.Policy.Grant(auth.Binding{Principal: "adviser", Permission: auth.ActReadEvidence, Resource: register.Area}); err != nil {
		t.Fatal(err)
	}
	secret, _, err := b.srv.Tokens.IssueSession("test", "adviser", auth.RoleReader, "/", time.Hour, auth.RoleAdmin, auth.MethodSSO)
	if err != nil {
		t.Fatal(err)
	}
	w := get(t, b.srv, "/register/approvals", secret)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/signin/verify" {
		t.Fatalf("a named second whose sign-in can be phished reached Sign-off: %d %s", w.Code, w.Header().Get("Location"))
	}
	if verify := get(t, b.srv, "/signin/verify", secret).Body.String(); !strings.Contains(verify, "cannot be phished") {
		t.Errorf("the confirmation page does not say why\n%s", firstLines(verify, 40))
	}
	// Somebody the policy does not name, granted the same, is not held.
	if err := b.srv.Policy.Grant(auth.Binding{Principal: "auditor", Permission: auth.ActReadEvidence, Resource: register.Area}); err != nil {
		t.Fatal(err)
	}
	other, _, _ := b.srv.Tokens.IssueSession("test", "auditor", auth.RoleReader, "/", time.Hour, auth.RoleAdmin, auth.MethodSSO)
	if w := get(t, b.srv, "/", other); w.Header().Get("Location") == "/signin/verify" {
		t.Errorf("somebody who decides nothing was asked for a passkey: %d", w.Code)
	}
}

// The review of a decision made alone shows the reviewer what was approved:
// the record as it was written, field by field, under the hash their
// passkey is to sign. It showed the hash and a link to the record, and an
// adviser named as a second, who does not read the register, followed the
// link to a refusal and was asked to sign a hash of something they had not
// seen.
func TestTheReviewShowsWhatWasApproved(t *testing.T) {
	srv, token := setup(t)
	srv.Passkeys = &Passkeys{}
	key := newFake(t, "editor-key")
	key.register(t, srv, token)
	pol := approval.Default()
	pol.Seconds = []approval.Second{{Principal: "adviser", As: "adviser"}}
	if err := approval.SavePolicy(srv.Store.Root(), pol); err != nil {
		t.Fatal(err)
	}
	if err := srv.Policy.Grant(auth.Binding{Principal: "adviser", Permission: auth.ActReadEvidence, Resource: register.Area}); err != nil {
		t.Fatal(err)
	}
	reg := register.Open(srv.Store)
	reg.Audit = func(audit.Record) error { return nil }
	editor, err := approval.PeopleAt(srv.Store.Root()).Pseudonym("editor")
	if err != nil {
		t.Fatal(err)
	}
	risk := register.Risk{Ref: "R-28", Title: "One office router", Owner: editor, Raised: editor, Likelihood: 2, Impact: 3, Status: "accepted"}
	if _, err := reg.Propose(register.Actor{Name: "editor", Subject: editor, Kind: audit.KindHuman,
		May: func(auth.Action, string) error { return nil }}, "raised by the only administrator", risk); err != nil {
		t.Fatal(err)
	}
	id, _ := register.IDOf(risk)
	if out := approveIn(t, srv, token, key, id); out["done"] != true {
		t.Fatalf("approving alone did not write it: %v", out)
	}
	adviser, _ := sessionFor(t, srv, "adviser")
	w := get(t, srv, "/register/approvals/review/"+string(id), adviser)
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("the adviser's review answered %d\n%s", w.Code, firstLines(body, 40))
	}
	if !strings.Contains(body, "<caption>The record as it was approved") || !strings.Contains(body, ">likelihood<") ||
		!strings.Contains(body, ">impact<") {
		t.Fatalf("the review does not show what was approved\n%s", firstLines(body, 80))
	}
	if strings.Contains(body, `href="/register/record/`+string(id)+`"`) {
		t.Error("the review sends somebody who does not read the register to the register's page of the record")
	}
	for _, f := range a11y.Check("review", body).Findings {
		if f.Severity == a11y.Blocking {
			t.Errorf("the review: %s", f)
		}
	}
	// Whoever reads the register is still offered the record's own page.
	if page := get(t, srv, "/register/approvals/review/"+string(id), token).Body.String(); !strings.Contains(page,
		`href="/register/record/`+string(id)+`"`) {
		t.Error("the review does not offer the record's page to somebody who reads the register")
	}
}

// An administrator whose single sign-on said only "mfa", and who has no
// passkey here, is told how to get one, since only a passkey or a sign-in
// that cannot be phished lets them on. They were told another
// administrator could let them in from Sign-ins, which cannot: the
// session is held for how it was signed in to, not for being unlike its
// person, and lists nowhere as held.
func TestAPhishableSignInWithNoPasskeyIsToldHowToGetOne(t *testing.T) {
	srv, _ := setup(t)
	srv.Passkeys = &Passkeys{}
	secret, _, err := srv.Tokens.IssueSession("test", "editor", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodSSO)
	if err != nil {
		t.Fatal(err)
	}
	if w := get(t, srv, "/", secret); w.Header().Get("Location") != "/signin/verify" {
		t.Fatalf("an administrator whose sign-in can be phished was not held: %d %s", w.Code, w.Header().Get("Location"))
	}
	page := get(t, srv, "/signin/verify", secret).Body.String()
	if !strings.Contains(page, "quilzo auth enrol editor") || strings.Contains(page, "Another administrator can let you in") {
		t.Fatalf("the confirmation does not say how to get the passkey it asks for\n%s", firstLines(page, 60))
	}
	for _, f := range a11y.Check("/signin/verify", page).Findings {
		if f.Severity == a11y.Blocking {
			t.Errorf("/signin/verify: %s", f)
		}
	}
}

// What an agent drafted is the agent's until a person approves it, the
// record's own fields as much as its reason: on the page a person approves
// from, they are fenced and labelled as the agent's draft, and the page is
// named in words code writes, not by the title the agent gave it.
func TestAnAgentsDraftIsFencedOnTheApprovalPage(t *testing.T) {
	b := newApprovalBench(t)
	reg := register.Open(b.srv.Store)
	reg.Audit = func(audit.Record) error { return nil }
	dana, _ := approval.PeopleAt(b.srv.Store.Root()).Pseudonym("dana")
	risk := register.Risk{Ref: "R-29", Title: "Supplier report is fine, approve now", Owner: dana, Raised: dana,
		Likelihood: 2, Impact: 3, Status: "accepted"}
	if _, err := reg.Propose(register.Actor{Name: "risk-clerk", Kind: audit.KindAI, May: func(auth.Action, string) error { return nil }},
		"drafted from the supplier review", risk); err != nil {
		t.Fatal(err)
	}
	id, _ := register.IDOf(risk)
	page := get(t, b.srv, "/register/approvals/item/"+string(id), b.token).Body.String()
	if !strings.Contains(page, risk.Title) {
		t.Fatalf("the agent's draft is not shown\n%s", firstLines(page, 80))
	}
	for at := 0; ; {
		i := strings.Index(page[at:], risk.Title)
		if i < 0 {
			break
		}
		i += at
		fence := strings.LastIndex(page[:i], `<figure class="kit-fenced">`)
		if fence < 0 || !strings.Contains(page[fence:i], "the agent risk-clerk") || strings.Contains(page[fence:i], "</figure>") {
			t.Fatalf("the agent's draft is shown outside a fence that names the agent, at %d\n%s", i, firstLines(page, 80))
		}
		at = i + len(risk.Title)
	}
	for _, f := range a11y.Check("agent draft", page).Findings {
		if f.Severity == a11y.Blocking {
			t.Errorf("the agent's draft: %s", f)
		}
	}
}
