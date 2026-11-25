// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/api"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/evidence"
	"github.com/quilzo/quilzo/internal/federate"
	"github.com/quilzo/quilzo/internal/oidc"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/sources"
)

// A pipeline's push, end to end: a job's identity token, signed by its
// platform, exchanged at /token/exchange with a proof by a key the job
// made, for a token of minutes bound to that key, presented at the content
// API's import with a fresh proof.

const pushWorkflow = ".github/workflows/evidence.yml"

type pushRig struct {
	srv     *Server
	issuer  *rsa.PrivateKey
	audited []audit.Record
	n       int
}

func newPushRig(t *testing.T) *pushRig {
	t.Helper()
	srv, _ := setup(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rig := &pushRig{srv: srv, issuer: key}
	srv.Federation = &Federation{
		Trusts: func() ([]federate.Trust, error) {
			return []federate.Trust{{Name: "docs-evidence", Issuer: federate.GitHub, Audience: "https://admin.example",
				Claims:    map[string]string{"repository": "octo/docs"},
				Principal: "ci:docs", Role: auth.RoleAuthor, Resource: auth.AreaCompliance, TTL: "10m"}}, nil
		},
		Keys: func(context.Context, string) (oidc.KeySource, []oidc.Algorithm, error) {
			return oneRSA{&key.PublicKey}, []oidc.Algorithm{oidc.RS256}, nil
		},
	}
	if err := srv.Policy.Grant(auth.Binding{Principal: "ci:docs", Role: auth.RoleAuthor, Resource: auth.AreaCompliance}); err != nil {
		t.Fatal(err)
	}
	srv.API = (&api.Server{Store: srv.Store, Policy: srv.Policy, Tokens: srv.Tokens}).Handler()
	was := evidence.Recorder
	evidence.Recorder = func(reg *register.Register) {
		reg.Audit = func(r audit.Record) error { rig.audited = append(rig.audited, r); return nil }
	}
	t.Cleanup(func() { evidence.Recorder = was })
	// The pipeline's source, which a person adds.
	reg := register.Open(srv.Store)
	reg.Audit = func(audit.Record) error { return nil }
	src, err := sources.PipelineSource(sources.Pipeline{Name: "docs-ci", Repository: "octo/docs", Workflow: pushWorkflow})
	if err != nil {
		t.Fatal(err)
	}
	person := register.Actor{Name: "editor", Kind: audit.KindHuman, Verified: true, May: func(auth.Action, string) error { return nil }}
	if _, err := sources.Open(reg).Add(person, src); err != nil {
		t.Fatal(err)
	}
	return rig
}

// jobToken is the identity token GitHub Actions signs for one job.
func (r *pushRig) jobToken(t *testing.T, repo, workflow string) string {
	t.Helper()
	r.n++
	now := time.Now()
	h, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "k1"})
	c, _ := json.Marshal(map[string]any{"iss": federate.GitHub, "aud": "https://admin.example",
		"sub": "repo:" + repo + ":ref:refs/heads/main", "repository": repo, "ref": "refs/heads/main",
		"workflow_ref": repo + "/" + workflow + "@refs/heads/main", "run_id": "7001", "jti": "jti-" + repo + "-" + string(rune('a'+r.n)),
		"iat": now.Add(-time.Minute).Unix(), "nbf": now.Add(-time.Minute).Unix(), "exp": now.Add(5 * time.Minute).Unix()})
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, r.issuer, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// exchangeJob trades a job's identity token, with a proof by key, for the
// token the trust gives it.
func (r *pushRig) exchangeJob(t *testing.T, job string, key *ecdsa.PrivateKey) exchangeAnswer {
	t.Helper()
	form := url.Values{"grant_type": {grantTokenExchange}, "subject_token": {job}, "subject_token_type": {typeIDToken}}
	proof := ""
	if key != nil {
		proof = proved(t, key, "POST", "http://example.com/token/exchange", "")
	}
	w := exchange(t, r.srv, form, proof)
	var got exchangeAnswer
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil {
		t.Fatalf("the exchange: %d %s", w.Code, w.Body)
	}
	return got
}

// push posts a file to the import, as DPoP with a proof by key, or as a
// bearer when key is nil.
func (r *pushRig) push(t *testing.T, token string, key *ecdsa.PrivateKey, query string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	target := "/api/v1/evidence/import?" + query
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/octet-stream")
	if key != nil {
		req.Header.Set("Authorization", "DPoP "+token)
		req.Header.Set("DPoP", proved(t, key, "POST", "http://example.com/api/v1/evidence/import", token))
	} else {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.srv.Handler().ServeHTTP(w, req)
	return w
}

func sarifOf(t *testing.T, repo string) []byte {
	t.Helper()
	return []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"scanner","rules":[{"id":"R1"}]}},` +
		`"versionControlProvenance":[{"repositoryUri":"https://github.com/` + repo + `"}],` +
		`"results":[{"ruleId":"R1","level":"error","message":{"text":"x"}}]}]}`)
}

// A job pushes evidence holding nothing but what its platform gave it for
// this run and a key it made for it: the token it is given lasts minutes,
// works only with that key, and is the only credential the store keeps for
// it, as a hash; no long-lived token, and no secret, was made.
func TestPushNeedsNoStoredSecret(t *testing.T) {
	r := newPushRig(t)
	before := len(r.srv.Tokens.Tokens)
	key, thumb := programKey(t)
	got := r.exchangeJob(t, r.jobToken(t, "octo/docs", pushWorkflow), key)
	if got.TokenType != "DPoP" || got.ExpiresIn > 10*60 {
		t.Fatalf("the job was given %+v", got)
	}
	if len(r.srv.Tokens.Tokens) != before+1 {
		t.Fatalf("%d credentials were made for one job", len(r.srv.Tokens.Tokens)-before)
	}
	tok := r.srv.Tokens.Tokens[len(r.srv.Tokens.Tokens)-1]
	if tok.Key != thumb || tok.Kind != auth.KindProgram || tok.ExpiresAt-tok.CreatedAt > 600 ||
		tok.Workload["repository"] != "octo/docs" || tok.Hash == got.AccessToken {
		t.Fatalf("the job's token is %+v", tok)
	}
	if w := r.push(t, got.AccessToken, key, "format=sarif", sarifOf(t, "octo/docs")); w.Code != http.StatusCreated {
		t.Fatalf("the push: %d %s", w.Code, w.Body)
	}
	// Nothing the job held is kept anywhere in the store's files.
	b, _ := json.Marshal(r.srv.Tokens)
	if strings.Contains(string(b), got.AccessToken) {
		t.Error("the token store holds the job's token itself")
	}
	entries, err := os.ReadDir(r.srv.Store.Root())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "secret") {
			t.Errorf("a push left %s in the store", e.Name())
		}
	}
}

// A job's token names its repository, and a push is filed only under a
// pipeline's source for that repository and workflow: a job of another
// repository, a file naming another repository and a push asking for
// another repository are all refused, and write nothing.
func TestPushForOtherRepositoryRefused(t *testing.T) {
	r := newPushRig(t)
	reg := register.Open(r.srv.Store)
	key, _ := programKey(t)
	got := r.exchangeJob(t, r.jobToken(t, "octo/docs", pushWorkflow), key)
	head := reg.Head()
	if w := r.push(t, got.AccessToken, key, "format=sarif", sarifOf(t, "octo/payroll")); w.Code != http.StatusForbidden {
		t.Errorf("a file naming another repository: %d %s", w.Code, w.Body)
	}
	if w := r.push(t, got.AccessToken, key, "format=sarif&repository=octo/payroll", sarifOf(t, "octo/payroll")); w.Code != http.StatusForbidden {
		t.Errorf("a push for another repository: %d %s", w.Code, w.Body)
	}
	if reg.Head() != head {
		t.Error("a refused push wrote to the register")
	}
	// A job of the right repository running another workflow has nothing
	// to push to.
	other := r.exchangeJob(t, r.jobToken(t, "octo/docs", ".github/workflows/release.yml"), key)
	if w := r.push(t, other.AccessToken, key, "format=sarif", sarifOf(t, "octo/docs")); w.Code != http.StatusNotFound {
		t.Errorf("another workflow's push: %d %s", w.Code, w.Body)
	}
	if w := r.push(t, other.AccessToken, key, "format=sarif&source=docs-ci", sarifOf(t, "octo/docs")); w.Code != http.StatusForbidden {
		t.Errorf("another workflow naming the source: %d %s", w.Code, w.Body)
	}
	if reg.Head() != head {
		t.Error("a refused push wrote to the register")
	}
}

// The job's token works only with a fresh proof by its key: as a bearer it
// is refused, with another key's proof it is refused, with a proof used
// once already it is refused, and a pipeline's token made without a key
// does not push at all.
func TestPushWithoutDPoPRefused(t *testing.T) {
	r := newPushRig(t)
	key, _ := programKey(t)
	got := r.exchangeJob(t, r.jobToken(t, "octo/docs", pushWorkflow), key)
	body := sarifOf(t, "octo/docs")
	if w := r.push(t, got.AccessToken, nil, "format=sarif", body); w.Code != http.StatusUnauthorized {
		t.Errorf("the bound token as a bearer: %d %s", w.Code, w.Body)
	}
	other, _ := programKey(t)
	if w := r.push(t, got.AccessToken, other, "format=sarif", body); w.Code != http.StatusUnauthorized {
		t.Errorf("another key's proof: %d %s", w.Code, w.Body)
	}
	req := func(proof string) int {
		q := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/import?format=sarif", strings.NewReader(string(body)))
		q.Header.Set("Authorization", "DPoP "+got.AccessToken)
		q.Header.Set("DPoP", proof)
		w := httptest.NewRecorder()
		r.srv.Handler().ServeHTTP(w, q)
		return w.Code
	}
	proof := proved(t, key, "POST", "http://example.com/api/v1/evidence/import", got.AccessToken)
	if code := req(proof); code != http.StatusCreated {
		t.Fatalf("a push with its proof: %d", code)
	}
	if code := req(proof); code != http.StatusUnauthorized {
		t.Errorf("a proof used twice: %d", code)
	}
	if code := req(proved(t, key, "POST", "http://example.com/api/v1/sources", got.AccessToken)); code != http.StatusUnauthorized {
		t.Errorf("a proof made for another address: %d", code)
	}
	// A bound token is refused at a route that does not check a proof.
	q := httptest.NewRequest(http.MethodGet, "/api/v1/sources", nil)
	q.Header.Set("Authorization", "DPoP "+got.AccessToken)
	q.Header.Set("DPoP", proved(t, key, "GET", "http://example.com/api/v1/sources", got.AccessToken))
	w := httptest.NewRecorder()
	r.srv.Handler().ServeHTTP(w, q)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("a bound token read a route that checks no proof: %d", w.Code)
	}
	// Exchanged without a proof, the job's token is a bearer that cannot
	// push.
	unbound := r.exchangeJob(t, r.jobToken(t, "octo/docs", pushWorkflow), nil)
	if w := r.push(t, unbound.AccessToken, nil, "format=sarif", body); w.Code != http.StatusUnauthorized ||
		!strings.Contains(w.Body.String(), "bound to a key") {
		t.Errorf("an unbound pipeline's token: %d %s", w.Code, w.Body)
	}
}

// What a pipeline pushes is graded "ci", filed under its source, and the
// write is in the audit log as the job's principal.
func TestPushGradedCI(t *testing.T) {
	r := newPushRig(t)
	key, _ := programKey(t)
	got := r.exchangeJob(t, r.jobToken(t, "octo/docs", pushWorkflow), key)
	w := r.push(t, got.AccessToken, key, "format=sarif", sarifOf(t, "octo/docs"))
	var res struct {
		Grade  register.Grade `json:"grade"`
		Source string         `json:"source"`
		Facts  int            `json:"facts"`
		Commit string         `json:"commit"`
	}
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &res) != nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if res.Grade != register.GradeCI || res.Source != "docs-ci" || res.Facts == 0 || res.Commit == "" {
		t.Errorf("the push: %+v", res)
	}
	reg := register.Open(r.srv.Store)
	entries, _, err := reg.List(register.KindObservation, 0, 100)
	if err != nil || len(entries) == 0 {
		t.Fatalf("%d facts, %v", len(entries), err)
	}
	for _, e := range entries {
		if o := e.Record.(register.Observation); o.Grade != register.GradeCI {
			t.Errorf("a pushed fact is graded %s", o.Grade)
		}
	}
	recorded := false
	for _, a := range r.audited {
		recorded = recorded || a.Action == register.AuditAction && a.Principal == "ci:docs" && a.Kind == audit.KindService
	}
	if !recorded {
		t.Errorf("the push is not in the audit log as the job: %+v", r.audited)
	}
	st, err := sources.Open(reg).Standings(time.Now())
	if err != nil || len(st) != 1 || st[0].Stale || st[0].Reports != 1 {
		t.Errorf("the pipeline's source after a push: %+v %v", st, err)
	}
}
