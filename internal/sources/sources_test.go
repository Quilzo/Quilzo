// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/connector"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/vault"
)

// clock is a fake clock a test moves by hand.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

var day0 = time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC)

const tenant = "72f988bf-86f1-41af-91ab-2d7cd011db47"

func allow(auth.Action, string) error { return nil }

var person = register.Actor{Name: "priya", Subject: "d0000000000000000000000000000001", Kind: audit.KindHuman,
	Verified: true, May: allow}

// tool answers a recipe's requests from the recorded responses in
// testdata, as the tool's documentation shows them.
type tool struct {
	t     *testing.T
	route func(r *http.Request) (status int, body string, header http.Header)
	seen  []string
	// asked is every request, for a test that reads what was sent.
	asked []*http.Request
}

func (f *tool) Do(r *http.Request) (*http.Response, error) {
	f.seen = append(f.seen, r.Method+" "+r.URL.Host+r.URL.Path)
	f.asked = append(f.asked, r)
	status, body, header := f.route(r)
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)),
		Request: r}, nil
}

func fixture(t *testing.T, recipe, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", recipe, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// world is a register on an encrypted store of its own, its sources on a
// fake clock with a tool answering from fixtures, and the audit entries
// written.
type world struct {
	t       *testing.T
	reg     *register.Register
	src     *Sources
	clock   *clock
	tool    *tool
	audited []audit.Record
}

func newWorld(t *testing.T, encrypted bool) *world {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if encrypted {
		kr, err := vault.NewKeyring("k1", day0)
		if err != nil {
			t.Fatal(err)
		}
		s.WithKeys(kr)
	}
	w := &world{t: t, clock: &clock{t: day0}}
	w.reg = register.Open(s)
	w.reg.Audit = func(r audit.Record) error { w.audited = append(w.audited, r); return nil }
	w.reg.Now = w.clock.now
	w.src = Open(w.reg)
	w.src.Now = w.clock.now
	w.src.Ing.Now = w.clock.now
	w.src.Sleep = func(context.Context, time.Duration) error { return nil }
	w.tool = &tool{t: t}
	w.src.Client = w.tool
	return w
}

// add adds a connector's source as a person, with its credentials.
func (w *world) add(name, recipe string, params map[string]string, creds map[string]string) register.Source {
	w.t.Helper()
	owner, err := w.reg.SubjectFor("priya@contoso.example", "person")
	if err != nil {
		w.t.Fatal(err)
	}
	src, err := ConnectorSource(Connector{Name: name, Recipe: recipe, Params: params, Owner: owner})
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := w.src.Add(person, src); err != nil {
		w.t.Fatal(err)
	}
	for k, v := range creds {
		if err := w.src.Vault.Set(name, k, v); err != nil {
			w.t.Fatal(err)
		}
	}
	return src
}

func (w *world) run(name string) Report {
	w.t.Helper()
	rep, err := w.src.Run(context.Background(), name, nil)
	if err != nil {
		w.t.Fatalf("the run of %s: %v", name, err)
	}
	return rep
}

// facts is every observation, by the account or asset it is about and the
// fact's name.
func (w *world) facts() map[register.ID]map[string]register.Observation {
	w.t.Helper()
	out := map[register.ID]map[string]register.Observation{}
	entries, _, err := w.reg.List(register.KindObservation, 0, 5000)
	if err != nil {
		w.t.Fatal(err)
	}
	for _, e := range entries {
		o := e.Record.(register.Observation)
		if out[o.About] == nil {
			out[o.About] = map[string]register.Observation{}
		}
		out[o.About][o.Fact] = o
	}
	return out
}

// subject is the pseudonym the subject map holds for a name.
func (w *world) subject(name string) register.ID {
	w.t.Helper()
	id, ok, err := w.reg.Side().Lookup(name)
	if err != nil || !ok {
		w.t.Fatalf("%s has no pseudonym: %v", name, err)
	}
	return register.ID(id)
}

// asset is the identifier of an asset the source reported.
func (w *world) asset(source register.Source, typ register.AssetType, ref string) register.ID {
	w.t.Helper()
	srcID, _ := register.IDOf(source)
	id, err := register.IDOf(register.Asset{Source: srcID, Ref: ref, Type: typ})
	if err != nil {
		w.t.Fatal(err)
	}
	return id
}

func value(t *testing.T, facts map[register.ID]map[string]register.Observation, about register.ID, fact string) any {
	t.Helper()
	o, ok := facts[about][fact]
	if !ok {
		t.Fatalf("no %s about %s", fact, about)
	}
	return o.Value.Value()
}

// graphToken is an unsigned token carrying roles, which is all the engine
// reads of it: Graph verifies its own tokens.
func graphToken(roles ...string) string {
	b, _ := json.Marshal(map[string]any{"roles": roles, "tid": tenant})
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
}

var entraRoles = []string{"User.Read.All", "AuditLog.Read.All", "RoleManagement.Read.Directory", "Policy.Read.All",
	"DeviceManagementManagedDevices.Read.All"}

// entra answers Graph from the fixtures; refuse names the endpoints that
// answer 403.
func entra(t *testing.T, token string, refuse ...string) func(*http.Request) (int, string, http.Header) {
	return func(r *http.Request) (int, string, http.Header) {
		for _, p := range refuse {
			if strings.HasSuffix(r.URL.Path, p) {
				return http.StatusForbidden, fixture(t, "entra", "forbidden.json"), nil
			}
		}
		switch {
		case r.URL.Host == "login.microsoftonline.com" && r.URL.Path == "/"+tenant+"/oauth2/v2.0/token":
			return 200, fmt.Sprintf(`{"token_type":"Bearer","expires_in":3599,"access_token":%q}`, token), nil
		case r.URL.Path == "/v1.0/users" && r.URL.Query().Get("$skiptoken") == "":
			return 200, fixture(t, "entra", "users-1.json"), nil
		case r.URL.Path == "/v1.0/users":
			return 200, fixture(t, "entra", "users-2.json"), nil
		case r.URL.Path == "/v1.0/reports/authenticationMethods/userRegistrationDetails":
			return 200, fixture(t, "entra", "registration.json"), nil
		case r.URL.Path == "/v1.0/roleManagement/directory/roleAssignments":
			return 200, fixture(t, "entra", "roles.json"), nil
		case r.URL.Path == "/v1.0/identity/conditionalAccess/policies":
			return 200, fixture(t, "entra", "policies.json"), nil
		case r.URL.Path == "/v1.0/deviceManagement/managedDevices":
			return 200, fixture(t, "entra", "devices.json"), nil
		}
		t.Errorf("Graph was asked for %s", r.URL)
		return 404, `{}`, nil
	}
}

var entraCreds = map[string]string{"entra-client-id": "11111111-2222-3333-4444-555555555555", "entra-client-secret": "a-client-secret"}

// The recorded Graph responses become Observations by subject, each graded
// "pulled by a connector", with its source, the run's time on its seal and
// the digest of the sealed run.
func TestEntraFixturesToObservations(t *testing.T) {
	w := newWorld(t, true)
	src := w.add("entra-contoso", "entra", map[string]string{"tenant": tenant}, entraCreds)
	w.tool.route = entra(t, graphToken(entraRoles...))
	rep := w.run("entra-contoso")
	if !rep.OK || rep.Written == 0 || rep.Raw == "" {
		t.Fatalf("%+v", rep)
	}
	facts := w.facts()
	ann, bo := w.subject("ann.lee@contoso.example"), w.subject("bo.chen@contoso.example")
	guest := w.subject("cat_fabrikam.example#EXT#@contoso.example")
	robot := w.subject("entra-object:9a8b7c6d-0000-4000-8000-00000000aaaa")
	for _, c := range []struct {
		about register.ID
		fact  string
		want  any
	}{
		{ann, "account.enabled", true}, {ann, "role.privileged", true}, {ann, "role.global-admin", true},
		{ann, "mfa.registered", true}, {ann, "mfa.phishing-resistant", true}, {ann, "account.admin", true},
		{ann, "mfa.methods", "fido2,microsoftAuthenticatorPush"},
		{bo, "role.privileged", false}, {bo, "role.count", 1.0}, {bo, "mfa.phishing-resistant", false},
		{guest, "account.guest", true}, {guest, "account.enabled", false}, {guest, "mfa.registered", false},
		{robot, "role.privileged", true},
	} {
		if got := value(t, facts, c.about, c.fact); got != c.want {
			t.Errorf("%s about %s is %v, want %v", c.fact, c.about, got, c.want)
		}
	}
	tenantID := w.asset(src, "cloud-resource", "entra-tenant/"+tenant)
	if value(t, facts, tenantID, "ca.mfa-for-everyone") != true || value(t, facts, tenantID, "ca.phishing-resistant-for-everyone") != false {
		t.Error("the tenant's Conditional Access was read wrong")
	}
	mfa := w.asset(src, "other", "conditional-access/a1d3b0c4-0001-4000-8000-000000000002")
	if value(t, facts, mfa, "policy.requires-mfa") != true || value(t, facts, mfa, "policy.all-users") != true {
		t.Error("the MFA policy was read wrong")
	}
	legacy := w.asset(src, "other", "conditional-access/a1d3b0c4-0001-4000-8000-000000000003")
	if value(t, facts, legacy, "policy.blocks-legacy") != true || value(t, facts, legacy, "policy.state") != "enabledForReportingButNotEnforced" {
		t.Error("the legacy block was read wrong")
	}
	laptop := w.asset(src, "device", "PF3ABC12")
	if value(t, facts, laptop, "disk.encrypted") != true || value(t, facts, w.asset(src, "device", "C02ZK1X9MD6T"), "disk.encrypted") != false {
		t.Error("the devices were read wrong")
	}

	srcID, _ := register.IDOf(src)
	for _, byAbout := range facts {
		for _, o := range byAbout {
			if o.Grade != register.GradeConnector || o.Source != srcID || o.Raw != rep.Raw || o.Place == "" {
				t.Fatalf("an observation is not graded, sourced and sealed: %+v", o)
			}
		}
	}
	files, _, err := w.src.Ing.Files(0, 10)
	if err != nil || len(files) != 1 {
		t.Fatalf("%d sealed runs, %v", len(files), err)
	}
	if rf := files[0].Record; rf.Digest != rep.Raw || rf.Grade != register.GradeConnector || !rf.Received.At().Equal(day0) ||
		rf.Format != "pull" || rf.Source != srcID {
		t.Errorf("the run's seal: %+v", rf)
	}
	// The sealed run is evidence that checks, read again from its seal.
	checks, err := w.src.Ing.Verify()
	if err != nil || len(checks) != 1 || !checks[0].OK() || checks[0].Replay != "same" {
		t.Errorf("the run does not check: %+v %v", checks, err)
	}
	// Only GETs reached Graph, and the token endpoint only its one POST.
	for _, s := range w.tool.seen {
		if !strings.HasPrefix(s, "GET graph.microsoft.com/") && s != "POST login.microsoftonline.com/"+tenant+"/oauth2/v2.0/token" {
			t.Errorf("a run sent %s", s)
		}
	}
}

// The same responses read again write nothing at all; read again later,
// the run's seal is new and no fact changes.
func TestEntraReplayIdempotent(t *testing.T) {
	w := newWorld(t, true)
	w.add("entra-contoso", "entra", map[string]string{"tenant": tenant}, entraCreds)
	w.tool.route = entra(t, graphToken(entraRoles...))
	first := w.run("entra-contoso")
	before := w.reg.Head()
	again := w.run("entra-contoso")
	if again.Written != 0 || again.Receipt.Commit != "" || w.reg.Head() != before || again.Raw != first.Raw {
		t.Errorf("the same run read again wrote %d record(s) in %q", again.Written, again.Receipt.Commit)
	}
	// An hour later the tool says the same: nothing is written, and the
	// source has reported, by its seal.
	w.clock.t = day0.Add(time.Hour)
	later := w.run("entra-contoso")
	if later.Written != 0 || w.reg.Head() != before {
		t.Errorf("an hour later, a run of the same facts wrote %d record(s)", later.Written)
	}
	st, err := w.src.Standings(w.clock.t)
	if err != nil || len(st) != 1 || !st[0].Last.Equal(w.clock.t) {
		t.Errorf("the source last reported at %+v (%v)", st, err)
	}
	// A change in one fact is written as the change, under the new run.
	w.clock.t = day0.Add(2 * time.Hour)
	w.tool.route = func(r *http.Request) (int, string, http.Header) {
		status, body, h := entra(t, graphToken(entraRoles...))(r)
		if r.URL.Path == "/v1.0/deviceManagement/managedDevices" {
			body = strings.Replace(body, `"isEncrypted": false`, `"isEncrypted": true`, 1)
		}
		return status, body, h
	}
	changed := w.run("entra-contoso")
	if changed.Written == 0 || changed.Raw == first.Raw {
		t.Fatalf("a changed fact wrote %d record(s)", changed.Written)
	}
	if o := w.facts()[w.asset(w.mustSource("entra-contoso"), "device", "C02ZK1X9MD6T")]["disk.encrypted"]; o.Value.Value() != true || o.Raw != changed.Raw {
		t.Errorf("the changed fact is %+v", o)
	}
}

func (w *world) mustSource(name string) register.Source {
	w.t.Helper()
	src, _, err := w.src.Source(name)
	if err != nil {
		w.t.Fatal(err)
	}
	return src
}

// A 403 on the registration report is a licence gap: the run says so, the
// tenant carries it as a fact, and everything else is read and written.
func TestRegistrationDetails403IsLicenceGap(t *testing.T) {
	w := newWorld(t, true)
	src := w.add("entra-contoso", "entra", map[string]string{"tenant": tenant}, entraCreds)
	w.tool.route = entra(t, graphToken(entraRoles...), "/userRegistrationDetails")
	rep := w.run("entra-contoso")
	if !rep.OK {
		t.Fatalf("a licence gap failed the run: %s", rep.Problem)
	}
	gapNoted := false
	for _, n := range rep.Notes {
		gapNoted = gapNoted || strings.Contains(n, "licence gap") && strings.Contains(n, "P1 or P2")
	}
	if !gapNoted {
		t.Errorf("the notes do not name the licence gap: %v", rep.Notes)
	}
	facts := w.facts()
	if v := value(t, facts, w.asset(src, "cloud-resource", "entra-tenant/"+tenant), "report.registration"); v != "licence gap" {
		t.Errorf("the tenant's registration report is %v", v)
	}
	ann := w.subject("ann.lee@contoso.example")
	if _, ok := facts[ann]["mfa.registered"]; ok {
		t.Error("a fact was written from a report that was refused")
	}
	if value(t, facts, ann, "role.privileged") != true {
		t.Error("the rest of the run was not read")
	}

	// Any other refusal is a failure, and nothing at all is written.
	w2 := newWorld(t, true)
	w2.add("entra-contoso", "entra", map[string]string{"tenant": tenant}, entraCreds)
	w2.tool.route = entra(t, graphToken(entraRoles...), "/roleAssignments")
	rep, err := w2.src.Run(context.Background(), "entra-contoso", nil)
	if err == nil || rep.OK || !strings.Contains(err.Error(), "nothing was written") {
		t.Errorf("a refused role list: %v", err)
	}
	if n, _, _ := w2.reg.List(register.KindObservation, 0, 1); len(n) != 0 {
		t.Error("a run that did not read everything wrote facts")
	}
	if a, _ := w2.src.LastAttempt("entra-contoso"); a == nil || a.OK || a.Problem == "" {
		t.Errorf("the failed run was not kept as the last attempt: %+v", a)
	}
}

// A credential that holds more than its recipe needs is refused before
// anything is read with it, for each recipe in the way its tool says what
// a credential may do.
func TestTokenWithExtraRolesRefused(t *testing.T) {
	t.Run("entra", func(t *testing.T) {
		for name, token := range map[string]string{
			"a write permission as well": graphToken(append(entraRoles, "User.ReadWrite.All")...),
			"another permission":         graphToken(append(entraRoles, "Mail.Read")...),
		} {
			w := newWorld(t, true)
			w.add("entra-contoso", "entra", map[string]string{"tenant": tenant}, entraCreds)
			w.tool.route = entra(t, token)
			if _, err := w.src.Run(context.Background(), "entra-contoso", nil); err == nil {
				t.Errorf("%s: the run went ahead", name)
			}
			for _, s := range w.tool.seen {
				if strings.Contains(s, "graph.microsoft.com") {
					t.Errorf("%s: Graph was read with it: %s", name, s)
				}
			}
		}
	})
	t.Run("github", func(t *testing.T) {
		w := newWorld(t, true)
		w.add("github-octo", "github", githubParams, githubCreds(t))
		w.tool.route = github(t, `{"token":"v1.installation-token-for-tests","expires_at":"2026-11-25T11:00:00Z",`+
			`"permissions":{"members":"read","organization_administration":"read","administration":"write","metadata":"read"}}`)
		if _, err := w.src.Run(context.Background(), "github-octo", nil); err == nil || !strings.Contains(err.Error(), "administration:write") {
			t.Errorf("a token that can write: %v", err)
		}
		if len(w.tool.seen) != 1 {
			t.Errorf("GitHub was read with it: %v", w.tool.seen)
		}
	})
	t.Run("google-workspace", func(t *testing.T) {
		w := newWorld(t, true)
		w.add("workspace", "google-workspace", nil, workspaceCreds(t))
		w.tool.route = workspace(t, `{"access_token":"google-access-token-for-tests","expires_in":3599,`+
			`"scope":"https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.directory.user"}`)
		if _, err := w.src.Run(context.Background(), "workspace", nil); err == nil {
			t.Error("a token that can change users was used")
		}
		if len(w.tool.seen) != 1 {
			t.Errorf("the directory was read with it: %v", w.tool.seen)
		}
	})
	t.Run("okta", func(t *testing.T) {
		w := newWorld(t, true)
		w.add("okta-northwind", "okta", map[string]string{"org": "northwind"}, oktaCreds)
		w.tool.route = okta(t, `[{"type":"READ_ONLY_ADMIN","status":"ACTIVE"},{"type":"SUPER_ADMIN","status":"ACTIVE"}]`)
		_, err := w.src.Run(context.Background(), "okta-northwind", nil)
		if !errors.Is(err, errRefusedGrant) || !strings.Contains(err.Error(), "SUPER_ADMIN") {
			t.Errorf("a super administrator's token: %v", err)
		}
		if len(w.tool.seen) != 1 {
			t.Errorf("Okta was read past the token's roles: %v", w.tool.seen)
		}
	})
}

// An account is its user principal name in the subject map, and its
// pseudonym in the register: the name is in no record.
func TestUPNStoredAsSubject(t *testing.T) {
	w := newWorld(t, true)
	w.add("entra-contoso", "entra", map[string]string{"tenant": tenant}, entraCreds)
	w.tool.route = entra(t, graphToken(entraRoles...))
	w.run("entra-contoso")
	ann := w.subject("ann.lee@contoso.example")
	e, err := w.reg.Get(ann)
	if err != nil || e.Record.(register.Subject).Type != "account" {
		t.Fatalf("the account's Subject record: %+v %v", e, err)
	}
	p, err := w.reg.Person(ann)
	if err != nil || p.Name != "ann.lee@contoso.example" {
		t.Errorf("the subject map holds %+v", p)
	}
	for _, spec := range register.Kinds() {
		k := spec.Kind
		entries, _, err := w.reg.List(k, 0, 5000)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			b, _ := json.Marshal(e.Record)
			for _, name := range []string{"ann.lee", "bo.chen", "contoso.example", "Ann Lee"} {
				if strings.Contains(string(b), name) {
					t.Errorf("a %s record holds %q: %s", k, name, b)
				}
			}
		}
	}
}

var githubParams = map[string]string{"org": "octo-example", "installation": "4242"}

var (
	appKeyOnce sync.Once
	appKey     *rsa.PrivateKey
)

// testKey is an RSA key made once, for the credentials that sign.
func testKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	appKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		appKey = k
	})
	pemText := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(appKey)})
	return appKey, string(pemText)
}

func githubCreds(t *testing.T) map[string]string {
	_, key := testKey(t)
	return map[string]string{"github-app-id": "123456", "github-app-key": key}
}

// github answers the REST API from the fixtures, with the installation
// token the token endpoint gives.
func github(t *testing.T, token string) func(*http.Request) (int, string, http.Header) {
	const org = "/orgs/octo-example"
	return func(r *http.Request) (int, string, http.Header) {
		q := r.URL.Query()
		switch p := r.URL.Path; {
		case p == "/app/installations/4242/access_tokens":
			return 201, token, nil
		case p == org:
			return 200, fixture(t, "github", "org.json"), nil
		case p == org+"/members" && q.Get("filter") == "2fa_disabled":
			return 200, fixture(t, "github", "without-2fa.json"), nil
		case p == org+"/members" && q.Get("role") == "admin":
			return 200, fixture(t, "github", "owners.json"), nil
		case p == org+"/members" && q.Get("page") == "2":
			return 200, fixture(t, "github", "members-2.json"), nil
		case p == org+"/members":
			h := http.Header{}
			h.Set("Link", `<https://api.github.com/orgs/octo-example/members?per_page=100&page=2>; rel="next", `+
				`<https://api.github.com/orgs/octo-example/members?per_page=100&page=2>; rel="last"`)
			return 200, fixture(t, "github", "members-1.json"), h
		case p == org+"/repos":
			return 200, fixture(t, "github", "repos.json"), nil
		case p == org+"/actions/permissions":
			return 200, fixture(t, "github", "actions.json"), nil
		case p == org+"/actions/permissions/workflow":
			return 200, fixture(t, "github", "workflow.json"), nil
		}
		for _, repo := range []struct{ name, branch string }{{"api", "main"}, {"web", "trunk"}, {"old", "master"}} {
			base := "/repos/octo-example/" + repo.name
			switch r.URL.Path {
			case base + "/branches/" + repo.branch:
				return 200, fixture(t, "github", "branch-"+repo.name+".json"), nil
			case base + "/rules/branches/" + repo.branch:
				return 200, fixture(t, "github", "rules-"+repo.name+".json"), nil
			case base + "/actions/permissions":
				return 200, fixture(t, "github", "repo-actions-"+repo.name+".json"), nil
			}
		}
		t.Errorf("GitHub was asked for %s", r.URL)
		return 404, `{"message":"Not Found"}`, nil
	}
}

// The App signs a JWT of ten minutes at most, issued a minute early by its
// ID, with its own key and the standard library's RS256; it is what asks
// for the installation token, and goes nowhere else.
func TestGitHubAppJWT(t *testing.T) {
	key, _ := testKey(t)
	signed, err := connector.AppJWT(key, "123456", day0)
	if err != nil {
		t.Fatal(err)
	}
	head, claims := decodeJWT(t, signed, &key.PublicKey)
	if head["alg"] != "RS256" || head["typ"] != "JWT" {
		t.Errorf("header %v", head)
	}
	iat, exp := int64(claims["iat"].(float64)), int64(claims["exp"].(float64))
	if claims["iss"] != "123456" || iat != day0.Add(-time.Minute).Unix() || exp-iat > 600 || exp <= day0.Unix() {
		t.Errorf("claims %v", claims)
	}

	w := newWorld(t, true)
	w.add("github-octo", "github", githubParams, githubCreds(t))
	w.tool.route = github(t, fixture(t, "github", "token.json"))
	w.run("github-octo")
	var bearer []string
	for _, r := range w.tool.asked {
		a := r.Header.Get("Authorization")
		switch {
		case r.URL.Path == "/app/installations/4242/access_tokens":
			if r.Method != http.MethodPost {
				t.Errorf("the token was asked for with %s", r.Method)
			}
			jwt, _ := strings.CutPrefix(a, "Bearer ")
			decodeJWT(t, jwt, &key.PublicKey)
			body, _ := io.ReadAll(r.Body)
			var asked struct{ Permissions map[string]string }
			_ = json.Unmarshal(body, &asked)
			if len(asked.Permissions) != 4 || asked.Permissions["administration"] != "read" {
				t.Errorf("the token was asked for %s", body)
			}
		default:
			bearer = append(bearer, a)
		}
	}
	for _, a := range bearer {
		if a != "Bearer v1.installation-token-for-tests" {
			t.Fatalf("a read carried %q, not the installation token", a)
		}
	}
}

func decodeJWT(t *testing.T, token string, pub *rsa.PublicKey) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("%q is not a JWT", token)
	}
	if err := verifyRS256(pub, parts[0]+"."+parts[1], parts[2]); err != nil {
		t.Fatalf("the JWT's signature: %v", err)
	}
	var head, claims map[string]any
	for i, into := range []*map[string]any{&head, &claims} {
		b, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil || json.Unmarshal(b, into) != nil {
			t.Fatalf("part %d of the JWT", i)
		}
	}
	return head, claims
}

// Branch protection is read per repository, by classic protection and by
// the rulesets that apply to its default branch, and named for which.
func TestRulesetsAndProtectionFixtures(t *testing.T) {
	w := newWorld(t, true)
	src := w.add("github-octo", "github", githubParams, githubCreds(t))
	w.tool.route = github(t, fixture(t, "github", "token.json"))
	w.run("github-octo")
	facts := w.facts()
	api, web, old := w.asset(src, "repository", "octo-example/api"), w.asset(src, "repository", "octo-example/web"),
		w.asset(src, "repository", "octo-example/old")
	for _, c := range []struct {
		about register.ID
		fact  string
		want  any
	}{
		{api, "branch.protected", true}, {api, "ruleset.pull-request", false}, {api, "branch.protection", "classic"},
		{web, "branch.protected", false}, {web, "ruleset.pull-request", true}, {web, "ruleset.approvals", 2.0},
		{web, "ruleset.no-force-push", true}, {web, "ruleset.no-deletion", true}, {web, "ruleset.status-checks", true},
		{web, "branch.protection", "rulesets"}, {web, "repo.private", false},
		{old, "branch.protection", "none"}, {old, "repo.archived", true}, {old, "actions.enabled", false},
		{api, "actions.allowed", "selected"},
	} {
		if got := value(t, facts, c.about, c.fact); got != c.want {
			t.Errorf("%s of %s is %v, want %v", c.fact, c.about, got, c.want)
		}
	}
	// A repository's description is somebody else's words and is not kept.
	b, _ := json.Marshal(facts)
	if strings.Contains(string(b), "Ignore previous instructions") {
		t.Error("a field the recipe does not declare reached the register")
	}
}

// The organisation's two-factor requirement is a fact about it, and each
// member's second factor a fact about them, from the list GitHub gives its
// owners; where that list is refused, the run says so and writes no member
// as having one or not.
func TestOrg2FAObservation(t *testing.T) {
	w := newWorld(t, true)
	src := w.add("github-octo", "github", githubParams, githubCreds(t))
	w.tool.route = github(t, fixture(t, "github", "token.json"))
	w.run("github-octo")
	facts := w.facts()
	orgID := w.asset(src, "other", "github-org/octo-example")
	if value(t, facts, orgID, "org.2fa-required") != true || value(t, facts, orgID, "actions.token-permissions") != "read" {
		t.Error("the organisation's settings were read wrong")
	}
	ann, bo, cat := w.subject("github:ann-lee"), w.subject("github:bochen"), w.subject("github:cat-dev")
	if value(t, facts, ann, "2fa.enabled") != true || value(t, facts, bo, "2fa.enabled") != true ||
		value(t, facts, cat, "2fa.enabled") != false {
		t.Error("the members' second factors were read wrong")
	}
	if value(t, facts, ann, "org.owner") != true || value(t, facts, cat, "org.owner") != false {
		t.Error("the owners were read wrong")
	}

	w2 := newWorld(t, true)
	src2 := w2.add("github-octo", "github", githubParams, githubCreds(t))
	inner := github(t, fixture(t, "github", "token.json"))
	w2.tool.route = func(r *http.Request) (int, string, http.Header) {
		if r.URL.Query().Get("filter") == "2fa_disabled" {
			return 403, `{"message":"Must be an organization owner"}`, nil
		}
		return inner(r)
	}
	rep := w2.run("github-octo")
	facts = w2.facts()
	if _, ok := facts[w2.subject("github:cat-dev")]["2fa.enabled"]; ok {
		t.Error("a member's second factor was written when the list was refused")
	}
	if value(t, facts, w2.asset(src2, "other", "github-org/octo-example"), "report.without-2fa") != "licence gap" {
		t.Error("the refused list is not recorded")
	}
	if !strings.Contains(strings.Join(rep.Notes, " "), "organisation owners") {
		t.Errorf("the notes: %v", rep.Notes)
	}
}

func workspaceCreds(t *testing.T) map[string]string {
	_, key := testKey(t)
	sa, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "reader@quilzo-example.iam.gserviceaccount.com",
		"private_key": key, "token_uri": "https://evil.example/token"})
	return map[string]string{"google-service-account": string(sa), "google-admin-user": "reader@fabrikam.example"}
}

func workspace(t *testing.T, token string) func(*http.Request) (int, string, http.Header) {
	return func(r *http.Request) (int, string, http.Header) {
		switch {
		case r.URL.Host == "oauth2.googleapis.com" && r.URL.Path == "/token":
			return 200, token, nil
		case r.URL.Path == "/admin/directory/v1/users" && r.URL.Query().Get("pageToken") == "":
			return 200, fixture(t, "google-workspace", "users.json"), nil
		case r.URL.Path == "/admin/directory/v1/users":
			return 200, fixture(t, "google-workspace", "users-2.json"), nil
		}
		t.Errorf("Google was asked for %s", r.URL)
		return 404, `{}`, nil
	}
}

// Every account in the directory, by its primary address, with its
// administrator role and its 2-Step Verification.
func TestWorkspaceFixturesToObservations(t *testing.T) {
	w := newWorld(t, true)
	w.add("workspace", "google-workspace", nil, workspaceCreds(t))
	w.tool.route = workspace(t, fixture(t, "google-workspace", "token.json"))
	w.run("workspace")
	facts := w.facts()
	ann, bo, left := w.subject("ann.lee@fabrikam.example"), w.subject("bo.chen@fabrikam.example"), w.subject("left@fabrikam.example")
	for _, c := range []struct {
		about register.ID
		fact  string
		want  any
	}{
		{ann, "account.admin", true}, {ann, "2sv.enforced", true}, {bo, "2sv.enrolled", false},
		{bo, "account.delegated-admin", true}, {left, "account.suspended", true}, {left, "account.archived", true},
	} {
		if got := value(t, facts, c.about, c.fact); got != c.want {
			t.Errorf("%s is %v, want %v", c.fact, got, c.want)
		}
	}
	// The key file's own token address is not believed: the assertion went
	// to the declared token host.
	for _, s := range w.tool.seen {
		if strings.Contains(s, "evil.example") {
			t.Errorf("a request went to %s", s)
		}
	}
}

var oktaCreds = map[string]string{"okta-api-token": "00a1b2c3d4e5f6g7h8i9"}

func okta(t *testing.T, grant string) func(*http.Request) (int, string, http.Header) {
	ids := map[string]string{"00u1ann0000000000001": "ann", "00u1bo00000000000002": "bo", "00u1cat0000000000003": "cat"}
	return func(r *http.Request) (int, string, http.Header) {
		if r.Header.Get("Authorization") != "SSWS "+oktaCreds["okta-api-token"] {
			t.Errorf("Okta was sent %q", r.Header.Get("Authorization"))
		}
		p := r.URL.Path
		switch {
		case p == "/api/v1/users/me/roles":
			return 200, grant, nil
		case p == "/api/v1/users":
			return 200, fixture(t, "okta", "users.json"), nil
		case p == "/api/v1/iam/assignees/users":
			return 200, fixture(t, "okta", "admins.json"), nil
		case p == "/api/v1/policies":
			return 200, fixture(t, "okta", "policies.json"), nil
		}
		for id, who := range ids {
			switch p {
			case "/api/v1/users/" + id + "/factors":
				return 200, fixture(t, "okta", "factors-"+who+".json"), nil
			case "/api/v1/users/" + id + "/roles":
				return 200, fixture(t, "okta", "admin-roles-"+who+".json"), nil
			}
		}
		t.Errorf("Okta was asked for %s", r.URL)
		return 404, `{}`, nil
	}
}

// Every user by their login, their factors, and who administers Okta.
func TestOktaFixturesToObservations(t *testing.T) {
	w := newWorld(t, true)
	src := w.add("okta-northwind", "okta", map[string]string{"org": "northwind"}, oktaCreds)
	w.tool.route = okta(t, fixture(t, "okta", "grant.json"))
	w.run("okta-northwind")
	facts := w.facts()
	ann, bo, cat := w.subject("ann.lee@northwind.example"), w.subject("bo.chen@northwind.example"), w.subject("cat@northwind.example")
	for _, c := range []struct {
		about register.ID
		fact  string
		want  any
	}{
		{ann, "mfa.phishing-resistant", true}, {ann, "role.super-admin", true}, {ann, "account.admin", true},
		{ann, "mfa.methods", "token:software:totp,webauthn"},
		{bo, "mfa.enrolled", true}, {bo, "mfa.phishing-resistant", false}, {bo, "account.admin", false},
		{cat, "mfa.enrolled", false}, {cat, "account.active", false}, {cat, "account.status", "SUSPENDED"},
		{w.asset(src, "other", "okta-policy/00p1sign00000000002"), "policy.status", "INACTIVE"},
	} {
		if got := value(t, facts, c.about, c.fact); got != c.want {
			t.Errorf("%s is %v, want %v", c.fact, got, c.want)
		}
	}
	for _, s := range w.tool.seen {
		if !strings.HasPrefix(s, "GET northwind.okta.com/") {
			t.Errorf("a run sent %s", s)
		}
	}
}

// A source reaches the hosts its recipe names and no others: one naming
// another host does not run, and a request for another host, or another
// port, is not sent.
func TestSourceReachesOnlyItsRecipesHosts(t *testing.T) {
	w := newWorld(t, true)
	src := w.add("entra-contoso", "entra", map[string]string{"tenant": tenant}, entraCreds)
	w.tool.route = entra(t, graphToken(entraRoles...))
	if want := []string{"graph.microsoft.com", "login.microsoftonline.com"}; strings.Join(src.Hosts, " ") != strings.Join(want, " ") {
		t.Errorf("the source reaches %v", src.Hosts)
	}
	src.Hosts = append(src.Hosts, "evil.example.com")
	if _, err := w.reg.Put(person, "a host added by hand", src); err != nil {
		t.Fatal(err)
	}
	if _, err := w.src.Run(context.Background(), "entra-contoso", nil); !errors.Is(err, ErrEgress) {
		t.Errorf("a source naming a second host ran: %v", err)
	}
	if len(w.tool.seen) != 0 {
		t.Errorf("it reached %v", w.tool.seen)
	}
	a := allowlist{inner: w.tool, hosts: []string{"graph.microsoft.com"}}
	for _, u := range []string{"https://evil.example.com/v1.0/users", "http://graph.microsoft.com/v1.0/users",
		"https://graph.microsoft.com:8443/v1.0/users"} {
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		if _, err := a.Do(req); !errors.Is(err, ErrEgress) {
			t.Errorf("%s was sent: %v", u, err)
		}
	}
}

// A credential is kept only sealed in the vault, bound to its source and
// its name; a store with no keyring keeps none; a run asks the vault for
// the names its manifest declares and nothing else, and never the
// environment.
func TestCredentialsOnlyInVault(t *testing.T) {
	plain := newWorld(t, false)
	if err := plain.src.Vault.Set("entra-contoso", "entra-client-secret", "a-client-secret"); !errors.Is(err, ErrNoKeyring) {
		t.Errorf("a credential was kept on a store with no keyring: %v", err)
	}

	w := newWorld(t, true)
	src := w.add("entra-contoso", "entra", map[string]string{"tenant": tenant}, entraCreds)
	for _, b := range []any{src} {
		j, _ := json.Marshal(b)
		if strings.Contains(string(j), "a-client-secret") {
			t.Error("the source record holds the credential")
		}
	}
	err := filepath.Walk(w.reg.Store.Root(), func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		if strings.Contains(string(b), "a-client-secret") {
			t.Errorf("%s holds the credential in the clear", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := w.src.Vault.Get("entra-contoso", "entra-client-secret"); err != nil || got != "a-client-secret" {
		t.Errorf("the vault gave back %q, %v", got, err)
	}
	// Bound to its source and name: a file moved to stand for another's
	// does not open.
	dir := filepath.Join(w.reg.Store.Root(), "sources", "credentials")
	if err := os.MkdirAll(filepath.Join(dir, "other"), 0o700); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "entra-contoso", "entra-client-secret"))
	_ = os.WriteFile(filepath.Join(dir, "other", "entra-client-secret"), b, 0o600)
	if _, err := w.src.Vault.Get("other", "entra-client-secret"); err == nil {
		t.Error("a credential moved to another source opened")
	}
	// A run asks for the manifest's names only.
	m, _ := recipes["entra"].Manifest("", map[string]string{"tenant": tenant})
	sec := w.src.Vault.secretsFor("entra-contoso", m)
	if _, err := sec.Secret("okta-api-token"); err == nil {
		t.Error("a run could ask the vault for a credential its recipe does not name")
	}
	// The environment is not where a run looks.
	t.Setenv("QUILZO_SECRET_ENTRA_CLIENT_SECRET", "from-the-environment")
	t.Setenv("ENTRA_CLIENT_SECRET", "from-the-environment")
	if err := w.src.Vault.Remove("entra-contoso", "entra-client-secret"); err != nil {
		t.Fatal(err)
	}
	var sentSecret string
	w.tool.route = func(r *http.Request) (int, string, http.Header) {
		_ = r.ParseForm()
		sentSecret = r.PostForm.Get("client_secret")
		return 401, `{"error":"invalid_client"}`, nil
	}
	if _, err := w.src.Run(context.Background(), "entra-contoso", nil); err == nil || !strings.Contains(err.Error(), "vault") {
		t.Errorf("a run with no credential in the vault: %v", err)
	}
	if sentSecret != "" {
		t.Errorf("a run sent %q from somewhere other than the vault", sentSecret)
	}
	// And no manifest holds one.
	for _, r := range Recipes() {
		m, err := r.Manifest("", map[string]string{"tenant": tenant, "org": "acme", "installation": "1"})
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Validate(); err != nil {
			t.Error(err)
		}
	}
}

// A source that misses its window is named, with its age, and its owner
// is mailed once, on the first tick that finds it stale; not again while
// it stays stale, and again once it has reported and gone stale again.
func TestStaleSourceNamedAndMailedOnce(t *testing.T) {
	w := newWorld(t, true)
	w.add("entra-contoso", "entra", map[string]string{"tenant": tenant}, entraCreds)
	w.tool.route = entra(t, graphToken(entraRoles...))
	w.run("entra-contoso")
	var sent []string
	alerts := &Alerts{Sources: w.src, Mail: func(to, subject, body string) error {
		sent = append(sent, to+"|"+subject+"|"+body)
		return nil
	}, Audit: func(r audit.Record) error { w.audited = append(w.audited, r); return nil }}

	tick := func(at time.Time) int {
		t.Helper()
		n, err := alerts.Tick(at)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := tick(day0.Add(23 * time.Hour)); n != 0 {
		t.Errorf("a fresh source's owner was told %d time(s)", n)
	}
	if st, _ := w.src.Stale(day0.Add(23 * time.Hour)); len(st) != 0 {
		t.Errorf("a fresh source was named stale: %+v", st)
	}
	late := day0.Add(24*time.Hour + 15*time.Minute)
	stale, err := w.src.Stale(late)
	if err != nil || len(stale) != 1 || !strings.Contains(stale[0].Said, "last reported 24 hours ago") ||
		!strings.Contains(stale[0].Said, "expected every 24 hours") {
		t.Fatalf("the stale source is named as %+v (%v)", stale, err)
	}
	if n := tick(late); n != 1 || len(sent) != 1 {
		t.Fatalf("on the first tick it was stale, %d told, %d sent", n, len(sent))
	}
	if !strings.HasPrefix(sent[0], "priya@contoso.example|Quilzo: the source entra-contoso is stale|") ||
		!strings.Contains(sent[0], "quilzo source run entra-contoso") {
		t.Errorf("the mail was %q", sent[0])
	}
	for i := 1; i <= 8; i++ {
		tick(late.Add(time.Duration(i) * 15 * time.Minute))
	}
	if len(sent) != 1 {
		t.Errorf("a source still stale was mailed %d times", len(sent))
	}
	told := 0
	for _, r := range w.audited {
		if r.Action == StaleAction && r.Outcome == audit.Success {
			told++
			if strings.Contains(fmt.Sprint(r.Detail), "priya") {
				t.Error("the audit entry names the owner by address")
			}
		}
	}
	if told != 1 {
		t.Errorf("%d tellings recorded", told)
	}
	// It reports again, is fresh, goes stale again: told again, once.
	w.clock.t = late.Add(3 * time.Hour)
	w.run("entra-contoso")
	tick(w.clock.t.Add(time.Minute))
	again := w.clock.t.Add(24*time.Hour + time.Minute)
	tick(again)
	tick(again.Add(15 * time.Minute))
	if len(sent) != 2 {
		t.Errorf("after reporting and going stale again, %d mail(s) in all", len(sent))
	}
}

// A person's table cannot overwrite a connector's observations: a file
// filed under a connector's source is refused, whoever's facts it names.
func TestAPersonsTableCannotOverwriteAConnectorsObservations(t *testing.T) {
	w := newWorld(t, true)
	w.add("entra-contoso", "entra", map[string]string{"tenant": tenant}, entraCreds)
	w.tool.route = entra(t, graphToken(entraRoles...))
	w.run("entra-contoso")
	before := w.reg.Head()
	m := register.ColumnMap{Name: "mfa", Makes: "Observation", Format: "csv",
		Columns: []register.MapColumn{{Field: "about", Column: "Serial", Asset: "device", Name: "Serial"}},
		Facts:   []register.MapFact{{Fact: "disk.encrypted", Column: "Encrypted"}}}
	if _, err := w.reg.Put(person, "a column map, confirmed", m); err != nil {
		t.Fatal(err)
	}
	before = w.reg.Head()
	_, err := w.src.Ing.Ingest(person, "", evidenceInput("csv", "Serial,Encrypted\nPF3ABC12,false\n", "entra-contoso", &m))
	if err == nil {
		t.Fatal("a person's table was filed under the connector's source")
	}
	if w.reg.Head() != before {
		t.Error("the refused table wrote something")
	}
}
