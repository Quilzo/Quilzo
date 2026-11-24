// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/api"
	"github.com/quilzo/quilzo/internal/attest"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/dual"
	"github.com/quilzo/quilzo/internal/egress"
	"github.com/quilzo/quilzo/internal/outpost"
)

// held is a file of attestations an organisation would publish.
func held() *attest.File {
	return &attest.File{Format: 1, Organisation: "Fernhollow Ltd",
		Attestations: []attest.Attestation{{ID: "soc2-2025", Kind: attest.Report, Title: "SOC 2 Type II report",
			Framework: "SOC 2", PeriodStart: "2025-01-01", PeriodEnd: "2025-12-31", Issuer: "Ashby & Rowe LLP",
			Issued: "2026-02-14", Available: "on request, under a non-disclosure agreement"}},
		Policies: []attest.Policy{{Title: "Information security policy", Version: "4.2", Approved: "2026-01-20"}}}
}

// internalStore is the internal instance: a security install with two
// administrators, dana and sam, whose tokens are returned, and a draft of
// attestations.
func internalStore(t *testing.T) (root string, tokens map[string]string) {
	t.Helper()
	root = securedStore(t)
	if err := cmdAuth(root, []string{"grant", "sam", "admin"}); err != nil {
		t.Fatal(err)
	}
	tokens = map[string]string{"dana": flagToken, "sam": personToken(t, root, "sam", auth.RoleAdmin)}
	body, err := held().Encode()
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "attestations.json")
	if err := os.WriteFile(file, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdAttest(root, []string{"set", file}); err != nil {
		t.Fatal(err)
	}
	return root, tokens
}

// publicHost is a public instance pinned to the internal instance's
// published head keys, served as `serve --profile public` serves it, and
// counting what reaches it.
func publicHost(t *testing.T, internal string) (pub string, srv *httptest.Server, posts *atomic.Int32) {
	t.Helper()
	pub = filepath.Join(t.TempDir(), "public-host")
	if err := runInit(pub, []string{"--profile", "public", "--pin", headKeysPath(internal)}); err != nil {
		t.Fatal(err)
	}
	// Served as serve serves it, which takes this process offline; the
	// internal instance in the same test process is put back at once.
	before := egress.Current()
	h, _, err := publicHandler(pub)
	_ = egress.SetMode(before)
	if err != nil {
		t.Fatal(err)
	}
	posts = &atomic.Int32{}
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts.Add(1)
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return pub, srv, posts
}

func getURL(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp.StatusCode, b.String()
}

// waitingRequest is the publication waiting for a second administrator.
func waitingRequest(t *testing.T, root string) dual.Request {
	t.Helper()
	pend, err := dualStore(root).Pending(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range pend {
		if r.Kind == dualPublishExternal && r.State == dual.Waiting {
			return r
		}
	}
	t.Fatal("no publication waits for a second administrator")
	return dual.Request{}
}

// Publishing to the public instance is autonomy level 4: one administrator
// proposes, a second approves, and only then does anything leave. The
// proposer cannot approve their own; a draft changed after the proposal is
// not what the approval sends; and a store with one administrator
// publishes alone, recorded as alone.
func TestPublishIsL4(t *testing.T) {
	root, tokens := internalStore(t)
	_, srv, posts := publicHost(t, root)
	if err := cmdPublic(root, []string{"target", srv.URL}); err != nil {
		t.Fatal(err)
	}

	flagToken = tokens["dana"]
	if err := cmdAttest(root, []string{"publish", "--reason", "the 2025 report is in"}); err != nil {
		t.Fatal(err)
	}
	req := waitingRequest(t, root)
	if posts.Load() != 0 {
		t.Fatal("something was sent to the public instance before a second administrator approved")
	}
	if _, body := getURL(t, srv.URL+"/"); strings.Contains(body, "Fernhollow") {
		t.Fatal("the public page shows the attestations before a second administrator approved")
	}
	if err := cmdPending(root, []string{"approve", req.ID}); !errors.Is(err, dual.ErrRefused) {
		t.Errorf("dana approved her own publication: %v", err)
	}

	flagToken = tokens["sam"]
	if err := cmdPending(root, []string{"approve", req.ID}); err != nil {
		t.Fatal(err)
	}
	if posts.Load() != 1 {
		t.Fatalf("approving sent %d transfers, want one", posts.Load())
	}
	if code, body := getURL(t, srv.URL+"/"); code != http.StatusOK || !strings.Contains(body, "SOC 2 Type II report") {
		t.Fatalf("after the second approval the page does not show the attestations: %d", code)
	}
	ev := lastEvent(t, root, "public.published")
	if ev == nil || ev.Detail["alone"] == "true" || ev.Detail["request"] != req.ID || ev.Detail["proposed_by"] == "" ||
		ev.Detail["approved_by"] == "" || ev.Detail["approved_by"] == ev.Detail["proposed_by"] {
		t.Errorf("the publication is not recorded as approved by two people: %+v", ev)
	}

	// A draft changed after it was proposed is not what an approval sends.
	flagToken = tokens["dana"]
	if err := cmdAttest(root, []string{"publish", "--reason", "add the policy review"}); err != nil {
		t.Fatal(err)
	}
	req = waitingRequest(t, root)
	changed := held()
	changed.Policies = append(changed.Policies, attest.Policy{Title: "Access control policy", Version: "3.0", Approved: "2026-03-02"})
	body, _ := changed.Encode()
	file := filepath.Join(t.TempDir(), "changed.json")
	if err := os.WriteFile(file, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdAttest(root, []string{"set", file}); err != nil {
		t.Fatal(err)
	}
	flagToken = tokens["sam"]
	if err := cmdPending(root, []string{"approve", req.ID}); err == nil {
		t.Error("an approval sent a draft that changed after it was proposed")
	}
	if posts.Load() != 1 {
		t.Errorf("a refused approval sent something: %d transfers", posts.Load())
	}
}

// Sending again is one administrator's, and sends only what two published:
// a draft changed since is not what `quilzo public send` carries. And an
// approval is for the place that was proposed: one given after the public
// instance's address changed sends nothing, there or anywhere.
func TestSendingAgainSendsOnlyWhatTwoPublished(t *testing.T) {
	root, tokens := internalStore(t)
	_, srv, posts := publicHost(t, root)
	if err := cmdPublic(root, []string{"target", srv.URL}); err != nil {
		t.Fatal(err)
	}
	flagToken = tokens["dana"]
	if err := cmdAttest(root, []string{"publish", "--reason", "the 2025 report is in"}); err != nil {
		t.Fatal(err)
	}
	req := waitingRequest(t, root)
	flagToken = tokens["sam"]
	if err := cmdPending(root, []string{"approve", req.ID}); err != nil {
		t.Fatal(err)
	}

	changed := held()
	changed.Policies = append(changed.Policies, attest.Policy{Title: "Access control policy", Version: "3.0", Approved: "2026-03-02"})
	body, _ := changed.Encode()
	file := filepath.Join(t.TempDir(), "changed.json")
	if err := os.WriteFile(file, body, 0o600); err != nil {
		t.Fatal(err)
	}
	flagToken = tokens["dana"]
	if err := cmdAttest(root, []string{"set", file}); err != nil {
		t.Fatal(err)
	}
	if err := cmdPublic(root, []string{"send", "--reason", "a fresh head"}); err != nil {
		t.Fatal(err)
	}
	if posts.Load() != 2 {
		t.Fatalf("sending again made %d posts in all, want two", posts.Load())
	}
	for _, path := range []string{"/", "/attestations.json"} {
		if _, got := getURL(t, srv.URL+path); strings.Contains(got, "Access control policy") {
			t.Errorf("one administrator sending again put a draft nobody approved on %s", path)
		}
	}

	if err := cmdAttest(root, []string{"publish", "--reason", "add the access control policy"}); err != nil {
		t.Fatal(err)
	}
	req = waitingRequest(t, root)
	elsewhere := t.TempDir()
	if err := cmdPublic(root, []string{"target", elsewhere}); err != nil {
		t.Fatal(err)
	}
	flagToken = tokens["sam"]
	if err := cmdPending(root, []string{"approve", req.ID}); err == nil {
		t.Error("an approval sent a publication after the public instance's address changed")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) > 0 || posts.Load() != 2 {
		t.Errorf("a refused approval sent something: %d posts, %d transfers written", posts.Load(), len(entries))
	}
}

// With one administrator, publication goes out as it is asked for, and the
// record says it was approved alone.
func TestPublishAloneIsRecordedAsAlone(t *testing.T) {
	root := securedStore(t)
	body, _ := held().Encode()
	file := filepath.Join(t.TempDir(), "a.json")
	if err := os.WriteFile(file, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdAttest(root, []string{"set", file}); err != nil {
		t.Fatal(err)
	}
	_, srv, posts := publicHost(t, root)
	if err := cmdPublic(root, []string{"target", srv.URL}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAttest(root, []string{"publish", "--reason", "the 2025 report is in"}); err != nil {
		t.Fatal(err)
	}
	if posts.Load() != 1 {
		t.Fatalf("a lone administrator's publication sent %d transfers", posts.Load())
	}
	if ev := lastEvent(t, root, "public.published"); ev == nil || ev.Detail["alone"] != "true" {
		t.Errorf("a publication by one administrator is not recorded as approved alone: %+v", ev)
	}
}

// The head feed the public instance serves is the internal log's: every head
// in it commits to the entries the log held at its size, and verifies with
// the keys the log publishes.
func TestHeadFeedMatchesLog(t *testing.T) {
	root := securedStore(t)
	body, _ := held().Encode()
	file := filepath.Join(t.TempDir(), "a.json")
	if err := os.WriteFile(file, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdAttest(root, []string{"set", file}); err != nil {
		t.Fatal(err)
	}
	_, srv, _ := publicHost(t, root)
	if err := cmdPublic(root, []string{"target", srv.URL}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAttest(root, []string{"publish", "--reason", "first"}); err != nil {
		t.Fatal(err)
	}
	// More happens in the record, and the head is sent again.
	if err := cmdProfile(root, []string{"enable", "boards", "--reason", "a forum for the board"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdPublic(root, []string{"send", "--reason", "a fresh head"}); err != nil {
		t.Fatal(err)
	}
	code, raw := getURL(t, srv.URL+"/heads.json")
	if code != http.StatusOK {
		t.Fatalf("the head feed answered %d", code)
	}
	var feed outpost.HeadFeed
	if err := json.Unmarshal([]byte(raw), &feed); err != nil {
		t.Fatal(err)
	}
	if len(feed.Heads) != 2 || feed.Heads[1].Size <= feed.Heads[0].Size {
		t.Fatalf("the feed holds %d heads, growing %v", len(feed.Heads), feed.Heads)
	}
	v, err := publishedVerifier(headKeysPath(root))
	if err != nil {
		t.Fatal(err)
	}
	events, err := auditEntries(root)
	if err != nil {
		t.Fatal(err)
	}
	for i, h := range feed.Heads {
		if err := v.Verify(h); err != nil {
			t.Errorf("head %d does not verify with the log's published keys: %v", i, err)
		}
		if h.Size > len(events) {
			t.Fatalf("head %d commits to %d entries and the log has %d", i, h.Size, len(events))
		}
		want, err := audit.TreeHead(events[:h.Size], time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if want.Root != h.Root {
			t.Errorf("head %d's root is not the log's over its first %d entries", i, h.Size)
		}
	}
	if _, page := getURL(t, srv.URL+"/"); !strings.Contains(page, feed.Heads[1].Root) {
		t.Error("the page does not show the newest head")
	}
}

// The public instance holds no register and serves no admin: every address
// the admin, the API and the agent interface answer at is not found there,
// and the admin and the site will not start on its root, nor will init give
// it an administrator.
func TestPublicHasNoRegisterOrAdminRoutes(t *testing.T) {
	root, _ := internalStore(t)
	pub, srv, _ := publicHost(t, root)
	paths := append(adminRoutes(t), "/api/v1/pages", "/api/v1/profile", "/api/v1/attestations", "/api/v1/register/kinds",
		"/mcp", "/register", "/a2a", "/scim/v2/Users")
	for _, p := range paths {
		if p == "/" {
			continue
		}
		if code, _ := getURL(t, srv.URL+templated(p)); code != http.StatusNotFound {
			t.Errorf("the public instance answers %s with %d", p, code)
		}
	}
	if err := cmdServe(pub, []string{"--addr", "127.0.0.1:0"}); err == nil || !strings.Contains(err.Error(), "public instance") {
		t.Errorf("the admin started on a public instance's root: %v", err)
	}
	if err := cmdSite(pub, []string{"--addr", "127.0.0.1:0"}); err == nil || !strings.Contains(err.Error(), "public instance") {
		t.Errorf("the site started on a public instance's root: %v", err)
	}
	if err := runInit(pub, []string{"--admin", "mallory"}); err == nil {
		t.Error("init gave a public instance an administrator")
	}
	entries, err := os.ReadDir(filepath.Join(pub, "refs"))
	if err == nil && len(entries) > 0 {
		t.Errorf("the public instance holds refs: %v", entries)
	}
}

// The public instance holds no secret: init writes the pinned public key and
// nothing secret, and the server refuses to start on a root that holds a
// vault, tokens, sealed credentials, a signing key or any other secret.
func TestPublicHoldsNoVaultSecrets(t *testing.T) {
	root, _ := internalStore(t)
	pub, _, _ := publicHost(t, root)
	if found := publicSecrets(pub); len(found) > 0 {
		t.Fatalf("a public instance just made holds %v", found)
	}
	err := filepath.Walk(pub, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(pub, path)
		if !strings.HasPrefix(rel, "public"+string(filepath.Separator)) {
			t.Errorf("init wrote %s on the public host", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Every secret a store keeps, not only the ones a list names: the
	// second-factor secrets, the provenance and pseudonymisation keys, the
	// newsletter's key and an agent credential issuer's, and a file of a
	// kind nobody has yet. A public instance holds its pinned key and what
	// it was sent, so anything else on its root is a store's.
	for _, planted := range []string{tokensPath(pub), keyringPath(pub), agentSecretsPath(pub), headKeyPath(pub),
		passkeysPath(pub), connectionsPath(pub), scimTokenPath(pub), oidcPath(pub), policyPath(pub),
		mfaPath(pub), provenanceKeyPath(pub), auditKeyPath(pub), newsletterKeyPath(pub), credKeysPath(pub),
		filepath.Join(pub, "a-secret-of-next-year.key")} {
		if err := os.MkdirAll(filepath.Dir(planted), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(planted, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := publicHandler(pub); err == nil || !strings.Contains(err.Error(), filepath.Base(planted)) {
			t.Errorf("the public instance started holding %s: %v", filepath.Base(planted), err)
		}
		if err := os.Remove(planted); err != nil {
			t.Fatal(err)
		}
	}
}

// The internal instance warns when it listens on a public address, and says
// nothing on loopback or a private network.
func TestInternalWarnsOnPublicBind(t *testing.T) {
	for addr, warns := range map[string]bool{
		"0.0.0.0:8080": true, "[::]:8080": true, ":8080": true, "203.0.113.7:8080": true,
		"[2001:db8::1]:8080": true, "127.0.0.1:8080": false, "localhost:8080": false,
		"10.1.2.3:8080": false, "192.168.0.10:8080": false, "[::1]:8080": false, "[fd00::5]:8080": false,
		// Shared address space (RFC 6598), which carriers and overlay
		// networks use and the internet does not route.
		"100.101.102.103:8080": false, "100.64.0.1:8080": false, "100.128.0.1:8080": true,
	} {
		if got := publicBindWarning(addr) != ""; got != warns {
			t.Errorf("%s: warns %v, want %v (%q)", addr, got, warns, publicBindWarning(addr))
		}
	}
	if !strings.Contains(publicBindWarning("203.0.113.7:8080"), "internal network") {
		t.Error("the warning does not say where the internal instance belongs")
	}
}

// The transfer is one way: the internal instance posts, and the public
// instance only answers. The public instance runs offline, so it can open
// no connection off its host; its configuration holds no address of the
// internal instance; and the internal instance has no address that takes
// anything from it.
func TestTransferIsOutboundOnly(t *testing.T) {
	root := securedStore(t)
	body, _ := held().Encode()
	file := filepath.Join(t.TempDir(), "a.json")
	if err := os.WriteFile(file, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdAttest(root, []string{"set", file}); err != nil {
		t.Fatal(err)
	}
	pub, srv, posts := publicHost(t, root)
	if err := cmdPublic(root, []string{"target", srv.URL}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAttest(root, []string{"publish", "--reason", "outbound"}); err != nil {
		t.Fatal(err)
	}
	if posts.Load() != 1 {
		t.Fatalf("the internal instance made %d posts to the public one", posts.Load())
	}

	// The public instance's whole configuration: a format, a profile, the
	// pinned key and when it was made. No address of anything.
	var cfg map[string]any
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(pub, "public", outpost.ConfigFile))), &cfg); err != nil {
		t.Fatal(err)
	}
	for k := range cfg {
		if k != "format" && k != "profile" && k != "pinned" && k != "created" {
			t.Errorf("the public instance's configuration holds %q", k)
		}
	}

	// Serving offline: no connection off the host.
	before := egress.Current()
	t.Cleanup(func() { _ = egress.SetMode(before) })
	if _, _, err := publicHandler(pub); err != nil {
		t.Fatal(err)
	}
	if egress.Current() != egress.Offline {
		t.Fatal("the public instance does not run offline")
	}
	if err := egress.Allowed("public-transfer", "198.51.100.4:443"); err == nil {
		t.Error("the public instance could open a connection off its host")
	}
	_ = egress.SetMode(before)

	// Nothing on the internal side takes a transfer.
	for _, p := range adminRoutes(t) {
		if strings.HasPrefix(outpost.IntakePath, strings.TrimSuffix(p, "/")+"/") && p != "/" || p == outpost.IntakePath {
			t.Errorf("the admin routes %s, which would take a transfer", p)
		}
	}
	pol, _ := loadPolicy(root)
	toks, _ := loadTokens(root)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/public/import", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+flagToken)
	securityAPIFor(root, pol, toks).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("the internal API takes a transfer: %d", rec.Code)
	}
}

// securityAPIFor is the API's security routes over a store's policy and
// tokens.
func securityAPIFor(root string, pol *auth.Policy, toks *auth.TokenStore) http.Handler {
	return securityAPI(root, &api.Server{Policy: pol, Tokens: toks})
}

// The public instance is on every surface: the admin's screen shows the
// draft and the key, names a wrong field beside itself and proposes a
// publication; the HTTP API reads it, keeps a draft and proposes; the agent
// interface reads it.
func TestThePublicInstanceIsOnEverySurface(t *testing.T) {
	root, tokens := internalStore(t)
	_, pubSrv, posts := publicHost(t, root)
	srv, tok := screenFor(t, root, func(srv *admin.Server) { wireProfile(srv, root, sessionCaller) })

	body := adminGet(t, srv, "/security/public", tok)
	for _, want := range []string{"<h1>Public instance</h1>", "SOC 2 Type II report", "Information security policy",
		`action="/security/public/act"`, "/security/public/key.json", "<caption>"} {
		if !strings.Contains(body, want) {
			t.Errorf("the screen does not show %q", want)
		}
	}
	accessible(t, "/security/public", body)

	rec := adminPost(t, srv.Handler(), "/security/public/act", tok, url.Values{"op": {"target"}, "to": {"relative/dir"}})
	loc, _, _ := strings.Cut(rec.Header().Get("Location"), "#")
	page := adminGet(t, srv, loc, tok)
	if !strings.Contains(page, `id="to-error"`) || !strings.Contains(page, `href="#to"`) {
		t.Error("a target that is neither an address nor a directory is not named beside its field")
	}
	accessible(t, "/security/public (with an error)", page)
	if rec = adminPost(t, srv.Handler(), "/security/public/act", tok, url.Values{"op": {"target"}, "to": {pubSrv.URL}}); !strings.Contains(rec.Header().Get("Location"), "m=") {
		t.Fatalf("saving the target answered %s", rec.Header().Get("Location"))
	}
	rec = adminPost(t, srv.Handler(), "/security/public/act", tok, url.Values{"op": {"publish"}, "reason": {"the 2025 report"}})
	if !strings.Contains(rec.Header().Get("Location"), "m=") || posts.Load() != 0 {
		t.Fatalf("proposing from the screen answered %s, with %d transfers sent", rec.Header().Get("Location"), posts.Load())
	}
	if !strings.Contains(adminGet(t, srv, "/security/public", tok), "waits for a second administrator") {
		t.Error("the screen does not say the publication waits for a second administrator")
	}
	var keys map[string]string
	if err := json.Unmarshal([]byte(adminGet(t, srv, "/security/public/key.json", tok)), &keys); err != nil || keys["key_id"] == "" {
		t.Errorf("the screen does not hand out the key to pin: %v", err)
	}

	// The HTTP API.
	pol, _ := loadPolicy(root)
	toks, _ := loadTokens(root)
	h := securityAPIFor(root, pol, toks)
	call := func(method, path, token, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec = call(http.MethodGet, "/api/v1/attestations", tokens["sam"], ""); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"waiting"`) {
		t.Errorf("GET /api/v1/attestations answered %d %s", rec.Code, rec.Body.String())
	}
	if rec = call(http.MethodPut, "/api/v1/attestations", tokens["sam"], `{"format": 1, "organisation": "Fernhollow Ltd", "attestations": [], "policies": [], "score": 97}`); rec.Code != http.StatusBadRequest {
		t.Errorf("a draft with a score was kept through the API: %d", rec.Code)
	}
	changed, _ := held().Encode()
	if rec = call(http.MethodPut, "/api/v1/attestations", tokens["sam"], string(changed)); rec.Code != http.StatusOK {
		t.Errorf("a draft could not be kept through the API: %d %s", rec.Code, rec.Body.String())
	}
	if rec = call(http.MethodPost, "/api/v1/attestations/publish", tokens["sam"], `{"reason": "from the pipeline"}`); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "waiting for a second administrator") {
		t.Errorf("a publication proposed through the API answered %d %s", rec.Code, rec.Body.String())
	}
	if posts.Load() != 0 {
		t.Error("a proposal through the API sent something")
	}

	// The agent interface.
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	text, mErr := callTool(t, buildMCP(root, s, human("dana"), "templates"), "quilzo_read", "public_status", nil)
	if mErr != nil || !strings.Contains(text, pubSrv.URL) || !strings.Contains(text, "SOC 2") {
		t.Errorf("public_status answered %v %s", mErr, text)
	}
}
