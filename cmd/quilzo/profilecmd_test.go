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
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/api"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/oscal"
	"github.com/quilzo/quilzo/internal/profile"
	"github.com/quilzo/quilzo/internal/render"
)

// securedStore is a store made the way the security install makes one, with
// an administrator whose token the command line uses.
func securedStore(t *testing.T) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root := connectStore(t)
	if err := runInit(root, []string{"--profile", "security"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func(old string) func() { return func() { flagToken = old } }(flagToken))
	if err := cmdAuth(root, []string{"grant", "dana", "admin"}); err != nil {
		t.Fatal(err)
	}
	flagToken = personToken(t, root, "dana", auth.RoleAdmin)
	return root
}

// reSiteRoute is a route the public site registers, with the method some of
// them are registered under taken off.
var reSiteRoute = regexp.MustCompile(`mux\.HandleFunc\("(?:[A-Z]+ )?([^"]+)"`)

// publicSiteRoutes is every address the public site's router registers, read from
// its source as adminRoutes reads the admin's.
func publicSiteRoutes(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, file := range []string{"../../internal/public/public.go", "../../internal/public/ucp.go"} {
		for _, m := range reSiteRoute.FindAllStringSubmatch(readFile(t, file), -1) {
			out = append(out, m[1])
		}
	}
	if len(out) < 20 {
		t.Fatalf("found %d site routes; the parse is wrong", len(out))
	}
	return out
}

// templated is a route with its wildcards filled in, so it can be asked for.
func templated(route string) string {
	return regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(route, "x")
}

// walkGated asks every route through the gate the server puts in front of its
// router, and reports which the profile switched off.
func walkGated(t *testing.T, root string, on profile.Surface, routes []string) map[string]bool {
	t.Helper()
	served := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("served")) })
	h := profileGate(root, on, served)
	off := map[string]bool{}
	for _, route := range routes {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, templated(route), nil))
		switch {
		case rec.Body.String() == "served":
		case rec.Code == http.StatusNotFound:
			off[route] = true
		default:
			t.Errorf("%s answered %d through the gate, neither served nor switched off", route, rec.Code)
		}
	}
	return off
}

func coveredBy(on profile.Surface, route string) (string, bool) {
	for _, f := range profile.Catalogue() {
		addrs := f.Admin
		if on == profile.SiteSurface {
			addrs = f.Site
		}
		for _, a := range addrs {
			if profile.Covers(a, templated(route)) {
				return f.Name, true
			}
		}
	}
	return "", false
}

// Under the security profile, every route of every feature in the
// catalogue is switched off and every other route is served, on the admin
// and on the public site, walked from the routers' own registrations; and
// each feature's commands and operations are refused. The catalogue is
// held to what the program serves: an address, a command or an operation
// it names that nothing registers is a door it believes it closed.
func TestProfileDisablesListedRoutes(t *testing.T) {
	root := securedStore(t)
	for _, surface := range []struct {
		on     profile.Surface
		routes []string
	}{{profile.AdminSurface, adminRoutes(t)}, {profile.SiteSurface, publicSiteRoutes(t)}} {
		off := walkGated(t, root, surface.on, surface.routes)
		for _, route := range surface.routes {
			name, covered := coveredBy(surface.on, route)
			if covered != off[route] {
				t.Errorf("%s %s: switched off %v, and the catalogue covers it %v (%s)",
					surface.on, route, off[route], covered, name)
			}
		}
		for _, f := range profile.Catalogue() {
			addrs := f.Admin
			if surface.on == profile.SiteSurface {
				addrs = f.Site
			}
			for _, a := range addrs {
				reached := false
				for _, route := range surface.routes {
					if profile.Covers(a, templated(route)) || profile.Covers(route, a) {
						reached = true
					}
				}
				if !reached {
					t.Errorf("%s names %s on the %s, and the router serves nothing there", f.Name, a, surface.on)
				}
			}
		}
	}

	dispatched := map[string]bool{}
	for _, c := range dispatchedCommands(t) {
		dispatched[c] = true
	}
	ops := registeredOperations(t)
	for _, f := range profile.Catalogue() {
		for _, c := range f.Commands {
			if !dispatched[c] {
				t.Errorf("%s names the command %s, which is not dispatched", f.Name, c)
			}
			err := profileRefuses(root, c)
			var blocked errBlocked
			if !errors.As(err, &blocked) || !strings.Contains(err.Error(), "quilzo profile enable "+f.Name) {
				t.Errorf("%s is not refused as switched off: %v", c, err)
			}
		}
		for _, op := range f.Operations {
			if !ops[op] {
				t.Errorf("%s names the operation %s, which nothing registers", f.Name, op)
			}
			if err := profileRefusesOperation(root, op); err == nil {
				t.Errorf("the operation %s is offered with %s switched off", op, f.Name)
			}
		}
	}
	if err := profileRefuses(root, "publish"); err != nil {
		t.Errorf("publish is refused, and nothing in the catalogue names it: %v", err)
	}
	// And an agent's run is refused its browser.
	if err := featureRefused(root, "browser-hands"); err == nil {
		t.Error("an agent run would be given a browser with browser hands switched off")
	}
}

// Without the profile, every feature is present: every route served, every
// command run, every operation offered. And under it, switching each
// feature back on brings each back.
func TestNothingRemovedWithoutProfile(t *testing.T) {
	assertEverythingPresent := func(root, when string) {
		t.Helper()
		if off := walkGated(t, root, profile.AdminSurface, adminRoutes(t)); len(off) > 0 {
			t.Errorf("%s, the admin switched off %v", when, off)
		}
		if off := walkGated(t, root, profile.SiteSurface, publicSiteRoutes(t)); len(off) > 0 {
			t.Errorf("%s, the site switched off %v", when, off)
		}
		for _, c := range dispatchedCommands(t) {
			if err := profileRefuses(root, c); err != nil {
				t.Errorf("%s, %s is refused: %v", when, c, err)
			}
		}
		for op := range registeredOperations(t) {
			if err := profileRefusesOperation(root, op); err != nil {
				t.Errorf("%s, the operation %s is refused: %v", when, op, err)
			}
		}
		if err := featureRefused(root, "browser-hands"); err != nil {
			t.Errorf("%s, an agent run is refused its browser: %v", when, err)
		}
	}
	t.Setenv("HOME", t.TempDir())
	plain := connectStore(t)
	assertEverythingPresent(plain, "on a store with no profile")

	root := securedStore(t)
	for _, f := range profile.Catalogue() {
		if err := cmdProfile(root, []string{"enable", f.Name, "--reason", "this installation uses it"}); err != nil {
			t.Fatal(err)
		}
	}
	assertEverythingPresent(root, "with every feature switched back on")
}

// Switching a feature back on needs a reason, is written to the audit log
// with the reason and who gave it, and is what the signed manifest says
// from then on.
func TestReenableIsRecorded(t *testing.T) {
	root := securedStore(t)
	err := cmdProfile(root, []string{"enable", "commerce"})
	var misused errMisused
	if err == nil || !errors.As(err, &misused) {
		t.Fatalf("commerce was switched back on with no reason: %v", err)
	}
	if err := cmdProfile(root, []string{"enable", "commerce", "--reason", "the conference sells tickets"}); err != nil {
		t.Fatal(err)
	}
	ev := lastEvent(t, root, "profile.feature.on")
	if ev == nil {
		t.Fatal("switching commerce back on is not in the audit log")
	}
	if ev.Detail["feature"] != "commerce" || ev.Detail["reason"] != "the conference sells tickets" ||
		!strings.HasPrefix(ev.Detail["manifest"], "sha256:") || ev.Principal == "" {
		t.Errorf("the record does not say what was switched on, why, by whom and under which manifest: %+v", ev)
	}
	sm, m := readManifest(t, root)
	if sm.Digest != ev.Detail["manifest"] {
		t.Errorf("the record names manifest %s and the store holds %s", ev.Detail["manifest"], sm.Digest)
	}
	for _, e := range m.Features {
		if e.Name == "commerce" && (e.State != "on" || e.Change == nil || e.Change.Reason != "the conference sells tickets") {
			t.Errorf("the manifest does not say commerce was switched back on and why: %+v", e)
		}
	}
	if err := profileRefuses(root, "pay"); err != nil {
		t.Errorf("pay is still refused after commerce was switched back on: %v", err)
	}
	// Somebody who may not administer the store may not switch features.
	if err := cmdAuth(root, []string{"grant", "kit", "author"}); err != nil {
		t.Fatal(err)
	}
	flagToken = personToken(t, root, "kit", auth.RoleAuthor)
	if err := cmdProfile(root, []string{"disable", "commerce", "--reason", "mine"}); err == nil {
		t.Error("an author switched a feature off")
	}
}

// The manifest the store holds is signed by the store's published head
// keys, and `quilzo compliance component` carries it on CM-7.
func TestManifestSignedAndInOSCAL(t *testing.T) {
	root := securedStore(t)
	sm, m := readManifest(t, root)
	if m.Profile != profile.Security || len(m.Off()) != len(profile.Catalogue()) {
		t.Fatalf("the manifest does not record the security profile's features off: %+v", m)
	}
	out := filepath.Join(t.TempDir(), "component.json")
	if err := complianceComponent(root, []string{"-o", out}); err != nil {
		t.Fatal(err)
	}
	var cd oscal.ComponentDefinition
	if err := json.Unmarshal([]byte(readFile(t, out)), &cd); err != nil {
		t.Fatal(err)
	}
	var digest []string
	for _, comp := range cd.ComponentDefinition.Components {
		for _, ci := range comp.ControlImplementations {
			for _, ir := range ci.ImplementedRequirements {
				if ir.ControlID != "cm-7" {
					continue
				}
				for _, p := range ir.Props {
					if p.Name == "feature-manifest" {
						digest = append(digest, p.Value)
					}
				}
			}
		}
	}
	if len(digest) != 1 || digest[0] != sm.Digest {
		t.Fatalf("CM-7 in the component carries %v and the store's manifest is %s", digest, sm.Digest)
	}
	// A manifest edited by hand is not evidence, and is not attached.
	edited := sm
	edited.Manifest = json.RawMessage(regexp.MustCompile(`"state":\s*"off"`).ReplaceAllString(string(sm.Manifest), `"state": "on"`))
	if string(edited.Manifest) == string(sm.Manifest) {
		t.Fatal("the edit changed nothing, so the test proves nothing")
	}
	body, _ := json.Marshal(edited)
	if err := os.WriteFile(manifestPath(root), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := complianceComponent(root, []string{"-o", out}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(readFile(t, out), sm.Digest) {
		t.Error("a manifest changed after it was signed was attached to CM-7")
	}
}

// readManifest is the store's signed manifest, checked against its
// published head keys.
func readManifest(t *testing.T, root string) (profile.Signed, profile.Manifest) {
	t.Helper()
	var sm profile.Signed
	if err := json.Unmarshal([]byte(readFile(t, manifestPath(root))), &sm); err != nil {
		t.Fatal(err)
	}
	v, err := publishedVerifier(headKeysPath(root))
	if err != nil {
		t.Fatal(err)
	}
	m, err := sm.Verify(v)
	if err != nil {
		t.Fatalf("the store's feature manifest does not verify with its published keys: %v", err)
	}
	return sm, m
}

// screenFor is the admin as `quilzo serve` builds it, with dana's session.
func screenFor(t *testing.T, root string, wire func(*admin.Server)) (*admin.Server, string) {
	t.Helper()
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := loadPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	toks, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := admin.New(s, pol, toks, render.Layouts{})
	if err != nil {
		t.Fatal(err)
	}
	wire(srv)
	tok := tokenFor(t, toks, waitingSession{name: "dana", actor: admin.Actor{Name: "dana", Role: auth.RoleAdmin, Scope: "/"}})
	return srv, tok
}

func accessible(t *testing.T, path, body string) {
	t.Helper()
	for _, f := range a11y.Check(path, body).Findings {
		if f.Severity == a11y.Blocking {
			t.Errorf("%s: %s (%s): %s", path, f.Rule, f.Criterion, f.Detail)
		}
	}
}

func adminPost(t *testing.T, h http.Handler, path, token string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The profile is on every surface: the admin's screen shows it, switches a
// feature with a reason (named beside its field when it is missing), hands
// out the manifest and leaves what is off out of the menu; the HTTP API
// reads it and lets an administrator switch a feature; the agent interface
// reads it and refuses what is off.
func TestTheProfileIsOnEverySurface(t *testing.T) {
	root := securedStore(t)
	srv, tok := screenFor(t, root, func(srv *admin.Server) { wireProfile(srv, root, sessionCaller) })

	body := adminGet(t, srv, "/security/profile", tok)
	for _, want := range []string{"<h1>Security profile</h1>", "Payments and commerce", "Off", `action="/security/profile/act"`,
		"<caption>", `scope="row"`, "/security/profile/manifest.json"} {
		if !strings.Contains(body, want) {
			t.Errorf("the screen does not show %q", want)
		}
	}
	if strings.Contains(body, `href="/pay"`) {
		t.Error("the menu offers Payments, which the profile switches off")
	}
	accessible(t, "/security/profile", body)

	rec := adminPost(t, srv.Handler(), "/security/profile/act", tok, url.Values{"feature": {"boards"}, "to": {"on"}})
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusSeeOther || !strings.Contains(loc, "f=boards") {
		t.Fatalf("a switch with no reason answered %d %s", rec.Code, loc)
	}
	// A browser keeps the fragment to itself; a request line carries none.
	path, _, _ := strings.Cut(loc, "#")
	errPage := adminGet(t, srv, path, tok)
	if !strings.Contains(errPage, `aria-invalid="true"`) || !strings.Contains(errPage, `id="err-boards"`) ||
		!strings.Contains(errPage, `href="#reason-boards"`) {
		t.Errorf("the missing reason is not named beside its field and summarised at the top:\n%s", errPage)
	}
	accessible(t, "/security/profile (with an error)", errPage)

	rec = adminPost(t, srv.Handler(), "/security/profile/act", tok,
		url.Values{"feature": {"commerce"}, "to": {"on"}, "reason": {"the conference sells tickets"}})
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "m=") {
		t.Fatalf("switching commerce on from the screen answered %s", loc)
	}
	if ev := lastEvent(t, root, "profile.feature.on"); ev == nil || ev.Detail["surface"] != "admin" || ev.Kind != "human" || !ev.Verified {
		t.Errorf("the screen's switch is not recorded as dana's, from the admin: %+v", ev)
	}
	if !strings.Contains(adminGet(t, srv, "/security/profile", tok), `href="/pay"`) {
		t.Error("with commerce switched back on, the menu still leaves Payments out")
	}
	var sm profile.Signed
	if err := json.Unmarshal([]byte(adminGet(t, srv, "/security/profile/manifest.json", tok)), &sm); err != nil || sm.Digest == "" {
		t.Errorf("the screen does not hand out the signed manifest: %v", err)
	}

	// The admin's gate, in front of the router as serve puts it.
	gated := profileGate(root, profile.AdminSurface, srv.Handler())
	req := httptest.NewRequest(http.MethodGet, "/experiments", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec = httptest.NewRecorder()
	gated.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || rec.Header().Get(profile.OffHeader) != "experiments" {
		t.Errorf("/experiments answered %d through the gate with experiments off", rec.Code)
	}
	accessible(t, "/experiments (switched off)", rec.Body.String())

	// The HTTP API.
	pol, _ := loadPolicy(root)
	toks, _ := loadTokens(root)
	h := securityAPI(root, &api.Server{Policy: pol, Tokens: toks})
	call := func(method, path, token, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	rec = call(http.MethodGet, "/api/v1/profile", flagToken, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"signed_manifest"`) ||
		!strings.Contains(rec.Body.String(), `"profile": "security"`) {
		t.Errorf("GET /api/v1/profile answered %d %s", rec.Code, rec.Body.String())
	}
	if rec = call(http.MethodGet, "/api/v1/profile", "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("the profile was read with no token: %d", rec.Code)
	}
	rec = call(http.MethodPost, "/api/v1/profile/features/experiments", flagToken, `{"on": true, "reason": "a test of the sign-up page"}`)
	if rec.Code != http.StatusOK || !profileState(root).On("experiments") {
		t.Errorf("an administrator's POST did not switch experiments on: %d %s", rec.Code, rec.Body.String())
	}
	if ev := lastEvent(t, root, "profile.feature.on"); ev == nil || ev.Detail["surface"] != "api" {
		t.Errorf("the API's switch is not recorded: %+v", ev)
	}
	rec = call(http.MethodPost, "/api/v1/profile/features/boards", flagToken, `{"on": true}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a switch with no reason answered %d", rec.Code)
	}
	if err := cmdAuth(root, []string{"grant", "kit", "reader"}); err != nil {
		t.Fatal(err)
	}
	kit := personToken(t, root, "kit", auth.RoleReader)
	toks, _ = loadTokens(root)
	pol, _ = loadPolicy(root)
	h = securityAPI(root, &api.Server{Policy: pol, Tokens: toks})
	if rec = call(http.MethodPost, "/api/v1/profile/features/boards", kit, `{"on": true, "reason": "mine"}`); rec.Code != http.StatusForbidden {
		t.Errorf("a reader switched a feature through the API: %d", rec.Code)
	}

	// The agent interface.
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	mcpSrv := buildMCP(root, s, human("dana"), "templates")
	text, mErr := callTool(t, mcpSrv, "quilzo_read", "profile_status", nil)
	if mErr != nil || !strings.Contains(text, "commerce") || !strings.Contains(text, "manifest") {
		t.Errorf("profile_status answered %v %s", mErr, text)
	}
	if err := cmdProfile(root, []string{"disable", "experiments", "--reason", "the test ended"}); err != nil {
		t.Fatal(err)
	}
	text, mErr = callTool(t, mcpSrv, "quilzo_read", "experiment_report", map[string]any{"name": "signup"})
	if mErr == nil && !strings.Contains(text, "switched off") {
		t.Errorf("experiment_report answered with experiments switched off: %s", text)
	}
}
