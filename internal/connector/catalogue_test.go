// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The shipped recipes, held to the rules every manifest is held to, and
// the engine's behaviour that only a catalogue shows. These are the tests
// of the catalogue the engine was copied with, kept for the recipes Quilzo
// ships (Entra, GitHub, Google Workspace and Okta); the copied tests of
// tools Quilzo does not ship went with those tools' manifests, and the
// engine behaviour they proved is proved here against manifests made in the
// test. What each recipe yields as facts is tested against recorded
// responses in internal/sources.

func entry(t *testing.T, name string) Entry {
	t.Helper()
	all, err := Catalogue()
	if err != nil {
		t.Fatal(err)
	}
	e, ok := all[name]
	if !ok {
		t.Fatalf("no %s in the catalogue", name)
	}
	return e
}

// sampleParams fill any parameters an entry takes.
var sampleParams = map[string]string{
	"tenant": "72f988bf-86f1-41af-91ab-2d7cd011db47", "org": "acme", "installation": "4242"}

func TestEveryShippedConnectorLoadsInEveryRegion(t *testing.T) {
	all, err := Catalogue()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"entra", "github", "google-workspace", "okta"} {
		if _, ok := all[want]; !ok {
			t.Errorf("%s is missing from the catalogue", want)
		}
	}
	for name, e := range all {
		if _, ok := e.Regions[e.Default]; !ok {
			t.Errorf("%s: the default region %q is not one of its regions",
				name, e.Default)
		}
		for _, region := range e.RegionNames() {
			m, err := e.With(region, sampleParams)
			if err != nil {
				t.Errorf("%s/%s: %v", name, region, err)
				continue
			}
			if m.Auth.Kind.oauth() && m.Auth.Token.Host == "" {
				t.Errorf("%s/%s has no token host", name, region)
			}
			// Every credential the manifest names is explained to the
			// person who has to go and make it, and nothing else is.
			names := []string{m.Auth.Secret}
			if m.Auth.Kind == NoAuth {
				names = nil
			}
			if m.Auth.Token != nil {
				names = append(names, m.Auth.Token.Client)
				if m.Auth.Token.Refresh != "" {
					names = append(names, m.Auth.Token.Refresh)
				}
			}
			for _, n := range names {
				if strings.TrimSpace(e.Credentials[n]) == "" {
					t.Errorf("%s names the credential %s and does not say "+
						"what it is or where it is made", name, n)
				}
			}
			if len(e.Credentials) != len(names) {
				t.Errorf("%s explains %d credentials and uses %d", name,
					len(e.Credentials), len(names))
			}
		}
		if _, err := e.With("mars", sampleParams); err == nil {
			t.Errorf("%s accepted a region it does not have", name)
		}
	}
}

// A region is chosen from the list; it is never a host somebody types.
func TestARegionCannotBeAHost(t *testing.T) {
	e := entry(t, "okta")
	for _, r := range []string{"evil.example.com", "acme.okta.com", "../okta"} {
		if _, err := e.With(r, sampleParams); err == nil {
			t.Errorf("%q was taken as a region", r)
		}
	}
	m, _ := e.With("emea", sampleParams)
	if m.Host != "acme.okta-emea.com" {
		t.Errorf("emea reads %s", m.Host)
	}
	// And choosing one does not change the catalogue for the next caller.
	us, _ := e.With("okta", sampleParams)
	if us.Host != "acme.okta.com" {
		t.Errorf("after reading emea, okta reads %s", us.Host)
	}
}

// The limits each tool publishes, which a run must stay inside.
func TestTheShippedConnectorsKeepToTheToolsLimits(t *testing.T) {
	gh := entry(t, "github").Manifest
	if gh.Rate.PerMinute == 0 || gh.Rate.PerMinute*60 > 5000 {
		t.Errorf("an installation token allows 5,000 requests an hour; this declares %+v", gh.Rate)
	}
	okta := entry(t, "okta").Manifest
	if okta.Rate.PerMinute == 0 && okta.Rate.PerSecond == 0 {
		t.Errorf("Okta limits each endpoint by the minute, and this declares no pace: %+v", okta.Rate)
	}
	graph := entry(t, "entra").Manifest
	if graph.Rate.PerSecond == 0 && graph.Rate.PerMinute == 0 {
		t.Errorf("Graph throttles a tenant's app, and this declares no pace: %+v", graph.Rate)
	}
}

// fake answers every host of a manifest from a table of path to body.
func fake(t *testing.T, m Manifest, bodies map[string]string,
	seen *[]string) *hosts {
	t.Helper()
	handler := func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, r.Method+" "+r.URL.Path+" "+
			r.Header.Get("Accept"))
		if strings.HasSuffix(r.URL.Path, "/token") {
			io.WriteString(w, `{"access_token":"1000.abcdef.123456","expires_in":3600}`)
			return
		}
		body, ok := bodies[r.URL.Path]
		if !ok {
			t.Errorf("unexpected request for %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		io.WriteString(w, body)
	}
	s := serve(t, handler)
	servers := map[string]*httptest.Server{m.Host: s}
	if m.Auth.Token != nil {
		servers[m.Auth.Token.Host] = s
	}
	return route(t, servers)
}

func readAll(t *testing.T, m Manifest, h Doer, s Secrets) map[string]Result {
	t.Helper()
	x, err := NewSession(m, h, s, noSleep)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Result{}
	for _, r := range x.All(context.Background(), nil, nil) {
		if r.Err != nil {
			t.Fatalf("%s: %v", r.Endpoint, r.Err)
		}
		out[r.Endpoint] = r.Result
	}
	return out
}

func want(t *testing.T, rec map[string]string, fields map[string]string) {
	t.Helper()
	for k, v := range fields {
		if rec[k] != v {
			t.Errorf("%s is %q, want %q (record %v)", k, rec[k], v, rec)
		}
	}
}

// If the user list fails, their factors are reported as not read, never
// as a directory whose people have no second factor.
func TestAChildOfAFailedParentIsNotReportedAsEmpty(t *testing.T) {
	m, _ := entry(t, "okta").With("okta", sampleParams)
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	h := route(t, map[string]*httptest.Server{m.Host: s})
	x, _ := NewSession(m, h, MapFunc{"okta-api-token": "00abcdef"}, noSleep)
	reads := x.All(context.Background(), []string{"factors"}, nil)
	var factors *Read
	for i := range reads {
		if reads[i].Endpoint == "factors" {
			factors = &reads[i]
		}
		if reads[i].Endpoint == "users" && reads[i].Asked {
			t.Error("users was read only for its records and is marked " +
				"as asked for")
		}
	}
	if factors == nil || factors.Err == nil ||
		!strings.Contains(factors.Err.Error(), "not read") {
		t.Errorf("factors after a failed user list: %+v", factors)
	}
}

func TestAChildOfATruncatedParentSaysSo(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/devices" {
			fmt.Fprint(w, `{"devices":[{"id":"1"},{"id":"2"}]}`)
			return
		}
		io.WriteString(w, `{"apps":[{"name":"x"}]}`)
	})
	m := mdmApps()
	m.Records = 1
	h := route(t, map[string]*httptest.Server{"mdm.example.com": s})
	x, _ := NewSession(m, h, MapFunc{"t": "k"}, noSleep)
	for _, r := range x.All(context.Background(), nil, nil) {
		if r.Endpoint == "apps" && r.Result.Complete() {
			t.Error("the apps of the first device read as the apps of the " +
				"estate")
		}
	}
}

// A parameter goes into a host or a path, so it is checked to be what it
// says and nothing more.
func TestAParameterCannotPointAConnectorElsewhere(t *testing.T) {
	okta, entra := entry(t, "okta"), entry(t, "entra")
	for _, org := range []string{"evil.com/x", "acme.evil", "acme@evil.com",
		"", "-acme", "a b", "acme.okta.com?"} {
		if m, err := okta.With("okta", map[string]string{"org": org}); err == nil {
			t.Errorf("org %q gave host %s", org, m.Host)
		}
	}
	for _, tenant := range []string{"common", "organizations", "consumers",
		"acme.com", "../x", ""} {
		if _, err := entra.With("global", map[string]string{"tenant": tenant}); err == nil {
			t.Errorf("tenant %q was accepted", tenant)
		}
	}
	m, err := okta.With("emea", map[string]string{"org": "Acme"})
	if err != nil || m.Host != "acme.okta-emea.com" {
		t.Errorf("%s, %v", m.Host, err)
	}
	m, err = entra.With("", map[string]string{"tenant": sampleParams["tenant"]})
	if err != nil || m.Auth.Token.Path != "/"+sampleParams["tenant"]+"/oauth2/v2.0/token" {
		t.Errorf("%+v, %v", m.Auth.Token, err)
	}
	for _, inst := range []string{"", "12a", "1/../2", "-1"} {
		if _, err := entry(t, "github").With("", map[string]string{"org": "acme", "installation": inst}); err == nil {
			t.Errorf("an installation of %q was accepted", inst)
		}
	}
}

// jwt is an unsigned token carrying roles, which is all checkRoles reads.
func jwt(roles ...string) string {
	b, _ := json.Marshal(map[string]any{"roles": roles})
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
}

func TestAGraphTokenThatCanWriteIsNeverUsed(t *testing.T) {
	m, _ := entry(t, "entra").With("", sampleParams)
	for name, token := range map[string]string{
		"granted write as well": jwt("User.Read.All", "User.ReadWrite.All"),
		"granted mail sending":  jwt("User.Read.All", "Mail.Send"),
		"no roles at all":       jwt(),
		"not a JWT":             "opaque-token-abcdefgh",
	} {
		calls := 0
		s := serve(t, func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/token") {
				fmt.Fprintf(w, `{"expires_in":3599,"access_token":%q}`, token)
				return
			}
			calls++
			io.WriteString(w, `{"value":[]}`)
		})
		h := route(t, map[string]*httptest.Server{"graph.microsoft.com": s,
			"login.microsoftonline.com": s})
		_, err := Run(context.Background(), m, "users", h,
			MapFunc{"entra-client-id": "c", "entra-client-secret": "s"},
			State{}, noSleep)
		if err == nil || calls != 0 {
			t.Errorf("%s: used (%d calls, %v)", name, calls, err)
		}
	}
	for _, role := range []string{"User.ReadWrite.All", "Mail.Send",
		"User.Invite.All", "Directory.AccessAsUser.All", "Read"} {
		if readRole(role) == nil {
			t.Errorf("%s was taken for a read permission", role)
		}
	}
	for _, role := range []string{"User.Read.All",
		"DeviceManagementManagedDevices.Read.All", "User.ReadBasic.All"} {
		if err := readRole(role); err != nil {
			t.Errorf("%s: %v", role, err)
		}
	}
}

// A .default scope says nothing about what the token can do, so it is only
// accepted where the roles on the token will be checked instead.
func TestADefaultScopeNeedsItsRolesDeclared(t *testing.T) {
	m, _ := entry(t, "entra").With("", sampleParams)
	m.Auth.Token.Roles = nil
	if m.Validate() == nil {
		t.Error("a .default scope with no roles to check was accepted")
	}
}

// audit is a manifest with an incremental endpoint, of the shape the
// copied catalogue's audit logs had: a filter around its checkpoint, or a
// checkpoint converted from the milliseconds it was written in.
func audit() Manifest {
	return Manifest{Name: "logs", Tool: "A tool with an audit log", Host: "logs.example.com",
		Auth: Auth{Kind: Bearer, Secret: "logs-token"},
		Endpoints: []Endpoint{
			{Name: "signin", Path: "/signins", Produces: Events, Since: "$filter",
				SinceAs: "createdDateTime ge {since}", Watermark: "createdDateTime",
				Reads: []string{"id", "createdDateTime"}, Map: map[string]string{"id": "id", "at": "createdDateTime"}},
			{Name: "audit", Path: "/audit", Produces: Events, Since: "phrase",
				SinceAs: "created:>={since}", Watermark: "at", WatermarkLayout: "epoch-ms",
				Reads: []string{"id", "at"}, Map: map[string]string{"id": "id", "at": "at"}},
			{Name: "system", Path: "/system", Produces: Events, Since: "since", Watermark: "published",
				Reads: []string{"id", "published"}, Map: map[string]string{"id": "id", "at": "published"}},
		}}
}

// A checkpoint goes back to the tool in the form the tool takes it: bare,
// inside a filter, or converted from the milliseconds it was written in.
// One that does not look like a checkpoint is never put into a filter.
func TestACheckpointIsSentInTheFormTheToolTakes(t *testing.T) {
	m := audit()
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	at := func(m Manifest, name, mark string) url.Values {
		e, ok := m.Endpoint(name)
		if !ok {
			t.Fatalf("%s has no endpoint %s", m.Name, name)
		}
		return m.first(e, State{Watermark: mark}).Query()
	}
	if got := at(m, "system", "2026-09-30T10:00:00.000Z").Get("since"); got != "2026-09-30T10:00:00.000Z" {
		t.Errorf("system: since=%q", got)
	}
	if got := at(m, "signin", "2026-09-30T10:00:00Z").Get("$filter"); got != "createdDateTime ge 2026-09-30T10:00:00Z" {
		t.Errorf("signin: $filter=%q", got)
	}
	if got := at(m, "audit", "1790762400000").Get("phrase"); got != "created:>=2026-09-30T10:00:00Z" {
		t.Errorf("audit: phrase=%q", got)
	}
	// A checkpoint with a second clause in it stays out of the filter.
	for _, bad := range []string{"2026-09-30T10:00:00Z or userId ne ''",
		"x') or (1 eq 1", "2026 created:<2030"} {
		if got := at(m, "signin", bad).Get("$filter"); got != "" {
			t.Errorf("a checkpoint of %q was sent as %q", bad, got)
		}
	}
	// With no checkpoint, nothing is asked for since.
	if q := at(m, "signin", ""); q.Has("$filter") {
		t.Error("a filter with no checkpoint")
	}
	for name, change := range map[string]func(*Endpoint){
		"a filter with no place for it":  func(e *Endpoint) { e.SinceAs = "createdDateTime ge" },
		"two places":                     func(e *Endpoint) { e.SinceAs = "{since} {since}" },
		"a quote":                        func(e *Endpoint) { e.SinceAs = "x eq '{since}'" },
		"a filter with no parameter":     func(e *Endpoint) { e.Since = "" },
		"a layout this does not convert": func(e *Endpoint) { e.WatermarkLayout = "roman" },
	} {
		m := audit()
		for i := range m.Endpoints {
			if m.Endpoints[i].Name == "signin" {
				change(&m.Endpoints[i])
			}
		}
		if m.Validate() == nil {
			t.Errorf("a manifest with %s was accepted", name)
		}
	}
}

// A path parameter is one segment, checked, and the per-record keys beside
// it are left for the run to fill.
func TestAParameterInAPathIsCheckedLikeOneInAHost(t *testing.T) {
	gh := entry(t, "github")
	m, err := gh.With("", map[string]string{"org": "Acme", "installation": "4242"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.Endpoints[0].Path, "/orgs/acme") {
		t.Errorf("the organisation is not in the path: %s", m.Endpoints[0].Path)
	}
	if m.Auth.Token.Path != "/app/installations/4242/access_tokens" {
		t.Errorf("the installation is not in the token path: %s", m.Auth.Token.Path)
	}
	branch, _ := m.Endpoint("branch")
	if branch.Path != "/repos/acme/{key}/branches/{also}" {
		t.Errorf("the per-record keys were filled or lost: %s", branch.Path)
	}
	if _, err := gh.With("", map[string]string{"org": "acme/../x", "installation": "1"}); err == nil {
		t.Error("an organisation with a path in it was accepted")
	}
}

func TestAConstantHeaderIsDeclaredNotSmuggled(t *testing.T) {
	for name, edit := range map[string]func(*Endpoint){
		"a credential": func(e *Endpoint) {
			e.Headers = map[string]string{"x-api-version": "sk-ant-api01-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
		},
		"two in one":       func(e *Endpoint) { e.Headers = map[string]string{"x-api-version": "2023-06-01\r\nX-Evil: 1"} },
		"an authorization": func(e *Endpoint) { e.Headers = map[string]string{"Authorization": "Bearer x"} },
		"an accept":        func(e *Endpoint) { e.Headers = map[string]string{"Accept": "text/html"} },
		"a broken name":    func(e *Endpoint) { e.Headers = map[string]string{"bad name": "1"} },
		"empty":            func(e *Endpoint) { e.Headers = map[string]string{"x-api-version": " "} },
	} {
		m := people()
		edit(&m.Endpoints[0])
		if err := m.Validate(); err == nil {
			t.Errorf("%s was accepted as a constant header", name)
		}
	}
	m := people()
	m.Endpoints[0].Headers = map[string]string{"x-api-version": "2023-06-01"}
	if err := m.Validate(); err != nil {
		t.Errorf("an honest constant header was refused: %v", err)
	}
	m2 := people()
	m2.Endpoints[0].WatermarkLayout = "roman"
	if m2.Validate() == nil {
		t.Error("a layout of \"roman\" was accepted")
	}
	m3 := people()
	m3.Endpoints[0].WatermarkLayout = "epoch-s"
	if err := m3.Validate(); err != nil {
		t.Errorf("epoch-s was refused: %v", err)
	}
}

// The seconds form of the milliseconds conversion, proved against a real
// page so the filter and the records agree on units.
func TestTheEpochSecondsWatermarkKeepsItsConversion(t *testing.T) {
	var asked []string
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Query().Get("effective_at[gte]"))
		w.Write([]byte(`{"data":[{"id":"a1","effective_at":1761180000}],"has_more":false}`))
	})
	m := Manifest{Name: "seconds", Tool: "A tool that counts in seconds", Host: "api.example.com",
		Auth: Auth{Kind: Bearer, Secret: "audit-token"},
		Endpoints: []Endpoint{{Name: "audit", Path: "/v1/audit", Produces: Events, Records: "data",
			Page:  Pagination{Kind: Cursor, From: "last_id", Param: "after", More: "has_more"},
			Since: "effective_at[gte]", Watermark: "effective_at", WatermarkLayout: "epoch-s",
			Reads: []string{"id", "effective_at"}, Map: map[string]string{"id": "id", "at": "effective_at"}}}}
	out, err := Run(context.Background(), m, "audit", dialTo(t, s),
		MapFunc{"audit-token": "t"}, State{}, noSleep)
	if err != nil {
		t.Fatal(err)
	}
	if asked[0] != "" {
		t.Errorf("the first run asked for %q", asked[0])
	}
	if out.Watermark != "1761180000" {
		t.Fatalf("watermark = %q", out.Watermark)
	}
	if _, err := Run(context.Background(), m, "audit", dialTo(t, s),
		MapFunc{"audit-token": "t"}, State{Watermark: out.Watermark},
		noSleep); err != nil {
		t.Fatal(err)
	}
	if asked[1] != "1761180000" {
		t.Errorf("the second run asked for %q in a filter that takes "+
			"seconds", asked[1])
	}
}

// The recipes read what they say they read: a recorded page of each tool
// comes back mapped, and nothing the recipe did not declare is kept.
func TestTheRecipesReadTheirRecordedPages(t *testing.T) {
	m, err := entry(t, "okta").With("okta", sampleParams)
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	h := fake(t, m, map[string]string{
		"/api/v1/users/me/roles":      `[{"type":"READ_ONLY_ADMIN","status":"ACTIVE"}]`,
		"/api/v1/users":               `[{"id":"00u1","status":"ACTIVE","profile":{"login":"ann@acme.com","firstName":"Ann"}}]`,
		"/api/v1/users/00u1/factors":  `[{"factorType":"webauthn","provider":"FIDO","status":"ACTIVE"}]`,
		"/api/v1/iam/assignees/users": `{"value":[{"id":"00u1"}]}`,
		"/api/v1/users/00u1/roles":    `[{"type":"SUPER_ADMIN","status":"ACTIVE"}]`,
		"/api/v1/policies":            `[{"id":"p1","name":"Default","status":"ACTIVE","priority":1}]`,
	}, &seen)
	got := readAll(t, m, h, MapFunc{"okta-api-token": "00abcdef"})
	want(t, got["users"].Records[0], map[string]string{"login": "ann@acme.com", "status": "ACTIVE"})
	if _, ok := got["users"].Records[0]["firstName"]; ok {
		t.Error("a field the recipe does not declare was kept")
	}
	want(t, got["factors"].Records[0], map[string]string{"type": "webauthn", "parent": "00u1"})
	for _, s := range seen {
		if !strings.HasPrefix(s, "GET ") {
			t.Errorf("a recipe sent %s", s)
		}
	}
}
