// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// hosts sends each declared host to its own test server, and remembers what
// each one was sent, so a test can say which host saw which credential.
type hosts struct {
	mu   sync.Mutex
	to   map[string]*url.URL
	sent []sent
}

type sent struct {
	Host, Method, Path, Query, Auth, Body string
}

func route(t *testing.T, servers map[string]*httptest.Server) *hosts {
	t.Helper()
	h := &hosts{to: map[string]*url.URL{}}
	for host, s := range servers {
		u, err := url.Parse(s.URL)
		if err != nil {
			t.Fatal(err)
		}
		h.to[host] = u
	}
	return h
}

func (h *hosts) Do(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}
	h.mu.Lock()
	h.sent = append(h.sent, sent{Host: req.URL.Host, Method: req.Method,
		Path: req.URL.Path, Query: req.URL.RawQuery,
		Auth: req.Header.Get("Authorization"), Body: string(body)})
	target, ok := h.to[req.URL.Host]
	h.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("the test has no server for %s", req.URL.Host)
	}
	out := *req.URL
	out.Scheme, out.Host = target.Scheme, target.Host
	fresh, err := http.NewRequestWithContext(req.Context(), req.Method,
		out.String(), strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	fresh.Header = req.Header.Clone()
	return http.DefaultClient.Do(fresh)
}

func (h *hosts) to_(host string) []sent {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []sent
	for _, s := range h.sent {
		if s.Host == host {
			out = append(out, s)
		}
	}
	return out
}

func vanta() Manifest {
	return Manifest{
		Name: "vanta", Tool: "Vanta", Host: "api.vanta.com",
		Auth: Auth{Kind: OAuthClient, Secret: "vanta-client-secret",
			Token: &TokenEndpoint{Host: "api.vanta.com", Path: "/oauth/token",
				Client: "vanta-client-id", Body: "json",
				Scopes: []string{"vanta-api.all:read"}}},
		Endpoints: []Endpoint{
			{Name: "people", Path: "/v1/people", Produces: Identities,
				Records: "results.data",
				Page: Pagination{Kind: Cursor, From: "results.pageInfo.endCursor",
					Param: "pageCursor", Size: 100, SizeParam: "pageSize"},
				Reads: []string{"id", "emailAddress"},
				Map:   map[string]string{"id": "id", "email": "emailAddress"}},
			{Name: "computers", Path: "/v1/monitored-computers",
				Produces: Identities, Records: "results.data",
				Reads: []string{"id", "serialNumber"},
				Map:   map[string]string{"id": "id", "serial": "serialNumber"}},
		},
	}
}

func vantaSecrets() Secrets {
	return MapFunc{"vanta-client-id": "vci_client",
		"vanta-client-secret": "vcs_topsecret"}
}

// tokenServer issues tokens and counts them.
func tokenServer(t *testing.T, issued *int, reply func(n int) (int, string)) *httptest.Server {
	return serve(t, func(w http.ResponseWriter, r *http.Request) {
		*issued++
		status, body := 200, fmt.Sprintf(
			`{"access_token":"tok-%d-abcdefgh","expires_in":3600,"token_type":"Bearer"}`,
			*issued)
		if reply != nil {
			status, body = reply(*issued)
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
	})
}

func dataServer(t *testing.T) *httptest.Server {
	return serve(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer tok-") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		io.WriteString(w, `{"results":{"data":[{"id":"p1","emailAddress":"a@x.com",`+
			`"serialNumber":"C02X"}],"pageInfo":{"hasNextPage":false}}}`)
	})
}

// Vanta revokes the old token when a new one is issued, so two endpoints in
// one session must share one.
func TestOneSessionAsksForOneToken(t *testing.T) {
	issued := 0
	tokens := tokenServer(t, &issued, nil)
	api := dataServer(t)
	// The token and the data share a host at Vanta; the test gives the token
	// path its own server by host, so both are "api.vanta.com" — routed by
	// path below instead.
	both := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokens.Config.Handler.ServeHTTP(w, r)
			return
		}
		api.Config.Handler.ServeHTTP(w, r)
	})
	h := route(t, map[string]*httptest.Server{"api.vanta.com": both})
	x, err := NewSession(vanta(), h, vantaSecrets(), noSleep)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"people", "computers"} {
		res, err := x.Run(context.Background(), name, State{})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Records) != 1 {
			t.Fatalf("%s: %d records", name, len(res.Records))
		}
	}
	if issued != 1 {
		t.Errorf("%d tokens were issued for one session. At Vanta each new "+
			"one revokes the last, so a session asking twice logs itself out",
			issued)
	}
}

// The client secret goes to the token endpoint, as a POST body, and nowhere
// else; the access token goes to the data endpoints and nowhere else.
func TestTheClientSecretOnlyEverGoesToTheTokenEndpoint(t *testing.T) {
	issued := 0
	m := vanta()
	m.Auth.Token.Host = "auth.vanta.test.example"
	h := route(t, map[string]*httptest.Server{
		"auth.vanta.test.example": tokenServer(t, &issued, nil),
		"api.vanta.com":           dataServer(t),
	})
	if _, err := Run(context.Background(), m, "people", h, vantaSecrets(),
		State{}, noSleep); err != nil {
		t.Fatal(err)
	}
	for _, s := range h.to_("auth.vanta.test.example") {
		if s.Method != http.MethodPost || s.Path != "/oauth/token" {
			t.Errorf("the token host was sent %s %s", s.Method, s.Path)
		}
		if strings.Contains(s.Query, "secret") {
			t.Error("the client secret went in a query string, which is " +
				"logged by every proxy on the way")
		}
		var body map[string]string
		if err := json.Unmarshal([]byte(s.Body), &body); err != nil {
			t.Fatalf("the token request is not the JSON Vanta documents: %v", err)
		}
		if body["grant_type"] != "client_credentials" ||
			body["scope"] != "vanta-api.all:read" ||
			body["client_secret"] != "vcs_topsecret" {
			t.Errorf("token request body: %v", body)
		}
	}
	for _, s := range h.to_("api.vanta.com") {
		if s.Method != http.MethodGet {
			t.Errorf("the data host was sent a %s", s.Method)
		}
		if strings.Contains(s.Body+s.Query+s.Auth, "vcs_topsecret") {
			t.Error("the client secret reached the data host")
		}
		if s.Auth != "Bearer tok-1-abcdefgh" {
			t.Errorf("the data host was sent %q", s.Auth)
		}
	}
}

// Zoho: a refresh token, a form body, and its own word for Bearer.
func TestAZohoRefreshTokenIsExchangedAndSentAsZohoSpellsIt(t *testing.T) {
	var form url.Values
	tokens := serve(t, func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		form = r.PostForm
		io.WriteString(w, `{"access_token":"1000.abcdef.123456","expires_in":3600,`+
			`"api_domain":"https://www.zohoapis.eu","token_type":"Bearer"}`)
	})
	var auth string
	api := serve(t, func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		io.WriteString(w, `{"devices":[{"device_id":"7","serial_number":"F9K"}]}`)
	})
	m := Manifest{
		Name: "mdmplus", Tool: "ManageEngine MDM Plus",
		Host: "mdm.manageengine.eu",
		Auth: Auth{Kind: OAuthRefresh, Secret: "zoho-client-secret",
			Scheme: "Zoho-oauthtoken",
			Token: &TokenEndpoint{Host: "accounts.zoho.eu",
				Path: "/oauth/v2/token", Client: "zoho-client-id",
				Refresh: "zoho-refresh",
				Scopes:  []string{"MDMOnDemand.MDMInventory.READ"}}},
		Endpoints: []Endpoint{{Name: "devices", Path: "/api/v1/mdm/devices",
			Produces: Identities, Records: "devices",
			Reads: []string{"device_id", "serial_number"},
			Map:   map[string]string{"id": "device_id", "serial": "serial_number"}}},
	}
	h := route(t, map[string]*httptest.Server{
		"accounts.zoho.eu": tokens, "mdm.manageengine.eu": api})
	res, err := Run(context.Background(), m, "devices", h, MapFunc{
		"zoho-client-id": "1000.CLIENT", "zoho-client-secret": "zsecret",
		"zoho-refresh": "1000.refresh"}, State{}, noSleep)
	if err != nil {
		t.Fatal(err)
	}
	if form.Get("grant_type") != "refresh_token" ||
		form.Get("refresh_token") != "1000.refresh" ||
		form.Get("client_id") != "1000.CLIENT" {
		t.Errorf("the refresh request was %v", form)
	}
	if auth != "Zoho-oauthtoken 1000.abcdef.123456" {
		t.Errorf("sent %q; Zoho refuses a token labelled Bearer", auth)
	}
	if len(res.Records) != 1 || res.Records[0]["serial"] != "F9K" {
		t.Errorf("records: %v", res.Records)
	}
}

// Zoho reports a bad refresh token with 200 and an error field.
func TestATokenEndpointErrorIsAnErrorAndDoesNotRepeatTheSecret(t *testing.T) {
	issued := 0
	for name, reply := range map[string]func(int) (int, string){
		"200 with an error": func(int) (int, string) {
			return 200, `{"error":"invalid_code"}`
		},
		"400 echoing the request": func(int) (int, string) {
			return 400, `{"error":"invalid_client","echo":"vcs_topsecret"}`
		},
		"an error field that is not a code": func(int) (int, string) {
			return 401, `{"error":"client vcs_topsecret was refused"}`
		},
		"a token with a line break": func(int) (int, string) {
			return 200, `{"access_token":"abcdefgh\r\nX-Evil: 1"}`
		},
		"no token at all": func(int) (int, string) { return 200, `{}` },
		// Go refuses a line break in a header value by itself; a space it
		// sends, so this is the case the check here is for.
		"a token with a space": func(int) (int, string) {
			return 200, `{"access_token":"abcdefgh ijklmnop"}`
		},
		"a token too short to be one": func(int) (int, string) {
			return 200, `{"access_token":"ok"}`
		},
	} {
		tokens := tokenServer(t, &issued, reply)
		// Data requests succeed whatever they carry, so a token that should
		// have been refused shows up as a run that worked.
		both := serve(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/oauth/token" {
				tokens.Config.Handler.ServeHTTP(w, r)
				return
			}
			io.WriteString(w, `{"results":{"data":[],"pageInfo":{}}}`)
		})
		h := route(t, map[string]*httptest.Server{"api.vanta.com": both})
		_, err := Run(context.Background(), vanta(), "people", h,
			vantaSecrets(), State{}, noSleep)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "vcs_topsecret") {
			t.Errorf("%s: the error repeats the secret: %v", name, err)
		}
	}
}

// A token refused once is replaced once. Refused again, it is an error, not
// a loop.
func TestARefusedTokenIsReplacedOnceAndOnlyOnce(t *testing.T) {
	for _, tc := range []struct {
		name      string
		refusals  int
		wantErr   bool
		wantToken int
	}{
		{"revoked by another process", 1, false, 2},
		{"refused every time", 100, true, 2},
	} {
		issued, refused := 0, 0
		both := serve(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/oauth/token" {
				issued++
				fmt.Fprintf(w, `{"access_token":"tok-%d-abcdefgh","expires_in":3600}`, issued)
				return
			}
			if refused < tc.refusals {
				refused++
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			io.WriteString(w, `{"results":{"data":[],"pageInfo":{}}}`)
		})
		h := route(t, map[string]*httptest.Server{"api.vanta.com": both})
		_, err := Run(context.Background(), vanta(), "people", h,
			vantaSecrets(), State{}, noSleep)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err %v", tc.name, err)
		}
		if issued != tc.wantToken {
			t.Errorf("%s: %d tokens issued", tc.name, issued)
		}
	}
}

func TestATokenThatCouldWriteIsRefused(t *testing.T) {
	for _, scope := range []string{
		"vanta-api.all:write", "vanta-api.documents:upload",
		"MDMOnDemand.MDMInventory.ALL", "DesktopCentralCloud.Inventory.UPDATE",
		"vanta-api.all:read-write:read", "admin.users:read", "",
	} {
		m := vanta()
		m.Auth.Token.Scopes = []string{scope}
		if err := m.Validate(); err == nil {
			t.Errorf("%q was accepted as a read scope", scope)
		}
	}
	for _, scope := range []string{"vanta-api.all:read",
		"MDMOnDemand.MDMInventory.READ", "DesktopCentralCloud.PatchMgmt.READ"} {
		m := vanta()
		m.Auth.Token.Scopes = []string{scope}
		if err := m.Validate(); err != nil {
			t.Errorf("%q: %v", scope, err)
		}
	}
	m := vanta()
	m.Auth.Token.Scopes = nil
	if m.Validate() == nil {
		t.Error("a token whose scopes nobody wrote down was accepted")
	}
}

func TestATokenEndpointIsCheckedLikeTheHost(t *testing.T) {
	for _, tc := range []struct{ host, path string }{
		{"169.254.169.254", "/oauth/token"},
		{"localhost", "/oauth/token"},
		{"accounts.zoho.eu", "/oauth/v2/token?client_secret=x"},
		{"accounts.zoho.eu", "//evil.example/token"},
		{"accounts.zoho.eu:8443", "/oauth/v2/token"},
	} {
		m := vanta()
		m.Auth.Token.Host, m.Auth.Token.Path = tc.host, tc.path
		if m.Validate() == nil {
			t.Errorf("%s%s was accepted as a token endpoint", tc.host, tc.path)
		}
	}
	m := vanta()
	m.Auth.Token.Client = "vci_4f8e1c2b9a7d6e5f4c3b2a1908f7e6d5c4b3a291"
	if m.Validate() == nil {
		t.Error("a client ID pasted into the manifest was accepted as a name")
	}
	m = vanta()
	m.Auth.Token = nil
	if m.Validate() == nil {
		t.Error("an OAuth connector with no token endpoint was accepted")
	}
	b := people()
	b.Auth.Token = &TokenEndpoint{Host: "a.example.com", Path: "/t",
		Client: "c", Scopes: []string{"x:read"}}
	if b.Validate() == nil {
		t.Error("a bearer connector declaring a token endpoint was accepted")
	}
}

func TestASchemeIsOneWord(t *testing.T) {
	for _, scheme := range []string{"Bearer x", "Zoho\r\nX: y", "a:b", ""} {
		m := people()
		m.Auth.Scheme = scheme
		err := m.Validate()
		if scheme == "" && err != nil {
			t.Errorf("no scheme: %v", err)
		}
		if scheme != "" && err == nil {
			t.Errorf("%q was accepted as a scheme", scheme)
		}
	}
	m := people()
	m.Auth = Auth{Kind: Basic, Secret: "p", User: "u", Scheme: "Token"}
	if m.Validate() == nil {
		t.Error("a scheme on basic auth was accepted")
	}
}

// What a read scope reaches and nothing here needs.
func TestPathsAndFieldsNobodyNeedsAreRefused(t *testing.T) {
	for _, path := range []string{
		"/api/1.4/bitlocker/recoverykeydetails",
		"/api/v1/mdm/devices/{key}/firmware/password",
		"/api/mdm/devices/locations",
		"/dcapi/credentials",
	} {
		m := people()
		m.Endpoints[0].Path = path
		if err := m.Validate(); err == nil ||
			strings.Contains(err.Error(), "placeholder") {
			t.Errorf("%s was not refused for what it reads: %v", path, err)
		}
	}
	for _, field := range []string{"admin_password", "recovery_key",
		"device.latitude", "ip_location", "client_secret"} {
		m := people()
		m.Endpoints[0].Reads = append(m.Endpoints[0].Reads, field)
		if m.Validate() == nil {
			t.Errorf("reading %s was accepted", field)
		}
	}
	for _, field := range []string{"location", "passwordManager.outcome",
		"security.passcode_present", "firmware.password_status"} {
		m := people()
		m.Endpoints[0].Reads = append(m.Endpoints[0].Reads, field)
		m.Endpoints[0].Map["posture"] = field
		if err := m.Validate(); err != nil {
			t.Errorf("%s, a fact about posture rather than a secret, was "+
				"refused: %v", field, err)
		}
	}
	for _, field := range []string{"Admin-Password", "user.passwd",
		"invsw\\.client_secret", "keys.recoveryKeys", "stored_credentials"} {
		m := people()
		m.Endpoints[0].Reads = append(m.Endpoints[0].Reads, field)
		if m.Validate() == nil {
			t.Errorf("reading %s was accepted", field)
		}
	}
}

func mdmApps() Manifest {
	return Manifest{
		Name: "mdm", Tool: "MDM", Host: "mdm.example.com",
		Auth: Auth{Kind: Bearer, Secret: "t"},
		Endpoints: []Endpoint{
			{Name: "devices", Path: "/devices", Produces: Identities,
				Records: "devices", Reads: []string{"id", "seen"},
				Map: map[string]string{"id": "id", "seen": "seen"}},
			{Name: "apps", Path: "/devices/{key}/apps", Produces: Software,
				Records: "apps", Reads: []string{"name"},
				Map:  map[string]string{"app": "name"},
				Each: &Each{Of: "devices", Key: "id"}},
		},
	}
}

func TestAPerRecordEndpointIsReadForEachParentAndSaysWhich(t *testing.T) {
	var paths []string
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.EscapedPath())
		io.WriteString(w, `{"apps":[{"name":"Slack"}]}`)
	})
	h := route(t, map[string]*httptest.Server{"mdm.example.com": s})
	x, err := NewSession(mdmApps(), h, MapFunc{"t": "k"}, noSleep)
	if err != nil {
		t.Fatal(err)
	}
	res, err := x.RunEach(context.Background(), "apps", []map[string]string{
		{"id": "7"}, {"id": "8"}, {"id": "7"},
		{"id": "../admin"}, {"id": "1?limit=99999"}, {"id": ""},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(paths, " ") != "/devices/7/apps /devices/8/apps" {
		t.Errorf("read %v; each safe key once, and nothing else", paths)
	}
	if res.Skipped != 3 {
		t.Errorf("skipped %d; three keys were not safe to put in a path",
			res.Skipped)
	}
	if len(res.Records) != 2 || res.Records[0]["parent"] != "7" ||
		res.Records[1]["parent"] != "8" {
		t.Errorf("records do not say which device they came from: %v",
			res.Records)
	}
	if _, err := x.Run(context.Background(), "apps", State{}); err == nil {
		t.Error("a per-record endpoint ran with no records to run for")
	}
}

func TestAWindowReadsOnlyRecentParents(t *testing.T) {
	var paths []string
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		io.WriteString(w, `{"apps":[]}`)
	})
	m := mdmApps()
	m.Endpoints[1].Each.When, m.Endpoints[1].Each.WithinDays = "seen", 90
	h := route(t, map[string]*httptest.Server{"mdm.example.com": s})
	x, _ := NewSession(m, h, MapFunc{"t": "k"}, noSleep)
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	x.now = func() time.Time { return now }
	recent := now.AddDate(0, 0, -10)
	x.RunEach(context.Background(), "apps", []map[string]string{
		{"id": "new", "seen": recent.Format(time.RFC3339)},
		{"id": "newms", "seen": fmt.Sprint(recent.UnixMilli())},
		{"id": "old", "seen": now.AddDate(-2, 0, 0).Format(time.RFC3339)},
		{"id": "undated", "seen": "sometime"},
	})
	if strings.Join(paths, " ") != "/devices/new/apps /devices/newms/apps" {
		t.Errorf("read %v; only the last 90 days, including a time "+
			"written in epoch milliseconds as ManageEngine writes it", paths)
	}
}

func TestAFanOutThatCouldHideIsRefused(t *testing.T) {
	cases := map[string]func(*Manifest){
		"no {key} in the path": func(m *Manifest) {
			m.Endpoints[1].Path = "/devices/apps"
		},
		"two holes": func(m *Manifest) {
			m.Endpoints[1].Path = "/devices/{key}/apps/{key}"
		},
		"a hole with no parent": func(m *Manifest) {
			m.Endpoints[0].Path = "/devices/{key}"
		},
		"an unknown parent": func(m *Manifest) { m.Endpoints[1].Each.Of = "nope" },
		"itself":            func(m *Manifest) { m.Endpoints[1].Each.Of = "apps" },
		"an unmapped key":   func(m *Manifest) { m.Endpoints[1].Each.Key = "serial" },
		"nested": func(m *Manifest) {
			m.Endpoints = append(m.Endpoints, Endpoint{Name: "files",
				Path: "/apps/{key}/files", Produces: Software, Records: "f",
				Reads: []string{"n"}, Map: map[string]string{"n": "n"},
				Each: &Each{Of: "apps", Key: "app"}})
		},
		"a window with no field": func(m *Manifest) {
			m.Endpoints[1].Each.WithinDays = 30
		},
		"a parent field of its own": func(m *Manifest) {
			m.Endpoints[1].Reads = append(m.Endpoints[1].Reads, "x")
			m.Endpoints[1].Map["parent"] = "x"
		},
	}
	for name, spoil := range cases {
		m := mdmApps()
		spoil(&m)
		if m.Validate() == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := mdmApps().Validate(); err != nil {
		t.Errorf("the plain fan-out was refused: %v", err)
	}
}

// KnowBe4's day is 2,000 requests plus one per seat, shared with the console.
func TestASpentBudgetStopsTheRunAndHoldsTheCheckpoint(t *testing.T) {
	calls := 0
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		p := r.URL.Query().Get("page")
		fmt.Fprintf(w, `[{"id":"%s","at":"2026-09-%02s"}]`, p, p)
	})
	m := Manifest{Name: "kb4", Tool: "KnowBe4", Host: "us.api.knowbe4.com",
		Auth: Auth{Kind: Bearer, Secret: "k"},
		Rate: Rate{PerSecond: 4, PerMinute: 50, PerDay: 2000},
		Endpoints: []Endpoint{{Name: "users", Path: "/v1/users",
			Produces: Identities, Reads: []string{"id", "at"},
			Map:       map[string]string{"id": "id"},
			Watermark: "at", Since: "since",
			Page: Pagination{Kind: PageNumber, Param: "page", Size: 1}}}}
	h := route(t, map[string]*httptest.Server{"us.api.knowbe4.com": s})
	x, err := NewSession(m, h, MapFunc{"k": "key"}, noSleep)
	if err != nil {
		t.Fatal(err)
	}
	x.Budget = 3
	res, err := x.Run(context.Background(), "users", State{})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 || x.Requests != 3 || x.Budget != 0 {
		t.Errorf("%d calls, %d counted, %d left", calls, x.Requests, x.Budget)
	}
	if res.Complete() || !strings.Contains(res.Truncated, "budget") {
		t.Errorf("a run stopped by its budget reads as %q", res.Truncated)
	}
	if res.Watermark != "" {
		t.Error("the checkpoint moved past records the budget left unread")
	}
}

func TestTheDeclaredPaceIsKept(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `[]`)
	})
	m := people()
	m.Endpoints[0].Records = ""
	m.Rate = Rate{PerSecond: 4, PerMinute: 50}
	var waits []time.Duration
	sleep := func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}
	h := route(t, map[string]*httptest.Server{"acme.api.kandji.io": s})
	x, _ := NewSession(m, h, secrets(), sleep)
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	x.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		x.Run(context.Background(), "devices", State{})
	}
	// Fifty a minute is the tighter of the two: 1.2s apart.
	if len(waits) != 2 || waits[0] != 1200*time.Millisecond {
		t.Errorf("waited %v; three requests at fifty a minute wait 1.2s "+
			"twice", waits)
	}
}

func TestACursorCanArriveInAHeader(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("cursor") {
		case "true":
			w.Header().Set("X-Next-Cursor", "c2")
			io.WriteString(w, `[{"id":"1"}]`)
		case "c2":
			io.WriteString(w, `[{"id":"2"}]`)
		default:
			t.Errorf("asked for cursor %q", r.URL.Query().Get("cursor"))
		}
	})
	m := people()
	m.Endpoints[0].Records = ""
	m.Endpoints[0].Query = map[string]string{"cursor": "true"}
	m.Endpoints[0].Page = Pagination{Kind: Cursor, From: "header:X-Next-Cursor",
		Param: "cursor"}
	h := route(t, map[string]*httptest.Server{"acme.api.kandji.io": s})
	res, err := Run(context.Background(), m, "devices", h, secrets(),
		State{}, noSleep)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 2 {
		t.Errorf("%d records over %d pages", len(res.Records), res.Pages)
	}
	m.Endpoints[0].Page.From = "header:X Next"
	if m.Validate() == nil {
		t.Error("a header name with a space was accepted")
	}
}

// A Link header is the server choosing the next URL, so it gets the same
// host check as a next URL in the body.
func TestALinkHeaderIsFollowedOnlyToTheDeclaredHost(t *testing.T) {
	for _, tc := range []struct {
		link    string
		wantErr bool
	}{
		{`<https://acme.api.kandji.io/api/v1/devices?page=2>; rel="next"`, false},
		{`<https://collector.example.net/steal>; rel="next"`, true},
	} {
		n := 0
		s := serve(t, func(w http.ResponseWriter, r *http.Request) {
			n++
			if n == 1 {
				w.Header().Set("Link", tc.link)
			}
			io.WriteString(w, `[{"device_id":"1"}]`)
		})
		m := people()
		m.Endpoints[0].Records = ""
		m.Endpoints[0].Page = Pagination{Kind: NextURL, From: "header:Link"}
		h := route(t, map[string]*httptest.Server{"acme.api.kandji.io": s})
		_, err := Run(context.Background(), m, "devices", h, secrets(),
			State{}, noSleep)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: %v", tc.link, err)
		}
	}
}

// ManageEngine's identifiers are past 2^53, where a float64 rounds odd
// numbers to a neighbour.
func TestALargeIdentifierIsKeptExactlyAndReadsTheRightDevice(t *testing.T) {
	var paths []string
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/devices" {
			io.WriteString(w, `{"devices":[{"id":9007199254741001,"seen":1557128715277}]}`)
			return
		}
		io.WriteString(w, `{"apps":[{"name":"Slack"}]}`)
	})
	h := route(t, map[string]*httptest.Server{"mdm.example.com": s})
	x, _ := NewSession(mdmApps(), h, MapFunc{"t": "k"}, noSleep)
	devices, err := x.Run(context.Background(), "devices", State{})
	if err != nil {
		t.Fatal(err)
	}
	if got := devices.Records[0]["id"]; got != "9007199254741001" {
		t.Fatalf("the device is %s", got)
	}
	if _, err := x.RunEach(context.Background(), "apps", devices.Records); err != nil {
		t.Fatal(err)
	}
	if paths[1] != "/devices/9007199254741001/apps" {
		t.Errorf("read %s: a neighbouring device's apps, filed under this one",
			paths[1])
	}
}

// Endpoint Central names a field invsw.software_name: one key, with a dot.
func TestAKeyWithADotInItIsReachedByEscapingTheDot(t *testing.T) {
	doc := map[string]any{"invsw.software_name": "Slack",
		"invsw": map[string]any{"software_name": "nested"}}
	if got := At(doc, `invsw\.software_name`); got != "Slack" {
		t.Errorf("escaped: %q", got)
	}
	if got := At(doc, "invsw.software_name"); got != "nested" {
		t.Errorf("unescaped still nests: %q", got)
	}
	// What probe prints is what an author pastes, and it must mean the
	// same key.
	only := map[string]any{"invsw.software_name": "Slack"}
	for _, p := range Paths(only, 10) {
		if At(only, p) != "Slack" {
			t.Errorf("Paths printed %s, which does not reach the key", p)
		}
	}
}

func TestAnInnerArrayBecomesRecordsThatKnowTheirOuterRecord(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"message_response":{"systemreport":[
			{"resource_id":"304","vulnerabilities":[
				{"vulnerabilityid":"148376","severity":"Moderate"},
				{"vulnerabilityid":"154557","severity":"Important"}]},
			{"resource_id":"305","vulnerabilities":[]},
			{"resource_id":"306","vulnerabilities":["not an object"]}]}}`)
	})
	m := Manifest{Name: "ec", Tool: "Endpoint Central",
		Host: "endpointcentral.manageengine.com",
		Auth: Auth{Kind: Bearer, Secret: "t"},
		Endpoints: []Endpoint{{Name: "vulns",
			Path: "/dcapi/threats/systemreport/vulnerabilities",
			Produces: Vulnerability, Records: "message_response.systemreport",
			Explode: "vulnerabilities",
			Reads:   []string{"^.resource_id", "vulnerabilityid", "severity"},
			Map: map[string]string{"computer": "^.resource_id",
				"id": "vulnerabilityid", "severity": "severity"}}}}
	h := route(t, map[string]*httptest.Server{
		"endpointcentral.manageengine.com": s})
	res, err := Run(context.Background(), m, "vulns", h, MapFunc{"t": "k"},
		State{}, noSleep)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 2 {
		t.Fatalf("%d records: %v", len(res.Records), res.Records)
	}
	if res.Records[1]["computer"] != "304" ||
		res.Records[1]["id"] != "154557" {
		t.Errorf("a vulnerability lost the computer it is on: %v",
			res.Records[1])
	}
}

func TestTheDeclaredMediaTypeIsAskedFor(t *testing.T) {
	var accept string
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		accept = r.Header.Get("Accept")
		io.WriteString(w, `{"results":[]}`)
	})
	m := people()
	m.Endpoints[0].Accept = "application/softwareInfo.v1+json"
	h := route(t, map[string]*httptest.Server{"acme.api.kandji.io": s})
	if _, err := Run(context.Background(), m, "devices", h, secrets(),
		State{}, noSleep); err != nil {
		t.Fatal(err)
	}
	if accept != "application/softwareInfo.v1+json" {
		t.Errorf("asked for %q", accept)
	}
	for _, bad := range []string{"text/html", "application/json\r\nX: y",
		"*/*"} {
		m.Endpoints[0].Accept = bad
		if m.Validate() == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// Vanta's last page still carries a cursor.
func TestAFlagSayingThereIsNoMoreEndsTheRead(t *testing.T) {
	calls := 0
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		io.WriteString(w, `{"results":{"data":[{"id":"1"}],
			"pageInfo":{"hasNextPage":false,"endCursor":"YXJy"}}}`)
	})
	m := vanta()
	m.Auth = Auth{Kind: Bearer, Secret: "t"}
	m.Endpoints[0].Page.More = "results.pageInfo.hasNextPage"
	h := route(t, map[string]*httptest.Server{"api.vanta.com": s})
	if _, err := Run(context.Background(), m, "people", h, MapFunc{"t": "k"},
		State{}, noSleep); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("%d requests for one page that said it was the last", calls)
	}
}

// A tool that answers every page with the cursor it was given would be read
// a thousand times over.
func TestAToolPointingBackAtThePageItServedIsNotFollowed(t *testing.T) {
	for _, page := range []Pagination{
		{Kind: Cursor, From: "next", Param: "cursor"},
		{Kind: NextURL, From: "next"},
	} {
		calls := 0
		s := serve(t, func(w http.ResponseWriter, r *http.Request) {
			calls++
			next := "same"
			if page.Kind == NextURL {
				next = "/api/v1/devices?cursor=same"
			}
			fmt.Fprintf(w, `{"results":[{"device_id":"1"}],"next":%q}`, next)
		})
		m := people()
		m.Endpoints[0].Page = page
		m.Endpoints[0].Query = map[string]string{"cursor": "same"}
		h := route(t, map[string]*httptest.Server{"acme.api.kandji.io": s})
		_, err := Run(context.Background(), m, "devices", h, secrets(),
			State{}, noSleep)
		if err == nil || calls > 2 {
			t.Errorf("%s: %d requests, err %v", page.Kind, calls, err)
		}
	}
}
