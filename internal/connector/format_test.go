// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// manifestFormatDigest is the SHA-256 of testdata/manifest-format.json, the
// manifest both repositories that read this format hold byte for byte.
const manifestFormatDigest = "7fa9dae2268a6c5b6366efdbb931f8be66f4d6d3ba57ca4443e0861ee6b839f4"

// The shared fixture is the format, unchanged, and still reads.
//
// The digest is what keeps the two copies of the engine reading one format:
// a field added, renamed or given a new meaning here shows up as this test
// failing, and the change is then made to the fixture, and to its digest, in
// both. The fixture uses the format as it is shared and none of what this
// copy adds, so a manifest written for either reads in both.
func TestManifestFormatFixtureDigest(t *testing.T) {
	b, err := os.ReadFile("testdata/manifest-format.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != manifestFormatDigest {
		t.Fatalf("the shared manifest fixture's digest is %s and the format pins %s: the format changed, so make the same "+
			"change to the fixture beside the engine it was copied from and pin the new digest in both", got, manifestFormatDigest)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("the shared fixture no longer decodes as a manifest: %v", err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("the shared fixture no longer validates: %v", err)
	}
	if m.Auth.Kind.signs() {
		t.Error("the shared fixture uses a way to authenticate only this copy has")
	}
	for _, e := range m.Endpoints {
		if e.Each != nil && e.Each.Also != "" {
			t.Errorf("%s uses a second key, which only this copy has", e.Name)
		}
	}
	// Every field of the format is in the fixture, so a field dropped from
	// the struct is noticed as well as one added to it.
	again, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var have, want map[string]any
	_ = json.Unmarshal(again, &have)
	_ = json.Unmarshal(b, &want)
	for k := range want {
		if _, ok := have[k]; !ok {
			t.Errorf("the manifest lost the field %q in reading", k)
		}
	}
}

// A manifest names one host for its data and, for the OAuth kinds, one for
// its token, and nothing it holds or is handed back reaches a third.
func TestManifestCannotLeaveHost(t *testing.T) {
	base := people()
	for name, change := range map[string]func(*Manifest){
		"two hosts in one":         func(m *Manifest) { m.Host = "acme.api.kandji.io,evil.example.com" },
		"a host and a path":        func(m *Manifest) { m.Host = "acme.api.kandji.io/evil.example.com" },
		"a URL for a path":         func(m *Manifest) { m.Endpoints[0].Path = "https://evil.example.com/api" },
		"a protocol-relative path": func(m *Manifest) { m.Endpoints[0].Path = "//evil.example.com/api" },
		"a wildcard host":          func(m *Manifest) { m.Host = "*.kandji.io" },
		"an address for a host":    func(m *Manifest) { m.Host = "169.254.169.254" },
		"a token on a URL": func(m *Manifest) {
			m.Auth = Auth{Kind: OAuthClient, Secret: "s", Token: &TokenEndpoint{Host: "https://evil.example.com",
				Path: "/token", Client: "c", Scopes: []string{"x:read"}}}
		},
		"a token path with a query": func(m *Manifest) {
			m.Auth = Auth{Kind: OAuthClient, Secret: "s", Token: &TokenEndpoint{Host: "login.example.com",
				Path: "/token?redirect=evil.example.com", Client: "c", Scopes: []string{"x:read"}}}
		},
	} {
		m := base
		m.Endpoints = append([]Endpoint(nil), base.Endpoints...)
		change(&m)
		if err := m.Validate(); err == nil {
			t.Errorf("a manifest with %s was accepted", name)
		}
	}

	// And on the way back: neither a next URL nor a Link header the server
	// writes takes a request elsewhere.
	for _, from := range []string{"next", "header:Link"} {
		served := 0
		s := serve(t, func(w http.ResponseWriter, r *http.Request) {
			served++
			w.Header().Set("Link", `<https://evil.example.com/api/v1/devices?page=2>; rel="next"`)
			w.Write(page([]map[string]any{{"device_id": served}}, map[string]any{
				"next": "https://evil.example.com/api/v1/devices?page=2"}))
		})
		m := people()
		m.Endpoints[0].Page = Pagination{Kind: NextURL, From: from}
		c := dialTo(t, s)
		_, err := Run(context.Background(), m, "devices", c, secrets(), State{}, noSleep)
		if err == nil || !strings.Contains(err.Error(), "evil.example.com") {
			t.Errorf("%s: a next page on another host was followed or not named: %v", from, err)
		}
		for _, u := range c.last {
			if strings.Contains(u, "evil.example.com") {
				t.Errorf("%s: a request was built for %s", from, u)
			}
		}
	}
}

// A 403 that is GitHub's spent rate limit is waited out until the moment it
// names, on the session's clock; a 403 that is not is a refusal by status,
// at once, with nothing waited.
func TestRateLimitBackoff(t *testing.T) {
	now := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	reset := now.Add(30 * time.Second)
	calls := 0
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch calls {
		case 1:
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", jsonInt(reset.Unix()))
			w.WriteHeader(http.StatusForbidden)
		case 2:
			// A secondary limit: 403 with Retry-After.
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusForbidden)
		default:
			w.Write(page([]map[string]any{{"device_id": 1}}, nil))
		}
	})
	var waited []time.Duration
	sleep := func(_ context.Context, d time.Duration) error { waited = append(waited, d); return nil }
	x, err := NewSession(people(), dialTo(t, s), secrets(), sleep)
	if err != nil {
		t.Fatal(err)
	}
	x.Clock(func() time.Time { return now })
	out, err := x.Run(context.Background(), "devices", State{})
	if err != nil {
		t.Fatalf("a rate limit was taken for a refusal: %v", err)
	}
	if len(out.Records) != 1 || calls != 3 {
		t.Fatalf("%d records in %d calls", len(out.Records), calls)
	}
	if len(waited) != 2 || waited[0] != 31*time.Second || waited[1] != 7*time.Second {
		t.Errorf("waited %v; the reset was 30 seconds away, and then a Retry-After of 7", waited)
	}
	if out.Waited != 38*time.Second {
		t.Errorf("the run says it waited %s", out.Waited)
	}

	// A refusal of what the credential may read is not waited for.
	refused := serve(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	waited = nil
	x, _ = NewSession(people(), dialTo(t, refused), secrets(), sleep)
	_, err = x.Run(context.Background(), "devices", State{})
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusForbidden || len(waited) != 0 {
		t.Errorf("a plain 403: %v, waited %v", err, waited)
	}
	if err == nil || err.Error() != "kandji/devices answered 403" {
		t.Errorf("the refusal reads %q, not as it always has", err)
	}

	// A limit that does not lift is left for the next run, not waited on
	// for ever.
	limited := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", jsonInt(now.Add(time.Hour).Unix()))
		w.WriteHeader(http.StatusForbidden)
	})
	waited = nil
	x, _ = NewSession(people(), dialTo(t, limited), secrets(), sleep)
	x.Clock(func() time.Time { return now })
	if _, err := x.Run(context.Background(), "devices", State{}); err == nil || !strings.Contains(err.Error(), "next scheduled run") {
		t.Errorf("a limit an hour long: %v", err)
	}
	for _, d := range waited {
		if d > 2*time.Minute {
			t.Errorf("one wait was %s; a wait is at most two minutes", d)
		}
	}
}

func jsonInt(n int64) string { b, _ := json.Marshal(n); return string(b) }

// A list of plain values is kept as one field, and a list of objects is
// still nothing.
func TestAListOfValuesIsOneField(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(page([]map[string]any{{"device_id": 1, "device_name": "a",
			"user":     map[string]any{"email": []any{"x@acme.test", "y@acme.test"}},
			"platform": []any{map[string]any{"a": 1}}}}, nil))
	})
	m := people()
	m.Endpoints[0].Map["platform"] = "platform"
	out, err := Run(context.Background(), m, "devices", dialTo(t, s), secrets(), State{}, noSleep)
	if err != nil {
		t.Fatal(err)
	}
	if got := out.Records[0]["email"]; got != "x@acme.test,y@acme.test" {
		t.Errorf("a list of values reads %q", got)
	}
	if got, ok := out.Records[0]["platform"]; ok {
		t.Errorf("a list of objects reads %q", got)
	}
}

// A per-record endpoint read by two keys fills both, and skips a record
// whose second key is not safe in a path.
func TestASecondKeyIsCheckedLikeTheFirst(t *testing.T) {
	var paths []string
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos" {
			w.Write([]byte(`[{"name":"api","branch":"main"},{"name":"web","branch":"../admin"},{"name":"ops","branch":"trunk"}]`))
			return
		}
		paths = append(paths, r.URL.Path)
		w.Write([]byte(`{"protected":true}`))
	})
	m := Manifest{Name: "code", Tool: "A code host", Host: "code.example.com",
		Auth: Auth{Kind: Bearer, Secret: "t"},
		Endpoints: []Endpoint{
			{Name: "repos", Path: "/repos", Produces: Devices, Reads: []string{"name", "branch"},
				Map: map[string]string{"name": "name", "branch": "branch"}},
			{Name: "branch", Path: "/repos/{key}/branches/{also}", Produces: Devices, Single: true,
				Each:  &Each{Of: "repos", Key: "name", Also: "branch"},
				Reads: []string{"protected"}, Map: map[string]string{"protected": "protected"}},
		}}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	x, _ := NewSession(m, route(t, map[string]*httptest.Server{"code.example.com": s}), MapFunc{"t": "k"}, noSleep)
	reads := x.All(context.Background(), nil, nil)
	var branch Read
	for _, r := range reads {
		if r.Endpoint == "branch" {
			branch = r
		}
	}
	if branch.Err != nil || len(branch.Result.Records) != 2 || branch.Result.Skipped != 1 {
		t.Fatalf("%+v", branch)
	}
	if strings.Join(paths, " ") != "/repos/api/branches/main /repos/ops/branches/trunk" {
		t.Errorf("read %v", paths)
	}
	m.Endpoints[1].Path = "/repos/{key}/branches/main"
	if m.Validate() == nil {
		t.Error("a second key with no place in the path was accepted")
	}
}

// Every page a run reads is handed over exactly as it came, and a page the
// tool refused is handed over by its status; read again, a kept page gives
// the records the run gave.
func TestEveryPageIsKeptAsItCameAndReadsAgainTheSame(t *testing.T) {
	calls := 0
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Write(page([]map[string]any{{"device_id": 1, "device_name": "a"}}, map[string]any{"next": "/api/v1/devices?page=2"}))
			return
		}
		w.Write(page([]map[string]any{{"device_id": 2, "device_name": "b"}}, nil))
	})
	m := people()
	m.Endpoints[0].Page = Pagination{Kind: NextURL, From: "next"}
	x, err := NewSession(m, dialTo(t, s), secrets(), noSleep)
	if err != nil {
		t.Fatal(err)
	}
	var kept []Page
	x.Keep = func(p Page) { kept = append(kept, p) }
	out, err := x.Run(context.Background(), "devices", State{})
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 2 || kept[0].Status != 200 || !strings.HasPrefix(kept[1].Path, "/api/v1/devices") {
		t.Fatalf("kept %+v", kept)
	}
	var again []map[string]string
	for _, p := range kept {
		recs, err := Records(m, p.Endpoint, p.Body, p.Parent)
		if err != nil {
			t.Fatal(err)
		}
		again = append(again, recs...)
	}
	if len(again) != len(out.Records) || again[1]["name"] != out.Records[1]["name"] {
		t.Errorf("read again %v, and the run read %v", again, out.Records)
	}
	for _, p := range kept {
		if strings.Contains(p.Path, "s3cret") {
			t.Error("a kept page's path holds the credential")
		}
	}

	refused := serve(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	x, _ = NewSession(people(), dialTo(t, refused), secrets(), noSleep)
	kept = nil
	x.Keep = func(p Page) { kept = append(kept, p) }
	if _, err := x.Run(context.Background(), "devices", State{}); err == nil {
		t.Fatal("a refusal read as a page")
	}
	if len(kept) != 1 || kept[0].Status != http.StatusForbidden || kept[0].Body != nil {
		t.Errorf("a refused page was kept as %+v", kept)
	}
}
