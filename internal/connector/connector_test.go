// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A Doer that rewrites the manifest's host to a test server, so the run loop
// under test is the real one: real requests, real headers, real pagination,
// real rate-limit responses. Only the name resolution is faked, which is the
// one part this package does not implement.
type toServer struct {
	base *url.URL
	seen []*http.Request
	// last is the raw URL as the loop built it, before rewriting, so a test
	// can assert on what the connector decided rather than on what the
	// server received.
	last []string
}

func (t *toServer) Do(req *http.Request) (*http.Response, error) {
	t.last = append(t.last, req.URL.String())
	t.seen = append(t.seen, req.Clone(req.Context()))
	out := *req.URL
	out.Scheme, out.Host = t.base.Scheme, t.base.Host
	fresh, err := http.NewRequestWithContext(req.Context(), req.Method,
		out.String(), nil)
	if err != nil {
		return nil, err
	}
	fresh.Header = req.Header.Clone()
	return http.DefaultClient.Do(fresh)
}

func dialTo(t *testing.T, s *httptest.Server) *toServer {
	t.Helper()
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &toServer{base: u}
}

func noSleep(context.Context, time.Duration) error { return nil }

func people() Manifest {
	return Manifest{
		Name: "kandji", Tool: "Kandji MDM", Host: "acme.api.kandji.io",
		Auth: Auth{Kind: Bearer, Secret: "kandji-token"},
		Endpoints: []Endpoint{{
			Name: "devices", Path: "/api/v1/devices", Produces: Identities,
			Records: "results",
			Reads: []string{"device_id", "device_name", "user.email",
				"last_check_in", "platform"},
			Map: map[string]string{
				"id": "device_id", "name": "device_name",
				"email": "user.email", "seen": "last_check_in",
			},
		}},
	}
}

func secrets() Secrets { return MapFunc{"kandji-token": "s3cret"} }

func serve(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s
}

func page(records []map[string]any, extra map[string]any) []byte {
	body := map[string]any{"results": records}
	for k, v := range extra {
		body[k] = v
	}
	b, _ := json.Marshal(body)
	return b
}

func TestAConnectorKeepsOnlyWhatItDeclared(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(page([]map[string]any{{
			"device_id": 1043, "device_name": "Jane's MBP",
			"user": map[string]any{"email": "jane@acme.test"},
			// The field nobody's integration needed and every integration
			// could see.
			"notes":         "recovery key ABCD-1234, root password hunter2",
			"last_check_in": "2026-09-25T10:00:00Z",
		}}, nil))
	})
	c := dialTo(t, s)
	out, err := Run(context.Background(), people(), "devices", c, secrets(),
		State{}, noSleep)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Records) != 1 {
		t.Fatalf("%d records", len(out.Records))
	}
	rec := out.Records[0]
	if rec["id"] != "1043" {
		// An identifier arriving as 1.043e+03 is a different identifier, and
		// a join on it silently finds nobody.
		t.Errorf("the id is %q", rec["id"])
	}
	if rec["email"] != "jane@acme.test" {
		t.Errorf("the nested field did not map: %q", rec["email"])
	}
	for k, v := range rec {
		if strings.Contains(v, "hunter2") || strings.Contains(v, "recovery") {
			t.Fatalf("%s carries a field the connector never declared: %q",
				k, v)
		}
	}
	if _, ok := rec["notes"]; ok {
		t.Fatal("an undeclared field came back")
	}
}

func TestAMappingOfSomethingUndeclaredIsRefused(t *testing.T) {
	m := people()
	m.Endpoints[0].Map["notes"] = "notes"
	err := m.Validate()
	if err == nil {
		t.Fatal("a manifest mapping an undeclared field loaded")
	}
	if !strings.Contains(err.Error(), "reads") {
		t.Errorf("the refusal does not name the declaration: %v", err)
	}
	// And the declaration cannot silently rot: adding it to reads is the
	// edit a reviewer sees.
	m.Endpoints[0].Reads = append(m.Endpoints[0].Reads, "notes")
	if err := m.Validate(); err != nil {
		t.Fatalf("declaring it did not help: %v", err)
	}
}

// The reason next-url pagination is named separately from cursor.
func TestAToolCannotChooseWhereTheNextRequestGoes(t *testing.T) {
	var served int
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		served++
		w.Write(page([]map[string]any{{"device_id": served}},
			map[string]any{
				// Somewhere the credential in this request should never go.
				"next": "https://169.254.169.254/latest/meta-data/",
			}))
	})
	m := people()
	m.Endpoints[0].Page = Pagination{Kind: NextURL, From: "next"}
	c := dialTo(t, s)

	_, err := Run(context.Background(), m, "devices", c, secrets(), State{},
		noSleep)
	if err == nil {
		t.Fatal("the connector followed a URL the server chose")
	}
	if !strings.Contains(err.Error(), "169.254.169.254") ||
		!strings.Contains(err.Error(), "acme.api.kandji.io") {
		t.Errorf("the error does not say what was refused: %v", err)
	}
	if !strings.Contains(err.Error(), "carries its own credential") {
		t.Errorf("the error does not say why it matters: %v", err)
	}
	if served != 1 {
		t.Errorf("%d requests made", served)
	}
}

func TestARelativeNextStaysOnTheDeclaredHost(t *testing.T) {
	var served int
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		served++
		extra := map[string]any{}
		if served == 1 {
			extra["next"] = "/api/v1/devices?page=2"
		}
		w.Write(page([]map[string]any{{"device_id": served}}, extra))
	})
	m := people()
	m.Endpoints[0].Page = Pagination{Kind: NextURL, From: "next"}
	c := dialTo(t, s)

	out, err := Run(context.Background(), m, "devices", c, secrets(), State{},
		noSleep)
	if err != nil {
		t.Fatal(err)
	}
	if out.Pages != 2 || len(out.Records) != 2 {
		t.Fatalf("%d pages, %d records", out.Pages, len(out.Records))
	}
	for _, raw := range c.last {
		if !strings.Contains(raw, "acme.api.kandji.io") {
			t.Errorf("a request went to %s", raw)
		}
	}
}

func TestCursorPaginationFollowsTheBodyAndStopsWhenItIsEmpty(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("cursor") {
		case "":
			w.Write(page([]map[string]any{{"device_id": 1}},
				map[string]any{"meta": map[string]any{"next": "abc"}}))
		case "abc":
			w.Write(page([]map[string]any{{"device_id": 2}},
				map[string]any{"meta": map[string]any{"next": ""}}))
		default:
			t.Errorf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	})
	m := people()
	m.Endpoints[0].Page = Pagination{Kind: Cursor, From: "meta.next",
		Param: "cursor"}
	out, err := Run(context.Background(), m, "devices", dialTo(t, s),
		secrets(), State{}, noSleep)
	if err != nil {
		t.Fatal(err)
	}
	if out.Pages != 2 || len(out.Records) != 2 {
		t.Fatalf("%d pages, %d records", out.Pages, len(out.Records))
	}
	if !out.Complete() {
		t.Errorf("a run that saw everything reports %q", out.Truncated)
	}
}

func TestOffsetPaginationStopsOnAShortPage(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		var recs []map[string]any
		for n := off; n < off+2 && n < 5; n++ {
			recs = append(recs, map[string]any{"device_id": n})
		}
		w.Write(page(recs, nil))
	})
	m := people()
	m.Endpoints[0].Page = Pagination{Kind: Offset, Param: "offset",
		Size: 2, SizeParam: "limit"}
	out, err := Run(context.Background(), m, "devices", dialTo(t, s),
		secrets(), State{}, noSleep)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Records) != 5 {
		t.Fatalf("%d records, want 5", len(out.Records))
	}
}

func TestPageNumbersStartWhereTheManifestSays(t *testing.T) {
	var firstSeen string
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if firstSeen == "" {
			firstSeen = r.URL.Query().Get("page")
		}
		w.Write(page(nil, nil))
	})
	m := people()
	m.Endpoints[0].Page = Pagination{Kind: PageNumber, Param: "page",
		Size: 50, SizeParam: "per_page"}
	if _, err := Run(context.Background(), m, "devices", dialTo(t, s),
		secrets(), State{}, noSleep); err != nil {
		t.Fatal(err)
	}
	// Counting from one, because an API that counts from one and a client
	// that counts from zero silently repeats a page or skips one.
	if firstSeen != "1" {
		t.Errorf("the first page was %q", firstSeen)
	}
}

func TestPaginationWithNoPageSizeIsRefused(t *testing.T) {
	m := people()
	m.Endpoints[0].Page = Pagination{Kind: Offset, Param: "offset"}
	err := m.Validate()
	if err == nil {
		t.Fatal("an offset strategy with no page size loaded")
	}
	if !strings.Contains(err.Error(), "skips records or repeats them") {
		t.Errorf("the refusal does not say what goes wrong: %v", err)
	}
}

func TestTheCredentialIsSentAndTheManifestHoldsNone(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer s3cret" {
			t.Errorf("Authorization is %q", got)
		}
		w.Write(page(nil, nil))
	})
	if _, err := Run(context.Background(), people(), "devices", dialTo(t, s),
		secrets(), State{}, noSleep); err != nil {
		t.Fatal(err)
	}

	// And a manifest carrying a credential rather than a name is refused,
	// because the way this goes wrong is somebody pasting a token in to test
	// it and committing the file.
	for _, pasted := range []string{
		"Bearer eyJhbGciOi", "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
		"xoxb-2404-xyz", "sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	} {
		m := people()
		m.Auth.Secret = pasted
		if err := m.Validate(); err == nil {
			t.Errorf("a manifest holding %q loaded", pasted)
		}
	}
}

func TestAnEmptyCredentialIsRefusedBeforeTheRequest(t *testing.T) {
	var reached bool
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusUnauthorized)
	})
	_, err := Run(context.Background(), people(), "devices", dialTo(t, s),
		MapFunc{"kandji-token": ""}, State{}, noSleep)
	if err == nil {
		t.Fatal("an empty credential was used")
	}
	if !strings.Contains(err.Error(), "revoked token") {
		t.Errorf("the error does not say why this matters: %v", err)
	}
	if reached {
		t.Error("the request was made anyway")
	}
}

func TestRetryAfterIsHonouredBeforeAnythingElse(t *testing.T) {
	var calls int
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "7")
			// The draft field says something different, and Retry-After wins
			// because it is RFC 9110 and every vendor emits it.
			w.Header().Set("RateLimit", `"default";r=0;t=99`)
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write(page([]map[string]any{{"device_id": 1}}, nil))
	})
	var waited []time.Duration
	sleep := func(_ context.Context, d time.Duration) error {
		waited = append(waited, d)
		return nil
	}
	out, err := Run(context.Background(), people(), "devices", dialTo(t, s),
		secrets(), State{}, sleep)
	if err != nil {
		t.Fatal(err)
	}
	if len(waited) != 1 || waited[0] != 7*time.Second {
		t.Fatalf("waited %v, want the 7 seconds Retry-After asked for",
			waited)
	}
	if len(out.Records) != 1 {
		t.Errorf("%d records after the retry", len(out.Records))
	}
	if out.Waited != 7*time.Second {
		t.Errorf("the run reports %s spent waiting", out.Waited)
	}
}

func TestTheDraftRateLimitFieldIsReadInBothSpellings(t *testing.T) {
	for header, want := range map[string]time.Duration{
		`"default";r=0;t=30`:               30 * time.Second,
		`limit=100, remaining=0, reset=45`: 45 * time.Second,
	} {
		res := &http.Response{Header: http.Header{}}
		res.Header.Set("RateLimit", header)
		got := backoff(res, 1)
		if got != want {
			t.Errorf("%q gave %s, want %s", header, got, want)
		}
	}
}

func TestBackoffIsJitteredSoAFleetDoesNotReturnTogether(t *testing.T) {
	res := &http.Response{Header: http.Header{}}
	seen := map[time.Duration]bool{}
	for range 40 {
		seen[backoff(res, 3)] = true
	}
	if len(seen) < 2 {
		t.Fatal("every backoff was identical, so a fleet of connectors " +
			"comes back at exactly the same moment")
	}
	for d := range seen {
		if d < 4*time.Second || d > 7*time.Second {
			t.Errorf("a jittered third attempt waited %s", d)
		}
	}
}

func TestAToolThatKeepsLimitingIsLeftForTheNextRun(t *testing.T) {
	var calls int
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	_, err := Run(context.Background(), people(), "devices", dialTo(t, s),
		secrets(), State{}, noSleep)
	if err == nil {
		t.Fatal("a connector retried for ever")
	}
	if calls != MaxAttempts {
		t.Errorf("%d attempts, want %d", calls, MaxAttempts)
	}
	if !strings.Contains(err.Error(), "next scheduled run") {
		t.Errorf("the error does not say what to do: %v", err)
	}
}

// A watermark past records nobody read is a gap that never reports itself.
func TestTheCheckpointDoesNotMoveWhenARunWasTruncated(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(page([]map[string]any{
			{"device_id": 1, "last_check_in": "2026-09-01T00:00:00Z"},
			{"device_id": 2, "last_check_in": "2026-09-20T00:00:00Z"},
		}, map[string]any{"meta": map[string]any{"next": "more"}}))
	})
	m := people()
	m.Endpoints[0].Page = Pagination{Kind: Cursor, From: "meta.next",
		Param: "cursor"}
	m.Endpoints[0].Since = "updated_after"
	m.Endpoints[0].Watermark = "last_check_in"
	m.Pages = 2

	out, err := Run(context.Background(), m, "devices", dialTo(t, s),
		secrets(), State{Watermark: "2026-08-01T00:00:00Z"}, noSleep)
	if err != nil {
		t.Fatal(err)
	}
	if out.Complete() {
		t.Fatal("an endless cursor ran to completion")
	}
	if out.Watermark != "" {
		t.Fatalf("the checkpoint advanced to %q on a truncated run, so the "+
			"next run starts after records nobody read", out.Watermark)
	}
	if !strings.Contains(out.Truncated, "there may be more") {
		t.Errorf("the truncation is not explained: %q", out.Truncated)
	}
}

func TestTheCheckpointMovesOnACompleteRunAndIsSentNextTime(t *testing.T) {
	var asked []string
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Query().Get("updated_after"))
		w.Write(page([]map[string]any{
			{"device_id": 1, "last_check_in": "2026-09-20T00:00:00Z"},
			{"device_id": 2, "last_check_in": "2026-09-25T00:00:00Z"},
		}, nil))
	})
	m := people()
	m.Endpoints[0].Since = "updated_after"
	m.Endpoints[0].Watermark = "last_check_in"

	out, err := Run(context.Background(), m, "devices", dialTo(t, s),
		secrets(), State{}, noSleep)
	if err != nil {
		t.Fatal(err)
	}
	if out.Watermark != "2026-09-25T00:00:00Z" {
		t.Fatalf("the checkpoint is %q", out.Watermark)
	}
	if _, err := Run(context.Background(), m, "devices", dialTo(t, s),
		secrets(), State{Watermark: out.Watermark}, noSleep); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 2 || asked[1] != "2026-09-25T00:00:00Z" {
		t.Errorf("the second run asked for %v", asked)
	}
}

func TestAnIncrementalPullWithNothingToRememberIsRefused(t *testing.T) {
	m := people()
	m.Endpoints[0].Since = "updated_after"
	err := m.Validate()
	if err == nil {
		t.Fatal("an incremental pull with no watermark loaded")
	}
	if !strings.Contains(err.Error(), "since the same moment") {
		t.Errorf("the refusal does not say what happens: %v", err)
	}
}

func TestAResponseThatChangedShapeIsAnErrorNotAnEmptyEstate(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		// The tool renamed results to data in a minor release.
		w.Write([]byte(`{"data":[{"device_id":1}]}`))
	})
	_, err := Run(context.Background(), people(), "devices", dialTo(t, s),
		secrets(), State{}, noSleep)
	if err == nil {
		t.Fatal("a renamed field produced zero records and no error, which " +
			"reads as an estate with nothing in it")
	}
	if !strings.Contains(err.Error(), "nothing in it") {
		t.Errorf("the error does not say why silence is the danger: %v", err)
	}
}

func TestAHostThatIsNotOneOrdinaryHostnameIsRefused(t *testing.T) {
	for host, why := range map[string]string{
		"https://api.acme.test": "a URL",
		"*.acme.test":           "a wildcard",
		"user:pw@api.acme.test": "userinfo",
		"api.acme.test:8443":    "a port",
		"169.254.169.254":       "an address",
		"localhost":             "a local name",
		"metadata.internal":     "a local name",
		"intranet":              "no dot",
		"api.acme.test/v1":      "a path",
	} {
		m := people()
		m.Host = host
		if err := m.Validate(); err == nil {
			t.Errorf("%s (%s) was accepted as a host", host, why)
		}
	}
	m := people()
	m.Host = "acme.api.kandji.io"
	if err := m.Validate(); err != nil {
		t.Fatalf("an ordinary hostname was refused: %v", err)
	}
}

func TestAPathThatCouldReachAnotherHostIsRefused(t *testing.T) {
	for _, path := range []string{
		"api/v1/devices", "//evil.test/v1", "https://evil.test/v1",
		"/api/../../v1", "/api\r\nX-Evil: 1",
	} {
		m := people()
		m.Endpoints[0].Path = path
		if err := m.Validate(); err == nil {
			t.Errorf("%q was accepted as a path", path)
		}
	}
}

func TestOnlyGetIsEverSent(t *testing.T) {
	var methods []string
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		w.Write(page([]map[string]any{{"device_id": 1}},
			map[string]any{"meta": map[string]any{"next": ""}}))
	})
	m := people()
	m.Endpoints[0].Page = Pagination{Kind: Cursor, From: "meta.next",
		Param: "cursor"}
	if _, err := Run(context.Background(), m, "devices", dialTo(t, s),
		secrets(), State{}, noSleep); err != nil {
		t.Fatal(err)
	}
	for _, got := range methods {
		if got != http.MethodGet {
			t.Errorf("a %s was sent", got)
		}
	}
}

func TestARecordLimitStopsAPullAndSaysSo(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		var recs []map[string]any
		for n := range 50 {
			recs = append(recs, map[string]any{"device_id": n})
		}
		w.Write(page(recs, map[string]any{
			"meta": map[string]any{"next": "more"}}))
	})
	m := people()
	m.Endpoints[0].Page = Pagination{Kind: Cursor, From: "meta.next",
		Param: "cursor"}
	m.Records = 10
	out, err := Run(context.Background(), m, "devices", dialTo(t, s),
		secrets(), State{}, noSleep)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Records) != 10 {
		t.Fatalf("%d records, want the limit of 10", len(out.Records))
	}
	if out.Complete() {
		t.Error("a truncated run reports itself as complete")
	}
}

func TestReachSaysWhatAReviewerNeedsToKnow(t *testing.T) {
	got := people().Reach()
	for _, want := range []string{"acme.api.kandji.io", "1 endpoint",
		"nothing else"} {
		if !strings.Contains(got, want) {
			t.Errorf("Reach does not mention %q: %q", want, got)
		}
	}
}

func TestPathsAreDottedAndNothingMore(t *testing.T) {
	var doc any
	if err := json.Unmarshal([]byte(`{
		"id": 1043, "big": 1e20, "ok": true, "nil": null,
		"user": {"email": "a@b.test"},
		"tags": ["one", "two"],
		"nested": {"deep": {"leaf": "found"}}
	}`), &doc); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		"id":               "1043",
		"ok":               "true",
		"user.email":       "a@b.test",
		"tags.0":           "one",
		"tags.1":           "two",
		"nested.deep.leaf": "found",
		"nil":              "",
		"missing":          "",
		"user":             "",
		"tags.9":           "",
		"":                 "",
	} {
		if got := At(doc, path); got != want {
			t.Errorf("At(%q) = %q, want %q", path, got, want)
		}
	}
	// A present null is reported as absent: a field a tool sets to null is
	// one it has no value for, and "null" in a name column is a bug that
	// looks like data.
	if Has(doc, "nil") {
		t.Error("an explicit null reads as present")
	}
	if !Has(doc, "id") {
		t.Error("a present field reads as absent")
	}
	// A number too large for an exact integer keeps its own formatting
	// rather than becoming an identifier nobody can join on.
	if got := At(doc, "big"); strings.Contains(got, "e+") {
		t.Errorf("a large number rendered as %q", got)
	}
}

func TestPathsListsWhatATooolReturns(t *testing.T) {
	var doc any
	if err := json.Unmarshal([]byte(
		`{"results":[{"id":1,"user":{"email":"a@b.test"}}]}`),
		&doc); err != nil {
		t.Fatal(err)
	}
	got := Paths(doc, 20)
	want := map[string]bool{"results.0.id": true,
		"results.0.user.email": true}
	for _, p := range got {
		delete(want, p)
	}
	if len(want) != 0 {
		t.Errorf("Paths returned %v, missing %v", got, want)
	}
}

func TestTwoEndpointsWithOneNameIsRefused(t *testing.T) {
	m := people()
	m.Endpoints = append(m.Endpoints, m.Endpoints[0])
	if err := m.Validate(); err == nil {
		t.Fatal("a manifest with two endpoints called devices loaded")
	}
}

func TestAnIssuerThatWouldBreakAJoinIsRefused(t *testing.T) {
	for _, name := range []string{"Kandji", "kandji mdm", "kandji:mdm",
		"acme/kandji", ""} {
		m := people()
		m.Name = name
		if err := m.Validate(); err == nil {
			t.Errorf("%q was accepted as an issuer", name)
		}
	}
}

func TestARunAgainstAnUnknownEndpointSaysSo(t *testing.T) {
	_, err := Run(context.Background(), people(), "users", nil, secrets(),
		State{}, noSleep)
	if err == nil || !strings.Contains(err.Error(), "no endpoint") {
		t.Fatalf("got %v", err)
	}
}

func TestAHeaderNameWithALineBreakIsRefused(t *testing.T) {
	m := people()
	m.Auth = Auth{Kind: HeaderKey, Secret: "kandji-token",
		Header: "X-Api-Key\r\nX-Evil"}
	if err := m.Validate(); err == nil {
		t.Fatal("a header name containing a line break loaded")
	}
}

func TestBasicAuthSendsTheNamedUser(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "quilzo" || pass != "s3cret" {
			t.Errorf("basic auth was %q/%q (%v)", user, pass, ok)
		}
		w.Write(page(nil, nil))
	})
	m := people()
	m.Auth = Auth{Kind: Basic, Secret: "kandji-token", User: "quilzo"}
	if _, err := Run(context.Background(), m, "devices", dialTo(t, s),
		secrets(), State{}, noSleep); err != nil {
		t.Fatal(err)
	}
}
