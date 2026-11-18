// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/jsonschema"
	"github.com/quilzo/quilzo/internal/mcpclient"
)

// aggregatorRequest is one request as the aggregator received it.
type aggregatorRequest struct {
	Method, URL string
	Header      http.Header
	Body        map[string]any
}

// aggregatorFixture answers as an aggregator's documentation says a post
// is answered: busy the first time, as one that counts its callers is,
// then the post it made. What it was sent is kept for the test to read.
type aggregatorFixture struct {
	mu   sync.Mutex
	got  []aggregatorRequest
	busy int
}

func (f *aggregatorFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.got = append(f.got, aggregatorRequest{Method: r.Method, URL: "https://" + r.Host + r.URL.RequestURI(),
		Header: r.Header.Clone(), Body: body})
	w.Header().Set("Content-Type", "application/json")
	if len(f.got) <= f.busy {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"status":"error","message":"too many requests"}`))
		return
	}
	w.Write([]byte(`{"status":"success","id":"pst_8f2c","posted":["instagram","tiktok"]}`))
}

// restViaHandler is a REST transport that hands each request to h, the
// way an httptest server receives it.
func restViaHandler(h http.Handler) func(context.Context, string, string, []byte, map[string]string) (*fetch.Result, error) {
	return func(_ context.Context, method, url string, body []byte, headers map[string]string) (*fetch.Result, error) {
		r := httptest.NewRequest(method, url, bytes.NewReader(body))
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return &fetch.Result{Status: rec.Code, Body: rec.Body.Bytes(), ContentType: rec.Header().Get("Content-Type"),
			Header: rec.Header()}, nil
	}
}

// The client's first platform, in week one, is reached through an
// aggregator that holds the platforms' approved apps while their own app
// reviews are pending. There was no ready way to declare one: the
// templates were a calendar and issues, each with a person's connected
// account at a host this program names. The aggregator is declared from a
// template as one REST integration, switched off, reaching the host the
// administrator names with the key kept in the vault; it posts a JSON body
// of text and media URLs on this site's /media/ID, which the aggregator
// fetches, and a media URL anywhere else is refused before it is sent.
func TestASocialAggregatorIsDeclaredOffAndPostsMediaFromTheSite(t *testing.T) {
	root, _ := identityStore(t)
	setConfigs(t, root, map[string]string{"site.base_url": "https://shop.example"})
	fx := &aggregatorFixture{busy: 1}
	restTransport = restViaHandler(fx)
	t.Cleanup(func() { restTransport = nil })

	// Nothing is assumed about which aggregator: without its host, nothing
	// is declared.
	if err := integrationsTemplate(root, []string{"social-aggregator"}); err == nil || !strings.Contains(err.Error(), "--endpoint") {
		t.Fatalf("declared an aggregator nobody named: %v", err)
	}
	if set, _ := loadIntegrations(root); len(set.Declared) != 0 {
		t.Fatalf("declared %+v", set.Declared)
	}
	if err := integrationsTemplate(root, []string{"social-aggregator", "--endpoint", "posts.aggregator.example",
		"--path", "/api/post", "--fields", "text=post"}); err != nil {
		t.Fatal(err)
	}
	set, err := loadIntegrations(root)
	if err != nil || len(set.Declared) != 1 {
		t.Fatalf("%v %+v", err, set)
	}
	in := set.Declared[0]
	if in.Enabled || in.Name != "social-aggregator" || in.Endpoint != "posts.aggregator.example" || in.Connection != "" ||
		in.Secret != "social-aggregator-key" || !in.Writes || !reflect.DeepEqual(in.Uses, []string{"publishPost"}) {
		t.Fatalf("declared %+v", in)
	}

	media := "https://shop.example/media/" + strings.Repeat("ab", 32)
	post := map[string]any{"post": "The spring range is in", "mediaUrls": []any{media}, "platforms": []any{"instagram", "tiktok"}}
	keyed := mcpclient.WithIdempotencyKey(context.Background(), "qz-run-7-step-2")
	// The key is in the vault already, so a call refused here is refused
	// for being off and not for wanting a key: with the key missing, this
	// passed whether or not being off stopped anything.
	t.Setenv("QUILZO_SECRET_SOCIAL_AGGREGATOR_KEY", "agg-k3y")
	if _, err := newMCPClient(root).Call(keyed, in, "publishPost", map[string]any{"body": post}); err == nil {
		t.Fatal("an aggregator nobody switched on was called")
	}
	if len(fx.got) != 0 {
		t.Fatalf("%d request(s) reached an aggregator that is off", len(fx.got))
	}

	// The administrator turns it on, and pins what it calls.
	set.Declared[0].Enabled = true
	if err := saveJSON(integrationsPath(root), set); err != nil {
		t.Fatal(err)
	}
	if err := integrationsPin(root, []string{"social-aggregator"}); err != nil {
		t.Fatal(err)
	}
	if in, err = oneIntegration(root, "social-aggregator"); err != nil || in.Pins["publishPost"] == "" {
		t.Fatalf("%v %+v", err, in)
	}
	answer, err := newMCPClient(root).Call(keyed, in, "publishPost", map[string]any{"body": post})
	if err != nil || !strings.Contains(answer, "pst_8f2c") {
		t.Fatalf("%q %v", answer, err)
	}
	// Busy once, then posted: tried again, as the same write.
	if len(fx.got) != 2 {
		t.Fatalf("the aggregator was asked %d time(s)", len(fx.got))
	}
	for _, r := range fx.got {
		if r.Method != "POST" || r.URL != "https://posts.aggregator.example/api/post" {
			t.Errorf("sent %s %s", r.Method, r.URL)
		}
		if r.Header.Get("Authorization") != "Bearer agg-k3y" || r.Header.Get("Content-Type") != "application/json" ||
			r.Header.Get("Idempotency-Key") != "qz-run-7-step-2" {
			t.Errorf("sent with %v", r.Header)
		}
		if !reflect.DeepEqual(r.Body, post) {
			t.Errorf("sent %v, not %v", r.Body, post)
		}
	}

	// A picture from anywhere but this site's /media/, or a field the
	// declaration does not name, never leaves.
	for _, bad := range []map[string]any{
		{"post": "Look", "mediaUrls": []any{"https://elsewhere.example/media/" + strings.Repeat("ab", 32)}},
		{"post": "Look", "mediaUrls": []any{"https://shop.example/admin/export"}},
		{"post": "Look", "mediaUrls": []any{media + "?then=https://elsewhere.example/x.jpg"}},
		{"text": "Look"},
		{"post": "Look", "visibility": "private"},
	} {
		if _, err := newMCPClient(root).Call(keyed, in, "publishPost", map[string]any{"body": bad}); err == nil {
			t.Errorf("%v was sent", bad)
		}
	}
	if len(fx.got) != 2 {
		t.Fatalf("%d refused post(s) reached the aggregator", len(fx.got)-2)
	}
}

// No aggregator is hard-coded: which one is the client's decision, on
// cost. The template names no host and no path, two declared from it
// reach the two the administrator named, each with that aggregator's own
// names for the text, the media and the platforms and its own way of
// sending the key, and a template whose host is fixed refuses being
// pointed somewhere else rather than ignoring the flag.
func TestTheAggregatorIsTheClientsChoice(t *testing.T) {
	root, _ := identityStore(t)
	setConfigs(t, root, map[string]string{"site.base_url": "https://shop.example"})
	tmpl, ok := integrationTemplates["social-aggregator"]
	if !ok {
		t.Fatalf("no aggregator template; there are %v", integrationTemplateNames())
	}
	if tmpl.Integration.Endpoint != "" || tmpl.Integration.Path != "" || tmpl.Provider != "" {
		t.Errorf("the template names a service: %+v", tmpl.Integration)
	}
	for _, o := range tmpl.Integration.Operations {
		if o.Path != "" {
			t.Errorf("the template names a path: %s %s", o.Name, o.Path)
		}
	}
	if err := integrationsTemplate(root, []string{"social-aggregator", "--endpoint", "posts.one.example"}); err == nil ||
		!strings.Contains(err.Error(), "--path") {
		t.Errorf("declared without the path a post goes to: %v", err)
	}
	if err := integrationsTemplate(root, []string{"social-aggregator", "--as", "one", "--endpoint", "posts.one.example",
		"--path", "/api/post"}); err != nil {
		t.Fatal(err)
	}
	if err := integrationsTemplate(root, []string{"social-aggregator", "--as", "two", "--endpoint", "api.two.example",
		"--path", "/v1/posts", "--fields", "text=content,media=media_urls,platforms=networks",
		"--secret", "two-api-key", "--auth", "header:X-Api-Key"}); err != nil {
		t.Fatal(err)
	}
	fields := func(name string) []string {
		t.Helper()
		in, err := oneIntegration(root, name)
		if err != nil || len(in.Operations) != 1 {
			t.Fatalf("%v %+v", err, in)
		}
		var s struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal(in.Operations[0].Body, &s); err != nil {
			t.Fatal(err)
		}
		var out []string
		for k := range s.Properties {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	one, _ := oneIntegration(root, "one")
	two, _ := oneIntegration(root, "two")
	if one.URL() != "https://posts.one.example/" || one.Operations[0].Path != "/api/post" || one.Auth != "" || one.Secret != "one-key" {
		t.Errorf("one: %+v", one)
	}
	if two.Endpoint != "api.two.example" || two.Operations[0].Path != "/v1/posts" || two.Auth != "header:X-Api-Key" ||
		two.Secret != "two-api-key" {
		t.Errorf("two: %+v", two)
	}
	if got := fields("one"); !reflect.DeepEqual(got, []string{"mediaUrls", "platforms", "text"}) {
		t.Errorf("one takes %v", got)
	}
	if got := fields("two"); !reflect.DeepEqual(got, []string{"content", "media_urls", "networks"}) {
		t.Errorf("two takes %v", got)
	}
	for _, bad := range [][]string{
		{"social-aggregator", "--as", "three", "--endpoint", "https://api.three.example/v1", "--path", "/posts"},
		{"social-aggregator", "--as", "three", "--endpoint", "api.three.example", "--path", "/posts", "--fields", "text=a,media=a"},
		{"social-aggregator", "--as", "three", "--endpoint", "api.three.example", "--path", "/posts", "--fields", "colour=red"},
		{"social-aggregator", "--as", "three", "--endpoint", "api.three.example", "--path", "/posts", "--connection", "google"},
		{"google-calendar", "--endpoint", "calendar.elsewhere.example"},
	} {
		if err := integrationsTemplate(root, bad); err == nil {
			t.Errorf("%v was declared", bad)
		}
	}
	if set, _ := loadIntegrations(root); len(set.Declared) != 2 {
		t.Errorf("declared %d", len(set.Declared))
	}
}

// The media a post may name are this site's own addresses as the site
// writes them: site.base_url, then /media/ID. The prefix was put back
// together from the parsed address, which decodes its path, so a site at
// https://shop.example/caf%C3%A9 was described to the agent as having its
// media at /café/media/, and every address the site gives its own
// pictures was refused.
func TestAnAggregatorTakesTheMediaAddressesTheSiteWrites(t *testing.T) {
	root, _ := identityStore(t)
	setConfigs(t, root, map[string]string{"site.base_url": "https://shop.example/caf%C3%A9"})
	if err := integrationsTemplate(root, []string{"social-aggregator", "--endpoint", "posts.aggregator.example",
		"--path", "/api/post"}); err != nil {
		t.Fatal(err)
	}
	in, err := oneIntegration(root, "social-aggregator")
	if err != nil || len(in.Operations) != 1 {
		t.Fatalf("%v %+v", err, in)
	}
	id := strings.Repeat("ab", 32)
	own := map[string]any{"text": "The spring range is in", "mediaUrls": []any{"https://shop.example/caf%C3%A9/media/" + id}}
	if err := jsonschema.Check(in.Operations[0].Body, own); err != nil {
		t.Errorf("the site's own picture was refused: %v", err)
	}
	// Outside the site's own path is not the site's.
	other := map[string]any{"text": "Look", "mediaUrls": []any{"https://shop.example/media/" + id}}
	if err := jsonschema.Check(in.Operations[0].Body, other); err == nil {
		t.Error("a picture outside the site's path was taken")
	}
}
