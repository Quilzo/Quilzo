// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/handoff"
	"github.com/quilzo/quilzo/internal/throttle"
)

var handingBot = assistant.Assistant{Name: "help", Title: "Ask the shop",
	Public: true, Exclude: []string{"drafts"}, Handoff: true, HandoffDays: 14}

type heard struct{ action, name, id, source string }

func handoffSite(t *testing.T, a ...assistant.Assistant) (*Site, *handoff.Store, *[]heard) {
	t.Helper()
	if len(a) == 0 {
		a = []assistant.Assistant{handingBot}
	}
	st, _ := askSite(t, a...)
	store := &handoff.Store{Dir: t.TempDir()}
	events := &[]heard{}
	st.Assistants.Handoff = store
	st.Assistants.HandoffEvent = func(action, name, id, source string) {
		*events = append(*events, heard{action, name, id, source})
	}
	return st, store, events
}

func send(st *Site, method, path string, form url.Values) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.RemoteAddr = "198.51.100.7:4321"
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, req)
	return w
}

// start asks a question, then asks for a person, and returns the
// conversation's address.
func start(t *testing.T, st *Site, message string) string {
	t.Helper()
	w := send(st, http.MethodPost, "/ask/help/handoff",
		url.Values{"q": {"can I return an opened bottle?"}, "message": {message}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("asking for a person answered %d: %s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/ask/help/c/") || len(loc) != len("/ask/help/c/")+32 {
		t.Fatalf("the visitor was sent to %q", loc)
	}
	return loc
}

func TestTheOfferToTalkToAPersonIsMadeOnlyWhereItCanBeKept(t *testing.T) {
	st, _, _ := handoffSite(t)
	body := askPost(st, "help", "can I return an opened bottle?").Body.String()
	for _, want := range []string{"Talk to a person instead",
		`action="/ask/help/handoff"`, "it is kept: for 14 days",
		"do not include passwords"} {
		if !strings.Contains(body, want) {
			t.Errorf("the answer page does not offer a person: missing %q", want)
		}
	}
	// Not on the greeting, before anything was asked.
	if strings.Contains(send(st, http.MethodGet, "/ask/help", nil).Body.String(),
		"Talk to a person") {
		t.Error("the offer is made before anything was asked")
	}
	// An assistant that did not declare it does not offer it, and its route
	// is not there.
	quiet := handingBot
	quiet.Handoff = false
	st2, _, _ := handoffSite(t, quiet)
	if strings.Contains(askPost(st2, "help", "returns?").Body.String(), "Talk to a person") {
		t.Error("an assistant that does not hand over offered to")
	}
	if w := send(st2, http.MethodPost, "/ask/help/handoff",
		url.Values{"message": {"hello"}}); w.Code != http.StatusNotFound {
		t.Errorf("handing over from an assistant that does not answered %d", w.Code)
	}
	// Nor does one whose site was started without a place to keep it.
	st3, _ := askSite(t, handingBot)
	if strings.Contains(askPost(st3, "help", "returns?").Body.String(), "Talk to a person") {
		t.Error("the offer is made by a site with nowhere to keep the conversation")
	}
}

func TestAVisitorStartsAConversationAndOnlyTheirAddressReachesIt(t *testing.T) {
	st, store, events := handoffSite(t)
	loc := start(t, st, "I'd like to return order 1182")

	w := send(st, http.MethodGet, loc, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("the conversation answered %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "I&#39;d like to return order 1182") ||
		!strings.Contains(body, "Keep this page") {
		t.Errorf("the conversation page is missing what was said:\n%s", body)
	}
	for k, v := range map[string]string{"Referrer-Policy": "no-referrer",
		"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"} {
		if got := w.Header().Get(k); got != v {
			t.Errorf("%s is %q; the address is the key and must not leak", k, got)
		}
	}
	all, _ := store.List()
	if len(all) != 1 || all[0].Question != "can I return an opened bottle?" {
		t.Fatalf("the store holds %+v", all)
	}
	// Told that it happened, not what was said.
	if len(*events) != 1 || (*events)[0].action != "handoff.open" ||
		(*events)[0].id != all[0].ID || (*events)[0].source != "198.51.100.7" {
		t.Errorf("the event is %+v", *events)
	}

	secret := strings.TrimPrefix(loc, "/ask/help/c/")
	other, _, _ := handoff.NewSecret()
	for _, bad := range []string{
		"/ask/help/c/" + other,                  // a well-formed wrong secret
		"/ask/help/c/" + all[0].ID,              // the stored identifier
		"/ask/help/c/" + secret[:31],            // one short
		"/ask/help/c/" + secret + "x",           // one long
		"/ask/help/c/" + secret[:30] + "%2F%2E", // not the alphabet
		"/ask/other/c/" + secret,                // another assistant
		"/ask/help/c/" + secret + "/extra",      // anything after it
	} {
		if w := send(st, http.MethodGet, bad, nil); w.Code != http.StatusNotFound {
			t.Errorf("%s answered %d", bad, w.Code)
		}
	}
}

func TestWhatEitherSideSaysArrivesAsText(t *testing.T) {
	st, store, _ := handoffSite(t)
	loc := start(t, st, "hello")
	id := handoff.IDFor(strings.TrimPrefix(loc, "/ask/help/c/"))

	w := send(st, http.MethodPost, loc, url.Values{"message": {`<script>alert(1)</script>`}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("a visitor's message answered %d", w.Code)
	}
	if _, err := store.Say("help", id, handoff.Person, "dana",
		`<img src=x onerror=alert(2)> which order?`, time.Now()); err != nil {
		t.Fatal(err)
	}
	body := send(st, http.MethodGet, loc, nil).Body.String()
	for _, bad := range []string{"<script>alert(1)", "<img src=x"} {
		if strings.Contains(body, bad) {
			t.Errorf("the page carries %q as markup", bad)
		}
	}
	// The person who answered is not named to the visitor.
	if strings.Contains(body, "dana") || !strings.Contains(body, "Ask the shop team") {
		t.Error("the answer is not attributed to the business alone")
	}

	var got struct {
		Messages []map[string]any `json:"messages"`
		Closed   bool             `json:"closed"`
	}
	w = send(st, http.MethodGet, loc+"?format=json&after=1", nil)
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Messages) != 2 || got.Messages[0]["text"] != `<script>alert(1)</script>` ||
		got.Messages[1]["from"] != "person" {
		t.Fatalf("what is new after the first message is %+v", got.Messages)
	}
	for _, m := range got.Messages {
		if _, named := m["by"]; named {
			t.Error("the JSON names who answered")
		}
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("the JSON may be cached")
	}
}

func TestAVisitorCanEndTheConversation(t *testing.T) {
	st, _, events := handoffSite(t)
	loc := start(t, st, "hello")
	if w := send(st, http.MethodPost, loc, url.Values{"end": {"1"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("ending answered %d", w.Code)
	}
	body := send(st, http.MethodGet, loc, nil).Body.String()
	if !strings.Contains(body, "This conversation has ended") || strings.Contains(body, `name="message"`) {
		t.Error("the ended conversation still takes messages on its page")
	}
	w := send(st, http.MethodPost, loc, url.Values{"message": {"one more thing"}})
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "ended") {
		t.Errorf("a message to an ended conversation answered %d", w.Code)
	}
	if (*events)[len(*events)-1].action != "handoff.close" {
		t.Errorf("the events are %+v", *events)
	}
}

func TestTalkingToAPersonSpendsTheSameAllowanceAsAsking(t *testing.T) {
	st, store, _ := handoffSite(t)
	st.Assistants.Limit = throttle.New(throttle.Policy{On: true, After: 2,
		Ceiling: 3, Base: time.Minute, Max: time.Hour, Window: time.Hour})
	codes := []int{}
	for i := 0; i < 5; i++ {
		w := send(st, http.MethodPost, "/ask/help/handoff", url.Values{"message": {"hi"}})
		codes = append(codes, w.Code)
	}
	if codes[len(codes)-1] != http.StatusTooManyRequests {
		t.Errorf("five conversations in a row answered %v", codes)
	}
	all, _ := store.List()
	if len(all) >= 5 {
		t.Errorf("%d conversations were opened past the limit", len(all))
	}
}

func TestTheOnlyWayInIsTheForm(t *testing.T) {
	st, _, _ := handoffSite(t)
	if w := send(st, http.MethodGet, "/ask/help/handoff", nil); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("a GET opened a conversation: %d", w.Code)
	}
	if w := send(st, http.MethodPost, "/ask/help/handoff",
		url.Values{"message": {"   "}}); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("an empty message opened a conversation: %d", w.Code)
	}
}

func TestTheLiveScriptOnlyEverWritesText(t *testing.T) {
	st, _, _ := handoffSite(t)
	w := send(st, http.MethodGet, "/ask-live.js", nil)
	js := w.Body.String()
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/javascript") {
		t.Fatalf("the script answered %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML",
		"document.write", "eval(", "Function("} {
		if strings.Contains(js, bad) {
			t.Errorf("the live script uses %s", bad)
		}
	}
	if !strings.Contains(js, "textContent") || !strings.Contains(js, `credentials: "omit"`) {
		t.Error("the live script does not write text, or sends credentials")
	}
}

// The page's one script runs under a site policy that runs none, by a nonce
// that is this response's alone, and nothing else is let in.
func TestTheLiveScriptRunsOnlyOnItsOwnPageAndOnlyItself(t *testing.T) {
	st, _, _ := handoffSite(t)
	strict := "default-src 'none'; script-src 'none'; style-src 'self'; " +
		"connect-src 'none'; frame-ancestors 'none'"
	st.CSP = func() (string, bool) { return "Content-Security-Policy", true }
	st.CSPValue = func() string { return strict }
	loc := start(t, st, "hello")

	w := send(st, http.MethodGet, loc, nil)
	csp := w.Header().Get("Content-Security-Policy")
	body := w.Body.String()
	i := strings.Index(csp, "'nonce-")
	if i < 0 {
		t.Fatalf("the conversation page's policy allows no script: %s", csp)
	}
	nonce := csp[i+len("'nonce-") : i+len("'nonce-")+22]
	if !strings.Contains(body, `<script src="/ask-live.js" nonce="`+nonce+`"`) {
		t.Error("the script tag does not carry the response's nonce")
	}
	for _, bad := range []string{"script-src 'none'", "'unsafe-inline' ", "script-src 'self'",
		"connect-src 'none'"} {
		if strings.Contains(csp, bad) {
			t.Errorf("the conversation page's policy has %q: %s", bad, csp)
		}
	}
	if !strings.Contains(csp, "connect-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("the policy lost what it should keep: %s", csp)
	}
	// Another response has another nonce.
	again := send(st, http.MethodGet, loc, nil).Header().Get("Content-Security-Policy")
	if again == csp {
		t.Error("two responses share a nonce")
	}
	// And the site's other pages keep the site's policy.
	if other := send(st, http.MethodGet, "/ask/help", nil).Header().Get("Content-Security-Policy"); !strings.Contains(other, "script-src 'none'") {
		t.Errorf("another page's policy changed: %s", other)
	}
}
