package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lithoform/lithoform/internal/audit"
	"github.com/lithoform/lithoform/internal/auth"
)

func logServer(t *testing.T, events []audit.Event, sep bool) (*Server, string) {
	t.Helper()
	s, _ := setup(t)
	tok, _, err := s.Tokens.Issue("a", "dana", auth.RoleAdmin, "/", time.Hour,
		auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	s.Policy.Grant(auth.Binding{Principal: "dana", Role: auth.RoleAdmin,
		Resource: "/"})
	s.LoadAudit = func() ([]audit.Event, error) { return events, nil }
	s.LogSeparated = sep
	return s, tok
}

func getLogs(t *testing.T, s *Server, tok, query string) (string, int) {
	t.Helper()
	r := httptest.NewRequest("GET", "http://h/logs"+query, nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w.Body.String(), w.Code
}

// realLog builds a log the way the writer does, so the chain is genuine.
func realLog(t *testing.T, n int) []audit.Event {
	t.Helper()
	dir := t.TempDir()
	l, err := audit.New(audit.Options{Path: dir + "/a.jsonl", Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		out := audit.Success
		if i%3 == 0 {
			out = audit.Denied
		}
		if _, err := l.Append(audit.Record{
			Action: "publish", Resource: "/", Outcome: out,
			Principal: "dana", Kind: audit.KindHuman, Verified: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := audit.Read(dir + "/a.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	return events
}

// A list of events with no statement about whether the chain holds invites the
// reader to trust it, which is the opposite of what the chain is for.
func TestTheLogSaysWhetherItVerifies(t *testing.T) {
	events := realLog(t, 5)
	s, tok := logServer(t, events, true)
	body, code := getLogs(t, s, tok, "")
	if code != http.StatusOK {
		t.Fatalf("got %d", code)
	}
	if !strings.Contains(body, "Chain intact") {
		t.Error("an intact log does not say so")
	}

	// Now alter one, exactly as somebody with filesystem access would.
	events[2].Action = "rollback"
	s2, tok2 := logServer(t, events, true)
	body, _ = getLogs(t, s2, tok2, "")
	if !strings.Contains(body, "has been altered") {
		t.Fatal("a tampered log was shown without saying so")
	}
	if strings.Contains(body, "Chain intact") {
		t.Error("it claimed to be intact as well")
	}
}

// The page must not offer, or imply, an edit path. There is none: this process
// cannot write the log where the writer has been separated out.
func TestTheLogPageOffersNoWayToChangeIt(t *testing.T) {
	s, tok := logServer(t, realLog(t, 3), true)
	body, _ := getLogs(t, s, tok, "")

	// Scoped to the page's own region rather than the whole document. The
	// shared header carries a preference toggle that posts, and a blanket
	// "no POST form anywhere" check would either fail on that or have to be
	// deleted — and deleting it is how the real property stops being tested.
	// What matters is that nothing in the log's own content acts on the log.
	main := body
	if i := strings.Index(body, "<main"); i >= 0 {
		main = body[i:]
	}
	if j := strings.Index(main, "</main>"); j >= 0 {
		main = main[:j]
	}
	for _, bad := range []string{"<form method=\"post\"", "Delete", "Remove",
		"Edit"} {
		if strings.Contains(main, bad) {
			t.Errorf("the log page contains %q", bad)
		}
	}
	// And no form anywhere on the page may target a log route.
	for _, route := range []string{"/logs/delete", "/logs/edit", "/logs/redact"} {
		if strings.Contains(body, route) {
			t.Errorf("the page references %s", route)
		}
	}
	if !strings.Contains(body, "Nothing here can edit or delete") {
		t.Error("the page does not say that nothing here can change an entry")
	}
}

// It must say what the record is worth, rather than implying it.
func TestThePageSaysWhetherTheWriterIsSeparated(t *testing.T) {
	s, tok := logServer(t, realLog(t, 2), true)
	if body, _ := getLogs(t, s, tok, ""); !strings.Contains(body, "separate account") {
		t.Error("a separated log does not say so")
	}
	s2, tok2 := logServer(t, realLog(t, 2), false)
	if body, _ := getLogs(t, s2, tok2, ""); !strings.Contains(body, "could rewrite it") {
		t.Error("an unseparated log does not admit it")
	}
}

// Names are matched forwards. Somebody the store has never heard of stays a
// pseudonym, which is the right outcome rather than a limitation.
func TestPseudonymsResolveOnlyForPeopleTheStoreKnows(t *testing.T) {
	events := realLog(t, 2)
	s, tok := logServer(t, events, true)
	s.ResolvePrincipal = func(p string) string {
		if p == events[0].Principal {
			return "dana"
		}
		return ""
	}
	body, _ := getLogs(t, s, tok, "")
	if !strings.Contains(body, "dana") {
		t.Error("a known principal was not resolved")
	}

	// An entry from somebody unknown keeps its pseudonym rather than being
	// hidden or guessed at.
	s.ResolvePrincipal = func(string) string { return "" }
	body, _ = getLogs(t, s, tok, "")
	if !strings.Contains(body, events[0].Principal) {
		t.Error("an unresolvable entry was not shown at all")
	}
}

// No access and an empty log look identical and mean opposite things.
func TestNoAccessIsNotAnEmptyLog(t *testing.T) {
	s, tok := logServer(t, nil, true)
	s.LoadAudit = nil
	body, _ := getLogs(t, s, tok, "")
	if !strings.Contains(body, "without access") {
		t.Error("a server with no access to the log showed an empty list " +
			"instead of saying it cannot see one")
	}
}

// Reading the log is administrative: it holds who did what across everybody,
// and is worth reading to plan an attack as well as to investigate one.
func TestTheLogNeedsAdmin(t *testing.T) {
	s, _ := logServer(t, realLog(t, 2), true)
	reader, _, err := s.Tokens.Issue("r", "kit", auth.RoleReader, "/",
		time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	s.Policy.Grant(auth.Binding{Principal: "kit", Role: auth.RoleReader,
		Resource: "/"})
	_, code := getLogs(t, s, reader, "")
	if code == http.StatusOK {
		t.Error("a reader could read the audit log")
	}
}

func TestFilteringNarrowsWithoutHidingTheTotal(t *testing.T) {
	s, tok := logServer(t, realLog(t, 9), true)
	all, _ := getLogs(t, s, tok, "")
	denied, _ := getLogs(t, s, tok, "?outcome=denied")
	if !strings.Contains(all, "9 entries") {
		t.Error("the unfiltered view does not report the total")
	}
	if !strings.Contains(denied, "of 9 entries") {
		t.Error("a filtered view does not say what it filtered from")
	}
}

// -- where the navigation sits ------------------------------------------------

// Both positions render the same markup in the same order. A layout that
// reorders the DOM to move a menu is a layout that is correct for one of its
// two settings: the reading order a screen reader follows and the order the
// keyboard moves through would change with a display preference.
func TestBothNavPositionsRenderTheSameDocumentOrder(t *testing.T) {
	s, tok := logServer(t, realLog(t, 2), true)

	order := func(body string) []int {
		var out []int
		for _, marker := range []string{"<header", "<nav", "<main"} {
			out = append(out, strings.Index(body, marker))
		}
		return out
	}

	s.NavPosition = "top"
	top, _ := getLogs(t, s, tok, "")
	s.NavPosition = "left"
	left, _ := getLogs(t, s, tok, "")

	if !strings.Contains(top, "nav-top") {
		t.Error("the top setting did not reach the page")
	}
	if !strings.Contains(left, "nav-left") {
		t.Error("the left setting did not reach the page")
	}
	a, b := order(top), order(left)
	for i := range a {
		if (a[i] < 0) != (b[i] < 0) {
			t.Fatalf("the two positions render different elements: %v vs %v", a, b)
		}
	}
	// Landmarks in the same relative order in both.
	for i := 1; i < len(a); i++ {
		if (a[i] > a[i-1]) != (b[i] > b[i-1]) {
			t.Error("the document order differs between nav positions, so a " +
				"screen reader would follow a different path depending on a " +
				"display preference")
		}
	}
}

// A person's choice beats the store's default, because where a menu sits is a
// preference about a screen rather than a property of the content.
func TestAPersonalChoiceOverridesTheConfiguredDefault(t *testing.T) {
	s, tok := logServer(t, realLog(t, 1), true)
	s.NavPosition = "top"

	r := httptest.NewRequest("GET", "http://h/logs", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	r.AddCookie(&http.Cookie{Name: "scrivet_nav", Value: "left"})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "nav-left") {
		t.Error("a person's cookie did not override the configured default")
	}
}

// The toggle is a state change on this origin, so it is POST-only,
// authenticated, and cannot be used to send somebody elsewhere.
func TestTheNavToggleIsGuarded(t *testing.T) {
	s, tok := logServer(t, realLog(t, 1), true)

	// GET does nothing.
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "http://h/nav", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /nav gave %d", w.Code)
	}

	// Unauthenticated POST does not set a cookie.
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "http://h/nav",
		strings.NewReader("to=left")))
	for _, c := range w.Result().Cookies() {
		if c.Name == "scrivet_nav" {
			t.Error("an unauthenticated request set the preference")
		}
	}

	// A junk value is refused rather than stored.
	r := httptest.NewRequest("POST", "http://h/nav",
		strings.NewReader("to=javascript:alert(1)"))
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code == http.StatusSeeOther {
		t.Error("an arbitrary value was accepted")
	}

	// And the Referer cannot send somebody off-site: an open redirect through
	// a preference toggle would be an embarrassing way to acquire one.
	r = httptest.NewRequest("POST", "http://h/nav", strings.NewReader("to=left"))
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Referer", "https://evil.example/somewhere")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if loc := w.Header().Get("Location"); strings.Contains(loc, "evil.example") {
		t.Errorf("the toggle redirected to %q", loc)
	}
}
