// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
)

func logServer(t *testing.T, events []audit.Event, sep bool) (*Server, string) {
	t.Helper()
	s, _ := setup(t)
	tok, _, err := s.Tokens.IssueSession("a", "dana", auth.RoleAdmin, "/", time.Hour,
		auth.RoleAdmin, auth.MethodPasskey)
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
	reader, _, err := s.Tokens.IssueSession("r", "kit", auth.RoleReader, "/",
		time.Hour, auth.RoleAdmin, auth.MethodPasskey)
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

// -- the navigation -----------------------------------------------------------

// It is rendered once.
//
// This is the property the two-position layout could not have. Supporting a
// top bar and a side column meant emitting the whole navigation twice and
// letting CSS display one of them, so every response carried a duplicate set
// of destinations whose absence from the accessibility tree depended entirely
// on a display rule being right. Get the breakpoint wrong — or load the page
// with the stylesheet missing, which is what a text browser and a stripped
// email client do — and every section is announced twice.
//
// Counted on the landmark rather than on a link, because the duplicate was a
// whole <nav>, and counting links would also catch a legitimate second link to
// the same place elsewhere on the page.
func TestTheNavigationIsRenderedOnce(t *testing.T) {
	s, tok := logServer(t, realLog(t, 2), true)
	body, _ := getLogs(t, s, tok, "")

	if n := strings.Count(body, `aria-label="Sections"`); n != 1 {
		t.Errorf("the navigation landmark appears %d times, want 1. Two "+
			"copies is what the top/side arrangement needed and it is what "+
			"a screen reader reads twice.", n)
	}
	// And the destinations with it. "Publishing" is a label from the table.
	if n := strings.Count(body, `>Publishing<`); n > 1 {
		t.Errorf("a destination label appears %d times; the navigation is "+
			"duplicated", n)
	}
}

// Landmarks in the reading order somebody navigates by: banner, then the
// navigation, then the content.
func TestTheLandmarkOrderIsBannerNavMain(t *testing.T) {
	s, tok := logServer(t, realLog(t, 2), true)
	body, _ := getLogs(t, s, tok, "")

	header := strings.Index(body, "<header")
	nav := strings.Index(body, "<nav")
	main := strings.Index(body, `<main`)
	if header < 0 || nav < 0 || main < 0 {
		t.Fatalf("a landmark is missing: header=%d nav=%d main=%d",
			header, nav, main)
	}
	if !(header < nav && nav < main) {
		t.Errorf("landmarks are in the order header=%d nav=%d main=%d; a "+
			"keyboard user reaches the content after the menu, not before it",
			header, nav, main)
	}
}

// The position toggle is gone, along with the preference it set.
//
// Asserted rather than assumed, because a removed feature that leaves its
// endpoint behind is worse than one that never existed: /nav still set a
// year-long cookie, and a class on <body> that no rule selects on is invisible
// until somebody wonders why their setting stopped working.
func TestTheNavPositionToggleIsGone(t *testing.T) {
	s, tok := logServer(t, realLog(t, 1), true)

	r := httptest.NewRequest("POST", "http://h/nav", strings.NewReader("to=left"))
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("POST /nav gave %d, want 404 — the endpoint should be gone, "+
			"not merely unreferenced", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "quilzo_nav" {
			t.Error("the removed toggle still set its cookie")
		}
	}

	// And an old cookie cannot bring the old layout back.
	r = httptest.NewRequest("GET", "http://h/logs", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	r.AddCookie(&http.Cookie{Name: "quilzo_nav", Value: "top"})
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if body := w.Body.String(); strings.Contains(body, "nav-top") ||
		strings.Contains(body, "nav-left") {
		t.Error("a stale preference cookie still reaches the markup")
	}
}

// A sentence in a pseudonymous log carries the handle of the person it
// names, and the screen names them there as it does in the record's other
// fields: known people by name, anybody else left as a handle.
func TestAPersonInASentenceIsNamedForWhoeverReadsTheScreen(t *testing.T) {
	dir := t.TempDir()
	key, _ := audit.NewKey()
	l, err := audit.New(audit.Options{Path: dir + "/a.jsonl", Key: key, Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(audit.Record{Action: "dual.approved", Resource: "/pat", Outcome: audit.Success,
		Principal: "lee", Kind: audit.KindHuman, Verified: true,
		Detail: map[string]string{"subject": "pat", "what": "make pat admin on /", "why": "asked by kim"},
		People: []string{"kim"}}); err != nil {
		t.Fatal(err)
	}
	events, err := audit.Read(dir + "/a.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(events[0].Detail["what"], "pat") {
		t.Fatalf("the log holds the name: %v", events[0].Detail)
	}
	s, tok := logServer(t, events, true)
	s.ResolvePrincipal = func(p string) string {
		for _, name := range []string{"lee", "pat"} {
			if p == audit.Pseudonym(key, name) {
				return name
			}
		}
		return ""
	}
	body, _ := getLogs(t, s, tok, "")
	if !strings.Contains(body, "make pat admin on /") || !strings.Contains(body, ">/pat<") {
		t.Errorf("the sentence or the resource is not named for the reader:\n%s", body)
	}
	if !strings.Contains(body, "asked by "+audit.Pseudonym(key, "kim")) {
		t.Error("somebody the store does not know was named, or dropped")
	}
}

// Where the writer signs the heads, the page says so and says where the
// keys that check them are: a receipt handed to somebody is checked against
// that file, and the page is where an administrator learns it exists.
func TestTheLogSaysWhoSignsItsHeads(t *testing.T) {
	events := realLog(t, 2)
	s, tok := logServer(t, events, true)
	byWriter := true
	s.LogHeads = func() (bool, string, string) { return byWriter, "/srv/audit/head.pub.json", "" }
	body, code := getLogs(t, s, tok, "")
	if code != http.StatusOK {
		t.Fatalf("got %d", code)
	}
	if !strings.Contains(body, "signed by\n    the writer too") || !strings.Contains(body, "/srv/audit/head.pub.json") {
		t.Errorf("the page does not say the writer signs the heads:\n%s", body)
	}
	byWriter = false
	if body, _ := getLogs(t, s, tok, ""); strings.Contains(body, "signed by\n    the writer too") {
		t.Error("the page says the writer signs heads it does not sign")
	}
}

// Where the writer is to sign the heads and signs none, the page says so,
// and why, rather than that it signs them: a writer that cannot use its key
// goes on writing the log, and the page said the heads were the writer's
// while the receipt on the apps screen failed with nothing here to say why.
func TestTheLogSaysWhenTheWriterSignsNoHeads(t *testing.T) {
	events := realLog(t, 2)
	s, tok := logServer(t, events, true)
	s.LogHeads = func() (bool, string, string) {
		return true, "/srv/audit/head.pub.json", "this writer signs nothing: head.key is not readable"
	}
	body, code := getLogs(t, s, tok, "")
	if code != http.StatusOK {
		t.Fatalf("got %d", code)
	}
	if strings.Contains(body, "signed by\n    the writer too") {
		t.Errorf("the page says the writer signs heads it refuses:\n%s", body)
	}
	if !strings.Contains(body, `<p class="hint warn">Its heads are the writer&rsquo;s to sign, and it signs`) ||
		!strings.Contains(body, "head.key is not readable") {
		t.Errorf("the page does not say the writer signs none, and why:\n%s", body)
	}
}

// outcomesLog is a genuine chain with one entry of each outcome, and one
// whose outcome was edited to something the log never writes.
func outcomesLog(t *testing.T) []audit.Event {
	t.Helper()
	dir := t.TempDir()
	l, err := audit.New(audit.Options{Path: dir + "/a.jsonl", Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct {
		action  string
		outcome audit.Outcome
	}{{"publish", audit.Success}, {"auth.grant", audit.Denied}, {"backup.failed", audit.Failure}, {"render", audit.Success}} {
		if _, err := l.Append(audit.Record{Action: r.action, Resource: "/", Outcome: r.outcome,
			Principal: "dana", Kind: audit.KindHuman, Verified: true}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := audit.Read(dir + "/a.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	events[3].Outcome = "succes"
	return events
}

// tagOf is the class of the outcome tag drawn in the row for an action.
func tagOf(t *testing.T, body, action string) string {
	t.Helper()
	i := strings.Index(body, `<td class="mono">`+action+`</td>`)
	if i < 0 {
		t.Fatalf("no row for %s:\n%s", action, body)
	}
	row := body[i:]
	if j := strings.Index(row, "</tr>"); j >= 0 {
		row = row[:j]
	}
	k := strings.Index(row, `<span class="`)
	if k < 0 {
		t.Fatalf("the row for %s has no outcome tag:\n%s", action, row)
	}
	row = row[k+len(`<span class="`):]
	return row[:strings.Index(row, `"`)]
}

// Denied is kept apart from Failure in the log (audit.Outcome): being refused
// is not the same as breaking, and the reader needs to tell them apart. The
// page drew every outcome that was not "denied" in the success colour, a
// failed backup included, and its filter offered success and denied only, so
// ?outcome=failure showed "any" and pressing Filter dropped it. Only a
// success is drawn as one, and an outcome the log never writes is not.
func TestAFailureLooksLikeAFailureAndCanBeChosen(t *testing.T) {
	s, tok := logServer(t, outcomesLog(t), true)
	body, code := getLogs(t, s, tok, "")
	if code != http.StatusOK {
		t.Fatalf("got %d", code)
	}
	success, denied, failure, edited := tagOf(t, body, "publish"), tagOf(t, body, "auth.grant"),
		tagOf(t, body, "backup.failed"), tagOf(t, body, "render")
	if !strings.Contains(success, "tag-ok") {
		t.Errorf("a success is drawn as %q", success)
	}
	if strings.Contains(failure, "tag-ok") || failure == denied {
		t.Errorf("a failure is drawn as %q, a success as %q and a refusal as %q; a failure "+
			"is told apart from both", failure, success, denied)
	}
	if strings.Contains(edited, "tag-ok") {
		t.Errorf("an outcome the log never writes is drawn as a success (%q)", edited)
	}

	body, _ = getLogs(t, s, tok, "?outcome=failure")
	if !strings.Contains(body, `<option value="failure" selected>failure</option>`) {
		t.Errorf("the filter cannot show that it is choosing failures:\n%s", body)
	}
	if !strings.Contains(body, "1 of 4 entries") || !strings.Contains(body, "backup.failed") {
		t.Errorf("?outcome=failure did not choose the failure")
	}
}

// manyPeopleLog is a genuine chain of n entries, each from somebody else, as
// a log of visitors' form submissions is.
func manyPeopleLog(t *testing.T, n int) []audit.Event {
	t.Helper()
	dir := t.TempDir()
	key, _ := audit.NewKey()
	l, err := audit.New(audit.Options{Path: dir + "/a.jsonl", Key: key, Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := l.Append(audit.Record{Action: "form.submit", Resource: "/contact",
			Outcome: audit.Success, Principal: fmt.Sprintf("visitor-%d", i), Kind: audit.KindUnknown}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := audit.Read(dir + "/a.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	return events
}

// A view costs the page it shows. The page built and resolved a row for
// every entry in the log before it showed two hundred of them, so its cost
// grew with the log, and every new pseudonym, which visitors make, was one
// more lookup. Resolving is asked for what is on the page, and the filter on
// a name is the only thing that looks at everybody.
func TestAViewResolvesOnlyThePageItShows(t *testing.T) {
	events := manyPeopleLog(t, 600)
	s, tok := logServer(t, events, true)
	asked := map[string]bool{}
	s.ResolvePrincipal = func(p string) string {
		asked[p] = true
		return ""
	}
	body, code := getLogs(t, s, tok, "")
	if code != http.StatusOK {
		t.Fatalf("got %d", code)
	}
	if !strings.Contains(body, "600 of 600 entries") {
		t.Errorf("the view does not count the whole log")
	}
	if len(asked) > 200 {
		t.Errorf("a view of 200 rows resolved %d people", len(asked))
	}
	// The newest page, and the next one from where it ended.
	if !strings.Contains(body, events[599].Principal) || strings.Contains(body, events[399].Principal) {
		t.Errorf("the first page is not the newest two hundred")
	}
	body, _ = getLogs(t, s, tok, "?offset=200")
	if !strings.Contains(body, events[399].Principal) || strings.Contains(body, events[400].Principal) ||
		strings.Contains(body, events[199].Principal) {
		t.Errorf("the second page is not the next two hundred")
	}
	// A name filter still finds somebody wherever they are.
	body, _ = getLogs(t, s, tok, "?who="+events[3].Principal)
	if !strings.Contains(body, "1 of 600 entries") {
		t.Errorf("filtering on a pseudonym did not find its one entry")
	}
}

// Where the server indexes the log, the page reads the index and not the
// whole file, and the index is never believed for having been read before:
// what is appended shows on the next view, and an entry edited in place,
// keeping the file's length, is reported as an alteration.
func TestThePageReadsTheIndexAndStillSaysWhenTheLogWasAltered(t *testing.T) {
	path := t.TempDir() + "/audit.jsonl"
	l, err := audit.New(audit.Options{Path: path, Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	add := func(resource string) {
		if _, err := l.Append(audit.Record{Action: "publish", Resource: resource, Outcome: audit.Success,
			Principal: "dana", Kind: audit.KindHuman, Verified: true}); err != nil {
			t.Fatal(err)
		}
	}
	add("/first")
	add("/second")
	s, tok := logServer(t, nil, true)
	s.LoadAudit = func() ([]audit.Event, error) {
		t.Error("the page loaded the whole log with an index to read")
		return nil, nil
	}
	index := audit.NewIndex(path)
	s.AuditIndex = func() *audit.Index { return index }

	body, _ := getLogs(t, s, tok, "")
	if !strings.Contains(body, "Chain intact") || !strings.Contains(body, "/second") {
		t.Fatalf("the indexed log is not shown:\n%s", body)
	}
	add("/third")
	if body, _ = getLogs(t, s, tok, ""); !strings.Contains(body, "/third") || !strings.Contains(body, "3 of 3 entries") {
		t.Errorf("an entry appended since the last view is not shown")
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(b), "/first", "/FIRST", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	body, _ = getLogs(t, s, tok, "")
	if !strings.Contains(body, "has been altered") || strings.Contains(body, "Chain intact") {
		t.Errorf("an entry edited in place was shown as an intact log:\n%s", body)
	}
}

// The template escapes what a browser reads as markup and nothing else, so
// the escape sequences somebody holding a decoy put in the path they asked
// for reached this page byte for byte, as did every other control character
// a field of the log can hold. A browser draws them as nothing, and the row
// read as an ordinary path with stray brackets in it. The command line marks
// each one, and the page does the same; the filter still takes the action as
// the log holds it.
func TestThePageMarksEveryControlCharacterInTheLog(t *testing.T) {
	const redraw = "\x1b[2K\x1b[1A\x1b[2K\x1b[32mall quiet\x1b[0m"
	dir := t.TempDir()
	l, err := audit.New(audit.Options{Path: dir + "/a.jsonl", Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []audit.Record{
		{Action: "shield.decoy-touched", Resource: "/api/v1/pages" + redraw, Outcome: audit.Denied,
			Principal: "visitor\x7f", Kind: audit.KindUnknown, Detail: map[string]string{"planted\x1b[2K": "ci\u009b2K vault"}},
		{Action: "publish\u009b2K", Resource: "/x\rquiet", Outcome: audit.Success, Principal: "dana", Kind: audit.KindHuman, Verified: true},
		{Action: "render", Resource: "/c", Outcome: audit.Success, Principal: "dana", Kind: audit.KindHuman, Verified: true},
	} {
		if _, err := l.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	events, err := audit.Read(dir + "/a.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	// A doctored entry is drawn too, under the warning that it was doctored.
	events[2].At = "2026-11-10T09:00:00\x1b[2K"
	events[2].Outcome = "success\x1b[5A"
	s, tok := logServer(t, events, true)

	body, code := getLogs(t, s, tok, "")
	if code != http.StatusOK || !strings.Contains(body, "has been altered") {
		t.Fatalf("got %d:\n%s", code, body)
	}
	// What is drawn, which is everything outside a tag: the template escapes
	// every < and > a value holds, so each one left is the page's own. A
	// filter's option keeps the action as the log holds it, as its value, so
	// that choosing it finds it.
	inTag := false
	for _, r := range body {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
		case !inTag && (r < 0x20 && r != '\t' && r != '\n' || r == 0x7f || r >= 0x80 && r <= 0x9f):
			t.Fatalf("the page draws the control character %q from the log:\n%q", r, body)
		}
	}
	for _, want := range []string{"/api/v1/pages\uFFFD[2K", "visitor\uFFFD", "planted\uFFFD[2K", "ci\uFFFD2K vault",
		"publish\uFFFD2K", "/x\uFFFDquiet", "success\uFFFD[5A"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not show %q", want)
		}
	}
	body, _ = getLogs(t, s, tok, "?action=publish%C2%9B2K")
	if !strings.Contains(body, "1 of 3 entries") {
		t.Errorf("the filter no longer finds an action holding a control character")
	}
}
