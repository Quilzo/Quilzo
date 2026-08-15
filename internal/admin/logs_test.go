package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rsh1k/scrivet/internal/audit"
	"github.com/rsh1k/scrivet/internal/auth"
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
	for _, bad := range []string{"<form method=\"post\"", "Delete", "Remove",
		"Edit"} {
		if strings.Contains(body, bad) {
			t.Errorf("the log page contains %q", bad)
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
