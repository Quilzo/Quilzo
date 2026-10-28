// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/newsletter"
)

// Newsletter lists who is on the list and the issues, sends a test, sends
// only with the box ticked, and keeps the list.
func TestNewsletterScreen(t *testing.T) {
	srv, token := setup(t)
	var tested, sent, removed, dismissed string
	now := time.Now()
	srv.Newsletter = &NewsletterHooks{
		Problems: func() []string { return nil },
		Counts:   func() (newsletter.Counts, error) { return newsletter.Counts{Subscribed: 1, Waiting: 1, Left: 2}, nil },
		List: func() ([]newsletter.Subscriber, error) {
			return []newsletter.Subscriber{
				{ID: "aaaaaaaaaaaaaaaaaaaaaaaa", Email: "ann@example.com", Name: "Ann", At: now, Source: "web", Confirmed: now},
				{ID: "bbbbbbbbbbbbbbbbbbbbbbbb", Email: "bob@example.com", At: now, Source: "import"},
			}, nil
		},
		Issues: func() ([]newsletter.Issue, error) {
			return []newsletter.Issue{
				{ID: "20261028-aaaaaaaa", Page: "october", Subject: "October news", State: newsletter.Proposed,
					Proposed: now, By: "writer", Note: "Rye is back"},
				{ID: "20261001-bbbbbbbb", Page: "september", Subject: "September", State: newsletter.Stopped,
					Started: now, To: 10, Sent: 4, Failed: 1, Problem: "554 no"},
			}, nil
		},
		Pages:  func() ([]string, error) { return []string{"september", "october"}, nil },
		Add:    func(string, Actor) error { return nil },
		Remove: func(id string, _ Actor) (bool, error) { removed = id; return true, nil },
		Import: func(io.Reader, string, Actor) (newsletter.Imported, error) { return newsletter.Imported{Added: 2}, nil },
		Export: func(w io.Writer, _ Actor) (int, error) {
			_, err := io.WriteString(w, "email\nann@example.com\n")
			return 1, err
		},
		Test: func(page, _, to string, _ Actor) error { tested = page + " " + to; return nil },
		Send: func(page, _, issue string, _ Actor) (newsletter.Issue, error) {
			sent = page + " " + issue
			return newsletter.Issue{Subject: "October news"}, nil
		},
		Continue: func(string, Actor) error { return nil },
		Stop:     func(string, Actor) error { return nil },
		Dismiss:  func(id string, _ Actor) error { dismissed = id; return nil },
	}

	res := get(t, srv, "/newsletter?page=october", token)
	page := res.Body.String()
	for _, want := range []string{"ann@example.com", "waiting to confirm", "October news", "writer", "Rye is back",
		"4 of 10", "554 no", "Carry on", "Send to 1", `<option value="october" selected>`} {
		if !strings.Contains(page, want) {
			t.Errorf("the screen lacks %q", want)
		}
	}
	if res.Header().Get("Cache-Control") != "no-store" {
		t.Error("a page of addresses may be kept by the browser")
	}
	whole(t, page)

	if _, loc := postFormLoc(t, srv, token, "/newsletter/act", url.Values{"do": {"test"}, "page": {"october"},
		"to": {"me@example.com"}}); tested != "october me@example.com" || problemIn(loc) != "" {
		t.Fatalf("a test: %q %s", tested, loc)
	}
	if _, loc := postFormLoc(t, srv, token, "/newsletter/act", url.Values{"do": {"send"}, "page": {"october"}}); sent != "" ||
		problemIn(loc) == "" {
		t.Fatalf("sent without the box ticked: %q %s", sent, loc)
	}
	if code, _ := postFormLoc(t, srv, token, "/newsletter/act", url.Values{"do": {"send"}, "page": {"october"},
		"sure": {"1"}, "issue": {"20261028-aaaaaaaa"}}); code != http.StatusSeeOther || sent != "october 20261028-aaaaaaaa" {
		t.Fatalf("sending a proposed issue: %d %q", code, sent)
	}
	if postFormLoc(t, srv, token, "/newsletter/act", url.Values{"do": {"remove"}, "id": {"bbbbbbbbbbbbbbbbbbbbbbbb"}}); removed == "" {
		t.Fatal("not removed")
	}
	if postFormLoc(t, srv, token, "/newsletter/act", url.Values{"do": {"dismiss"}, "issue": {"20261028-aaaaaaaa"}}); dismissed == "" {
		t.Fatal("not dismissed")
	}
	csv := get(t, srv, "/newsletter/export.csv", token)
	if csv.Header().Get("Content-Type") != "text/csv; charset=utf-8" || !strings.Contains(csv.Body.String(), "ann@example.com") ||
		csv.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("the export: %q", csv.Header())
	}
}

// problemIn is the error a redirect back to the screen carries.
func problemIn(loc string) string {
	u, err := url.Parse(loc)
	if err != nil {
		return err.Error()
	}
	return u.Query().Get("e")
}
