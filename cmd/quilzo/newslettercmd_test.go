// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/mail"
	"github.com/quilzo/quilzo/internal/newsletter"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// newsletterStore is a bakery with mail set up, its https address, a
// published issue and a page for members, and the mail it would send.
func newsletterStore(t *testing.T) (string, *[]mail.Message) {
	t.Helper()
	root, _ := siteStore(t)
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"site.base_url": "https://crumb.example", "site.name": "Crumb"} {
		if err := cfg.Set(k, v, "", "dana"); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mailConfigPath(root), []byte(`{"host":"relay.example:587","from":"news@crumb.example"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index":   map[string]any{"title": "Crumb"},
		"october": map[string]any{"title": "October at Crumb", "paragraphs": []any{"Rye is back."}},
		"club":    map[string]any{"title": "For members", "members_only": true},
	}, "issue", "dana"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	sent := &[]mail.Message{}
	old := deliverMail
	deliverMail = func(_ *mail.Mailer, m mail.Message) error {
		mu.Lock()
		defer mu.Unlock()
		if _, err := m.Bytes(); err != nil {
			return err
		}
		*sent = append(*sent, m)
		return nil
	}
	t.Cleanup(func() { deliverMail = old })
	return root, sent
}

func confirmed(t *testing.T, root string, addrs ...string) *newsletter.List {
	t.Helper()
	list, err := openNewsletter(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		s, _, err := list.SignUp(newsletter.Subscriber{Email: a, Source: "web", Consent: "News"}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := list.Confirm(s.ID, list.Token(newsletter.ForConfirm, s.ID), time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	return list
}

// An issue goes to each confirmed address once, as its own message with its
// own way out, and to nobody who has not said yes.
func TestAnIssueGoesToEachConfirmedAddressWithItsOwnWayOut(t *testing.T) {
	root, sent := newsletterStore(t)
	list := confirmed(t, root, "ann@example.com", "bob@example.com")
	if _, _, err := list.SignUp(newsletter.Subscriber{Email: "waiting@example.com"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Without --yes, it says who it would go to and sends nothing.
	if err := sendCmd(root, "send", "october"); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 0 {
		t.Fatal("an issue was sent without --yes")
	}
	if err := sendCmd(root, "send", "october", "--yes"); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 2 {
		t.Fatalf("sent %d messages, want 2", len(*sent))
	}
	for _, m := range *sent {
		id := list.ID(m.To)
		u, err := url.Parse(m.Unsubscribe)
		if err != nil || u.Host != "crumb.example" || u.Query().Get("s") != id ||
			!list.Check(newsletter.ForLeave, id, u.Query().Get("t")) {
			t.Fatalf("%s's way out is not their own: %q", m.To, m.Unsubscribe)
		}
		if m.To == "waiting@example.com" || m.Subject != "October at Crumb" || m.FromName != "Crumb" ||
			m.ListID != "Crumb <newsletter.crumb.example>" || !strings.Contains(m.Body, "Rye is back.") ||
			!strings.Contains(m.Body, m.Unsubscribe) || !strings.Contains(m.HTML, "October at Crumb") {
			t.Fatalf("the message: %+v", m)
		}
	}
	issues, _ := list.Issues()
	if len(issues) != 1 || issues[0].State != newsletter.Sent || issues[0].Sent != 2 || issues[0].SentBy == "" {
		t.Fatalf("the issue: %+v", issues)
	}
	// Carrying on with a sent issue sends nothing more.
	if err := sendCmd(root, "send", "--issue", issues[0].ID, "--yes"); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 2 {
		t.Fatal("an issue went to the same addresses twice")
	}
	assertNoAddressInAudit(t, root)
}

func sendCmd(root string, args ...string) error {
	return newsletterCmd(root, args, asAdmin("dana"))
}

func TestAnIssueIsAPageAnybodyCanReadSentOverHTTPS(t *testing.T) {
	root, sent := newsletterStore(t)
	confirmed(t, root, "ann@example.com")
	for _, page := range []string{"club", "nowhere"} {
		if err := sendCmd(root, "send", page, "--yes"); err == nil {
			t.Errorf("%s was sent as an issue", page)
		}
	}
	cfg, _ := loadConfig(root)
	_ = cfg.Set("site.base_url", "http://crumb.example", "", "dana")
	_ = saveConfig(root, cfg)
	if err := sendCmd(root, "send", "october", "--yes"); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("an issue was sent with links over plain http: %v", err)
	}
	if len(*sent) != 0 {
		t.Fatal("something was sent")
	}
	reader := human("rae")
	reader.Role = "reader"
	if _, err := startIssue(root, "october", "", "", reader); err == nil {
		t.Fatal("a reader sent an issue")
	}
}

// An agent proposes; a person sends.
func TestAnAgentProposesAnIssueAndAPersonSendsIt(t *testing.T) {
	root, sent := newsletterStore(t)
	confirmed(t, root, "ann@example.com")
	call := siteCrew(t, root)
	got := call("quilzo_write", "propose_issue", map[string]any{"page": "october", "note": "Rye is back"})
	id, _ := got["issue"].(string)
	if id == "" || got["state"] != newsletter.Proposed {
		t.Fatalf("proposed: %v", got)
	}
	if len(*sent) != 0 {
		t.Fatal("proposing sent it")
	}
	status := call("quilzo_read", "newsletter_status", nil)
	if status["subscribed"] != float64(1) || strings.Contains(stringOf(status), "ann@") {
		t.Fatalf("the status, which names nobody: %v", status)
	}
	if got := call("quilzo_write", "propose_issue", map[string]any{"page": "club"}); got["error"] == nil {
		t.Fatal("a page for members was proposed as an issue")
	}
	// Another page chosen with the proposal open is a new issue of that page.
	other, err := startIssue(root, "index", "", id, asAdmin("dana"))
	if err != nil || other.ID == id || other.Page != "index" {
		t.Fatalf("another page chosen: %+v %v", other, err)
	}
	if err := sendCmd(root, "send", "--issue", id, "--yes"); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 1 || (*sent)[0].To != "ann@example.com" {
		t.Fatalf("sent: %+v", *sent)
	}
}

// A list comes from another platform and goes to one; who left stays gone.
func TestAListMovesBetweenPlatforms(t *testing.T) {
	root, sent := newsletterStore(t)
	file := filepath.Join(t.TempDir(), "mailchimp.csv")
	_ = os.WriteFile(file, []byte("Email Address,First Name,Last Name\nann@example.com,Ann,Lee\nbob@example.com,Bob,\n"), 0o600)
	if err := sendCmd(root, "import", file); err == nil {
		t.Fatal("imported without saying where they agreed")
	}
	if err := sendCmd(root, "import", file, "--agreed", "Signed up on our Mailchimp form"); err != nil {
		t.Fatal(err)
	}
	if _, err := removeSubscriber(root, "bob@example.com", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if err := sendCmd(root, "import", file, "--agreed", "Signed up on our Mailchimp form"); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := exportSubscribers(root, &out, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	csv := out.String()
	if !strings.Contains(csv, "ann@example.com,Ann Lee,") || strings.Contains(csv, "bob@") ||
		!strings.Contains(csv, "Mailchimp") {
		t.Fatalf("the export:\n%s", csv)
	}
	if len(*sent) != 0 {
		t.Fatal("an import mailed somebody")
	}
	// Asking somebody mails them the link a sign-up gets, and they are not
	// on the list until they say yes.
	if err := addSubscriber(root, "cat@example.com", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 1 || !strings.Contains((*sent)[0].Body, "https://crumb.example/newsletter/confirm?") {
		t.Fatalf("asked: %+v", *sent)
	}
	list, _ := openNewsletter(root)
	if ids, _ := list.ConfirmedIDs(); len(ids) != 1 {
		t.Fatalf("confirmed: %d", len(ids))
	}
	assertNoAddressInAudit(t, root)
}

// Addresses that never confirm are forgotten by the housekeeping.
func TestTheHousekeepingForgetsWhoNeverConfirmed(t *testing.T) {
	root, _ := newsletterStore(t)
	list, _ := openNewsletter(root)
	s, _, _ := list.SignUp(newsletter.Subscriber{Email: "ann@example.com"}, time.Now())
	old := time.Now().Add(-8 * 24 * time.Hour)
	_ = os.Chtimes(filepath.Join(newsletterDir(root), "subscribers", s.ID+".json"), old, old)
	job, ok := retentionJob(root)
	if !ok {
		t.Fatal("no housekeeping")
	}
	if _, err := job.Do(time.Now()); err != nil {
		t.Fatal(err)
	}
	if list.Has(s.ID) {
		t.Fatal("an address that never said yes is kept past the week")
	}
}

func assertNoAddressInAudit(t *testing.T, root string) {
	t.Helper()
	b, err := os.ReadFile(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "@example.com") {
		t.Fatal("the audit log names an address on the list")
	}
}

func stringOf(m map[string]any) string {
	b, _ := json.Marshal(m)
	return string(b)
}
