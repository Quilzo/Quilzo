// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package newsletter

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openList(t *testing.T) *List {
	t.Helper()
	dir := t.TempDir()
	key := filepath.Join(dir, "newsletter.key")
	if err := MakeKey(key); err != nil {
		t.Fatal(err)
	}
	l, err := Open(filepath.Join(dir, "newsletter"), key)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

var t0 = time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)

func TestTheKeyIsMadeOnceAndAListNeedsIt(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "newsletter.key")
	if _, err := Open(filepath.Join(dir, "n"), key); !errors.Is(err, ErrNoKey) {
		t.Fatalf("a list without its key opened: %v", err)
	}
	if err := MakeKey(key); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(key)
	if err := MakeKey(key); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(key)
	if string(before) != string(after) {
		t.Fatal("making the key again replaced it, and every link already mailed stopped working")
	}
}

func TestOneInboxIsOneEntry(t *testing.T) {
	l := openList(t)
	for _, bad := range []string{"", "no-at-sign", "a@b", "two@@example.com", "x@example.com\r\nBcc: y@example.com"} {
		if _, err := Normalize(bad); err == nil {
			t.Errorf("%q was taken as an address", bad)
		}
	}
	a, _ := Normalize("  Ann@Example.COM ")
	b, _ := Normalize("ann@example.com")
	if a != b || l.ID(a) != l.ID(b) {
		t.Fatalf("%q and %q are one inbox and two entries", a, b)
	}
}

func TestSigningUpMailsOnceAnHourAndNeverAConfirmedAddress(t *testing.T) {
	l := openList(t)
	s, out, err := l.SignUp(Subscriber{Email: "ann@example.com", Source: "web", Consent: "News, monthly"}, t0)
	if err != nil || out != Mail {
		t.Fatalf("a new address: %v %v", out, err)
	}
	if _, out, _ := l.SignUp(Subscriber{Email: "ANN@example.com"}, t0.Add(10*time.Minute)); out != Quiet {
		t.Fatal("asked again within the hour, it was mailed again: the form fills somebody's inbox")
	}
	// The hour is the record's clock, which the test moves.
	old := t0.Add(-2 * time.Hour)
	_ = os.Chtimes(l.subscriberPath(s.ID), old, old)
	if _, out, _ := l.SignUp(Subscriber{Email: "ann@example.com"}, t0.Add(time.Minute)); out != Mail {
		t.Fatal("asked again after an hour, nothing was sent: a lost mail is a lost subscriber")
	}
	if err := l.Confirm(s.ID, l.Token(ForConfirm, s.ID), t0); err != nil {
		t.Fatal(err)
	}
	old = t0.Add(-5 * time.Hour)
	_ = os.Chtimes(l.subscriberPath(s.ID), old, old)
	if _, out, _ := l.SignUp(Subscriber{Email: "ann@example.com"}, t0.Add(time.Hour)); out != Quiet {
		t.Fatal("a confirmed address was mailed a link again by whoever typed it in")
	}
	got, err := l.Get(s.ID)
	if err != nil || got.Confirmed.IsZero() || got.Consent != "News, monthly" || got.Source != "web" {
		t.Fatalf("the record: %+v %v", got, err)
	}
}

func TestALinkWorksOnlyForItsAddressAndPurpose(t *testing.T) {
	l := openList(t)
	ann, _, _ := l.SignUp(Subscriber{Email: "ann@example.com"}, t0)
	bob, _, _ := l.SignUp(Subscriber{Email: "bob@example.com"}, t0)
	for name, try := range map[string][2]string{
		"another address's token": {ann.ID, l.Token(ForConfirm, bob.ID)},
		"the leave token":         {ann.ID, l.Token(ForLeave, ann.ID)},
		"no token":                {ann.ID, ""},
		"a made-up id":            {strings.Repeat("0", 24), l.Token(ForConfirm, strings.Repeat("0", 24))},
	} {
		if err := l.Confirm(try[0], try[1], t0); err == nil {
			t.Errorf("%s confirmed an address", name)
		}
	}
	if c, _ := l.Count(); c.Subscribed != 0 || c.Waiting != 2 {
		t.Fatalf("counts: %+v", c)
	}
	if _, err := l.Leave(ann.ID, l.Token(ForConfirm, ann.ID), "one-click", t0); err == nil {
		t.Fatal("a confirm link took an address off the list")
	}
}

func TestLeavingDeletesTheAddressAndKeepsItFromComingBack(t *testing.T) {
	l := openList(t)
	s, _, _ := l.SignUp(Subscriber{Email: "ann@example.com"}, t0)
	_ = l.Confirm(s.ID, l.Token(ForConfirm, s.ID), t0)
	was, err := l.Leave(s.ID, l.Token(ForLeave, s.ID), "one-click", t0)
	if err != nil || !was {
		t.Fatalf("leave: %v %v", was, err)
	}
	if _, err := l.Get(s.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("the address is still kept after it left")
	}
	if was, err := l.Leave(s.ID, l.Token(ForLeave, s.ID), "one-click", t0); err != nil || was {
		t.Fatalf("leaving twice is not an error, and says it was not there: %v %v", was, err)
	}
	if added, err := l.Add(Subscriber{Email: "ann@example.com", Source: "import"}, t0); err != nil || added {
		t.Fatal("an import put back an address that asked to stop")
	}
	// Asking again on the site, and confirming, is the way back.
	if _, out, _ := l.SignUp(Subscriber{Email: "ann@example.com"}, t0); out != Mail {
		t.Fatal("asking again after leaving sent no link")
	}
	if !l.Left(s.ID) {
		t.Fatal("the leaving was forgotten before the address confirmed again")
	}
	if err := l.Confirm(s.ID, l.Token(ForConfirm, s.ID), t0); err != nil {
		t.Fatal(err)
	}
	if l.Left(s.ID) {
		t.Fatal("confirmed again, and still marked as having left")
	}
	ids, _ := l.ConfirmedIDs()
	if len(ids) != 1 || ids[0] != s.ID {
		t.Fatalf("confirmed: %v", ids)
	}
}

// What the public site does — sign up, confirm, leave, count, expire —
// reads no address. A record it cannot make sense of changes none of it.
func TestTheSitesOperationsReadNoAddress(t *testing.T) {
	l := openList(t)
	s, _, _ := l.SignUp(Subscriber{Email: "ann@example.com"}, t0)
	if err := os.WriteFile(l.subscriberPath(s.ID), []byte("not an address at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.SignUp(Subscriber{Email: "ann@example.com"}, t0.Add(2*time.Hour)); err != nil {
		t.Fatalf("signing up again read the record: %v", err)
	}
	if !l.Waiting(s.ID) {
		t.Fatal("waiting is answered by reading")
	}
	if err := l.Confirm(s.ID, l.Token(ForConfirm, s.ID), t0); err != nil {
		t.Fatalf("confirming read the record: %v", err)
	}
	if c, err := l.Count(); err != nil || c.Subscribed != 1 {
		t.Fatalf("counting read the record: %+v %v", c, err)
	}
	if _, err := l.Leave(s.ID, l.Token(ForLeave, s.ID), "page", t0); err != nil {
		t.Fatalf("leaving read the record: %v", err)
	}
}

func TestAnAddressThatNeverConfirmsIsForgottenAfterAWeek(t *testing.T) {
	l := openList(t)
	waiting, _, _ := l.SignUp(Subscriber{Email: "ann@example.com"}, t0)
	confirmed, _, _ := l.SignUp(Subscriber{Email: "bob@example.com"}, t0)
	_ = l.Confirm(confirmed.ID, l.Token(ForConfirm, confirmed.ID), t0)
	old := t0.Add(-8 * 24 * time.Hour)
	for _, id := range []string{waiting.ID, confirmed.ID} {
		_ = os.Chtimes(l.subscriberPath(id), old, old)
	}
	n, err := l.Expire(t0)
	if err != nil || n != 1 {
		t.Fatalf("expired %d: %v", n, err)
	}
	if _, err := l.Get(waiting.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("an address that never said yes is kept past the week")
	}
	if _, err := l.Get(confirmed.ID); err != nil {
		t.Fatal("a confirmed address was expired")
	}
	if err := l.Confirm(waiting.ID, l.Token(ForConfirm, waiting.ID), t0); !errors.Is(err, ErrNotFound) {
		t.Fatal("a link to a forgotten address still confirmed it")
	}
}

func TestAnIssueReachesEachAddressOnceAndGoesOnWhereItStopped(t *testing.T) {
	l := openList(t)
	var ids []string
	for _, a := range []string{"a@example.com", "b@example.com", "c@example.com", "d@example.com"} {
		s, _, _ := l.SignUp(Subscriber{Email: a}, t0)
		_ = l.Confirm(s.ID, l.Token(ForConfirm, s.ID), t0)
		ids = append(ids, s.ID)
	}
	// One that never confirmed is not sent to.
	waiting, _, _ := l.SignUp(Subscriber{Email: "w@example.com"}, t0)
	is, err := l.NewIssue("october", "October news", Sending, "ann", "", t0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	stop := make(chan struct{})
	n := 0
	deliver := func(s Subscriber) error {
		got[s.Email]++
		n++
		if n == 2 {
			close(stop)
		}
		return nil
	}
	clock := func() time.Time { return t0 }
	res, err := l.Send(is.ID, "ann", deliver, 0, clock, stop, nil)
	if err != nil || res.State != Stopped || res.Sent != 2 {
		t.Fatalf("stopped: %+v %v", res, err)
	}
	// One leaves before it goes on.
	left := ""
	for _, id := range ids {
		if r, _ := l.Reached(is.ID); !r[id] {
			left = id
			break
		}
	}
	_, _ = l.Remove(left, t0)
	res, err = l.Send(is.ID, "ann", deliver, 0, clock, make(chan struct{}), nil)
	if err != nil || res.State != Sent || res.Sent != 3 || res.To != 3 {
		t.Fatalf("went on: %+v %v", res, err)
	}
	for a, c := range got {
		if c != 1 {
			t.Errorf("%s was sent the issue %d times", a, c)
		}
	}
	if got["w@example.com"] > 0 {
		t.Error("an address that never confirmed was sent the issue")
	}
	_ = waiting
	if len(got) != 3 {
		t.Errorf("reached %d addresses, want 3: %v", len(got), got)
	}
	again, _ := l.Send(is.ID, "ann", deliver, 0, clock, make(chan struct{}), nil)
	if again.Sent != 3 || len(got) != 3 {
		t.Fatal("sending a sent issue again sent it again")
	}
}

func TestARelayThatKeepsRefusingStopsTheSend(t *testing.T) {
	l := openList(t)
	for i := 0; i < GiveUpAfter+3; i++ {
		s, _, _ := l.SignUp(Subscriber{Email: string(rune('a'+i)) + "@example.com"}, t0)
		_ = l.Confirm(s.ID, l.Token(ForConfirm, s.ID), t0)
	}
	is, _ := l.NewIssue("october", "October", Sending, "ann", "", t0)
	tries := 0
	res, err := l.Send(is.ID, "ann", func(Subscriber) error { tries++; return errors.New("554 relay says no") },
		0, func() time.Time { return t0 }, make(chan struct{}), nil)
	if err == nil || res.State != Stopped || tries != GiveUpAfter || !strings.Contains(res.Problem, "554") {
		t.Fatalf("after %d refusals: %+v %v", tries, res, err)
	}
}

func TestAgentsProposeAShortListOfIssues(t *testing.T) {
	l := openList(t)
	for i := 0; i < MaxProposed; i++ {
		if _, err := l.NewIssue("p", "Subject", Proposed, "writer", "", t0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.NewIssue("p", "One more", Proposed, "writer", "", t0); err == nil {
		t.Fatal("an agent in a loop proposes without end")
	}
	if _, err := l.NewIssue("p", " ", Sending, "ann", "", t0); err == nil {
		t.Fatal("an issue with no subject")
	}
}

func TestAPageBecomesALetterWithItsWordsInOrder(t *testing.T) {
	page := map[string]any{
		"title":      "October at the bakery",
		"standfirst": "Rye is back, and so are we on Sundays.",
		"hero":       "/media/rye.jpg", "hero_alt": "Rye loaves",
		"paragraphs": []any{"The starter survived the summer.", "## Opening hours\n\nSundays, 8 to 1."},
		"sections": []any{
			map[string]any{"features": map[string]any{"title": "New this month", "items": []any{
				map[string]any{"title": "Rye", "body": "Dark and dense."}}}},
			map[string]any{"booking": map[string]any{"service": "class"}},
			map[string]any{"cta": map[string]any{"title": "Order", "cta_label": "Order a loaf", "cta_href": "/order"}},
			map[string]any{"prose": map[string]any{"paragraphs": []any{"<script>alert(1)</script> & more"}}},
		},
	}
	lt := Compose(Source{Site: "Crumb", Base: "https://crumb.example", Path: "/october", Page: page}, "October")
	order := []string{"October at the bakery", "Rye is back", "The starter survived", "OPENING HOURS",
		"Sundays, 8 to 1.", "NEW THIS MONTH", "• Rye: Dark and dense.", "Order a loaf: https://crumb.example/order",
		"Read it on the web: https://crumb.example/october"}
	at := 0
	for _, want := range order {
		i := strings.Index(lt.Text[at:], want)
		if i < 0 {
			t.Fatalf("the text lacks %q after position %d:\n%s", want, at, lt.Text)
		}
		at += i
	}
	if !strings.Contains(lt.Text, "more on the page than a mail can carry") {
		t.Error("a booking section left out, and the letter does not say so")
	}
	if strings.Contains(lt.HTML, "<script>") || !strings.Contains(lt.HTML, "&lt;script&gt;") {
		t.Error("page text went into the HTML unescaped")
	}
	if !strings.Contains(lt.HTML, `src="https://crumb.example/media/rye.jpg"`) || !strings.Contains(lt.HTML, `alt="Rye loaves"`) {
		t.Error("the picture is not there, absolute and described")
	}
	text, html := lt.For("https://crumb.example/newsletter/leave?s=abc&t=xyz")
	if !strings.Contains(text, "leave?s=abc&t=xyz") || !strings.Contains(html, `leave?s=abc&amp;t=xyz`) {
		t.Fatalf("the leave link is not in both parts")
	}
	if strings.Contains(text+html, leaveMark) {
		t.Fatal("the placeholder for the leave link was sent")
	}
}

// A sign-up form left out is not "more on the page": everybody reading
// the letter is on the list already.
func TestASignUpLeftOutIsNotMissed(t *testing.T) {
	page := map[string]any{"title": "T", "sections": []any{map[string]any{"newsletter": map[string]any{"title": "Join"}}}}
	lt := Compose(Source{Base: "https://crumb.example", Path: "/t", Page: page}, "T")
	if strings.Contains(lt.Text, "more on the page") || strings.Contains(lt.Text, "Join") {
		t.Fatalf("the letter:\n%s", lt.Text)
	}
}

func TestOnlyPicturesTheSiteServesOrHTTPSAreInALetter(t *testing.T) {
	page := map[string]any{"title": "T", "hero": "javascript:alert(1)",
		"sections": []any{map[string]any{"split": map[string]any{"image": "//evil.example/x.png"}}}}
	lt := Compose(Source{Base: "https://crumb.example", Path: "/", Page: page}, "T")
	if strings.Contains(lt.HTML, "javascript:") || strings.Contains(lt.HTML, "evil.example") {
		t.Fatal("a picture from an address that is not the site's or https went into the mail")
	}
}

func TestListsFromOtherPlatformsAreRead(t *testing.T) {
	cases := map[string]struct {
		file             string
		emails, left, sk int
	}{
		"mailchimp": {"\xef\xbb\xbfEmail Address,First Name,Last Name,OPTIN_TIME\nann@example.com,Ann,Lee,2025-03-01 10:00:00\nbob@example.com,,,\n", 2, 0, 0},
		"ghost":     {"id,email,name,note,subscribed_to_emails,created_at\n1,ann@example.com,Ann,,true,2025-03-01T10:00:00Z\n2,bob@example.com,Bob,,false,2025-03-01T10:00:00Z\n", 2, 1, 0},
		"mailpoet":  {"email;status\nann@example.com;subscribed\nbob@example.com;unsubscribed\ncat@example.com;unconfirmed\n", 3, 1, 1},
		"substack":  {"email,active_subscription,email_disabled,created_at\nann@example.com,false,false,2025-01-01\nbob@example.com,false,true,2025-01-01\n", 2, 1, 0},
		"headless":  {"ann@example.com\nbob@example.com\n", 2, 0, 0},
	}
	for name, c := range cases {
		rows, err := ReadCSV(strings.NewReader(c.file))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		left, skip := 0, 0
		for _, r := range rows {
			if r.Left {
				left++
			}
			if r.Skip {
				skip++
			}
		}
		if len(rows) != c.emails || left != c.left || skip != c.sk {
			t.Errorf("%s: %d rows, %d left, %d skipped: %+v", name, len(rows), left, skip, rows)
		}
	}
	rows, _ := ReadCSV(strings.NewReader("Email Address,First Name,Last Name,OPTIN_TIME\nann@example.com,Ann,Lee,2025-03-01 10:00:00\n"))
	if rows[0].Name != "Ann Lee" || rows[0].At.Year() != 2025 {
		t.Errorf("name and date: %+v", rows[0])
	}
	if _, err := ReadCSV(strings.NewReader("name,phone\nAnn,123\n")); err == nil {
		t.Error("a file with no addresses was read as a list")
	}
}

func TestAnImportHonoursWhoLeftWhereverTheyLeft(t *testing.T) {
	l := openList(t)
	here, _, _ := l.SignUp(Subscriber{Email: "here@example.com"}, t0)
	_ = l.Confirm(here.ID, l.Token(ForConfirm, here.ID), t0)
	got, err := l.Import([]Row{
		{Email: "new@example.com", Name: "New"},
		{Email: "gone@example.com", Left: true},
		{Email: "here@example.com", Left: true},
		{Email: "maybe@example.com", Skip: true},
		{Email: "not an address"},
	}, "Imported from Mailchimp, where they signed up", t0)
	if err != nil {
		t.Fatal(err)
	}
	if got != (Imported{Added: 1, Already: 1, Left: 1, Skipped: 1, Bad: 1}) {
		t.Fatalf("import: %+v", got)
	}
	if _, err := l.Get(here.ID); err != nil {
		t.Fatal("an old list saying they left took off somebody who signed up here")
	}
	if !l.Left(l.ID("gone@example.com")) {
		t.Fatal("somebody who left elsewhere can be imported again")
	}
	s, _ := l.Get(l.ID("new@example.com"))
	if s.Confirmed.IsZero() || s.Source != "import" || !strings.Contains(s.Consent, "Mailchimp") {
		t.Fatalf("imported: %+v", s)
	}
	var b strings.Builder
	all, _ := l.All()
	all = append(all, Subscriber{Email: "x@example.com", Name: "=HYPERLINK(\"http://evil\")", Confirmed: t0, At: t0})
	if err := WriteCSV(&b, all); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.HasPrefix(out, "email,name,") || !strings.Contains(out, "new@example.com") ||
		strings.Contains(out, ",=HYPERLINK") {
		t.Fatalf("export:\n%s", out)
	}
	// What was exported is read back as the same list.
	back, err := ReadCSV(strings.NewReader(out))
	if err != nil || len(back) != 3 {
		t.Fatalf("read back: %v %+v", err, back)
	}
}
