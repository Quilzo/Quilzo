// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/mail"
	"github.com/quilzo/quilzo/internal/newsletter"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/starter"
)

type newsletterRig struct {
	st     *Site
	list   *newsletter.List
	mailed chan mail.Message
	ready  *bool
	now    *time.Time
	mu     sync.Mutex
	events []string
}

// newsletterSite is a bakery whose "news" page signs visitors up, on the
// sections starter's own layout.
func newsletterSite(t *testing.T) *newsletterRig {
	t.Helper()
	st := published(t, map[string]any{
		"index": map[string]any{"title": "Crumb"},
		"news": map[string]any{"title": "News", "sections": []any{
			map[string]any{"newsletter": map[string]any{"title": "Get our news",
				"what": "Bread, once a month."}}}},
		"about": map[string]any{"title": "About"},
	})
	tpl, _ := starter.Get("sections")
	html, err := tpl.HTML()
	if err != nil {
		t.Fatal(err)
	}
	st.Layouts = render.OneLayout(html)
	st.Name, st.Index, st.BaseURL = "Crumb", "index", "https://crumb.example"
	dir := t.TempDir()
	key := filepath.Join(dir, "newsletter.key")
	if err := newsletter.MakeKey(key); err != nil {
		t.Fatal(err)
	}
	list, err := newsletter.Open(filepath.Join(dir, "newsletter"), key)
	if err != nil {
		t.Fatal(err)
	}
	rig := &newsletterRig{st: st, list: list, mailed: make(chan mail.Message, 8), ready: new(bool)}
	*rig.ready = true
	now := time.Date(2026, 11, 2, 8, 0, 0, 0, time.UTC)
	rig.now = &now
	var audited []string
	st.Newsletter = &Newsletter{List: list, Ready: func() bool { return *rig.ready },
		Mail: func(m mail.Message) error { rig.mailed <- m; return nil },
		Now:  func() time.Time { return *rig.now },
		Audit: func(action, source string, ok bool) {
			rig.mu.Lock()
			audited = append(audited, action+" "+source)
			rig.mu.Unlock()
		},
		Notify: func(e string) { rig.mu.Lock(); rig.events = append(rig.events, e); rig.mu.Unlock() }}
	t.Cleanup(func() {
		rig.mu.Lock()
		defer rig.mu.Unlock()
		for _, a := range audited {
			if strings.Contains(a, "@") {
				t.Errorf("an audit record names an address: %s", a)
			}
		}
	})
	return rig
}

func (rig *newsletterRig) signUp(addr string) *httptest.ResponseRecorder {
	read := fmt.Sprint(rig.now.Add(-time.Minute).Unix())
	return postTo(rig.st, "/newsletter/subscribe", url.Values{"page": {"news"}, "email": {addr}, "form_started": {read}})
}

func (rig *newsletterRig) nextMail(t *testing.T) mail.Message {
	t.Helper()
	select {
	case m := <-rig.mailed:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no mail was sent")
	}
	return mail.Message{}
}

func (rig *newsletterRig) noMail(t *testing.T) {
	t.Helper()
	select {
	case m := <-rig.mailed:
		t.Fatalf("a mail was sent: %+v", m)
	case <-time.After(200 * time.Millisecond):
	}
}

var reConfirm = regexp.MustCompile(`https://crumb\.example(/newsletter/confirm\?s=[0-9a-f]+&t=[A-Za-z0-9_-]+)`)

// A visitor signs up, is mailed one link, says yes on the page it opens,
// and leaves again with the one click a mail app makes. Nothing the site
// says or records names them.
func TestAVisitorSignsUpConfirmsAndLeaves(t *testing.T) {
	rig := newsletterSite(t)
	page := getPage(rig.st, "/news")
	body := page.Body.String()
	if !strings.Contains(body, `action="/newsletter/subscribe"`) || !strings.Contains(body, "Bread, once a month.") {
		t.Fatalf("the sign-up form:\n%s", body)
	}
	if rep := a11y.Check("news", body); rep.Blocks() {
		t.Fatalf("the sign-up form is not usable by everybody: %+v", rep)
	}
	res := rig.signUp("Ann@Example.com")
	loc := res.Header().Get("Location")
	if res.Code != http.StatusSeeOther || loc != "/news?newsletter=sent#newsletter" {
		t.Fatalf("signing up: %d %q %s", res.Code, loc, res.Body.String())
	}
	thanks := getPage(rig.st, loc)
	if !strings.Contains(thanks.Body.String(), "a link to confirm it is on its way") ||
		thanks.Header().Get("Cache-Control") != "no-store" || strings.Contains(thanks.Body.String(), "Ann@") {
		t.Fatalf("after signing up: %q\n%s", thanks.Header().Get("Cache-Control"), thanks.Body.String())
	}
	m := rig.nextMail(t)
	link := reConfirm.FindStringSubmatch(m.Body)
	if m.To != "ann@example.com" || link == nil || !strings.Contains(m.Subject, "Crumb") {
		t.Fatalf("the confirmation: %+v", m)
	}
	if c, _ := rig.list.Count(); c.Waiting != 1 || c.Subscribed != 0 {
		t.Fatalf("before saying yes: %+v", c)
	}

	// Opening the link, as a mail filter does, confirms nothing.
	open := getPage(rig.st, link[1])
	ob := open.Body.String()
	if open.Code != 200 || !strings.Contains(ob, "Yes, send it to me") || open.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("the confirm page: %d\n%s", open.Code, ob)
	}
	if rep := a11y.Check("confirm", ob); rep.Blocks() {
		t.Fatalf("the confirm page is not usable by everybody: %+v", rep)
	}
	if c, _ := rig.list.Count(); c.Subscribed != 0 {
		t.Fatal("opening the link confirmed the address: a mail filter's look is a yes")
	}
	yes := postTo(rig.st, link[1], url.Values{})
	if yes.Code != 200 || !strings.Contains(yes.Body.String(), "You are subscribed") {
		t.Fatalf("saying yes: %d\n%s", yes.Code, yes.Body.String())
	}
	if c, _ := rig.list.Count(); c.Subscribed != 1 || c.Waiting != 0 {
		t.Fatalf("after saying yes: %+v", c)
	}
	// Signing up again is answered alike, and mails nothing.
	*rig.now = rig.now.Add(3 * time.Hour)
	if res := rig.signUp("ann@example.com"); res.Header().Get("Location") != "/news?newsletter=sent#newsletter" {
		t.Fatal("signing up a subscribed address was answered differently, which tells anybody who is on the list")
	}
	rig.noMail(t)

	// One click, the way a mail app does it: a POST, multipart, no cookie.
	id := rig.list.ID("ann@example.com")
	leave := "/newsletter/leave?" + url.Values{"s": {id}, "t": {rig.list.Token(newsletter.ForLeave, id)}}.Encode()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("List-Unsubscribe", "One-Click")
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, leave, &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	rig.st.Handler().ServeHTTP(w, r)
	if w.Code != 200 || w.Header().Get("Location") != "" || !strings.Contains(w.Body.String(), "unsubscribed") {
		t.Fatalf("one click: %d %q %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	if c, _ := rig.list.Count(); c.Subscribed != 0 || c.Left != 1 {
		t.Fatalf("after leaving: %+v", c)
	}
	if _, err := rig.list.Get(id); err == nil {
		t.Fatal("the address is still kept after it left")
	}
	// The link in the mail's own words still opens a page saying so.
	again := getPage(rig.st, leave)
	if again.Code != 200 || !strings.Contains(again.Body.String(), "Stop sending it") {
		t.Fatalf("the leave page: %d", again.Code)
	}
	rig.mu.Lock()
	defer rig.mu.Unlock()
	if strings.Join(rig.events, ",") != "subscribed,unsubscribed" {
		t.Fatalf("told: %v", rig.events)
	}
}

func TestASignUpThatShouldNotGoThroughDoesNot(t *testing.T) {
	rig := newsletterSite(t)
	now := fmt.Sprint(rig.now.Unix())
	for name, c := range map[string]struct {
		v    url.Values
		want string
	}{
		"a script filling every field": {url.Values{"page": {"news"}, "email": {"a@example.com"},
			"website_url": {"x"}, "form_started": {"1"}}, "newsletter_error=refused"},
		"no time to read the page": {url.Values{"page": {"news"}, "email": {"a@example.com"},
			"form_started": {now}}, "newsletter_error=refused"},
		"not an address": {url.Values{"page": {"news"}, "email": {"ann at example"},
			"form_started": {"1"}}, "newsletter_error=address"},
	} {
		res := postTo(rig.st, "/newsletter/subscribe", c.v)
		if !strings.Contains(res.Header().Get("Location"), c.want) {
			t.Errorf("%s: %d %q", name, res.Code, res.Header().Get("Location"))
		}
	}
	if res := postTo(rig.st, "/newsletter/subscribe", url.Values{"page": {"about"}, "email": {"a@example.com"},
		"form_started": {"1"}}); res.Code != http.StatusNotFound {
		t.Errorf("a page with no sign-up signed somebody up: %d", res.Code)
	}
	rig.noMail(t)
	if c, _ := rig.list.Count(); c.Waiting != 0 {
		t.Fatalf("refused sign-ups were kept: %+v", c)
	}
	// Without mail set up the section says so, and takes nobody.
	*rig.ready = false
	if b := getPage(rig.st, "/news").Body.String(); strings.Contains(b, `action="/newsletter/subscribe"`) ||
		!strings.Contains(b, "Sign-ups are not taken just now") {
		t.Fatalf("a site that cannot mail a link offered to:\n%s", b)
	}
	if res := rig.signUp("a@example.com"); !strings.Contains(res.Header().Get("Location"), "newsletter_error=closed") {
		t.Fatalf("a site that cannot mail a link took a sign-up: %q", res.Header().Get("Location"))
	}
	*rig.ready = true
	// Links that are not whole.
	id := rig.list.ID("a@example.com")
	for _, target := range []string{
		"/newsletter/confirm?s=" + id + "&t=nope",
		"/newsletter/confirm?s=../../etc&t=x",
		"/newsletter/leave?s=" + id + "&t=" + rig.list.Token(newsletter.ForConfirm, id),
	} {
		if res := getPage(rig.st, target); res.Code != http.StatusNotFound {
			t.Errorf("%s: %d", target, res.Code)
		}
	}
	oneClick := postTo(rig.st, "/newsletter/leave?s="+id+"&t=nope", url.Values{"List-Unsubscribe": {"One-Click"}})
	if oneClick.Code != http.StatusNotFound {
		t.Errorf("a leave link that is not whole: %d", oneClick.Code)
	}
}

// Whether a page takes sign-ups is in its tag, so turning mail on is not
// answered "not modified" with a page that says sign-ups are closed.
func TestTurningMailOnChangesThePagesTag(t *testing.T) {
	rig := newsletterSite(t)
	*rig.ready = false
	closed := getPage(rig.st, "/news").Header().Get("ETag")
	*rig.ready = true
	r := httptest.NewRequest(http.MethodGet, "/news", nil)
	r.Header.Set("If-None-Match", closed)
	w := httptest.NewRecorder()
	rig.st.Handler().ServeHTTP(w, r)
	if w.Code == http.StatusNotModified || w.Header().Get("ETag") == closed {
		t.Fatal("the page that said sign-ups were closed is still the one a cache serves")
	}
}

func TestTheSignUpIsAToolForAVisitorsAgentAndTheVisitorSendsIt(t *testing.T) {
	rig := newsletterSite(t)
	body := getPage(rig.st, "/news").Body.String()
	form := regexp.MustCompile(`<form class="newsletter-form"[^>]*>`).FindString(body)
	if !strings.Contains(form, `toolname="subscribe-newsletter"`) || strings.Contains(form, "toolautosubmit") {
		t.Fatalf("the sign-up form as a tool: %s", form)
	}
	if !regexp.MustCompile(`name="website_url"[^>]*readonly|readonly[^>]*name="website_url"`).MatchString(body) {
		t.Fatal("the honeypot is offered to the agent to fill")
	}
}

// The whole site mails a bounded number of links an hour, however many
// addresses are typed in from however many places.
func TestTheSiteMailsABoundedNumberOfLinksAnHour(t *testing.T) {
	n := &Newsletter{}
	at := time.Date(2026, 11, 2, 8, 0, 0, 0, time.UTC)
	for i := 0; i < linksPerHour; i++ {
		if !n.mayMail(at) {
			t.Fatalf("refused link %d", i)
		}
	}
	if n.mayMail(at.Add(time.Minute)) {
		t.Fatal("one more link than the hour allows")
	}
	if !n.mayMail(at.Add(time.Hour)) {
		t.Fatal("the next hour mails nothing")
	}
}
