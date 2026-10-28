// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/mail"
	"github.com/quilzo/quilzo/internal/newsletter"
	"github.com/quilzo/quilzo/internal/throttle"
)

// A newsletter, on the public site.
//
// A page carries a newsletter section: what the letter is and how often,
// and a field for an address. Signing up mails that address one link; the
// page it opens has a button, and pressing it is the yes. Every issue
// carries a link to leave, and the List-Unsubscribe headers a mail app
// turns into its own button, which ends the subscription with one POST
// and no page at all (RFC 8058).
//
// What this process does with the list is write to it — sign up, confirm,
// leave — and never read an address back (see internal/newsletter). The
// address it mails a link to is the one the visitor typed, in the request
// in front of it.

// Newsletter gives the site its mailing list. Nil means /newsletter/
// answers 404 and a newsletter section says sign-ups are not taken.
type Newsletter struct {
	List *newsletter.List
	// Ready says whether a link can be mailed now: mail is set up and the
	// site knows its own address. Asked per request, so setting up mail
	// opens sign-ups without a restart.
	Ready func() bool
	// Mail sends one message. Called in the background.
	Mail func(mail.Message) error
	// Limit bounds sign-ups from one address.
	Limit *throttle.Limiter
	// Audit records what happened, never to which address.
	Audit func(action, source string, ok bool)
	// Notify tells another system somebody subscribed or left.
	Notify func(event string)
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	mu     sync.Mutex
	hour   time.Time
	mailed int
}

// linksPerHour bounds the links the whole site mails in an hour. One
// address is mailed at most once an hour already; this is the bound on
// many addresses typed in from many places, which is how a sign-up form is
// turned against the relay's reputation and the site's.
const linksPerHour = 200

func (st *Site) newsletterOn() bool { return st.Newsletter != nil && st.Newsletter.List != nil }

func (st *Site) newsletterReady() bool {
	return st.newsletterOn() && st.BaseURL != "" && (st.Newsletter.Ready == nil || st.Newsletter.Ready())
}

func (st *Site) newsletterNow() time.Time {
	if st.newsletterOn() && st.Newsletter.Now != nil {
		return st.Newsletter.Now()
	}
	return time.Now()
}

func (n *Newsletter) audit(action, source string, ok bool) {
	if n.Audit != nil {
		n.Audit(action, source, ok)
	}
}

// mayMail spends one of the hour's links.
func (n *Newsletter) mayMail(now time.Time) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if now.Sub(n.hour) >= time.Hour {
		n.hour, n.mailed = now, 0
	}
	if n.mailed >= linksPerHour {
		return false
	}
	n.mailed++
	return true
}

// newsletterMessages are what a page can be made to say after a sign-up,
// by code, so nothing a request sent is written back.
var newsletterMessages = map[string]string{
	"sent": "Thank you. If that address is not subscribed yet, a link to confirm it is on its way: " +
		"nothing is sent until you press the button on the page it opens.",
}

var newsletterProblems = map[string]string{
	"address": "That does not look like an email address. Check it and try again.",
	"closed":  "Sign-ups are not being taken just now. Please try again later.",
	"refused": "That sign-up was not accepted.",
}

// newsletterData is what a newsletter section on a page shows.
func (st *Site) newsletterData(page string, args map[string]string) map[string]any {
	if !st.newsletterReady() {
		return map[string]any{"closed": true}
	}
	out := map[string]any{"open": true, "page": page}
	if msg, ok := newsletterMessages[args["newsletter"]]; ok {
		out["done"] = msg
	}
	if msg, ok := newsletterProblems[args["newsletter_error"]]; ok {
		out["problem"] = msg
	}
	return out
}

// newsletterSection is a page's newsletter section, when it has one.
func newsletterSection(body any) (map[string]any, bool) {
	m, ok := body.(map[string]any)
	if !ok {
		return nil, false
	}
	sections, _ := m["sections"].([]any)
	for _, s := range sections {
		sec, _ := s.(map[string]any)
		if n, ok := sec["newsletter"].(map[string]any); ok {
			return n, true
		}
	}
	return nil, false
}

// newsletterPage is a published page that signs visitors up, and the
// section that does.
func (st *Site) newsletterPage(name string) (string, map[string]any, bool) {
	pages, _, err := st.pages()
	if err != nil {
		return "", nil, false
	}
	sec, ok := newsletterSection(pages[name])
	if !ok {
		return "", nil, false
	}
	return st.pagePath(name), sec, true
}

// consentWords is what an address agreed to, in the words the section
// showed it.
func (st *Site) consentWords(sec map[string]any, page string) string {
	words := []string{}
	for _, k := range []string{"title", "what"} {
		if s, _ := sec[k].(string); strings.TrimSpace(s) != "" {
			words = append(words, strings.TrimSpace(s))
		}
	}
	if len(words) == 0 {
		words = append(words, st.siteLabel()+"'s newsletter")
	}
	return strings.Join(words, ": ") + " (signed up on " + st.pagePath(page) + ")"
}

// newsletterSubscribe signs an address up: POST /newsletter/subscribe with
// the page, the address, and a form's honeypot and stamp.
func (st *Site) newsletterSubscribe(w http.ResponseWriter, r *http.Request) {
	if !st.newsletterOn() {
		st.notFound(w, r)
		return
	}
	n := st.Newsletter
	if _, until, off := st.shielded("newsletter"); off {
		st.resting(w, r, "Signing up", until)
		return
	}
	source := sourceOf(r)
	if n.Limit != nil {
		if d := n.Limit.Check(throttle.Subject{Source: source}); !d.Allowed {
			w.Header().Set("Retry-After", fmt.Sprint(max(1, int(d.RetryAfter.Seconds()))))
			http.Error(w, "too many sign-ups from here, try again shortly", http.StatusTooManyRequests)
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "that sign-up could not be read", http.StatusBadRequest)
		return
	}
	page := r.PostFormValue("page")
	path, sec, ok := st.newsletterPage(page)
	if !ok {
		st.notFound(w, r)
		return
	}
	if n.Limit != nil {
		n.Limit.Spend(throttle.Subject{Source: source})
	}
	back := func(q url.Values) { http.Redirect(w, r, path+"?"+q.Encode()+"#newsletter", http.StatusSeeOther) }
	fail := func(code string) {
		n.audit("newsletter.signup", source, false)
		back(url.Values{"newsletter_error": {code}})
	}
	now := st.newsletterNow()
	// The two checks a form makes: a field nobody sees, and a page read by
	// a person for at least two seconds. No upper bound on the page's age:
	// a page with a sign-up in its footer is cached, and an old one is
	// still somebody's page.
	if strings.TrimSpace(r.PostFormValue(form.Honeypot)) != "" {
		st.signal(FormSpam, "newsletter", r)
		fail("refused")
		return
	}
	started, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue(form.StampField)), 10, 64)
	if err != nil || now.Unix()-started < form.MinFillSeconds {
		st.signal(FormSpam, "newsletter", r)
		fail("refused")
		return
	}
	if !st.newsletterReady() {
		fail("closed")
		return
	}
	s, outcome, err := n.List.SignUp(newsletter.Subscriber{Email: r.PostFormValue("email"), Source: "web",
		Consent: st.consentWords(sec, page), Page: page}, now)
	switch {
	case errors.Is(err, newsletter.ErrAddress):
		fail("address")
		return
	case err != nil:
		http.Error(w, "that sign-up could not be kept", http.StatusInternalServerError)
		return
	}
	if outcome == newsletter.Mail {
		if n.mayMail(now) {
			go st.mailConfirm(s)
		} else {
			// Not sent, so the address may ask again later rather than
			// waiting an hour for a link that is not coming.
			n.List.Unsent(s.ID, now)
			n.audit("newsletter.link-held", source, false)
		}
	}
	n.audit("newsletter.signup", source, true)
	st.convert(r, "newsletter")
	back(url.Values{"newsletter": {"sent"}})
}

// newsletterLink is the address of a confirm or leave page for an id.
func (st *Site) newsletterLink(purpose, id string) string {
	return strings.TrimSuffix(st.BaseURL, "/") + "/newsletter/" + purpose + "?" +
		url.Values{"s": {id}, "t": {st.Newsletter.List.Token(purpose, id)}}.Encode()
}

// mailConfirm mails the one link that asks an address to say yes.
func (st *Site) mailConfirm(s newsletter.Subscriber) {
	n := st.Newsletter
	if n.Mail == nil {
		return
	}
	site := st.siteLabel()
	body := "Somebody, most likely you, asked for " + site + "'s newsletter to be sent to this address.\n\n" +
		"To say yes, open this link and press the button on the page:\n" +
		st.newsletterLink(newsletter.ForConfirm, s.ID) + "\n\n" +
		"If it was not you, there is nothing to do: nothing more is sent, and the address is forgotten in a week.\n"
	err := n.Mail(mail.Message{To: s.Email, FromName: site, Subject: "Confirm your subscription to " + site,
		Body: body})
	if err != nil {
		n.List.Unsent(s.ID, st.newsletterNow())
		n.audit("newsletter.link-failed", "", false)
		return
	}
	n.audit("newsletter.link-sent", "", true)
}

// newsletterView is the page a link opens.
type newsletterView struct {
	Site, Title, Lead, Action, Button, Note string
	Done, Problem                           bool
}

// readLink is the id and token a confirm or leave request carries: in the
// address, where a mail put them, or in a form posted from the page.
func readLink(r *http.Request) (string, string) {
	q := r.URL.Query()
	id, token := q.Get("s"), q.Get("t")
	if id == "" {
		id, token = r.PostFormValue("s"), r.PostFormValue("t")
	}
	return id, token
}

// newsletterConfirm is GET and POST /newsletter/confirm: a page with a
// button, and the button.
func (st *Site) newsletterConfirm(w http.ResponseWriter, r *http.Request) {
	if !st.newsletterOn() {
		st.notFound(w, r)
		return
	}
	n := st.Newsletter
	site := st.siteLabel()
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		_ = r.ParseForm()
	}
	id, token := readLink(r)
	if !n.List.Check(newsletter.ForConfirm, id, token) || (!n.List.Waiting(id) && n.List.Left(id)) {
		st.newsletterPageOut(w, http.StatusNotFound, newsletterView{Site: site, Problem: true,
			Title: "This link no longer works",
			Lead:  "It may be incomplete, or more than a week old. Sign up again on the site to get a new one."})
		return
	}
	waiting := n.List.Waiting(id)
	if r.Method != http.MethodPost {
		if !waiting {
			st.newsletterGone(w, site, id)
			return
		}
		st.newsletterPageOut(w, http.StatusOK, newsletterView{Site: site,
			Title:  "Get " + site + "'s newsletter",
			Lead:   "Press the button to say yes. Until you do, nothing is sent to this address.",
			Action: "/newsletter/confirm?" + url.Values{"s": {id}, "t": {token}}.Encode(), Button: "Yes, send it to me"})
		return
	}
	err := n.List.Confirm(id, token, st.newsletterNow())
	if err != nil {
		st.newsletterGone(w, site, id)
		return
	}
	if waiting {
		n.audit("newsletter.confirmed", sourceOf(r), true)
		if n.Notify != nil {
			n.Notify("subscribed")
		}
	}
	st.newsletterPageOut(w, http.StatusOK, newsletterView{Site: site, Done: true,
		Title: "You are subscribed",
		Lead:  "The next issue of " + site + "'s newsletter will come to this address.",
		Note:  "Every issue has a link to stop it, and your mail app's unsubscribe button works too."})
}

// newsletterGone answers a confirm link whose address is confirmed, or is
// no longer on the list.
func (st *Site) newsletterGone(w http.ResponseWriter, site, id string) {
	if st.Newsletter.List.Has(id) {
		st.newsletterPageOut(w, http.StatusOK, newsletterView{Site: site, Done: true,
			Title: "You are subscribed", Lead: "This address already gets " + site + "'s newsletter."})
		return
	}
	st.newsletterPageOut(w, http.StatusNotFound, newsletterView{Site: site, Problem: true,
		Title: "This link no longer works",
		Lead:  "It may be more than a week old. Sign up again on the site to get a new one."})
}

// newsletterLeave is GET and POST /newsletter/leave: a page with a button
// for a person, and the one-click POST a mail app makes for them, which is
// answered with a plain 200 and never a redirect (RFC 8058).
func (st *Site) newsletterLeave(w http.ResponseWriter, r *http.Request) {
	if !st.newsletterOn() {
		st.notFound(w, r)
		return
	}
	n := st.Newsletter
	site := st.siteLabel()
	oneClick := false
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
			_ = r.ParseMultipartForm(8 << 10)
		} else {
			_ = r.ParseForm()
		}
		oneClick = r.PostFormValue("List-Unsubscribe") == "One-Click"
	}
	id, token := readLink(r)
	if !n.List.Check(newsletter.ForLeave, id, token) {
		if oneClick {
			http.Error(w, "that unsubscribe link is not whole", http.StatusNotFound)
			return
		}
		st.newsletterPageOut(w, http.StatusNotFound, newsletterView{Site: site, Problem: true,
			Title: "This link is not whole",
			Lead:  "Open the link from the bottom of a newsletter again, or use your mail app's unsubscribe button."})
		return
	}
	if r.Method != http.MethodPost {
		st.newsletterPageOut(w, http.StatusOK, newsletterView{Site: site,
			Title:  "Stop getting " + site + "'s newsletter",
			Lead:   "Press the button and this address is taken off the list and deleted.",
			Action: "/newsletter/leave?" + url.Values{"s": {id}, "t": {token}}.Encode(), Button: "Stop sending it"})
		return
	}
	how := "page"
	if oneClick {
		how = "one-click"
	}
	was, err := n.List.Leave(id, token, how, st.newsletterNow())
	if err != nil {
		http.Error(w, "that could not be done just now; please try again", http.StatusInternalServerError)
		return
	}
	if was {
		n.audit("newsletter.left", how, true)
		if n.Notify != nil {
			n.Notify("unsubscribed")
		}
	}
	if oneClick {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("unsubscribed\n"))
		return
	}
	st.newsletterPageOut(w, http.StatusOK, newsletterView{Site: site, Done: true,
		Title: "You will get no more",
		Lead:  "This address is off " + site + "'s list, and deleted from it. Signing up again on the site is the way back."})
}

func (st *Site) newsletterPageOut(w http.ResponseWriter, status int, v newsletterView) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Robots-Tag", "noindex")
	// The address carries the link's token: it goes nowhere else.
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	_ = newsletterTemplate.Execute(w, map[string]any{"V": v, "Icon": template.HTML(st.iconLink())})
}

var newsletterTemplate = template.Must(template.New("newsletter").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.V.Title}} — {{.V.Site}}</title>
<meta name="robots" content="noindex">
<link rel="stylesheet" href="/site.css">
<link rel="stylesheet" href="/ask.css">
{{.Icon}}</head>
<body class="qz-ask qz-account"><main>
<p class="qz-home"><a href="/">{{.V.Site}}</a></p>
<h1>{{.V.Title}}</h1>
{{if .V.Problem}}<p class="qz-problem" role="alert">{{.V.Lead}}</p>{{else if .V.Done}}<p class="qz-notice" role="status">{{.V.Lead}}</p>{{end}}
{{if .V.Action}}<section class="qz-turn" aria-labelledby="nl-do">
  <p id="nl-do">{{.V.Lead}}</p>
  <form method="post" action="{{.V.Action}}"><p><button type="submit" class="qz-button">{{.V.Button}}</button></p></form>
</section>{{end}}
{{if .V.Note}}<p class="qz-small">{{.V.Note}}</p>{{end}}
<p class="qz-small"><a href="/">Back to {{.V.Site}}</a></p>
</main></body></html>
`))

// newsletterTool is the sign-up form as a tool a visitor's browser agent
// can fill in (WebMCP): the agent fills in the address, and the visitor
// signs up, and then says yes from their own inbox.
func (st *Site) newsletterTool() (toolSpec, bool) {
	if !st.newsletterReady() {
		return toolSpec{}, false
	}
	return toolSpec{name: "subscribe-newsletter", trap: form.Honeypot,
		description: "Sign up for " + st.siteLabel() + "'s newsletter. The visitor sends the form, and nothing is " +
			"mailed to them until they confirm from the link sent to the address.",
		params: map[string]string{"email": "The visitor's email address. Required"}}, true
}
