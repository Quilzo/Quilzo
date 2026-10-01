// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/handoff"
	"github.com/quilzo/quilzo/internal/throttle"
)

// Talking to a person.
//
// An assistant that declared Handoff offers, under each answer, to pass the
// conversation to somebody at the business. Choosing it is the visitor's
// decision and the first point at which anything they say is kept: the offer
// says so, and how long for, before they send.
//
// The visitor is then sent to their conversation's own address, which
// carries the secret that reaches it. That address is the only way back, so
// the page tells them to keep it, and everything about the page is set so
// it does not leak: no referrer, no caching, no indexing.
//
// The page works with no script: a person's reply appears when the page is
// loaded again, and there is a button for that. With the small first-party
// script the site serves at /ask-live.js, replies appear on their own. The
// script writes text with textContent and never markup, so a reply cannot
// become part of the page.

// handoffRoute answers /ask/NAME/handoff and /ask/NAME/c/SECRET. It reports
// whether the path was one of them.
func (st *Site) handoffRoute(w http.ResponseWriter, r *http.Request,
	a assistant.Assistant, rest string) bool {

	switch {
	case rest == "handoff":
		st.handoffOpen(w, r, a)
		return true
	case strings.HasPrefix(rest, "c/"):
		st.handoffConversation(w, r, a, strings.TrimPrefix(rest, "c/"))
		return true
	}
	return false
}

func (st *Site) handoffStore(a assistant.Assistant) (handoff.Store, bool) {
	if !a.Handoff || st.Assistants == nil || st.Assistants.Handoff == nil {
		return handoff.Store{}, false
	}
	return *st.Assistants.Handoff, true
}

// handoffAllowed spends from the same allowance as asking a question, so
// talking to a person is not a way round the rate limit.
func (st *Site) handoffAllowed(w http.ResponseWriter, r *http.Request) bool {
	l := st.Assistants.Limit
	if l == nil {
		return true
	}
	sub := throttle.Subject{Source: sourceOf(r)}
	if d := l.Check(sub); !d.Allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(d.RetryAfter.Seconds())+1))
		http.Error(w, "You have sent a lot in a short time. Please wait a "+
			"moment and try again.", http.StatusTooManyRequests)
		return false
	}
	l.Spend(sub)
	return true
}

func (st *Site) handoffOpen(w http.ResponseWriter, r *http.Request, a assistant.Assistant) {
	store, ok := st.handoffStore(a)
	if !ok {
		st.notFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "use the form", http.StatusMethodNotAllowed)
		return
	}
	if !st.handoffAllowed(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "that could not be read", http.StatusBadRequest)
		return
	}
	secret, id, err := handoff.NewSecret()
	if err != nil {
		http.Error(w, "a conversation could not be started", http.StatusInternalServerError)
		return
	}
	if _, err := store.Open(a.Name, id, r.PostFormValue("q"),
		r.PostFormValue("message"), time.Now()); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if st.Assistants.HandoffEvent != nil {
		st.Assistants.HandoffEvent("handoff.open", a.Name, id, sourceOf(r))
	}
	to := "/ask/" + a.Name + "/c/" + secret
	if r.PostFormValue("embed") == "1" {
		to += "?embed=1"
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// conversationView is what the visitor's page shows.
type conversationView struct {
	Assistant assistant.Assistant
	Self      string
	Messages  []handoff.Message
	Closed    bool
	Embedded  bool
	Problem   string
	Days      int
	Count     int
	// Nonce lets this page's one script run under a policy that otherwise
	// runs none.
	Nonce string
}

func (st *Site) handoffConversation(w http.ResponseWriter, r *http.Request,
	a assistant.Assistant, secret string) {

	store, ok := st.handoffStore(a)
	// A secret is URL-safe base64 of 24 bytes; anything else is not one, and
	// is answered exactly as a wrong secret is.
	if !ok || len(secret) != 32 || strings.Trim(secret,
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
		st.notFound(w, r)
		return
	}
	id := handoff.IDFor(secret)
	c, err := store.Get(a.Name, id)
	if err != nil {
		st.notFound(w, r)
		return
	}
	h := w.Header()
	// The address is the key. It must not travel to another site in a
	// Referer, sit in a cache, or be indexed.
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("X-Content-Type-Options", "nosniff")

	self := "/ask/" + a.Name + "/c/" + secret
	embedded := r.URL.Query().Get("embed") == "1"
	view := conversationView{Assistant: a, Self: self, Embedded: embedded,
		Days: a.Keep()}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if r.URL.Query().Get("format") == "json" {
			after, _ := strconv.Atoi(r.URL.Query().Get("after"))
			writeConversationJSON(w, c, after)
			return
		}
	case http.MethodPost:
		if !st.handoffAllowed(w, r) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "that could not be read", http.StatusBadRequest)
			return
		}
		embedded = r.PostFormValue("embed") == "1"
		back := self
		if embedded {
			back += "?embed=1"
		}
		if r.PostFormValue("end") != "" {
			if err := store.Close(a.Name, id, "", time.Now()); err != nil {
				st.notFound(w, r)
				return
			}
			if st.Assistants.HandoffEvent != nil {
				st.Assistants.HandoffEvent("handoff.close", a.Name, id, sourceOf(r))
			}
			http.Redirect(w, r, back, http.StatusSeeOther)
			return
		}
		if _, err := store.Say(a.Name, id, handoff.Visitor, "",
			r.PostFormValue("message"), time.Now()); err != nil {
			view.Problem = err.Error()
			break
		}
		if st.Assistants.HandoffEvent != nil {
			st.Assistants.HandoffEvent("handoff.say", a.Name, id, sourceOf(r))
		}
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "use GET or POST", http.StatusMethodNotAllowed)
		return
	}
	if c2, err := store.Get(a.Name, id); err == nil {
		c = c2
	}
	view.Messages, view.Closed, view.Count = c.Messages, c.Closed, len(c.Messages)
	view.Embedded = embedded
	h.Set("Content-Type", "text/html; charset=utf-8")
	allowFraming(h, a.Embed)
	if n, err := newNonce(); err == nil {
		view.Nonce = n
		allowLiveScript(h, n)
	}
	status := http.StatusOK
	if view.Problem != "" {
		status = http.StatusUnprocessableEntity
	}
	w.WriteHeader(status)
	_ = conversationTemplate.Execute(w, view)
}

// writeConversationJSON is what the page's script asks for: what is new
// since the n-th message. Who answered is not included; a visitor is
// answered by the business, and the name of the person at it is theirs.
func writeConversationJSON(w http.ResponseWriter, c handoff.Conversation, after int) {
	type msg struct {
		N    int    `json:"n"`
		From string `json:"from"`
		Text string `json:"text"`
		At   string `json:"at"`
	}
	out := struct {
		Messages []msg `json:"messages"`
		Closed   bool  `json:"closed"`
	}{Messages: []msg{}, Closed: c.Closed}
	for _, m := range c.After(after) {
		out.Messages = append(out.Messages, msg{N: m.N, From: m.From,
			Text: m.Text, At: m.At.Format(time.RFC3339)})
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(out)
}

// handoffOffer is the form under an answer.
func handoffAction(a assistant.Assistant) string {
	return "/ask/" + url.PathEscape(a.Name) + "/handoff"
}

var conversationTemplate = template.Must(template.New("conversation").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{{.Assistant.Title}}: talking to a person</title>
<link rel="stylesheet" href="/site.css">
<link rel="stylesheet" href="/ask.css">
{{if .Nonce}}<script src="/ask-live.js" nonce="{{.Nonce}}" defer></script>{{end}}
</head>
<body class="qz-ask{{if .Embedded}} qz-embed{{end}}"><main>
{{if .Embedded}}<p class="qz-embed-title">{{.Assistant.Title}}</p>{{else}}<h1>{{.Assistant.Title}}</h1>{{end}}
<p class="qz-small"><strong>Keep this page's address</strong> to come back to
  this conversation; it is the only way back. It is kept for {{.Days}} days
  after it last moves, then deleted.</p>
<ol class="qz-thread" data-live="{{.Self}}?format=json" data-after="{{.Count}}" aria-live="polite" aria-label="Conversation">
{{range .Messages}}<li class="qz-msg qz-{{.From}}"><span class="qz-who">{{if eq .From "visitor"}}You{{else}}{{$.Assistant.Title}} team{{end}}</span><span class="qz-text">{{.Text}}</span></li>
{{end}}</ol>
{{if .Closed}}<p class="qz-greeting" data-ended>This conversation has ended.</p>
{{else}}
<p class="qz-waiting qz-small" data-waiting>Somebody will reply here. You can leave this page and come back to it.</p>
{{if .Problem}}<p class="qz-problem" role="alert">{{.Problem}}</p>{{end}}
<form method="post" action="{{.Self}}" class="qz-ask-form">
  {{if .Embedded}}<input type="hidden" name="embed" value="1">{{end}}
  <label for="message">Add to the conversation</label>
  <textarea id="message" name="message" rows="3" maxlength="2000" required></textarea>
  <button type="submit">Send</button>
</form>
<p class="qz-actions"><a class="qz-button-quiet" href="{{.Self}}{{if .Embedded}}?embed=1{{end}}">Check for a reply</a></p>
<form method="post" action="{{.Self}}" class="qz-end">
  {{if .Embedded}}<input type="hidden" name="embed" value="1">{{end}}
  <button type="submit" name="end" value="1" class="qz-button-quiet">End this conversation</button>
</form>
{{end}}
</main></body></html>`))

// askLiveJS asks for new messages while the page is open and visible, and
// adds them as text. First-party, no dependencies, and nothing here can turn
// a message into markup: every value goes in through textContent.
const askLiveJS = `(function () {
  "use strict";
  var list = document.querySelector("[data-live]");
  if (!list || !window.fetch) return;
  var src = list.getAttribute("data-live");
  var after = parseInt(list.getAttribute("data-after"), 10) || 0;
  var team = (document.querySelector(".qz-embed-title, h1") || {}).textContent || "";
  var started = Date.now(), timer = null, ended = false;
  function add(m) {
    var li = document.createElement("li");
    li.className = "qz-msg qz-" + (m.from === "visitor" ? "visitor" : "person");
    var who = document.createElement("span");
    who.className = "qz-who";
    who.textContent = m.from === "visitor" ? "You" : team + " team";
    var text = document.createElement("span");
    text.className = "qz-text";
    text.textContent = m.text;
    li.appendChild(who);
    li.appendChild(text);
    list.appendChild(li);
  }
  function end() {
    ended = true;
    var w = document.querySelector("[data-waiting]");
    if (w) w.textContent = "This conversation has ended.";
    document.querySelectorAll("form textarea, form button").forEach(function (e) { e.disabled = true; });
  }
  function poll() {
    timer = null;
    if (ended || document.hidden) return;
    // Thirty minutes of waiting with the page open is long enough; after
    // that the button on the page still works.
    if (Date.now() - started > 30 * 60 * 1000) return;
    fetch(src + "&after=" + after, { credentials: "omit", cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d) return;
        (d.messages || []).forEach(function (m) {
          if (typeof m.n === "number" && m.n > after && typeof m.text === "string") {
            add(m);
            after = m.n;
          }
        });
        if (d.closed) end();
      })
      .catch(function () {})
      .then(function () { if (!ended) timer = setTimeout(poll, 5000); });
  }
  document.addEventListener("visibilitychange", function () {
    if (!document.hidden && !timer && !ended) poll();
  });
  timer = setTimeout(poll, 5000);
})();
`

func (st *Site) askLiveScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(askLiveJS))
}

// newNonce is a value for one response's script-src.
func newNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	// URL-safe, so the value is the same in the header and in the
	// attribute, where html/template would escape a "+" or a "/".
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

var (
	reScriptSrc  = regexp.MustCompile(`script-src[^;]*`)
	reConnectSrc = regexp.MustCompile(`connect-src[^;]*`)
)

// allowLiveScript lets the conversation page run its one script, and fetch
// from this site, whatever the site's policy says about scripts elsewhere.
//
// By nonce rather than by opening script-src to 'self': this response
// allows the script tag it carries and nothing else, so a site that runs no
// script anywhere still runs none on any other page, and none on this one
// that it did not write. Like allowFraming, it rewrites only the directives
// it needs, in whichever policy header the site sends.
func allowLiveScript(h http.Header, nonce string) {
	script := "script-src 'nonce-" + nonce + "'"
	for _, name := range []string{"Content-Security-Policy",
		"Content-Security-Policy-Report-Only"} {
		cur := h.Get(name)
		if cur == "" {
			continue
		}
		if reScriptSrc.MatchString(cur) {
			cur = reScriptSrc.ReplaceAllString(cur, script)
		} else {
			cur += "; " + script
		}
		switch {
		case !reConnectSrc.MatchString(cur):
			cur += "; connect-src 'self'"
		case strings.Contains(reConnectSrc.FindString(cur), "'none'"):
			cur = reConnectSrc.ReplaceAllString(cur, "connect-src 'self'")
		}
		h.Set(name, cur)
	}
}
