package admin

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html"
	"net/http"
	"sort"
	"strings"
)

// A playground for the content API, served from the admin.
//
// The thing it replaces is a developer with curl, a token pasted into a shell,
// and no idea what the response looks like until they get one. Every CMS that
// has a good one wins developers on it, and the reason they are usually bad is
// that they are built as a separate application against a documented API — so
// they drift, and the playground shows a version of the API that no longer
// exists.
//
// This one cannot drift, because it calls the same server the customer's code
// will call, through the same middleware, with the caller's own session. What
// it shows is what they will get, including the failures: a 428 because they
// forgot If-Match is a better lesson here than in production.
//
// The security note, because this is the first script this program has ever
// served.
//
// The admin's Content-Security-Policy is `default-src 'none'`, which blocks
// script entirely — that was a real property and giving it up for a
// convenience would be a bad trade. So the policy gains a nonce rather than a
// host: a fresh 128-bit value per response, in the header and on the one
// script tag, and nothing else executes. An injected script has no nonce, and
// cannot read this one because it never runs to look.
//
// The script itself is inline, small, has no build step, loads nothing, and
// uses no eval or innerHTML. Fetching a library would mean either a CDN in the
// policy — reopening what the nonce just closed — or vendoring a dependency
// this program does not have.

// nonce returns a fresh per-response value.
//
// Per response, never per process. A nonce reused across responses is a nonce
// an attacker can read from one page and use in an injection into another,
// which is the same as not having one.
func nonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}

// playground serves the API console.
func (s *Server) playground(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	n, err := nonce()
	if err != nil {
		http.Error(w, "no entropy", http.StatusInternalServerError)
		return
	}

	// The policy for this page only. Everything else in the admin keeps
	// default-src 'none' with no script at all.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data:; connect-src 'self'; "+
			"script-src 'nonce-"+n+"'; form-action 'self'; "+
			"frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	// The theme travels with the request, because this page builds its own
	// document instead of using the layout.
	//
	// That is the whole bug it had: every other screen renders through
	// layout.html, which puts data-theme on <html> from this cookie, and this
	// one wrote its own <html> and never read it. So the playground followed
	// the operating system while the rest of the admin followed the person —
	// press Dark in the header, walk into the API console, and it is still
	// light. A page that opts out of the layout has to opt back into
	// everything the layout was doing.
	fmt.Fprint(w, playgroundHTML(n, p.Name, themeOf(r), s.playgroundRoutes()))
}

// Route is one thing the playground can call.
type Route struct {
	Method  string
	Path    string
	Summary string
	// Body is a starting request body, for the methods that take one.
	Body string
	// Note explains a control the caller will meet, so the first 428 is
	// expected rather than confusing.
	Note string
}

// playgroundRoutes describes the API to the console.
//
// Written here rather than derived from the server's mux, and that is a
// deliberate limitation with a stated cost: a route added to the API and not
// added here is invisible in the playground. The alternative — reflecting over
// the mux — would produce paths with no summaries, no example bodies and no
// notes, which is a list of URLs rather than a thing that teaches anybody
// anything. A test keeps the two from diverging silently.
func (s *Server) playgroundRoutes() []Route {
	return []Route{
		{Method: "GET", Path: "/api/v1/pages",
			Summary: "every page you can see, paged"},
		{Method: "GET", Path: "/api/v1/pages?limit=2",
			Summary: "a page of results, with a next link"},
		{Method: "GET", Path: "/api/v1/pages/index",
			Summary: "one page, with its ETag",
			Note: "the ETag is the content hash, so If-None-Match answers " +
				"exactly the question it appears to ask"},
		{Method: "PUT", Path: "/api/v1/pages/index",
			Summary: "replace a page",
			Body:    "{\n  \"title\": \"Home\",\n  \"body\": \"Edited from the playground.\"\n}",
			Note: "this needs If-Match. Without it you get 428: a write with " +
				"no validator overwrites whatever is there now, including " +
				"somebody else's edit. Send * to create a page that does not " +
				"exist yet"},
	}
}

func playgroundHTML(nonce, who, theme string, routes []Route) string {
	var opts strings.Builder
	sorted := append([]Route(nil), routes...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Path < sorted[j].Path
	})
	for i, rt := range sorted {
		opts.WriteString(fmt.Sprintf(
			`<option value="%d" data-method="%s" data-path="%s" `+
				`data-body="%s" data-note="%s">%s %s — %s</option>`,
			i, html.EscapeString(rt.Method), html.EscapeString(rt.Path),
			html.EscapeString(rt.Body), html.EscapeString(rt.Note),
			html.EscapeString(rt.Method), html.EscapeString(rt.Path),
			html.EscapeString(rt.Summary)))
	}

	// Written the same way layout.html writes it: no attribute at all when the
	// person has not chosen, so the stylesheet's own `color-scheme: light dark`
	// follows the system.
	themeAttr := ""
	if theme != "" {
		themeAttr = ` data-theme="` + html.EscapeString(theme) + `"`
	}

	return `<!doctype html>
<html lang="en"` + themeAttr + `><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>API playground</title>
<link rel="stylesheet" href="/style.css">
<style>
  /* Native controls follow the theme. Without this the select's dropdown is
     drawn with the OS light palette and inherits a light text colour, which
     is white on white.
     Only the unchosen case is declared here; style.css turns data-theme into
     an explicit color-scheme, and repeating the two-value form after it would
     be a rule of equal weight taking the choice back. */
  :root:not([data-theme]) { color-scheme: light dark; }
  .pg { max-width: 60rem; margin: 0 auto; padding: 1.5rem; }
  .pg-row { display: flex; gap: .5rem; flex-wrap: wrap; margin: .75rem 0; }
  /* An explicit display beats the user-agent rule that makes [hidden] work,
     so the body field stayed on screen for every GET. Visible in a
     screenshot, invisible in a unit test: nothing asserts on layout. */
  .pg-row[hidden] { display: none; }
  /* Explicit surface and text, never inherit. Inheriting means the control
     takes the page's colour and the browser's own background, which is the
     pair that does not match. */
  .pg select, .pg input, .pg textarea, .pg button {
    font: inherit; padding: .5rem .6rem; border-radius: 8px;
    border: 1px solid var(--outline, #8a9199);
    background: var(--surface, Canvas); color: var(--on-surface, CanvasText); }
  .pg option { background: var(--surface, Canvas); color: var(--on-surface, CanvasText); }
  .pg button { cursor: pointer; font-weight: 600; }
  .pg select:focus-visible, .pg input:focus-visible,
  .pg textarea:focus-visible, .pg button:focus-visible {
    outline: 2px solid var(--primary, Highlight); outline-offset: 2px; }
  .pg select { flex: 1 1 22rem; }
  .pg input { flex: 1 1 14rem; }
  .pg textarea { width: 100%; min-height: 7rem; font-family: ui-monospace, monospace; }
  .pg pre { background: rgba(127,127,127,.10); padding: .9rem; border-radius: 10px;
    overflow-x: auto; font-family: ui-monospace, monospace; font-size: .85rem;
    white-space: pre-wrap; word-break: break-word; }
  .pg .status { font-weight: 600; }
  .pg .ok { color: #2e7d32 } .pg .warn { color: #b26a00 } .pg .err { color: #c62828 }
  .pg .note { font-size: .875rem; opacity: .8; margin: .4rem 0 0 }
  .pg .hint { font-size: .8125rem; opacity: .7 }
</style>
</head><body>
<main class="pg">
<p class="hint"><a href="/">&larr; back to quilzo</a></p>
<h1>API playground</h1>
<p class="hint">Signed in as ` + html.EscapeString(who) + `. Requests go to this
server, through the same middleware your own code will meet, using your session
&mdash; so what you see here is what you will get.</p>

<div class="pg-row">
  <select id="route" aria-label="Operation">` + opts.String() + `</select>
</div>
<div class="pg-row">
  <input id="path" spellcheck="false" aria-label="Request path">
  <input id="ifmatch" placeholder="If-Match (paste an ETag, or *)" spellcheck="false"
         aria-label="If-Match header">
</div>
<div class="pg-row" id="bodyrow" hidden>
  <textarea id="body" spellcheck="false" aria-label="Request body"></textarea>
</div>
<p class="note" id="note"></p>
<div class="pg-row">
  <button id="send" type="button">Send</button>
  <button id="curl" type="button">Copy as curl</button>
</div>

<h2>Response</h2>
<p class="status" id="status">&mdash;</p>
<pre id="headers"></pre>
<pre id="out"></pre>
</main>

<script nonce="` + nonce + `">
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var route = $("route"), path = $("path"), body = $("body"),
      bodyrow = $("bodyrow"), note = $("note"), ifmatch = $("ifmatch");

  function selected() { return route.options[route.selectedIndex]; }

  function sync() {
    var o = selected();
    path.value = o.getAttribute("data-path");
    var b = o.getAttribute("data-body");
    body.value = b;
    bodyrow.hidden = b === "";
    note.textContent = o.getAttribute("data-note");
  }
  route.addEventListener("change", sync);
  sync();

  function method() { return selected().getAttribute("data-method"); }

  function show(status, statusText, headers, text) {
    var s = $("status");
    s.textContent = status + " " + statusText;
    s.className = "status " + (status < 300 ? "ok" : status < 500 ? "warn" : "err");
    $("headers").textContent = headers;
    // Assigned as text, never as markup: the response is content somebody
    // wrote, and this page is inside the admin's origin.
    $("out").textContent = text;
  }

  $("send").addEventListener("click", function () {
    var opts = { method: method(), headers: {}, credentials: "same-origin" };
    if (ifmatch.value) { opts.headers["If-Match"] = ifmatch.value; }
    if (!bodyrow.hidden) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = body.value;
    }
    show(0, "sending…", "", "");
    fetch(path.value, opts).then(function (res) {
      var hs = [];
      res.headers.forEach(function (v, k) { hs.push(k + ": " + v); });
      hs.sort();
      // The ETag is offered back for the next request, because the whole
      // read-then-write cycle is the thing people get wrong and copying a
      // hash by hand is where they give up.
      var etag = res.headers.get("ETag");
      if (etag) { ifmatch.value = etag; }
      return res.text().then(function (t) {
        var pretty = t;
        try { pretty = JSON.stringify(JSON.parse(t), null, 2); } catch (e) {}
        show(res.status, res.statusText, hs.join("\n"), pretty);
      });
    }).catch(function (e) {
      show(0, "request failed", "", String(e));
    });
  });

  $("curl").addEventListener("click", function () {
    var parts = ["curl -X " + method(),
                 "-H 'Authorization: Bearer $QUILZO_TOKEN'"];
    if (ifmatch.value) { parts.push("-H 'If-Match: " + ifmatch.value + "'"); }
    if (!bodyrow.hidden) {
      parts.push("-H 'Content-Type: application/json'");
      parts.push("-d '" + body.value.replace(/'/g, "'\\''") + "'");
    }
    parts.push("'" + location.origin + path.value + "'");
    var cmd = parts.join(" \\\n  ");
    // The session cookie is deliberately not translated into the command.
    // Emitting a working credential into somebody's clipboard, and from there
    // into a terminal history and a support ticket, is how tokens leak.
    $("out").textContent = cmd;
    $("status").textContent = "copied below — set QUILZO_TOKEN yourself";
    $("status").className = "status";
  });
}());
</script>
</body></html>`
}
