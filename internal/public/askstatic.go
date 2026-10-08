// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/assistant"
)

// A chatbot on a static copy of the site.
//
// # The problem
//
// `ipfs write` and `export` make a copy of the site that a static host can
// serve, and the chatbot was the one public feature with no static form: its
// page posts a question to this server, and a static host has nothing to
// post to. So the copy simply had no chatbot, and the demonstration site —
// which is a static copy — could not show one.
//
// # The answer
//
// An assistant that declares static gets two more addresses:
//
//	/ask/NAME/knowledge.json   the passages it answers from, with their
//	                           term counts, from published pages only
//	/ask/NAME?copy=static      the conversation page, carrying a script that
//	                           ranks and quotes in the visitor's browser
//
// and a static copy carries both, at ask/NAME/knowledge.json and
// ask/NAME/index.html. The live site goes on answering on the server; these
// addresses exist on it so the copy is made the way every other page in it
// is, by asking this handler.
//
// # Why by hash, and why inline
//
// The script is one constant, so its hash is known when the program is
// built, and a policy naming that hash permits exactly these bytes. A nonce
// would mean nothing on a static copy, where the page and its nonce are the
// same file for everybody. Inline, because a hash naming an external file
// needs integrity metadata that not every browser honours yet, and the
// alternative — script-src 'self' — would let any script file the copy
// happened to carry run on this page.

//go:embed askstatic.js
var askStaticJS string

// askStaticHash is the script's source expression for script-src.
var askStaticHash = func() string {
	sum := sha256.Sum256([]byte(askStaticJS))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}()

// staticCopy is the query that asks for the page a static copy carries.
const staticCopy = "static"

// askKnowledge serves what the browser answers from.
func (st *Site) askKnowledge(w http.ResponseWriter, r *http.Request, a assistant.Assistant) {
	if !a.Static {
		st.notFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET")
		http.Error(w, "use GET", http.StatusMethodNotAllowed)
		return
	}
	idx, err := st.assistantIndex(a)
	if err != nil {
		http.Error(w, "the site could not be read", http.StatusInternalServerError)
		return
	}
	k := assistant.Browser(a, idx.Passages, st.passageHref)
	body, err := json.Marshal(k)
	if err != nil {
		http.Error(w, "the site could not be read", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	// Revalidated rather than kept: it changes whenever a page it reads is
	// published.
	h.Set("Cache-Control", "no-cache")
	_, _ = w.Write(body)
}

// passageHref is where a citation of a page passage points.
func (st *Site) passageHref(p assistant.Passage) string {
	if p.Doc == "" && p.Page == st.indexName() {
		return "/"
	}
	return p.Link()
}

// renderAskStatic draws the page a static copy carries.
func (st *Site) renderAskStatic(w http.ResponseWriter, v askView) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Content-Type-Options", "nosniff")
	allowScript(h, askStaticHash)
	w.WriteHeader(http.StatusOK)
	_ = askStaticTemplate.Execute(w, map[string]any{
		"Disclosure": Disclosure, "V": v,
		// The constant, as JS rather than as text, so html/template places
		// the bytes the hash was taken over. Never anything from a request.
		"Script": template.JS(askStaticJS),
		// Built from an id checked against the library; see icon.go.
		"Icon": template.HTML(st.iconLink()),
	})
}

// staticAssistants are the assistants a static copy carries, by name.
func (st *Site) staticAssistants() []string {
	if st.Assistants == nil || st.Assistants.Set == nil {
		return nil
	}
	set, err := st.Assistants.Set()
	if err != nil || set == nil {
		return nil
	}
	var out []string
	for _, a := range set.Assistants {
		if a.Public && a.Static {
			out = append(out, a.Name)
		}
	}
	sort.Strings(out)
	return out
}

// askStaticTemplate is the conversation page of a static copy. The answers
// are drawn by the script, into the log, as the visitor asks.
var askStaticTemplate = template.Must(template.New("ask-static").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.V.Assistant.Title}}</title>
<meta name="robots" content="noindex">
<link rel="stylesheet" href="/site.css">
<link rel="stylesheet" href="/ask.css">
{{.Icon}}</head>
<body class="qz-ask qz-static"><main>
<p class="qz-home"><a href="/">Back to the site</a></p>
<h1>{{.V.Assistant.Title}}</h1>
<p class="qz-greeting">{{.V.Greeting}}</p>
<div id="qz-log" class="qz-log"></div>
<p id="qz-status" class="qz-status" role="status"></p>
<form id="qz-form" method="get" action="/ask/{{.V.Assistant.Name}}/" class="qz-ask-form" aria-busy="true">
  <label for="q">Your question</label>
  <textarea id="q" name="q" rows="2" maxlength="1000" required autofocus></textarea>
  <button type="submit">Ask</button>
</form>
<noscript><p class="qz-problem">This copy of the site answers in your
  browser, which needs JavaScript. Every answer it would give is on the
  site's own pages.</p></noscript>
<p class="qz-small">{{.Disclosure}} It answers from this site's pages, in your
  browser, and links every answer to the page it came from. Nothing you ask
  is stored or sent anywhere.</p>
</main>
<script>{{.Script}}</script>
</body></html>`))

// allowScript lets this response run the scripts the source expression
// names, and fetch from this site, whatever the site's policy says about
// scripts elsewhere.
//
// It rewrites only the two directives it needs, in whichever policy header
// the site sends, so every other response keeps the site's own policy.
func allowScript(h http.Header, source string) {
	script := "script-src " + source
	for _, name := range []string{"Content-Security-Policy",
		"Content-Security-Policy-Report-Only"} {
		cur := h.Get(name)
		if cur == "" {
			continue
		}
		// A page with two of this site's scripts allows both: a hash added
		// to a list of hashes joins it, where one added to anything else
		// replaces it, so 'self' or 'none' never survives beside a hash.
		if m := reScriptSrc.FindString(cur); m != "" {
			if strings.Contains(m, "'sha256-") {
				if !strings.Contains(m, source) {
					cur = reScriptSrc.ReplaceAllString(cur, m+" "+source)
				}
			} else {
				cur = reScriptSrc.ReplaceAllString(cur, script)
			}
		} else {
			cur += "; " + script
		}
		connect := reConnectSrc.FindString(cur)
		switch {
		case connect == "":
			cur += "; connect-src 'self'"
		case strings.Contains(connect, "'none'"):
			cur = reConnectSrc.ReplaceAllString(cur, "connect-src 'self'")
		case !slices.Contains(strings.Fields(connect), "'self'"):
			cur = reConnectSrc.ReplaceAllString(cur, connect+" 'self'")
		}
		h.Set(name, cur)
	}
}
