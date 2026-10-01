// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"html/template"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/handoff"
	"github.com/quilzo/quilzo/internal/throttle"
	"github.com/quilzo/quilzo/internal/tmpl"
)

// A site's assistants, served to its visitors.
//
// /ask/NAME is a page with a question box, and a question posted to it gets
// an answer built from the published site, checked sentence by sentence
// against what it cites — see internal/assistant. No script: the policy on
// this server is script-src 'none', so the conversation is forms and pages,
// which also means it works for everybody, on every browser, with a screen
// reader and with JavaScript switched off.
//
// What is kept: nothing. The question and the answer are not stored, logged
// or sent anywhere but the model, when the assistant uses one. The audit
// records that a question was asked and whether it was answered, which is
// what an owner needs to see usage and nothing about who asked what.
//
// What it can do: offer, never act. A link action is a link. A form action
// is the site's own form, filled in with what the conversation established,
// which the visitor reads, corrects and submits themselves — through the
// form's own validation, honeypot, timing check, rate limit and retention.
// The assistant adds no way in that the form did not already have.

// Assistants gives the public server the declared assistants.
type Assistants struct {
	Set func() (*assistant.Set, error)
	// Model returns the model for an assistant, or nil for extractive. It is
	// only called for an assistant that declared UseModel.
	Model func(assistant.Assistant) assistant.Model
	// Forms are the site's declared forms, for pre-filling a form action.
	Forms func() (*form.Set, error)
	// Document reads a media library file an assistant was given. Nil means
	// assistants answer from pages only.
	Document func(id string) (name, format string, body []byte, err error)
	// Limit bounds questions per source. A question can cost a model call;
	// an unbounded public endpoint that spends somebody's model budget is a
	// way to spend it.
	Limit *throttle.Limiter
	// Audit records that a question was asked, never what.
	Audit func(name, source string, answered bool)
	// Handoff keeps conversations an assistant passed to a person. Nil means
	// no assistant on this site can hand over, whatever it declares.
	Handoff *handoff.Store
	// HandoffEvent is told that a conversation was opened, added to or
	// ended — which one and from where, never what was said.
	HandoffEvent func(action, name, id, source string)

	mu    sync.Mutex
	cache map[string]cachedIndex
}

type cachedIndex struct {
	key string
	idx *assistant.Index
}

// Disclosure is what every conversation page says about who is answering.
//
// EU AI Act Article 50(1): somebody talking to an AI system is told so,
// unless it is obvious. The built-in page says it under every answer; a
// page an owner designs gets it as {{ ask.disclosure }}, and the posture
// check ai.chatbot-undisclosed reports a published one that leaves it out.
const Disclosure = "You are talking to an automated assistant, not a person."

// askPageName is the published page an owner may design the conversation
// with. Absent, a plain built-in page is served.
const askPageName = "ask"

func (st *Site) ask(w http.ResponseWriter, r *http.Request) {
	if st.Assistants == nil || st.Assistants.Set == nil {
		st.notFound(w, r)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/ask/")
	name, rest, _ := strings.Cut(name, "/")
	set, err := st.Assistants.Set()
	if err != nil {
		http.Error(w, "this assistant is not available", http.StatusServiceUnavailable)
		return
	}
	a, ok := set.Get(name)
	if !ok || !a.Public {
		// One answer for "no such assistant" and "not public", so the route
		// is not a way to learn what an owner is still building.
		st.notFound(w, r)
		return
	}

	if rest != "" {
		if !st.handoffRoute(w, r, a, rest) {
			st.notFound(w, r)
		}
		return
	}

	view := askView{Assistant: a, Greeting: a.Greeting}
	if _, ok := st.handoffStore(a); ok {
		view.Handoff = handoffAction(a)
	}
	if view.Greeting == "" {
		view.Greeting = "Ask a question about this site."
	}

	view.Embedded = r.URL.Query().Get("embed") == "1"
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	case http.MethodPost:
		source := sourceOf(r)
		if l := st.Assistants.Limit; l != nil {
			if d := l.Check(throttle.Subject{Source: source}); !d.Allowed {
				secs := int(d.RetryAfter.Seconds()) + 1
				w.Header().Set("Retry-After", strconv.Itoa(secs))
				view.Problem = "You have asked a lot of questions in a short " +
					"time. Please wait a moment and try again."
				st.renderAsk(w, r, view, http.StatusTooManyRequests)
				return
			}
			l.Spend(throttle.Subject{Source: source})
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if err := r.ParseForm(); err != nil {
			view.Problem = "That question could not be read."
			st.renderAsk(w, r, view, http.StatusBadRequest)
			return
		}
		view.Question = r.PostFormValue("q")
		view.Previous = r.PostFormValue("prev")
		view.Embedded = r.PostFormValue("embed") == "1"
		idx, ierr := st.assistantIndex(a)
		if ierr != nil {
			http.Error(w, "the site could not be read", http.StatusInternalServerError)
			return
		}
		var m assistant.Model
		if a.UseModel && st.Assistants.Model != nil {
			m = st.Assistants.Model(a)
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		ans, aerr := assistant.RespondTo(ctx, a, idx, m, view.Question, view.Previous)
		if aerr != nil {
			view.Problem = aerr.Error()
			st.renderAsk(w, r, view, http.StatusUnprocessableEntity)
			return
		}
		if st.Assistants.Audit != nil {
			st.Assistants.Audit(a.Name, source, !ans.Refused)
		}
		if !ans.Refused {
			st.convert(r, "chatbot:"+a.Name)
		}
		view.Answer = &ans
		view.Sources = st.citedSources(ans)
		if ans.Proposed != nil {
			view.Offer = st.offerFor(*ans.Proposed)
		}
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "use GET or POST", http.StatusMethodNotAllowed)
		return
	}
	st.renderAsk(w, r, view, http.StatusOK)
}

// assistantIndex is the assistant's knowledge at the published commit,
// rebuilt only when what it reads has changed.
func (st *Site) assistantIndex(a assistant.Assistant) (*assistant.Index, error) {
	pages, hashes, err := st.pages()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(hashes))
	for n := range hashes {
		if a.Reads(n) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	h := sha256.New()
	// The declaration is part of the key: an owner narrowing what the
	// assistant reads must not be answered from the wider index.
	h.Write([]byte(strings.Join(a.Pages, ",") + "|" + strings.Join(a.Exclude, ",") +
		"|" + strings.Join(a.Documents, ",")))
	for _, n := range names {
		h.Write([]byte(n + "\x00" + hashes[n] + "\x00"))
	}
	key := hex.EncodeToString(h.Sum(nil))

	as := st.Assistants
	as.mu.Lock()
	defer as.mu.Unlock()
	if c, ok := as.cache[a.Name]; ok && c.key == key {
		return c.idx, nil
	}
	passages := assistant.Chunk(pages, a.Reads)
	if as.Document != nil {
		for _, id := range a.Documents {
			name, format, body, derr := as.Document(id)
			if derr != nil {
				continue // a removed file is not knowledge, and not an outage
			}
			ps, cerr := assistant.ChunkDocument(id, name, format, body)
			if cerr != nil {
				continue // the owner's console says why; a visitor is not told
			}
			passages = append(passages, ps...)
		}
	}
	idx := assistant.NewIndex(passages)
	if as.cache == nil {
		as.cache = map[string]cachedIndex{}
	}
	as.cache[a.Name] = cachedIndex{key: key, idx: idx}
	return idx, nil
}

type askView struct {
	Assistant assistant.Assistant
	Greeting  string
	Question  string
	Previous  string
	Embedded  bool
	Answer    *assistant.Answer
	Sources   []askSource
	Offer     *askOffer
	Problem   string
	// Handoff is where the "talk to a person" form posts, when this
	// assistant may hand over.
	Handoff string
}

type askSource struct {
	N           int
	Title, Href string
}

type askOffer struct {
	Kind, Label, Description, Href string
	Form                           string
	Fields                         []askField
	Stamp                          string
}

type askField struct {
	Name, Label, Kind, Value string
	Required                 bool
	Choices                  []string
}

// citedSources are the passages the answer cites, as links to their pages.
func (st *Site) citedSources(ans assistant.Answer) []askSource {
	seen := map[int]bool{}
	var out []askSource
	for _, s := range ans.Kept {
		for _, n := range s.Cites {
			if seen[n] || n < 1 || n > len(ans.Sources) {
				continue
			}
			seen[n] = true
			h := ans.Sources[n-1]
			href := h.Link()
			if h.Doc == "" && h.Page == st.indexName() {
				href = "/"
			}
			out = append(out, askSource{N: n, Title: h.Header(), Href: href})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].N < out[j].N })
	return out
}

// offerFor turns a proposal into something the visitor can take up.
func (st *Site) offerFor(p assistant.Proposal) *askOffer {
	o := &askOffer{Kind: string(p.Action.Kind), Description: p.Action.Description}
	switch p.Action.Kind {
	case assistant.Link:
		o.Href = "/" + strings.TrimPrefix(p.Action.Target, "/")
		o.Label = p.Action.Description
		return o
	case assistant.Form:
		if st.Assistants.Forms == nil {
			return nil
		}
		set, err := st.Assistants.Forms()
		if err != nil {
			return nil
		}
		f, ok := set.Get(p.Action.Target)
		if !ok || f.Closed {
			return nil
		}
		o.Form = f.Name
		o.Label = f.Label
		if o.Label == "" {
			o.Label = f.Name
		}
		o.Stamp = strconv.FormatInt(time.Now().Unix(), 10)
		for _, fl := range f.Fields {
			v := p.Args[fl.Name]
			// Never pre-filled, whatever the conversation established: a
			// field the owner marked sensitive is one the visitor types.
			if fl.Sensitive {
				v = ""
			}
			o.Fields = append(o.Fields, askField{Name: fl.Name,
				Label: fl.Label, Kind: string(fl.Kind), Value: v,
				Required: fl.Required, Choices: fl.Choices})
		}
		return o
	}
	return nil
}

// renderAsk draws the conversation, through the owner's "ask" page when
// they published one and the built-in page otherwise.
func (st *Site) renderAsk(w http.ResponseWriter, r *http.Request, v askView, status int) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	// Never cached: an answer is to one person's question.
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	allowFraming(h, v.Assistant.Embed)

	pages, hashes, err := st.pages()
	if err == nil {
		if body, ok := pages[askPageName]; ok {
			if html, ok := st.askThroughLayout(body, hashes[askPageName], r, v); ok {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(html))
				return
			}
		}
	}
	w.WriteHeader(status)
	_ = askTemplate.Execute(w, map[string]any{
		"Disclosure": Disclosure,
		"V":          v, "Honeypot": form.Honeypot, "StampField": form.StampField,
	})
}

// askThroughLayout renders the owner's page with the conversation under
// "ask". Plain data: the template language has no calls, so an owner's
// layout can arrange this and cannot do anything with it.
func (st *Site) askThroughLayout(body any, hash string, r *http.Request, v askView) (string, bool) {
	ctx, err := st.sources().For(askPageName, body, firstOf(r.URL.Query()))
	if err != nil {
		return "", false
	}
	data := map[string]any{
		"name": v.Assistant.Name, "title": v.Assistant.Title,
		"greeting": v.Greeting, "question": v.Question, "problem": v.Problem,
		"action": "/ask/" + v.Assistant.Name, "answered": v.Answer != nil,
		"disclosure": Disclosure,
	}
	if v.Answer != nil {
		data["answer"] = v.Answer.Text
		data["refused"] = v.Answer.Refused
		var srcs []any
		for _, s := range v.Sources {
			srcs = append(srcs, map[string]any{"n": float64(s.N),
				"title": s.Title, "href": s.Href})
		}
		data["sources"] = srcs
	}
	ctx["ask"] = data
	_, layout, lerr := st.Layouts.For(body)
	if lerr != nil {
		return "", false
	}
	html, rerr := tmpl.Render(layout, ctx)
	if rerr != nil {
		return "", false
	}
	return st.injectHead(html, askPageName, hash, body), true
}

// askTemplate is the built-in conversation page. html/template, so every
// value — the question, the answer, a page title, a pre-filled field — is
// escaped for where it lands.
var askTemplate = template.Must(template.New("ask").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.V.Assistant.Title}}</title>
<link rel="stylesheet" href="/site.css">
<link rel="stylesheet" href="/ask.css">
</head>
<body class="qz-ask{{if .V.Embedded}} qz-embed{{end}}"><main>
{{if .V.Embedded}}<p class="qz-embed-title">{{.V.Assistant.Title}}</p>{{else}}<h1>{{.V.Assistant.Title}}</h1>{{end}}
{{if .V.Answer}}
<section class="qz-turn" aria-label="Your question">
  <p class="qz-q">{{.V.Question}}</p>
</section>
<section class="qz-turn qz-a{{if .V.Answer.Refused}} qz-refused{{end}}" aria-live="polite" aria-label="Answer">
  {{if .V.Answer.Refused}}<p>{{.V.Answer.Text}}</p>
  {{else}}{{range .V.Answer.Kept}}<p>{{.Text}}{{range .Cites}} <sup><a href="#src-{{.}}">[{{.}}]</a></sup>{{end}}</p>{{end}}{{end}}
  {{if .V.Sources}}
  <h2>Sources</h2>
  <ol class="qz-sources">{{range .V.Sources}}<li id="src-{{.N}}" value="{{.N}}"><a href="{{.Href}}"{{if $.V.Embedded}} target="_blank" rel="noopener"{{end}}>{{.Title}}</a></li>{{end}}</ol>
  {{end}}
</section>
{{with .V.Offer}}
<section class="qz-offer" aria-label="Something I can help with">
  {{if eq .Kind "link"}}<p><a class="qz-button" href="{{.Href}}"{{if $.V.Embedded}} target="_blank" rel="noopener"{{end}}>{{.Label}}</a></p>
  {{else}}
  <h2>{{.Label}}</h2>
  <p>I have filled in what I could. Check it, change anything that is
    wrong, and send it yourself — nothing is sent until you do.</p>
  <form method="post" action="/form/{{.Form}}">
    {{range .Fields}}
    <p><label for="f-{{.Name}}">{{.Label}}{{if .Required}} (required){{end}}</label><br>
    {{if eq .Kind "para"}}<textarea id="f-{{.Name}}" name="{{.Name}}" rows="4"{{if .Required}} required{{end}}>{{.Value}}</textarea>
    {{else if eq .Kind "choice"}}<select id="f-{{.Name}}" name="{{.Name}}"{{if .Required}} required{{end}}>{{$v := .Value}}{{range .Choices}}<option{{if eq . $v}} selected{{end}}>{{.}}</option>{{end}}</select>
    {{else if eq .Kind "agree"}}<input id="f-{{.Name}}" name="{{.Name}}" type="checkbox" value="yes"{{if .Required}} required{{end}}>
    {{else}}<input id="f-{{.Name}}" name="{{.Name}}" type="{{if eq .Kind "email"}}email{{else if eq .Kind "number"}}number{{else}}text{{end}}" value="{{.Value}}"{{if .Required}} required{{end}}>{{end}}</p>
    {{end}}
    <p class="qz-hidden" aria-hidden="true"><label>Leave this empty <input name="{{$.Honeypot}}" tabindex="-1" autocomplete="off"></label></p>
    <input type="hidden" name="{{$.StampField}}" value="{{.Stamp}}">
    <p><button type="submit">Send</button></p>
  </form>
  {{end}}
</section>
{{end}}
{{else}}
<p class="qz-greeting">{{.V.Greeting}}</p>
{{end}}
{{if .V.Problem}}<p class="qz-problem" role="alert">{{.V.Problem}}</p>{{end}}
{{if and .V.Answer .V.Handoff}}
<details class="qz-handoff"{{if .V.Answer.Refused}} open{{end}}>
  <summary>Talk to a person instead</summary>
  <form method="post" action="{{.V.Handoff}}">
    <input type="hidden" name="q" value="{{.V.Question}}">
    {{if .V.Embedded}}<input type="hidden" name="embed" value="1">{{end}}
    <p><label for="handoff-message">What would you like to ask?</label><br>
    <textarea id="handoff-message" name="message" rows="3" maxlength="2000" required>{{.V.Question}}</textarea></p>
    <p class="qz-small">Sending this starts a conversation that somebody at
      the business will read and answer. Unlike your questions to the
      assistant, it is kept: for {{.V.Assistant.Keep}} days after it last
      moves, then deleted. Please do not include passwords or card numbers.</p>
    <p><button type="submit">Send to a person</button></p>
  </form>
</details>
{{end}}
<form method="post" action="/ask/{{.V.Assistant.Name}}" class="qz-ask-form">
  {{if .V.Answer}}<input type="hidden" name="prev" value="{{.V.Question}}">{{end}}
  {{if .V.Embedded}}<input type="hidden" name="embed" value="1">{{end}}
  <label for="q">{{if .V.Answer}}Ask another question{{else}}Your question{{end}}</label>
  <textarea id="q" name="q" rows="2" maxlength="1000" required{{if not .V.Embedded}} autofocus{{end}}></textarea>
  <button type="submit">Ask</button>
</form>
<p class="qz-small">{{.Disclosure}} Answers come from this site's pages, and
  every sentence links to where it came from. Nothing you ask is stored.</p>
</main></body></html>`))

// askCSS is the built-in page's stylesheet, served at /ask.css. Small and
// inheriting from the site's own, so an assistant looks like the site it is
// on rather than like a widget from somewhere else.
const askCSS = `.qz-ask main{max-width:42rem;margin:0 auto;padding:1.5rem 1rem 3rem}
.qz-turn{margin:1rem 0;padding:.9rem 1.1rem;border-radius:12px;border:1px solid color-mix(in srgb,currentColor 18%,transparent)}
.qz-q{font-weight:600;margin:0}
.qz-a p{margin:.4rem 0;line-height:1.6}
.qz-a sup a{text-decoration:none;font-size:.8em}
.qz-refused{opacity:.85}
.qz-sources{font-size:.9em;padding-left:1.4rem}
.qz-offer{margin:1.2rem 0;padding:1rem 1.1rem;border-radius:12px;border:2px solid color-mix(in srgb,currentColor 30%,transparent)}
.qz-offer input:not([type=checkbox]),.qz-offer textarea,.qz-offer select,.qz-ask-form textarea{width:100%;box-sizing:border-box;font:inherit;padding:.5rem .6rem;border-radius:8px;border:1px solid color-mix(in srgb,currentColor 35%,transparent)}
.qz-ask-form{display:grid;gap:.5rem;margin-top:1.5rem}
.qz-ask-form button,.qz-offer button,.qz-button{justify-self:start;font:inherit;font-weight:600;padding:.55rem 1.1rem;border-radius:999px;border:0;cursor:pointer;text-decoration:none;display:inline-block;background:CanvasText;color:Canvas}
.qz-hidden{position:absolute;left:-10000px;width:1px;height:1px;overflow:hidden}
.qz-problem{padding:.7rem 1rem;border-radius:8px;border:1px solid}
.qz-small{font-size:.85em;opacity:.75;margin-top:1.5rem}
.qz-embed main{padding:.75rem .75rem 1rem;max-width:none}
.qz-embed-title{font-weight:700;margin:0 0 .5rem}
.qz-embed .qz-small{margin-top:.75rem}
:focus-visible{outline:2px solid currentColor;outline-offset:2px}
.qz-handoff{margin:1.2rem 0;padding:.8rem 1.1rem;border-radius:12px;border:1px dashed color-mix(in srgb,currentColor 35%,transparent)}
.qz-handoff summary{cursor:pointer;font-weight:600}
.qz-handoff textarea{width:100%;box-sizing:border-box;font:inherit;padding:.5rem .6rem;border-radius:8px;border:1px solid color-mix(in srgb,currentColor 35%,transparent)}
.qz-handoff button{font:inherit;font-weight:600;padding:.55rem 1.1rem;border-radius:999px;border:0;cursor:pointer;background:CanvasText;color:Canvas}
.qz-thread{list-style:none;padding:0;margin:1rem 0;display:grid;gap:.6rem}
.qz-msg{padding:.7rem 1rem;border-radius:12px;max-width:85%;border:1px solid color-mix(in srgb,currentColor 18%,transparent);white-space:pre-wrap;overflow-wrap:anywhere}
.qz-msg.qz-visitor{justify-self:end;background:color-mix(in srgb,currentColor 7%,transparent)}
.qz-who{display:block;font-size:.8em;font-weight:700;opacity:.75;margin-bottom:.2rem}
.qz-actions{margin:.8rem 0}
.qz-button-quiet{font:inherit;padding:.4rem .9rem;border-radius:999px;border:1px solid color-mix(in srgb,currentColor 35%,transparent);background:transparent;color:inherit;cursor:pointer;text-decoration:none;display:inline-block}
.qz-end{margin-top:1.5rem}
`

func (st *Site) askStylesheet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write([]byte(askCSS))
}

// allowFraming lets the sites an owner listed show this page in a frame.
//
// Only this page, only those origins, and only by rewriting the one
// directive: the rest of the policy stays exactly what the site sends. Every
// other response keeps frame-ancestors 'none'. The origins were checked by
// assistant.Origin when they were declared, so none can carry a wildcard or
// end the directive early — and they are checked again here, because a
// declaration file can be edited by hand.
func allowFraming(h http.Header, origins []string) {
	var ok []string
	for _, o := range origins {
		if n, err := assistant.Origin(o); err == nil {
			ok = append(ok, n)
		}
	}
	if len(ok) == 0 {
		return
	}
	value := "frame-ancestors 'self' " + strings.Join(ok, " ")
	for _, name := range []string{"Content-Security-Policy",
		"Content-Security-Policy-Report-Only"} {
		cur := h.Get(name)
		if cur == "" {
			continue
		}
		h.Set(name, reFrameAncestors.ReplaceAllString(cur, value))
	}
}

var reFrameAncestors = regexp.MustCompile(`frame-ancestors[^;]*`)
