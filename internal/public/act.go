// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/chatact"
)

// A chatbot's agent actions, on the public site: what the visitor is asked
// to confirm, the request it makes, and the page that waits for the answer.
//
// The site does not run the agent: it is confined, and an agent needs the
// store, the models and the policy. It writes the confirmed request where
// the admin server's dispatcher takes it (internal/chatact), and the page
// it sends the visitor to shows the answer when there is one. Nothing the
// visitor typed is trusted there; who they are is only what the host site
// signed (assistant.VerifyVisitor), and the admin server checks that
// signature again for itself.

// MaxActArg bounds what a visitor gives an agent action, per field.
const MaxActArg = 300

// visitor is what the host site signed about the visitor whose page this
// is, if it signed anything this assistant can check.
func (st *Site) visitor(a assistant.Assistant, token string) (map[string]string, bool) {
	if token == "" || st.Assistants.VisitorKey == nil {
		return nil, false
	}
	key := st.Assistants.VisitorKey(a)
	if len(key) == 0 {
		return nil, false
	}
	claims, err := assistant.VerifyVisitor(token, key, time.Now())
	return claims, err == nil
}

// agentOffer is an agent action offered to the visitor: what it asks, with
// what the conversation filled in, for them to check and confirm.
func (st *Site) agentOffer(p assistant.Proposal, token string, a assistant.Assistant) *askOffer {
	if st.Assistants.Act == nil {
		return nil
	}
	if p.Action.Identity {
		if _, ok := st.visitor(a, token); !ok {
			return nil
		}
	}
	o := &askOffer{Kind: "agent", Label: p.Action.Description, Description: p.Action.Description,
		Action: p.Action.Name, Writes: p.Action.Writes, Token: token}
	for _, f := range p.Action.Fields {
		o.Fields = append(o.Fields, askField{Name: f, Label: fieldLabel(f), Kind: "line", Value: p.Args[f], Required: true})
	}
	return o
}

// fieldLabel is a field's name as a person reads it: booking_ref is
// "Booking ref".
func fieldLabel(name string) string {
	s := strings.ReplaceAll(name, "_", " ")
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// actRoute serves /ask/NAME/act and /ask/NAME/act/ID.
func (st *Site) actRoute(w http.ResponseWriter, r *http.Request, a assistant.Assistant, rest string) bool {
	switch {
	case rest == "act":
		st.actAsk(w, r, a)
		return true
	case strings.HasPrefix(rest, "act/"):
		st.actWait(w, r, a, strings.TrimPrefix(rest, "act/"))
		return true
	}
	return false
}

// actAsk takes a visitor's confirmed request and hands it on.
func (st *Site) actAsk(w http.ResponseWriter, r *http.Request, a assistant.Assistant) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	if st.Assistants.Act == nil {
		st.notFound(w, r)
		return
	}
	if ok, wait := st.questionAllowed(r); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		http.Error(w, "You have asked a lot in a short time. You can ask again "+inAbout(wait)+".", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "that request could not be read", http.StatusBadRequest)
		return
	}
	var action *assistant.Action
	for i := range a.Actions {
		if a.Actions[i].Name == r.PostFormValue("action") && a.Actions[i].Kind == assistant.Agent {
			action = &a.Actions[i]
		}
	}
	if action == nil {
		http.Error(w, "this chatbot does not offer that", http.StatusBadRequest)
		return
	}
	token := r.PostFormValue("v")
	if action.Identity {
		if _, ok := st.visitor(a, token); !ok {
			http.Error(w, "Sign in on the site first: this is only for somebody it knows.", http.StatusForbidden)
			return
		}
	}
	args := map[string]string{}
	for _, f := range action.Fields {
		v := strings.Join(strings.Fields(r.PostFormValue("a_"+f)), " ")
		if v == "" {
			http.Error(w, fieldLabel(f)+" is needed", http.StatusBadRequest)
			return
		}
		if len(v) > MaxActArg {
			v = v[:MaxActArg]
		}
		args[f] = v
	}
	id, err := chatact.NewID()
	if err != nil {
		http.Error(w, "this could not be asked", http.StatusInternalServerError)
		return
	}
	req := chatact.Request{ID: id, Chatbot: a.Name, Action: action.Name, Args: args, Token: token, At: time.Now().UTC()}
	if err := st.Assistants.Act(req); err != nil {
		http.Error(w, "this could not be asked just now", http.StatusServiceUnavailable)
		return
	}
	to := "/ask/" + a.Name + "/act/" + id
	if e := r.PostFormValue("embed"); e != "" {
		to += "?embed=" + e
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// actWait shows the answer to a request, or that it is still being worked
// on, refreshing until there is one.
func (st *Site) actWait(w http.ResponseWriter, r *http.Request, a assistant.Assistant, id string) {
	if st.Assistants.Answer == nil || !chatact.ValidID(id) {
		st.notFound(w, r)
		return
	}
	res, answered, made := st.Assistants.Answer(id)
	if !made {
		st.notFound(w, r)
		return
	}
	embedded, panel := embedMode(r.URL.Query().Get("embed"))
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	allowFraming(h, a.Embed, panel)
	switch {
	case !answered || res.State == chatact.Working:
		// The page asks again in a few seconds, without script.
		h.Set("Refresh", "3")
	case res.State == chatact.Waiting:
		// A person decides first, which takes minutes or a day rather than
		// seconds, so it asks less often; and the page links to itself, the
		// one address that leads to this request's answer, for a visitor
		// who comes back to it later.
		h.Set("Refresh", "30")
	}
	again := "/ask/" + a.Name + "/act/" + id
	if embedded {
		again += "?embed=" + r.URL.Query().Get("embed")
	}
	_ = actTemplate.Execute(w, map[string]any{"A": a, "R": res, "Answered": answered && res.State != chatact.Working,
		"Embedded": embedded, "Person": res.State == chatact.Person, "Failed": res.State == chatact.Failed,
		"Waiting": res.State == chatact.Waiting, "Again": again, "Lang": st.siteLang()})
}

var actTemplate = template.Must(template.New("act").Parse(`<!doctype html>
<html lang="{{.Lang}}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{{.A.Title}}</title>
<link rel="stylesheet" href="/site.css">
<link rel="stylesheet" href="/ask.css">
</head>
<body class="qz-ask{{if .Embedded}} qz-embed{{end}}"><main>
{{if .Embedded}}<p class="qz-embed-title">{{.A.Title}}</p>{{else}}<h1>{{.A.Title}}</h1>{{end}}
{{if not .Answered}}<p class="qz-waiting" role="status" aria-live="polite">Working on it. This page shows the answer when it is ready.</p>
{{else if .Waiting}}<p class="qz-greeting" role="status" aria-live="polite">A person needs to look at this, and will. You do not need to ask again: once they have, the answer is shown on this page.</p>
<p class="qz-actions"><a class="qz-button-quiet" href="{{.Again}}">Check again</a></p>
{{else if .Person}}<p class="qz-greeting" role="status">A person needs to look at this, and will. You do not need to ask again.</p>
{{else if .Failed}}<p class="qz-problem" role="alert">This could not be done just now. You could try again later, or ask a person.</p>
{{else}}<section class="qz-answer" aria-label="Answer"><p>{{.R.Answer}}</p></section>{{end}}
<p class="qz-actions"><a class="qz-button-quiet" href="/ask/{{.A.Name}}{{if .Embedded}}?embed=1{{end}}">Ask something else</a></p>
</main></body></html>`))
