// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/chatact"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/handoff"
	"github.com/quilzo/quilzo/internal/rate"
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
	// Questions bounds how often a visitor may ask: a burst at once, then a
	// steady pace (chatbot.questions.*). A question can cost a model call,
	// and an unbounded public endpoint is a way to spend somebody's model
	// budget; but a conversation is a person asking on purpose and often,
	// so this is a rate, not the sign-in throttle's lengthening penalty.
	// Counted per signed-in member where there is one — a team behind one
	// office address is several people — and per address otherwise.
	Questions *rate.Limiter
	// Audit records that a question was asked, never what.
	Audit func(name, source string, answered bool)
	// Act hands on a visitor's confirmed request to a chatbot's agent
	// (internal/chatact), and Answer reads its answer back: whether there
	// is one, and whether the request was made at all. VisitorKey is the
	// key the host site signs visitors' tokens with, for an assistant that
	// names one. Nil Act offers no agent action.
	// RecordsTree is the published tree records are read from, which
	// keys the index of an assistant that reads records, so it is rebuilt
	// when they change; Records are some collections' records in it, as
	// passages, read only when the index is rebuilt.
	RecordsTree func() string
	Records     func(tree string, collections []string) []assistant.Passage
	Act         func(chatact.Request) error
	Answer      func(id string) (res chatact.Result, answered, made bool)
	VisitorKey  func(assistant.Assistant) []byte
	// Meaning is a chatbot's ranker by meaning (assistant.Meaning), or
	// nil when it ranks by words alone; MeaningKey is what that ranker
	// depends on, which keys the index too.
	Meaning    func(assistant.Assistant, []assistant.Passage) *assistant.Meaning
	MeaningKey func(assistant.Assistant) string
	// Unanswered is told a question a chatbot could not answer, for the
	// owner's record of what the site does not say (chatbot.gaps). Nil,
	// which it is unless the owner turned that on, keeps nothing.
	Unanswered func(name, question string)
	// Rated is told a visitor's rating of an answer: whether it helped,
	// and the question, for the owner's record of what the site says badly
	// when they keep one. Nil offers no rating. Keeps reports whether
	// questions are kept at all (chatbot.gaps), which the page says.
	Rated func(name, question string, helpful bool)
	Keeps func() bool
	// Handoff keeps conversations an assistant passed to a person. Nil means
	// no assistant on this site can hand over, whatever it declares.
	Handoff *handoff.Store
	// HandoffEvent is told that a conversation was opened, added to or
	// ended — which one and from where, never what was said.
	HandoffEvent func(action, name, id, source string)
	// Takeover is told when a page new to a chatbot's knowledge is the first
	// source it cites: which chatbot, which page, and a digest of the
	// question, so the shield can count how many different questions one
	// new page is winning. A page written to win every question is how a
	// poisoned page behaves (PoisonedRAG); a popular new page can look the
	// same, so a person is told, nothing is refused.
	Takeover func(name, page, question string)
	// Guardrail asks an outside classifier about texts, after Quilzo's own
	// checks (internal/guardrail): which it flags, and how many went
	// unanswered, which are kept. GuardrailEvent is told the counts.
	Guardrail      func(ctx context.Context, texts []string) (flagged []bool, unanswered int)
	GuardrailEvent func(name, what string, n int)

	// What the chatbots hold for the visitors they are answering, guarded
	// by mu. When keep is set (Keep), these are kept by that one instead,
	// for both, and this one's are unused.
	mu    sync.Mutex
	keep  *Assistants
	cache map[string]cachedIndex
	// rateKey signs rating tokens; rated are the ones used (askrate.go).
	rateKey []byte
	rated   map[string]time.Time
	// fresh is, for each chatbot, the pages that entered its knowledge in a
	// rebuild while this server ran, and when. A page already there when
	// the server started is not new.
	fresh map[string]map[string]time.Time
}

// Keep makes these chatbots carry on from prev's, when the site is built
// again while it runs: the key their ratings are signed with and the ratings
// already used, which pages are new to each, and the index each answered
// from, as the one a new page is new against. Everything else, the
// guardrail included, is as was given here.
//
// Shared rather than copied, because prev goes on serving the requests it
// already has: a rating spent there while this one starts must be spent here
// too. Called before this one serves anything.
//
// The server that rebuilt its site when its settings changed kept the
// previous chatbots whole, for their ratings, and with them the guardrail
// they were built with: an operator who turned one on was told the site had
// read its settings again, and no passage reached the classifier until a
// restart.
func (as *Assistants) Keep(prev *Assistants) {
	if as == nil || prev == nil {
		return
	}
	if o := prev.own(); o != as {
		as.keep = o
	}
}

// own is the chatbots that hold this one's visitor state: itself, or the
// first of the builds it carries on from. One step, never a chain, because
// Keep follows prev to its own.
func (as *Assistants) own() *Assistants {
	if as.keep != nil {
		return as.keep
	}
	return as
}

// NewFor is how long a page that entered a chatbot's knowledge counts as new.
const NewFor = 7 * 24 * time.Hour

type cachedIndex struct {
	key string
	// by is the build that made it. The knowledge alone does not decide what
	// an index holds: the guardrail of the build answering does, so a
	// rebuilt site's chatbots build their own rather than answer from one
	// their guardrail never saw.
	by  *Assistants
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
	if level, until, on := st.shielded("chatbot:" + a.Name); on && level != "limited" {
		st.resting(w, r, "This assistant", until)
		return
	}

	if rest == "knowledge.json" {
		st.askKnowledge(w, r, a)
		return
	}
	if rest == "rate" {
		st.rate(w, r, a)
		return
	}
	if rest != "" {
		if !st.actRoute(w, r, a, rest) && !st.handoffRoute(w, r, a, rest) {
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

	view.Embedded, view.Panel = embedMode(r.URL.Query().Get("embed"))
	view.Visitor = visitorToken(r.URL.Query().Get("v"))
	view.Rated = ratedNote(r.URL.Query().Get("rated"))
	if st.Assistants.Keeps != nil {
		view.Keeps = st.Assistants.Keeps()
	}
	if a.Launcher != nil {
		view.Suggestions = a.Launcher.Suggestions
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if a.Static && r.URL.Query().Get("copy") == staticCopy {
			st.renderAskStatic(w, view)
			return
		}
		// A question in the address is answered, as site search answers
		// one: the question box a page carries is a GET form, so the same
		// form works on the live site and on a static copy.
		if q := r.URL.Query().Get("q"); q != "" && r.Method == http.MethodGet {
			view.Question = q
			if !st.answer(w, r, a, &view) {
				return
			}
		}
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, questionForm)
		if err := r.ParseForm(); err != nil {
			view.Problem = "That question could not be read."
			st.renderAsk(w, r, view, http.StatusBadRequest)
			return
		}
		view.Question = r.PostFormValue("q")
		view.Previous = r.PostFormValue("prev")
		view.Visitor = visitorToken(r.PostFormValue("v"))
		view.Embedded, view.Panel = embedMode(r.PostFormValue("embed"))
		if !st.answer(w, r, a, &view) {
			return
		}
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "use GET or POST", http.StatusMethodNotAllowed)
		return
	}
	st.renderAsk(w, r, view, http.StatusOK)
}

// questionForm bounds the body of a form that carries a question: the
// question and the previous one, each of assistant.MaxQuestion characters
// at up to four bytes, each written as three in a form's encoding. At 8 KiB
// a question of 1000 characters in Japanese, which the box takes, could not
// be read.
const questionForm = 2*assistant.MaxQuestion*4*3 + 8<<10

// handoffForm bounds the body of a form that carries a message to a person,
// and the question it follows, in the same way.
const handoffForm = (handoff.MaxText+assistant.MaxQuestion)*4*3 + 8<<10

// answer puts the view's question to the assistant and fills in the answer.
// False means a response has already been written.
func (st *Site) answer(w http.ResponseWriter, r *http.Request,
	a assistant.Assistant, view *askView) bool {

	if ok, wait := st.questionAllowed(r); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		view.Problem = "You have asked a lot of questions in a short time. " +
			"You can ask again " + inAbout(wait) + "."
		st.renderAsk(w, r, *view, http.StatusTooManyRequests)
		return false
	}
	// The previous question is the visitor's text too: it comes back in a
	// hidden field, which a script fills as it likes, and goes to the model
	// beside a follow-up. Screened only in the question box, an attempt put
	// there with a harmless follow-up reached the model and was never
	// counted. Both are looked at, and a request is one signal at most.
	said := []string{view.Question}
	if strings.TrimSpace(view.Previous) != "" {
		said = append(said, view.Previous)
	}
	if LooksLikeInjection(view.Question) || LooksLikeInjection(view.Previous) {
		st.signal(ChatbotInjection, a.Name, r)
	} else if g := st.Assistants.Guardrail; g != nil {
		// A second look, counted the same way: a flagged question is a
		// signal, never a refusal on a classifier's word.
		gctx, gcancel := context.WithTimeout(r.Context(), 3*time.Second)
		flagged, missed := g(gctx, said)
		gcancel()
		for _, f := range flagged {
			if f {
				st.signal(ChatbotInjection, a.Name, r)
				break
			}
		}
		if missed > 0 && st.Assistants.GuardrailEvent != nil {
			st.Assistants.GuardrailEvent(a.Name, "unanswered", missed)
		}
	}
	idx, ierr := st.assistantIndex(a)
	if ierr != nil {
		http.Error(w, "the site could not be read", http.StatusInternalServerError)
		return false
	}
	var m assistant.Model
	// Limited by the shield: it quotes pages and asks no model, which takes
	// away what injection is after and what it costs.
	if _, _, limited := st.shielded("chatbot:" + a.Name); a.UseModel && st.Assistants.Model != nil && !limited {
		m = st.Assistants.Model(a)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	ans, aerr := assistant.RespondTo(ctx, a, idx, m, view.Question, view.Previous)
	if aerr != nil {
		view.Problem = aerr.Error()
		st.renderAsk(w, r, *view, http.StatusUnprocessableEntity)
		return false
	}
	if st.Assistants.Audit != nil {
		st.Assistants.Audit(a.Name, sourceOf(r), !ans.Refused)
	}
	if ans.Refused && st.Assistants.Unanswered != nil {
		st.Assistants.Unanswered(a.Name, view.Question)
	}
	if !ans.Refused {
		st.convert(r, "chatbot:"+a.Name)
	}
	view.Answer = &ans
	if !ans.Refused && st.Assistants.Rated != nil {
		view.Rate = st.Assistants.rateToken(a.Name, view.Question, time.Now())
		view.Rated = ""
	}
	view.Sources = st.citedSources(ans)
	if top, ok := firstCited(ans); ok && st.Assistants.Takeover != nil && st.Assistants.isFresh(a.Name, top, time.Now()) {
		sum := sha256.Sum256([]byte(strings.ToLower(strings.Join(strings.Fields(view.Question), " "))))
		st.Assistants.Takeover(a.Name, top, hex.EncodeToString(sum[:8]))
	}
	view.Cards = st.cardsFor(view.Sources, ans)
	view.FollowUps = followUps(a, view.Question, &ans, view.Sources)
	if ans.Proposed != nil {
		if ans.Proposed.Action.Kind == assistant.Agent {
			view.Offer = st.agentOffer(*ans.Proposed, view.Visitor, a)
		} else {
			view.Offer = st.offerFor(*ans.Proposed)
		}
	}
	return true
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
		"|" + strings.Join(a.Documents, ",") + "|" + strconv.FormatBool(a.KeepInstructions) +
		"|" + strings.Join(a.Collections, ",")))
	tree := ""
	if len(a.Collections) > 0 && st.Assistants.RecordsTree != nil {
		tree = st.Assistants.RecordsTree()
		h.Write([]byte("|" + tree))
	}
	for _, n := range names {
		h.Write([]byte(n + "\x00" + hashes[n] + "\x00"))
	}
	// And how it ranks by meaning: a passage embedded since the index was
	// built is found by meaning once it is rebuilt.
	if st.Assistants.MeaningKey != nil {
		h.Write([]byte("|" + st.Assistants.MeaningKey(a)))
	}
	key := hex.EncodeToString(h.Sum(nil))

	as := st.Assistants
	o := as.own()
	o.mu.Lock()
	defer o.mu.Unlock()
	if c, ok := o.cache[a.Name]; ok && c.key == key && c.by == as {
		return c.idx, nil
	}
	passages := assistant.Chunk(pages, a.Reads)
	if tree != "" && st.Assistants.Records != nil {
		passages = append(passages, st.Assistants.Records(tree, a.Collections)...)
	}
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
	// What addresses an AI reading it is left out, unless the owner keeps
	// it on purpose: see internal/assistant/screen.go.
	if !a.KeepInstructions {
		passages, _ = assistant.Hold(passages)
		passages = as.guard(a.Name, passages)
	}
	idx := assistant.NewIndex(passages)
	if as.Meaning != nil {
		idx = idx.WithMeaning(as.Meaning(a, idx.Passages))
	}
	if o.cache == nil {
		o.cache = map[string]cachedIndex{}
	}
	if old, ok := o.cache[a.Name]; ok {
		o.noteFresh(a.Name, old.idx, idx, time.Now())
	}
	o.cache[a.Name] = cachedIndex{key: key, by: as, idx: idx}
	return idx, nil
}

// guard leaves out of a chatbot's knowledge what an outside classifier
// flags, after Quilzo's own screen; what it does not answer about is kept.
func (as *Assistants) guard(name string, passages []assistant.Passage) []assistant.Passage {
	if as.Guardrail == nil || len(passages) == 0 {
		return passages
	}
	texts := make([]string, len(passages))
	for i, p := range passages {
		texts[i] = p.Header() + "\n" + p.Text
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	flagged, missed := as.Guardrail(ctx, texts)
	cancel()
	kept := make([]assistant.Passage, 0, len(passages))
	held := 0
	for i, p := range passages {
		if i < len(flagged) && flagged[i] {
			held++
			continue
		}
		kept = append(kept, p)
	}
	if as.GuardrailEvent != nil {
		if held > 0 {
			as.GuardrailEvent(name, "flagged", held)
		}
		if missed > 0 {
			as.GuardrailEvent(name, "unanswered", missed)
		}
	}
	return kept
}

// noteFresh marks the pages a rebuilt index has that the one before did
// not. Called on own(), with its lock held.
func (as *Assistants) noteFresh(name string, was, now *assistant.Index, at time.Time) {
	before := map[string]bool{}
	for _, p := range was.Passages {
		before[p.Page] = true
	}
	if as.fresh == nil {
		as.fresh = map[string]map[string]time.Time{}
	}
	f := as.fresh[name]
	if f == nil {
		f = map[string]time.Time{}
		as.fresh[name] = f
	}
	for page, since := range f {
		if at.Sub(since) > NewFor {
			delete(f, page)
		}
	}
	for _, p := range now.Passages {
		if p.Page != "" && !before[p.Page] {
			if _, seen := f[p.Page]; !seen {
				f[p.Page] = at
			}
		}
	}
}

// isFresh says a page entered a chatbot's knowledge within NewFor.
func (as *Assistants) isFresh(name, page string, at time.Time) bool {
	o := as.own()
	o.mu.Lock()
	defer o.mu.Unlock()
	since, ok := o.fresh[name][page]
	return ok && at.Sub(since) <= NewFor
}

type askView struct {
	Assistant assistant.Assistant
	Greeting  string
	Question  string
	Previous  string
	Embedded  bool
	// Panel is the conversation opened beside a page of this site by its
	// launcher: framed by this site only, and its links go to the page.
	Panel bool
	// Suggestions are questions offered before the first is asked.
	Suggestions []string
	// Cards are the cited pages with more to show than a title, and
	// FollowUps the next questions worth asking. See askrich.go.
	Cards     []askCard
	FollowUps []string
	Answer    *assistant.Answer
	Sources   []askSource
	Offer     *askOffer
	Problem   string
	// Handoff is where the "talk to a person" form posts, when this
	// assistant may hand over.
	Handoff string
	// Visitor is the host site's signed token about the visitor, carried
	// from the address the page was opened at to the forms it posts.
	Visitor string
	// Rate is the token an answer's "did this help?" form carries, when it
	// can be rated; Rated is what the page says after a rating. Keeps is
	// whether some questions are kept (chatbot.gaps), which it says too.
	Rate  string
	Rated string
	Keeps bool
}

// EmbedValue is how the page was framed, carried on its forms: "panel" for
// the launcher's, "1" for another site's, nothing for neither.
func (v askView) EmbedValue() string {
	switch {
	case v.Panel:
		return "panel"
	case v.Embedded:
		return "1"
	}
	return ""
}

// embedMode reads the embed parameter: framed at all, and framed as the
// launcher's panel.
func embedMode(v string) (embedded, panel bool) {
	return v == "1" || v == "panel", v == "panel"
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
	// Action names an agent action, Writes says it may change something,
	// and Token is the host site's word about the visitor, carried.
	Action string
	Writes bool
	Token  string
	// Multipart is a form that takes a file.
	Multipart bool
}

type askField struct {
	Name, Label, Kind, Value string
	Required                 bool
	Choices                  []string
	// Accept is a file field's hint; When the words saying when a field
	// is asked.
	Accept, When string
}

// firstCited is the page of the first source an answer cites.
func firstCited(ans assistant.Answer) (string, bool) {
	for _, s := range ans.Kept {
		for _, n := range s.Cites {
			if n >= 1 && n <= len(ans.Sources) && ans.Sources[n-1].Page != "" {
				return ans.Sources[n-1].Page, true
			}
		}
	}
	return "", false
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
		o.Multipart = f.HasFiles()
		for _, fl := range f.Fields {
			v := p.Args[fl.Name]
			// Never pre-filled, whatever the conversation established: a
			// field the owner marked sensitive is one the visitor types.
			if fl.Sensitive {
				v = ""
			}
			if fl.Kind == form.File {
				v = ""
			}
			// Asked only on an answer: required by the server when it is,
			// never by the markup.
			o.Fields = append(o.Fields, askField{Name: fl.Name,
				Label: fl.Label, Kind: string(fl.Kind), Value: v,
				Required: fl.Required && fl.When == nil, Choices: fl.Choices,
				Accept: fl.AcceptTypes(), When: f.Words(fl.When)})
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
	// Nor indexed, when it shows one. The question comes from the address
	// (?q=), and the page prints it back: indexable, it let anybody link to
	// the site with their own words in the address for a crawler to file
	// under the business's name, running the chatbot each time it looked.
	// The chatbot's own page, with no question, is the owner's to be found.
	if v.Question != "" {
		h.Set("X-Robots-Tag", "noindex, nofollow")
	}
	allowFraming(h, v.Assistant.Embed, v.Panel)
	st.originTrial(h)
	if wantsVoice(v.Assistant) {
		allowScript(h, askVoiceHash)
	}

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
		// Built from an id checked against the library; see icon.go.
		"Icon": template.HTML(st.iconLink()),
		"V":    v, "Honeypot": form.Honeypot, "StampField": form.StampField,
		"Tools": !st.ToolsOff, "Voice": st.voiceHTML(v.Assistant), "Lang": st.siteLang(),
	})
}

// askThroughLayout renders the owner's page with the conversation under
// "ask". Plain data: the template language has no calls, so an owner's
// layout can arrange this and cannot do anything with it.
func (st *Site) askThroughLayout(body any, hash string, r *http.Request, v askView) (string, bool) {
	ctx, err := st.sourcesFor(r).For(askPageName, body, firstOf(r.URL.Query()))
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
		var cards []any
		for _, c := range v.Cards {
			cards = append(cards, map[string]any{"title": c.Title, "href": c.Href,
				"image": c.Image, "summary": c.Summary, "meta": c.Meta})
		}
		data["cards"] = cards
		var fu []any
		for _, q := range v.FollowUps {
			fu = append(fu, q)
		}
		data["followups"] = fu
	}
	if v.Rate != "" {
		data["rate"] = map[string]any{"action": "/ask/" + v.Assistant.Name + "/rate", "token": v.Rate}
	}
	data["rated"] = v.Rated
	ctx["ask"] = data
	_, layout, lerr := st.Layouts.For(body)
	if lerr != nil {
		return "", false
	}
	html, rerr := tmpl.Render(layout, ctx)
	if rerr != nil {
		return "", false
	}
	out := st.annotateTools(st.injectHead(html, askPageName, hash, body))
	if snippet := st.voiceSnippet(v.Assistant); snippet != "" {
		if i := strings.LastIndex(out, "</body>"); i >= 0 {
			out = out[:i] + snippet + out[i:]
		} else {
			out += snippet
		}
	}
	return out, true
}

// askTemplate is the built-in conversation page. html/template, so every
// value — the question, the answer, a page title, a pre-filled field — is
// escaped for where it lands.
var askTemplate = template.Must(template.New("ask").Parse(`<!doctype html>
<html lang="{{.Lang}}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.V.Assistant.Title}}</title>
<link rel="stylesheet" href="/site.css">
<link rel="stylesheet" href="/ask.css">
{{.Icon}}</head>
<body class="qz-ask{{if .V.Embedded}} qz-embed{{end}}"><main>
{{if .V.Panel}}<h1 class="qz-sr">{{.V.Assistant.Title}}</h1>{{else if .V.Embedded}}<p class="qz-embed-title">{{.V.Assistant.Title}}</p>{{else}}<h1>{{.V.Assistant.Title}}</h1>{{end}}
{{if .V.Answer}}
<section class="qz-turn" aria-label="Your question">
  <p class="qz-q">{{.V.Question}}</p>
</section>
<section class="qz-turn qz-a{{if .V.Answer.Refused}} qz-refused{{end}}" aria-live="polite" aria-label="Answer">
  {{if .V.Answer.Refused}}<p>{{.V.Answer.Text}}</p>
  {{else}}{{range .V.Answer.Kept}}<p>{{.Text}}{{range .Cites}} <sup><a href="#src-{{.}}">[{{.}}]</a></sup>{{end}}</p>{{end}}{{end}}
  {{if .V.Cards}}
  <ul class="qz-cards" aria-label="Pages this answer draws on">{{range .V.Cards}}<li class="qz-card">
    {{if .Image}}<img src="{{.Image}}" alt="" loading="lazy" decoding="async">{{end}}
    <a href="{{.Href}}"{{if $.V.Panel}} target="_top"{{else if $.V.Embedded}} target="_blank" rel="noopener"{{end}}>{{.Title}}</a>
    {{if .Meta}}<p class="qz-card-meta">{{.Meta}}</p>{{end}}
    {{if .Summary}}<p class="qz-small">{{.Summary}}</p>{{end}}
  </li>{{end}}</ul>
  {{end}}
  {{if .V.Sources}}
  <h2>Sources</h2>
  <ol class="qz-sources">{{range .V.Sources}}<li id="src-{{.N}}" value="{{.N}}">{{if .Href}}<a href="{{.Href}}"{{if $.V.Panel}} target="_top"{{else if $.V.Embedded}} target="_blank" rel="noopener"{{end}}>{{.Title}}</a>{{else}}{{.Title}}{{end}}</li>{{end}}</ol>
  {{end}}
</section>
{{with .V.Offer}}
<section class="qz-offer" aria-label="Something I can help with">
  {{if eq .Kind "agent"}}
  <h2>{{.Label}}</h2>
  <p>Check what will be asked, change anything that is wrong, and press to ask it.
    {{if .Writes}}It may make a change for you once you do.{{else}}It only looks things up; it changes nothing.{{end}}</p>
  <form method="post" action="/ask/{{$.V.Assistant.Name}}/act">
    <input type="hidden" name="action" value="{{.Action}}">
    {{if .Token}}<input type="hidden" name="v" value="{{.Token}}">{{end}}
    {{if $.V.EmbedValue}}<input type="hidden" name="embed" value="{{$.V.EmbedValue}}">{{end}}
    {{range .Fields}}
    <p><label for="a-{{.Name}}">{{.Label}}</label><br>
    <input id="a-{{.Name}}" name="a_{{.Name}}" type="text" value="{{.Value}}" maxlength="300" required></p>
    {{end}}
    <p><button type="submit">Ask</button></p>
  </form>
  {{else if eq .Kind "link"}}<p><a class="qz-button" href="{{.Href}}"{{if $.V.Panel}} target="_top"{{else if $.V.Embedded}} target="_blank" rel="noopener"{{end}}>{{.Label}}</a></p>
  {{else}}
  <h2>{{.Label}}</h2>
  <p>I have filled in what I could. Check it, change anything that is
    wrong, and send it yourself — nothing is sent until you do.</p>
  <form method="post" action="/form/{{.Form}}"{{if .Multipart}} enctype="multipart/form-data"{{end}}>
    {{range .Fields}}
    <p><label for="f-{{.Name}}">{{.Label}}{{if .Required}} (required){{end}}</label><br>
    {{if eq .Kind "para"}}<textarea id="f-{{.Name}}" name="{{.Name}}" rows="4"{{if .Required}} required{{end}}>{{.Value}}</textarea>
    {{else if eq .Kind "choice"}}<select id="f-{{.Name}}" name="{{.Name}}"{{if .Required}} required{{end}}>{{$v := .Value}}{{range .Choices}}<option{{if eq . $v}} selected{{end}}>{{.}}</option>{{end}}</select>
    {{else if eq .Kind "agree"}}<input id="f-{{.Name}}" name="{{.Name}}" type="checkbox" value="yes"{{if .Required}} required{{end}}>
    {{else if eq .Kind "file"}}<input id="f-{{.Name}}" name="{{.Name}}" type="file" accept="{{.Accept}}"{{if .Required}} required{{end}}>
    {{else}}<input id="f-{{.Name}}" name="{{.Name}}" type="{{if eq .Kind "email"}}email{{else if eq .Kind "number"}}number{{else}}text{{end}}" value="{{.Value}}"{{if .Required}} required{{end}}>{{end}}{{if .When}}<br><span class="qz-small">{{.When}}</span>{{end}}</p>
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
{{if .V.Suggestions}}<ul class="qz-suggest" aria-label="Questions you could ask">{{range .V.Suggestions}}<li><a href="/ask/{{$.V.Assistant.Name}}?q={{.}}{{if $.V.EmbedValue}}&amp;embed={{$.V.EmbedValue}}{{end}}">{{.}}</a></li>{{end}}</ul>{{end}}
{{end}}
{{if .V.Rate}}<form method="post" action="/ask/{{.V.Assistant.Name}}/rate" class="qz-rate" aria-labelledby="qz-rate-label">
  <input type="hidden" name="q" value="{{.V.Question}}"><input type="hidden" name="t" value="{{.V.Rate}}">
  {{if .V.Visitor}}<input type="hidden" name="v" value="{{.V.Visitor}}">{{end}}
  {{if .V.Embedded}}<input type="hidden" name="embed" value="{{.V.EmbedValue}}">{{end}}
  <span id="qz-rate-label">Did this answer help?</span>
  <button type="submit" name="helpful" value="yes">Yes</button>
  <button type="submit" name="helpful" value="no">No</button>
</form>{{end}}
{{if .V.Rated}}<p class="qz-small" role="status">{{.V.Rated}}</p>{{end}}
{{if and .V.Answer .V.FollowUps}}<ul class="qz-suggest" aria-label="You could also ask">{{range .V.FollowUps}}<li><a href="/ask/{{$.V.Assistant.Name}}?q={{.}}{{if $.V.EmbedValue}}&amp;embed={{$.V.EmbedValue}}{{end}}">{{.}}</a></li>{{end}}</ul>{{end}}
{{if .V.Problem}}<p class="qz-problem" role="alert">{{.V.Problem}}</p>{{end}}
{{if and .V.Answer .V.Handoff}}
<details class="qz-handoff"{{if .V.Answer.Refused}} open{{end}}>
  <summary>Talk to a person instead</summary>
  <form method="post" action="{{.V.Handoff}}">
    <input type="hidden" name="q" value="{{.V.Question}}">
    {{if .V.Embedded}}<input type="hidden" name="embed" value="{{.V.EmbedValue}}">{{end}}
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
<form method="post" action="/ask/{{.V.Assistant.Name}}" class="qz-ask-form"{{if and .Tools (not .V.Embedded)}} toolname="ask-{{.V.Assistant.Name}}" tooldescription="{{.V.Assistant.Title}}: answers a question from this site's published pages only, and every sentence links to the page it came from." toolautosubmit{{end}}>
  {{if .V.Answer}}<input type="hidden" name="prev" value="{{.V.Question}}">{{end}}
  {{if .V.Visitor}}<input type="hidden" name="v" value="{{.V.Visitor}}">{{end}}
  {{if .V.Embedded}}<input type="hidden" name="embed" value="{{.V.EmbedValue}}">{{end}}
  <label for="q">{{if .V.Answer}}Ask another question{{else}}Your question{{end}}</label>
  <textarea id="q" name="q" rows="2" maxlength="1000" required{{if not .V.Embedded}} autofocus{{end}}{{if and .Tools (not .V.Embedded)}} toolparamdescription="The question, in plain words."{{end}}></textarea>
  <button type="submit">Ask</button>
</form>
<p class="qz-small">{{.Disclosure}} Answers come from this site's pages, and
  every sentence links to where it came from. {{if .V.Keeps}}A question it cannot answer, or whose
  answer you say did not help, is kept for a while with anything that could name you taken out, so the
  site can say it better; nothing else you ask is stored.{{else}}Nothing you ask is stored.{{end}}</p>
</main>{{.Voice}}</body></html>`))

// askCSS is the built-in page's stylesheet, served at /ask.css. Small and
// inheriting from the site's own, so an assistant looks like the site it is
// on rather than like a widget from somewhere else.
const askCSS = `.qz-ask main{max-width:42rem;margin:0 auto;padding:1.5rem 1rem 3rem}
.qz-turn{margin:1rem 0;padding:.9rem 1.1rem;border-radius:12px;border:1px solid color-mix(in srgb,currentColor 18%,transparent)}
.qz-q{font-weight:600;margin:0}
.qz-a p{margin:.4rem 0;line-height:1.6}
.qz-a sup a{text-decoration:none;font-size:.8em}
.qz-refused{opacity:.85}
.qz-rate{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center;margin:.6rem 0;font-size:.95em}
.qz-sources{font-size:.9em;padding-left:1.4rem}
.qz-offer{margin:1.2rem 0;padding:1rem 1.1rem;border-radius:12px;border:2px solid color-mix(in srgb,currentColor 30%,transparent)}
.qz-offer input:not([type=checkbox]),.qz-offer textarea,.qz-offer select,.qz-ask-form textarea{width:100%;box-sizing:border-box;font:inherit;padding:.5rem .6rem;border-radius:8px;border:1px solid color-mix(in srgb,currentColor 35%,transparent)}
.qz-ask-form{display:grid;gap:.5rem;margin-top:1.5rem}
.qz-ask-form button,.qz-offer button,.qz-button{justify-self:start;font:inherit;font-weight:600;padding:.55rem 1.1rem;border-radius:999px;border:0;cursor:pointer;text-decoration:none;display:inline-block;background:var(--primary,CanvasText);color:var(--on-primary,Canvas)}
.qz-hidden{position:absolute;left:-10000px;width:1px;height:1px;overflow:hidden}
.qz-problem{padding:.7rem 1rem;border-radius:8px;border:1px solid}
.qz-small{font-size:.85em;opacity:.75;margin-top:1.5rem}
.qz-embed main{padding:.75rem .75rem 1rem;max-width:none}
.qz-embed-title{font-weight:700;margin:0 0 .5rem}
.qz-embed h2{font-size:1rem;margin:1rem 0 .5rem}
.qz-cards{list-style:none;margin:1rem 0;padding:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,11rem),1fr));gap:.75rem}
.qz-card{display:flex;flex-direction:column;gap:.35rem;padding:.75rem;border-radius:var(--radius-lg,16px);border:1px solid var(--outline-variant,#c4c7c5);min-width:0}
.qz-card img{width:100%;aspect-ratio:4/3;object-fit:cover;border-radius:var(--radius-md,8px);max-width:100%}
.qz-card a{font-weight:700}.qz-card p{margin:0}.qz-card-meta{font-weight:600}
.qz-suggest{list-style:none;margin:.75rem 0 1rem;padding:0;display:flex;flex-direction:column;gap:.5rem}
.qz-suggest a{display:block;padding:.6rem .9rem;border-radius:var(--radius-lg,16px);border:1px solid var(--outline-variant,#c4c7c5);text-decoration:none;color:inherit}
.qz-suggest a:hover{background:color-mix(in srgb,currentColor 6%,transparent)}
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
.qz-home{margin:0 0 .75rem;font-size:.9em}
.qz-log{display:grid}
.qz-log .qz-q-turn{justify-self:end;max-width:85%;background:color-mix(in srgb,currentColor 7%,transparent)}
.qz-sources-title{font-size:1em;margin:.8rem 0 .2rem}
.qz-status{font-size:.9em;opacity:.8;margin:.5rem 0}
.qz-status:empty{display:none}
.qz-account .qz-turn h2{font-size:1.2rem;margin:0 0 .5rem}
.qz-account .qz-turn{padding:1.1rem 1.3rem}
.qz-account .qz-turn p+form{margin-top:.75rem}
.qz-account input:not([type=hidden]){width:100%;box-sizing:border-box;font:inherit;padding:.5rem .6rem;border-radius:8px;border:1px solid color-mix(in srgb,currentColor 35%,transparent);margin:.25rem 0 .6rem}
.qz-codes{font-family:var(--font-mono,ui-monospace,monospace);columns:2 12rem;padding-left:1.6rem}
.qz-keys{list-style:none;padding:0}.qz-keys li{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem;padding:.4rem 0}
.qz-keys form{margin-left:auto}
.qz-inline{display:inline-block;margin-right:.5rem}
.qz-notice{padding:.7rem 1rem;border-radius:8px;background:color-mix(in srgb,currentColor 7%,transparent)}
.qz-danger{border-color:color-mix(in srgb,#b3261e 45%,transparent)}
.qz-sr{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}
.qz-ask-row{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center}
.qz-voice-btn{display:inline-flex;align-items:center;gap:.4rem;font:inherit;font-weight:600;padding:.45rem .95rem;border-radius:999px;border:1px solid color-mix(in srgb,currentColor 35%,transparent);background:transparent;color:inherit;cursor:pointer;min-height:2.5rem}
.qz-voice-btn[aria-pressed=true]{background:color-mix(in srgb,currentColor 12%,transparent)}
.qz-icon{width:1.25em;height:1.25em;fill:currentColor;flex:none}
.qz-read,.qz-tr-offer{margin:.25rem 0 .5rem}
.qz-speaking{background:color-mix(in srgb,currentColor 8%,transparent);border-radius:6px;box-shadow:0 0 0 4px color-mix(in srgb,currentColor 8%,transparent)}
.qz-link{border:0;padding:0;min-height:0;background:none;text-decoration:underline;color:inherit;font:inherit;cursor:pointer}
.qz-tr-note{margin:0 0 .5rem}
.qz-voice-note{margin-top:0}
.qz-voice-status{margin-top:.5rem}.qz-voice-status:empty{display:none}
@media (prefers-reduced-motion:no-preference){.qz-mic[aria-pressed=true] .qz-icon{animation:qz-listen 1.2s ease-in-out infinite}}
@keyframes qz-listen{50%{opacity:.35}}
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
func allowFraming(h http.Header, origins []string, self bool) {
	var ok []string
	for _, o := range origins {
		if n, err := assistant.Origin(o); err == nil {
			ok = append(ok, n)
		}
	}
	// The launcher's panel is this site framing itself, and needs no
	// declared origin; anything else needs one.
	if len(ok) == 0 && !self {
		return
	}
	value := strings.TrimSpace("frame-ancestors 'self' " + strings.Join(ok, " "))
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

// questionAllowed spends one question from the visitor's allowance: the
// signed-in member's when there is one, the address's otherwise.
func (st *Site) questionAllowed(r *http.Request) (bool, time.Duration) {
	l := st.Assistants.Questions
	if l == nil {
		return true, 0
	}
	key := "a:" + sourceOf(r)
	if m, ok := st.signedIn(r); ok && m.ID != "" {
		key = "m:" + m.ID
	}
	return l.Allow(key, time.Now())
}

// inAbout is a wait as a visitor reads it.
func inAbout(d time.Duration) string {
	switch s := int(d.Round(time.Second).Seconds()); {
	case s <= 1:
		return "in a second"
	case s < 60:
		return fmt.Sprintf("in about %d seconds", s)
	case s < 120:
		return "in about a minute"
	default:
		return fmt.Sprintf("in about %d minutes", (s+59)/60)
	}
}

// visitorToken is a token as it may be carried: short, one line, and the
// characters a signed token has, or nothing.
func visitorToken(s string) string {
	if s == "" || len(s) > assistant.MaxVisitorToken {
		return ""
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return ""
		}
	}
	return s
}
