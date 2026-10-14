// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/schema"
)

// Asking Today a question, and keeping the answer.
//
// The answer is a view made of cards from a fixed set, which this program
// draws: a figure, a table, bars, what is waiting, agent runs. The model
// chooses the cards and what each one asks of the records; it never sees a
// record and never writes a value. It is told the collections the person
// may read, by their fields, and the agents they may manage, and it answers
// in JSON that names those and nothing else. Every card is then checked as
// a listing is, against what the person may read, and filled in here.
//
// The same reasons as the brief, and two more. Choosing from declared
// fields and conditions is how question-answering over data is made
// reliable: a wrong choice shows up as a card that cannot be drawn, not as
// a plausible wrong number. And nothing the model writes is markup or
// script: the cards are this program's own templates, so the admin's
// policy of running no script it did not ship stands.
//
// Each card says in words what it counted, so the person checks the
// question that was asked of their data and not only the answer. A view
// worth keeping is pinned to Today and drawn afresh on every visit, with
// what the person may read then.

// Ask reaches the model and the views people keep.
type Ask struct {
	// Model is the model a person's questions are answered with, charged
	// to them; nil when asking is off or no model is set up.
	Model func(person string) assist.Model
	// Load and Save keep each person's pinned views.
	Load func(person string) ([]SavedView, error)
	Save func(person string, views []SavedView) error
}

// SavedView is an answer somebody pinned to Today: what they asked and the
// cards, never the values, which are read again on every visit.
type SavedView struct {
	ID       string    `json:"id"`
	Question string    `json:"question"`
	Title    string    `json:"title"`
	Cards    []AskCard `json:"cards"`
	Pinned   time.Time `json:"pinned"`
}

// AskCard is one card in a view.
type AskCard struct {
	Kind       string              `json:"kind"`
	Collection string              `json:"collection,omitempty"`
	Where      []listing.Condition `json:"where,omitempty"`
	Fields     []string            `json:"fields,omitempty"`
	Sort       string              `json:"sort,omitempty"`
	Descending bool                `json:"descending,omitempty"`
	Rows       int                 `json:"rows,omitempty"`
	Op         string              `json:"op,omitempty"`
	Field      string              `json:"field,omitempty"`
	By         string              `json:"by,omitempty"`
	Agent      string              `json:"agent,omitempty"`
	Outcome    string              `json:"outcome,omitempty"`
	Days       int                 `json:"days,omitempty"`
	Commits    string              `json:"commits,omitempty"`
}

const (
	maxAskCards   = 4
	maxAskRows    = 25
	maxAskFields  = 5
	maxAskBars    = 12
	maxSavedViews = 12
	maxQuestion   = 300
)

// askSources is what a person's question may be answered from.
type askSources struct {
	Types  map[string]schema.Type // by collection
	Agents []string
}

// askAllowed is whether a person may ask: somebody who may use the store's
// models somewhere, other than one who only reads the evidence, while a
// model is set up.
func (s *Server) askAllowed(p principal) bool {
	if s.Ask == nil || s.Ask.Model == nil {
		return false
	}
	if s.Policy == nil {
		return true
	}
	return s.Policy.AnywhereUnder(p.Name, auth.ActUseModels, "/") && !s.evidenceOnly(p)
}

// sourcesFor is the collections a person may read that have a type, and
// the agents they may manage.
func (s *Server) sourcesFor(p principal) askSources {
	out := askSources{Types: map[string]schema.Type{}}
	if s.Types != nil && s.Types.Load != nil {
		if st, err := s.Types.Load(); err == nil {
			for c, t := range st.Collections {
				if typ, ok := st.Registry.Get(t); ok && s.allows(p, auth.ActView, auth.DataResource(c)) {
					out.Types[c] = typ
				}
			}
		}
	}
	if s.Agents != nil && s.Agents.Load != nil && s.allows(p, auth.ActManageAgents, auth.AreaAgents) {
		if declared, err := s.Agents.Load(); err == nil {
			for name := range declared {
				if reAgentName.MatchString(name) {
					out.Agents = append(out.Agents, name)
				}
			}
			sort.Strings(out.Agents)
		}
	}
	return out
}

const askSystem = `You turn a question about a Quilzo store into a view made of cards. You never see the records and never write a value: Quilzo fills every card in from the records the person may read.

Answer with one JSON object and nothing else: {"title": "a few words", "cards": [one to four cards]}. The cards are:
- {"kind":"figure","collection":C,"where":[conditions],"op":"count"}, or op "sum", "min" or "max" with "field": one number about the records that match.
- {"kind":"table","collection":C,"where":[conditions],"fields":[up to five fields],"sort":F,"descending":true or false,"rows":up to 25}: the records that match.
- {"kind":"bars","collection":C,"where":[conditions],"by":F}: how many matching records have each value of F.
- {"kind":"waiting","commits":K}: decisions waiting for the person; commits is optional, one of answers, installs, pays, deletes, publishes, sends, writes, acts, reads.
- {"kind":"runs","agent":A,"outcome":O,"days":D}: agent runs in the last D days, one to thirty; agent and outcome are optional, outcome one of complete, failed, waiting, running. Only when agents are listed.

A condition is {"field":F,"match":"is","value":V} for an exact value, or "match":"has" for text containing V. Use only the collections, fields, choices and agents listed. If the question cannot be answered with these cards, answer {"title":"","cards":[]}.`

// askPrompt is the person's sources and question, as the model reads them.
func askPrompt(src askSources, question string) string {
	var b strings.Builder
	b.WriteString("Collections you may use:\n")
	names := make([]string, 0, len(src.Types))
	for c := range src.Types {
		names = append(names, c)
	}
	sort.Strings(names)
	for _, c := range names {
		var fields []string
		for _, f := range src.Types[c].Fields {
			d := fmt.Sprintf("%s (%s", f.Name, f.Kind)
			if len(f.Choices) > 0 {
				d += ": " + strings.Join(f.Choices, ", ")
			}
			fields = append(fields, d+")")
		}
		fmt.Fprintf(&b, "- %s: %s\n", c, strings.Join(fields, "; "))
	}
	if len(names) == 0 {
		b.WriteString("- none\n")
	}
	if len(src.Agents) > 0 {
		fmt.Fprintf(&b, "Agents you may ask about: %s\n", strings.Join(src.Agents, ", "))
	}
	fmt.Fprintf(&b, "Question: %s\n", question)
	return b.String()
}

// readAsk keeps the cards of a model's answer that name only what the
// person may use, each within its bounds, and says what it left out.
func readAsk(answer string, src askSources) (string, []AskCard, []string) {
	answer = strings.TrimSpace(answer)
	start, end := strings.Index(answer, "{"), strings.LastIndex(answer, "}")
	if start < 0 || end <= start {
		return "", nil, []string{"the model's answer held no view"}
	}
	var raw struct {
		Title string    `json:"title"`
		Cards []AskCard `json:"cards"`
	}
	if err := json.Unmarshal([]byte(answer[start:end+1]), &raw); err != nil {
		return "", nil, []string{"the model's answer was not a view: " + clipText(err.Error(), 120)}
	}
	title := strings.TrimSpace(raw.Title)
	if len(title) > 80 || reNotProse.MatchString(title) {
		title = ""
	}
	var cards []AskCard
	var notes []string
	for i, c := range raw.Cards {
		if len(cards) == maxAskCards {
			notes = append(notes, fmt.Sprintf("left out %d more cards; a view has at most %d", len(raw.Cards)-i, maxAskCards))
			break
		}
		if err := checkCard(&c, src); err != nil {
			notes = append(notes, fmt.Sprintf("left out a %s card: %v", clipText(c.Kind, 20), err))
			continue
		}
		cards = append(cards, c)
	}
	return title, cards, notes
}

var askCommits = map[string]bool{"answers": true, "installs": true, "pays": true, "deletes": true,
	"publishes": true, "sends": true, "writes": true, "acts": true, "reads": true}

var askOutcomes = map[string]bool{"complete": true, "failed": true, "waiting": true, "running": true}

// checkCard holds a card to its kind's rules and the person's sources, and
// trims what it may hold to what it uses.
func checkCard(c *AskCard, src askSources) error {
	switch c.Kind {
	case "waiting":
		if c.Commits != "" && !askCommits[c.Commits] {
			return fmt.Errorf("%q is not a kind of decision", c.Commits)
		}
		*c = AskCard{Kind: c.Kind, Commits: c.Commits}
		return nil
	case "runs":
		if c.Agent != "" && !slices.Contains(src.Agents, c.Agent) {
			return fmt.Errorf("%q is not an agent you may ask about", c.Agent)
		}
		if len(src.Agents) == 0 {
			return fmt.Errorf("you may not ask about agents")
		}
		if c.Outcome != "" && !askOutcomes[c.Outcome] {
			return fmt.Errorf("%q is not an outcome", c.Outcome)
		}
		if c.Days < 1 || c.Days > 30 {
			c.Days = 7
		}
		*c = AskCard{Kind: c.Kind, Agent: c.Agent, Outcome: c.Outcome, Days: c.Days}
		return nil
	case "figure", "table", "bars":
	default:
		return fmt.Errorf("there is no such card")
	}
	typ, ok := src.Types[c.Collection]
	if !ok {
		return fmt.Errorf("%q is not a collection you may read", c.Collection)
	}
	has := map[string]schema.Field{}
	for _, f := range typ.Fields {
		has[f.Name] = f
	}
	field := func(name string) bool { _, ok := has[name]; return ok }
	for _, w := range c.Where {
		if !field(w.Field) || w.Param != "" || (w.Match != listing.Is && w.Match != listing.Has) || len(w.Value) > 120 {
			return fmt.Errorf("a condition on %q is not one this card can use", w.Field)
		}
	}
	switch c.Kind {
	case "figure":
		switch c.Op {
		case "", "count":
			c.Op, c.Field = "count", ""
		case "sum", "min", "max":
			if f, ok := has[c.Field]; !ok || f.Kind != schema.Number {
				return fmt.Errorf("%s needs a number field", c.Op)
			}
		default:
			return fmt.Errorf("%q is not something a figure does", c.Op)
		}
		*c = AskCard{Kind: c.Kind, Collection: c.Collection, Where: c.Where, Op: c.Op, Field: c.Field}
	case "table":
		var fields []string
		for _, f := range c.Fields {
			if field(f) && !slices.Contains(fields, f) && len(fields) < maxAskFields {
				fields = append(fields, f)
			}
		}
		if len(fields) == 0 {
			return fmt.Errorf("a table needs fields of %q", c.Collection)
		}
		if c.Sort != "" && !field(c.Sort) {
			c.Sort = ""
		}
		if c.Rows < 1 || c.Rows > maxAskRows {
			c.Rows = 10
		}
		*c = AskCard{Kind: c.Kind, Collection: c.Collection, Where: c.Where, Fields: fields, Sort: c.Sort,
			Descending: c.Descending, Rows: c.Rows}
	case "bars":
		if !field(c.By) {
			return fmt.Errorf("bars need a field of %q to count by", c.Collection)
		}
		*c = AskCard{Kind: c.Kind, Collection: c.Collection, Where: c.Where, By: c.By}
	}
	l := cardListing(*c)
	return l.Validate()
}

// cardListing is a card over records as the listing it amounts to.
func cardListing(c AskCard) listing.Listing {
	l := listing.Listing{Name: "ask", Collection: c.Collection, Where: c.Where, Fields: c.Fields,
		Sort: c.Sort, Descending: c.Descending, Rows: c.Rows}
	switch c.Kind {
	case "figure":
		l.Fields, l.Rows = []string{"id"}, 1
		if c.Op != "count" {
			l.Fields = []string{c.Field}
			l.Agg = []listing.Agg{{Op: listing.Op(c.Op), Field: c.Field, As: "value"}}
		}
	case "bars":
		l.Fields, l.Rows = []string{c.By}, 1
	}
	return l
}

// shownCard is a card drawn.
type shownCard struct {
	Kind, Says, Problem string
	Figure              string
	Href                string
	Cols                []string
	Cells               [][]string
	Links               []string
	Bars                []shownBar
	More                int
	Waiting             []approvalItem
}

type shownBar struct {
	Label string
	N     int
	W     int
}

// drawCard fills a card in from what the person may read now.
func (s *Server) drawCard(p principal, c AskCard, now time.Time) shownCard {
	out := shownCard{Kind: c.Kind, Says: cardWords(c)}
	switch c.Kind {
	case "waiting":
		for _, it := range s.waitingItems(p, now) {
			if c.Commits == "" || it.Commits == c.Commits {
				out.Waiting = append(out.Waiting, it)
			}
		}
		out.Figure, out.Href = fmt.Sprint(len(out.Waiting)), "/approvals"
		if c.Commits != "" {
			out.Href += "?commits=" + c.Commits
		}
		return out
	case "runs":
		if !s.allows(p, auth.ActManageAgents, auth.AreaAgents) || s.Agents == nil || s.Agents.Runs == nil {
			out.Problem = "you may no longer read agent runs"
			return out
		}
		runs, err := s.Agents.Runs(c.Agent)
		if err != nil {
			out.Problem = err.Error()
			return out
		}
		out.Cols = []string{"agent", "outcome", "started"}
		n := 0
		for _, rec := range runs {
			if rec.Eval != "" || now.Sub(rec.Started) > time.Duration(c.Days)*24*time.Hour {
				continue
			}
			outcome := rec.OutcomeAt(now)
			if c.Outcome == "failed" && (outcome == "refused" || outcome == "interrupted" || outcome == "stopped") {
				outcome = "failed"
			}
			if c.Outcome != "" && outcome != c.Outcome && !(c.Outcome == "running" && outcome == agent.Running) {
				continue
			}
			n++
			if len(out.Cells) < maxAskRows {
				out.Cells = append(out.Cells, []string{rec.Agent, rec.OutcomeAt(now), agoText(now.Sub(rec.Started))})
				out.Links = append(out.Links, "/agents/run/"+rec.ID)
			}
		}
		out.Figure, out.More, out.Href = fmt.Sprint(n), n-len(out.Cells), "/agents"
		return out
	}
	if !s.allows(p, auth.ActView, auth.DataResource(c.Collection)) || s.Records == nil {
		out.Problem = fmt.Sprintf("you may no longer read %s", c.Collection)
		return out
	}
	tree, _ := draftTreeOf(s)
	idx, err := s.Records.For(s.Store, tree, c.Collection)
	if err != nil {
		out.Problem = err.Error()
		return out
	}
	l := cardListing(c)
	out.Href = "/records?c=" + c.Collection
	switch c.Kind {
	case "bars":
		counts, total, err := listing.CountBy(&l, idx, c.By, nil)
		if err != nil {
			out.Problem = err.Error()
			return out
		}
		top := 0
		for v, n := range counts {
			if v == "" {
				v = "(none)"
			}
			out.Bars = append(out.Bars, shownBar{Label: v, N: n})
			top = max(top, n)
		}
		sort.Slice(out.Bars, func(i, j int) bool {
			if out.Bars[i].N != out.Bars[j].N {
				return out.Bars[i].N > out.Bars[j].N
			}
			return out.Bars[i].Label < out.Bars[j].Label
		})
		if len(out.Bars) > maxAskBars {
			out.More = len(out.Bars) - maxAskBars
			out.Bars = out.Bars[:maxAskBars]
		}
		for i := range out.Bars {
			out.Bars[i].W = 1 + out.Bars[i].N*199/max(top, 1)
		}
		out.Figure = fmt.Sprint(total)
		return out
	}
	res, err := listing.Resolve(&l, idx, nil)
	if err != nil {
		out.Problem = err.Error()
		return out
	}
	switch c.Kind {
	case "figure":
		if c.Op == "count" {
			out.Figure = fmt.Sprint(res.Total)
		} else if v, ok := res.Agg["value"]; ok && v != nil {
			out.Figure = fmt.Sprint(v)
		} else {
			out.Figure = "nothing to " + c.Op
		}
	case "table":
		out.Cols, out.Cells = previewTable(c.Fields, res.Rows)
		out.Figure, out.More = fmt.Sprint(res.Total), res.Total-len(res.Rows)
	}
	return out
}

// cardWords says what a card counts, so the question asked of the records
// can be checked as well as the answer.
func cardWords(c AskCard) string {
	where := ""
	for i, w := range c.Where {
		join := " where "
		if i > 0 {
			join = " and "
		}
		verb := "is"
		if w.Match == listing.Has {
			verb = "contains"
		}
		where += fmt.Sprintf("%s%s %s %q", join, w.Field, verb, w.Value)
	}
	switch c.Kind {
	case "figure":
		if c.Op == "count" {
			return "How many records in " + c.Collection + where
		}
		return fmt.Sprintf("The %s of %s over records in %s%s", map[string]string{"sum": "total", "min": "least", "max": "most"}[c.Op], c.Field, c.Collection, where)
	case "table":
		by := ""
		if c.Sort != "" {
			by = ", by " + c.Sort
			if c.Descending {
				by += ", highest first"
			}
		}
		return fmt.Sprintf("Records in %s%s%s, showing %s", c.Collection, where, by, strings.Join(c.Fields, ", "))
	case "bars":
		return fmt.Sprintf("Records in %s%s, counted by %s", c.Collection, where, c.By)
	case "waiting":
		if c.Commits != "" {
			return "Decisions waiting for you that " + commitWords[c.Commits]
		}
		return "Decisions waiting for you"
	case "runs":
		who := "every agent you manage"
		if c.Agent != "" {
			who = "the agent " + c.Agent
		}
		what := "Runs"
		if c.Outcome != "" {
			what = map[string]string{"complete": "Finished runs", "failed": "Failed runs", "waiting": "Runs waiting", "running": "Runs going"}[c.Outcome]
		}
		return fmt.Sprintf("%s of %s in the last %d days", what, who, c.Days)
	}
	return ""
}

// asked is a person's latest answer, kept until they ask again or pin it.
type asked struct {
	Question, Title string
	Cards           []AskCard
	Notes           []string
	Problem         string
}

type askCache struct {
	mu sync.Mutex
	by map[string]*asked
}

func (s *Server) lastAsked(p principal) *asked {
	if s.asks == nil {
		return nil
	}
	s.asks.mu.Lock()
	defer s.asks.mu.Unlock()
	return s.asks.by[p.Name]
}

// handleTodayAsk asks the model to build a view for a question.
func (s *Server) handleTodayAsk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.askAllowed(p) || s.asks == nil {
		http.Error(w, "asking is not offered to you here", http.StatusForbidden)
		return
	}
	question := strings.TrimSpace(strings.Join(strings.Fields(r.FormValue("question")), " "))
	if question == "" {
		http.Redirect(w, r, "/today", http.StatusSeeOther)
		return
	}
	if len(question) > maxQuestion {
		question = question[:maxQuestion]
	}
	a := &asked{Question: question}
	model := s.Ask.Model(p.Name)
	src := s.sourcesFor(p)
	if model == nil {
		a.Problem = "No model is set up to answer with."
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		answer, err := model.Complete(ctx, askSystem, askPrompt(src, question))
		cancel()
		if err != nil {
			a.Problem = "The model did not answer: " + clipText(err.Error(), 200)
		} else {
			a.Title, a.Cards, a.Notes = readAsk(answer, src)
			if len(a.Cards) == 0 && a.Problem == "" {
				a.Problem = "That cannot be answered with the cards Today draws, from what you may read."
			}
		}
	}
	if a.Title == "" {
		a.Title = question
	}
	s.asks.mu.Lock()
	if s.asks.by == nil {
		s.asks.by = map[string]*asked{}
	}
	s.asks.by[p.Name] = a
	s.asks.mu.Unlock()
	kinds := make([]string, 0, len(a.Cards))
	for _, c := range a.Cards {
		kinds = append(kinds, c.Kind)
	}
	s.audit("today.ask", "/", map[string]string{"by": p.Name, "cards": strings.Join(kinds, " "),
		"dropped": fmt.Sprint(len(a.Notes))})
	http.Redirect(w, r, "/today#answer", http.StatusSeeOther)
}

// handleTodayPin keeps the latest answer on Today, or takes a kept one off.
func (s *Server) handleTodayPin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if s.Ask == nil || s.Ask.Load == nil || s.Ask.Save == nil {
		http.Error(w, "views cannot be kept here", http.StatusNotFound)
		return
	}
	views, err := s.Ask.Load(p.Name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	switch r.FormValue("do") {
	case "pin":
		a := s.lastAsked(p)
		if a == nil || len(a.Cards) == 0 {
			http.Redirect(w, r, "/today", http.StatusSeeOther)
			return
		}
		if len(views) >= maxSavedViews {
			http.Error(w, fmt.Sprintf("Today keeps at most %d views; take one off first", maxSavedViews), http.StatusConflict)
			return
		}
		id := make([]byte, 6)
		if _, err := rand.Read(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		views = append(views, SavedView{ID: hex.EncodeToString(id), Question: a.Question, Title: a.Title,
			Cards: a.Cards, Pinned: time.Now().UTC()})
		s.asks.mu.Lock()
		delete(s.asks.by, p.Name)
		s.asks.mu.Unlock()
	case "unpin":
		id := r.FormValue("id")
		views = slices.DeleteFunc(views, func(v SavedView) bool { return v.ID == id })
	default:
		http.Error(w, "pin or unpin", http.StatusBadRequest)
		return
	}
	if err := s.Ask.Save(p.Name, views); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/today#views", http.StatusSeeOther)
}

// shownView is a kept or new view, drawn.
type shownView struct {
	ID, Title, Question string
	Cards               []shownCard
	Notes               []string
	Problem             string
}

func (s *Server) drawView(p principal, id, title, question string, cards []AskCard, now time.Time) shownView {
	v := shownView{ID: id, Title: title, Question: question}
	for _, c := range cards {
		v.Cards = append(v.Cards, s.drawCard(p, c, now))
	}
	return v
}
