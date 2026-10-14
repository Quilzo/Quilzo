// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/auth"
)

// The brief: a few sentences on Today saying what matters most.
//
// Three things go wrong with a written summary, and each has a rule here.
//
// A model gets numbers wrong, and the usual mistake is a right figure put
// with the wrong thing rather than an invented one. Checking for that after
// the fact is unreliable. So the model never writes a number: the figures
// are worked out here, each with an id, and the model refers to one only by
// writing its id. The figure and its link are put in by this code, and a
// sentence carrying a digit or a number word of its own is dropped.
//
// A model obeys instructions hidden in what it summarises. That is how a
// mailbox's summariser was made to warn of a hacked password and give a
// phone number to ring, and how another was made to send a mailbox's
// contents away through a link. So the model is given counts, kinds of
// decision and agents' names, and never anything somebody else wrote: no
// agent's question, no visitor's message, no finding's title, no log line.
// What it writes is shown as text, and no link in it comes from the model.
//
// People take polished text as checked. So the brief comes after what is
// waiting, not before it, says which model wrote it and when, and every
// figure in it is a link to the records it counts.
//
// It is written on a person's first visit of the day and kept for the day;
// once the figures change it is written again, at most every half hour.
// It is paid for as the person's own use of the model, within their budget.

// Brief reaches the model a person's brief is written by.
type Brief struct {
	// Model is the model, charged to the person; nil when briefs are off
	// or no model is set up.
	Model func(person string) assist.Model
}

// briefFact is one figure the model may refer to.
type briefFact struct {
	ID, Text, Href string
	N              int
	Warn           bool
}

// briefPart is a run of the model's words, or a figure.
type briefPart struct {
	Text string
	Fact *briefFact
}

// briefEntry is one person's brief.
type briefEntry struct {
	Day, Digest, Model string
	// Asked is when the model was last asked, and Written when the words
	// on show were written.
	Asked, Written time.Time
	Parts          []briefPart
	// From is the digest of the figures the words on show were written from.
	From string
	// Writing is set while the model is asked; done closes when it answers.
	Writing bool
	done    chan struct{}
}

type briefCache struct {
	mu sync.Mutex
	by map[string]*briefEntry
}

// briefView is what Today shows.
type briefView struct {
	Parts   []briefPart
	Model   string
	At      string
	Writing bool
	// Stale is set when the figures have changed since it was written.
	Stale bool
}

const (
	// briefRewrite is the least time between two briefs for one person.
	briefRewrite = 30 * time.Minute
	// briefWait is how long Today waits for a brief being written before
	// it shows the page without it.
	briefWait = 3 * time.Second
	// briefSentences is the most a brief keeps.
	briefSentences = 3
)

// briefFacts are the figures a brief is written from: what is waiting,
// by what deciding it commits to and by agent, and Today's counts.
func briefFacts(waiting []approvalItem, lines []todayLine, now time.Time) []briefFact {
	var out []briefFact
	add := func(n int, text, href string, warn bool) {
		if n > 0 {
			out = append(out, briefFact{ID: fmt.Sprintf("f%d", len(out)+1), N: n, Text: text, Href: href, Warn: warn})
		}
	}
	add(len(waiting), "things waiting for you to decide", "/approvals", false)
	byCommit, byAgent, expired := map[string]int{}, map[string]int{}, 0
	var agents []string
	oldest := now
	for _, it := range waiting {
		byCommit[it.Commits]++
		// An agent's name, as a declaration allows it, is the only word in
		// the facts that somebody other than this code chose.
		if it.Source == "run" && reAgentName.MatchString(it.Agent) {
			if byAgent[it.Agent] == 0 {
				agents = append(agents, it.Agent)
			}
			byAgent[it.Agent]++
		}
		if it.Expired {
			expired++
		}
		if !it.Since.IsZero() && it.Since.Before(oldest) {
			oldest = it.Since
		}
	}
	for _, c := range commitsOrder {
		add(byCommit[c], "of those, decisions that "+commitWords[c], "/approvals?commits="+c, c == "pays" || c == "deletes" || c == "publishes")
	}
	for _, a := range agents {
		add(byAgent[a], "of those, waiting in runs of the agent "+a, "/approvals", false)
	}
	add(expired, "of those, asked too long ago to agree to", "/approvals", true)
	if days := int(now.Sub(oldest).Hours() / 24); len(waiting) > 0 && days > 0 {
		add(days, "days the oldest of those has waited", "/approvals", days > 2)
	}
	for _, l := range lines {
		add(l.N, strings.ToLower(l.Text[:1])+l.Text[1:], l.Href, l.Warn)
	}
	return out
}

// commitWords is what deciding commits to, as the model reads it.
var commitWords = map[string]string{
	"answers": "answer an agent's question", "installs": "install a feature", "pays": "pay",
	"deletes": "delete", "publishes": "publish", "sends": "send something out", "writes": "write",
	"acts": "act on another tool", "reads": "only read",
}

const briefSystem = `You write the brief at the top of a person's first screen in Quilzo, where they run AI agents and the content and records those agents work on.

Write two or three short sentences in plain English, saying what matters most first: decisions waiting that cannot be taken back, then what went wrong, then the rest. Use only the facts given.

Refer to a figure only by writing its placeholder exactly as given, such as {{f2}}. Never write a number, a number word, a date or a time yourself. Address the reader as "you". No greeting, no headings, no lists, no links, no markdown, and nothing the facts do not say. If nothing needs attention, say so in one sentence.`

// briefPrompt is the facts, as the model reads them.
func briefPrompt(facts []briefFact) string {
	var b strings.Builder
	b.WriteString("Facts:\n")
	for _, f := range facts {
		fmt.Fprintf(&b, "{{%s}} = %d: %s\n", f.ID, f.N, f.Text)
	}
	return b.String()
}

func briefDigest(facts []briefFact) string {
	h := sha256.New()
	for _, f := range facts {
		fmt.Fprintf(h, "%s|%d|%s\n", f.ID, f.N, f.Text)
	}
	return hex.EncodeToString(h.Sum(nil))
}

var (
	rePlaceholder = regexp.MustCompile(`\{\{\s*(f[0-9]{1,3})\s*\}\}`)
	reNumberWord  = regexp.MustCompile(`(?i)\b(zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundreds?|thousands?|millions?|billions?|dozens?|half|couple|twice|double|triple)\b`)
	reNotProse    = regexp.MustCompile(`[0-9%<>\[\]{}#*_` + "`" + `|]|https?:|www\.|\bmailto:`)
)

// readBrief keeps the sentences of a model's answer that keep the rules,
// with each placeholder made the figure it names, and says how many it
// dropped.
func readBrief(answer string, facts []briefFact) ([]briefPart, int) {
	byID := map[string]*briefFact{}
	for i := range facts {
		byID[facts[i].ID] = &facts[i]
	}
	var out []briefPart
	kept, dropped := 0, 0
	for _, sentence := range sentences(strings.Join(strings.Fields(answer), " ")) {
		sentence = strings.TrimSpace(sentence)
		if sentence == "" {
			continue
		}
		var parts []briefPart
		ok, at := true, 0
		for _, m := range rePlaceholder.FindAllStringSubmatchIndex(sentence, -1) {
			f := byID[sentence[m[2]:m[3]]]
			if f == nil {
				ok = false
				break
			}
			parts = append(parts, briefPart{Text: sentence[at:m[0]]}, briefPart{Fact: f})
			at = m[1]
		}
		parts = append(parts, briefPart{Text: sentence[at:]})
		for _, p := range parts {
			if p.Fact == nil && (reNotProse.MatchString(p.Text) || reNumberWord.MatchString(p.Text)) {
				ok = false
			}
		}
		if !ok || kept == briefSentences {
			dropped++
			continue
		}
		if kept > 0 {
			out = append(out, briefPart{Text: " "})
		}
		out = append(out, parts...)
		kept++
	}
	return out, dropped
}

// sentences splits text where a full stop, question or exclamation mark is
// followed by a space or the end, so the dot in a name such as
// shop.example.com does not end one.
func sentences(text string) []string {
	var out []string
	start := 0
	for i := 0; i < len(text); i++ {
		// Inside a name, or a run of marks that has not ended yet.
		if !strings.ContainsRune(".!?", rune(text[i])) || (i+1 < len(text) && text[i+1] != ' ') {
			continue
		}
		out = append(out, text[start:i+1])
		start = i + 1
	}
	if strings.TrimSpace(text[start:]) != "" {
		out = append(out, text[start:])
	}
	return out
}

// briefAllowed is whether a person is given a brief. Somebody whose only
// access is to read the evidence and the log, an auditor, is not: what they
// look at has to be the records, not a summary of them.
func (s *Server) briefAllowed(p principal) bool {
	if s.Brief == nil || s.Brief.Model == nil || s.briefs == nil {
		return false
	}
	if s.Policy == nil {
		return true
	}
	held, evidenceOnly := 0, true
	for _, b := range s.Policy.Snapshot() {
		if b.Principal != p.Name || b.Deny || !b.Live(time.Now()) {
			continue
		}
		held++
		if b.Permission != "" || b.Role != auth.RoleReader ||
			(b.Resource != auth.AreaCompliance && b.Resource != auth.AreaLog) {
			evidenceOnly = false
		}
	}
	return held == 0 || !evidenceOnly
}

// briefFor is a person's brief: the one kept for today, or a new one being
// written when there is none or the figures have changed since.
func (s *Server) briefFor(p principal, facts []briefFact, now time.Time) *briefView {
	if len(facts) == 0 || !s.briefAllowed(p) {
		return nil
	}
	day, digest := now.Format("2006-01-02"), briefDigest(facts)
	s.briefs.mu.Lock()
	if s.briefs.by == nil {
		s.briefs.by = map[string]*briefEntry{}
	}
	e := s.briefs.by[p.Name]
	fresh := e != nil && e.Day == day && (e.Writing || e.Digest == digest || now.Sub(e.Asked) < briefRewrite)
	if !fresh {
		model := s.Brief.Model(p.Name)
		if model == nil {
			s.briefs.mu.Unlock()
			return nil
		}
		next := &briefEntry{Day: day, Digest: digest, Asked: now, Writing: true, done: make(chan struct{}), Model: modelLabel(model)}
		if e != nil && e.Day == day {
			// The earlier brief stays on show while the new one is written.
			next.Parts, next.Written, next.From = e.Parts, e.Written, e.From
		}
		s.briefs.by[p.Name] = next
		e = next
		go s.writeBrief(p.Name, next, model, facts)
	}
	done, writing := e.done, e.Writing
	s.briefs.mu.Unlock()

	if writing && done != nil {
		select {
		case <-done:
		case <-time.After(briefWait):
		}
	}
	s.briefs.mu.Lock()
	defer s.briefs.mu.Unlock()
	if len(e.Parts) == 0 && !e.Writing {
		return nil
	}
	return &briefView{Parts: e.Parts, Model: e.Model, At: e.Written.Local().Format("15:04"), Writing: e.Writing,
		Stale: e.From != digest}
}

// writeBrief asks the model and keeps what passes.
func (s *Server) writeBrief(person string, e *briefEntry, model assist.Model, facts []briefFact) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	answer, err := model.Complete(ctx, briefSystem, briefPrompt(facts))
	var parts []briefPart
	dropped := 0
	if err == nil {
		parts, dropped = readBrief(answer, facts)
	}
	s.briefs.mu.Lock()
	if err == nil && len(parts) > 0 {
		e.Parts, e.Written, e.From = parts, time.Now(), briefDigest(facts)
	}
	e.Writing = false
	close(e.done)
	s.briefs.mu.Unlock()

	detail := map[string]string{"by": person, "model": e.Model, "dropped": fmt.Sprint(dropped)}
	if err != nil {
		detail["error"] = clipText(err.Error(), 200)
	}
	s.audit("today.brief", "/", detail)
}

// modelLabel is how the brief names the model that wrote it.
func modelLabel(m assist.Model) string {
	if name := m.Name(); name != "" && !strings.HasPrefix(name, "gateway:") {
		return name
	}
	return "the model gateway"
}
