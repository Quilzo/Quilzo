// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package scribe

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Span is one stretch of transcript: somebody saying something.
type Span struct {
	Index int           `json:"index"`
	Seat  int           `json:"seat"`
	Name  string        `json:"name"`
	From  time.Duration `json:"from"`
	To    time.Duration `json:"to"`
	Text  string        `json:"text"`

	// Quarantined marks a span that reads like an instruction to a machine
	// rather than a remark to a person.
	//
	// The detector is a heuristic and can be evaded, which is why it is not
	// the defence. The defence is the manifest: an agent that has been
	// entirely talked round can still only do what it was declared to do.
	// What this adds is that a quarantined span may be quoted and may never
	// be the authority for an action item — so the worst case is a summary
	// containing a strange sentence, rather than a task somebody has to
	// explain.
	Quarantined bool `json:"quarantined,omitempty"`
	// Erased marks a span whose words have been removed, leaving the fact
	// that somebody spoke.
	Erased bool `json:"erased,omitempty"`
}

// Kind is what a line of the minutes is.
type Kind string

const (
	// Point is something that was said worth writing down.
	Point Kind = "point"
	// Decision is something that was settled.
	Decision Kind = "decision"
	// Action is something somebody agreed to do.
	Action Kind = "action"
	// Question is something left open.
	Question Kind = "question"
)

// Kinds is every kind of line.
var Kinds = []Kind{Point, Decision, Action, Question}

// Known reports whether a kind is one of the four.
func (k Kind) Known() bool {
	for _, c := range Kinds {
		if c == k {
			return true
		}
	}
	return false
}

// Line is one entry in the minutes.
type Line struct {
	Kind Kind   `json:"kind"`
	Text string `json:"text"`
	// Owner is who agreed to do it, for an action.
	Owner string `json:"owner,omitempty"`
	Due   string `json:"due,omitempty"`
	// Anchors are the spans this was drawn from. Never empty: a line that
	// points at nothing is the thing this package exists to stop.
	Anchors []int `json:"anchors"`
}

// Minutes is the write-up, with its sources attached.
type Minutes struct {
	Call    string    `json:"call"`
	Epoch   uint64    `json:"epoch"`
	By      string    `json:"by"`
	Written time.Time `json:"written"`
	Spans   []Span    `json:"spans"`
	Lines   []Line    `json:"lines"`
}

// Say appends a span of transcript.
func (m *Minutes) Say(seat int, name string, from, to time.Duration,
	text string) (int, error) {
	if strings.TrimSpace(text) == "" {
		return 0, fmt.Errorf("an empty span is not something somebody said")
	}
	if to < from {
		return 0, fmt.Errorf("a span cannot end before it starts")
	}
	s := Span{
		Index: len(m.Spans), Seat: seat, Name: name, From: from, To: to,
		Text:        strings.TrimSpace(text),
		Quarantined: Instructionish(text),
	}
	m.Spans = append(m.Spans, s)
	return s.Index, nil
}

// Write adds a line, which must point at something.
func (m *Minutes) Write(k Kind, text string, anchors []int,
	owner string) error {
	if !k.Known() {
		return fmt.Errorf("%q is not a kind of line; they are %s", k,
			joinKinds())
	}
	if strings.TrimSpace(text) == "" {
		return fmt.Errorf("a line with no words is not a line")
	}
	if len(anchors) == 0 {
		return fmt.Errorf("%q points at nothing. Every line of these "+
			"minutes has to name the part of the call it came from, "+
			"because a summary that cannot show its working is a plausible "+
			"essay about a meeting", text)
	}
	seen := map[int]bool{}
	for _, a := range anchors {
		if a < 0 || a >= len(m.Spans) {
			return fmt.Errorf("span %d does not exist", a)
		}
		if seen[a] {
			continue
		}
		seen[a] = true
	}
	if k == Action {
		if strings.TrimSpace(owner) == "" {
			return fmt.Errorf("an action nobody owns is a wish. Who agreed " +
				"to do it?")
		}
		for _, a := range anchors {
			if m.Spans[a].Quarantined {
				return fmt.Errorf(
					"span %d reads as an instruction to a machine rather "+
						"than a remark to a person, so it cannot be the "+
						"authority for something somebody now has to do. "+
						"It can still be quoted", a)
			}
		}
	}
	ord := append([]int(nil), anchors...)
	sort.Ints(ord)
	m.Lines = append(m.Lines, Line{
		Kind: k, Text: strings.TrimSpace(text), Owner: strings.TrimSpace(owner),
		Anchors: ord,
	})
	return nil
}

func joinKinds() string {
	out := make([]string, 0, len(Kinds))
	for _, k := range Kinds {
		out = append(out, string(k))
	}
	return strings.Join(out, ", ")
}

// Quote is what a line was drawn from.
func (m Minutes) Quote(line int) []Span {
	if line < 0 || line >= len(m.Lines) {
		return nil
	}
	var out []Span
	for _, a := range m.Lines[line].Anchors {
		if a >= 0 && a < len(m.Spans) {
			out = append(out, m.Spans[a])
		}
	}
	return out
}

// Unanchored is every line that no longer points at anything.
//
// Lines cannot be written unanchored, so this is about what happens
// afterwards: somebody withdraws consent, their words come out, and a line
// that rested only on them has lost its authority. It is reported rather
// than quietly kept, because a minute whose source has been erased is a
// claim about a meeting with nothing behind it.
func (m Minutes) Unanchored() []int {
	var out []int
	for i, l := range m.Lines {
		live := 0
		for _, a := range l.Anchors {
			if a >= 0 && a < len(m.Spans) && !m.Spans[a].Erased {
				live++
			}
		}
		if live == 0 {
			out = append(out, i)
		}
	}
	return out
}

// Check refuses minutes that cannot show their working.
func (m Minutes) Check() error {
	if len(m.Lines) == 0 {
		return fmt.Errorf("there is nothing in these minutes")
	}
	if bad := m.Unanchored(); len(bad) > 0 {
		var names []string
		for _, i := range bad {
			names = append(names, fmt.Sprintf("%q", m.Lines[i].Text))
		}
		return fmt.Errorf("%d line(s) point at nothing that is still in "+
			"the transcript: %s", len(bad), strings.Join(names, ", "))
	}
	return nil
}

// Erase removes one participant's words.
//
// Article 17, and the practical case behind it: somebody withdraws consent
// after the fact. Their words go and the fact that they spoke stays,
// because the minutes have to remain an accurate record of who was in the
// room even when they no longer record what one of them said.
func (m *Minutes) Erase(seat int) int {
	n := 0
	for i := range m.Spans {
		if m.Spans[i].Seat == seat && !m.Spans[i].Erased {
			m.Spans[i].Text = ""
			m.Spans[i].Erased = true
			n++
		}
	}
	return n
}

// Withdraw removes the lines an erasure left without authority.
//
// Separate from Erase and returning what it took out, because dropping
// somebody's contribution from the minutes is a visible change to a shared
// record and should be reported to the room rather than done silently.
func (m *Minutes) Withdraw() []Line {
	bad := m.Unanchored()
	if len(bad) == 0 {
		return nil
	}
	drop := map[int]bool{}
	var gone []Line
	for _, i := range bad {
		drop[i] = true
		gone = append(gone, m.Lines[i])
	}
	kept := m.Lines[:0]
	for i, l := range m.Lines {
		if !drop[i] {
			kept = append(kept, l)
		}
	}
	m.Lines = kept
	return gone
}

// Coverage is how much of the call the minutes actually rest on.
//
// A number worth showing. Minutes drawn from four spans of a fifty-minute
// call are not wrong, but somebody deciding whether to trust them should
// be able to see that before they do.
type Coverage struct {
	Spans    int           `json:"spans"`
	Cited    int           `json:"cited"`
	Talked   time.Duration `json:"talked"`
	Drawn    time.Duration `json:"drawn"`
	Speakers int           `json:"speakers"`
	Quoted   int           `json:"quoted"`
}

// Share is the fraction of what was said that the minutes rest on.
func (c Coverage) Share() float64 {
	if c.Talked == 0 {
		return 0
	}
	return float64(c.Drawn) / float64(c.Talked)
}

// Thin reports whether the minutes rest on so little that somebody should
// be told before they rely on them.
func (c Coverage) Thin() bool {
	return c.Speakers > c.Quoted || c.Share() < 0.1
}

// Why explains a coverage, or returns empty when there is nothing to say.
func (c Coverage) Why() string {
	switch {
	case c.Speakers > c.Quoted:
		return fmt.Sprintf("%d of %d people who spoke are not quoted "+
			"anywhere in these minutes", c.Speakers-c.Quoted, c.Speakers)
	case c.Share() < 0.1:
		return fmt.Sprintf("these minutes rest on %.0f%% of what was said",
			c.Share()*100)
	}
	return ""
}

// Coverage measures the minutes against the transcript.
func (m Minutes) Coverage() Coverage {
	out := Coverage{Spans: len(m.Spans)}
	cited := map[int]bool{}
	for _, l := range m.Lines {
		for _, a := range l.Anchors {
			cited[a] = true
		}
	}
	speakers, quoted := map[int]bool{}, map[int]bool{}
	for _, s := range m.Spans {
		if s.Erased {
			continue
		}
		speakers[s.Seat] = true
		out.Talked += s.To - s.From
		if cited[s.Index] {
			out.Cited++
			out.Drawn += s.To - s.From
			quoted[s.Seat] = true
		}
	}
	out.Speakers, out.Quoted = len(speakers), len(quoted)
	return out
}

// instructions are the shapes that mean somebody is talking to a machine.
//
// Deliberately a short list of phrasings rather than an attempt at
// completeness. A long list would suggest the detector is the protection,
// and it is not: the manifest is. This catches the obvious attempt and
// makes it visible, which is worth having and is not worth overstating.
var instructions = []string{
	"ignore previous", "ignore all previous", "ignore your previous",
	"disregard the above", "disregard previous", "new instructions",
	"system prompt", "you are now", "from now on you",
	"forget everything", "override your", "do not tell",
	"without telling anyone", "send the summary to",
	"email the transcript", "reveal your instructions",
	"print your instructions",
}

// Instructionish reports whether a stretch of speech reads as an
// instruction to a machine.
func Instructionish(text string) bool {
	t := strings.ToLower(text)
	t = strings.Join(strings.Fields(t), " ")
	for _, p := range instructions {
		if strings.Contains(t, p) {
			return true
		}
	}
	return false
}

// Quarantined is every span held as untrusted.
func (m Minutes) Quarantined() []Span {
	var out []Span
	for _, s := range m.Spans {
		if s.Quarantined {
			out = append(out, s)
		}
	}
	return out
}
