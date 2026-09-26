// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package room

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
)

// The conversation itself, and the three things it has to get right to be
// worth trusting: the same message twice is one message, two clients agree
// about the order, and a reply is never lost because nobody was following
// the thread.

// Log is the messages in a room.
type Log struct {
	room  Room
	byID  map[string]*Message
	order []string
	acts  []Reaction
}

// New opens a log for a room.
func New(r Room) (*Log, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &Log{room: r, byID: map[string]*Message{}}, nil
}

// Room is which room this is.
func (l *Log) Room() Room { return l.room }

// Len is how many messages it holds, tombstones included.
func (l *Log) Len() int { return len(l.byID) }

// Post adds a message.
//
// The same identifier twice is the same message and not two. A client that
// timed out and retried has sent one thing, and a conversation that shows it
// twice is a conversation that lost an argument with the network.
func (l *Log) Post(m Message) (*Message, bool, error) {
	if err := m.Validate(); err != nil {
		return nil, false, err
	}
	if m.Room != l.room.ID {
		return nil, false, fmt.Errorf("%s belongs to %s and this is %s",
			m.ID, m.Room, l.room.ID)
	}
	if !l.room.Holds(m.Author) && l.room.Kind != Open {
		return nil, false, fmt.Errorf(
			"%s is not in %s. A message from outside the room is one nobody "+
				"in it agreed to receive", m.Author, l.room.ID)
	}
	if m.Reply != "" {
		parent, ok := l.byID[m.Reply]
		if !ok {
			return nil, false, fmt.Errorf(
				"%s replies to %s, which is not in this room", m.ID, m.Reply)
		}
		if parent.Reply != "" {
			// One level. A thread of threads is a thread nobody can follow
			// and it is where every product in this category loses people.
			return nil, false, fmt.Errorf(
				"%s replies to %s, which is itself a reply. Threads are one "+
					"level deep: a thread of threads is one nobody can "+
					"follow", m.ID, m.Reply)
		}
	}
	if existing, ok := l.byID[m.ID]; ok {
		return existing, false, nil
	}
	copied := m
	l.byID[m.ID] = &copied
	l.order = append(l.order, m.ID)
	return &copied, true, nil
}

// Edit appends a revision.
//
// Appends. The earlier text stays where everybody in the room can read it,
// which is the whole difference between this and a field that holds only the
// present.
func (l *Log) Edit(id string, r Revision) (*Message, error) {
	m, ok := l.byID[id]
	if !ok {
		return nil, fmt.Errorf("there is no message %s here", id)
	}
	if m.Deleted != nil {
		return nil, fmt.Errorf(
			"%s was removed on %s. Editing it would be putting words into a "+
				"message a reader has already been told is gone", id,
			m.Deleted.At.Format("2006-01-02"))
	}
	if !strings.EqualFold(r.By, m.Author) {
		// Somebody else's words. Not a permission question — a factual one:
		// the author field says who said it, and an edit by anybody else
		// would make that false.
		return nil, fmt.Errorf(
			"%s is editing a message by %s. An edit changes what somebody "+
				"is recorded as having said, so only they may make one",
			r.By, m.Author)
	}
	if strings.TrimSpace(r.Text) == "" {
		return nil, fmt.Errorf(
			"editing %s to nothing is deleting it, and deleting leaves a "+
				"tombstone that says so", id)
	}
	if r.At.IsZero() {
		return nil, fmt.Errorf("an edit needs a time")
	}
	if r.Text == m.Text() {
		// Nothing changed. Appending would add an "(edited)" mark for a
		// keystroke somebody undid.
		return m, nil
	}
	m.Revisions = append(m.Revisions, r)
	return m, nil
}

// Remove takes a message's text away and leaves the shape.
func (l *Log) Remove(id string, t Tombstone) (*Message, error) {
	m, ok := l.byID[id]
	if !ok {
		return nil, fmt.Errorf("there is no message %s here", id)
	}
	if m.Deleted != nil {
		return nil, fmt.Errorf("%s was already removed on %s", id,
			m.Deleted.At.Format("2006-01-02"))
	}
	if err := t.Validate(strings.EqualFold(t.By, m.Author)); err != nil {
		return nil, err
	}
	m.Deleted = &t
	if t.Why.Erases() {
		// Article 17. The text goes from here; the audit log never had it,
		// only the digest, so the chain is intact and holds no words.
		m.Revisions = []Revision{{At: m.At, By: m.Author}}
	}
	return m, nil
}

// Expire removes everything past the room's retention period.
//
// Content and never shape. A room that has been running for three years
// still says how much was said and when, which is the knowledge that is
// otherwise lost and the record an auditor asks for.
func (l *Log) Expire(now time.Time) int {
	if l.room.Retention <= 0 {
		return 0
	}
	cutoff := now.Add(-l.room.Retention)
	var n int
	for _, id := range l.order {
		m := l.byID[id]
		if m.Deleted != nil || !m.At.Before(cutoff) {
			continue
		}
		m.Deleted = &Tombstone{At: now, By: "retention",
			Kind: audit.KindService, Why: ByRetention}
		m.Revisions = []Revision{{At: m.At, By: m.Author}}
		n++
	}
	return n
}

// Get returns one message.
func (l *Log) Get(id string) (*Message, bool) {
	m, ok := l.byID[id]
	return m, ok
}

// All returns every message in order.
//
// By time, then by identifier. Two clients that received the same messages in
// different orders have to display the same conversation, and a sort that
// falls back to arrival order does not give them that.
func (l *Log) All() []Message {
	out := make([]Message, 0, len(l.order))
	for _, id := range l.order {
		out = append(out, *l.byID[id])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.Before(out[j].At)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Thread returns a message and its replies, in order.
func (l *Log) Thread(id string) ([]Message, error) {
	parent, ok := l.byID[id]
	if !ok {
		return nil, fmt.Errorf("there is no message %s here", id)
	}
	if parent.Reply != "" {
		id = parent.Reply
		parent = l.byID[id]
	}
	out := []Message{*parent}
	for _, m := range l.All() {
		if m.Reply == id {
			out = append(out, m)
		}
	}
	return out, nil
}

// React records a reaction.
func (l *Log) React(r Reaction) error {
	if _, ok := l.byID[r.Message]; !ok {
		return fmt.Errorf("there is no message %s here", r.Message)
	}
	if strings.TrimSpace(r.Emoji) == "" || strings.TrimSpace(r.By) == "" {
		return fmt.Errorf("a reaction needs an emoji and somebody")
	}
	if r.At.IsZero() {
		return fmt.Errorf("a reaction needs a time")
	}
	l.acts = append(l.acts, r)
	return nil
}

// Reactions folds what a message currently carries.
func (l *Log) Reactions(id string) map[string][]string {
	var mine []Reaction
	for _, r := range l.acts {
		if r.Message == id {
			mine = append(mine, r)
		}
	}
	return Tally(mine)
}

// Unread is what somebody has not seen since a moment.
//
// Thread replies included. The commonest structural complaint about Slack is
// that a reply in a thread nobody is following goes unnoticed, and the reason
// is that a thread is a separate place with its own unread state. Here a
// reply is a message in the room: if you have not read it, it is unread, and
// a room you have muted is silent whether the message was threaded or not.
func (l *Log) Unread(who string, since time.Time, muted bool) []Message {
	if muted {
		return nil
	}
	var out []Message
	for _, m := range l.All() {
		if !m.At.After(since) {
			continue
		}
		if strings.EqualFold(m.Author, who) {
			// Your own message is not news.
			continue
		}
		out = append(out, m)
	}
	return out
}

// Reach is who a message would notify.
type Reach struct {
	// People is how many would be told.
	People int `json:"people"`
	// Broadcast says the message addresses everybody in the room rather
	// than named individuals.
	Broadcast bool `json:"broadcast"`
	// Named are the individuals mentioned by name.
	Named []string `json:"named,omitempty"`
	// Room is how many are in it, for the comparison that matters.
	Room int `json:"room"`
}

// Why explains a reach in one line.
//
// Shown before sending, which nothing else does. A broadcast in a room of two
// hundred is an interruption of two hundred people, and the person about to
// make it is the only one who can decide it is worth that — but only if they
// are told the number first.
func (r Reach) Why() string {
	switch {
	case r.Broadcast && r.People > 20:
		return fmt.Sprintf(
			"this interrupts all %d people in the room. Everything anybody "+
				"finds tiring about a place like this is made of messages "+
				"like this one", r.People)
	case r.Broadcast:
		return fmt.Sprintf("this notifies all %d people in the room",
			r.People)
	case r.People == 0:
		return "this notifies nobody directly"
	default:
		return fmt.Sprintf("this notifies %s", strings.Join(r.Named, ", "))
	}
}

// Reaches works out who a message would notify.
//
// Two forms only: naming somebody, and addressing the room. A product with
// several kinds of broadcast has several ways to interrupt everybody, and
// the difference between them is never as clear to the sender as it is in the
// documentation.
func Reaches(text string, r Room) Reach {
	out := Reach{Room: len(r.Members)}
	if r.Kind == Open {
		// An open room's membership is not enumerated here, so the count
		// is what the caller knows. Reported as zero rather than guessed.
		out.Room = len(r.Members)
	}
	seen := map[string]bool{}
	for _, word := range strings.FieldsFunc(text, func(c rune) bool {
		switch c {
		case ' ', '\t', '\n', '\r', ',', ';', ':', '.', '!', '?', '(', ')':
			return true
		}
		return false
	}) {
		if !strings.HasPrefix(word, "@") || len(word) < 2 {
			continue
		}
		who := strings.ToLower(word[1:])
		if who == "room" || who == "everyone" || who == "channel" {
			out.Broadcast = true
			continue
		}
		if seen[who] {
			continue
		}
		seen[who] = true
		out.Named = append(out.Named, who)
	}
	sort.Strings(out.Named)
	switch {
	case out.Broadcast:
		out.People = out.Room
	default:
		out.People = len(out.Named)
	}
	return out
}
