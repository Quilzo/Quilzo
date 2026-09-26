// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package room is conversation, built so that what was said stays said.
//
// Distinct from internal/chat, which is the inbound side of a messenger
// integration — a Telegram or Slack bot taking commands. This is the
// organisation's own conversation.
//
// # An edit is an append, not a rewrite
//
// Slack shows "(edited)" and the previous text is gone. Gone for everybody,
// including the person who already acted on it, and recoverable only through
// a separate eDiscovery product on the top plan. "I said deploy to staging",
// edited to "I said deploy to prod", is unfalsifiable by design.
//
// A message here is an append-only sequence of revisions and the current text
// is a fold of them. Editing appends; nothing is overwritten; "edited" is not
// a flag somebody can clear but the observable fact that there is more than
// one revision. Everybody in the room can see what it said before, which is
// the same argument internal/finding makes about a status column: the
// question is about the past, and a field that holds only the present cannot
// answer it.
//
// # A deletion leaves a tombstone
//
// Slack's own documentation is plain that there is no recycle bin and a
// deleted message may be gone forever. That is two separate problems. The
// first is that the content is lost. The second is worse: a conversation
// where message 47 is missing and nothing says so is a conversation somebody
// edited, and a reader cannot tell it from one where nothing was ever sent.
//
// So removing a message removes the text and leaves the shape: that something
// was here, who took it away, when, and under which of the four reasons
// anybody removes anything. A message that vanished and a message that was
// never sent are different facts and they stay different.
//
// # Retention removes content and never the shape
//
// The same rule with a different actor. When a retention period expires the
// text goes and the tombstone remains, so a room that has been running for
// three years still says how much was said and when — which is the knowledge
// that is otherwise lost, and the record an auditor asks for.
//
// # Erasure is the one that removes the text everywhere
//
// Article 17 is a legal obligation and it outranks all of this. It is handled
// the way internal/notify handles a breach record: the audit log carries the
// hash of what was said and never the text, so erasing the text leaves the
// log intact and still able to prove that a message existed, when, and from
// whom — without holding a word of it.
package room

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
)

// MaxMessage is the longest a message may be.
//
// Forty thousand characters, which is Slack's own limit and is already far
// past the point where anybody reads it. The number exists so that a client
// cannot use a message as a file upload.
const MaxMessage = 40000

// Kind is what sort of room this is.
type Kind string

const (
	// Open is readable by everybody in the organisation.
	Open Kind = "open"
	// Closed is readable by its members.
	Closed Kind = "closed"
	// Direct is between named people and has no name of its own.
	Direct Kind = "direct"
)

// Kinds lists them.
func Kinds() []Kind { return []Kind{Open, Closed, Direct} }

func (k Kind) known() bool {
	for _, x := range Kinds() {
		if x == k {
			return true
		}
	}
	return false
}

// Room is where a conversation happens.
type Room struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	// Purpose is what it is for, in one line.
	//
	// Required for an open or closed room. A room nobody can say the
	// purpose of is one that accumulates people and produces the
	// notification fatigue that is the commonest complaint about every
	// product in this category.
	Purpose string `json:"purpose,omitempty"`
	Kind    Kind   `json:"kind"`
	Owner   string `json:"owner,omitempty"`
	// Members are who is in it. Empty for an open room, which everybody is
	// in by definition.
	Members []string  `json:"members,omitempty"`
	Created time.Time `json:"created"`
	// Retention is how long the text is kept. Zero means indefinitely.
	Retention time.Duration `json:"retention,omitempty"`
}

// Validate refuses a room that cannot be used.
func (r Room) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("a room needs an identifier")
	}
	if !r.Kind.known() {
		return fmt.Errorf("%s: %q is not a kind of room", r.ID, r.Kind)
	}
	if r.Created.IsZero() {
		return fmt.Errorf("%s has no creation time", r.ID)
	}
	if r.Kind == Direct {
		if len(r.Members) < 2 {
			return fmt.Errorf(
				"%s is a direct conversation between %d people", r.ID,
				len(r.Members))
		}
		return nil
	}
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("%s has no name", r.ID)
	}
	if strings.TrimSpace(r.Purpose) == "" {
		return fmt.Errorf(
			"%s says nothing about what it is for. A room nobody can state "+
				"the purpose of accumulates people, and that is where "+
				"notification fatigue comes from", r.ID)
	}
	if r.Kind == Closed && len(r.Members) == 0 {
		return fmt.Errorf("%s is closed and has nobody in it", r.ID)
	}
	if r.Retention < 0 {
		return fmt.Errorf("%s keeps messages for %s", r.ID, r.Retention)
	}
	return nil
}

// Holds reports whether somebody can see this room.
func (r Room) Holds(who string) bool {
	if r.Kind == Open {
		return true
	}
	for _, m := range r.Members {
		if strings.EqualFold(m, who) {
			return true
		}
	}
	return false
}

// Revision is one version of what a message said.
type Revision struct {
	Text string     `json:"text"`
	At   time.Time  `json:"at"`
	By   string     `json:"by"`
	Kind audit.Kind `json:"kind,omitempty"`
}

// Digest is the hash of what this revision said.
//
// What goes in the audit log, instead of the text. A log that held the words
// would be a second copy of every conversation, kept for longer and read by
// more people — and it could not be erased under Article 17 without breaking
// the chain. The hash proves a message said what somebody later claims it
// said, and holds nothing.
func (r Revision) Digest() string {
	sum := sha256.Sum256([]byte(r.Text))
	return hex.EncodeToString(sum[:])[:32]
}

// Removal is why a message is gone.
type Removal string

const (
	// ByAuthor is somebody deleting their own message.
	ByAuthor Removal = "author"
	// ByModerator is somebody else deciding it should not be there.
	//
	// Kept apart from ByAuthor because they are different events with
	// different consequences, and a log where they read the same cannot be
	// searched for the one that matters.
	ByModerator Removal = "moderator"
	// ByRetention is the room's own period expiring.
	ByRetention Removal = "retention"
	// ByErasure is Article 17, which outranks everything here.
	//
	// The only one that removes the text from the log as well as from the
	// room, because the obligation is to erase and a copy kept for
	// integrity is still a copy.
	ByErasure Removal = "erasure"
)

// Removals lists them.
func Removals() []Removal {
	return []Removal{ByAuthor, ByModerator, ByRetention, ByErasure}
}

func (r Removal) known() bool {
	for _, x := range Removals() {
		if x == r {
			return true
		}
	}
	return false
}

// Erases reports whether this removal takes the text out of the log too.
func (r Removal) Erases() bool { return r == ByErasure }

// Tombstone is what is left where a message was.
type Tombstone struct {
	At   time.Time  `json:"at"`
	By   string     `json:"by"`
	Kind audit.Kind `json:"kind,omitempty"`
	Why  Removal    `json:"why"`
	// Because is required when somebody removes a message that is not
	// theirs. Taking down another person's words is a decision, and a
	// decision with no reason attached is one nobody can question.
	Because string `json:"because,omitempty"`
}

// Validate refuses a removal nobody can account for.
func (t Tombstone) Validate(byAuthor bool) error {
	if t.At.IsZero() {
		return fmt.Errorf("a removal needs a time")
	}
	if strings.TrimSpace(t.By) == "" {
		return fmt.Errorf("a removal needs somebody who did it")
	}
	if !t.Why.known() {
		return fmt.Errorf("%q is not a reason to remove a message", t.Why)
	}
	if t.Why == ByAuthor && !byAuthor {
		return fmt.Errorf(
			"%s is removing somebody else's message and calling it the "+
				"author's own. Those are different events and a log where "+
				"they read the same cannot be searched for the one that "+
				"matters", t.By)
	}
	if t.Why == ByModerator && strings.TrimSpace(t.Because) == "" {
		return fmt.Errorf(
			"%s is taking down another person's words with no reason "+
				"recorded, and a decision nobody can question is one "+
				"nobody can appeal", t.By)
	}
	return nil
}

// Message is one thing somebody said.
type Message struct {
	// ID is generated by the client that sent it.
	//
	// So that a retry after a timeout is the same message rather than a
	// second one. Every product in this category has sent something twice
	// on a bad connection, and the fix is that the sender names it.
	ID   string `json:"id"`
	Room string `json:"room"`
	// Author is who said it. It never changes, whoever edits.
	Author string    `json:"author"`
	At     time.Time `json:"at"`
	// Reply names the message this answers, making it part of that thread.
	Reply string `json:"reply,omitempty"`

	// Revisions are what it has said, oldest first. Never rewritten.
	Revisions []Revision `json:"revisions"`
	// Deleted is the tombstone, where there is one.
	Deleted *Tombstone `json:"deleted,omitempty"`
}

// Text is what the message says now, or empty if it is gone.
func (m Message) Text() string {
	if m.Deleted != nil || len(m.Revisions) == 0 {
		return ""
	}
	return m.Revisions[len(m.Revisions)-1].Text
}

// Edited reports whether this has been changed since it was sent.
//
// Derived, not stored. A flag can be cleared by whoever can write the record;
// the number of revisions cannot be reduced without removing one, and the
// removal is itself in the log.
func (m Message) Edited() bool { return len(m.Revisions) > 1 }

// Gone reports whether the message has been removed.
func (m Message) Gone() bool { return m.Deleted != nil }

// Threaded reports whether this is a reply.
func (m Message) Threaded() bool { return m.Reply != "" }

// History is what the message has said, oldest first.
func (m Message) History() []Revision {
	return append([]Revision(nil), m.Revisions...)
}

// Says describes the message's state in one line.
func (m Message) Says() string {
	switch {
	case m.Deleted != nil && m.Deleted.Why == ByRetention:
		return fmt.Sprintf("removed by retention on %s; a message was here",
			m.Deleted.At.Format("2006-01-02"))
	case m.Deleted != nil && m.Deleted.Why == ByErasure:
		return "erased under Article 17; the log holds the fact and no words"
	case m.Deleted != nil && m.Deleted.Why == ByModerator:
		return fmt.Sprintf("taken down by %s: %s", m.Deleted.By,
			m.Deleted.Because)
	case m.Deleted != nil:
		return fmt.Sprintf("deleted by its author on %s",
			m.Deleted.At.Format("2006-01-02"))
	case m.Edited():
		return fmt.Sprintf("%s (edited %d time(s); the earlier versions are "+
			"here)", m.Text(), len(m.Revisions)-1)
	default:
		return m.Text()
	}
}

// Validate refuses a message that cannot be stored.
func (m Message) Validate() error {
	if strings.TrimSpace(m.ID) == "" {
		return fmt.Errorf(
			"a message needs an identifier from whoever sent it, so that a " +
				"retry after a timeout is the same message rather than a " +
				"second one")
	}
	if strings.TrimSpace(m.Room) == "" {
		return fmt.Errorf("%s is in no room", m.ID)
	}
	if strings.TrimSpace(m.Author) == "" {
		return fmt.Errorf("%s has no author", m.ID)
	}
	if m.At.IsZero() {
		return fmt.Errorf("%s has no time", m.ID)
	}
	if len(m.Revisions) == 0 {
		return fmt.Errorf("%s has never said anything", m.ID)
	}
	var last time.Time
	for i, r := range m.Revisions {
		if strings.TrimSpace(r.Text) == "" && m.Deleted == nil {
			return fmt.Errorf("%s revision %d is empty", m.ID, i)
		}
		if len(r.Text) > MaxMessage {
			return fmt.Errorf(
				"%s revision %d is %d characters, past the %d ceiling. A "+
					"message is not a file upload", m.ID, i, len(r.Text),
				MaxMessage)
		}
		if strings.TrimSpace(r.By) == "" {
			return fmt.Errorf("%s revision %d was written by nobody", m.ID, i)
		}
		if r.At.IsZero() {
			return fmt.Errorf("%s revision %d has no time", m.ID, i)
		}
		if r.At.Before(last) {
			return fmt.Errorf(
				"%s revision %d is older than the one before it, so the "+
					"history does not read in order", m.ID, i)
		}
		last = r.At
	}
	if m.Deleted != nil {
		if err := m.Deleted.Validate(
			strings.EqualFold(m.Deleted.By, m.Author)); err != nil {
			return fmt.Errorf("%s: %w", m.ID, err)
		}
	}
	if m.Reply == m.ID {
		return fmt.Errorf("%s replies to itself", m.ID)
	}
	return nil
}

// Record turns a message event into an audit entry.
//
// The digest and never the text. A log that held the words would be a second
// copy of every conversation, kept longer and read by more people — and one
// that could not be erased under Article 17 without breaking the chain.
func (m Message) Record(action string, by string, kind audit.Kind) audit.Record {
	detail := map[string]string{
		"message": m.ID, "room": m.Room, "author": m.Author,
		"revisions": fmt.Sprint(len(m.Revisions)),
	}
	if len(m.Revisions) > 0 {
		detail["digest"] = m.Revisions[len(m.Revisions)-1].Digest()
	}
	if m.Reply != "" {
		detail["reply_to"] = m.Reply
	}
	outcome := audit.Success
	if m.Deleted != nil {
		detail["removed"] = string(m.Deleted.Why)
		if m.Deleted.Because != "" {
			detail["because"] = m.Deleted.Because
		}
		// A removal is recorded as a denial so that the occasions somebody
		// took words away can be searched for, which is the population
		// anybody investigating asks about.
		outcome = audit.Denied
	}
	return audit.Record{
		Action: "room." + action, Resource: "/room/" + m.Room,
		Outcome: outcome, Principal: by, Kind: kind,
		Verified: kind != audit.KindUnknown, Detail: detail,
	}
}

// Reaction is somebody's response to a message.
type Reaction struct {
	Message string    `json:"message"`
	Emoji   string    `json:"emoji"`
	By      string    `json:"by"`
	At      time.Time `json:"at"`
	// Off records taking one back, which is an append like everything else
	// so that two clients that saw the events in different orders agree.
	Off bool `json:"off,omitempty"`
}

// Key identifies what a reaction is about.
func (r Reaction) Key() string {
	return r.Message + "\x00" + r.Emoji + "\x00" +
		strings.ToLower(r.By)
}

// Tally folds reactions into who currently holds each emoji.
//
// Last write wins per person per emoji, by time. Reactions arrive out of
// order on a bad connection and two clients must agree about the result, so
// the fold is over a total order rather than over arrival.
func Tally(in []Reaction) map[string][]string {
	latest := map[string]Reaction{}
	for _, r := range in {
		if existing, ok := latest[r.Key()]; ok && existing.At.After(r.At) {
			continue
		}
		latest[r.Key()] = r
	}
	out := map[string][]string{}
	for _, r := range latest {
		if r.Off {
			continue
		}
		out[r.Emoji] = append(out[r.Emoji], r.By)
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}
