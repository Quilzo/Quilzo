// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package handoff keeps the conversations a site's assistant hands to a
// person.
//
// An assistant answers from the site and stores nothing. When it cannot
// help, or the visitor asks for a person, the visitor can choose to start a
// conversation that somebody at the business reads and answers. From that
// moment something is stored, and only from that moment: the visitor is told
// so before they send anything, and the conversation is deleted a set time
// after it last moved.
//
// # How a conversation is reached
//
// The visitor holds a secret, carried in the address of their conversation.
// The store keeps only a digest of it, so a copy of the store is not a way
// into anybody's conversation. People at the business reach it through the
// admin, by the digest, which is not a way in on the public side.
//
// # Why one file per conversation, appended to
//
// The public site and the admin are separate processes, and both write: the
// visitor from one, the person answering from the other. Each event is one
// line written in one call to a file opened for appending, which the
// operating system does not interleave, so neither process needs a lock the
// other might hold. The state of a conversation is the replay of its lines.
package handoff

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Who said something.
const (
	Visitor = "visitor"
	Person  = "person"
)

// Limits. A conversation is a few messages between two people, and these are
// generous for that and small for anything else.
const (
	MaxText     = 2000
	MaxMessages = 200
	MaxFile     = 1 << 20
	// DefaultDays is how long a conversation is kept after it last moved,
	// unless the assistant says otherwise; MaxDays is the most it may say.
	DefaultDays = 30
	MaxDays     = 90
)

// ErrNotFound is returned for a conversation that does not exist, has been
// deleted, or was asked for with the wrong secret. One error for all three.
var ErrNotFound = errors.New("there is no such conversation")

// ErrClosed is returned for a message to a conversation that has ended.
var ErrClosed = errors.New("this conversation has ended")

var (
	reAssistant = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	reID        = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// ValidID reports whether s can name a conversation. It becomes a file name.
func ValidID(s string) bool { return reID.MatchString(s) }

// Message is one thing somebody said.
type Message struct {
	N    int       `json:"n"`
	At   time.Time `json:"at"`
	From string    `json:"from"`
	// By is the person at the business who answered. Empty for the visitor,
	// who is not asked who they are.
	By   string `json:"by,omitempty"`
	Text string `json:"text"`
}

// Conversation is the replay of one conversation's events.
type Conversation struct {
	ID        string    `json:"id"`
	Assistant string    `json:"assistant"`
	Opened    time.Time `json:"opened"`
	Last      time.Time `json:"last"`
	// Question is what the visitor had asked the assistant when they chose
	// to talk to a person, so whoever answers does not have to ask again.
	Question string    `json:"question,omitempty"`
	Messages []Message `json:"messages"`
	Closed   bool      `json:"closed"`
	// ClosedBy is "visitor", or the name of the person who closed it.
	ClosedBy string `json:"closed_by,omitempty"`
}

// Waiting reports whether the visitor spoke last, so somebody owes a reply.
func (c Conversation) Waiting() bool {
	if c.Closed || len(c.Messages) == 0 {
		return false
	}
	return c.Messages[len(c.Messages)-1].From == Visitor
}

// After is the messages after the n-th, for a page asking what is new.
func (c Conversation) After(n int) []Message {
	if n < 0 {
		n = 0
	}
	if n >= len(c.Messages) {
		return nil
	}
	return c.Messages[n:]
}

// event is one line of a conversation's file.
type event struct {
	Kind     string    `json:"kind"` // open, say, close
	At       time.Time `json:"at"`
	From     string    `json:"from,omitempty"`
	By       string    `json:"by,omitempty"`
	Text     string    `json:"text,omitempty"`
	Question string    `json:"question,omitempty"`
}

// Store keeps conversations under a directory.
type Store struct {
	Dir string
}

// NewSecret makes the secret a visitor holds, and the identifier the store
// and the admin use for the same conversation.
func NewSecret() (secret, id string, err error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", err
	}
	secret = base64.RawURLEncoding.EncodeToString(raw[:])
	return secret, IDFor(secret), nil
}

// IDFor is the identifier a secret stands for. A digest, so the identifier
// does not give back the secret.
func IDFor(secret string) string {
	sum := sha256.Sum256([]byte("quilzo handoff\x00" + secret))
	return hex.EncodeToString(sum[:16])
}

func (s Store) path(assistant, id string) (string, error) {
	if !reAssistant.MatchString(assistant) || !ValidID(id) {
		return "", ErrNotFound
	}
	return filepath.Join(s.Dir, assistant, id+".jsonl"), nil
}

func clean(text string) (string, error) {
	text = strings.TrimSpace(strings.ToValidUTF8(text, "�"))
	if text == "" {
		return "", fmt.Errorf("there is nothing to send")
	}
	if len(text) > MaxText {
		return "", fmt.Errorf("a message is at most %d characters", MaxText)
	}
	return text, nil
}

// Open starts a conversation, with the visitor's first message.
func (s Store) Open(assistant, id, question, first string, now time.Time) (Conversation, error) {
	p, err := s.path(assistant, id)
	if err != nil {
		return Conversation{}, err
	}
	text, err := clean(first)
	if err != nil {
		return Conversation{}, err
	}
	if len(question) > MaxText {
		question = question[:MaxText]
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return Conversation{}, err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Conversation{}, err
	}
	err = writeEvents(f, event{Kind: "open", At: now.UTC(), Question: question},
		event{Kind: "say", At: now.UTC(), From: Visitor, Text: text})
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return Conversation{}, err
	}
	return s.Get(assistant, id)
}

// Say adds a message to an open conversation.
func (s Store) Say(assistant, id, from, by, text string, now time.Time) (Message, error) {
	if from != Visitor && from != Person {
		return Message{}, fmt.Errorf("%q cannot say anything here", from)
	}
	if from == Person && strings.TrimSpace(by) == "" {
		return Message{}, fmt.Errorf("an answer says who gave it")
	}
	if from == Visitor {
		by = ""
	}
	text, err := clean(text)
	if err != nil {
		return Message{}, err
	}
	c, err := s.Get(assistant, id)
	if err != nil {
		return Message{}, err
	}
	if c.Closed {
		return Message{}, ErrClosed
	}
	if len(c.Messages) >= MaxMessages {
		return Message{}, fmt.Errorf("this conversation has reached %d "+
			"messages; start another", MaxMessages)
	}
	if err := s.append(assistant, id, event{Kind: "say", At: now.UTC(),
		From: from, By: by, Text: text}); err != nil {
		return Message{}, err
	}
	return Message{N: len(c.Messages) + 1, At: now.UTC(), From: from, By: by,
		Text: text}, nil
}

// Close ends a conversation. Nothing more can be said in it, and the
// retention period runs from now.
func (s Store) Close(assistant, id, by string, now time.Time) error {
	c, err := s.Get(assistant, id)
	if err != nil {
		return err
	}
	if c.Closed {
		return nil
	}
	return s.append(assistant, id, event{Kind: "close", At: now.UTC(), By: by})
}

func (s Store) append(assistant, id string, e event) error {
	p, err := s.path(assistant, id)
	if err != nil {
		return err
	}
	// O_CREATE is not given: appending to a conversation that was deleted
	// between reading and writing must not bring a fragment of it back.
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0o600)
	if os.IsNotExist(err) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	err = writeEvents(f, e)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// writeEvents writes every event in one call, so that a reader in the other
// process sees all of them or none.
func writeEvents(f *os.File, events ...event) error {
	// A leading newline: if an earlier write was cut short, its fragment
	// ends here rather than swallowing the start of this event.
	b := bytes.NewBufferString("\n")
	for _, e := range events {
		line, err := json.Marshal(e)
		if err != nil {
			return err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	_, err := f.Write(b.Bytes())
	return err
}

// Get replays one conversation.
func (s Store) Get(assistant, id string) (Conversation, error) {
	p, err := s.path(assistant, id)
	if err != nil {
		return Conversation{}, err
	}
	f, err := os.Open(p)
	if os.IsNotExist(err) {
		return Conversation{}, ErrNotFound
	}
	if err != nil {
		return Conversation{}, err
	}
	defer f.Close()
	c := Conversation{ID: id, Assistant: assistant}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), MaxFile)
	read := 0
	for sc.Scan() {
		read += len(sc.Bytes()) + 1
		if read > MaxFile {
			return Conversation{}, fmt.Errorf("conversation %s is larger "+
				"than any conversation should be", id)
		}
		var e event
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			// A line cut short by a write that did not finish is the only
			// way to get here; what came before it still stands.
			continue
		}
		switch e.Kind {
		case "open":
			c.Opened, c.Question = e.At, e.Question
		case "say":
			c.Messages = append(c.Messages, Message{N: len(c.Messages) + 1,
				At: e.At, From: e.From, By: e.By, Text: e.Text})
		case "close":
			c.Closed = true
			c.ClosedBy = e.By
			if c.ClosedBy == "" {
				c.ClosedBy = Visitor
			}
		}
		if e.At.After(c.Last) {
			c.Last = e.At
		}
	}
	if err := sc.Err(); err != nil {
		return Conversation{}, err
	}
	if c.Opened.IsZero() {
		return Conversation{}, ErrNotFound
	}
	return c, nil
}

// List is every conversation: open ones waiting for a reply first, then the
// rest by when they last moved.
func (s Store) List() ([]Conversation, error) {
	assistants, err := os.ReadDir(s.Dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Conversation
	for _, a := range assistants {
		if !a.IsDir() || !reAssistant.MatchString(a.Name()) {
			continue
		}
		files, err := os.ReadDir(filepath.Join(s.Dir, a.Name()))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			id, ok := strings.CutSuffix(f.Name(), ".jsonl")
			if !ok || !ValidID(id) || !f.Type().IsRegular() {
				continue
			}
			c, err := s.Get(a.Name(), id)
			if err != nil {
				continue
			}
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		wi, wj := out[i].Waiting(), out[j].Waiting()
		if wi != wj {
			return wi
		}
		if out[i].Closed != out[j].Closed {
			return !out[i].Closed
		}
		return out[i].Last.After(out[j].Last)
	})
	return out, nil
}

// Expire deletes conversations that have not moved for longer than their
// assistant keeps them. keep returns that period for an assistant, or zero
// for one that no longer exists, whose conversations go at the default.
func (s Store) Expire(keep func(assistant string) time.Duration, now time.Time) (int, error) {
	all, err := s.List()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, c := range all {
		d := keep(c.Assistant)
		if d <= 0 {
			d = DefaultDays * 24 * time.Hour
		}
		if now.Sub(c.Last) <= d {
			continue
		}
		p, _ := s.path(c.Assistant, c.ID)
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return n, err
		}
		n++
	}
	return n, nil
}
