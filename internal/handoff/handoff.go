// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

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
// A message is the one thing written under a lock, held for the length of
// the write, so that the file's size can be kept under what is read back
// (appendWithin).
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

	"github.com/quilzo/quilzo/internal/atomicfile"
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
	if err := s.appendWithin(assistant, id, event{Kind: "say", At: now.UTC(),
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

// closeRoom is what a conversation keeps free for the line that ends it,
// so that it can always be ended, by the visitor or by whoever answered.
const closeRoom = 4 << 10

// appendWithin adds a message to a conversation's file, and refuses one
// that would take the file past MaxFile. MaxText and MaxMessages alone did
// not keep it under: a message of '<' is stored six bytes to the character,
// so at about 88 such messages the file passed the limit Get reads to, and
// from then on the visitor's page answered 503, the Inbox left the
// conversation out and nobody could answer it. The visitor is told to start
// another, as at MaxMessages.
//
// The size is read and the line written under a lock. Read first and
// written after with nothing held between, two messages sent together near
// the limit were each told there was room, and the second took the file
// past it all the same. It is the one place a lock is taken here: by
// writers of messages only, for the length of one write, and the kernel
// lets go of it when its holder dies, so neither process waits on a lock
// the other left behind. The lock is a file beside the conversations and
// not the conversation itself, which a reader must be able to read while
// a message is written (a lock on Windows keeps other handles out of the
// bytes it covers).
func (s Store) appendWithin(assistant, id string, e event) (err error) {
	p, err := s.path(assistant, id)
	if err != nil {
		return err
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	// O_CREATE is not given, as in append.
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0o600)
	if os.IsNotExist(err) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	// A message whose file did not close is not reported as said, as in
	// append.
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	unlock, err := atomicfile.Lock(filepath.Join(filepath.Dir(p), sayLock))
	if err != nil {
		return err
	}
	defer unlock()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	// The leading and trailing newline writeEvents adds, then the room
	// kept for the end.
	if fi.Size()+int64(len(line))+2+closeRoom > MaxFile {
		return fmt.Errorf("this conversation is as long as one can be; start another")
	}
	return writeEvents(f, e)
}

// sayLock is the file, in an assistant's folder, that writers of messages
// lock. Not a conversation's name, so List and Expire pass it by.
const sayLock = "say.lock"

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
	var out []Conversation
	err := s.walk(func(assistant, id string, _ os.DirEntry) error {
		c, err := s.Get(assistant, id)
		if err != nil {
			return nil
		}
		out = append(out, c)
		return nil
	})
	if err != nil {
		return nil, err
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
//
// A conversation Get cannot read goes by when its file last changed. Expire
// walked List, which leaves such a conversation out, so one written past
// the read limit was kept for ever, although its visitor had been told it
// is deleted after the period.
func (s Store) Expire(keep func(assistant string) time.Duration, now time.Time) (int, error) {
	n := 0
	err := s.walk(func(assistant, id string, f os.DirEntry) error {
		var last time.Time
		if c, err := s.Get(assistant, id); err == nil {
			last = c.Last
		} else if fi, ferr := f.Info(); ferr == nil {
			last = fi.ModTime()
		} else {
			return nil
		}
		d := keep(assistant)
		if d <= 0 {
			d = DefaultDays * 24 * time.Hour
		}
		if now.Sub(last) <= d {
			return nil
		}
		p, _ := s.path(assistant, id)
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
		n++
		return nil
	})
	return n, err
}

// walk calls fn for every file that can be a conversation.
func (s Store) walk(fn func(assistant, id string, f os.DirEntry) error) error {
	assistants, err := os.ReadDir(s.Dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, a := range assistants {
		if !a.IsDir() || !reAssistant.MatchString(a.Name()) {
			continue
		}
		files, err := os.ReadDir(filepath.Join(s.Dir, a.Name()))
		if err != nil {
			return err
		}
		for _, f := range files {
			id, ok := strings.CutSuffix(f.Name(), ".jsonl")
			if !ok || !ValidID(id) || !f.Type().IsRegular() {
				continue
			}
			if err := fn(a.Name(), id, f); err != nil {
				return err
			}
		}
	}
	return nil
}
