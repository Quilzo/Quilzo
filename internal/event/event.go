// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package event keeps what happened on the site, for whatever is started by
// it: an agent with a trigger, today.
//
// # Why a log, and not a channel
//
// Things happen in three processes: the admin server, the command line,
// and the public site. A page is published from the first two; a form is
// sent, a visitor asks for a person, a booking is made and somebody joins
// the newsletter in the third. A channel inside one process sees a third
// of it. So each event is a line appended to a log on disk, read by the
// one dispatcher in the admin server from where it last stopped, which
// also means nothing is lost while that server is down.
//
// # Where an event came from is where it is kept
//
// The public site is the process facing the internet, and it runs confined
// (cmd/quilzo/siteconfine.go). It keeps its events in a directory of its own
// and cannot write the admin's. So which log an event was read from — not
// anything it says about itself — is its Source, and an event the site
// could not have caused (a page published) is refused when read from the
// site's log. A site that was broken into can fire a form event; it cannot
// make agents believe a page went live.
//
// # No people in it
//
// An event says what kind of thing happened and to what — a page, a
// collection, a form, a chatbot, a service — never who: not the visitor
// who sent the form, nor what they wrote. Whatever it starts reads the
// details it is allowed to through the operations it holds, and is
// recorded doing so. The log is kept for a fortnight's worth of lines and
// then rotated away.
package event

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// Type is what happened.
type Type string

// The events. A closed list: a trigger naming anything else is refused when
// it is declared, rather than waiting for something that never comes.
const (
	PagePublished     Type = "page.published"
	PageRolledBack    Type = "page.rolled-back"
	DraftProposed     Type = "draft.proposed"
	RecordChanged     Type = "record.changed"
	FormSubmitted     Type = "form.submitted"
	HandoffRequested  Type = "handoff.requested"
	ChatbotUnanswered Type = "chatbot.unanswered"
	BookingMade       Type = "booking.made"
	BookingCancelled  Type = "booking.cancelled"
	SubscriberJoined  Type = "subscriber.joined"
	SubscriberLeft    Type = "subscriber.left"
)

// Source is the process an event was written by, known from its log.
type Source string

const (
	// Admin is the admin server and the command line: the store's owner.
	Admin Source = "admin"
	// Site is the public server, confined.
	Site Source = "site"
)

// producers says which sources may write which events. The admin may write
// a site's kind too (a booking cancelled from the admin, a form imported);
// the site may write only what visitors do.
var producers = map[Type][]Source{
	PagePublished:     {Admin},
	PageRolledBack:    {Admin},
	DraftProposed:     {Admin},
	RecordChanged:     {Admin},
	FormSubmitted:     {Site, Admin},
	HandoffRequested:  {Site},
	ChatbotUnanswered: {Site},
	BookingMade:       {Site, Admin},
	BookingCancelled:  {Site, Admin},
	SubscriberJoined:  {Site, Admin},
	SubscriberLeft:    {Site, Admin},
}

// Types lists every event, for a person choosing one.
func Types() []Type {
	return []Type{PagePublished, PageRolledBack, DraftProposed, RecordChanged, FormSubmitted,
		HandoffRequested, ChatbotUnanswered, BookingMade, BookingCancelled, SubscriberJoined, SubscriberLeft}
}

// Known reports whether t is an event.
func Known(t Type) bool { _, ok := producers[t]; return ok }

// Describe is what an event means, in a person's words.
func Describe(t Type) string {
	switch t {
	case PagePublished:
		return "pages go live"
	case PageRolledBack:
		return "the live site is rolled back"
	case DraftProposed:
		return "a draft is proposed for review"
	case RecordChanged:
		return "records in a collection change"
	case FormSubmitted:
		return "somebody sends a form"
	case HandoffRequested:
		return "a visitor asks a chatbot for a person"
	case ChatbotUnanswered:
		return "a chatbot cannot answer a question"
	case BookingMade:
		return "somebody books a service"
	case BookingCancelled:
		return "a booking is cancelled"
	case SubscriberJoined:
		return "somebody joins the newsletter"
	case SubscriberLeft:
		return "somebody leaves the newsletter"
	}
	return string(t)
}

// VisitorCaused reports whether an event is something a visitor did, so
// anything it starts treats what it reads about it as untrusted.
func VisitorCaused(t Type) bool {
	switch t {
	case FormSubmitted, HandoffRequested, ChatbotUnanswered, BookingMade, BookingCancelled,
		SubscriberJoined, SubscriberLeft:
		return true
	}
	return false
}

// MaxChain is how many agents' runs may lead one to the next before an
// event starts nothing more. One agent publishing because of another is
// work; a fourth is a loop nobody designed.
const MaxChain = 3

// Event is one thing that happened.
type Event struct {
	// Seq is its place in its log, from one, and ID a random name for it
	// that a run record can cite.
	Seq  int64     `json:"seq"`
	ID   string    `json:"id"`
	Type Type      `json:"type"`
	At   time.Time `json:"at"`
	// Subject is what it is about: a page path, a collection, a form, a
	// chatbot or a service. Never a person.
	Subject string `json:"subject,omitempty"`
	// Commit is the content it concerns, and Pages the pages it changed,
	// at most MaxPages of them.
	Commit string   `json:"commit,omitempty"`
	Pages  []string `json:"pages,omitempty"`
	// Kind is what caused it: human, ai, visitor or system. Agent is the
	// agent whose run did, and Chain the agents whose runs led here, oldest
	// first: what keeps agents from setting each other off for ever.
	Kind  string   `json:"kind,omitempty"`
	Agent string   `json:"agent,omitempty"`
	Chain []string `json:"chain,omitempty"`

	// Source is the log it was read from. Not stored: it is where the line
	// is, not what the line says.
	Source Source `json:"-"`
}

// MaxPages bounds an event's list of pages.
const MaxPages = 50

var reSubject = regexp.MustCompile(`^[\p{L}\p{N}/_.:@ -]{0,200}$`)

// check refuses an event that is malformed or could carry more than it
// should: a subject that is not a name, a page list that is a dump.
func (e Event) check() error {
	if !Known(e.Type) {
		return fmt.Errorf("%q is not an event", e.Type)
	}
	if !utf8.ValidString(e.Subject) || !reSubject.MatchString(e.Subject) {
		return fmt.Errorf("an event's subject is a name, and %q is not one", e.Subject)
	}
	if len(e.Pages) > MaxPages {
		return fmt.Errorf("an event names at most %d pages", MaxPages)
	}
	if len(e.Chain) > MaxChain+1 {
		return fmt.Errorf("an event's chain is at most %d agents", MaxChain+1)
	}
	return nil
}

// Within reports whether the event is about where, a prefix of its subject
// or one of its pages, matched on whole path parts: "/blog" is within
// "/blog" and "/blog/x", not "/blogroll". Empty is anywhere.
func (e Event) Within(where string) bool {
	where = strings.TrimSuffix(strings.TrimSpace(where), "/")
	if where == "" {
		return true
	}
	in := func(s string) bool {
		s = "/" + strings.TrimPrefix(s, "/")
		w := "/" + strings.TrimPrefix(where, "/")
		return s == w || strings.HasPrefix(s, w+"/")
	}
	if e.Subject != "" && in(e.Subject) {
		return true
	}
	for _, p := range e.Pages {
		if in(p) {
			return true
		}
	}
	return false
}

// Log is the events one source writes, in its own directory.
type Log struct {
	Dir    string
	Source Source
	// MaxBytes is how large the log grows before it is rotated, keeping the
	// one before it; DefaultMaxBytes when zero.
	MaxBytes int64
}

// DefaultMaxBytes is a log's size before it is rotated: some tens of
// thousands of events, well over a fortnight of a busy site's.
const DefaultMaxBytes = 8 << 20

func (l Log) current() string  { return filepath.Join(l.Dir, "events.jsonl") }
func (l Log) previous() string { return filepath.Join(l.Dir, "events.1.jsonl") }
func (l Log) seqPath() string  { return filepath.Join(l.Dir, "seq") }

// Append writes an event, giving it its sequence number and, when it has
// none, an ID and the time. It is safe across processes: the log's lock is
// held from reading the last number to writing the line.
func (l Log) Append(e Event) (Event, error) {
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	if e.ID == "" {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return e, err
		}
		e.ID = "ev_" + hex.EncodeToString(b[:])
	}
	if len(e.Pages) > MaxPages {
		e.Pages = e.Pages[:MaxPages]
	}
	if err := e.check(); err != nil {
		return e, err
	}
	if !allowed(e.Type, l.Source) {
		return e, fmt.Errorf("the %s does not write %s events", l.Source, e.Type)
	}
	if err := os.MkdirAll(l.Dir, 0o700); err != nil {
		return e, err
	}
	unlock, err := atomicfile.Lock(filepath.Join(l.Dir, "lock"))
	if err != nil {
		return e, err
	}
	defer unlock()

	last, err := l.lastSeq()
	if err != nil {
		return e, err
	}
	e.Seq = last + 1
	line, err := json.Marshal(e)
	if err != nil {
		return e, err
	}
	max := l.MaxBytes
	if max <= 0 {
		max = DefaultMaxBytes
	}
	if info, err := os.Stat(l.current()); err == nil && info.Size()+int64(len(line))+1 > max {
		if err := os.Rename(l.current(), l.previous()); err != nil {
			return e, err
		}
	}
	f, err := os.OpenFile(l.current(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return e, err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return e, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return e, err
	}
	if err := f.Close(); err != nil {
		return e, err
	}
	// The number last, after the line is safely written: a crash between
	// leaves a line whose number is reused, which the reader tells apart by
	// reading the number from the line, never by counting.
	return e, atomicfile.Write(l.seqPath(), []byte(strconv.FormatInt(e.Seq, 10)+"\n"), 0o600)
}

// lastSeq is the number of the last event written: the larger of the
// number kept beside the log and the last line in it, so a process that
// stopped between writing a line and its number does not have the next
// event take the same number, which a reader already past it would skip.
func (l Log) lastSeq() (int64, error) {
	var kept int64
	b, err := os.ReadFile(l.seqPath())
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return 0, err
	default:
		n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%s is not a number", l.seqPath())
		}
		kept = n
	}
	line, err := lastLineSeq(l.current())
	if err != nil {
		return 0, err
	}
	if line == 0 {
		if line, err = lastLineSeq(l.previous()); err != nil {
			return 0, err
		}
	}
	return max(kept, line), nil
}

// lastLineSeq reads the number of the last whole event in a log, looking
// only at its end.
func lastLineSeq(path string) (int64, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	const tail = 64 << 10
	start := max(info.Size()-tail, 0)
	buf := make([]byte, info.Size()-start)
	if _, err := f.ReadAt(buf, start); err != nil {
		return 0, err
	}
	lines := bytes.Split(bytes.TrimRight(buf, "\n"), []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		var e struct {
			Seq int64 `json:"seq"`
		}
		if json.Unmarshal(lines[i], &e) == nil && e.Seq > 0 {
			return e.Seq, nil
		}
	}
	return 0, nil
}

// Read returns up to max events after seq, oldest first, each marked with
// this log's Source. An event its source may not write is dropped, and
// counted in refused, rather than returned.
func (l Log) Read(after int64, max int) (events []Event, refused int, err error) {
	if max <= 0 {
		max = 1000
	}
	for _, path := range []string{l.previous(), l.current()} {
		f, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return events, refused, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() && len(events) < max {
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 {
				continue
			}
			var e Event
			if json.Unmarshal(line, &e) != nil || e.Seq <= after {
				continue
			}
			if e.check() != nil || !allowed(e.Type, l.Source) {
				refused++
				after = e.Seq
				continue
			}
			e.Source = l.Source
			events = append(events, e)
			after = e.Seq
		}
		err = sc.Err()
		f.Close()
		if err != nil {
			return events, refused, err
		}
	}
	return events, refused, nil
}

func allowed(t Type, s Source) bool {
	for _, p := range producers[t] {
		if p == s {
			return true
		}
	}
	return false
}
