// Package audit is the security log, built against NIST SP 800-53's AU family
// rather than against a general sense of what logging should look like.
//
// # AU-3: what a record has to contain
//
// AU-3 names six things an audit record must establish, and each is a field
// here rather than something a caller might remember to include:
//
//	What      the type of event                    Event.Action
//	When      when it occurred                     Event.At
//	Where     where it occurred                    Event.Resource
//	Source    the source of the event              Event.Source
//	Outcome   success or failure, and the result   Event.Outcome, Event.Detail
//	Identity  who or what was associated with it   Event.Principal, Event.Kind
//
// Constructing an Event with any of them missing fails. A log with holes is
// worse than no log, because its silence gets read as "nothing happened".
//
// # AU-9: protecting the record
//
// AU-9 requires audit information be protected from modification and deletion
// "by any user, including privileged administrators". A file an admin can edit
// does not meet that on its own, so each entry carries the hash of the one
// before it. Altering or removing an entry breaks the chain at that point, and
// `Verify` says exactly where.
//
// A hash chain rather than a Merkle tree, deliberately. A Merkle log buys
// inclusion proofs — proving one entry to somebody without handing over the
// rest — and that is worth the complexity when a third party audits a log they
// cannot read. This log is read whole by its own operator, so the chain is the
// right size of tool and there is no reason to reach for the larger one.
//
// # Identity, and the three kinds of actor
//
// AU-3 asks for the identity of individuals, subjects *or objects*. A person
// publishing, a service token running in CI, and a model writing a page are
// three different things, and a log that records all of them as "user" has
// thrown away the distinction that matters most when reading it back.
//
// # Sensitive values
//
// Identifiers are pseudonymised with HMAC-SHA256 under a key held outside the
// log. Plain hashing would not do: usernames and email addresses have little
// entropy, so a SHA-256 of one is recovered by guessing, and a log full of
// reversible hashes is a log full of identifiers with extra steps. With a key
// the pseudonym is stable — the same person is the same pseudonym across
// entries, so behaviour is still traceable — while the log alone identifies
// nobody.
//
// Content bodies, tool arguments and token secrets are never written at all.
// Redaction is for values that must be recorded but not read; the right
// treatment for a credential is not to log it.
package audit

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Kind distinguishes the three sorts of actor. AU-3(f).
type Kind string

const (
	// KindHuman is a person, accountable in the way a person is.
	KindHuman Kind = "human"
	// KindService is a token running unattended — CI, a script, a cron job.
	KindService Kind = "service"
	// KindAI is a model. Recorded separately because "a model wrote this" is a
	// different fact from "a person did", and Article 50 turns on the difference.
	KindAI Kind = "ai"
)

func (k Kind) Valid() bool {
	return k == KindHuman || k == KindService || k == KindAI
}

// Outcome is AU-3(e). Denied is kept apart from Failure: being refused is not
// the same as breaking, and an audit reader needs to tell them apart.
type Outcome string

const (
	Success Outcome = "success"
	Failure Outcome = "failure"
	Denied  Outcome = "denied"
)

func (o Outcome) Valid() bool {
	return o == Success || o == Failure || o == Denied
}

// Event is one audit record.
type Event struct {
	Seq  int64  `json:"seq"`
	At   string `json:"at"`   // AU-3(b), RFC 3339 in UTC
	Prev string `json:"prev"` // hash of the preceding entry — AU-9
	Hash string `json:"hash"` // hash of this entry's content

	Action   string  `json:"action"`   // AU-3(a)
	Resource string  `json:"resource"` // AU-3(c)
	Source   string  `json:"source"`   // AU-3(d)
	Outcome  Outcome `json:"outcome"`  // AU-3(e)

	Principal string `json:"principal"` // AU-3(f), pseudonymised
	Kind      Kind   `json:"kind"`

	// Detail carries event-specific results. Values are the caller's
	// responsibility and are documented as never holding content or secrets.
	Detail map[string]string `json:"detail,omitempty"`

	// Model is present when Kind is KindAI.
	Model string `json:"model,omitempty"`
}

// content is the bytes the hash covers: everything except the hash itself.
func (e *Event) content() ([]byte, error) {
	c := *e
	c.Hash = ""
	return json.Marshal(c)
}

func (e *Event) computeHash() (string, error) {
	b, err := e.content()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Log appends events to a file and keeps the chain.
type Log struct {
	mu   sync.Mutex
	path string
	key  []byte // HMAC key for pseudonymisation
	last string
	seq  int64
	src  string
}

// Options configures a Log.
type Options struct {
	Path string
	// Key pseudonymises identifiers. Without one, principals are written in the
	// clear — see New for why that is a decision rather than a default.
	Key []byte
	// Source names where events come from: a host, a service, a CLI. AU-3(d).
	Source string
}

// NewKey generates a pseudonymisation key.
func NewKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// New opens or resumes a log.
//
// An absent key is permitted and does not fail, because a log that refuses to
// start is a log that gets switched off. It is reported instead: `Pseudonymous`
// tells a caller which mode it is in so the choice is visible rather than
// assumed.
func New(opt Options) (*Log, error) {
	if strings.TrimSpace(opt.Path) == "" {
		return nil, fmt.Errorf("an audit log needs a path")
	}
	if strings.TrimSpace(opt.Source) == "" {
		return nil, fmt.Errorf("an audit log needs a source; AU-3 requires it on every record")
	}
	l := &Log{path: opt.Path, key: opt.Key, src: opt.Source}

	// Resume from the existing chain so appending after a restart continues it
	// rather than starting a second one.
	events, err := Read(opt.Path)
	if err != nil {
		return nil, err
	}
	if n := len(events); n > 0 {
		l.last = events[n-1].Hash
		l.seq = events[n-1].Seq
	}
	return l, nil
}

// Pseudonymous reports whether identifiers are being protected.
func (l *Log) Pseudonymous() bool { return len(l.key) > 0 }

// pseudonym maps an identifier to a stable, non-reversible handle.
func (l *Log) pseudonym(id string) string {
	if id == "" {
		return ""
	}
	if len(l.key) == 0 {
		return id
	}
	m := hmac.New(sha256.New, l.key)
	m.Write([]byte(id))
	// Truncated to 16 bytes: still far beyond collision risk at any plausible
	// number of principals, and short enough to read in a terminal.
	return "p_" + hex.EncodeToString(m.Sum(nil))[:32]
}

// Matches reports whether a pseudonym belongs to an identifier.
//
// This is how an investigation proceeds without the log holding identities:
// someone with both the key and a suspected name can confirm it, and someone
// with only the log cannot enumerate anybody.
func (l *Log) Matches(pseudonym, id string) bool {
	return hmac.Equal([]byte(pseudonym), []byte(l.pseudonym(id)))
}

// Record is what a caller fills in. The fields map to AU-3 one for one.
type Record struct {
	Action    string
	Resource  string
	Outcome   Outcome
	Principal string
	Kind      Kind
	Model     string
	Detail    map[string]string
}

// forbidden names Detail keys that must never appear. Content bodies and
// credentials do not belong in an audit log at any level of redaction.
var forbidden = []string{"token", "secret", "password", "key", "body", "content"}

// Append writes one event and returns it.
func (l *Log) Append(r Record) (*Event, error) {
	if strings.TrimSpace(r.Action) == "" {
		return nil, fmt.Errorf("an audit record needs an action (AU-3: what happened)")
	}
	if strings.TrimSpace(r.Resource) == "" {
		return nil, fmt.Errorf("an audit record needs a resource (AU-3: where)")
	}
	if !r.Outcome.Valid() {
		return nil, fmt.Errorf("outcome must be success, failure or denied (AU-3)")
	}
	if strings.TrimSpace(r.Principal) == "" {
		return nil, fmt.Errorf("an audit record needs a principal (AU-3: who)")
	}
	if !r.Kind.Valid() {
		return nil, fmt.Errorf(
			"kind must be human, service or ai; recording all three as one thing " +
				"discards the distinction most needed when reading the log back")
	}
	if r.Kind == KindAI && strings.TrimSpace(r.Model) == "" {
		return nil, fmt.Errorf("an AI principal must name its model")
	}
	for k := range r.Detail {
		lower := strings.ToLower(k)
		for _, bad := range forbidden {
			if strings.Contains(lower, bad) {
				return nil, fmt.Errorf(
					"detail key %q looks like it carries a secret or content; those are "+
						"not logged at all, redacted or otherwise", k)
			}
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	e := &Event{
		Seq: l.seq, At: time.Now().UTC().Format(time.RFC3339Nano),
		Prev: l.last, Action: r.Action, Resource: r.Resource, Source: l.src,
		Outcome: r.Outcome, Principal: l.pseudonym(r.Principal), Kind: r.Kind,
		Model: r.Model, Detail: r.Detail,
	}
	h, err := e.computeHash()
	if err != nil {
		l.seq--
		return nil, err
	}
	e.Hash = h

	line, err := json.Marshal(e)
	if err != nil {
		l.seq--
		return nil, err
	}

	// Append-only, and fsynced. An audit record still in a buffer when the
	// process dies is a record of an event that is now invisible.
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		l.seq--
		return nil, err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		l.seq--
		return nil, err
	}
	if err := f.Sync(); err != nil {
		l.seq--
		return nil, err
	}

	l.last = e.Hash
	return e, nil
}

// Read loads every event.
func Read(path string) ([]Event, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			// A malformed line is itself a finding. Reporting it as an error
			// rather than skipping it is the point: silent tolerance of
			// unreadable entries is how a tampered log passes review.
			return out, fmt.Errorf("entry %d is not readable: %w", len(out)+1, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// Problem is a break in the chain.
type Problem struct {
	Seq    int64
	Reason string
}

// Verify walks the chain and reports the first thing wrong with it.
//
// Three failures are distinguished because they mean different things: an entry
// whose own hash does not match was altered; one whose prev does not match was
// inserted or had a neighbour removed; a sequence gap means an entry was
// deleted.
func Verify(events []Event) (bool, []Problem) {
	var problems []Problem
	prev := ""
	var lastSeq int64

	for i := range events {
		e := events[i]

		want, err := e.computeHash()
		if err != nil {
			problems = append(problems, Problem{e.Seq, "entry cannot be re-hashed"})
			continue
		}
		if want != e.Hash {
			problems = append(problems, Problem{e.Seq,
				"the entry does not match its own hash; it was altered after being written"})
		}
		if e.Prev != prev {
			problems = append(problems, Problem{e.Seq,
				"the chain does not link to the previous entry; something was inserted or removed"})
		}
		if lastSeq != 0 && e.Seq != lastSeq+1 {
			problems = append(problems, Problem{e.Seq,
				fmt.Sprintf("sequence jumps from %d; an entry was deleted", lastSeq)})
		}
		prev, lastSeq = e.Hash, e.Seq
	}
	return len(problems) == 0, problems
}

// VerifyFile is Verify over a file on disk.
func VerifyFile(path string) (int, bool, []Problem, error) {
	events, err := Read(path)
	if err != nil {
		return len(events), false, []Problem{{0, err.Error()}}, nil
	}
	ok, problems := Verify(events)
	return len(events), ok, problems, nil
}

// Export writes events out for a SIEM, one JSON object per line.
func Export(events []Event, w io.Writer) error {
	enc := json.NewEncoder(w)
	for i := range events {
		if err := enc.Encode(events[i]); err != nil {
			return err
		}
	}
	return nil
}
