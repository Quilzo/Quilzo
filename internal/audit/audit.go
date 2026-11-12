// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

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
// `Verify` says exactly where — except at the end. Entries removed from the
// end leave a shorter chain that verifies, so they show only against a head
// taken while they were there (AgainstHead), and the hashes are not keyed, so
// whoever can rewrite the file can re-chain what is left: the chain alone
// proves nothing against them either.
//
// The chain is what Verify walks, and it is enough for an operator who reads
// the log whole. A third party who audits a log they cannot read needs more:
// proof of one entry without the rest, and proof that nothing before a
// published head moved. For them a Merkle tree is built over the same entries
// (merkle.go, on internal/translog). It is computed from the chain's entries
// and does not replace the chain.
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
// treatment for a credential is not to log it. Nor is the user, password,
// query or fragment of an address a record carries: those are written as
// "…" wherever the address stands (addresses.go).
package audit

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
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
	// KindUnknown is an actor whose nature cannot be known.
	//
	// There is exactly one thing this is for: a failed authentication. Nobody
	// proved who they were — that is what failing means — so calling the actor
	// a person is a claim the log has no basis for, and calling it a service
	// is one the validation below correctly refuses. A credential-stuffing run
	// is not a human, and recording it as one would put a person's shape on
	// every graph drawn from this log.
	//
	// It is never verified, and never carries a principal that resolves to
	// anybody: the identifier is whatever was presented or where it came from.
	KindUnknown Kind = "unknown"
)

func (k Kind) Valid() bool {
	return k == KindHuman || k == KindService || k == KindAI ||
		k == KindUnknown
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

	// Verified says whether the identity was proved or merely asserted.
	//
	// This is the difference between integrity and authenticity, and conflating
	// them produces the worst kind of log: one that is cryptographically intact
	// and substantively false. The chain proves nobody edited a record after it
	// was written. It says nothing about whether the record was true when
	// written — and an identity taken from $USER is true only if nobody minds
	// lying, since `USER=ceo quilzo publish` costs nothing.
	//
	// So an unproven identity is recorded as unproven rather than dressed up as
	// a name. An auditor can then filter for what was actually established,
	// which is the only thing a log is for.
	Verified bool `json:"verified"`

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
	mode os.FileMode
	// size is how long the file was when this handle last read or wrote
	// it. A different size at the next append means another writer has
	// been, and the chain is picked up from the file again.
	size int64
	// torn says the file ends part way through a line.
	torn bool
}

// Options configures a Log.
type Options struct {
	Path string
	// Key pseudonymises identifiers. Without one, principals are written in the
	// clear — see New for why that is a decision rather than a default.
	Key []byte
	// Source names where events come from: a host, a service, a CLI. AU-3(d).
	Source string
	// Mode is the file mode for the log. Zero means ModePrivate.
	Mode os.FileMode
}

// The file mode depends on the deployment, and picking one for both is wrong
// in whichever direction it is picked.
//
// Single account: the log lives in the store and the CMS owns it, so 0600 —
// group-readable would hand the audit record to anybody else on the machine
// for no benefit, and the posture inspector says so.
//
// Separated: the writer owns the log and the CMS is in its group, because the
// CMS is not trusted to *write* the log, which is a different claim from not
// being trusted to read it. Every reader — auditlog, siem, the posture
// inspector itself — needs it, and at 0600 the correct configuration was the
// one that broke the tooling.
//
// Hard-coding 0640 fixed that and made the inspector flag its own default as a
// high-severity exposure with "fix: chmod 600" — the program telling an
// operator to undo the thing that makes the recommended deployment work.
const (
	ModePrivate os.FileMode = 0o600 // in the store, one account
	ModeShared  os.FileMode = 0o640 // the writer owns it, readers share its group
)

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
	mode := opt.Mode
	if mode == 0 {
		mode = ModePrivate
	}
	l := &Log{path: opt.Path, key: opt.Key, src: opt.Source, mode: mode}

	// The source is pseudonymised too, when there is a key.
	//
	// AU-3(d) wants to know where an event came from, and a stable pseudonym
	// answers that: every event from one host still groups together, which is
	// what the field is for. What it stops is the case that makes
	// pseudonymising the principal pointless — a hostname on a single-user
	// machine is a person's name, so emitting it in clear beside a protected
	// principal re-identifies them in the same record.
	if len(l.key) > 0 {
		l.src = l.pseudonym(opt.Source)
	}

	// Resume from the existing chain so appending after a restart continues it
	// rather than starting a second one. Only the last entry is read: every
	// audited action opens a log, and reading the whole file each time made
	// every action cost more the longer the installation had run.
	if err := l.resync(); err != nil {
		return nil, err
	}
	return l, nil
}

// resync picks the chain up from the file: the last complete entry's hash
// and sequence, and the file's size.
func (l *Log) resync() error {
	last, size, torn, err := tail(l.path)
	if err != nil {
		return err
	}
	l.last, l.seq, l.size, l.torn = "", 0, size, torn
	if last != nil {
		l.last, l.seq = last.Hash, last.Seq
	}
	return nil
}

// tail reads the last complete entry of a log, the file's size, and whether
// the file ends part way through a line, as a writer that died mid-write
// leaves it. A line still open that is a whole entry, missing only its
// newline, is the last entry, as it is to Read.
//
// It reads backwards from the end in growing windows, so its cost is the
// length of the last line, not of the log. A last complete line that is not
// an entry, and is not a write left unfinished, is an error: the chain
// cannot be continued from something that is not part of it.
func tail(path string) (*Event, int64, bool, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, 0, false, err
	}
	size := fi.Size()
	if size == 0 {
		return nil, 0, false, nil
	}
	const maxLine = 4 << 20
	for window := int64(64 << 10); ; window *= 4 {
		if window > size {
			window = size
		}
		buf := make([]byte, window)
		if _, err := f.ReadAt(buf, size-window); err != nil && err != io.EOF {
			return nil, size, false, err
		}
		torn := buf[len(buf)-1] != '\n'
		body := buf
		if i := strings.LastIndexByte(string(body), '\n'); i >= 0 {
			// A line still open that is a whole entry is the last entry: the
			// write reached the disk but for its newline. Every reader takes
			// it for one, and the chain carries on from it. Passed over as
			// unfinished, it was not, and the next write took its number and
			// linked to the entry before it: two entries of one number, a
			// fork, reported as tampering after a crash.
			if torn {
				if e := wholeEntry(body[i+1:]); e != nil {
					return e, size, true, nil
				}
			}
			body = body[:i]
		} else if window == size {
			// One line, never finished: nothing complete to continue from,
			// unless all that is missing is its newline.
			return wholeEntry(body), size, true, nil
		} else {
			continue
		}
		// The last non-blank complete line in the window, if its start is in
		// the window too.
		for len(body) > 0 {
			start := strings.LastIndexByte(string(body), '\n') + 1
			if start == 0 && window < size {
				break // the line may begin before the window
			}
			line := strings.TrimSpace(string(body[start:]))
			// A line a write left unfinished, closed off by Append, is passed
			// over like a blank one: the chain carries on from the entry
			// before it, as it does past one still open. A full disk cut a
			// record short and let the next write close it and no more, and
			// then nothing could be written, because the last line was not
			// an entry.
			if line == "" || unfinished(line) {
				if start == 0 {
					return nil, size, torn, nil
				}
				body = body[:start-1]
				continue
			}
			var e Event
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				return nil, size, torn, fmt.Errorf("the last entry is not readable: %w", err)
			}
			return &e, size, torn, nil
		}
		if window == size {
			return nil, size, torn, nil
		}
		if window >= maxLine*2 {
			return nil, size, torn, fmt.Errorf("the last entry is longer than an entry may be")
		}
	}
}

// Pseudonymous reports whether identifiers are being protected.
func (l *Log) Pseudonymous() bool { return len(l.key) > 0 }

// Key is the pseudonymisation key, for computing a handle with Pseudonym.
func (l *Log) Key() []byte { return append([]byte(nil), l.key...) }

// IdentityKeys are detail keys whose values name a person or account.
//
// Pseudonymised like the principal. They were not: the principal was HMAC'd
// and the same person's name sat beside it in clear under "by" or
// "on_behalf_of" — every grant, every agent call, every sign-in — so a log
// exported to a SIEM precisely so it would carry no identities carried them
// all, in the one field nobody thought to check. A key added to this list is
// covered everywhere; a writer inventing a new key for a person is the thing
// a test here refuses.
var IdentityKeys = map[string]bool{
	"by": true, "on_behalf_of": true, "principal": true, "owner": true,
	"granted": true, "for": true, "author": true,
	// The person whose workforce profile was opened. Pseudonymised like the
	// one who opened it; whoever holds the log's key can still answer the
	// question the entry exists for, which is who looked at whose profile.
	"subject": true,
	// Who asked for a change a second administrator decided, and who
	// approved it (internal/dual, the shield and the policy).
	"proposed_by": true, "approved_by": true,
	// Who gave somebody the link they added their first passkey with, an
	// agent's sponsor, and the person who decided what an agent or a call
	// through the gateway waited for.
	"link_by": true, "sponsor": true, "decided_by": true,
	// Whose identity fired something somebody else arranged: the server or
	// the timer that published an entry another person scheduled.
	"fired_by": true,
}

// people are the identifiers a record names as somebody: its principal,
// when a person (or nobody knows who) acted, every value under an identity
// key, and its People. Longest first, so a name inside a longer one is not
// taken for it. The program's own name and its word for nobody named are
// nobody's: it names itself in its own sentences ("quilzo pending
// approve"), and writes "anonymous" where nobody was named.
func (r Record) people() []string {
	var out []string
	add := func(v string) {
		if v = strings.TrimSpace(v); v != "" && v != "quilzo" && v != "anonymous" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	if r.Kind == KindHuman || r.Kind == KindUnknown {
		add(r.Principal)
	}
	for k, v := range r.Detail {
		if IdentityKeys[k] {
			add(v)
		}
	}
	for _, v := range r.People {
		add(v)
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// pseudonymDetail returns detail with identity values pseudonymised, and
// each of people pseudonymised where another detail names them too,
// leaving the caller's map alone.
func (l *Log) pseudonymDetail(d map[string]string, people []string) map[string]string {
	if len(l.key) == 0 || len(d) == 0 {
		return d
	}
	out := make(map[string]string, len(d))
	for k, v := range d {
		if IdentityKeys[k] && v != "" {
			v = l.pseudonym(v)
		} else {
			v = l.namedIn(v, people)
		}
		out[k] = v
	}
	return out
}

// namedIn is s with each of people, where it stands as a word, replaced by
// their pseudonym.
//
// A record's identity fields were pseudonymised and the same person stood
// in clear in its sentences ("make lee admin on /", "rae is reader on /",
// "lee declined this") and its resource ("/lee"), in the log and in every
// batch streamed from it. Only the people the record itself names are
// replaced, each by the handle its identity field has, so the sentence
// still reads and still matches the rest of the log; a writer mentioning
// somebody it does not name under an identity key is what
// cmd/quilzo/auditnames_test.go refuses.
func (l *Log) namedIn(s string, people []string) string {
	if len(l.key) == 0 || s == "" {
		return s
	}
	for _, p := range people {
		s = replaceWord(s, p, l.pseudonym(p))
	}
	return s
}

// replaceWord replaces each occurrence of word in s that is not part of a
// longer word, address or path segment's name. A letter, digit, '_', '@'
// or '-' on either side, a '.' before it, or anything not ASCII, joins it
// to its neighbour; a '.' after it ends a sentence.
func replaceWord(s, word, with string) string {
	joins := func(c byte, before bool) bool {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '@', c == '-', c >= 0x80:
			return true
		}
		return before && c == '.'
	}
	var b strings.Builder
	rest := s
	for {
		i := strings.Index(rest, word)
		if i < 0 {
			break
		}
		end := i + len(word)
		if (i > 0 && joins(rest[i-1], true)) || (end < len(rest) && joins(rest[end], false)) {
			b.WriteString(rest[:i+1])
			rest = rest[i+1:]
			continue
		}
		b.WriteString(rest[:i])
		b.WriteString(with)
		rest = rest[end:]
	}
	if b.Len() == 0 {
		return s
	}
	b.WriteString(rest)
	return b.String()
}

// AsWritten is a record's resource and details as a log kept with key
// writes them: what anybody reading the log, or a stream of it, sees.
func AsWritten(key []byte, r Record) (string, map[string]string) {
	l := &Log{key: key}
	r.Resource, r.Detail = WithoutCredentials(r.Resource), detailWithoutCredentials(r.Detail)
	people := r.people()
	return l.namedIn(r.Resource, people), l.pseudonymDetail(r.Detail, people)
}

// pseudonym maps an identifier to a stable, non-reversible handle.
func (l *Log) pseudonym(id string) string {
	if id == "" {
		return ""
	}
	if len(l.key) == 0 {
		return id
	}
	return Pseudonym(l.key, id)
}

// Pseudonym is the handle an identifier has in a log kept with this key:
// the one derivation, for anything that must match the log without holding
// identities itself (internal/shield blocks a source by its handle).
func Pseudonym(key []byte, id string) string {
	m := hmac.New(sha256.New, key)
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

	// Verified must be set by whoever proved the identity, and only by them.
	// Defaulting to false means a caller that forgets records an honest
	// "unverified" rather than an unearned claim.
	Verified bool
	// People are people the record names in its text without a detail of
	// their own: everybody a posture finding lists, say. A keyed log
	// pseudonymises them wherever the record names them, as it does the
	// people under identity keys, and keeps nothing else of them.
	People []string
}

// forbidden names Detail keys that must never appear. Content bodies and
// credentials do not belong in an audit log at any level of redaction.
var forbidden = []string{"token", "secret", "password", "key", "body", "content"}

// ForbiddenKey explains why a Detail key is refused, or answers empty.
//
// Exported because the refusal is the whole record, not the key: Append
// returns an error and the callers print it and carry on, so a record with one
// badly-named key is not a redacted record — it is no record. Two of them were
// shipped that way. "token" for the id of a credential being revoked, and
// "content" for the hash of a proposal a publish gate had just refused: both
// are identifiers rather than secrets, both matched a substring, and both acts
// went unlogged while the code that wrote them looked correct.
//
// So the list is checkable from outside, and a test walks the source and fails
// on a literal that would be refused — before it becomes a hole in the trail
// that only shows up when somebody goes looking for an act that is not there.
func ForbiddenKey(k string) string {
	lower := strings.ToLower(k)
	for _, bad := range forbidden {
		if strings.Contains(lower, bad) {
			return fmt.Sprintf("detail key %q looks like it carries a secret "+
				"or content; those are not logged at all, redacted or "+
				"otherwise. The whole record is refused, so rename the key "+
				"(%q is the part that matched) rather than leaving the act "+
				"unlogged", k, bad)
		}
	}
	return ""
}

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
	if r.Kind == KindUnknown && r.Verified {
		// The inverse of the service rule below. An unknown actor that is
		// somehow verified is a contradiction: verification is what makes an
		// actor known.
		return nil, fmt.Errorf(
			"an unknown principal cannot be verified: verification is what " +
				"would make it known")
	}
	if r.Kind == KindService && !r.Verified {
		// A service identity exists only because a credential was presented. An
		// unverified one is a self-declared string wearing a service label,
		// which is precisely the confusion this field exists to prevent.
		return nil, fmt.Errorf(
			"a service principal cannot be unverified: it is only a service " +
				"because a credential proved it")
	}
	for k := range r.Detail {
		if why := ForbiddenKey(k); why != "" {
			return nil, fmt.Errorf("%s", why)
		}
	}
	// No address is written with the credentials it can carry, whoever
	// wrote the record (WithoutCredentials).
	r.Resource, r.Detail = WithoutCredentials(r.Resource), detailWithoutCredentials(r.Detail)

	l.mu.Lock()
	defer l.mu.Unlock()

	// One writer at a time on the file, across every handle and process: the
	// admin, the site and the command line all append to this log, each
	// action through a handle of its own. Two writers that read the same
	// last entry would both write the next sequence number after it, forking
	// the chain, and a writer that read another's half-written line lost its
	// own record.
	unlock, err := atomicfile.Lock(l.path + ".lock")
	if err != nil {
		return nil, err
	}
	defer unlock()
	if fi, serr := os.Stat(l.path); serr == nil && fi.Size() != l.size {
		if err := l.resync(); err != nil {
			return nil, err
		}
	}
	// A line a writer died part way through is closed off, so this entry
	// starts on a line of its own. The broken line stays, and Read and Verify
	// report it: a crash leaves a visible mark rather than none, and the
	// chain carries on from the last entry that was whole.
	if l.torn {
		if err := l.write([]byte("\n")); err != nil {
			return nil, err
		}
		l.torn = false
	}

	l.seq++
	people := r.people()
	e := &Event{
		Seq: l.seq, At: time.Now().UTC().Format(time.RFC3339Nano),
		Prev: l.last, Action: r.Action, Resource: l.namedIn(r.Resource, people), Source: l.src,
		Outcome: r.Outcome, Principal: l.pseudonym(r.Principal), Kind: r.Kind,
		Verified: r.Verified, Model: r.Model, Detail: l.pseudonymDetail(r.Detail, people),
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

	if err := l.write(append(line, '\n')); err != nil {
		l.seq--
		return nil, err
	}
	l.last = e.Hash
	return e, nil
}

// write appends bytes to the log file, fsynced: an audit record still in a
// buffer when the process dies is a record of an event that is now
// invisible. Called with the file lock held.
func (l *Log) write(b []byte) error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, l.mode)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	l.size = fi.Size()
	return nil
}

// Events reads back every entry of this log's own file, as it stood when
// asked.
//
// For the log writer, which signs a tree head over the file it keeps rather
// than over one a client describes (internal/logd). A line being written is
// never read half-way: Read reports a line it cannot parse as a finding,
// and a head refused because a record happened to be arriving at that
// moment is a head refused for nothing.
//
// The locks Append takes are held only to open the file and learn where its
// last whole line ends, not while it is read. Reading a log of a year or
// two under them took over a second, and every record submitted meanwhile
// waited: with a few heads asked for at once, records ran past the writer's
// timeout and were not written. The file only grows, by whole lines written
// under those locks, so what lies before that point does not change while
// it is read.
func (l *Log) Events() ([]Event, error) {
	f, size, err := l.whole()
	if err != nil || f == nil {
		return nil, err
	}
	defer f.Close()
	return readEvents(io.LimitReader(f, size))
}

// whole opens the log and says how much of it is whole lines, under the
// locks Append takes. Nil when there is no log yet.
func (l *Log) whole() (*os.File, int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	unlock, err := atomicfile.Lock(l.path + ".lock")
	if err != nil {
		return nil, 0, err
	}
	defer unlock()
	f, err := os.Open(l.path)
	if os.IsNotExist(err) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, fi.Size(), nil
}

// Read loads every event, up to where the file stands once no write to it
// is part way through (settled).
func Read(path string) ([]Event, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Only a regular file has a size to read up to. Whatever else the path
	// names, a pipe a log is handed over through say, is read to its end,
	// as every log was before Read stopped where one had settled. Asked its
	// size, a pipe says none, so Read returned no entries and no error, and
	// Check called a log nobody had read an empty one that is intact.
	if fi, err := f.Stat(); err != nil {
		return nil, err
	} else if !fi.Mode().IsRegular() {
		return readEvents(f)
	}
	size, err := settled(f, path)
	if err != nil {
		return nil, err
	}
	return readEvents(io.LimitReader(f, size))
}

// writeGrace is how long a reader that may not take the writers' lock
// waits for a last line with no end to be finished, before taking it for
// one a crash left (settled). A variable so that a test can be a writer
// slower than any is.
var writeGrace = 100 * time.Millisecond

// settled is how much of the log open in f a reader reads: its size, once
// nobody can still be writing its last line.
//
// Every record is one write, made holding the lock every writer takes
// (Append), and the only newline in it is its last byte. A reader sees a
// write in progress all the same: the kernel makes the file longer a page
// at a time as it copies the write in, so a reader could find the first
// part of a record as the last line, and took it for a write a crash left
// unfinished. A live, healthy log was then not intact for a moment: the
// admin's log page and `auditlog verify` called it a crash, and posture
// raised its finding about the chain during ordinary use. So a last line
// with no end is judged only once the lock is free: this takes it, looks at
// the size, and lets it go at once, since every writer waits while it is
// held. A reader that may not take it waits up to writeGrace for the line
// to end instead: in a separated deployment the lock is the writer's
// account's alone, as it has to be, because a reader that could take it
// could hold it and stop every record.
func settled(f *os.File, path string) (int64, error) {
	size, ends, err := lineEnd(f)
	if err != nil || ends {
		return size, err
	}
	lock, err := os.Open(path + ".lock")
	if os.IsNotExist(err) {
		// Every writer makes the lock before it writes, so there is no
		// write in progress.
		return size, nil
	}
	if err == nil {
		defer lock.Close()
		if atomicfile.LockFile(lock) == nil {
			fi, err := f.Stat()
			atomicfile.UnlockFile(lock)
			if err != nil {
				return 0, err
			}
			return fi.Size(), nil
		}
	}
	for deadline := time.Now().Add(writeGrace); time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
		if size, ends, err = lineEnd(f); err != nil || ends {
			return size, err
		}
	}
	return size, nil
}

// lineEnd is the size of the file open in f, and whether it is empty or
// ends a line, as every write leaves it.
func lineEnd(f *os.File) (int64, bool, error) {
	fi, err := f.Stat()
	if err != nil {
		return 0, false, err
	}
	size := fi.Size()
	if size == 0 {
		return 0, true, nil
	}
	last := make([]byte, 1)
	if _, err := f.ReadAt(last, size-1); err != nil && err != io.EOF {
		return 0, false, err
	}
	return size, last[0] == '\n', nil
}

func readEvents(r io.Reader) ([]Event, error) {
	var out []Event
	var bad []BadLine
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			// A malformed line is itself a finding. Reporting it as an error
			// rather than skipping it is the point: silent tolerance of
			// unreadable entries is how a tampered log passes review. It is
			// not the end of the log, though: what follows it is read too
			// (Unreadable says why).
			b := BadLine{Line: n, Torn: unfinished(line), Err: err}
			if len(out) > 0 {
				b.After = out[len(out)-1].Seq
			}
			bad = append(bad, b)
			continue
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	if len(bad) > 0 {
		return out, &Unreadable{Lines: bad}
	}
	return out, nil
}

// unfinished says a line stops part way through a JSON value, as a write
// cut short leaves it, rather than holding something that is not one.
//
// Zeros at its end are what was not written. A filesystem that put the
// file's new size on disk before the data leaves the rest of the write as
// zeros after a crash. A line of them, a record that stops in them, or a
// whole record whose newline is one of them was called tampering, and such
// a line, closed off by the next write with nothing after it, stopped the
// log opening at all.
func unfinished(line string) bool {
	if strings.TrimRight(line, "\x00") != line {
		return true
	}
	return errors.Is(json.NewDecoder(strings.NewReader(line)).Decode(new(json.RawMessage)),
		io.ErrUnexpectedEOF)
}

// wholeEntry is a line still open at the end of a log, if it is an entry, as
// Read takes it: nil when it is not.
func wholeEntry(b []byte) *Event {
	line := strings.TrimSpace(string(b))
	if line == "" {
		return nil
	}
	var e Event
	if json.Unmarshal([]byte(line), &e) != nil {
		return nil
	}
	return &e
}

// Unreadable is the lines of a log that are not entries. Read and Events
// return it, with every whole entry, when those lines are all that was
// wrong.
//
// Reading stopped at the first one. Append is built to carry on past a line
// a writer died part way through, closing it off and chaining from the last
// whole entry, and every reader then stopped there: one crash or full disk
// blanked the audit log screen, `auditlog show` and every export, stopped
// the stream, the heads and agentwatch, and was reported by `auditlog
// verify` as tampering, with every record written after it unreadable for
// good. The lines are still reported, where they are; a reader that works
// from the entries takes them (Entries), and one that reports on the log
// says what the lines are (Check).
type Unreadable struct {
	Lines []BadLine
}

// BadLine is one line of a log that is not an entry.
type BadLine struct {
	// Line is its line number in the file, from 1.
	Line int
	// After is the sequence number of the last whole entry before it, 0
	// when there is none.
	After int64
	// Torn says it stops part way through an entry, as a write a crash or a
	// full disk cut short leaves it.
	Torn bool
	Err  error
}

func (u *Unreadable) Error() string {
	b := u.Lines[0]
	msg := fmt.Sprintf("line %d of the log is not an entry: %v", b.Line, b.Err)
	if b.Torn {
		msg = fmt.Sprintf("line %d of the log is a write left unfinished (%v)", b.Line, b.Err)
	}
	if more := len(u.Lines) - 1; more > 0 {
		msg += fmt.Sprintf(", and %d more line(s) are not entries", more)
	}
	return msg
}

// Problems are the lines as problems, each at the entry before it.
func (u *Unreadable) Problems() []Problem {
	out := make([]Problem, 0, len(u.Lines))
	for _, b := range u.Lines {
		where := fmt.Sprintf("line %d of the file, after this entry,", b.Line)
		if b.After == 0 {
			where = fmt.Sprintf("line %d of the file, before the first entry,", b.Line)
		}
		why := fmt.Sprintf("%s is not an entry: %v", where, b.Err)
		if b.Torn {
			why = fmt.Sprintf("%s is a write left unfinished, as a crash or a full disk leaves "+
				"one: it is not an entry, and the record it was making is lost", where)
		}
		out = append(out, Problem{Seq: b.After, Reason: why})
	}
	return out
}

// Entries is what Read or Events returned, for a reader that works from the
// entries: every whole entry, and the error only when it is something other
// than lines that are not entries. Those lines are not part of the chain or
// the tree, so heads, exports and the stream over the whole entries are
// what they would have been without them; the views that report on the log
// report them (Check).
func Entries(events []Event, err error) ([]Event, error) {
	var bad *Unreadable
	if errors.As(err, &bad) {
		return events, nil
	}
	return events, err
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
func Verify(events []Event) (bool, []Problem) { return VerifyFrom(events, "") }

// VerifyFrom verifies a run of entries that begins partway along a chain.
//
// A slice of a chain cannot be checked with Verify, because the first entry
// links back to one that was not included — so Verify reports a break that is
// not there. That matters for exports: sending last week's entries to a SIEM is
// the normal case, and a verifier on the other end has to be able to check what
// it received.
//
// anchor is the hash the first entry is expected to link to. Empty means the
// start of the chain, which is what Verify passes.
func VerifyFrom(events []Event, anchor string) (bool, []Problem) {
	var problems []Problem
	c := link{prev: anchor}
	for i := range events {
		problems = c.check(&events[i], problems)
	}
	return len(problems) == 0, problems
}

// link is what verifying carries from one entry to the next. One check, used
// by Verify and by an Index reading a log as it grows, so the two cannot come
// to disagree about what an intact chain is.
type link struct {
	prev    string
	lastSeq int64
}

// check verifies the next entry and adds what is wrong with it to problems.
func (c *link) check(e *Event, problems []Problem) []Problem {
	want, err := e.computeHash()
	return c.checkHashed(e, want, err, problems)
}

// checkHashed is check given what computeHash made of the entry, for a
// reader that needs the hash again: an Index takes the entry's leaf from it
// (leafOf) rather than hashing every entry twice.
func (c *link) checkHashed(e *Event, want string, err error, problems []Problem) []Problem {
	if err != nil {
		return append(problems, Problem{e.Seq, "entry cannot be re-hashed"})
	}
	if want != e.Hash {
		problems = append(problems, Problem{e.Seq,
			"the entry does not match its own hash; it was altered after being written"})
	}
	if e.Prev != c.prev {
		problems = append(problems, Problem{e.Seq,
			"the chain does not link to the previous entry; something was inserted or removed"})
	}
	if c.lastSeq != 0 && e.Seq != c.lastSeq+1 {
		problems = append(problems, Problem{e.Seq,
			fmt.Sprintf("sequence jumps from %d; an entry was deleted", c.lastSeq)})
	}
	c.prev, c.lastSeq = e.Hash, e.Seq
	return problems
}

// Report is what checking a log found.
type Report struct {
	// Intact says nothing was: every line is an entry, and every entry
	// re-hashes and links to the one before it.
	Intact   bool
	Problems []Problem
	// Unfinished is how many of the problems are writes left unfinished
	// (BadLine.Torn).
	Unfinished int
}

// Crashed says the only problems are writes left unfinished: every whole
// entry re-hashes and links up around them, so nothing a crash would not do
// is evident. A crash is not tampering, and calling it that is the alarm
// that teaches whoever hears it to ignore the next one.
func (r Report) Crashed() bool {
	return len(r.Problems) > 0 && r.Unfinished == len(r.Problems)
}

// Check is what can be said of a log from what Read or Events returned:
// its chain, and its lines that are not entries. Any other error reading
// it is returned, since then nothing can be said.
func Check(events []Event, readErr error) (Report, error) {
	var bad *Unreadable
	if readErr != nil && !errors.As(readErr, &bad) {
		return Report{}, readErr
	}
	_, problems := Verify(events)
	var lines []BadLine
	if bad != nil {
		lines = bad.Lines
	}
	return reportOf(problems, lines), nil
}

// reportOf is a Report from the breaks in a log's chain and its lines that
// are not entries: what Check says, and what an Index's look says of the
// same bytes (Snapshot.Report), made in one place so the two cannot come to
// disagree.
//
// Where every line is an entry, the problems are the chain's, in the order
// Verify finds them, which is the order of the file. The lines that are not
// entries are put among them by number, and only then: sorted by number
// always, the problems of a log whose lines had been moved, or whose
// numbers had been edited, came out in an order Verify does not give, and
// a look at it no longer said what Verify says of the same bytes.
func reportOf(chain []Problem, bad []BadLine) Report {
	r := Report{Intact: len(chain) == 0 && len(bad) == 0}
	if len(bad) == 0 {
		r.Problems = chain
		return r
	}
	r.Problems = (&Unreadable{Lines: bad}).Problems()
	for _, b := range bad {
		if b.Torn {
			r.Unfinished++
		}
	}
	r.Problems = append(r.Problems, chain...)
	sort.SliceStable(r.Problems, func(i, j int) bool { return r.Problems[i].Seq < r.Problems[j].Seq })
	return r
}

// VerifyFile is Verify over a file on disk, with its lines that are not
// entries among the problems (Check).
func VerifyFile(path string) (int, bool, []Problem, error) {
	events, err := Read(path)
	r, err := Check(events, err)
	if err != nil {
		return len(events), false, []Problem{{0, err.Error()}}, nil
	}
	return len(events), r.Intact, r.Problems, nil
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
