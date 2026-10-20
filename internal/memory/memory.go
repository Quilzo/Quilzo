// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package memory is what agents remember between runs, kept so that the
// people it is about can see it, and so that what somebody else wrote
// cannot quietly become what an agent believes.
//
// # Whose it is
//
// An entry is about the person who started the run it was learnt in, and
// only their runs of that agent recall it: what an agent learnt helping one
// person is not what it tells the next. Procedural memory, how to do
// something, is the agent's own and recalled for everybody, and so is never
// about anybody.
//
// # Where it came from
//
// Every entry names its run and step. One learnt in a run that had read
// content somebody else may have written is held: it is not recalled until a
// person has read it and confirmed it. That is the answer to memory
// poisoning (OWASP ASI06): an instruction planted in a page can make an
// agent write a memory, and the memory would otherwise steer every run
// after it, long after the page was fixed. Here it waits for a person.
//
// # How long
//
// Each agent declares how long it keeps memory, ninety days at most. Held
// entries go sooner, in two weeks, because a memory nobody has confirmed in
// that time is one nobody wanted. Expired entries are removed by the
// server's upkeep, not merely hidden.
//
// # Forgetting
//
// A person sees everything any agent remembers about them and removes any
// of it, or all of it at once, across every agent. What was removed is
// recorded by id and count. Never by digest: the audit log cannot forget,
// and a digest of "Dana is in Lisbon" is that sentence to anybody who can
// guess it. When the identity provider deletes somebody, their memory goes
// too.
package memory

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/plaintext"
	"github.com/quilzo/quilzo/internal/search"
	"github.com/quilzo/quilzo/internal/vector"
)

// The kinds, the manifest's tiers.
const (
	Episodic   = "episodic"
	Semantic   = "semantic"
	Procedural = "procedural"
)

// Kinds is every kind.
var Kinds = map[string]bool{Episodic: true, Semantic: true, Procedural: true}

// Tiers say how far what was learnt can be trusted, from what the run had
// read when it learnt it: nothing but what the person said; only what is
// published, which somebody reviewed; or something nobody here reviewed, a
// draft, a tool's answer or another agent's.
const (
	TierPerson     = "person"
	TierPublished  = "published"
	TierUnreviewed = "unreviewed"
)

// TierRetain is the longest each tier is kept, whatever an agent declares:
// what a tool returned is not kept for a season because an agent would
// like it to be.
var TierRetain = map[string]time.Duration{
	TierPerson:     MaxRetain,
	TierPublished:  MaxRetain,
	TierUnreviewed: 30 * 24 * time.Hour,
}

// tierRank orders the tiers by trust; an entry from before tiers is the
// least trusted.
var tierRank = map[string]int{TierPerson: 3, TierPublished: 2, TierUnreviewed: 1}

// TierWords is each tier as a person reads it.
var TierWords = map[string]string{
	TierPerson:     "from what the person said",
	TierPublished:  "after reading published pages",
	TierUnreviewed: "after reading what nobody here reviewed",
}

// keepFor is retain, no longer than the tier allows.
func keepFor(tier string, retain time.Duration) time.Duration {
	if most, ok := TierRetain[tier]; ok && retain > most {
		return most
	}
	return retain
}

// Bounds.
const (
	MaxText       = 2000 // characters in one entry
	MaxPerSubject = 500  // entries about one person, for one agent
	MaxPerAgent   = 5000
	HeldFor       = 14 * 24 * time.Hour
	MaxRetain     = 90 * 24 * time.Hour // the ceiling agent.MaxRetain declares
)

// Entry is one thing remembered.
type Entry struct {
	ID    string `json:"id"`
	Agent string `json:"agent"`
	// About is the person it is about; empty for procedural memory, which
	// is the agent's own.
	About string `json:"about,omitempty"`
	Kind  string `json:"kind"`
	Text  string `json:"text"`
	// Tier is how far it can be trusted: see TierPerson.
	Tier string `json:"tier,omitempty"`
	// Edited is when the person it is about last rewrote it.
	Edited time.Time `json:"edited,omitzero"`
	// Run and Step are where it was learnt, and By who started that run.
	Run  string `json:"run"`
	Step int    `json:"step,omitempty"`
	By   string `json:"by"`
	// Held is an entry learnt after reading somebody else's words, recalled
	// only once a person confirms it; Sources is what those words were.
	Held        bool      `json:"held,omitempty"`
	Sources     string    `json:"sources,omitempty"`
	Confirmed   time.Time `json:"confirmed,omitzero"`
	ConfirmedBy string    `json:"confirmed_by,omitempty"`
	Created     time.Time `json:"created"`
	Expires     time.Time `json:"expires"`
	// Digest is the text's, for telling the same memory learnt twice
	// apart from a new one. It stays in this store, never in the log.
	Digest string `json:"digest"`

	// Key names what a fact is about, such as "shipping_city", so a newer
	// fact about the same thing closes the older one instead of sitting
	// beside it. A closed fact is kept, with when it stopped being true and
	// what replaced it, so "what changed when" has an answer; it is not
	// recalled. A held fact closes nothing until a person confirms it: a
	// planted instruction cannot retire a true fact by being learnt.
	Key        string    `json:"key,omitempty"`
	ValidUntil time.Time `json:"valid_until,omitzero"`
	Replaces   string    `json:"replaces,omitempty"`
	ReplacedBy string    `json:"replaced_by,omitempty"`
}

// Current reports whether an entry is still true at now.
func (e Entry) Current(now time.Time) bool { return e.ValidUntil.IsZero() || now.Before(e.ValidUntil) }

var reKey = regexp.MustCompile(`^[a-z][a-z0-9_]{0,59}$`)

// closeFacts closes every current fact with e's key about the same person,
// other than e, as replaced by e. The caller holds the lock.
func closeFacts(f *file, e *Entry, now time.Time) {
	if e.Key == "" {
		return
	}
	for i := range f.Entries {
		o := &f.Entries[i]
		if o.ID == e.ID || o.Key != e.Key || o.About != e.About || o.Agent != e.Agent || o.Held || !o.Current(now) {
			continue
		}
		o.ValidUntil, o.ReplacedBy = now.UTC(), e.ID
		if e.Replaces == "" {
			e.Replaces = o.ID
		}
	}
}

// Store is every agent's memory, a file per agent under Dir.
type Store struct {
	Dir string
	mu  sync.Mutex
}

type file struct {
	Entries []Entry `json:"entries"`
}

var reAgent = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

func (s *Store) path(agent string) (string, error) {
	if !reAgent.MatchString(agent) {
		return "", fmt.Errorf("%q is not an agent's name", agent)
	}
	return filepath.Join(s.Dir, agent+".json"), nil
}

// lockAgent takes the lock on one agent's memory, across processes, for a
// read, a change and a write.
//
// The mutex beside it serialises one Store, and the host makes a Store per
// call, so it serialised nothing: a run that read an agent's memory before
// somebody had it forget a person, and wrote after, put the forgotten
// entries back while the receipt said they were gone. That is an erasure
// undone (GDPR Article 17), so every change holds the file's own lock.
func (s *Store) lockAgent(agent string) (func(), error) {
	p, err := s.path(agent)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, err
	}
	return atomicfile.Lock(p + ".lock")
}

func (s *Store) load(agent string) (file, error) {
	var f file
	p, err := s.path(agent)
	if err != nil {
		return f, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return f, fmt.Errorf("%s's memory cannot be read: %w", agent, err)
	}
	return f, nil
}

func (s *Store) save(agent string, f file) error {
	p, err := s.path(agent)
	if err != nil {
		return err
	}
	if len(f.Entries) == 0 {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		return err
	}
	return atomicfile.Write(p, b, 0o600)
}

func digest(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "m_" + hex.EncodeToString(b)
}

// Remember keeps an entry for as long as retain says. The same thing
// remembered again about the same person is the one entry, kept longer.
func (s *Store) Remember(e Entry, retain time.Duration, now time.Time) (Entry, error) {
	e.Text = strings.TrimSpace(plaintext.Clean(e.Text))
	switch {
	case !Kinds[e.Kind]:
		return Entry{}, fmt.Errorf("%q is not a kind of memory: episodic, semantic or procedural", e.Kind)
	case e.Text == "":
		return Entry{}, errors.New("nothing to remember")
	case utf8.RuneCountInString(e.Text) > MaxText:
		return Entry{}, fmt.Errorf("a memory is at most %d characters; this is a document, not a memory", MaxText)
	case e.Kind == Procedural && e.About != "":
		return Entry{}, errors.New("procedural memory is the agent's own, about nobody")
	case e.Kind != Procedural && e.About == "":
		return Entry{}, errors.New("what an agent remembers from a run is about the person who started it")
	case retain <= 0 || retain > MaxRetain:
		return Entry{}, fmt.Errorf("memory is kept for a declared time, at most %d days", int(MaxRetain.Hours()/24))
	case e.Tier != "" && tierRank[e.Tier] == 0:
		return Entry{}, fmt.Errorf("%q is not a tier: person, published or unreviewed", e.Tier)
	case e.Key != "" && e.Kind != Semantic:
		return Entry{}, errors.New("only a fact has a key; episodes and procedures are not replaced")
	case e.Key != "" && !reKey.MatchString(e.Key):
		return Entry{}, fmt.Errorf("%q is not a key: lower-case words joined by underscores", e.Key)
	}
	expires := func(held bool) time.Time {
		keep := keepFor(e.Tier, retain)
		if held && keep > HeldFor {
			keep = HeldFor
		}
		return now.Add(keep).UTC()
	}
	e.Digest, e.Created = digest(e.Text), now.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockAgent(e.Agent)
	if err != nil {
		return Entry{}, err
	}
	defer unlock()
	f, err := s.load(e.Agent)
	if err != nil {
		return Entry{}, err
	}
	for i, old := range f.Entries {
		if old.Digest == e.Digest && old.About == e.About && old.Kind == e.Kind {
			// Learnt again: kept longer, and only ever more trusted, never
			// less, by being said again in a run that was not.
			if !old.Held || e.Held {
				e.Held, e.Confirmed, e.ConfirmedBy = old.Held, old.Confirmed, old.ConfirmedBy
			}
			if tierRank[old.Tier] > tierRank[e.Tier] {
				e.Tier = old.Tier
			}
			e.Edited = old.Edited
			e.ID, e.Expires = old.ID, expires(e.Held)
			f.Entries[i] = e
			return e, s.save(e.Agent, f)
		}
	}
	e.ID, e.Expires = newID(), expires(e.Held)
	if !e.Held {
		closeFacts(&f, &e, now)
	}
	f.Entries = append(f.Entries, e)
	// Bounded: the oldest about the same person goes first, then the
	// oldest of all.
	about := 0
	for _, x := range f.Entries {
		if x.About == e.About {
			about++
		}
	}
	sort.SliceStable(f.Entries, func(i, j int) bool { return f.Entries[i].Created.Before(f.Entries[j].Created) })
	for about > MaxPerSubject {
		for i, x := range f.Entries {
			if x.About == e.About {
				f.Entries = append(f.Entries[:i], f.Entries[i+1:]...)
				about--
				break
			}
		}
	}
	if len(f.Entries) > MaxPerAgent {
		f.Entries = f.Entries[len(f.Entries)-MaxPerAgent:]
	}
	return e, s.save(e.Agent, f)
}

// Recall is what an agent remembers for a person's run: about them, and
// its own procedures, never held, never expired, the most relevant to the
// query first and at most limit of them.
func (s *Store) Recall(agent, about, query string, kinds map[string]bool, limit int, now time.Time) ([]Entry, error) {
	s.mu.Lock()
	f, err := s.load(agent)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var cands []Entry
	for _, e := range f.Entries {
		if e.Held || !now.Before(e.Expires) || !kinds[e.Kind] || !e.Current(now) {
			continue
		}
		if e.About != "" && e.About != about {
			continue
		}
		cands = append(cands, e)
	}
	var out []Entry
	chars := 0
	for _, e := range rank(cands, query) {
		if len(out) == limit || chars+len(e.Text) > RecallChars {
			break
		}
		out = append(out, e)
		chars += len(e.Text)
	}
	return out, nil
}

// RecallChars bounds what one recall returns, in characters: memory is
// context a model reads, and a recall that fills it crowds out the task.
const RecallChars = 6000

// rrfK is reciprocal rank fusion's constant, from Cormack et al. (2009).
const rrfK = 60

// rank orders what may be recalled for a query: words (BM25) and vectors
// fused by reciprocal rank, with how recent each is as a lighter third
// list, and only what matched the query at all. With no query, the most
// recent first. Text is what is ranked, whatever model the agent uses, so
// a change of model changes nothing that was learnt.
func rank(cands []Entry, query string) []Entry {
	recent := append([]Entry(nil), cands...)
	sort.SliceStable(recent, func(i, j int) bool { return recent[i].Created.After(recent[j].Created) })
	if strings.TrimSpace(query) == "" {
		return recent
	}
	pages := make(map[string]any, len(cands))
	for _, e := range cands {
		pages[e.ID] = map[string]any{"text": e.Text, "key": strings.ReplaceAll(e.Key, "_", " ")}
	}
	score := map[string]float64{}
	for i, r := range search.Build("memory", pages).Search(query, len(cands)) {
		score[r.Page] += 1 / float64(rrfK+i+1)
	}
	idx := vector.Build("memory", pages, search.Tokenise)
	if near, err := idx.Nearest(idx.Embed(query, search.Tokenise), len(cands), ""); err == nil {
		for i, n := range near {
			if n.Score > 0 {
				score[n.Page] += 1 / float64(rrfK+i+1)
			}
		}
	}
	var out []Entry
	for i, e := range recent {
		if score[e.ID] == 0 {
			continue
		}
		score[e.ID] += 0.5 / float64(rrfK+i+1)
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return score[out[i].ID] > score[out[j].ID] })
	return out
}

// History is every fact with a key about a person, current or not, oldest
// first: what was believed, and when it changed.
func (s *Store) History(agent, about, key string) ([]Entry, error) {
	s.mu.Lock()
	f, err := s.load(agent)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, e := range f.Entries {
		if e.Key == key && e.About == about {
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out, nil
}

// Filter chooses entries to list.
type Filter struct {
	Agent string // empty: every agent
	About string // empty: everybody
	Held  bool   // only held ones
}

// List is every entry the filter chooses, newest first.
func (s *Store) List(f Filter) ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	agents, err := s.agents(f.Agent)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, a := range agents {
		fl, err := s.load(a)
		if err != nil {
			return nil, err
		}
		for _, e := range fl.Entries {
			if (f.About == "" || e.About == f.About) && (!f.Held || e.Held) {
				out = append(out, e)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out, nil
}

func (s *Store) agents(only string) ([]string, error) {
	if only != "" {
		return []string{only}, nil
	}
	ents, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if name, ok := strings.CutSuffix(e.Name(), ".json"); ok && reAgent.MatchString(name) {
			out = append(out, name)
		}
	}
	return out, nil
}

// ErrNoEntry is an id nothing has.
var ErrNoEntry = errors.New("no memory has that id")

// change finds one entry by id, across agents, and changes or removes it.
func (s *Store) change(id string, fn func(*Entry) (keep bool, err error)) (Entry, error) {
	return s.changeIn(id, func(_ *file, e *Entry) (bool, error) { return fn(e) })
}

// changeIn is change with the entry's whole file, for a change to one
// entry that changes others with it.
func (s *Store) changeIn(id string, fn func(f *file, e *Entry) (keep bool, err error)) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	agents, err := s.agents("")
	if err != nil {
		return Entry{}, err
	}
	for _, a := range agents {
		e, found, err := s.changeAgent(a, id, fn)
		if found || err != nil {
			return e, err
		}
	}
	return Entry{}, ErrNoEntry
}

// changeAgent is changeIn within one agent's memory, under its lock.
func (s *Store) changeAgent(a, id string, fn func(f *file, e *Entry) (keep bool, err error)) (Entry, bool, error) {
	unlock, err := s.lockAgent(a)
	if err != nil {
		return Entry{}, false, err
	}
	defer unlock()
	f, err := s.load(a)
	if err != nil {
		return Entry{}, false, err
	}
	for i := range f.Entries {
		if f.Entries[i].ID != id {
			continue
		}
		e := f.Entries[i]
		keep, err := fn(&f, &f.Entries[i])
		if err != nil {
			return e, true, err
		}
		if !keep {
			f.Entries = append(f.Entries[:i], f.Entries[i+1:]...)
		} else {
			e = f.Entries[i]
		}
		return e, true, s.save(a, f)
	}
	return Entry{}, false, nil
}

// Get is one entry.
func (s *Store) Get(id string) (Entry, error) {
	all, err := s.List(Filter{})
	if err != nil {
		return Entry{}, err
	}
	for _, e := range all {
		if e.ID == id {
			return e, nil
		}
	}
	return Entry{}, ErrNoEntry
}

// Confirm lets a held entry be recalled: a person has read it.
func (s *Store) Confirm(id, by string, now time.Time, retain time.Duration) (Entry, error) {
	return s.changeIn(id, func(f *file, e *Entry) (bool, error) {
		if !e.Held {
			return true, errors.New("that memory is not held")
		}
		e.Held, e.Confirmed, e.ConfirmedBy = false, now.UTC(), by
		if retain > 0 && retain <= MaxRetain {
			e.Expires = e.Created.Add(keepFor(e.Tier, retain))
		}
		// Confirmed, it is a fact like any other: it replaces what it says
		// changed.
		closeFacts(f, e, now)
		return true, nil
	})
}

// Edit rewrites what is remembered, as the person it is about says it.
// What they wrote is theirs: trusted as what a person said, not held, and
// kept no longer than it was.
func (s *Store) Edit(id, text, by string, now time.Time) (Entry, error) {
	text = strings.TrimSpace(plaintext.Clean(text))
	switch {
	case text == "":
		return Entry{}, errors.New("nothing to remember; delete it instead")
	case utf8.RuneCountInString(text) > MaxText:
		return Entry{}, fmt.Errorf("a memory is at most %d characters", MaxText)
	}
	return s.change(id, func(e *Entry) (bool, error) {
		e.Text, e.Digest, e.Tier, e.Edited = text, digest(text), TierPerson, now.UTC()
		if e.Held {
			e.Held, e.Confirmed, e.ConfirmedBy = false, now.UTC(), by
		}
		return true, nil
	})
}

// Delete removes one entry.
func (s *Store) Delete(id string) (Entry, error) {
	return s.change(id, func(*Entry) (bool, error) { return false, nil })
}

// Forget removes everything any agent remembers about a person, and says
// which entries, by id.
func (s *Store) Forget(about string) ([]string, error) {
	if about == "" {
		return nil, errors.New("forgetting is about somebody")
	}
	return s.remove("", func(e Entry) bool { return e.About == about })
}

// EraseAgent removes an agent's whole memory.
func (s *Store) EraseAgent(agent string) ([]string, error) {
	return s.remove(agent, func(Entry) bool { return true })
}

// Sweep removes what has expired.
func (s *Store) Sweep(now time.Time) ([]string, error) {
	return s.remove("", func(e Entry) bool { return !now.Before(e.Expires) })
}

func (s *Store) remove(only string, match func(Entry) bool) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	agents, err := s.agents(only)
	if err != nil {
		return nil, err
	}
	var gone []string
	for _, a := range agents {
		ids, err := s.removeIn(a, match)
		gone = append(gone, ids...)
		if err != nil {
			return gone, err
		}
	}
	return gone, nil
}

// removeIn is remove within one agent's memory, under its lock.
func (s *Store) removeIn(a string, match func(Entry) bool) ([]string, error) {
	unlock, err := s.lockAgent(a)
	if err != nil {
		return nil, err
	}
	defer unlock()
	f, err := s.load(a)
	if err != nil {
		return nil, err
	}
	var gone []string
	kept := f.Entries[:0]
	for _, e := range f.Entries {
		if match(e) {
			gone = append(gone, e.ID)
			continue
		}
		kept = append(kept, e)
	}
	if len(kept) != len(f.Entries) {
		f.Entries = kept
		if err := s.save(a, f); err != nil {
			return gone, err
		}
	}
	return gone, nil
}
