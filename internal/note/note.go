// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package note is what one person wants to say to another about a page.
//
// # What was missing
//
// internal/collab has locks, proposals and approvals, so a reviewer could
// agree or not agree and leave a sentence saying why. What they could not do
// was say "this paragraph is wrong" — there was one note per approval, about
// the whole commit, and no way to point at anything.
//
// That is the ordinary shape of editorial review and it was the one thing
// missing from a package built for exactly this.
//
// # Why these are not in the store
//
// The store is append-only and content-addressed, and a note is a message
// between people: somebody will want one removed, and an append-only merkle
// store cannot erase anything. internal/form reached this conclusion first,
// for submissions, and said it plainly — "A store that cannot forget is the
// right design for published content and the wrong one for a message from a
// member of the public". A note about a draft is the same kind of thing, so it
// lives in the same kind of place: a plain directory of files, individually
// deletable.
//
// # Why a note carries a hash
//
// Because the thing it is about can change underneath it, and a note that
// silently starts describing different words is worse than no note.
//
// collab.Approval already solves this and says why: the hash "is what makes
// the approval unfalsifiable by later editing: change anything and the hash
// changes and this approval is about content that is no longer proposed". A
// note gets the same treatment and, deliberately, the same answer about what
// to do when it happens — Stale reports rather than deletes, because "who
// asked for this before it was rewritten" is a real question and dropping the
// record answers it with nothing.
//
// A stale note is still shown. It is marked, and it says what it was written
// against, so the reader can decide whether it still applies. That is the one
// thing the tool cannot decide for them.
package note

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Limits, none configurable.
//
// The same reasoning internal/schema gives about its own bounds: "a bound
// somebody can raise is a bound an attacker can raise". These are large enough
// for anything anybody writes in a review and small enough that a directory of
// them cannot become a problem.
const (
	MaxText   = 4096
	MaxAuthor = 128
	// MaxField is a field name, which is bounded by the schema anyway; the
	// limit is here so an untyped page cannot carry an unbounded one.
	MaxField = 64
)

// ErrNotFound is returned when there is no such note.
//
// A value rather than a new error each time, so a caller can tell "already
// gone" from "the disk is broken" — the distinction internal/form had to
// learn when two sweeps started running at once.
var ErrNotFound = errors.New("there is no such note")

// A Note is one remark about one page.
type Note struct {
	ID   string `json:"id"`
	Page string `json:"page"`
	// Field is what on the page this is about, empty for the page as a whole.
	// A field name rather than a position: a position moves when a paragraph
	// is added above it, and a note that drifts to the wrong paragraph is the
	// failure this is trying to avoid.
	Field string `json:"field,omitempty"`
	// Content is the hash of the page this was written against. See the
	// package comment: it is what lets Stale be exact rather than a guess.
	Content string `json:"content"`
	Author  string `json:"author"`
	Text    string `json:"text"`
	At      int64  `json:"at"`
	// Resolved records that somebody dealt with it, and who. A note is
	// resolved rather than deleted, so the conversation stays readable: an
	// editor asking "why is this heading different" should find the answer,
	// not an empty list.
	Resolved   bool   `json:"resolved,omitempty"`
	ResolvedBy string `json:"resolved_by,omitempty"`
	ResolvedAt int64  `json:"resolved_at,omitempty"`
}

// Stale reports whether the page has changed since this was written.
//
// Against the hash the caller says the page has now. False when either hash is
// empty: a note with no anchor cannot be shown to have drifted, and claiming
// it has would put a warning on every note in a store that predates this.
func (n Note) Stale(nowHash string) bool {
	if n.Content == "" || nowHash == "" {
		return false
	}
	return n.Content != nowHash
}

// Valid reports what is wrong with a note, or nil.
func (n Note) Valid() error {
	switch {
	case strings.TrimSpace(n.Page) == "":
		return fmt.Errorf("a note has to be about a page")
	case strings.TrimSpace(n.Text) == "":
		return fmt.Errorf("a note with nothing in it is not a note")
	case strings.TrimSpace(n.Author) == "":
		// Named, always. An anonymous note in a review is a note nobody can
		// ask a follow-up question about.
		return fmt.Errorf("a note needs an author; somebody has to be askable")
	case utf8.RuneCountInString(n.Text) > MaxText:
		return fmt.Errorf("that note is %d characters and the limit is %d",
			utf8.RuneCountInString(n.Text), MaxText)
	case utf8.RuneCountInString(n.Author) > MaxAuthor:
		return fmt.Errorf("that author name is longer than %d characters", MaxAuthor)
	case utf8.RuneCountInString(n.Field) > MaxField:
		return fmt.Errorf("that field name is longer than %d characters", MaxField)
	}
	return nil
}

// Store is a directory of notes.
//
// Keyed by page, like internal/form is by form: a page's notes are read
// together and almost never one at a time, so a directory per page is the
// layout that matches how it is used.
type Store struct{ dir string }

// Open makes the directory if it is not there.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// safeName refuses anything that could leave the directory.
//
// A page name arrives from content and a note id from a URL. Both become path
// segments, so both are checked here rather than trusted to have been checked
// somewhere else — the place a path is built is the only place that can be
// sure.
func safeName(s string) error {
	if s == "" {
		return fmt.Errorf("empty name")
	}
	if strings.ContainsAny(s, `\:`) || strings.Contains(s, "..") {
		return fmt.Errorf("%q is not a usable name", s)
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("%q is not a usable name", s)
		}
	}
	return nil
}

func (st *Store) dirFor(page string) (string, error) {
	if err := safeName(page); err != nil {
		return "", err
	}
	// Page names may contain "/", so the directory nests with them. Cleaned
	// and then checked to still be under the root, because Clean is
	// normalisation and the check is the guard.
	p := filepath.Join(st.dir, filepath.FromSlash(page))
	if !strings.HasPrefix(filepath.Clean(p)+string(filepath.Separator),
		filepath.Clean(st.dir)+string(filepath.Separator)) {
		return "", fmt.Errorf("%q is not a usable name", page)
	}
	return p, nil
}

// Add writes a note and returns it with its id filled in.
func (st *Store) Add(n Note, now time.Time) (Note, error) {
	if err := n.Valid(); err != nil {
		return Note{}, err
	}
	dir, err := st.dirFor(n.Page)
	if err != nil {
		return Note{}, err
	}
	id, err := newID(now)
	if err != nil {
		return Note{}, err
	}
	n.ID, n.At = id, now.Unix()

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Note{}, err
	}
	return n, writeJSON(filepath.Join(dir, n.ID+".json"), n)
}

// List returns a page's notes, oldest first.
//
// Oldest first because it is a conversation, and a conversation read newest
// first is one nobody can follow. Resolved ones are included: see the comment
// on Resolved.
func (st *Store) List(page string) ([]Note, error) {
	dir, err := st.dirFor(page)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	out := make([]Note, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		body, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			continue
		}
		var n Note
		if json.Unmarshal(body, &n) == nil {
			out = append(out, n)
		}
	}
	// By id, which is the clock to the nanosecond followed by randomness — so
	// this is insertion order, and it is the same order every time. Sorting on
	// At first would be sorting on a coarser copy of the same thing and would
	// need a tie-break for every note written in the same second, which is
	// most of them.
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Get reads one note.
func (st *Store) Get(page, id string) (Note, error) {
	notes, err := st.List(page)
	if err != nil {
		return Note{}, err
	}
	for _, n := range notes {
		if n.ID == id {
			return n, nil
		}
	}
	return Note{}, ErrNotFound
}

// Resolve marks a note dealt with.
func (st *Store) Resolve(page, id, by string, now time.Time) error {
	n, err := st.Get(page, id)
	if err != nil {
		return err
	}
	if strings.TrimSpace(by) == "" {
		return fmt.Errorf("resolving a note records who did it")
	}
	n.Resolved, n.ResolvedBy, n.ResolvedAt = true, by, now.Unix()
	dir, err := st.dirFor(page)
	if err != nil {
		return err
	}
	return writeJSON(filepath.Join(dir, n.ID+".json"), n)
}

// Remove deletes a note.
//
// Deleting is possible because these are not in the store, which is the whole
// reason they are not in the store. Resolving is the ordinary way to finish
// with one; this is for a note that should not have been written.
func (st *Store) Remove(page, id string) error {
	if err := safeName(id); err != nil {
		return err
	}
	dir, err := st.dirFor(page)
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, id+".json")); err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

// Pages lists every page that has notes.
func (st *Store) Pages() ([]string, error) {
	var out []string
	err := filepath.WalkDir(st.dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		rel, rerr := filepath.Rel(st.dir, filepath.Dir(p))
		if rerr != nil {
			return nil
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	sort.Strings(out)
	return dedupe(out), nil
}

// Unresolved reports how many of these notes nobody has dealt with.
//
// The number worth putting on a screen: resolved notes are kept and are not
// something anybody has to act on.
func Unresolved(notes []Note) int {
	n := 0
	for _, x := range notes {
		if !x.Resolved {
			n++
		}
	}
	return n
}

func dedupe(in []string) []string {
	out := in[:0]
	var last string
	for i, s := range in {
		if i == 0 || s != last {
			out = append(out, s)
		}
		last = s
	}
	return out
}

// newID is time-ordered, then random.
//
// # Why not just random
//
// At is Unix seconds, like every other timestamp here, and two notes written
// in one sitting land in the same second. Sorting by At and breaking ties on a
// random id then puts the second remark before the first about two-thirds of
// the time — which was the first thing driving this by hand showed.
//
// The first eight bytes are the nanosecond clock, big-endian, so the hex form
// sorts in the order they were made. The remaining eight are random, which is
// what makes an id unguessable and what keeps two notes written in the same
// nanosecond apart.
//
// The timestamp is not a disclosure: At already carries the time, to the
// second, in the same file.
func newID(now time.Time) (string, error) {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(now.UnixNano()))
	if _, err := rand.Read(b[8:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// writeJSON writes a file whole or not at all.
func writeJSON(path string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
