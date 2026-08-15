// Package site is the workflow: draft, review, publish, roll back.
//
// The workflow is the point rather than a wrapper over the store. Conventional
// CMSes treat publishing as saving, so a bad edit is live the moment it is made
// and getting back is a restore from whatever the backup happened to catch. Here
// draft and live are two refs over the same immutable objects:
//
//	editing       writes new objects; live is untouched and still serving
//	reviewing     is a diff between two commits, both of which exist
//	publishing    moves one pointer
//	rolling back  moves it back
//
// None of those can half-complete, and none destroys the alternative. That is
// what makes it safe to let an assistant work here: an agent producing a
// terrible draft has produced an object nobody is serving, and discarding it
// costs a pointer that never moved.
//
// Publishing is still the moment that matters. It is the one action with an
// outside observer — a reader, a crawler, a cache — and undoing it restores the
// bytes without unsending what was seen.
package site

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rsh1k/scrivet/internal/store"
)

const (
	RefDraft = "draft"
	RefLive  = "live"
)

// Change is one path that differs between two commits.
type Change struct {
	Path   string
	Kind   string // added | removed | modified
	Before string
	After  string
}

// Diff reports what changed between two commits, by object id rather than by
// content.
//
// Comparing ids is exact and cheap: identical content has an identical id, so an
// unchanged page is provably unchanged without being read. That is why review
// stays fast on a large site — only what actually moved gets looked at.
func Diff(s *store.Store, oldCommit, newCommit string) ([]Change, error) {
	newTree := map[string]string{}
	oldTree := map[string]string{}

	nc, err := s.GetCommit(newCommit)
	if err != nil {
		return nil, err
	}
	if newTree, err = s.GetTree(nc.Tree); err != nil {
		return nil, err
	}
	if oldCommit != "" {
		oc, err := s.GetCommit(oldCommit)
		if err != nil {
			return nil, err
		}
		if oldTree, err = s.GetTree(oc.Tree); err != nil {
			return nil, err
		}
	}

	paths := map[string]bool{}
	for p := range oldTree {
		paths[p] = true
	}
	for p := range newTree {
		paths[p] = true
	}
	names := make([]string, 0, len(paths))
	for p := range paths {
		names = append(names, p)
	}
	sort.Strings(names)

	var out []Change
	for _, p := range names {
		before, after := oldTree[p], newTree[p]
		if before == after {
			continue
		}
		switch {
		case before == "":
			out = append(out, Change{Path: p, Kind: "added", After: after})
		case after == "":
			out = append(out, Change{Path: p, Kind: "removed", Before: before})
		default:
			out = append(out, Change{Path: p, Kind: "modified", Before: before, After: after})
		}
	}
	return out, nil
}

// SaveDraft writes a new draft commit on top of whatever draft points at.
func SaveDraft(s *store.Store, pages map[string]any, message, author string) (string, error) {
	// The unchecked form: whatever the draft is now becomes the parent. Kept
	// because a single-writer store has nothing to collide with, and because
	// requiring a base id from every caller would make the common case worse to
	// serve the uncommon one.
	return SaveDraftFrom(s, pages, message, author, "")
}

// SaveDraftFrom writes a draft that must be based on a specific commit.
//
// This is compare-and-swap, and in a content-addressed store it is exact rather
// than a heuristic: the caller says which commit they read, and if the draft
// has moved since, the write is refused with what changed. No timestamps, no
// version columns, no lock to go stale.
//
// An empty base means "whatever is current", which is the single-writer case.
func SaveDraftFrom(s *store.Store, pages map[string]any, message, author,
	base string) (string, error) {

	current := s.GetRef(RefDraft)
	if current == "" {
		current = s.GetRef(RefLive)
	}
	if base != "" && base != current {
		return "", newConflict(s, base, current)
	}

	tree, err := store.BuildTree(s, pages)
	if err != nil {
		return "", err
	}
	parent := current
	var parents []string
	if parent != "" {
		parents = []string{parent}
	}
	cid, err := s.PutCommit(store.Commit{
		Tree: tree, Parents: parents, Message: message,
		Author: author, At: time.Now().Unix(),
	})
	if err != nil {
		return "", err
	}
	return cid, s.SetRef(RefDraft, cid)
}

// PagesAt reads every page at a ref or commit.
func PagesAt(s *store.Store, refOrCommit string) (map[string]any, error) {
	cid := s.GetRef(refOrCommit)
	if cid == "" {
		// A known ref that resolves to nothing means the ref exists as a
		// concept and has never been set — nothing published, or no draft yet.
		// Falling straight through to "not an object id: live" tells the truth
		// about the lookup and nothing about the situation, which sends people
		// hunting for a corrupt store.
		switch refOrCommit {
		case RefLive:
			return nil, fmt.Errorf("nothing is published yet; " +
				"`scrivet publish` moves live to the draft")
		case RefDraft:
			return nil, fmt.Errorf("there is no draft yet; " +
				"`scrivet add NAME=FILE.json` starts one")
		}
		cid = refOrCommit
	}
	c, err := s.GetCommit(cid)
	if err != nil {
		return nil, err
	}
	tree, err := s.GetTree(c.Tree)
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(tree))
	for name, oid := range tree {
		var v any
		if err := s.GetBlob(oid, &v); err != nil {
			return nil, err
		}
		out[name] = v
	}
	return out, nil
}

// Publication records a ref move.
type Publication struct {
	Published string
	Previous  string
	Changes   []Change
}

// Publish moves live to a commit. The one action with an outside observer.
func Publish(s *store.Store, commitID string) (Publication, error) {
	target := commitID
	if target == "" {
		target = s.GetRef(RefDraft)
	}
	if target == "" {
		return Publication{}, fmt.Errorf("nothing to publish: no draft and no commit given")
	}
	previous := s.GetRef(RefLive)
	if previous == target {
		return Publication{Published: target, Previous: previous}, nil
	}
	changes, err := Diff(s, previous, target)
	if err != nil {
		return Publication{}, err
	}
	if err := s.SetRef(RefLive, target); err != nil {
		return Publication{}, err
	}
	return Publication{Published: target, Previous: previous, Changes: changes}, nil
}

// Rollback walks live back along its own history.
//
// Not a restore. The commit being returned to was never removed, so this is a
// pointer going back to an object that has been sitting there the whole time.
// There is no window in which the site is neither one version nor the other.
func Rollback(s *store.Store, steps int) (Publication, error) {
	current := s.GetRef(RefLive)
	if current == "" {
		return Publication{}, fmt.Errorf("nothing is live")
	}
	hist, err := s.History(current, steps+1)
	if err != nil {
		return Publication{}, err
	}
	if len(hist) <= steps {
		return Publication{}, fmt.Errorf(
			"cannot go back %d: only %d earlier commit(s) exist on this line",
			steps, len(hist)-1)
	}
	target := hist[steps].ID
	changes, err := Diff(s, current, target)
	if err != nil {
		return Publication{}, err
	}
	if err := s.SetRef(RefLive, target); err != nil {
		return Publication{}, err
	}
	return Publication{Published: target, Previous: current, Changes: changes}, nil
}

// Conflict is a write refused because the draft moved underneath it.
//
// It carries what changed rather than only that something did, because "there
// was a conflict" makes somebody go looking and a list of pages makes them go
// asking.
type Conflict struct {
	Expected string
	Actual   string
	By       string
	At       int64
	Pages    []string
}

func (c *Conflict) Error() string {
	var b strings.Builder
	b.WriteString("the draft moved while you were working")
	if c.By != "" {
		fmt.Fprintf(&b, "; %s changed it", c.By)
	}
	fmt.Fprintf(&b, "\n  you were working from %s, the draft is now %s",
		shortID(c.Expected), shortID(c.Actual))
	if len(c.Pages) > 0 {
		fmt.Fprintf(&b, "\n  changed since: %s", strings.Join(c.Pages, ", "))
	}
	return b.String()
}

// Touches reports which of the given pages the conflicting change also
// altered. Empty means the two writes do not actually collide, which is the
// common case and the one worth telling people about — otherwise every
// concurrent edit looks equally dangerous and people learn to retry blindly.
func (c *Conflict) Touches(pages []string) []string {
	mine := map[string]bool{}
	for _, p := range pages {
		mine[p] = true
	}
	var both []string
	for _, p := range c.Pages {
		if mine[p] {
			both = append(both, p)
		}
	}
	sort.Strings(both)
	return both
}

func newConflict(s *store.Store, base, current string) *Conflict {
	c := &Conflict{Expected: base, Actual: current}
	if commit, err := s.GetCommit(current); err == nil {
		c.By, c.At = commit.Author, commit.At
	}
	// What differs, so the caller can tell a real collision from a ref that
	// merely moved.
	if changes, err := Diff(s, base, current); err == nil {
		for _, ch := range changes {
			c.Pages = append(c.Pages, ch.Path)
		}
		sort.Strings(c.Pages)
	}
	return c
}

func shortID(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	if s == "" {
		return "(nothing)"
	}
	return s
}
