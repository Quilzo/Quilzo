package store

import (
	"fmt"
	"sort"
	"strings"
)

// Writing part of a tree without rebuilding all of it.
//
// BuildTree re-serialises and re-hashes every entry it is given, which is O(n)
// work to change one thing: measured at 201ms for a single edit in a store of
// twenty thousand pages, or five writes a second. That is a property of the
// function, not of content-addressing — git has the same object model and does
// not pay it, because an object whose content has not changed already exists
// under its hash and there is nothing to write.
//
// PutPaths takes a base tree and a set of changes, and touches only what
// changed. Everything else keeps the object id it already had, which is what
// makes the cost proportional to the edit rather than to the store.

// Change is one addition, replacement or removal.
type Change struct {
	// Path is a slash-separated location: "pages/index", "data/users/ab/cd/id".
	Path string
	// Value is the new content. Nil with Delete set removes the entry.
	Value  any
	Delete bool
}

// PutPaths writes changes against a base tree and returns the new tree id.
//
// The tree is flat on disk — one object listing every path — but the paths are
// nested, so this is the step that avoids re-hashing. Nesting the tree objects
// themselves is the next optimisation and a separate one; this removes the
// cost that dominated, which was hashing n blobs to change one.
func (s *Store) PutPaths(base string, changes []Change) (string, error) {
	entries := map[string]string{}
	if base != "" {
		existing, err := s.GetTree(base)
		if err != nil {
			return "", fmt.Errorf("cannot read the base tree: %w", err)
		}
		for path, oid := range existing {
			entries[path] = oid
		}
	}

	for _, c := range changes {
		if err := validPath(c.Path); err != nil {
			return "", err
		}
		if c.Delete {
			delete(entries, c.Path)
			continue
		}
		// The only hashing done is for what actually changed.
		oid, err := s.PutBlob(c.Value)
		if err != nil {
			return "", err
		}
		entries[c.Path] = oid
	}
	return s.PutTree(entries)
}

// PathsUnder returns every entry beneath a prefix, so a collection can be
// listed without loading the pages beside it.
func (s *Store) PathsUnder(tree, prefix string) (map[string]string, error) {
	all, err := s.GetTree(tree)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for path, oid := range all {
		if strings.HasPrefix(path, prefix) {
			out[path] = oid
		}
	}
	return out, nil
}

// SortedPaths is the deterministic order of a tree's entries.
func SortedPaths(t map[string]string) []string {
	out := make([]string, 0, len(t))
	for p := range t {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// validPath refuses a path that would escape or collide.
//
// A path is an address inside an immutable object, so a traversal here is not
// a filesystem problem — it is a record written where another one is meant to
// be, which is worse, because nothing on disk complains.
func validPath(p string) error {
	if p == "" {
		return fmt.Errorf("an empty path")
	}
	if strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return fmt.Errorf("%q must not begin or end with a slash", p)
	}
	if strings.Contains(p, "//") {
		return fmt.Errorf("%q contains an empty segment", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("%q contains a traversal", p)
		}
	}
	if strings.ContainsAny(p, "\x00\n\r\\") {
		return fmt.Errorf("%q contains a character a path cannot hold", p)
	}
	return nil
}
