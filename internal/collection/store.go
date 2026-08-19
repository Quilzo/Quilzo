package collection

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/store"
)

// Reading and writing records against a commit.
//
// Records share the tree with pages and are separated by prefix: pages keep
// the names they always had, and records live under data/. That separation is
// what lets both exist without either knowing about the other — but it is also
// the thing that has to be got right in one specific place, because the page
// writer builds its tree from the page set alone.
//
// A flat rebuild from pages would drop every record in the store, silently,
// on the next time anybody edited a page. There is no error, no conflict, no
// diff showing the loss — the tree simply no longer contains them. That is the
// worst failure this design can have, and Preserve below is what prevents it.

// Check validates a record before it is stored. Nil means unvalidated.
//
// A parameter rather than a package-level hook, because every caller has to
// decide — and a test walks the source to make sure each one passes a real
// check rather than nil. That is the same arrangement the page write path
// uses: gateWrite is called explicitly and a test refuses a surface that
// forgets, which is what caught the content API storing pages nobody had
// validated.
type Check func(collection string, fields map[string]any) error

// Put stores a record and returns the new tree.
//
// The tree, not a commit: whether this becomes a draft, a promotion or
// something else is the caller's decision, and a function that made it here
// would make the same decision for every caller.
//
// The type gate runs here rather than in each of the four surfaces that write
// records. It was in none of them: types bound to pages only, so a record
// could be anything while the equivalent page was refused. One chokepoint is
// what makes the answer the same from the command line, the browser, the
// content API and the agent interface — the property this project has twice
// shipped without.
func Put(s *store.Store, baseTree, collection string, r Record,
	now time.Time, check Check) (tree string, out Record, err error) {

	// Before anything is written. The store is append-only, so a record that
	// does not satisfy its type is addressable forever once it lands, and
	// "fix it in the next write" leaves the broken one in the history.
	if check != nil {
		if err := check(collection, r.Fields); err != nil {
			return "", Record{}, err
		}
	}

	if err := ValidName(collection); err != nil {
		return "", Record{}, err
	}
	if r.ID == "" {
		id, err := NewID()
		if err != nil {
			return "", Record{}, err
		}
		r.ID = id
	}
	if err := ValidID(r.ID); err != nil {
		return "", Record{}, err
	}
	if r.Fields == nil {
		r.Fields = map[string]any{}
	}

	existing, _ := Get(s, baseTree, collection, r.ID)
	Stamp(&r, now, existing)

	tree, err = s.PutNested(baseTree, []store.Change{{
		Path:  Path(collection, r.ID),
		Value: r,
	}})
	if err != nil {
		return "", Record{}, err
	}
	return tree, r, nil
}

// PutMany stores several records in one write.
//
// One call rather than a loop, because the cost of a commit is paid per commit
// and not per record: writing a thousand records one at a time pays for a
// thousand tree rebuilds and a thousand ref moves. Measured at roughly three
// times the throughput for five hundred at a time, which is the difference
// between an import that finishes and one somebody watches.
func PutMany(s *store.Store, baseTree, collection string, records []Record,
	now time.Time) (string, []Record, error) {

	if err := ValidName(collection); err != nil {
		return "", nil, err
	}
	changes := make([]store.Change, 0, len(records))
	out := make([]Record, 0, len(records))
	for _, r := range records {
		if r.ID == "" {
			id, err := NewID()
			if err != nil {
				return "", nil, err
			}
			r.ID = id
		}
		if err := ValidID(r.ID); err != nil {
			return "", nil, err
		}
		if r.Fields == nil {
			r.Fields = map[string]any{}
		}
		existing, _ := Get(s, baseTree, collection, r.ID)
		Stamp(&r, now, existing)
		changes = append(changes, store.Change{
			Path: Path(collection, r.ID), Value: r})
		out = append(out, r)
	}
	tree, err := s.PutNested(baseTree, changes)
	if err != nil {
		return "", nil, err
	}
	return tree, out, nil
}

// Get reads one record.
func Get(s *store.Store, tree, collection, id string) (*Record, error) {
	if err := ValidName(collection); err != nil {
		return nil, err
	}
	if err := ValidID(id); err != nil {
		return nil, err
	}
	if tree == "" {
		return nil, fmt.Errorf("no such record")
	}
	entries, err := s.GetNested(tree)
	if err != nil {
		return nil, err
	}
	oid, ok := entries[Path(collection, id)]
	if !ok {
		return nil, fmt.Errorf("no such record")
	}
	return read(s, oid)
}

// Delete removes a record and returns the new tree.
func Delete(s *store.Store, baseTree, collection, id string) (string, error) {
	if err := ValidName(collection); err != nil {
		return "", err
	}
	if err := ValidID(id); err != nil {
		return "", err
	}
	if _, err := Get(s, baseTree, collection, id); err != nil {
		// Refused rather than treated as done. "Delete succeeded" for
		// something that was never there hides a client working against the
		// wrong collection or the wrong id, and it will keep hiding it.
		return "", fmt.Errorf("no such record")
	}
	return s.PutNested(baseTree, []store.Change{{
		Path: Path(collection, id), Delete: true,
	}})
}

// List returns the records in a collection, filtered and paged.
//
// Every record in the collection is read to answer this, which is a scan and
// is said plainly rather than hidden behind a name like Query. It is the
// honest cost of having no index, it is fine for the collections a single node
// holds, and knowing it is a scan is what stops somebody building a page that
// runs twenty of them.
func List(s *store.Store, tree, collection string, q Query) ([]Record, int, error) {
	if err := ValidName(collection); err != nil {
		return nil, 0, err
	}
	if tree == "" {
		return nil, 0, nil
	}
	entries, err := s.GetNested(tree)
	if err != nil {
		return nil, 0, err
	}
	prefix := Prefix(collection)
	var all []Record
	for path, oid := range entries {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		r, err := read(s, oid)
		if err != nil {
			// One unreadable record must not make the collection
			// unreadable. It is reported by `verify`, which is the tool for
			// it; a listing that fails entirely tells somebody their data is
			// gone when one row is damaged.
			continue
		}
		all = append(all, *r)
	}
	page, total := q.Apply(all)
	return page, total, nil
}

// Names returns the collections that exist in a tree.
//
// Derived from the tree rather than from a registry. A registry is a second
// thing to keep true, and the first time it disagrees with the tree nobody
// knows which one is lying.
func Names(s *store.Store, tree string) ([]string, error) {
	if tree == "" {
		return nil, nil
	}
	entries, err := s.GetNested(tree)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for path := range entries {
		if name, _, ok := IsCollectionPath(path); ok {
			seen[name] = true
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// Count returns how many records a collection holds, without reading them.
func Count(s *store.Store, tree, collection string) (int, error) {
	if tree == "" {
		return 0, nil
	}
	entries, err := s.GetNested(tree)
	if err != nil {
		return 0, err
	}
	prefix := Prefix(collection)
	n := 0
	for path := range entries {
		if strings.HasPrefix(path, prefix) {
			n++
		}
	}
	return n, nil
}

// Preserve carries a tree's records across a write that only knows about
// pages.
//
// The page writer builds its tree from the page set alone, so without this
// every record in the store disappears the next time anybody edits a page —
// silently, with no error and no conflict, because the tree simply stops
// containing them.
//
// It returns the record entries as changes to re-apply, which is cheap: the
// objects already exist under their hashes, so re-applying them writes
// nothing and only rebuilds the trees along their paths.
func Preserve(s *store.Store, fromTree string) ([]store.Change, error) {
	if fromTree == "" {
		return nil, nil
	}
	entries, err := s.GetNested(fromTree)
	if err != nil {
		return nil, err
	}
	var out []store.Change
	for path, oid := range entries {
		if _, _, ok := IsCollectionPath(path); !ok {
			continue
		}
		r, err := read(s, oid)
		if err != nil {
			return nil, fmt.Errorf("cannot carry %s across the write: %w",
				path, err)
		}
		out = append(out, store.Change{Path: path, Value: *r})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// read loads one record blob.
func read(s *store.Store, oid string) (*Record, error) {
	var r Record
	if err := s.GetBlob(oid, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
