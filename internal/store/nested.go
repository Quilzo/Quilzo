package store

import (
	"fmt"
	"strings"
)

// Nested trees: the change that makes a write cost what the edit costs.
//
// The measurement, in order:
//
//	whole tree, 20k records   340ms   3 writes/sec
//	sparse blobs, 20k         176ms   6 writes/sec
//
// Sparse blobs removed the re-hashing of every record and gained a factor of
// two, and then stopped, because one flat tree object still listed every path
// — so changing one record still serialised and hashed a hundred thousand
// entries. That is the remaining O(n), and it is in the tree rather than in
// the blobs.
//
// Git does not have it because a tree entry may point at another tree. Writing
// data/users/ab/cd/id rewrites five small objects along that path and reuses
// every sibling subtree by the hash it already had. The store's format already
// allows this — an entry is a name and an object id, and the object's kind is
// recorded with it — so this is a way of using the format rather than a change
// to it.
//
// Old stores are unaffected. A flat tree is a nested tree of depth one, reads
// fall back to it, and nothing has to be converted.

// PutNested writes changes against a base tree, rewriting only the trees along
// each changed path.
func (s *Store) PutNested(base string, changes []Change) (string, error) {
	for _, c := range changes {
		if err := validPath(c.Path); err != nil {
			return "", err
		}
	}
	return s.putNode(base, changes, 0)
}

// putNode rebuilds one level.
func (s *Store) putNode(oid string, changes []Change, depth int) (string, error) {
	entries := map[string]string{}
	if oid != "" {
		existing, err := s.GetTree(oid)
		if err != nil {
			return "", fmt.Errorf("cannot read tree %s: %w", short(oid), err)
		}
		for k, v := range existing {
			entries[k] = v
		}
	}

	// Split into what lands here and what belongs to a subtree.
	groups := map[string][]Change{}
	for _, c := range changes {
		segs := strings.Split(c.Path, "/")
		if depth >= len(segs) {
			return "", fmt.Errorf("path %q is shorter than its own depth", c.Path)
		}
		name := segs[depth]
		if depth == len(segs)-1 {
			if c.Delete {
				delete(entries, name)
				continue
			}
			blob, err := s.PutBlob(c.Value)
			if err != nil {
				return "", err
			}
			entries[name] = blob
			continue
		}
		groups[name] = append(groups[name], c)
	}

	for name, sub := range groups {
		child, err := s.putNode(entries[name], sub, depth+1)
		if err != nil {
			return "", err
		}
		// A subtree that ended up empty is removed rather than left as an
		// empty object. Otherwise deleting the last record in a collection
		// leaves the collection present but empty, and "does this collection
		// exist" stops having an answer.
		if empty, err := s.treeIsEmpty(child); err == nil && empty {
			delete(entries, name)
			continue
		}
		entries[name] = child
	}
	return s.PutTree(entries)
}

func (s *Store) treeIsEmpty(oid string) (bool, error) {
	t, err := s.GetTree(oid)
	if err != nil {
		return false, err
	}
	return len(t) == 0, nil
}

// GetNested flattens a nested tree into slash-separated paths.
//
// Bounded by depth as well as by breadth. A tree that pointed at itself would
// otherwise be an infinite walk, and while the object model makes a cycle
// impossible to create — an object's name is the hash of its content, so a
// tree cannot contain its own id — a corrupted or hostile store is not
// obliged to be well-formed, and a reader that assumes it is hangs.
func (s *Store) GetNested(oid string) (map[string]string, error) {
	out := map[string]string{}
	if oid == "" {
		return out, nil
	}
	return out, s.walk(oid, "", out, 0)
}

// maxDepth bounds the walk. Paths here are at most data/<name>/<aa>/<bb>/<id>,
// which is five, so sixteen is generous by a wide margin and still finite.
const maxDepth = 16

func (s *Store) walk(oid, prefix string, out map[string]string, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("tree nests deeper than %d levels at %q", maxDepth, prefix)
	}
	entries, err := s.GetTree(oid)
	if err != nil {
		return err
	}
	for name, child := range entries {
		path := name
		if prefix != "" {
			path = prefix + "/" + name
		}
		// Is it a subtree or a leaf? Asked of the object rather than inferred
		// from the name, because a name cannot be trusted to say what it
		// points at.
		if s.isTree(child) {
			if err := s.walk(child, path, out, depth+1); err != nil {
				return err
			}
			continue
		}
		out[path] = child
	}
	return nil
}

// IsTree reports whether an object id names a tree.
//
// Exported because callers outside this package have to tell a page from a
// branch of the tree, and asking what the object is beats keeping a list of
// reserved names that whoever adds the next branch will not know to update.
func (s *Store) IsTree(oid string) bool { return s.isTree(oid) }

// isTree reports whether an object id names a tree.
func (s *Store) isTree(oid string) bool {
	_, err := s.read(oid, KindTree)
	return err == nil
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
