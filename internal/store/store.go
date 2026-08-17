// Package store holds content that cannot be edited, only added to.
//
// Every CMS breach worth reading about has the same shape. WordPress's wp2shell
// chained a REST batch-route confusion with SQL injection to reach an admin
// account and then uploaded a plugin, achieving pre-auth remote code execution
// on a stock install with no plugins present. Drupal's 2026 disclosure was SQL
// injection in the database abstraction layer itself.
//
// Both chains need the same two links: a query the attacker can influence, and
// somewhere that writing data means writing something which later executes.
// This package removes the first. Package tmpl removes the second.
//
// # The model
//
// It is git's, applied to content rather than files. Three immutable object
// kinds, each addressed by the SHA-256 of its own bytes:
//
//	blob    a piece of content
//	tree    a named mapping from path segment to object id
//	commit  a tree, its parents, and who did it and why
//
// Nothing is ever modified. Editing a page writes a new blob, a new tree
// pointing at it, and a new commit; the old objects are still there and still
// exactly what they were. There is no UPDATE and no DELETE, so there is no
// statement for an injection to alter, and reading is a file open on a path
// derived from a hash.
//
// # Why this rather than a database
//
// Publishing becomes moving a pointer: atomic, and instantly reversible. That
// matters more than it sounds. Rolling back a conventional CMS is frightening
// because the previous state was overwritten and has to be reconstructed from a
// backup taken at some other moment. Here the previous state was never touched,
// so rollback is a pointer moving back and cannot half-complete.
//
// It also gives an assistant somewhere safe to work. An agent proposing a
// change produces a commit nobody is serving; reviewing it is a diff, and
// rejecting it costs a pointer that never moved.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/vault"
	"sync"
)

// MaxPathSegments bounds how deep a tree entry may be nested.
//
// Five is what the record layout needs — data/<collection>/<aa>/<bb>/<id> — and
// eight leaves room without letting a caller choose the depth of the tree the
// reader has to walk.
const MaxPathSegments = 8

const (
	KindBlob   = "blob"
	KindTree   = "tree"
	KindCommit = "commit"
)

var (
	// An object id becomes part of a filesystem path, so it is validated at the
	// boundary rather than trusted from every caller.
	reID = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// Names in a tree. Deliberately narrow: no traversal, no leading dot, and a
	// single optional slash.
	//
	// The slash exists for one reason — a site in more than one language stores
	// its French pages as fr/about — and it is bounded to one because that is
	// all that use needs. Each half must independently satisfy the same rule as
	// a bare name, so ".." cannot appear on either side, an empty half is
	// refused, and no name can begin or end with a separator. A tree name never
	// becomes a filesystem path (objects are filed under their hash), so what
	// this protects is the URL and the tree's own structure.
	// One segment. Paths are split on the separator and each part checked
	// against this, so the pattern no longer has to describe the separator —
	// which is what let "a/../b" through a pattern that tried to.
	reSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// Commit records a tree and how it came to be.
type Commit struct {
	Tree    string            `json:"tree"`
	Parents []string          `json:"parents"`
	Message string            `json:"message"`
	Author  string            `json:"author"`
	At      int64             `json:"at"`
	Meta    map[string]string `json:"meta,omitempty"`
}

// Store is an append-only object store on a plain filesystem.
type Store struct {
	mu      sync.Mutex
	root    string
	objects string
	refs    string
	// keys encrypts objects at rest when it is set. Nil means plaintext, which
	// is the default: a store that silently encrypted with a key generated on
	// first run would be a store whose contents are lost when that key is.
	keys *vault.Keyring
	// durability chooses fsync-per-object or fsync-per-commit.
	durability Durability
	// pending holds object files written but not yet flushed.
	pending map[string]bool
}

// WithKeys turns on encryption at rest.
//
// Set after Open rather than as an option to it, because supplying the key is
// the operator's decision and the failure to supply one has to be visible at
// the point of that decision rather than swallowed by a constructor.
func (s *Store) WithKeys(kr *vault.Keyring) *Store {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = kr
	return s
}

// Encrypted reports whether this store is writing sealed objects.
func (s *Store) Encrypted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keys != nil
}

// ObjectID is the address of an object, which is a fact about its bytes.
//
// The kind is folded into the hash so a blob and a tree with identical bytes get
// different ids. Without that, content an attacker controls could be crafted to
// also parse as a tree and have one object stand in for the other — the same
// domain-separation reasoning that puts a prefix byte on Merkle leaves.
func ObjectID(kind string, payload []byte) string {
	h := sha256.New()
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

// canonical produces bytes for a value that are stable across runs and machines.
// Go's encoding/json already sorts map keys, which is what makes identical
// content land on an identical id and deduplicate.
func canonical(v any) ([]byte, error) {
	return json.Marshal(v)
}

// Open creates or reuses a store rooted at dir.
func Open(dir string) (*Store, error) {
	s := &Store{
		root:    dir,
		objects: filepath.Join(dir, "objects"),
		refs:    filepath.Join(dir, "refs"),
	}
	for _, d := range []string{s.objects, s.refs} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("cannot create %s: %w", d, err)
		}
	}
	return s, nil
}

func (s *Store) Root() string { return s.root }

func (s *Store) pathFor(oid string) (string, error) {
	if !reID.MatchString(oid) {
		return "", fmt.Errorf("not an object id: %q", oid)
	}
	return filepath.Join(s.objects, oid[:2], oid[2:]), nil
}

// Has reports whether an object is stored.
func (s *Store) Has(oid string) bool {
	p, err := s.pathFor(oid)
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// writeAtomic writes through a temporary file and renames.
//
// A reader must never observe a half-written object. Rename within a directory
// is atomic on POSIX, so either the whole object is there or none of it is.
func writeAtomic(path string, body []byte, perm os.FileMode, sync bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op once the rename succeeds

	if _, err := f.Write(body); err != nil {
		f.Close()
		return err
	}
	if sync {
		if err := f.Sync(); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Store) write(kind string, payload []byte) (string, error) {
	oid := ObjectID(kind, payload)
	path, err := s.pathFor(oid)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := os.Stat(path); err == nil {
		// Already stored, and by construction with identical bytes. Rewriting
		// would be pointless and opens a window where the object is absent.
		return oid, nil
	}
	body := append(append([]byte(kind), 0), payload...)

	// Encryption sits here, at the one place objects reach the disk. Putting it
	// anywhere else would mean finding every writer, and the next writer added
	// would not know to look.
	//
	// The object id is deliberately computed above, from the plaintext. The
	// name is load-bearing everywhere else in this system — deduplication key,
	// ETag, what a content type binds to, what an approval signs — so it stays
	// the hash of the content and the file holds the sealed form.
	if s.keys != nil {
		sealed, err := s.keys.Seal(body, []byte(oid))
		if err != nil {
			return "", fmt.Errorf("cannot encrypt %s: %w", kind, err)
		}
		if body, err = vault.Marshal(sealed); err != nil {
			return "", err
		}
	}

	// Objects are deferred by default: immutable, named by their own hash, and
	// unreachable until a ref points at them, so an unflushed one is garbage
	// rather than corruption.
	if err := writeAtomic(path, body, 0o400, s.durability == SyncEach); err != nil {
		return "", fmt.Errorf("cannot store %s: %w", kind, err)
	}
	if s.durability != SyncEach {
		// Recorded inline rather than through a helper, because write already
		// holds the mutex and a Go mutex is not reentrant. Calling a locking
		// helper from here deadlocked on the very first object written, which
		// is about as quiet as a failure gets: no error, no panic, just a
		// process that stops.
		if s.pending == nil {
			s.pending = map[string]bool{}
		}
		s.pending[path] = true
	}
	return oid, nil
}

// PutBlob stores a piece of content.
func (s *Store) PutBlob(v any) (string, error) {
	payload, err := canonical(v)
	if err != nil {
		return "", fmt.Errorf("content is not serialisable: %w", err)
	}
	return s.write(KindBlob, payload)
}

// PutTree stores a named mapping from path segment to object id.
func (s *Store) PutTree(entries map[string]string) (string, error) {
	for name, oid := range entries {
		// A key may be a path of segments, each of which must still be a
		// usable segment.
		//
		// Nesting is what makes a write proportional to the edit rather than
		// to the store: a record at data/users/ab/cd/id is addressable without
		// every page beside it being re-hashed to reach it. Every segment is
		// validated individually, so allowing the separator has not allowed a
		// traversal — "a/../b" fails on the ".." segment exactly as "a/.." did
		// when it was one name.
		segs := strings.Split(name, "/")
		// Bounded, not unbounded. The old rule allowed at most one slash,
		// which was a real limit and not an accident; nesting needs five
		// levels (data/<collection>/<aa>/<bb>/<id>) and nothing needs more.
		// Relaxing a bound to what the design requires is different from
		// removing it, and an unbounded path is a tree an attacker chooses
		// the depth of.
		if len(segs) > MaxPathSegments {
			return "", fmt.Errorf(
				"%q has %d segments and the limit is %d", name, len(segs),
				MaxPathSegments)
		}
		for _, seg := range segs {
			if !reSegment.MatchString(seg) {
				return "", fmt.Errorf(
					"%q is not a usable path: %q is not a segment of letters, "+
						"digits, dot, dash and underscore, starting with a "+
						"letter or digit", name, seg)
			}
		}
		if !reID.MatchString(oid) {
			return "", fmt.Errorf("%q points at %q, which is not an object id", name, oid)
		}
	}
	payload, err := canonical(entries)
	if err != nil {
		return "", err
	}
	return s.write(KindTree, payload)
}

// PutCommit stores a commit.
func (s *Store) PutCommit(c Commit) (string, error) {
	if !reID.MatchString(c.Tree) {
		return "", fmt.Errorf("commit tree %q is not an object id", c.Tree)
	}
	for _, p := range c.Parents {
		if !reID.MatchString(p) {
			return "", fmt.Errorf("commit parent %q is not an object id", p)
		}
	}
	if c.Parents == nil {
		c.Parents = []string{}
	}
	payload, err := canonical(c)
	if err != nil {
		return "", err
	}
	return s.write(KindCommit, payload)
}

func (s *Store) read(oid, expect string) ([]byte, error) {
	path, err := s.pathFor(oid)
	if err != nil {
		return nil, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no object %s", oid)
	}

	// A store can be half converted: turning encryption on does not rewrite
	// what is already there, so both forms have to be readable and the reader
	// cannot be told which to expect.
	if vault.IsSealed(body) {
		if s.keys == nil {
			return nil, fmt.Errorf(
				"object %s is encrypted and no key was supplied. The content is "+
					"intact; without the key encryption key it cannot be read, "+
					"which is the point", oid)
		}
		sealed, err := vault.Unmarshal(body)
		if err != nil {
			return nil, fmt.Errorf("object %s is malformed: %w", oid, err)
		}
		if body, err = s.keys.Open(sealed, []byte(oid)); err != nil {
			return nil, fmt.Errorf("object %s: %w", oid, err)
		}
	}

	i := strings.IndexByte(string(body), 0)
	if i < 0 {
		return nil, fmt.Errorf("object %s is malformed", oid)
	}
	kind, payload := string(body[:i]), body[i+1:]
	if kind != expect {
		return nil, fmt.Errorf("object %s is a %s, not a %s", oid, kind, expect)
	}
	// Verify the bytes still hash to the name they are filed under. Corruption
	// and tampering look identical from here, and both should stop a read rather
	// than return content that is not what was written.
	if ObjectID(kind, payload) != oid {
		return nil, fmt.Errorf(
			"object %s does not hash to its own id; the store has been corrupted "+
				"or altered", oid)
	}
	return payload, nil
}

// GetBlob reads content back into v.
func (s *Store) GetBlob(oid string, v any) error {
	payload, err := s.read(oid, KindBlob)
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, v)
}

// GetTree reads a tree.
func (s *Store) GetTree(oid string) (map[string]string, error) {
	payload, err := s.read(oid, KindTree)
	if err != nil {
		return nil, err
	}
	var out map[string]string
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetCommit reads a commit.
func (s *Store) GetCommit(oid string) (Commit, error) {
	payload, err := s.read(oid, KindCommit)
	if err != nil {
		return Commit{}, err
	}
	var c Commit
	if err := json.Unmarshal(payload, &c); err != nil {
		return Commit{}, err
	}
	return c, nil
}

func (s *Store) refPath(name string) (string, error) {
	if !reSegment.MatchString(name) {
		return "", fmt.Errorf("%q is not a usable ref name", name)
	}
	return filepath.Join(s.refs, name), nil
}

// SetRef points a ref at a commit. This is what publishing is.
func (s *Store) SetRef(name, oid string) error {
	if !reID.MatchString(oid) {
		return fmt.Errorf("%q is not an object id", oid)
	}
	if !s.Has(oid) {
		return fmt.Errorf("refusing to point %s at %s, which is not stored", name, oid)
	}
	path, err := s.refPath(name)
	if err != nil {
		return err
	}
	// Everything this ref reaches is made durable first. Reverse the order and
	// a crash leaves a ref pointing at an object that is not there — a store
	// that verifies as broken rather than as incomplete.
	//
	// Outside the lock, because Flush takes it and a Go mutex is not
	// reentrant: calling it from inside deadlocked the process on the first
	// commit, which is a very quiet way for a store to stop working.
	if err := s.Flush(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return writeAtomic(path, []byte(oid), 0o600, true)
}

// GetRef returns what a ref points at, or "" if it does not exist.
func (s *Store) GetRef(name string) string {
	path, err := s.refPath(name)
	if err != nil {
		return ""
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

// History walks back along first parents.
func (s *Store) History(oid string, limit int) ([]struct {
	ID     string
	Commit Commit
}, error) {
	var out []struct {
		ID     string
		Commit Commit
	}
	seen := map[string]bool{}
	current := oid
	for current != "" && len(out) < limit {
		if seen[current] {
			break
		}
		seen[current] = true
		c, err := s.GetCommit(current)
		if err != nil {
			return out, err
		}
		out = append(out, struct {
			ID     string
			Commit Commit
		}{current, c})
		if len(c.Parents) > 0 {
			current = c.Parents[0]
		} else {
			current = ""
		}
	}
	return out, nil
}

// Verify re-hashes every object.
//
// The point of content addressing is that this check exists and is cheap. A
// conventional CMS cannot answer "has anything in here been altered outside the
// application" at all.
func (s *Store) Verify() (int, error) {
	checked := 0
	shards, err := os.ReadDir(s.objects)
	if err != nil {
		return 0, err
	}
	for _, shard := range shards {
		if !shard.IsDir() {
			continue
		}
		names, err := os.ReadDir(filepath.Join(s.objects, shard.Name()))
		if err != nil {
			return checked, err
		}
		for _, n := range names {
			if strings.HasPrefix(n.Name(), ".") {
				continue
			}
			oid := shard.Name() + n.Name()
			body, err := os.ReadFile(filepath.Join(s.objects, shard.Name(), n.Name()))
			if err != nil {
				return checked, err
			}
			i := strings.IndexByte(string(body), 0)
			if i < 0 {
				return checked, fmt.Errorf("object %s is malformed", oid)
			}
			if ObjectID(string(body[:i]), body[i+1:]) != oid {
				return checked, fmt.Errorf("object %s does not match its contents", oid)
			}
			checked++
		}
	}
	return checked, nil
}

// BuildTree stores each page as a blob and gathers them into one tree.
func BuildTree(s *Store, pages map[string]any) (string, error) {
	entries := make(map[string]string, len(pages))
	names := make([]string, 0, len(pages))
	for name := range pages {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		oid, err := s.PutBlob(pages[name])
		if err != nil {
			return "", err
		}
		entries[name] = oid
	}
	return s.PutTree(entries)
}
