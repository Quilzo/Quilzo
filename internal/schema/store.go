package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Store is the one place that decides whether content is allowed to be written.
//
// It exists as a package-level object rather than as code in each command
// because of a mistake this project has now made three times: a rule enforced in
// the CLI and absent from the web UI, or present in both and absent from the
// agent interface, is not a rule. It is a rule-shaped thing in whichever
// interface the person happened to read. Type validation has three write
// surfaces — `scrivet add`, the admin save handler, and the MCP write_page
// operation — and all three call Gate. Adding a fourth without calling it is
// caught by a test that walks the source.
type Store struct {
	dir      string
	Registry *Registry `json:"types"`
	// Bound maps a page to the type it is expected to satisfy. A page with no
	// entry is unconstrained; there is no implicit default type, because a
	// default would validate content nobody chose to validate and reject writes
	// for reasons the author never set up.
	Bound map[string]string `json:"bound"`
	// Records is the append-only history of successful validations: which
	// content hash passed which type hash, and when.
	Records []Binding `json:"records"`
}

// Hash is the address of a type: the SHA-256 of its canonical JSON.
//
// Content is content-addressed and so are types, for the same reason. A page
// records the hash of the type it passed, which means editing a type cannot
// retroactively invalidate content that was valid when it was written — the old
// type still exists at its own address. "This page was valid under that exact
// type" stays a checkable claim about two hashes rather than a claim about what
// a mutable file used to contain.
func Hash(t Type) string {
	// Field order is the author's, and is preserved: two types with the same
	// fields in a different order present a different editor, so they are not
	// the same type.
	b, err := json.Marshal(t)
	if err != nil {
		// Type holds only strings, numbers, bools and slices of those.
		panic("schema: a type failed to marshal: " + err.Error())
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// contentHash addresses a page body the same way the object store does.
func contentHash(content map[string]any) string {
	b, err := json.Marshal(content)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func storePath(dir string) string { return filepath.Join(dir, "types.json") }

// Load reads the store, returning an empty one if the site has no types yet.
func Load(dir string) (*Store, error) {
	s := &Store{dir: dir, Registry: NewRegistry(), Bound: map[string]string{}}
	raw, err := os.ReadFile(storePath(dir))
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, s); err != nil {
		return nil, fmt.Errorf("%s is corrupt: %w", storePath(dir), err)
	}
	if s.Registry == nil {
		s.Registry = NewRegistry()
	}
	if s.Bound == nil {
		s.Bound = map[string]string{}
	}
	// Recompile on load. A type that reached the file by some route other than
	// Add — a hand edit, a restored backup, a merge — has not been through
	// Compile, and the bounds Compile enforces are the reason validation is
	// bounded. Trusting the file because it is ours is how a limit becomes
	// advisory.
	for name, t := range s.Registry.Types {
		if err := Compile(t); err != nil {
			return nil, fmt.Errorf("stored type %q does not compile: %w", name, err)
		}
	}
	return s, nil
}

// Save writes the store. Mode 0600: types describe the shape of a site, which is
// reconnaissance, and bindings name pages that may not be published yet.
func (s *Store) Save() error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(storePath(s.dir), b, 0o600)
}

// Bind declares that a page must satisfy a type.
func (s *Store) Bind(page, typeName string) error {
	if _, ok := s.Registry.Get(typeName); !ok {
		return fmt.Errorf("there is no type %q; run scrivet type list", typeName)
	}
	if s.Bound == nil {
		s.Bound = map[string]string{}
	}
	s.Bound[page] = typeName
	return nil
}

// Check validates one page. An unbound page yields no problems: absence of a
// type is not a failure, it is the default state of a site that has not declared
// one.
func (s *Store) Check(page string, body any) []Problem {
	typeName, bound := s.Bound[page]
	if !bound {
		return nil
	}
	t, ok := s.Registry.Get(typeName)
	if !ok {
		// A binding pointing at a deleted type is a configuration error, and it
		// must fail closed. Treating it as "unbound" would make deleting a type
		// a way to switch validation off for every page using it.
		return []Problem{{Field: page, Reason: fmt.Sprintf(
			"is bound to type %q, which no longer exists", typeName)}}
	}
	content, ok := body.(map[string]any)
	if !ok {
		return []Problem{{Field: page, Reason: fmt.Sprintf(
			"must be an object to satisfy type %s, got %T", typeName, body)}}
	}
	return Validate(t, content)
}

// Failure is what Gate reports: which page failed and how.
type Failure struct {
	Page     string    `json:"page"`
	Type     string    `json:"type"`
	Problems []Problem `json:"problems"`
}

func (f Failure) String() string {
	out := f.Page + " does not satisfy " + f.Type
	for _, p := range f.Problems {
		out += "\n    " + p.String()
	}
	return out
}

// Gate is the check every write surface performs before content is stored.
//
// It validates the whole page set rather than the pages being changed, because
// a write that leaves an already-broken page in place is still a write that
// produces an invalid site, and because "only what you touched" is an exception
// people learn to route around by touching something else.
func (s *Store) Gate(pages map[string]any) []Failure {
	names := make([]string, 0, len(pages))
	for name := range pages {
		names = append(names, name)
	}
	sort.Strings(names)

	var failures []Failure
	for _, name := range names {
		if problems := s.Check(name, pages[name]); len(problems) > 0 {
			failures = append(failures, Failure{
				Page: name, Type: s.Bound[name], Problems: problems})
		}
	}
	return failures
}

// Record notes that a page's content passed its type, keeping the two hashes so
// the claim survives both being edited afterwards.
func (s *Store) Record(page string, body any, now time.Time) {
	typeName, bound := s.Bound[page]
	if !bound {
		return
	}
	t, ok := s.Registry.Get(typeName)
	if !ok {
		return
	}
	content, ok := body.(map[string]any)
	if !ok {
		return
	}
	s.Records = append(s.Records, Binding{
		Page:        page,
		TypeName:    typeName,
		TypeHash:    Hash(t),
		ContentHash: contentHash(content),
		ValidatedAt: now.Unix(),
	})
}

// RecordAll notes every bound page in a set that has just been written.
func (s *Store) RecordAll(pages map[string]any, now time.Time) {
	names := make([]string, 0, len(pages))
	for name := range pages {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		s.Record(name, pages[name], now)
	}
}

// Validated reports whether exactly this content passed exactly this type.
//
// Both hashes must match. Matching only the content hash would say "this content
// was valid once", which is true of content whose type has since been tightened
// and which would fail today.
func (s *Store) Validated(page string, body any) bool {
	typeName, bound := s.Bound[page]
	if !bound {
		return false
	}
	t, ok := s.Registry.Get(typeName)
	if !ok {
		return false
	}
	content, ok := body.(map[string]any)
	if !ok {
		return false
	}
	wantType, wantContent := Hash(t), contentHash(content)
	for i := len(s.Records) - 1; i >= 0; i-- {
		r := s.Records[i]
		if r.Page == page && r.TypeHash == wantType && r.ContentHash == wantContent {
			return true
		}
	}
	return false
}
