package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// Store is the one place that decides whether content is allowed to be written.
//
// It exists as a package-level object rather than as code in each command
// because of a mistake this project has now made three times: a rule enforced in
// the CLI and absent from the web UI, or present in both and absent from the
// agent interface, is not a rule. It is a rule-shaped thing in whichever
// interface the person happened to read. Type validation has three write
// surfaces — `quilzo add`, the admin save handler, and the MCP write_page
// operation — and all three call Gate. Adding a fourth without calling it is
// caught by a test that walks the source.
type Store struct {
	// Broken names the stored types that no longer compile, and why.
	//
	// Not serialised: it is a fact about this load, derived from the file, and
	// writing it back would make a repaired type look broken forever.
	Broken map[string]string `json:"-"`

	dir      string
	Registry *Registry `json:"types"`
	// Bound maps a page to the type it is expected to satisfy. A page with no
	// entry is unconstrained; there is no implicit default type, because a
	// default would validate content nobody chose to validate and reject writes
	// for reasons the author never set up.
	Bound map[string]string `json:"bound"`
	// Collections maps a collection to the type its records must satisfy.
	//
	// Separate from Bound, and deliberately so. A page is one document with a
	// name; a collection is many documents sharing a shape, and binding the
	// shape to the collection rather than to each record is what makes the
	// constraint hold for records nobody has written yet.
	//
	// Its absence was a real gap: types bound to pages only, so `records add`
	// stored anything at all while the equivalent page write was refused. That
	// stopped being academic when the catalogue began publishing records to
	// shopping agents — a product with no price is not a product, and nothing
	// said so.
	Collections map[string]string `json:"collections,omitempty"`
	// Records is the append-only history of successful validations: which
	// content hash passed which type hash, and when.
	Records []Binding `json:"records"`
}

// RecordGate builds the check a record write passes through.
//
// Returns a plain function so the storage package needs no import of this one:
// the dependency would run the wrong way, since types are a constraint on
// content and this is what content is stored by.
//
// Written once so the four surfaces that write records cannot express the same
// rule four different ways — which is exactly how the page gate came to be
// enforced on the command line and not in the content API.
//
// A loader that is nil or fails refuses the write. A type store that cannot be
// read is not a store with no types, and treating it as one would make an
// unreadable file the way to switch validation off.
// Invalid is content that does not satisfy its type.
//
// A distinct type because the alternative is what the API did: every failure
// out of the write path became one generic error, so a record missing a
// required field came back as HTTP 500. That is wrong in three ways at once —
// it pages somebody, it spends an error budget on a typo, and it tells the
// client to retry something that will never succeed however many times it is
// sent.
//
// The distinction a caller actually needs is "the content is wrong" versus
// "this store is broken", and only the writer knows which. So the writer says.
type Invalid struct {
	// Collection or page the content was destined for.
	Where string
	// Problems is what is wrong with it, in the author's terms.
	Problems []Problem
}

func (e *Invalid) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "this record does not satisfy the type bound to %s", e.Where)
	for _, p := range e.Problems {
		fmt.Fprintf(&b, "\n  %s", p)
	}
	return b.String()
}

// IsInvalid reports whether an error is content failing its type, as opposed
// to anything else that can go wrong on a write.
func IsInvalid(err error) bool {
	var inv *Invalid
	return errors.As(err, &inv)
}

func RecordGate(load func() (*Store, error)) func(string, map[string]any) error {
	return func(collection string, fields map[string]any) error {
		if load == nil {
			return fmt.Errorf(
				"this server cannot read the content types, so it will not " +
					"store a record it has not validated")
		}
		st, err := load()
		if err != nil {
			return fmt.Errorf("the content types could not be read: %w", err)
		}
		if st == nil {
			return fmt.Errorf(
				"this server has no content types loaded, so it will not " +
					"store a record it has not validated")
		}
		problems := st.CheckRecord(collection, fields)
		if len(problems) == 0 {
			return nil
		}
		return &Invalid{Where: collection, Problems: problems}
	}
}

// BindCollection requires every record in a collection to satisfy a type.
func (s *Store) BindCollection(collection, typeName string) error {
	if _, ok := s.Registry.Get(typeName); !ok {
		return fmt.Errorf("there is no type %q; run quilzo type list", typeName)
	}
	if s.Collections == nil {
		s.Collections = map[string]string{}
	}
	s.Collections[collection] = typeName
	return nil
}

// UnbindCollection removes the requirement.
func (s *Store) UnbindCollection(collection string) {
	delete(s.Collections, collection)
}

// CollectionType names the type a collection's records must satisfy, if any.
func (s *Store) CollectionType(collection string) (string, bool) {
	t, ok := s.Collections[collection]
	return t, ok
}

// CheckRecord validates one record's fields against its collection's type.
//
// Nil when the collection is unbound, which is every collection until somebody
// binds one — the same rule pages follow. There is no implicit default type,
// because a default would reject writes for reasons the author never set up.
//
// A binding pointing at a deleted type fails closed, for the same reason the
// page path does: treating it as unbound would make deleting a type a way to
// switch validation off for everything using it.
func (s *Store) CheckRecord(collection string, fields map[string]any) []Problem {
	typeName, bound := s.Collections[collection]
	if !bound {
		return nil
	}
	t, ok := s.Registry.Get(typeName)
	if !ok {
		return []Problem{{Field: collection, Reason: fmt.Sprintf(
			"is bound to type %q, which no longer exists", typeName)}}
	}
	if fields == nil {
		fields = map[string]any{}
	}
	return Validate(t, fields)
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
	//
	// Set aside rather than fatal. Refusing the whole load meant one bad type
	// made every type command refuse, including the ones that would show you
	// which type and why: the store became unreadable and therefore
	// unrepairable through the tool. It happened here the day a field name
	// became reserved — a type that compiled last week did not this week, and
	// there was no way to look at it.
	//
	// A broken type is not in the registry, so nothing validates against it and
	// no page is quietly let through: Store.Broken is what the commands report,
	// and a page bound to one is refused by name.
	for name, t := range s.Registry.Types {
		if err := Compile(t); err != nil {
			if s.Broken == nil {
				s.Broken = map[string]string{}
			}
			s.Broken[name] = err.Error()
			delete(s.Registry.Types, name)
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
	// Atomic: the admin writes this while the site is reading it to render.
	return atomicfile.Write(storePath(s.dir), b, 0o600)
}

// Bind declares that a page must satisfy a type.
func (s *Store) Bind(page, typeName string) error {
	if _, ok := s.Registry.Get(typeName); !ok {
		return fmt.Errorf("there is no type %q; run quilzo type list", typeName)
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
		//
		// A type that is stored and does not compile is the same situation with
		// a different cause, and saying which one it is saves somebody looking
		// for a type they can see in the file.
		if why, broken := s.Broken[typeName]; broken {
			return []Problem{{Field: page, Reason: fmt.Sprintf(
				"is bound to type %q, which is stored and does not compile, so "+
					"nothing is validated against it: %s", typeName, why)}}
		}
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
