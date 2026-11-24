// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package side is the register's side store: the words and the files a
// record names by their hash, and the map from a pseudonym to the person it
// stands for, each kept where it can be erased.
//
// # Why there is a second store
//
// The register is an append-only store addressed by hash, and it cannot
// forget anything without breaking every hash above it. That is what makes
// it evidence, and it is why personal data does not go in it. A person is a
// pseudonym there, 128 random bits; free text, where a person's name ends
// up, is the digest of the words; a raw file is the digest of the file. The
// pseudonym, the words and the file are here, one file each, and erasing
// one deletes that file and nothing in the register, so every hash and
// every chain still checks after a person is erased.
//
// # Files
//
//	side/entries/AB/CDEF…       one entry: what it holds, which kinds hold it, whom it is about
//	side/erased/ABCDEF….json    what was erased, when and why; nothing of what it held
//	side/subjects/ID            one person: the pseudonym, their name, what sort of account
//	side/subjects/erased/ID.json  an erased person: when and why; nothing of who they were
//	side/.lock                  held while anything here changes
//
// An entry's name is the SHA-256 of what it holds, and reading one checks
// the hash, so a file changed beside the store is refused where it is read.
// On an encrypted store each file is sealed with the store's own keyring,
// bound to its name, so nothing here is in the clear either. A tombstone is
// in the clear on every store: it says only that something under a name
// was erased, and when, which is what a screen shows in its place.
package side

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/plaintext"
)

// Sealer seals and opens a file kept beside the store, under the store's
// keyring when it has one. *store.Store is one.
type Sealer interface {
	Seal(payload, aad []byte) ([]byte, error)
	Unseal(body, aad []byte) ([]byte, error)
}

// Store is the side store in one directory.
type Store struct {
	dir  string
	seal Sealer
	// Now is the clock, for tests. Nil is the system's.
	Now func() time.Time
}

// Open is the side store in dir, sealed by seal. Nothing is created until
// something is written.
func Open(dir string, seal Sealer) *Store { return &Store{dir: dir, seal: seal} }

// Dir is where the side store keeps its files.
func (s *Store) Dir() string { return s.dir }

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

var (
	// ErrNotHeld is a digest nothing was ever put under here, or not on
	// this instance: the words may be kept by another, or were never kept.
	ErrNotHeld = errors.New("the side store holds nothing under that digest")
	// ErrMismatch is an entry that does not hold what its name says.
	ErrMismatch = errors.New("the side entry does not match its digest")
	// ErrNoSubject is a pseudonym the map has never named.
	ErrNoSubject = errors.New("the subject map names nobody by that pseudonym")

	reHex       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	rePseudonym = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// The bases an entry is erased on by the side store itself. A person's
// erasure gives its own (the Erasure record's basis).
const (
	// BasisRetention is an entry every kind holding it had kept for as
	// long as it declares.
	BasisRetention = "retention"
	// BasisSubject is an entry about a person who was erased.
	BasisSubject = "subject"
)

// Erased is what was under a name before it was erased: when, and on what
// basis. It is an error, so a reader of an erased entry is told so in
// place of the entry.
type Erased struct {
	At    time.Time `json:"at"`
	Basis string    `json:"basis"`
}

func (e *Erased) Error() string {
	return fmt.Sprintf("erased on %s (%s)", e.At.Format("2 January 2006"), e.Basis)
}

// Entry is what the side store knows about one entry, without what it
// holds.
type Entry struct {
	// Digest is the entry's name: "sha256:" and 64 hexadecimal characters.
	Digest string `json:"digest"`
	// Media is "text" for words a person wrote, or the media type of a file.
	Media string `json:"media"`
	Size  int64  `json:"size"`
	// Kinds is each kind whose records hold the entry, with the last time a
	// record of it was put, in seconds since 1970: what retention is
	// counted from.
	Kinds map[string]int64 `json:"kinds"`
	// Subjects are the pseudonyms of the people the entry is about, erased
	// with them.
	Subjects []string `json:"subjects,omitempty"`
}

// stored is an entry as its file holds it.
type stored struct {
	Entry
	Content []byte `json:"content"`
}

// Person is one entry of the subject map: who a pseudonym stands for.
type Person struct {
	Pseudonym string `json:"pseudonym"`
	// Name is how the person is known to the systems that name them: their
	// account's principal, user principal name or address.
	Name string `json:"name"`
	// Type is what sort of person or account it is, as the register's
	// Subject records say.
	Type    string    `json:"type"`
	Created time.Time `json:"created"`
}

func (s *Store) entryPath(hexd string) string {
	return filepath.Join(s.dir, "entries", hexd[:2], hexd[2:])
}
func (s *Store) tombPath(hexd string) string { return filepath.Join(s.dir, "erased", hexd+".json") }
func (s *Store) personPath(id string) string { return filepath.Join(s.dir, "subjects", id) }
func (s *Store) personTomb(id string) string {
	return filepath.Join(s.dir, "subjects", "erased", id+".json")
}

// hexOf is a digest's hexadecimal part, or an error for anything that is
// not a digest: a digest is a file's name here, and a path is not one.
func hexOf(digest string) (string, error) {
	h, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || !reHex.MatchString(h) {
		return "", fmt.Errorf("%q is not a digest: sha256: and 64 hexadecimal characters", clip(digest))
	}
	return h, nil
}

// clip is what a refusal quotes of a value it was given: one short line,
// cut on a character.
func clip(s string) string { return plaintext.Clip(s, 80, "…") }

// locked runs fn holding the side store's lock, which every change takes:
// two processes adding one entry, or enrolling one person, write one.
func (s *Store) locked(fn func() error) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	unlock, err := atomicfile.Lock(filepath.Join(s.dir, ".lock"))
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

// write puts a sealed file in place, with only its owner able to read it.
func (s *Store) write(path string, payload, aad []byte) error {
	body, err := s.seal.Seal(payload, aad)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(path, body, 0o600)
}

// read is a sealed file's payload.
func (s *Store) read(path string, aad []byte) ([]byte, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return s.seal.Unseal(body, aad)
}

func entryAAD(hexd string) []byte { return []byte("quilzo/side/entry/" + hexd) }
func personAAD(id string) []byte  { return []byte("quilzo/side/subject/" + id) }

// Put keeps content under its digest, as held by a record of kind and about
// the people subjects names by pseudonym, and returns the digest. The same
// content put again is the same entry: the kind and the people are added
// to it, and the kind's time is moved on, which is what its retention is
// counted from.
//
// media is "text" for words a person wrote, or the media type of a file.
func (s *Store) Put(kind, media string, content []byte, subjects ...string) (string, error) {
	if strings.TrimSpace(kind) == "" {
		return "", fmt.Errorf("a side entry is held by a kind of record, and none was named")
	}
	for _, p := range subjects {
		if !rePseudonym.MatchString(p) {
			return "", fmt.Errorf("%q is not a pseudonym", clip(p))
		}
	}
	sum := sha256.Sum256(content)
	hexd := hex.EncodeToString(sum[:])
	digest := "sha256:" + hexd
	err := s.locked(func() error {
		st := stored{Entry: Entry{Digest: digest, Media: media, Size: int64(len(content)), Kinds: map[string]int64{}},
			Content: content}
		if was, err := s.entry(hexd); err == nil {
			st.Entry = was
			if st.Media == "" {
				st.Media = media
			}
		} else if !errors.Is(err, ErrNotHeld) {
			var erased *Erased
			if !errors.As(err, &erased) {
				return err
			}
		}
		st.Kinds[kind] = s.now().Unix()
		for _, p := range subjects {
			if !contains(st.Subjects, p) {
				st.Subjects = append(st.Subjects, p)
			}
		}
		sort.Strings(st.Subjects)
		payload, err := json.Marshal(st)
		if err != nil {
			return err
		}
		if err := s.write(s.entryPath(hexd), payload, entryAAD(hexd)); err != nil {
			return err
		}
		// Put again after it was erased, it is kept again: somebody wrote
		// the same words a second time, and that is new.
		if err := os.Remove(s.tombPath(hexd)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return digest, nil
}

// load reads and checks one entry's file.
func (s *Store) load(hexd string) (stored, error) {
	payload, err := s.read(s.entryPath(hexd), entryAAD(hexd))
	if errors.Is(err, fs.ErrNotExist) {
		if t, terr := s.tomb(s.tombPath(hexd)); terr == nil {
			return stored{}, t
		}
		return stored{}, ErrNotHeld
	}
	if err != nil {
		return stored{}, fmt.Errorf("%w: %v", ErrMismatch, err)
	}
	var st stored
	if err := json.Unmarshal(payload, &st); err != nil {
		return stored{}, fmt.Errorf("%w: it does not read as an entry", ErrMismatch)
	}
	sum := sha256.Sum256(st.Content)
	if hex.EncodeToString(sum[:]) != hexd || st.Digest != "sha256:"+hexd {
		return stored{}, ErrMismatch
	}
	if st.Kinds == nil {
		st.Kinds = map[string]int64{}
	}
	return st, nil
}

func (s *Store) entry(hexd string) (Entry, error) {
	st, err := s.load(hexd)
	return st.Entry, err
}

func (s *Store) tomb(path string) (*Erased, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var e Erased
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// Get is what is kept under a digest, checked against it. An entry that
// was erased answers *Erased, one never put here ErrNotHeld, and one that
// does not hold what its name says ErrMismatch.
func (s *Store) Get(digest string) ([]byte, error) {
	hexd, err := hexOf(digest)
	if err != nil {
		return nil, err
	}
	st, err := s.load(hexd)
	if err != nil {
		return nil, err
	}
	return st.Content, nil
}

// Entry is what the side store knows about one entry, without what it
// holds; checked, as Get checks it.
func (s *Store) Entry(digest string) (Entry, error) {
	hexd, err := hexOf(digest)
	if err != nil {
		return Entry{}, err
	}
	return s.entry(hexd)
}

// Entries is every entry the side store holds, in the order of their
// digests. An entry that does not check is an error, not left out: a sweep
// that skipped what it could not read would keep it for ever.
func (s *Store) Entries() ([]Entry, error) {
	var out []Entry
	root := filepath.Join(s.dir, "entries")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) && path == root {
			return fs.SkipDir
		}
		if err != nil || d.IsDir() || strings.HasPrefix(d.Name(), ".") {
			return err
		}
		hexd := filepath.Base(filepath.Dir(path)) + d.Name()
		if !reHex.MatchString(hexd) {
			return nil
		}
		e, err := s.entry(hexd)
		if err != nil {
			return fmt.Errorf("the side entry %s: %w", hexd, err)
		}
		out = append(out, e)
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Digest < out[j].Digest })
	return out, err
}

// About is every entry about the person a pseudonym stands for.
func (s *Store) About(pseudonym string) ([]Entry, error) {
	all, err := s.Entries()
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, e := range all {
		if contains(e.Subjects, pseudonym) {
			out = append(out, e)
		}
	}
	return out, nil
}

// EraseEntries deletes each entry, leaving a tombstone that says when and
// on what basis. An entry already gone is not an error: erasing is what
// was asked, and it is so.
func (s *Store) EraseEntries(entries []Entry, basis string) error {
	return s.locked(func() error {
		for _, e := range entries {
			hexd, err := hexOf(e.Digest)
			if err != nil {
				return err
			}
			if err := s.erase(hexd, basis); err != nil {
				return err
			}
		}
		return nil
	})
}

// Erase deletes one entry, as EraseEntries does.
func (s *Store) Erase(digest, basis string) error {
	return s.EraseEntries([]Entry{{Digest: digest}}, basis)
}

func (s *Store) erase(hexd, basis string) error {
	if err := s.tombstone(s.tombPath(hexd), basis); err != nil {
		return err
	}
	if err := os.Remove(s.entryPath(hexd)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Store) tombstone(path, basis string) error {
	b, err := json.Marshal(Erased{At: s.now(), Basis: basis})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(path, b, 0o600)
}

// Expire deletes every entry that each kind holding it has kept for as long
// as retain says it keeps its entries, and returns their digests. A kind
// retain gives no period keeps its entries until a person erases them, so
// an entry it shares is kept.
func (s *Store) Expire(retain func(kind string) time.Duration) ([]string, error) {
	var gone []string
	err := s.locked(func() error {
		all, err := s.Entries()
		if err != nil {
			return err
		}
		now := s.now()
		for _, e := range all {
			if !expired(e, retain, now) {
				continue
			}
			hexd, _ := hexOf(e.Digest)
			if err := s.erase(hexd, BasisRetention); err != nil {
				return err
			}
			gone = append(gone, e.Digest)
		}
		return nil
	})
	return gone, err
}

func expired(e Entry, retain func(string) time.Duration, now time.Time) bool {
	if len(e.Kinds) == 0 {
		return false
	}
	for kind, put := range e.Kinds {
		keep := retain(kind)
		if keep <= 0 || now.Before(time.Unix(put, 0).Add(keep)) {
			return false
		}
	}
	return true
}

// Enrol is the pseudonym of the person a name belongs to, minted the first
// time they are named. minted says it was new. Names are compared without
// regard to letter case, as an address or an account name is.
func (s *Store) Enrol(name, typ string) (pseudonym string, minted bool, err error) {
	name = strings.TrimSpace(name)
	if err := validName(name); err != nil {
		return "", false, err
	}
	err = s.locked(func() error {
		if found, ok, err := s.lookup(name); err != nil || ok {
			pseudonym = found
			return err
		}
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("no entropy for a pseudonym: %w", err)
		}
		pseudonym, minted = hex.EncodeToString(b), true
		payload, err := json.Marshal(Person{Pseudonym: pseudonym, Name: name, Type: typ, Created: s.now()})
		if err != nil {
			return err
		}
		return s.write(s.personPath(pseudonym), payload, personAAD(pseudonym))
	})
	return pseudonym, minted, err
}

// validName refuses a name that is no name: empty, or on more than one
// line, or longer than any address.
func validName(name string) error {
	if name == "" {
		return fmt.Errorf("a person is enrolled under a name, and none was given")
	}
	if len(name) > 320 {
		return fmt.Errorf("a name of %d bytes is longer than any address", len(name))
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("a name is one line")
		}
	}
	return nil
}

// Lookup is the pseudonym of the person a name belongs to, if they are
// enrolled and not erased.
func (s *Store) Lookup(name string) (string, bool, error) {
	return s.lookup(strings.TrimSpace(name))
}

func (s *Store) lookup(name string) (string, bool, error) {
	people, err := s.Subjects()
	if err != nil {
		return "", false, err
	}
	for _, p := range people {
		if strings.EqualFold(p.Name, name) {
			return p.Pseudonym, true, nil
		}
	}
	return "", false, nil
}

// Who is the person a pseudonym stands for. An erased one answers *Erased,
// and one the map never named ErrNoSubject.
func (s *Store) Who(pseudonym string) (Person, error) {
	if !rePseudonym.MatchString(pseudonym) {
		return Person{}, fmt.Errorf("%q is not a pseudonym", clip(pseudonym))
	}
	payload, err := s.read(s.personPath(pseudonym), personAAD(pseudonym))
	if errors.Is(err, fs.ErrNotExist) {
		if t, terr := s.tomb(s.personTomb(pseudonym)); terr == nil {
			return Person{}, t
		}
		return Person{}, ErrNoSubject
	}
	if err != nil {
		return Person{}, err
	}
	var p Person
	if err := json.Unmarshal(payload, &p); err != nil || p.Pseudonym != pseudonym {
		return Person{}, fmt.Errorf("the subject map's entry for %s does not read as one", pseudonym)
	}
	return p, nil
}

// Subjects is every person the map names, in the order of their
// pseudonyms.
func (s *Store) Subjects() ([]Person, error) {
	dir := filepath.Join(s.dir, "subjects")
	list, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Person
	for _, de := range list {
		if de.IsDir() || !rePseudonym.MatchString(de.Name()) {
			continue
		}
		p, err := s.Who(de.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// EraseSubject deletes the map's entry for a pseudonym, leaving a tombstone
// that says when and on what basis; from then on the pseudonym names
// nobody. A pseudonym already erased answers *Erased, and one never named
// ErrNoSubject.
func (s *Store) EraseSubject(pseudonym, basis string) error {
	if _, err := s.Who(pseudonym); err != nil {
		return err
	}
	return s.locked(func() error {
		if err := s.tombstone(s.personTomb(pseudonym), basis); err != nil {
			return err
		}
		return os.Remove(s.personPath(pseudonym))
	})
}

// SubjectErased is when and why a pseudonym's person was erased, or nil
// when they were not.
func (s *Store) SubjectErased(pseudonym string) *Erased {
	if !rePseudonym.MatchString(pseudonym) {
		return nil
	}
	t, err := s.tomb(s.personTomb(pseudonym))
	if err != nil {
		return nil
	}
	return t
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
