// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
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

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/register"
)

// The raw evidence store: each file as it was received, under its SHA-256,
// sealed with the store's keyring, kept until its time is up and then
// erased, and beside it, kept for good, the list of what was read from it.
//
// The register cannot forget, and a raw file has to be able to go: it holds
// whatever its sender put in it, people's names included, and how long it
// is kept is a decision about personal data. So the bytes live here, next
// to the store and not in it, and a record in the register holds only their
// digest. What is kept after the bytes have gone is what lets every fact
// read from them still be checked: the seal's own record (its size and
// when it came) and the list of the records the file yielded, each with the
// hash of its fields, whose digest the register holds.
//
//	evidence/raw/AB/CDEF…        a file, sealed
//	evidence/seal/ABCDEF….json   when it came, until when it is kept, when it went
//	evidence/yield/ABCDEF…       a list of what was read from a file, by the list's own digest
//	evidence/.lock               held while anything here changes
//
// Each file is sealed bound to its own name, so a file moved to stand for
// another does not open, and every read checks the hash it is filed under.

// Sealer seals and opens a file kept beside the store, under the store's
// keyring when it has one. *store.Store is one.
type Sealer interface {
	Seal(payload, aad []byte) ([]byte, error)
	Unseal(body, aad []byte) ([]byte, error)
}

// Raw is the raw evidence store in one directory.
type Raw struct {
	dir  string
	seal Sealer
}

// OpenRaw is the raw evidence store in dir, sealed by seal. Nothing is
// made until something is sealed.
func OpenRaw(dir string, seal Sealer) *Raw { return &Raw{dir: dir, seal: seal} }

// Dir is where the store keeps its files.
func (r *Raw) Dir() string { return r.dir }

// DefaultKeep is how long a raw file is kept after it was last received:
// thirteen months, a year's audit and the month an auditor takes to ask.
const DefaultKeep = 396 * 24 * time.Hour

var (
	// ErrNotHeld is a digest nothing was sealed under here.
	ErrNotHeld = errors.New("the raw evidence store holds nothing under that digest")
	// ErrMismatch is a file that does not hold what its name says.
	ErrMismatch = errors.New("the raw file does not match the digest it is filed under")

	reHex = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Expired is the error a read of a raw file gets once its time is up.
type Expired struct{ At time.Time }

func (e *Expired) Error() string {
	return "the raw file was erased on " + e.At.UTC().Format("2 January 2006") + ", when its time to be kept was up"
}

// Sealed is what the store knows about a raw file, without the file.
type Sealed struct {
	Digest   register.Digest `json:"digest"`
	Size     int64           `json:"size"`
	Received time.Time       `json:"received"`
	// Last is when the file was last received, and Until when it may be
	// erased: Last and the time it is kept for.
	Last  time.Time `json:"last"`
	Until time.Time `json:"until"`
	// Erased is when the bytes were erased, or zero while they are held.
	Erased time.Time `json:"erased,omitzero"`
}

// Held reports whether the bytes are still kept.
func (s Sealed) Held() bool { return s.Erased.IsZero() }

func hexOf(d register.Digest) (string, error) {
	h, ok := strings.CutPrefix(string(d), "sha256:")
	if !ok || !reHex.MatchString(h) {
		return "", fmt.Errorf("%q is not a digest: sha256: and 64 hexadecimal characters", label(string(d)))
	}
	return h, nil
}

func digestOf(b []byte) register.Digest {
	sum := sha256.Sum256(b)
	return register.Digest("sha256:" + hex.EncodeToString(sum[:]))
}

func (r *Raw) rawPath(h string) string   { return filepath.Join(r.dir, "raw", h[:2], h[2:]) }
func (r *Raw) sealPath(h string) string  { return filepath.Join(r.dir, "seal", h+".json") }
func (r *Raw) yieldPath(h string) string { return filepath.Join(r.dir, "yield", h) }

// aad is what a file here is sealed bound to: what it is and its name.
func aad(what, h string) []byte { return []byte("quilzo evidence " + what + " " + h) }

func (r *Raw) locked(fn func() error) error {
	if err := os.MkdirAll(r.dir, 0o700); err != nil {
		return err
	}
	unlock, err := atomicfile.Lock(filepath.Join(r.dir, ".lock"))
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

func (r *Raw) write(path string, payload, ad []byte) error {
	body, err := r.seal.Seal(payload, ad)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(path, body, 0o600)
}

func (r *Raw) read(path string, ad []byte) ([]byte, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return r.seal.Unseal(body, ad)
}

// Seal keeps a file under its digest, before anything has read it, and
// says what the store knows of it. Sealing a file already held changes only
// when it was last received; one whose bytes were erased is held again.
// When it was first received never changes, so a second import of the same
// file is the same import.
func (r *Raw) Seal(body []byte, now time.Time, keep time.Duration) (Sealed, error) {
	if keep <= 0 {
		keep = DefaultKeep
	}
	d := digestOf(body)
	h, _ := hexOf(d)
	now = now.UTC().Truncate(time.Second)
	var out Sealed
	err := r.locked(func() error {
		s, err := r.meta(h)
		switch {
		case errors.Is(err, ErrNotHeld):
			s = Sealed{Digest: d, Size: int64(len(body)), Received: now}
		case err != nil:
			return err
		}
		if !s.Held() || !fileExists(r.rawPath(h)) {
			if err := r.write(r.rawPath(h), body, aad("raw", h)); err != nil {
				return err
			}
			s.Erased = time.Time{}
		}
		if now.After(s.Last) {
			s.Last = now
		}
		if until := s.Last.Add(keep); until.After(s.Until) {
			s.Until = until
		}
		out = s
		return r.putMeta(h, s)
	})
	return out, err
}

func (r *Raw) meta(h string) (Sealed, error) {
	b, err := r.read(r.sealPath(h), aad("seal", h))
	if errors.Is(err, fs.ErrNotExist) {
		return Sealed{}, ErrNotHeld
	}
	if err != nil {
		return Sealed{}, err
	}
	var s Sealed
	if err := json.Unmarshal(b, &s); err != nil {
		return Sealed{}, fmt.Errorf("the seal of a raw file is malformed: %w", err)
	}
	if h2, err := hexOf(s.Digest); err != nil || h2 != h {
		return Sealed{}, fmt.Errorf("%w: the seal filed under %s names another file", ErrMismatch, h[:12])
	}
	return s, nil
}

func (r *Raw) putMeta(h string, s Sealed) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return r.write(r.sealPath(h), b, aad("seal", h))
}

// Meta is what the store knows about a raw file.
func (r *Raw) Meta(d register.Digest) (Sealed, error) {
	h, err := hexOf(d)
	if err != nil {
		return Sealed{}, err
	}
	return r.meta(h)
}

// Open is a raw file's bytes, checked against the digest they are filed
// under. A file whose time was up is an *Expired.
func (r *Raw) Open(d register.Digest) ([]byte, error) {
	h, err := hexOf(d)
	if err != nil {
		return nil, err
	}
	s, err := r.meta(h)
	if err != nil {
		return nil, err
	}
	if !s.Held() {
		return nil, &Expired{At: s.Erased}
	}
	b, err := r.read(r.rawPath(h), aad("raw", h))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: its seal is here and the file is not", ErrNotHeld)
	}
	if err != nil {
		return nil, err
	}
	if digestOf(b) != d {
		return nil, fmt.Errorf("%w: %s", ErrMismatch, d)
	}
	return b, nil
}

// PutYield keeps the list of what was read from a file, under the list's
// own digest, and returns that digest.
func (r *Raw) PutYield(list []byte) (register.Digest, error) {
	d := digestOf(list)
	h, _ := hexOf(d)
	err := r.locked(func() error {
		if fileExists(r.yieldPath(h)) {
			return nil
		}
		return r.write(r.yieldPath(h), list, aad("yield", h))
	})
	return d, err
}

// Yield is a list of what was read from a file, checked against its digest.
func (r *Raw) Yield(d register.Digest) ([]byte, error) {
	h, err := hexOf(d)
	if err != nil {
		return nil, err
	}
	b, err := r.read(r.yieldPath(h), aad("yield", h))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotHeld
	}
	if err != nil {
		return nil, err
	}
	if digestOf(b) != d {
		return nil, fmt.Errorf("%w: the list of what was read, %s", ErrMismatch, d)
	}
	return b, nil
}

// Expire erases the bytes of every raw file whose time to be kept is up,
// and keeps its seal and the list of what was read from it. It returns
// what it erased. Nothing is erased before its time: an early erasure of
// evidence is a decision for a person, not for housekeeping.
func (r *Raw) Expire(now time.Time) ([]Sealed, error) {
	var out []Sealed
	err := r.locked(func() error {
		all, err := r.list()
		if err != nil {
			return err
		}
		for _, s := range all {
			if !s.Held() || now.Before(s.Until) {
				continue
			}
			h, _ := hexOf(s.Digest)
			if err := os.Remove(r.rawPath(h)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			s.Erased = now.UTC().Truncate(time.Second)
			if err := r.putMeta(h, s); err != nil {
				return err
			}
			out = append(out, s)
		}
		return nil
	})
	return out, err
}

// List is every raw file the store has sealed, held or erased, in the
// order of their digests.
func (r *Raw) List() ([]Sealed, error) { return r.list() }

func (r *Raw) list() ([]Sealed, error) {
	entries, err := os.ReadDir(filepath.Join(r.dir, "seal"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Sealed
	for _, e := range entries {
		h, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !reHex.MatchString(h) {
			continue
		}
		s, err := r.meta(h)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Digest < out[j].Digest })
	return out, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
