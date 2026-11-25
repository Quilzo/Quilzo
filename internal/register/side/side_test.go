// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package side

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/vault"
)

// clock is a fake clock a test moves by hand.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newSide(t *testing.T) (*Store, *clock, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)}
	side := Open(filepath.Join(dir, "side"), s)
	side.Now = c.now
	return side, c, dir
}

const ada = "0123456789abcdef0123456789abcdef"

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// A side entry is named by the hash of what it holds, and gives back what
// was put, once more under the same name.
func TestASideEntryIsNamedByItsHash(t *testing.T) {
	s, _, _ := newSide(t)
	words := []byte("Accepted until the new laptops arrive.")
	d, err := s.Put("Exception", "text", words, ada)
	if err != nil {
		t.Fatal(err)
	}
	if d != digestOf(words) {
		t.Fatalf("the entry is named %s, and the hash of its words is %s", d, digestOf(words))
	}
	again, err := s.Put("Risk", "text", words)
	if err != nil || again != d {
		t.Fatalf("the same words put again are %s (%v)", again, err)
	}
	got, err := s.Get(d)
	if err != nil || !bytes.Equal(got, words) {
		t.Fatalf("the entry reads back as %q (%v)", got, err)
	}
	e, err := s.Entry(d)
	if err != nil || len(e.Kinds) != 2 || len(e.Subjects) != 1 || e.Subjects[0] != ada {
		t.Fatalf("the entry's account of itself is %+v (%v)", e, err)
	}
}

// PLAN theme 7: a side entry that does not hold what its name says is
// refused, not returned. The digest in a record is what the words are
// checked against, so a file changed beside the store is caught where it
// is read.
func TestSideEntryDigestMismatchRefused(t *testing.T) {
	s, _, dir := newSide(t)
	d, err := s.Put("Risk", "text", []byte("The supplier holds our customers' addresses."))
	if err != nil {
		t.Fatal(err)
	}
	path := s.entryPath(strings.TrimPrefix(d, "sha256:"))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(raw, []byte(`"content":"`), []byte(`"content":"QQ`), 1)
	if bytes.Equal(changed, raw) {
		t.Fatal("the test did not change the entry")
	}
	if err := os.WriteFile(path, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(d); !errors.Is(err, ErrMismatch) {
		t.Fatalf("a changed entry read back with %v", err)
	}
	// And one moved to stand under another's name.
	other, err := s.Put("Risk", "text", []byte("A second risk."))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.entryPath(strings.TrimPrefix(other, "sha256:")), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(other); !errors.Is(err, ErrMismatch) {
		t.Fatalf("an entry under another's name read back with %v", err)
	}
	_ = dir
}

// PLAN theme 7: when every kind that holds an entry has kept it for as
// long as it declares, the entry is deleted, and reading it says it was
// erased, when and why. A kind that keeps its entries until a person erases
// them keeps an entry it shares.
func TestAnEntryExpiresWhenEveryKindHoldingItHasKeptItLongEnough(t *testing.T) {
	s, c, _ := newSide(t)
	keep := map[string]time.Duration{"Observation": 30 * 24 * time.Hour, "Evidence": 90 * 24 * time.Hour}
	retain := func(kind string) time.Duration { return keep[kind] }

	raw, err := s.Put("Observation", "application/json", []byte(`{"mfa":true}`))
	if err != nil {
		t.Fatal(err)
	}
	both, err := s.Put("Observation", "text", []byte("read from the export of 24 November"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put("Evidence", "text", []byte("read from the export of 24 November")); err != nil {
		t.Fatal(err)
	}
	forever, err := s.Put("Decision", "text", []byte("The board minuted it."))
	if err != nil {
		t.Fatal(err)
	}

	c.t = c.t.Add(29 * 24 * time.Hour)
	if gone, err := s.Expire(retain); err != nil || len(gone) != 0 {
		t.Fatalf("a day early, the sweep took %v (%v)", gone, err)
	}
	c.t = c.t.Add(2 * 24 * time.Hour)
	gone, err := s.Expire(retain)
	if err != nil || len(gone) != 1 || gone[0] != raw {
		t.Fatalf("past the observation's period the sweep took %v (%v)", gone, err)
	}
	var erased *Erased
	if _, err := s.Get(raw); !errors.As(err, &erased) || erased.Basis != BasisRetention || !erased.At.Equal(c.t) {
		t.Fatalf("an expired entry reads as %v", err)
	}
	if _, err := os.Stat(s.entryPath(strings.TrimPrefix(raw, "sha256:"))); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the expired entry's file is still there: %v", err)
	}
	if _, err := s.Get(both); err != nil {
		t.Errorf("an entry evidence still keeps was swept with the observation's: %v", err)
	}
	c.t = c.t.Add(60 * 24 * time.Hour)
	if gone, _ := s.Expire(retain); len(gone) != 1 || gone[0] != both {
		t.Errorf("past the evidence's period too, the sweep took %v", gone)
	}
	c.t = c.t.Add(10 * 365 * 24 * time.Hour)
	if gone, _ := s.Expire(retain); len(gone) != 0 {
		t.Errorf("an entry kept until a person erases it was swept: %v", gone)
	}
	if _, err := s.Get(forever); err != nil {
		t.Errorf("the decision's words are gone: %v", err)
	}
}

// The map from a pseudonym to a person: one pseudonym per person, the same
// every time they are asked about, and erasable, after which the pseudonym
// names nobody and says it was erased.
func TestTheSubjectMapIsErasable(t *testing.T) {
	s, c, _ := newSide(t)
	id, minted, err := s.Enrol("ada.lovelace@example.com", "person")
	if err != nil || !minted || len(id) != 32 {
		t.Fatalf("enrolling minted %q (%v, %v)", id, minted, err)
	}
	again, minted, err := s.Enrol("Ada.Lovelace@example.com", "person")
	if err != nil || minted || again != id {
		t.Fatalf("the same person enrolled again is %q (%v, %v)", again, minted, err)
	}
	other, _, _ := s.Enrol("grace@example.com", "person")
	if other == id {
		t.Fatal("two people have one pseudonym")
	}
	p, err := s.Who(id)
	if err != nil || p.Name != "ada.lovelace@example.com" {
		t.Fatalf("the pseudonym names %+v (%v)", p, err)
	}

	words, _ := s.Put("Risk", "text", []byte("Ada Lovelace raised this after the audit."), id)
	kept, _ := s.Put("Risk", "text", []byte("Nobody in particular."))
	planned, err := s.About(id)
	if err != nil || len(planned) != 1 || planned[0].Digest != words {
		t.Fatalf("the entries about the person are %+v (%v)", planned, err)
	}
	c.t = c.t.Add(time.Hour)
	if err := s.EraseEntries(planned, BasisSubject); err != nil {
		t.Fatal(err)
	}
	if err := s.EraseSubject(id, "request"); err != nil {
		t.Fatal(err)
	}
	var erased *Erased
	if _, err := s.Who(id); !errors.As(err, &erased) || erased.Basis != "request" {
		t.Fatalf("an erased pseudonym answers %v", err)
	}
	if _, err := s.Get(words); !errors.As(err, &erased) || erased.Basis != BasisSubject {
		t.Fatalf("the words about the person read as %v", err)
	}
	if _, err := s.Get(kept); err != nil {
		t.Errorf("words about nobody were erased with the person's: %v", err)
	}
	if found, ok, _ := s.Lookup("ada.lovelace@example.com"); ok {
		t.Errorf("the erased person is still found, as %s", found)
	}
	if err := s.EraseSubject(id, "request"); !errors.As(err, &erased) {
		t.Errorf("erasing an erased person again answered %v", err)
	}
	// Enrolled again, the person is somebody new: the old pseudonym stays
	// the pseudonym of nobody.
	fresh, minted, _ := s.Enrol("ada.lovelace@example.com", "person")
	if !minted || fresh == id {
		t.Errorf("enrolling an erased person gave back %s", fresh)
	}
}

// On an encrypted store the side store keeps nothing in the clear: not the
// words, not the person's address.
func TestASealedSideStoreKeepsNothingInTheClear(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := vault.NewKeyring("k1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	st.WithKeys(kr)
	s := Open(filepath.Join(dir, "side"), st)
	if _, _, err := s.Enrol("ada.lovelace@example.com", "person"); err != nil {
		t.Fatal(err)
	}
	d, err := s.Put("Risk", "text", []byte("Ada Lovelace raised this."))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(d); err != nil || string(got) != "Ada Lovelace raised this." {
		t.Fatalf("the sealed entry reads back as %q (%v)", got, err)
	}
	_ = filepath.WalkDir(filepath.Join(dir, "side"), func(path string, de fs.DirEntry, err error) error {
		if err != nil || de.IsDir() {
			return err
		}
		b, _ := os.ReadFile(path)
		for _, secret := range []string{"ada.lovelace", "Ada Lovelace"} {
			if bytes.Contains(b, []byte(secret)) {
				t.Errorf("%s holds %q in the clear", path, secret)
			}
		}
		return nil
	})
}

// What the side store refuses: a pseudonym that is not one, an empty name,
// and a name on more than one line.
func TestTheSideStoreRefusesWhatItCannotName(t *testing.T) {
	s, _, _ := newSide(t)
	if _, err := s.Who("../../etc/passwd"); err == nil {
		t.Error("a path was taken for a pseudonym")
	}
	for _, name := range []string{"", "  ", "ada\nlovelace"} {
		if _, _, err := s.Enrol(name, "person"); err == nil {
			t.Errorf("the name %q was enrolled", name)
		}
	}
	if _, err := s.Get("sha256:../../x"); err == nil {
		t.Error("a path was taken for a digest")
	}
	if _, err := s.Get(digestOf([]byte("never put"))); !errors.Is(err, ErrNotHeld) {
		t.Errorf("an entry never put answered %v", err)
	}
}

// A name is found in the subject map by its bucket of the name index,
// without reading every person the map holds: a connector names thousands
// of accounts on every run, and a map read whole for each would take as
// long as their number squared. So one person's file that does not read
// stops nobody else being found or enrolled; an index that is missing is
// built again from the map; and an erased person's name goes from the
// index with their file, so no file of the side store holds it.
func TestTheSubjectMapFindsANameByItsBucket(t *testing.T) {
	s, _, _ := newSide(t)
	ada, _, err := s.Enrol("ada.lovelace@example.com", "person")
	if err != nil {
		t.Fatal(err)
	}
	grace, _, _ := s.Enrol("grace@example.com", "person")
	if err := os.WriteFile(s.personPath(grace), []byte("not a person"), 0o600); err != nil {
		t.Fatal(err)
	}
	if found, ok, err := s.Lookup("ADA.LOVELACE@example.com"); err != nil || !ok || found != ada {
		t.Fatalf("with another person's file unreadable, ada is found as %q, %v (%v)", found, ok, err)
	}
	if _, minted, err := s.Enrol("lin@example.com", "person"); err != nil || !minted {
		t.Fatalf("with another person's file unreadable, enrolling answered %v, %v", minted, err)
	}
	if err := os.RemoveAll(filepath.Join(s.dir, "subjects", "names")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.personPath(grace)); err != nil {
		t.Fatal(err)
	}
	if found, ok, err := s.Lookup("ada.lovelace@example.com"); err != nil || !ok || found != ada {
		t.Fatalf("with the index gone, ada is found as %q, %v (%v)", found, ok, err)
	}
	if again, minted, _ := s.Enrol("ada.lovelace@example.com", "person"); minted || again != ada {
		t.Fatalf("with the index built again, ada enrolled as %s (minted %v)", again, minted)
	}
	if err := s.EraseSubject(ada, "request"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Lookup("ada.lovelace@example.com"); ok {
		t.Error("the erased person is still found")
	}
	_ = filepath.WalkDir(s.dir, func(path string, de fs.DirEntry, err error) error {
		if err != nil || de.IsDir() {
			return err
		}
		if b, _ := os.ReadFile(path); bytes.Contains(bytes.ToLower(b), []byte("ada.lovelace")) {
			t.Errorf("%s still holds the erased person's name", path)
		}
		return nil
	})
}
