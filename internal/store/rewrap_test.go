// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/vault"
)

// sealedStore is a store with a one-key keyring and some content.
func sealedStore(t *testing.T) (*Store, *vault.Keyring, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	kr := &vault.Keyring{Keys: map[string]*vault.KEK{}}
	if err := kr.Add("k1", time.Now()); err != nil {
		t.Fatal(err)
	}
	s = s.WithKeys(kr)
	for _, name := range []string{"one", "two", "three"} {
		if _, err := s.PutBlob(map[string]any{"title": name}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	return s, kr, dir
}

// kekOf reads which key each object on disk is wrapped with.
func kekOf(t *testing.T, dir string) map[string]int {
	t.Helper()
	out := map[string]int{}
	root := filepath.Join(dir, "objects")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(d.Name(), ".") {
			return err
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if !vault.IsSealed(body) {
			out["plain"]++
			return nil
		}
		sealed, uerr := vault.Unmarshal(body)
		if uerr != nil {
			return uerr
		}
		out[sealed.KEK]++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The thing rotation was for and did not do. `quilzo vault rotate` added a key
// and printed "nothing was re-encrypted. Rotation rewraps data keys, which is
// why it is cheap enough to actually do" — and rewrapped nothing, because
// vault.Keyring.Rewrap had no caller outside its own tests. So a compromised
// key could never be retired.
func TestRewrapMovesEveryObjectToTheActiveKey(t *testing.T) {
	s, kr, dir := sealedStore(t)

	if got := kekOf(t, dir); got["k1"] == 0 {
		t.Fatalf("nothing was sealed under k1: %v", got)
	}
	if err := kr.Add("k2", time.Now()); err != nil {
		t.Fatal(err)
	}

	done, err := s.Rewrap()
	if err != nil {
		t.Fatal(err)
	}
	if done.Moved == 0 {
		t.Fatal("nothing was moved")
	}
	got := kekOf(t, dir)
	if got["k1"] != 0 {
		t.Errorf("%d object(s) are still wrapped with the old key", got["k1"])
	}
	if got["k2"] != done.Moved {
		t.Errorf("%d on k2, %d reported moved", got["k2"], done.Moved)
	}
}

// The whole point: after a rewrap the old key is no longer needed to read the
// store. This is the assertion the command's own message makes.
func TestAfterRewrapTheOldKeyIsNotNeeded(t *testing.T) {
	s, kr, dir := sealedStore(t)
	oid, err := s.PutBlob(map[string]any{"title": "findable"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := kr.Add("k2", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rewrap(); err != nil {
		t.Fatal(err)
	}

	// A keyring holding only the new key, which is what an operator has once
	// they have retired the old one.
	only := &vault.Keyring{Active: "k2", Keys: map[string]*vault.KEK{
		"k2": {ID: "k2", Key: kr.Keys["k2"].Key},
	}}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	reopened = reopened.WithKeys(only)

	var body map[string]any
	if err := reopened.GetBlob(oid, &body); err != nil {
		t.Fatalf("the store cannot be read without the retired key: %v", err)
	}
	if body["title"] != "findable" {
		t.Errorf("the content came back as %v", body)
	}
	if _, err := reopened.Verify(); err != nil {
		t.Errorf("verify failed with only the new key: %v", err)
	}
}

// The content is never decrypted. A rewrap that re-encrypted would still pass
// the test above, and would be the expensive thing this design exists to
// avoid — so the ciphertext itself must be byte-identical.
func TestRewrapDoesNotTouchTheCiphertext(t *testing.T) {
	s, kr, dir := sealedStore(t)

	before := map[string]string{}
	for path, sealed := range sealedFiles(t, dir) {
		before[path] = string(sealed.Body) + "|" + string(sealed.Nonce)
	}
	if err := kr.Add("k2", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rewrap(); err != nil {
		t.Fatal(err)
	}

	for path, sealed := range sealedFiles(t, dir) {
		if got := string(sealed.Body) + "|" + string(sealed.Nonce); got != before[path] {
			t.Errorf("%s: the ciphertext changed, so the content was "+
				"decrypted and re-encrypted", filepath.Base(path))
		}
		if sealed.KEK != "k2" {
			t.Errorf("%s is still on %s", filepath.Base(path), sealed.KEK)
		}
	}
}

func sealedFiles(t *testing.T, dir string) map[string]*vault.Sealed {
	t.Helper()
	out := map[string]*vault.Sealed{}
	err := filepath.WalkDir(filepath.Join(dir, "objects"),
		func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || strings.HasPrefix(d.Name(), ".") {
				return err
			}
			body, rerr := os.ReadFile(path)
			if rerr != nil || !vault.IsSealed(body) {
				return rerr
			}
			s, uerr := vault.Unmarshal(body)
			if uerr != nil {
				return uerr
			}
			out[path] = s
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Running it twice moves nothing the second time, which is what makes it the
// recovery path for a rewrap that stopped half way.
func TestRewrapIsIdempotent(t *testing.T) {
	s, kr, _ := sealedStore(t)
	if err := kr.Add("k2", time.Now()); err != nil {
		t.Fatal(err)
	}
	first, err := s.Rewrap()
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.Rewrap()
	if err != nil {
		t.Fatal(err)
	}
	if again.Moved != 0 {
		t.Errorf("the second pass moved %d", again.Moved)
	}
	if again.Current != first.Moved {
		t.Errorf("%d already current, %d were moved", again.Current, first.Moved)
	}
}

// Objects written before encryption was enabled stay in the clear. The
// operator who enabled the vault was told "objects already written stay in the
// clear; only new ones are sealed" — a rotation that quietly changed that
// would be a different command wearing this one's name.
func TestRewrapLeavesPlaintextObjectsAlone(t *testing.T) {
	dir := t.TempDir()
	plain, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	before, err := plain.PutBlob(map[string]any{"title": "written in the clear"})
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.Flush(); err != nil {
		t.Fatal(err)
	}

	kr := &vault.Keyring{Keys: map[string]*vault.KEK{}}
	if err := kr.Add("k1", time.Now()); err != nil {
		t.Fatal(err)
	}
	sealed := plain.WithKeys(kr)
	if _, err := sealed.PutBlob(map[string]any{"title": "sealed"}); err != nil {
		t.Fatal(err)
	}
	if err := sealed.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := kr.Add("k2", time.Now()); err != nil {
		t.Fatal(err)
	}

	done, err := sealed.Rewrap()
	if err != nil {
		t.Fatal(err)
	}
	if done.Plain == 0 {
		t.Error("the plaintext object was not reported")
	}
	// And it is still readable, which is the thing that would break.
	var body map[string]any
	if err := sealed.GetBlob(before, &body); err != nil {
		t.Fatalf("the plaintext object stopped reading: %v", err)
	}
}

// A store with no keyring has nothing to rewrap, and says so rather than
// reporting a successful pass over nothing.
func TestRewrapOnAPlainStoreIsRefused(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rewrap(); err == nil {
		t.Fatal("an unencrypted store reported a successful rewrap")
	}
}

// A key that sealed something and is no longer loaded stops the pass with the
// object named, before anything is written.
func TestRewrapNamesTheObjectItCannotUnwrap(t *testing.T) {
	s, kr, dir := sealedStore(t)
	if err := kr.Add("k2", time.Now()); err != nil {
		t.Fatal(err)
	}
	// The operator retired k1 too early.
	delete(kr.Keys, "k1")
	kr.Active = "k2"

	_, err := s.Rewrap()
	if err == nil {
		t.Fatal("a missing key produced a successful rewrap")
	}
	if !strings.Contains(err.Error(), "k1") {
		t.Errorf("the error does not name the key: %v", err)
	}
	// And nothing was half-written.
	if got := kekOf(t, dir); got["k2"] != 0 {
		t.Errorf("%d object(s) were moved before the failure", got["k2"])
	}
}

// The check this whole system is built around did not work on an encrypted
// store.
//
// Verify read each file, looked for the null byte separating the kind from the
// payload, and hashed what followed. A sealed object is JSON with no null
// byte, so the first one it reached was reported malformed and the walk
// stopped — on every store that had turned encryption on, which is the
// configuration where an operator most wants to ask the question. Found by
// running it:
//
//	object 4da978b9d015… is malformed
func TestVerifyWorksOnAnEncryptedStore(t *testing.T) {
	s, _, _ := sealedStore(t)

	n, err := s.Verify()
	if err != nil {
		t.Fatalf("verify failed on an encrypted store: %v", err)
	}
	if n == 0 {
		t.Fatal("verify checked nothing")
	}
}

// And it checks strictly more than the plaintext path: that the object
// decrypts, that its additional authenticated data is still its own object id,
// and then that the plaintext hashes to that id.
//
// A ciphertext moved to another object's filename passes every check the
// plaintext path could make — the bytes are intact, they are simply the wrong
// bytes — and fails here.
func TestVerifyCatchesASealedObjectMovedToAnotherName(t *testing.T) {
	s, _, dir := sealedStore(t)

	files := sealedFiles(t, dir)
	if len(files) < 2 {
		t.Fatalf("need two objects, have %d", len(files))
	}
	var paths []string
	for p := range files {
		paths = append(paths, p)
	}
	first, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	// One object's ciphertext under the other's name. Both are intact files.
	if err := os.Chmod(paths[1], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths[1], first, 0o400); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Verify(); err == nil {
		t.Fatal("a ciphertext under another object's name verified clean")
	}
}

// Without the key there is no honest answer, so it says so rather than
// reporting the store intact or malformed.
func TestVerifyRefusesWhenTheKeyIsMissing(t *testing.T) {
	_, _, dir := sealedStore(t)

	plain, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = plain.Verify()
	if err == nil {
		t.Fatal("an encrypted store verified clean with no key loaded")
	}
	if !strings.Contains(err.Error(), "no key is loaded") {
		t.Errorf("the error does not say a key is missing: %v", err)
	}
}
