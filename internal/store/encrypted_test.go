package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/vault"
)

func encrypted(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := vault.NewKeyring("k1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return s.WithKeys(kr)
}

// The threat this exists for: somebody obtains the files. A stolen laptop, a
// backup on an open bucket, a disposed disk.
func TestContentIsNotReadableOnDisk(t *testing.T) {
	dir := t.TempDir()
	s := encrypted(t, dir)

	oid, err := s.PutBlob(map[string]any{
		"title": "Unannounced acquisition", "body": "Closing next Tuesday."})
	if err != nil {
		t.Fatal(err)
	}

	// Read every file the way somebody with the disk would.
	var all strings.Builder
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(path)
		all.Write(b)
		return nil
	})
	for _, secret := range []string{"Unannounced", "acquisition", "Tuesday"} {
		if strings.Contains(all.String(), secret) {
			t.Errorf("%q is readable on disk", secret)
		}
	}

	// And it still reads back through the program.
	var back map[string]any
	if err := s.GetBlob(oid, &back); err != nil {
		t.Fatal(err)
	}
	if back["title"] != "Unannounced acquisition" {
		t.Errorf("the content did not survive: %v", back)
	}
}

// The name is load-bearing: deduplication key, ETag, what a content type binds
// to, what an approval signs. Encrypting must not change it.
func TestTheObjectIDIsUnchangedByEncryption(t *testing.T) {
	content := map[string]any{"title": "Home", "body": "Welcome."}

	plain, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	plainID, err := plain.PutBlob(content)
	if err != nil {
		t.Fatal(err)
	}

	sealedID, err := encrypted(t, t.TempDir()).PutBlob(content)
	if err != nil {
		t.Fatal(err)
	}

	if plainID != sealedID {
		t.Errorf("encryption changed the address: %s vs %s. Every ETag, "+
			"content-type binding and approval signature is keyed on this.",
			plainID, sealedID)
	}
}

// Turning encryption on does not rewrite what is already there, so a reader has
// to handle both forms without being told which to expect.
func TestAHalfConvertedStoreIsFullyReadable(t *testing.T) {
	dir := t.TempDir()
	plain, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	before, err := plain.PutBlob(map[string]any{"title": "Written in the clear"})
	if err != nil {
		t.Fatal(err)
	}

	kr, _ := vault.NewKeyring("k1", time.Now())
	s := plain.WithKeys(kr)
	after, err := s.PutBlob(map[string]any{"title": "Written sealed"})
	if err != nil {
		t.Fatal(err)
	}

	for name, oid := range map[string]string{"plaintext": before, "sealed": after} {
		var back map[string]any
		if err := s.GetBlob(oid, &back); err != nil {
			t.Errorf("the %s object does not read: %v", name, err)
		}
	}
}

// Without the key the content is intact and unreadable, which is the point —
// and the message has to say that rather than looking like corruption.
func TestWithoutTheKeyTheRefusalIsClear(t *testing.T) {
	dir := t.TempDir()
	oid, err := encrypted(t, dir).PutBlob(map[string]any{"title": "Secret"})
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	err = reopened.GetBlob(oid, &back)
	if err == nil {
		t.Fatal("an encrypted object read without a key")
	}
	if !strings.Contains(err.Error(), "key") {
		t.Errorf("the error reads like corruption rather than a missing key: %v",
			err)
	}
}

// The wrong key must fail authentication, not return something.
func TestTheWrongKeyDoesNotSilentlyProduceGarbage(t *testing.T) {
	dir := t.TempDir()
	oid, err := encrypted(t, dir).PutBlob(map[string]any{"title": "Secret"})
	if err != nil {
		t.Fatal(err)
	}

	other, _ := vault.NewKeyring("k1", time.Now()) // same id, different material
	s, _ := Open(dir)
	var back map[string]any
	if err := s.WithKeys(other).GetBlob(oid, &back); err == nil {
		t.Fatal("a different key decrypted the object")
	}
}

// Swapping two sealed files on disk must not swap two pages. The ciphertext is
// bound to the address it is filed under.
func TestSwappingTwoSealedFilesIsDetected(t *testing.T) {
	dir := t.TempDir()
	kr, _ := vault.NewKeyring("k1", time.Now())
	s, _ := Open(dir)
	s = s.WithKeys(kr)

	terms, err := s.PutBlob(map[string]any{"title": "Terms", "body": "Arbitration."})
	if err != nil {
		t.Fatal(err)
	}
	blog, err := s.PutBlob(map[string]any{"title": "Blog", "body": "Cats."})
	if err != nil {
		t.Fatal(err)
	}

	termsPath, _ := s.pathFor(terms)
	blogPath, _ := s.pathFor(blog)
	a, _ := os.ReadFile(termsPath)
	b, _ := os.ReadFile(blogPath)
	// Objects are written 0400, so the swap needs a chmod — which somebody with
	// the disk has.
	_ = os.Chmod(termsPath, 0o600)
	_ = os.Chmod(blogPath, 0o600)
	if err := os.WriteFile(termsPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blogPath, a, 0o600); err != nil {
		t.Fatal(err)
	}

	var back map[string]any
	if err := s.GetBlob(terms, &back); err == nil {
		t.Errorf("a swapped object opened as %v; the terms page would now serve "+
			"the blog's content with no error anywhere", back)
	}
}
