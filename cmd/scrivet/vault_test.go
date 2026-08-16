package main

import (
	"strings"
	"testing"
	"time"

	"github.com/lithoform/lithoform/internal/vault"
)

// Base64 ends in `=` padding, and the first version split the environment
// variable on `=` to find `id=key` pairs — so it chopped a valid key at its own
// padding and read the front half as an id. Every unit test passed; a five-line
// shell demo found it immediately.
func TestABareBase64KeyIsNotMistakenForAnIDPair(t *testing.T) {
	kr, err := vault.NewKeyring("k1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	encoded := vault.EncodeKey(kr.Keys["k1"].Key)
	if !strings.HasSuffix(encoded, "=") {
		// Most 32-byte keys encode with padding; regenerate until one does, so
		// the test is actually exercising the case it names.
		for range 20 {
			kr, _ = vault.NewKeyring("k1", time.Now())
			encoded = vault.EncodeKey(kr.Keys["k1"].Key)
			if strings.HasSuffix(encoded, "=") {
				break
			}
		}
	}

	fresh := &vault.Keyring{Active: "k1", Keys: map[string]*vault.KEK{
		"k1": {ID: "k1"},
	}}
	if err := applyMaterial(fresh, encoded); err != nil {
		t.Fatalf("a bare key was rejected: %v", err)
	}
	if len(fresh.Keys["k1"].Key) != vault.KeyBytes {
		t.Errorf("the key was not loaded: %d bytes", len(fresh.Keys["k1"].Key))
	}
}

// Two keys during a rotation, given as id=key pairs, each with its own padding.
func TestMultipleKeysAreLoadedByID(t *testing.T) {
	a, _ := vault.NewKeyring("k1", time.Now())
	b, _ := vault.NewKeyring("k2", time.Now())
	material := "k1=" + vault.EncodeKey(a.Keys["k1"].Key) + "," +
		"k2=" + vault.EncodeKey(b.Keys["k2"].Key)

	fresh := &vault.Keyring{Active: "k2", Keys: map[string]*vault.KEK{
		"k1": {ID: "k1", Retired: true}, "k2": {ID: "k2"},
	}}
	if err := applyMaterial(fresh, material); err != nil {
		t.Fatalf("a rotation pair was rejected: %v", err)
	}
	for _, id := range []string{"k1", "k2"} {
		if len(fresh.Keys[id].Key) != vault.KeyBytes {
			t.Errorf("%s was not loaded", id)
		}
	}
}

// A key for an id the keyring does not list is a mismatch the operator has to
// see, not something to ignore.
func TestAKeyForAnUnknownIDIsRefused(t *testing.T) {
	kr, _ := vault.NewKeyring("k1", time.Now())
	fresh := &vault.Keyring{Active: "k1", Keys: map[string]*vault.KEK{
		"k1": {ID: "k1"},
	}}
	material := "k9=" + vault.EncodeKey(kr.Keys["k1"].Key)
	if err := applyMaterial(fresh, material); err == nil {
		t.Fatal("a key for an unlisted id was accepted")
	}
}

// Supplying only a retired key leaves the store unable to write, and that has
// to be said rather than discovered at the first save.
func TestMissingMaterialForTheActiveKeyIsRefused(t *testing.T) {
	old, _ := vault.NewKeyring("k1", time.Now())
	fresh := &vault.Keyring{Active: "k2", Keys: map[string]*vault.KEK{
		"k1": {ID: "k1", Retired: true}, "k2": {ID: "k2"},
	}}
	err := applyMaterial(fresh, "k1="+vault.EncodeKey(old.Keys["k1"].Key))
	if err == nil {
		t.Fatal("a keyring with no active key material was accepted")
	}
	if !strings.Contains(err.Error(), "k2") {
		t.Errorf("the error does not name the key that is missing: %v", err)
	}
}

// After a rotation a bare key is ambiguous, and the first version assumed it
// belonged to the active entry — silently attaching the old key's material to
// the new key's id. Every read then failed with a message about a key that had
// in fact been supplied, which looks like a corrupt store rather than a
// mistyped environment variable.
func TestABareKeyIsRefusedOnceThereIsMoreThanOne(t *testing.T) {
	old, _ := vault.NewKeyring("k1", time.Now())
	rotated := &vault.Keyring{Active: "k2", Keys: map[string]*vault.KEK{
		"k1": {ID: "k1", Retired: true}, "k2": {ID: "k2"},
	}}

	err := applyMaterial(rotated, vault.EncodeKey(old.Keys["k1"].Key))
	if err == nil {
		t.Fatal("a bare key was silently assigned to the active entry after " +
			"a rotation")
	}
	for _, want := range []string{"ambiguous", "k1", "k2"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error omits %q: %v", want, err)
		}
	}

	// Named, it works.
	if err := applyMaterial(rotated,
		"k1="+vault.EncodeKey(old.Keys["k1"].Key)+","+
			"k2="+vault.EncodeKey(mustKey(t))); err != nil {
		t.Fatalf("named keys were rejected: %v", err)
	}
}

func mustKey(t *testing.T) []byte {
	t.Helper()
	kr, err := vault.NewKeyring("x", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return kr.Keys["x"].Key
}
