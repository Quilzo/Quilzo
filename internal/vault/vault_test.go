package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

func ring(t *testing.T) *Keyring {
	t.Helper()
	kr, err := NewKeyring("k1", now)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func oid(payload []byte) []byte {
	sum := sha256.Sum256(payload)
	return []byte(hex.EncodeToString(sum[:]))
}

func TestSealAndOpenRoundTrip(t *testing.T) {
	kr := ring(t)
	payload := []byte(`{"title":"Home","body":"Not yet published."}`)
	id := oid(payload)

	sealed, err := kr.Seal(payload, id)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed.Body, []byte("Home")) {
		t.Fatal("the plaintext is visible in the ciphertext")
	}
	back, err := kr.Open(sealed, id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, payload) {
		t.Errorf("got %q", back)
	}
}

// The failure mode AES-GCM cannot survive. Here it is impossible rather than
// avoided: each object gets a data key used for exactly one encryption, because
// the store is content-addressed and write-once.
func TestEveryObjectGetsItsOwnKeyAndNonce(t *testing.T) {
	kr := ring(t)
	seenNonce := map[string]bool{}
	seenDEK := map[string]bool{}

	// The same payload sealed repeatedly, which is the worst case: identical
	// input must not produce identical output.
	payload := []byte("the same bytes every time")
	id := oid(payload)
	for i := range 200 {
		s, err := kr.Seal(payload, id)
		if err != nil {
			t.Fatal(err)
		}
		n := string(s.Nonce)
		if seenNonce[n] {
			t.Fatalf("nonce repeated on iteration %d; with GCM this leaks the "+
				"XOR of two plaintexts and destroys authentication", i)
		}
		seenNonce[n] = true

		if seenDEK[string(s.DEK)] {
			t.Fatalf("a wrapped data key repeated on iteration %d", i)
		}
		seenDEK[string(s.DEK)] = true
	}
}

// Sealing the same bytes twice must produce different ciphertext, or an
// observer with the encrypted directory learns which objects are identical.
func TestIdenticalContentDoesNotProduceIdenticalCiphertext(t *testing.T) {
	kr := ring(t)
	payload := []byte("hello")
	id := oid(payload)

	a, _ := kr.Seal(payload, id)
	b, _ := kr.Seal(payload, id)
	if bytes.Equal(a.Body, b.Body) {
		t.Error("the same plaintext sealed to the same ciphertext")
	}
}

// -- what the AAD binding buys -----------------------------------------------

// An attacker with write access to the data directory swaps two sealed files.
// Without binding the ciphertext to its address, both would decrypt cleanly and
// the content would be intact and entirely misattributed.
func TestASealedObjectCannotBeMovedToAnotherAddress(t *testing.T) {
	kr := ring(t)
	terms := []byte(`{"title":"Terms","body":"You agree to arbitration."}`)
	blog := []byte(`{"title":"Blog","body":"A post about cats."}`)

	sealedTerms, _ := kr.Seal(terms, oid(terms))

	// Try to open the terms object as though it were filed under the blog's id.
	if _, err := kr.Open(sealedTerms, oid(blog)); err == nil {
		t.Fatal("a sealed object opened at an address it was not sealed for; " +
			"swapping two files would silently swap two pages")
	}
}

func TestTamperingWithTheCiphertextIsDetected(t *testing.T) {
	kr := ring(t)
	payload := []byte("original content")
	id := oid(payload)
	s, _ := kr.Seal(payload, id)

	for _, mutate := range []func(*Sealed){
		func(s *Sealed) { s.Body[0] ^= 1 },
		func(s *Sealed) { s.Nonce[0] ^= 1 },
		func(s *Sealed) { s.DEK[0] ^= 1 },
		func(s *Sealed) { s.DEKNonce[0] ^= 1 },
	} {
		altered := *s
		altered.Body = append([]byte{}, s.Body...)
		altered.Nonce = append([]byte{}, s.Nonce...)
		altered.DEK = append([]byte{}, s.DEK...)
		altered.DEKNonce = append([]byte{}, s.DEKNonce...)
		mutate(&altered)

		out, err := kr.Open(&altered, id)
		if err == nil {
			t.Error("an altered object opened")
		}
		if out != nil {
			t.Error("a failed decryption returned bytes; a plaintext that failed " +
				"authentication is attacker-chosen and using it is how this " +
				"becomes an oracle")
		}
	}
}

// -- rotation ----------------------------------------------------------------

// Rotating means re-wrapping thirty-two bytes per object, not re-encrypting
// every page. That is the entire argument for envelope encryption, and it is
// the only property that decides whether rotation actually happens.
func TestRotationRewrapsWithoutTouchingTheContent(t *testing.T) {
	kr := ring(t)
	payload := []byte("content written under the first key")
	id := oid(payload)

	old, err := kr.Seal(payload, id)
	if err != nil {
		t.Fatal(err)
	}
	originalBody := append([]byte{}, old.Body...)
	originalNonce := append([]byte{}, old.Nonce...)

	if err := kr.Add("k2", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	rewrapped, err := kr.Rewrap(old, id)
	if err != nil {
		t.Fatal(err)
	}

	if rewrapped.KEK != "k2" {
		t.Errorf("still wrapped with %q", rewrapped.KEK)
	}
	if !bytes.Equal(rewrapped.Body, originalBody) {
		t.Error("the content was re-encrypted; rotation should only touch the " +
			"data key, or rotating a large site is a batch job nobody runs")
	}
	if !bytes.Equal(rewrapped.Nonce, originalNonce) {
		t.Error("the content nonce changed, which means the body was re-sealed")
	}
	back, err := kr.Open(rewrapped, id)
	if err != nil || !bytes.Equal(back, payload) {
		t.Errorf("the rewrapped object does not open: %v", err)
	}
}

// A retired key still has to unwrap what it wrapped. Deleting it would make
// rotation destructive, which is how people end up not rotating.
func TestARetiredKeyStillOpensWhatItSealed(t *testing.T) {
	kr := ring(t)
	payload := []byte("sealed under k1")
	id := oid(payload)
	sealed, _ := kr.Seal(payload, id)

	if err := kr.Add("k2", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !kr.Keys["k1"].Retired {
		t.Error("the previous key was not marked retired")
	}
	if back, err := kr.Open(sealed, id); err != nil || !bytes.Equal(back, payload) {
		t.Errorf("an object sealed under the retired key no longer opens: %v", err)
	}

	// And new objects use the new key.
	fresh, _ := kr.Seal([]byte("new"), oid([]byte("new")))
	if fresh.KEK != "k2" {
		t.Errorf("a new object was sealed with %q", fresh.KEK)
	}
}

func TestAMissingKeyIsAClearRefusalNotACrash(t *testing.T) {
	kr := ring(t)
	payload := []byte("x")
	id := oid(payload)
	sealed, _ := kr.Seal(payload, id)

	delete(kr.Keys, "k1")
	_, err := kr.Open(sealed, id)
	if err == nil {
		t.Fatal("an object opened with no key")
	}
	if !strings.Contains(err.Error(), "k1") {
		t.Errorf("the error does not name the missing key: %v", err)
	}
}

// -- refusals ----------------------------------------------------------------

// Silently padding or hashing a short key to length would hide that the
// operator supplied the wrong thing — a truncated paste, the wrong file.
func TestAKeyOfTheWrongLengthIsRefused(t *testing.T) {
	for _, bad := range []string{
		"", "c2hvcnQ=", EncodeKey(make([]byte, 16)), EncodeKey(make([]byte, 64)),
	} {
		if _, err := DecodeKey(bad); err == nil {
			t.Errorf("a key of the wrong size was accepted: %q", bad)
		}
	}
	good := EncodeKey(make([]byte, KeyBytes))
	if _, err := DecodeKey(good); err != nil {
		t.Errorf("a correct key was refused: %v", err)
	}
}

// Guessing at the layout of a ciphertext is how a decryption routine becomes an
// oracle.
func TestAnUnknownFormatVersionIsRefused(t *testing.T) {
	kr := ring(t)
	payload := []byte("x")
	id := oid(payload)
	sealed, _ := kr.Seal(payload, id)
	sealed.Version = 99

	if _, err := kr.Open(sealed, id); err == nil {
		t.Fatal("an object in an unknown format was decrypted anyway")
	}
}

// A store can hold both while encryption is being turned on, and a reader has
// to handle a half-converted directory without being told which half.
func TestSealedAndPlainObjectsAreDistinguishable(t *testing.T) {
	kr := ring(t)
	sealed, _ := kr.Seal([]byte("secret"), oid([]byte("secret")))
	body, err := Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !IsSealed(body) {
		t.Error("a sealed object was not recognised")
	}
	for _, plain := range [][]byte{
		[]byte(`blob` + "\x00" + `{"title":"Home"}`),
		[]byte(`{"title":"Home"}`),
		[]byte(""),
		[]byte("  "),
	} {
		if IsSealed(plain) {
			t.Errorf("plain bytes were taken for a sealed object: %q", plain)
		}
	}
}

func TestSealingWithNoKeyMaterialIsRefused(t *testing.T) {
	kr := &Keyring{Active: "k1", Keys: map[string]*KEK{"k1": {ID: "k1"}}}
	if _, err := kr.Seal([]byte("x"), []byte("id")); err == nil {
		t.Fatal("sealed with an empty key")
	}
}

// -- serialisation -----------------------------------------------------------

// Somebody holding an encrypted backup and no working copy of this program
// should be able to see what they have.
func TestASealedObjectSaysWhatItIsWithoutRevealingContent(t *testing.T) {
	kr := ring(t)
	payload := []byte(`{"title":"Confidential"}`)
	id := oid(payload)
	sealed, _ := kr.Seal(payload, id)

	body, err := Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, `"kek":"k1"`) {
		t.Error("the file does not say which key wrapped it")
	}
	if strings.Contains(text, "Confidential") {
		t.Fatal("the plaintext is in the stored file")
	}

	back, err := Unmarshal(body)
	if err != nil {
		t.Fatal(err)
	}
	out, err := kr.Open(back, id)
	if err != nil || !bytes.Equal(out, payload) {
		t.Errorf("a round trip through storage lost the content: %v", err)
	}
}
