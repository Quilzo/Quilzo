// Package vault encrypts objects at rest.
//
// # What this defends against, and what it does not
//
// One thing: somebody who obtains the files. A stolen laptop, a backup on a
// misconfigured bucket, a disposed disk, a container image with the data
// directory baked in. That is a real and common way content leaks, and it is
// worth a real defence.
//
// It does not defend against somebody who can run the program, because the
// program has to be able to read its own content — it renders templates,
// validates types, checks accessibility and generates sitemaps. End-to-end
// encryption is the wrong control here: it would mean the server cannot read
// content whose entire purpose is to be read out loud, and every feature this
// tool has would stop working. Saying so plainly is better than shipping
// something that sounds stronger and protects less.
//
// # Why nonce reuse cannot happen here
//
// AES-GCM has one catastrophic failure mode: using a nonce twice with the same
// key destroys authentication and leaks the XOR of the two plaintexts. Every
// serious implementation is organised around not doing that, usually with a
// counter that somebody has to remember not to reset.
//
// There is nothing to remember here. Each object gets its own data key, used
// for exactly one encryption, because the store is content-addressed and
// write-once: an object with the same bytes has the same name and is never
// written twice, and an object with different bytes is a different object. A
// key that encrypts one thing once cannot repeat a nonce. This is not a rule
// being followed, it is a shape that has no room for the mistake.
//
// It also makes key rotation nearly free, which is the usual argument for
// envelope encryption: rotating means re-wrapping small data keys, never
// re-encrypting content.
//
// # Why the object id is still the hash of the plaintext
//
// Encrypting the stored bytes would change the name of every object, and the
// name is load-bearing — it is the deduplication key, the ETag, the thing a
// content type binds to, the thing an approval signs. So the id stays the hash
// of the plaintext and the file holds the sealed form.
//
// The pleasant consequence is two independent integrity checks. GCM's tag says
// the ciphertext was not altered; re-hashing the plaintext says it is the
// object it claims to be. Either failing stops the read.
//
// # Where the key encryption key comes from
//
// Never from the code, and by default not from the same directory as the data —
// a key stored beside the thing it protects protects nothing against the threat
// this exists for. It comes from a file, an environment variable, or the output
// of a command, and the command is the interesting one: it makes an HSM, a
// cloud KMS, a password manager or a Yubikey work without this package knowing
// any of them exist.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// KeyBytes is the size of every key here: 256 bits.
const KeyBytes = 32

// NonceBytes is what GCM wants, per NIST SP 800-38D. Twelve bytes is the
// size for which GCM's security proof holds without an extra derivation step.
const NonceBytes = 12

// Sealed is one encrypted object.
//
// Stored as JSON rather than a packed binary format, because somebody holding
// an encrypted backup and no working copy of this program should be able to see
// what they have — which key wrapped it, when, and that it is AES-256-GCM —
// without reverse-engineering a byte layout.
type Sealed struct {
	// Version guards the format. A reader that does not recognise it must
	// refuse rather than guess at the layout of a ciphertext.
	Version int `json:"v"`
	// KEK names the key encryption key that wrapped the data key, so rotation
	// can leave old objects readable without re-encrypting them.
	KEK string `json:"kek"`
	// DEK is the data key, wrapped by the KEK. It is never stored in the clear
	// and never reused.
	DEK []byte `json:"dek"`
	// DEKNonce is the nonce used to wrap the data key.
	DEKNonce []byte `json:"dn"`
	// Nonce is the nonce used on the content itself.
	Nonce []byte `json:"n"`
	// Body is the ciphertext with GCM's tag appended.
	Body []byte `json:"b"`
}

// KEK is a key encryption key.
type KEK struct {
	ID string `json:"id"`
	// Key is the raw key material. It is only ever populated in memory; the
	// keyring on disk holds ids and metadata, never this.
	Key       []byte `json:"-"`
	CreatedAt int64  `json:"created_at"`
	// Retired keys can still unwrap, but nothing new is wrapped with them.
	Retired bool `json:"retired,omitempty"`
}

// Keyring is the set of key encryption keys in use.
type Keyring struct {
	// Active is the id of the key new objects are wrapped with.
	Active string          `json:"active"`
	Keys   map[string]*KEK `json:"keys"`
}

// NewKeyring creates a keyring with one key.
func NewKeyring(id string, now time.Time) (*Keyring, error) {
	k, err := newKey()
	if err != nil {
		return nil, err
	}
	return &Keyring{
		Active: id,
		Keys: map[string]*KEK{id: {
			ID: id, Key: k, CreatedAt: now.Unix(),
		}},
	}, nil
}

func newKey() ([]byte, error) {
	k := make([]byte, KeyBytes)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("no randomness available: %w", err)
	}
	return k, nil
}

// Add introduces a new key encryption key and makes it active.
//
// The old key is retired rather than deleted: it still has to unwrap everything
// written before now. Deleting it would make rotation a destructive operation,
// which is how people end up not rotating.
func (kr *Keyring) Add(id string, now time.Time) error {
	if id == "" {
		return fmt.Errorf("a key needs an id")
	}
	if _, exists := kr.Keys[id]; exists {
		return fmt.Errorf("there is already a key called %q", id)
	}
	k, err := newKey()
	if err != nil {
		return err
	}
	if kr.Keys == nil {
		kr.Keys = map[string]*KEK{}
	}
	if old, ok := kr.Keys[kr.Active]; ok {
		old.Retired = true
	}
	kr.Keys[id] = &KEK{ID: id, Key: k, CreatedAt: now.Unix()}
	kr.Active = id
	return nil
}

// IDs lists the keys, active first.
func (kr *Keyring) IDs() []string {
	out := make([]string, 0, len(kr.Keys))
	for id := range kr.Keys {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i] == kr.Active {
			return true
		}
		if out[j] == kr.Active {
			return false
		}
		return out[i] < out[j]
	})
	return out
}

// Seal encrypts a payload.
//
// aad is authenticated but not encrypted, and here it is the object's id. That
// binds the ciphertext to its address: a sealed object copied over a different
// one fails to open, because the id it is now filed under is not the id that was
// authenticated. Without this, an attacker with write access to the data
// directory could swap two objects and both would decrypt cleanly — the
// content would be intact and the meaning entirely wrong.
func (kr *Keyring) Seal(payload, aad []byte) (*Sealed, error) {
	kek, ok := kr.Keys[kr.Active]
	if !ok || len(kek.Key) != KeyBytes {
		return nil, fmt.Errorf("no active key is loaded; the keyring holds ids " +
			"but the key material has to be supplied at startup")
	}

	// A fresh data key for this object, used once. This is what makes nonce
	// reuse structurally impossible rather than a rule somebody follows.
	dek, err := newKey()
	if err != nil {
		return nil, err
	}
	defer zero(dek)

	body, nonce, err := encrypt(dek, payload, aad)
	if err != nil {
		return nil, err
	}
	// The wrapped key is bound to the same address, so a data key cannot be
	// lifted from one object and attached to another.
	wrapped, dekNonce, err := encrypt(kek.Key, dek, aad)
	if err != nil {
		return nil, err
	}

	return &Sealed{
		Version: 1, KEK: kek.ID,
		DEK: wrapped, DEKNonce: dekNonce,
		Nonce: nonce, Body: body,
	}, nil
}

// Open decrypts a sealed object.
func (kr *Keyring) Open(s *Sealed, aad []byte) ([]byte, error) {
	if s.Version != 1 {
		return nil, fmt.Errorf("this object is sealed in format version %d, "+
			"which this build does not know how to read. Guessing at the layout "+
			"of a ciphertext is how a decryption routine becomes an oracle",
			s.Version)
	}
	kek, ok := kr.Keys[s.KEK]
	if !ok {
		return nil, fmt.Errorf("this object was sealed with key %q, which is not "+
			"in the keyring. A retired key still has to be present to read what "+
			"it wrapped", s.KEK)
	}
	if len(kek.Key) != KeyBytes {
		return nil, fmt.Errorf("key %q is in the keyring but its material was "+
			"not supplied", s.KEK)
	}

	dek, err := decrypt(kek.Key, s.DEK, s.DEKNonce, aad)
	if err != nil {
		return nil, fmt.Errorf("the data key does not unwrap: %w", err)
	}
	defer zero(dek)

	payload, err := decrypt(dek, s.Body, s.Nonce, aad)
	if err != nil {
		return nil, fmt.Errorf("the object does not decrypt: %w", err)
	}
	return payload, nil
}

// Rewrap moves a sealed object to the active key without decrypting its body.
//
// This is the point of envelope encryption. Rotating a key means unwrapping and
// re-wrapping thirty-two bytes per object, not re-encrypting every page — so
// rotation is cheap enough that it actually happens, which is the only property
// that matters about a rotation scheme.
func (kr *Keyring) Rewrap(s *Sealed, aad []byte) (*Sealed, error) {
	old, ok := kr.Keys[s.KEK]
	if !ok || len(old.Key) != KeyBytes {
		return nil, fmt.Errorf("key %q is not available to unwrap with", s.KEK)
	}
	active, ok := kr.Keys[kr.Active]
	if !ok || len(active.Key) != KeyBytes {
		return nil, fmt.Errorf("no active key is loaded")
	}
	if s.KEK == kr.Active {
		return s, nil
	}

	dek, err := decrypt(old.Key, s.DEK, s.DEKNonce, aad)
	if err != nil {
		return nil, fmt.Errorf("the data key does not unwrap: %w", err)
	}
	defer zero(dek)

	wrapped, nonce, err := encrypt(active.Key, dek, aad)
	if err != nil {
		return nil, err
	}
	out := *s
	out.KEK = kr.Active
	out.DEK, out.DEKNonce = wrapped, nonce
	// The body and its nonce are untouched. The content was never decrypted.
	return &out, nil
}

// -- the primitives ----------------------------------------------------------

func encrypt(key, plaintext, aad []byte) (ciphertext, nonce []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, NonceBytes)
	// Random rather than counter-based. A counter needs durable state that
	// survives restarts and rollbacks, and getting that wrong is the usual
	// cause of the reuse this is avoiding. With a key used once, one random
	// nonce is all that is ever drawn from it.
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("no randomness available: %w", err)
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nonce, nil
}

func decrypt(key, ciphertext, nonce, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != NonceBytes {
		return nil, fmt.Errorf("the nonce is %d bytes, not %d", len(nonce), NonceBytes)
	}
	// Open returns an error on a bad tag and returns nothing. There is no
	// partial output and no continuing anyway: a plaintext that failed
	// authentication is attacker-chosen, and using it is how a decryption
	// routine becomes a padding oracle.
	out, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: the object was altered, " +
			"the key is wrong, or it was moved from a different address")
	}
	return out, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeyBytes {
		return nil, fmt.Errorf("a key must be %d bytes, got %d", KeyBytes, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// zero overwrites key material.
//
// Go gives no guarantee this survives the optimiser or that the bytes were not
// copied by the garbage collector first, so it is a reduction in exposure
// rather than a guarantee. It is done because the alternative — leaving keys in
// freed memory for the life of the process — is worse for no reason.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Equal compares in constant time, for anything that compares key material.
func Equal(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// -- serialisation -----------------------------------------------------------

// Marshal renders a sealed object for storage.
func Marshal(s *Sealed) ([]byte, error) { return json.Marshal(s) }

// Unmarshal reads one back.
func Unmarshal(b []byte) (*Sealed, error) {
	var s Sealed
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// IsSealed reports whether stored bytes are an encrypted object.
//
// Needed because a store can hold both: turning encryption on does not rewrite
// what is already there, and a reader has to handle a directory that is half
// converted without being told which half.
func IsSealed(b []byte) bool {
	trimmed := strings.TrimLeft(string(b), " \t\r\n")
	return strings.HasPrefix(trimmed, `{"v":`)
}

// EncodeKey renders key material for a key file.
func EncodeKey(k []byte) string { return base64.StdEncoding.EncodeToString(k) }

// DecodeKey reads key material, refusing anything that is not the right size.
func DecodeKey(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("the key is not valid base64: %w", err)
	}
	if len(raw) != KeyBytes {
		return nil, fmt.Errorf("a key must be %d bytes, this one is %d. A short "+
			"key is not a weak key here, it is a refusal — silently padding or "+
			"hashing it to length would hide that the operator supplied the "+
			"wrong thing", KeyBytes, len(raw))
	}
	return raw, nil
}
