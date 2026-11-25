// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package approval

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/webauthn"
)

// The authentication evidence behind each signature, kept where it can be
// checked again without the server that took it.
//
// A record holds the digest of its approvers' evidence and not the evidence,
// as it holds the digest of a raw file: the register is for ever, and what a
// passkey sent names the device it came from. The evidence is kept beside
// the store, one file to each digest, written once and never changed, and it
// holds what anybody needs to check the signature offline: the assertion as
// the browser sent it, the public key it is checked against, the site and
// origin it was made for, and the challenge, whose bytes hold the hash of
// what was approved. A person is in it by pseudonym only.

// Evidence is one person's authentication over one hash.
type Evidence struct {
	Method  register.Method `json:"method"`
	Purpose Purpose         `json:"purpose"`
	Subject register.ID     `json:"subject"`
	// For is what they approved: a surface, a batch's root, or for a
	// review the surface of the approval reviewed.
	For register.Digest `json:"for"`
	At  register.Time   `json:"at"`
	// Passkey is a passkey's assertion, and Console an administrator at
	// the store's own console; one of the two, as Method says.
	Passkey *PasskeyProof `json:"passkey,omitempty"`
	Console *ConsoleProof `json:"console,omitempty"`
}

// PasskeyProof is a passkey's assertion, with what it is checked against.
type PasskeyProof struct {
	RelyingParty string             `json:"rp_id"`
	Origin       string             `json:"origin"`
	Credential   []byte             `json:"credential"`
	PublicKey    []byte             `json:"public_key"`
	Algorithm    int                `json:"algorithm"`
	Challenge    string             `json:"challenge"`
	Assertion    webauthn.Assertion `json:"assertion"`
}

// ConsoleProof is an administrator at the store's own console, who typed
// back the hash of what they approved. Weaker than a passkey, because
// nothing but the machine vouches for the person at it, and said so
// wherever an approval made this way is shown.
type ConsoleProof struct {
	Typed register.Digest `json:"typed"`
	// Credential is the name of the token the command line proved them
	// by, empty when the store has no access control and the person at
	// the console is its owner.
	Credential string `json:"credential,omitempty"`
}

// Digest is the evidence's hash, which the record's signer holds.
func (e Evidence) Digest() register.Digest {
	raw, _ := json.Marshal(e)
	sum := sha256.Sum256(raw)
	return register.Digest("sha256:" + hex.EncodeToString(sum[:]))
}

// Check checks the evidence by itself, as anybody holding it can: that it
// is what it says it is for, and that its signature holds.
//
// The passkey's signature counter is not checked again: it was checked
// when the signature was given, against the counter as it stood then, and
// it has moved on since.
func (e Evidence) Check() error {
	switch e.Method {
	case "passkey":
		p := e.Passkey
		if p == nil || e.Console != nil {
			return fmt.Errorf("the evidence says a passkey and holds no assertion")
		}
		purpose, of, err := ChallengeFor(p.Challenge)
		if err != nil {
			return err
		}
		if purpose != e.Purpose {
			return fmt.Errorf("the passkey signed a challenge to %s, and this evidence is for one to %s", purpose, e.Purpose)
		}
		if of != e.For {
			return fmt.Errorf("the passkey signed a challenge holding %s, which is another surface than %s", of, e.For)
		}
		party := webauthn.Party{ID: p.RelyingParty, Origin: p.Origin}
		cred := webauthn.Credential{ID: p.Credential, PublicKey: p.PublicKey, Algorithm: p.Algorithm}
		if _, err := party.Verify(cred, p.Challenge, p.Assertion); err != nil {
			return fmt.Errorf("the passkey's assertion does not hold: %w", err)
		}
		return nil
	case "console":
		c := e.Console
		if c == nil || e.Passkey != nil {
			return fmt.Errorf("the evidence says the console and holds nothing typed there")
		}
		if c.Typed != e.For {
			return fmt.Errorf("the hash typed at the console is not the hash of what was approved")
		}
		return nil
	}
	return fmt.Errorf("%q is not a way an approval is given", clip(string(e.Method)))
}

// evidenceDir is where a store keeps its approvals' evidence.
func evidenceDir(root string) string { return filepath.Join(root, "approvals", "evidence") }

func evidencePath(root string, d register.Digest) (string, error) {
	if !d.Valid() {
		return "", fmt.Errorf("%q is not the digest of any evidence", clip(string(d)))
	}
	return filepath.Join(evidenceDir(root), string(d)[len("sha256:"):]+".json"), nil
}

// keep writes evidence beside the store, under its digest, once. Writing
// the same evidence again changes nothing.
func keep(root string, e Evidence) (register.Digest, error) {
	d := e.Digest()
	path, err := evidencePath(root, d)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); err == nil {
		return d, nil
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	return d, atomicfile.Write(path, raw, 0o600)
}

// ErrNoEvidence is a digest no evidence beside the store has.
var ErrNoEvidence = errors.New("no evidence is kept under that digest")

// LoadEvidence reads the evidence kept under a digest, and refuses a file
// that is not what its name says.
func LoadEvidence(root string, d register.Digest) (Evidence, error) {
	path, err := evidencePath(root, d)
	if err != nil {
		return Evidence{}, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Evidence{}, fmt.Errorf("%w: %s", ErrNoEvidence, d)
	}
	if err != nil {
		return Evidence{}, err
	}
	var e Evidence
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return Evidence{}, fmt.Errorf("the evidence %s does not read as evidence: %w", d, err)
	}
	if e.Digest() != d {
		return Evidence{}, fmt.Errorf("the evidence kept as %s is not what that digest names", d)
	}
	return e, nil
}
