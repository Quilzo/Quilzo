// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/register"
)

// DSSE envelopes, verified against keys a person pinned.
//
// A DSSE envelope is a payload and signatures over it (the Dead Simple
// Signing Envelope, as in-toto and Sigstore use it). A signature counts only
// when it checks against a PinnedKey in the register: a key that came with
// the file proves only that whoever made the file had a key, so an envelope
// no pinned key verifies is refused outright, and nothing in it is read.
//
// What a verified envelope holds is graded "signed": an in-toto statement's
// subjects become assets with their digests, and the statement says which
// sort of attestation it is; a predicate that is itself a bill of materials
// or a VEX document is read as one, under the signature. A payload of any
// other type is refused rather than read without understanding.
//
// Keyless signing, a certificate from a public log, needs that log to
// check against, and is not read here.

func init() { readers[FormatDSSE] = readDSSE }

type envelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	} `json:"signatures"`
}

// pae is DSSE's pre-authentication encoding: what is signed is the payload
// bound to its type, so a payload cannot be passed off as another type.
func pae(typ string, body []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "DSSEv1 %d %s %d ", len(typ), typ, len(body))
	b.Write(body)
	return b.Bytes()
}

func decode64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("it is not base64")
}

// publicKey is a pinned key's key, held to what the record says of it: its
// algorithm, and the fingerprint a person checked.
func publicKey(k register.PinnedKey) (any, error) {
	der, err := base64.StdEncoding.DecodeString(k.Public)
	if err != nil {
		return nil, fmt.Errorf("the pinned key %s is not base64", k.Name)
	}
	sum := sha256.Sum256(der)
	if register.Digest("sha256:"+hex.EncodeToString(sum[:])) != k.Fingerprint {
		return nil, fmt.Errorf("the pinned key %s does not have the fingerprint it was pinned with", k.Name)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("the pinned key %s: %v", k.Name, err)
	}
	switch p := pub.(type) {
	case ed25519.PublicKey:
		if k.Algorithm == "ed25519" {
			return p, nil
		}
	case *ecdsa.PublicKey:
		if k.Algorithm == "ecdsa-p256" && p.Curve == elliptic.P256() || k.Algorithm == "ecdsa-p384" && p.Curve == elliptic.P384() {
			return p, nil
		}
	}
	return nil, fmt.Errorf("the pinned key %s is not an %s key", k.Name, k.Algorithm)
}

// verify reports whether sig is a signature by pub over msg.
func verify(pub any, msg, sig []byte) bool {
	switch p := pub.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(p, msg, sig)
	case *ecdsa.PublicKey:
		if p.Curve == elliptic.P384() {
			h := sha512.Sum384(msg)
			return ecdsa.VerifyASN1(p, h[:], sig)
		}
		h := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(p, h[:], sig)
	}
	return false
}

func readDSSE(rd *reader) error {
	var env envelope
	if err := decodeJSON(rd.in.Body, &env); err != nil {
		return err
	}
	if env.PayloadType == "" || env.Payload == "" || len(env.Signatures) == 0 {
		return fmt.Errorf("%w: it is not a DSSE envelope: it needs a payloadType, a payload and a signature", ErrUnreadable)
	}
	payload, err := decode64(env.Payload)
	if err != nil {
		return fmt.Errorf("%w: the payload: %v", ErrUnreadable, err)
	}
	msg := pae(env.PayloadType, payload)
	var problems []string
	for _, k := range rd.in.Keys {
		pub, err := publicKey(k)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		for _, s := range env.Signatures {
			if s.KeyID != "" && k.KeyID != "" && s.KeyID != k.KeyID {
				continue
			}
			sig, err := decode64(s.Sig)
			if err != nil {
				continue
			}
			if verify(pub, msg, sig) {
				rd.signer = k.Name
				break
			}
		}
		if rd.signer != "" {
			break
		}
	}
	if rd.signer == "" {
		why := "none of the keys a person pinned signed it"
		if len(rd.in.Keys) == 0 {
			why = "no key has been pinned"
		}
		if len(problems) > 0 {
			why += " (" + label(strings.Join(problems, "; ")) + ")"
		}
		return fmt.Errorf("%w: %s, so nothing in it is read", ErrUnpinned, why)
	}
	if err := checkJSON(payload, false); err != nil {
		return fmt.Errorf("%w: the signed payload: %v", ErrUnreadable, err)
	}
	var doc any
	if err := decodeJSON(payload, &doc); err != nil {
		return err
	}
	switch env.PayloadType {
	case "application/vnd.in-toto+json":
		return rd.statement(obj(doc))
	case "application/vnd.cyclonedx+json":
		return rd.cyclonedx(obj(doc), "/payload")
	case "application/spdx+json":
		return rd.spdx(obj(doc), "/payload")
	case "application/openvex+json":
		return rd.openvex(obj(doc), "/payload")
	}
	return fmt.Errorf("%w: the payload is of type %q, which this does not read", ErrUnreadable, label(env.PayloadType))
}

// statement reads an in-toto statement: its subjects as assets with their
// digests, the sort of attestation it is, and a predicate this can read.
func (rd *reader) statement(st map[string]any) error {
	switch t := str(st["_type"]); t {
	case "https://in-toto.io/Statement/v1", "https://in-toto.io/Statement/v0.1":
	default:
		return fmt.Errorf("%w: the payload is not an in-toto statement (its _type is %q)", ErrUnreadable, label(t))
	}
	ptype := str(st["predicateType"])
	kind := factName("attestation", strings.TrimPrefix(strings.TrimPrefix(ptype, "https://"), "http://"))
	subjects := arr(st["subject"])
	if len(subjects) == 0 {
		return fmt.Errorf("%w: the statement has no subject", ErrUnreadable)
	}
	if len(subjects) > maxComponents {
		return fmt.Errorf("%w: the statement has more than %d subjects", ErrUnreadable, maxComponents)
	}
	for i, s := range subjects {
		so := obj(s)
		place := fmt.Sprintf("/payload/subject/%d", i)
		name := str(so["name"])
		digest := str(at(so, "digest", "sha256"))
		ref := firstText(name, "sha256:"+digest)
		if ref == "sha256:" {
			return fmt.Errorf("%w: the subject at %s has no name and no digest", ErrUnreadable, place)
		}
		id, err := rd.asset("application", ref, name, place)
		if err != nil {
			return err
		}
		if digest != "" {
			if err := rd.observe(id, "artifact.sha256", register.TextValue(label(strings.ToLower(digest))), place+"/digest", ""); err != nil {
				return err
			}
		}
		if err := rd.observe(id, kind, register.BoolValue(true), "/payload/predicateType", ""); err != nil {
			return err
		}
	}
	predicate := obj(st["predicate"])
	switch {
	case predicate == nil:
	case strings.HasPrefix(ptype, "https://cyclonedx.org/bom"):
		return rd.cyclonedx(predicate, "/payload/predicate")
	case strings.HasPrefix(ptype, "https://spdx.dev/Document"):
		return rd.spdx(predicate, "/payload/predicate")
	case strings.HasPrefix(ptype, "https://openvex.dev/ns"):
		return rd.openvex(predicate, "/payload/predicate")
	default:
		rd.note("the statement's predicate, %s, is kept in the sealed file and not read as facts", label(ptype))
	}
	return nil
}

// PinKey is a third party's public key, from its PEM or DER encoding, as
// the record a person pins it by. The fingerprint is what the person checks
// against what the key's owner published before pinning it.
func PinKey(name, title, keyID string, key []byte, now time.Time) (register.PinnedKey, error) {
	der := key
	if block, _ := pem.Decode(key); block != nil {
		if block.Type != "PUBLIC KEY" {
			return register.PinnedKey{}, fmt.Errorf("the file holds a %s, and a key is pinned by its PUBLIC KEY", label(block.Type))
		}
		der = block.Bytes
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return register.PinnedKey{}, fmt.Errorf("the file is not a public key in PEM or DER: %v", err)
	}
	var alg register.KeyAlgorithm
	switch p := pub.(type) {
	case ed25519.PublicKey:
		alg = "ed25519"
	case *ecdsa.PublicKey:
		switch p.Curve {
		case elliptic.P256():
			alg = "ecdsa-p256"
		case elliptic.P384():
			alg = "ecdsa-p384"
		}
	}
	if alg == "" {
		return register.PinnedKey{}, fmt.Errorf("the key is neither Ed25519 nor ECDSA on P-256 or P-384, which are the keys pinned")
	}
	sum := sha256.Sum256(der)
	k := register.PinnedKey{Name: name, Title: label(title), Algorithm: alg, Public: base64.StdEncoding.EncodeToString(der),
		KeyID: label(keyID), Fingerprint: register.Digest("sha256:" + hex.EncodeToString(sum[:])), Pinned: register.TimeOf(now)}
	return k, register.Validate(k)
}
