// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package approval

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"

	"github.com/quilzo/quilzo/internal/register"
)

// What an approver is shown, as the hash their passkey signs.
//
// A WebAuthn prompt shows nothing of what is being approved: the browser
// asks for a fingerprint, and the person gives it to whatever the page asked
// for. So the page shows what is approved, and the hash of exactly that
// beside the button; the challenge the passkey signs holds the hash; and the
// receipt and the audit entry carry it. Three places with one hash in them
// are what make "this is what they were shown" a fact that can be checked
// after the person has forgotten the page.
//
// The surface is the record as it will be written, without the approval it
// is waiting for; the evidence it cites, by hash, and the stored hash of
// each record it points at that the register holds; and the change, field
// by field, from the record as the register holds it now. A change to any
// of the three after the page was shown is another surface, and an
// approval of the first is not an approval of the second.

// SurfaceVersion names the way a surface is written, inside the bytes that
// are hashed, so a surface written another way later can never hash the
// same as one written this way.
const SurfaceVersion = "quilzo-approval-surface/1"

// Surface is what an approver is shown.
type Surface struct {
	Version string        `json:"v"`
	Kind    register.Kind `json:"kind"`
	ID      register.ID   `json:"id"`
	// Record is the record as it will be written, its approval aside, as
	// canonical JSON.
	Record json.RawMessage `json:"record"`
	// Evidence is what the record cites: each digest it holds, and each
	// record of the register it points at, as "Kind id object".
	Evidence []string `json:"evidence"`
	// Diff is the change from the record as the register holds it, one
	// field at a time in the order of their names. A record the register
	// does not hold yet is all change.
	Diff []Change `json:"diff"`
}

// Change is one field that a decision changes.
type Change struct {
	Field  string          `json:"field"`
	Before json.RawMessage `json:"before,omitempty"`
	After  json.RawMessage `json:"after,omitempty"`
}

// Digest is the surface's hash: SHA-256 over its JSON, which is canonical
// because every part of it is.
func (s Surface) Digest() register.Digest {
	raw, _ := json.Marshal(s)
	sum := sha256.Sum256(raw)
	return register.Digest("sha256:" + hex.EncodeToString(sum[:]))
}

// SurfaceOf is what a person approving rec, whose identifier is id, is
// shown: the record against the register as it stands.
func SurfaceOf(reg *register.Register, rec register.Record, id register.ID) (Surface, error) {
	bare := register.WithApproval(rec, nil)
	after, err := register.Canonical(bare)
	if err != nil {
		return Surface{}, err
	}
	s := Surface{Version: SurfaceVersion, Kind: rec.Kind(), ID: id, Record: after, Evidence: []string{}, Diff: []Change{}}

	digests, ids := cited(bare)
	seen := map[string]bool{}
	for _, d := range digests {
		seen[d] = true
	}
	for _, ref := range ids {
		if ref == id {
			continue
		}
		e, err := reg.Get(ref)
		if errors.Is(err, register.ErrNotFound) {
			continue
		}
		if err != nil {
			return Surface{}, err
		}
		seen[fmt.Sprintf("%s %s %s", e.Kind, e.ID, e.Object)] = true
	}
	s.Evidence = append(s.Evidence, sortedNames(seen)...)

	var before json.RawMessage
	if e, err := reg.Get(id); err == nil {
		if before, err = register.Canonical(register.WithApproval(e.Record, nil)); err != nil {
			return Surface{}, err
		}
	} else if !errors.Is(err, register.ErrNotFound) {
		return Surface{}, err
	}
	s.Diff = diff(before, after)
	return s, nil
}

// diff is the fields that differ between two canonical records.
func diff(before, after json.RawMessage) []Change {
	var b, a map[string]json.RawMessage
	_ = json.Unmarshal(before, &b)
	_ = json.Unmarshal(after, &a)
	names := map[string]bool{}
	for k := range b {
		names[k] = true
	}
	for k := range a {
		names[k] = true
	}
	out := []Change{}
	for _, k := range sortedNames(names) {
		if bytes.Equal(b[k], a[k]) {
			continue
		}
		out = append(out, Change{Field: k, Before: b[k], After: a[k]})
	}
	return out
}

var (
	typeDigest = reflect.TypeOf(register.Digest(""))
	typeText   = reflect.TypeOf(register.Text(""))
	typeID     = reflect.TypeOf(register.ID(""))
	typeApprov = reflect.TypeOf((*register.Approval)(nil))
)

// cited is every digest and every identifier a record holds, at any depth,
// in the order of their values. An approval inside it is not walked: it is
// what is being given, not what is cited.
func cited(rec register.Record) (digests []string, ids []register.ID) {
	seenD, seenI := map[string]bool{}, map[register.ID]bool{}
	var walk func(v reflect.Value)
	walk = func(v reflect.Value) {
		switch {
		case v.Type() == typeApprov:
			return
		case v.Type() == typeDigest || v.Type() == typeText:
			if s := v.String(); s != "" {
				seenD[s] = true
			}
			return
		case v.Type() == typeID:
			if id := register.ID(v.String()); id.Valid() {
				seenI[id] = true
			}
			return
		}
		switch v.Kind() {
		case reflect.Pointer:
			if !v.IsNil() {
				walk(v.Elem())
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if v.Type().Field(i).IsExported() {
					walk(v.Field(i))
				}
			}
		case reflect.Slice, reflect.Array:
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i))
			}
		}
	}
	walk(reflect.ValueOf(rec))
	digests = sortedNames(seenD)
	for id := range seenI {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return digests, ids
}

// Purpose is what a passkey's signature is for. Each has its own tag at
// the start of the challenge, so a signature given for one can never be
// taken for another: a review's for an approval, or one record's approval
// for a batch's.
type Purpose string

const (
	ForApproval Purpose = "approve"
	ForBatch    Purpose = "batch"
	ForReview   Purpose = "review"
)

// tags begin a challenge, one for each purpose, and say which way of
// writing it this is. They are written with dots, not spaces, so that
// nothing reads one as a command somebody is told to run.
var tags = map[Purpose]string{
	ForApproval: "quilzo.approve.v1\x00",
	ForBatch:    "quilzo.batch.v1\x00",
	ForReview:   "quilzo.review.v1\x00",
}

// nonceSize is how many random bytes follow the hash in a challenge: the
// part that makes each ceremony fresh, so a signature cannot be asked for
// in advance or used twice.
const nonceSize = 16

// Challenge is the WebAuthn challenge for a purpose over a hash: the tag,
// the hash's 32 bytes and a random nonce, in base64url as a browser reports
// it. The hash is in the bytes the authenticator signs, so whoever holds
// the assertion can read from it what was approved.
func Challenge(p Purpose, of register.Digest, nonce []byte) (string, error) {
	tag, ok := tags[p]
	if !ok {
		return "", fmt.Errorf("%q is not something a passkey signs here", p)
	}
	raw, err := digestBytes(of)
	if err != nil {
		return "", err
	}
	if len(nonce) != nonceSize {
		return "", fmt.Errorf("a challenge's nonce is %d bytes", nonceSize)
	}
	b := append(append([]byte(tag), raw...), nonce...)
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ChallengeFor reads back what a challenge was made for, and refuses one
// that is not an approval's challenge at all: a sign-in's, which is random
// bytes, or one of another purpose.
func ChallengeFor(challenge string) (Purpose, register.Digest, error) {
	b, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil {
		return "", "", fmt.Errorf("the challenge is not base64url")
	}
	for p, tag := range tags {
		if len(b) == len(tag)+32+nonceSize && string(b[:len(tag)]) == tag {
			return p, register.Digest("sha256:" + hex.EncodeToString(b[len(tag):len(tag)+32])), nil
		}
	}
	return "", "", fmt.Errorf("the challenge was not made for an approval")
}

func digestBytes(d register.Digest) ([]byte, error) {
	if !d.Valid() {
		return nil, fmt.Errorf("%q is not a hash", clip(string(d)))
	}
	return hex.DecodeString(string(d)[len("sha256:"):])
}
