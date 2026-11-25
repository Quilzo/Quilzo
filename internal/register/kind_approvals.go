// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// The kinds that hold what happened to approvals after they were given: the
// review a decision made alone owes, and the batch in which several were
// approved by one assertion. The approval itself is never one of these: it
// lives in the record it decides (types.go).

// ReviewOutcome is what a compensating review found.
type ReviewOutcome string

// Values lists the outcomes: the reviewer upheld the decision, or challenged
// it, which leaves it standing and on the record as challenged until it is
// decided again.
func (ReviewOutcome) Values() []string { return []string{"upheld", "challenged"} }

// Review is the compensating review of a decision made alone: somebody other
// than the person who made it looked at exactly what they approved and said
// whether it stands. A team of one approves alone because there is nobody
// else to ask at the time; the review is the second pair of eyes arriving
// later, and until it does the decision carries a badge saying so.
type Review struct {
	About    ID            `json:"about" reg:"required" about:"the record whose approval was made alone"`
	Surface  Digest        `json:"surface" reg:"required" about:"the hash of the approval it reviews, which is what the reviewer was shown"`
	Reviewer ID            `json:"reviewer" reg:"required,ref=Subject" about:"who reviewed it"`
	At       Time          `json:"at" reg:"required" about:"when they reviewed it"`
	Outcome  ReviewOutcome `json:"outcome" reg:"required" about:"whether the reviewer upheld the decision or challenged it"`
	// Assertion is the digest of the reviewer's authentication evidence,
	// bound to the same surface as the approval it reviews.
	Assertion Digest `json:"assertion" reg:"required" about:"the digest of the reviewer's authentication evidence, bound to the surface"`
	Method    Method `json:"method,omitempty" about:"how the evidence binds them: a passkey, or an administrator at the console"`
}

const KindReview Kind = "Review"

func (Review) Kind() Kind              { return KindReview }
func (r Review) Key() (string, string) { return Local, string(r.About) + "/" + string(r.Surface) }
func (Review) Check() error            { return nil }
func (r Review) index(w *Row) {
	w.About, w.Via, w.At, w.State = r.About.bytes(), r.Reviewer.bytes(), int64(r.At), ordinal(r.Outcome)
}

var _ = define[Review]("The compensating review of a decision made alone, by somebody else.", ClassRestricted, immutable)

// BatchItem is one record of a batch, as the approver was shown it.
type BatchItem struct {
	Record  ID     `json:"record" reg:"required" about:"the record approved"`
	Kind    string `json:"kind" reg:"required,label" about:"the record's kind"`
	Surface Digest `json:"surface" reg:"required" about:"the hash of what was shown of it, which is its leaf"`
	// Sampled marks the items the batch chose at random, which the approver
	// had to open before the batch could be approved; Opened says they did.
	Sampled bool `json:"sampled,omitempty" about:"it was one of the forced sample, which had to be opened first"`
	Opened  bool `json:"opened,omitempty" about:"the approver opened it before approving"`
	// Seconds is how long the approver spent on it: from opening it to
	// opening the next, or to approving the batch.
	Seconds int64 `json:"seconds,omitempty" reg:"min=0" about:"how long the approver spent on it, in seconds"`
}

// ApprovalBatch is several approvals given by one assertion: a passkey's
// signature over the Merkle root of the items' surfaces, in the order they
// were shown. Each record approved carries its own approval, whose signer
// names this root; this record shows which surfaces the root covers, which
// of them the approver was made to open, and how long each was looked at,
// which is what tells a batch approved with care from one approved without
// reading.
type ApprovalBatch struct {
	Root      Digest      `json:"root" reg:"required" about:"the Merkle root over the items' surfaces in the order shown; with the approver, its natural key"`
	Items     []BatchItem `json:"items" reg:"required,min=2" about:"the records approved, in the order they were shown"`
	Approver  ID          `json:"approver" reg:"required,ref=Subject" about:"who approved them, whose batch this is"`
	At        Time        `json:"at" reg:"required" about:"when"`
	Assertion Digest      `json:"assertion" reg:"required" about:"the digest of the approver's authentication evidence, bound to the root"`
	Method    Method      `json:"method,omitempty" about:"how the evidence binds them: a passkey, or an administrator at the console"`
	// Seconds is how long passed from the batch being shown to its being
	// approved.
	Seconds int64 `json:"seconds,omitempty" reg:"min=0" about:"how long passed from the batch being shown to its approval, in seconds"`
}

const KindApprovalBatch Kind = "ApprovalBatch"

// The key is the root and the approver: two people who approve the same
// decisions, as one that takes two of them asks, sign the same root, and
// each one's batch is a record of its own.
func (ApprovalBatch) Kind() Kind { return KindApprovalBatch }
func (b ApprovalBatch) Key() (string, string) {
	return Local, string(b.Root) + "/" + string(b.Approver)
}
func (b ApprovalBatch) Check() error {
	seen := map[ID]bool{}
	sampled := 0
	leaves := make([]Digest, 0, len(b.Items))
	for _, it := range b.Items {
		if seen[it.Record] {
			return fmt.Errorf("a batch holds each record once")
		}
		seen[it.Record] = true
		if it.Sampled {
			sampled++
			if !it.Opened {
				return fmt.Errorf("an item the batch chose to be opened was not opened before it was approved")
			}
		}
		leaves = append(leaves, it.Surface)
	}
	if sampled == 0 {
		return fmt.Errorf("a batch makes its approver open at least one of its items")
	}
	// The root is the items' and nothing else's: a record that said it
	// covered surfaces it does not would let one signature stand for
	// approvals nobody signed.
	if MerkleRoot(leaves) != b.Root {
		return fmt.Errorf("the root is not the Merkle root of the items' surfaces in the order shown")
	}
	return nil
}
func (b ApprovalBatch) index(r *Row) {
	r.Via, r.At, r.N = b.Approver.bytes(), int64(b.At), clamp32(int64(len(b.Items)))
}

var _ = define[ApprovalBatch]("Several approvals given by one assertion over the Merkle root of what was shown.",
	ClassRestricted, immutable)

// MerkleRoot is the root of a Merkle tree over surfaces, as RFC 6962 builds
// one: a leaf is SHA-256 over a zero byte and the surface's 32 bytes, a node
// SHA-256 over a one byte and its two children, and a tree of n leaves is
// split at the largest power of two below n. The prefixes keep a leaf from
// ever being taken for a node, so no list of surfaces has the root of
// another. An empty list has no root.
func MerkleRoot(leaves []Digest) Digest {
	if len(leaves) == 0 {
		return ""
	}
	return asDigest(merkle(leaves))
}

// MerkleLeaf is the hash a surface is as a leaf.
func MerkleLeaf(d Digest) [32]byte {
	raw, _ := hex.DecodeString(string(d[len("sha256:"):]))
	return sha256.Sum256(append([]byte{0}, raw...))
}

// MerkleNode is the hash of two children.
func MerkleNode(left, right [32]byte) [32]byte {
	return sha256.Sum256(append(append([]byte{1}, left[:]...), right[:]...))
}

func merkle(leaves []Digest) [32]byte {
	if len(leaves) == 1 {
		if !leaves[0].Valid() {
			return [32]byte{}
		}
		return MerkleLeaf(leaves[0])
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	return MerkleNode(merkle(leaves[:k]), merkle(leaves[k:]))
}

func asDigest(sum [32]byte) Digest { return Digest("sha256:" + hex.EncodeToString(sum[:])) }

// Covers reports whether the batch holds a surface as the leaf of a record.
func (b ApprovalBatch) Covers(record ID, surface Digest) bool {
	for _, it := range b.Items {
		if it.Record == record && it.Surface == surface {
			return true
		}
	}
	return false
}

// Canonical is a record's fields as bytes that are the same whoever wrote
// them: keys in order at every depth, numbers as they were written. It is
// what a surface hashes, so the hash a person is shown is the hash of the
// record the register will hold.
func Canonical(rec Record) (json.RawMessage, error) { return canonicalFields(rec) }

// approvalCheck makes, for a register as it is opened, the check of its
// approvals' authentication evidence. The approvals module sets it once, at
// start (CheckApprovalsWith), so that a register opened anywhere in the
// program, by a command, a screen or the API, is held to the evidence
// without each surface remembering to ask: a check one surface forgot is
// the check that surface did not make.
var approvalCheck func(*Register) func(rec Record, id ID, a *Approval) error

// CheckApprovalsWith sets how every register opened from now on checks the
// authentication evidence of the approvals written to it. It is called from
// the approvals module's init and nowhere else; a program without that
// module checks an approval's shape and its separation, and not its
// evidence.
func CheckApprovalsWith(make func(*Register) func(rec Record, id ID, a *Approval) error) {
	approvalCheck = make
}

// awaitingApproval is the record a write is held to: the record itself,
// except that a decision proposed without its approval is held to every
// rule but the approval it has not yet been given. A proposal waits for its
// approval; refusing it for not having one left no way to ask for one. The
// stand-in is what the kind's own rules ask of an approval, raised by
// whoever the record says raised it and agreed by somebody else, and it is
// never stored: the proposal is kept without an approval (Register.prepare
// drops any a proposer sends), and the person who accepts it gives the
// approval it is written with.
func awaitingApproval(ref string, rec Record) Record {
	if ref != ProposalsRef || approvalOf(rec) != nil || !holdsApproval(rec) {
		return rec
	}
	raised := ID("00000000000000000000000000000001")
	if r, ok := stringField(rec, "raised_by"); ok && ID(r).Valid() {
		raised = ID(r)
	}
	other := ID("00000000000000000000000000000002")
	if other == raised {
		other = "00000000000000000000000000000003"
	}
	// The stand-in is over the record as it waits, as the approval it will
	// be given must be: a kind whose Check holds its approval to the
	// record's surface (SurfaceOf) is held to it while waiting too.
	none := Digest("sha256:" + strings.Repeat("0", 64))
	return withApproval(rec, &Approval{Atom: "awaiting", Rule: "awaiting", Needed: 1, Of: 2, Surface: SurfaceOf(rec), Raised: raised,
		Signers: []Signer{{Subject: other, At: 1, Assertion: none}}})
}

// holdsApproval reports whether a record's kind has a field for an
// approval.
func holdsApproval(rec Record) bool {
	v := reflect.Indirect(reflect.ValueOf(rec))
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return false
	}
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Type() == reflect.TypeOf((*Approval)(nil)) {
			return true
		}
	}
	return false
}

// stringField is a string field of a record, by its JSON name.
func stringField(rec Record, name string) (string, bool) {
	raw, err := json.Marshal(rec)
	if err != nil {
		return "", false
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return "", false
	}
	s, ok := m[name].(string)
	return s, ok
}
