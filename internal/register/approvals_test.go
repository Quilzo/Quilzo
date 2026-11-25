// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

// A batch's root is the Merkle root of the items' surfaces in the order they
// were shown, and nothing else's. A record of a batch that said its root
// covered other surfaces, or the same ones in another order, would let one
// signature stand for approvals nobody signed.
func TestBatchRootCoversItemsAsShown(t *testing.T) {
	items := []BatchItem{
		{Record: "a0000000000000000000000000000001", Kind: "Exception", Surface: digest(11), Sampled: true, Opened: true, Seconds: 40},
		{Record: "a0000000000000000000000000000002", Kind: "Exception", Surface: digest(12), Seconds: 5},
		{Record: "a0000000000000000000000000000003", Kind: "Risk", Surface: digest(13), Seconds: 9},
	}
	root := MerkleRoot([]Digest{digest(11), digest(12), digest(13)})
	batch := ApprovalBatch{Root: root, Items: items, Approver: dana.Subject, At: 1_790_000_000, Assertion: digest(20)}
	b := newBench(t)
	mustPut(t, b, dana, batch)
	if !batch.Covers(items[1].Record, digest(12)) || batch.Covers(items[1].Record, digest(13)) {
		t.Error("Covers does not say which leaf is whose")
	}

	// The same surfaces in another order are another root.
	swapped := append([]BatchItem(nil), items...)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	if _, err := b.Put(dana, "a test's write", ApprovalBatch{Root: root, Items: swapped, Approver: dana.Subject,
		At: 1_790_000_001, Assertion: digest(21)}); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "order shown") {
		t.Errorf("a batch whose items were reordered under the same root was written: %v", err)
	}
	// A leaf that is not what was signed is refused.
	changed := append([]BatchItem(nil), items...)
	changed[2].Surface = digest(14)
	if _, err := b.Put(dana, "a test's write", ApprovalBatch{Root: root, Items: changed, Approver: dana.Subject,
		At: 1_790_000_002, Assertion: digest(22)}); !errors.Is(err, ErrInvalid) {
		t.Errorf("a batch with a leaf the root does not cover was written: %v", err)
	}

	// The tree is RFC 6962's: a leaf is hashed with a zero byte in front and
	// a node with a one, and a tree of three is split after the second.
	leaf := func(d Digest) [32]byte { return MerkleLeaf(d) }
	want := MerkleNode(MerkleNode(leaf(digest(11)), leaf(digest(12))), leaf(digest(13)))
	if root != asDigest(want) {
		t.Errorf("the root is %s, and RFC 6962 makes it %s", root, asDigest(want))
	}
	if one := MerkleRoot([]Digest{digest(11)}); one != asDigest(leaf(digest(11))) || one == digest(11) {
		t.Errorf("a tree of one is its leaf hash, not the surface itself: %s", one)
	}
	raw := sha256.Sum256([]byte{1})
	if MerkleLeaf(digest(11)) == raw {
		t.Error("a leaf hashed like a node")
	}
}

// A batch makes its approver open at least one of its items, and an item it
// chose has to have been opened before the batch was approved.
func TestBatchRefusesAnUnopenedSampleInTheRecord(t *testing.T) {
	items := []BatchItem{
		{Record: "a0000000000000000000000000000001", Kind: "Exception", Surface: digest(11), Sampled: true},
		{Record: "a0000000000000000000000000000002", Kind: "Exception", Surface: digest(12)},
	}
	root := MerkleRoot([]Digest{digest(11), digest(12)})
	b := newBench(t)
	if _, err := b.Put(dana, "a test's write", ApprovalBatch{Root: root, Items: items, Approver: dana.Subject,
		At: 1_790_000_000, Assertion: digest(20)}); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "not opened") {
		t.Errorf("a batch whose sample was never opened was written: %v", err)
	}
	items[0].Sampled = false
	if _, err := b.Put(dana, "a test's write", ApprovalBatch{Root: root, Items: items, Approver: dana.Subject,
		At: 1_790_000_000, Assertion: digest(20)}); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "at least one") {
		t.Errorf("a batch with no sample at all was written: %v", err)
	}
}

// A decision made alone keeps the count the rule asked for, so the badge
// can say what was not met, and holds one approver, the one eligible.
func TestAnApprovalMadeAloneKeepsWhatTheRuleAsked(t *testing.T) {
	a := signedBy(dana.Subject, dana.Subject)
	a.Alone, a.Of, a.Needed, a.ReviewDue = true, 1, 2, 1_790_000_000+30*86_400
	risk := Risk{Ref: "R-9", Title: "Supplier outage", Owner: owner, Raised: dana.Subject, Likelihood: 2, Impact: 5,
		Status: "accepted", Approval: a}
	b := newBench(t)
	rc := mustPut(t, b, dana, risk)
	if len(rc.Approved) != 1 || rc.Approved[0] != a.Surface {
		t.Errorf("the receipt does not carry the surface approved: %+v", rc.Approved)
	}
	a2 := signedBy(dana.Subject, dana.Subject)
	a2.Alone, a2.Of, a2.Needed, a2.ReviewDue = true, 1, 2, 1_790_000_000+30*86_400
	a2.Signers = append(a2.Signers, Signer{Subject: owner, At: 1_790_000_000, Assertion: digest(3)})
	risk.Ref, risk.Approval = "R-10", a2
	if _, err := b.Put(dana, "a test's write", risk); !errors.Is(err, ErrInvalid) {
		t.Errorf("a decision made alone with two approvers was written: %v", err)
	}
	// An approval that had lapsed before anybody gave it is not one.
	a3 := signedBy(dana.Subject, owner)
	a3.Expires = a3.Signers[0].At
	risk.Ref, risk.Approval = "R-11", a3
	if _, err := b.Put(dana, "a test's write", risk); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "stops counting") {
		t.Errorf("an approval that lapsed as it was given was written: %v", err)
	}
	if !a3.Lapsed(a3.Expires) || a3.Lapsed(a3.Expires-1) || (&Approval{}).Lapsed(1<<40) {
		t.Error("Lapsed is wrong about when an approval stops counting")
	}
}
