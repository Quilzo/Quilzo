// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/quilzo/quilzo/internal/translog"
)

// The hash chain says whether this log was altered. A Merkle tree over the same
// entries says something stronger and more useful to somebody who does not
// trust the machine it lives on.
//
// # What the chain cannot do
//
// A chain is verified by walking it from the start. To be convinced that one
// entry is in the log, you have to be given the whole log — and to be convinced
// that nothing was removed between Tuesday and Friday, you have to have been
// holding Tuesday's copy. Neither is how an auditor works.
//
// A Merkle tree gives both in logarithmic size:
//
//	inclusion    this exact entry is in the log whose head is H,
//	             provable with about twenty hashes rather than the whole file
//	consistency  the log with head H2 is an append-only extension of the log
//	             with head H1 — nothing before H1 was changed or removed
//
// # Why that answers "not even an administrator"
//
// It does not, on its own, and nothing can: on a machine somebody controls, they
// can rewrite any file. What consistency proofs change is that rewriting becomes
// *provable* rather than merely suspected — and only against a head that was
// published somewhere they do not control.
//
// So the head is the thing to get out of the building. Exported to a SIEM,
// shown to an auditor, or anchored to Bitcoin, a published head fixes history
// before it. An administrator can still alter yesterday's log; they cannot make
// the altered version consistent with a head that is already in a block.
//
// That is the honest shape of the guarantee, and it is worth stating precisely
// because "immutable logs" is usually sold as something stronger than anybody
// can deliver.

// Head is a commitment to the whole log at a moment.
type Head struct {
	// Size is how many entries the log had.
	Size int `json:"size"`
	// Root is the Merkle root over those entries.
	Root string `json:"root"`
	// At is when the head was taken, which is our clock and is not evidence.
	// The evidence is what the root commits to.
	At string `json:"at"`
}

// tree builds a Merkle log over a run of entries.
//
// Over the entry hashes rather than the raw lines, so the tree and the chain
// commit to the same thing: an entry that fails the chain also fails the tree,
// and the two cannot disagree about what an entry was.
// tree builds the Merkle log over the entries.
//
// The leaf is recomputed from the entry's content. It used to be the entry's
// own Hash field, read out and trusted, and that made the whole transparency
// story circular: an administrator who edited an entry and left its hash
// alone changed the log without changing the tree.
//
// Verify caught that, because Verify recomputes. Consistency did not, and
// reported "every entry behind the published head is still there, unchanged"
// about a log whose second entry had just been rewritten. Worse, `auditlog
// anchor` puts this root into Bitcoin — so the anchor attested to a list of
// self-declared strings rather than to the content of the log, and the one
// claim that cannot be walked back was the one that was not true.
//
// The leaf commits to both, and it has to, because there are two ways to edit
// an entry and each defeats one of them.
//
// Using the stored Hash alone — what this did — misses a content edit that
// leaves the hash field untouched. Using the recomputed content hash alone
// misses an edit to the hash field itself, which breaks the chain that an
// auditor following inclusion proofs never looks at.
//
// So the leaf is over the pair. An honest entry has them equal and the leaf is
// then a deterministic function of the content; a tampered one has them differ
// and the leaf differs from either. The tree still builds either way, which
// matters: a consistency proof that can be produced and shown to fail against
// an anchored head is evidence somebody else can check, where a local refusal
// to build is a message from the same machine that holds the log.
func LeafHash(e Event) ([]byte, error) {
	want, err := e.computeHash()
	return leafOf(&e, want, err)
}

// leafOf is LeafHash given what computeHash made of the entry, for a reader
// that has already hashed it to check the chain (Index).
func leafOf(e *Event, want string, err error) ([]byte, error) {
	if err != nil {
		return nil, fmt.Errorf("entry %d cannot be re-hashed: %w", e.Seq, err)
	}
	h := sha256.New()
	// Domain-separated and length-prefixed, so no pair of fields can be slid
	// across the boundary to produce another pair's leaf.
	h.Write([]byte("quilzo.audit.leaf.v1\n"))
	writeField(h, want)
	writeField(h, e.Hash)
	writeField(h, e.Prev)
	return h.Sum(nil), nil
}

func writeField(h io.Writer, s string) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(s)))
	h.Write(n[:])
	h.Write([]byte(s))
}

func tree(events []Event) (*translog.Log, error) { return treeOf(leavesOf(events)) }

// leaves is a log as its tree is built from it: how many entries it holds,
// and the leaf of each (LeafHash). From entries in memory (leavesOf), or
// from what an Index kept of each entry, so that a view reading the log a
// page at a time checks it against its heads without reading it whole
// (Snapshot.AgainstHeads), by the same code.
type leaves struct {
	n    int
	leaf func(i int) ([]byte, error)
}

func leavesOf(events []Event) leaves {
	return leaves{len(events), func(i int) ([]byte, error) { return LeafHash(events[i]) }}
}

func treeOf(ls leaves) (*translog.Log, error) {
	l := translog.New()
	for i := 0; i < ls.n; i++ {
		leaf, err := ls.leaf(i)
		if err != nil {
			return nil, err
		}
		l.Append(leaf)
	}
	return l, nil
}

// TreeHead returns a commitment to the log as it stands.
func TreeHead(events []Event, now time.Time) (Head, error) {
	l, err := tree(events)
	if err != nil {
		return Head{}, err
	}
	h := l.Head()
	return Head{
		Size: h.Size, Root: h.Root, At: now.UTC().Format(time.RFC3339),
	}, nil
}

// Inclusion proves that one entry is in the log.
//
// The proof is about twenty hashes for a log of a million entries, which is
// what makes it usable: an auditor asking "was this specific action recorded"
// does not have to be handed the entire log, and handing them the entire log is
// also handing them every other action.
func Inclusion(events []Event, seq int64) ([]string, Head, error) {
	index := -1
	for i, e := range events {
		if e.Seq == seq {
			index = i
			break
		}
	}
	if index < 0 {
		return nil, Head{}, fmt.Errorf("there is no entry with sequence %d", seq)
	}
	l, err := tree(events)
	if err != nil {
		return nil, Head{}, err
	}
	proof, err := l.InclusionProof(index, l.Size())
	if err != nil {
		return nil, Head{}, err
	}
	head := l.Head()
	return proof, Head{Size: head.Size, Root: head.Root}, nil
}

// VerifyInclusion checks a proof without the log.
//
// The point of the exercise: somebody holding one entry, a proof and a head
// they trust can confirm the entry is in that log, on a machine that has never
// seen the log file.
func VerifyInclusion(e Event, index int, proof []string, head Head) error {
	// Derived from the entry rather than read off it, which is the same
	// reasoning as the tree: an auditor handed one entry and a proof must be
	// checking the entry they were handed, not a field inside it claiming
	// what the entry is.
	leaf, err := LeafHash(e)
	if err != nil {
		return err
	}
	root, err := hex.DecodeString(head.Root)
	if err != nil {
		return fmt.Errorf("the head's root is not hex: %w", err)
	}
	raw, err := translog.DecodeHashes(proof)
	if err != nil {
		return err
	}
	// The leaf is hashed with the domain-separating prefix RFC 6962 requires;
	// without it a leaf and an interior node could be confused, which is how a
	// second-preimage attack on a Merkle tree works.
	return translog.VerifyInclusion(translog.HashLeaf(leaf), index, head.Size,
		raw, root)
}

// Consistency proves that a log only ever grew.
//
// This is the one that matters for an administrator with root. Given a head
// published last month and the log as it stands now, a consistency proof shows
// that every entry behind the old head is still there, unchanged, in the same
// order. A log that cannot produce one has been rewritten.
func Consistency(events []Event, oldSize int) ([]string, Head, error) {
	return consistencyOf(leavesOf(events), oldSize)
}

func consistencyOf(ls leaves, oldSize int) ([]string, Head, error) {
	l, err := treeOf(ls)
	if err != nil {
		return nil, Head{}, err
	}
	if oldSize > l.Size() {
		return nil, Head{}, fmt.Errorf(
			"the published head covers %d entries and this log has %d. The log "+
				"has shrunk, which an append-only log cannot do",
			oldSize, l.Size())
	}
	proof, err := l.ConsistencyProof(oldSize, l.Size())
	if err != nil {
		return nil, Head{}, err
	}
	head := l.Head()
	return proof, Head{Size: head.Size, Root: head.Root}, nil
}

// Extends proves the log still extends a head taken from it earlier: every
// entry behind the head is there, unchanged, in the same order. It returns
// the proof and the log's head now, or what is wrong.
//
// The one check against a head, for everything that makes it. The chain
// cannot: entries removed from the end of a log leave a shorter chain that
// verifies, and the next write takes the first number removed and links to
// what is left, so not even a gap shows.
func Extends(events []Event, old Head) ([]string, Head, error) {
	return extendsOf(leavesOf(events), old)
}

func extendsOf(ls leaves, old Head) ([]string, Head, error) {
	proof, now, err := consistencyOf(ls, old.Size)
	if err != nil {
		return nil, Head{}, err
	}
	if err := VerifyConsistency(old, now, proof); err != nil {
		return nil, now, fmt.Errorf("this log is NOT an append-only extension of the head at %d "+
			"entries (%v): entries before that point have been changed, reordered or removed",
			old.Size, err)
	}
	return proof, now, nil
}

// AgainstHead is what is wrong with a log against a head taken from it
// earlier, at the last entry the head covers, or nil when the log still
// extends it (Extends).
func AgainstHead(events []Event, h Head) *Problem { return againstHead(leavesOf(events), h) }

func againstHead(ls leaves, h Head) *Problem {
	if _, _, err := extendsOf(ls, h); err != nil {
		return &Problem{Seq: int64(h.Size), Reason: fmt.Sprintf("against the head saved %s: %v", h.At, err)}
	}
	return nil
}

// AgainstHeads is what is wrong with a log against every head taken from it
// earlier: nil when it still extends each one, or a problem at the smallest
// it does not (AgainstHead), saying how many more it does not extend either.
//
// Every head, not the largest alone. A log cut back and grown again past
// its largest head extends the next head saved, by `auditlog head --save`
// or `anchor` as routinely as anything, because that head was taken from
// the log as it was left. Checked against the largest only, it was then
// called intact, and the head saved before the cut, which is the one that
// shows it, was never looked at again.
func AgainstHeads(events []Event, heads []Head) *Problem {
	return againstHeads(leavesOf(events), heads, nil)
}

// againstHeads is AgainstHeads over a log's leaves, with its roots at the
// heads' sizes from rootsAt when that is set (an Index keeps those it has
// made), and made in one pass over the leaves (rootsOf) when it is not.
func againstHeads(ls leaves, heads []Head, rootsAt func(sizes map[int]bool) (map[int][]byte, error)) *Problem {
	if len(heads) == 0 {
		return nil
	}
	if rootsAt == nil {
		rootsAt = func(sizes map[int]bool) (map[int][]byte, error) { return rootsOf(ls, sizes) }
	}
	sizes := map[int]bool{}
	for _, h := range heads {
		if h.Size >= 0 && h.Size <= ls.n {
			sizes[h.Size] = true
		}
	}
	roots, err := rootsAt(sizes)
	if err != nil {
		return &Problem{Reason: fmt.Sprintf("the log cannot be checked against the heads saved from it: %v", err)}
	}
	var bad []Head
	for _, h := range heads {
		if !extendsAt(roots, h) {
			bad = append(bad, h)
		}
	}
	if len(bad) == 0 {
		return nil
	}
	sort.SliceStable(bad, func(i, j int) bool { return bad[i].Size < bad[j].Size })
	p := againstHead(ls, bad[0])
	if p == nil {
		// The one-pass roots and the proof disagree, which they cannot unless
		// one of them is wrong: said so rather than passed over.
		p = &Problem{Seq: int64(bad[0].Size), Reason: fmt.Sprintf("against the head saved %s: the root "+
			"of the first %d entries is not the head's", bad[0].At, bad[0].Size)}
	}
	if more := len(bad) - 1; more > 0 {
		p.Reason += fmt.Sprintf("; and it does not extend %d more of the heads saved from it, "+
			"the largest at %d entries", more, bad[len(bad)-1].Size)
	}
	return p
}

// extendsAt says whether a log whose roots at each size are roots holds a
// head: the root of its first Size entries is the head's. Every tree extends
// the empty one, as VerifyConsistency has it.
func extendsAt(roots map[int][]byte, h Head) bool {
	if h.Size == 0 {
		return true
	}
	root, ok := roots[h.Size]
	if !ok {
		return false // more entries than the log has, or a size no log has
	}
	want, err := hex.DecodeString(h.Root)
	return err == nil && bytes.Equal(root, want)
}

// rootsOf is the tree's root over the first n entries of a log, for each n
// asked for, in one pass over it.
//
// One pass, because the log is checked against every head saved from it,
// as often as the audit log screen is opened: a root over n entries
// computed afresh for each head is n hashes a head, and a log of a million
// entries with a year of heads saved beside it would take minutes. The
// tree over n leaves is the run of perfect subtrees that n's binary digits
// give, largest first, folded from the right (RFC 6962 splits at the
// largest power of two below n, and so on down), which is what is kept
// here as the leaves go by. The test checks it against the tree's own root
// at every size up to past 64.
func rootsOf(ls leaves, sizes map[int]bool) (map[int][]byte, error) {
	roots := map[int][]byte{}
	last := 0
	for n := range sizes {
		last = max(last, n)
	}
	var peaks [][]byte
	for i := 0; i < last; i++ {
		leaf, err := ls.leaf(i)
		if err != nil {
			return nil, err
		}
		h := translog.HashLeaf(leaf)
		// Two subtrees of a size merge into one of twice it: as many times
		// as the count of leaves so far ends in zeros in binary.
		for n := i + 1; n&1 == 0; n >>= 1 {
			h = translog.HashNode(peaks[len(peaks)-1], h)
			peaks = peaks[:len(peaks)-1]
		}
		peaks = append(peaks, h)
		if sizes[i+1] {
			root := peaks[len(peaks)-1]
			for j := len(peaks) - 2; j >= 0; j-- {
				root = translog.HashNode(peaks[j], root)
			}
			roots[i+1] = root
		}
	}
	return roots, nil
}

// LargestHead is the head covering the most entries, the one saved last of
// those that cover as many, or nil when there is none: the one a check
// against saved heads names.
func LargestHead(heads []Head) *Head {
	var best *Head
	for i := range heads {
		if best == nil || heads[i].Size >= best.Size {
			best = &heads[i]
		}
	}
	return best
}

// VerifyConsistency checks that a new head extends an old one.
func VerifyConsistency(old, new Head, proof []string) error {
	oldRoot, err := hex.DecodeString(old.Root)
	if err != nil {
		return fmt.Errorf("the old root is not hex: %w", err)
	}
	newRoot, err := hex.DecodeString(new.Root)
	if err != nil {
		return fmt.Errorf("the new root is not hex: %w", err)
	}
	raw, err := translog.DecodeHashes(proof)
	if err != nil {
		return err
	}
	return translog.VerifyConsistency(old.Size, new.Size, raw, oldRoot, newRoot)
}
