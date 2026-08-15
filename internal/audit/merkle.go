package audit

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/rsh1k/scrivet/internal/translog"
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
func tree(events []Event) (*translog.Log, error) {
	l := translog.New()
	for _, e := range events {
		h, err := hex.DecodeString(e.Hash)
		if err != nil || len(h) != 32 {
			return nil, fmt.Errorf(
				"entry %d has a hash that is not a SHA-256, so no tree can be "+
					"built over it", e.Seq)
		}
		l.Append(h)
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
	leaf, err := hex.DecodeString(e.Hash)
	if err != nil {
		return fmt.Errorf("the entry's hash is not hex: %w", err)
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
	l, err := tree(events)
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
