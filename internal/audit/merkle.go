package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
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
	if err != nil {
		return nil, fmt.Errorf("entry %d cannot be re-hashed: %w", e.Seq, err)
	}
	h := sha256.New()
	// Domain-separated and length-prefixed, so no pair of fields can be slid
	// across the boundary to produce another pair's leaf.
	h.Write([]byte("scrivet.audit.leaf.v1\n"))
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

func tree(events []Event) (*translog.Log, error) {
	l := translog.New()
	for _, e := range events {
		leaf, err := LeafHash(e)
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
