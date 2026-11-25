// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package approval

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"
	"path/filepath"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
)

// Several decisions approved by one assertion.
//
// Twenty exceptions renewed on one morning are twenty prompts for a
// fingerprint, and the twentieth is given without reading. So they can be
// approved together: one passkey assertion over the Merkle root of their
// surfaces, in the order they were shown, which proves each surface was
// among what was signed without the approver signing twenty times.
//
// What keeps that from being one click for twenty decisions is the sample.
// The batch chooses some of its items at random, about the square root of
// how many there are and at least one, and the approver opens each of those
// before the batch can be approved; the time spent on each item is
// recorded, from opening it to opening the next. The batch's record holds
// all of it, so anybody reading it later can tell a batch looked at from a
// batch waved through.

// MaxBatch is the most records one batch holds.
const MaxBatch = 200

// BatchWait is how long a batch, once shown, waits to be approved.
const BatchWait = 24 * time.Hour

// Batch is a batch as it is shown to its approver.
type Batch struct {
	Root register.Digest `json:"root"`
	// By is who it was shown to, the only person who may approve it.
	By      string        `json:"by"`
	Subject register.ID   `json:"subject"`
	Shown   register.Time `json:"shown"`
	Until   register.Time `json:"until"`
	Items   []BatchEntry  `json:"items"`
	// Viewing is the item open now, -1 for none, and Since when it was
	// opened: where the time spent on it is counted from.
	Viewing int           `json:"viewing"`
	Since   register.Time `json:"since,omitempty"`
}

// BatchEntry is one record of a batch.
type BatchEntry struct {
	Record  register.ID     `json:"record"`
	Kind    register.Kind   `json:"kind"`
	Object  string          `json:"object"`
	Surface register.Digest `json:"surface"`
	Sampled bool            `json:"sampled"`
	Opened  register.Time   `json:"opened,omitempty"`
	Seconds int64           `json:"seconds"`
}

// Unopened is how many of the items the batch chose are still to be
// opened.
func (b *Batch) Unopened() int {
	n := 0
	for _, it := range b.Items {
		if it.Sampled && it.Opened == 0 {
			n++
		}
	}
	return n
}

// BatchOutcome is what approving a batch did.
type BatchOutcome struct {
	Root     register.Digest  `json:"root"`
	Evidence register.Digest  `json:"evidence"`
	Receipt  register.Receipt `json:"receipt"`
	Items    []*Outcome       `json:"items"`
}

type batchesFile struct {
	Batches []Batch `json:"batches"`
}

func (m *Approvals) batchesPath() string { return filepath.Join(m.Root, "approvals", "batches.json") }

// sampleSize is how many of n items a batch makes its approver open.
func sampleSize(n int) int {
	return max(1, min(n, int(math.Ceil(math.Sqrt(float64(n))))))
}

// StartBatch shows a batch of waiting decisions to the person who is to
// approve them, in the order given, choosing the ones they must open.
func (m *Approvals) StartBatch(by Person, ids []register.ID) (*Batch, error) {
	pol, err := m.policy()
	if err != nil {
		return nil, err
	}
	if err := m.mayDecide(pol, by); err != nil {
		return nil, err
	}
	if len(ids) < 2 || len(ids) > MaxBatch {
		return nil, errRefused("a batch holds 2 to %d decisions, and this holds %d", MaxBatch, len(ids))
	}
	subject, err := m.people().Pseudonym(by.Name)
	if err != nil {
		return nil, err
	}
	now := m.now()
	b := Batch{By: auth.PersonKey(by.Name), Subject: subject, Shown: register.TimeOf(now),
		Until: register.TimeOf(now.Add(BatchWait)), Viewing: -1}
	seen := map[register.ID]bool{}
	var leaves []register.Digest
	for _, id := range ids {
		if seen[id] {
			return nil, errRefused("a batch holds each decision once")
		}
		seen[id] = true
		a, err := m.Ask(id)
		if err != nil {
			return nil, err
		}
		if _, err := m.canSign(pol, by, subject, a, now); err != nil {
			return nil, refusal{msg: fmt.Sprintf("%s %s cannot be in your batch: %v", a.Proposal.Kind, id, err)}
		}
		b.Items = append(b.Items, BatchEntry{Record: id, Kind: a.Proposal.Kind, Object: a.Proposal.Object, Surface: a.Hash})
		leaves = append(leaves, a.Hash)
	}
	b.Root = register.MerkleRoot(leaves)
	picked, err := pick(len(b.Items), sampleSize(len(b.Items)))
	if err != nil {
		return nil, err
	}
	for _, i := range picked {
		b.Items[i].Sampled = true
	}
	err = atomicfile.Update(m.batchesPath(), func(f *batchesFile) error {
		f.prune(now)
		f.drop(b.Root, b.By)
		f.Batches = append(f.Batches, b)
		return nil
	})
	return &b, err
}

// pick chooses k of n indexes at random.
func pick(n, k int) ([]int, error) {
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	for i := 0; i < k; i++ {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(n-i)))
		if err != nil {
			return nil, fmt.Errorf("no entropy to choose a batch's sample: %w", err)
		}
		at := i + int(j.Int64())
		idx[i], idx[at] = idx[at], idx[i]
	}
	return idx[:k], nil
}

// ErrNoBatch is a root no batch waiting has.
var ErrNoBatch = errors.New("no batch waiting has that root")

// BatchOf is the batch with this root waiting for this person. Two people
// who each approve the same decisions, as one that takes two of them asks,
// are each shown the batch on their own, with a sample of their own and
// their own time on each item, and the same root, because it is the root of
// the same surfaces in the same order.
func (m *Approvals) BatchOf(by Person, root register.Digest) (*Batch, error) {
	var out *Batch
	err := atomicfile.Update(m.batchesPath(), func(f *batchesFile) error {
		f.prune(m.now())
		if b := f.find(root, by.Name); b != nil {
			c := *b
			c.Items = append([]BatchEntry(nil), b.Items...)
			out = &c
		}
		return atomicfile.ErrUnchanged
	})
	if err == nil && out == nil {
		err = fmt.Errorf("%w: %s; a batch waits a day once it is shown", ErrNoBatch, clip(string(root)))
	}
	return out, err
}

// OpenInBatch is the approver opening one item of their batch: the time
// from the item open before it is counted to that one, and the item, if
// the batch chose it, is opened. It is the item as it stands that they are
// shown.
func (m *Approvals) OpenInBatch(by Person, root register.Digest, id register.ID) (*Batch, *Ask, error) {
	now := register.TimeOf(m.now())
	var out *Batch
	err := atomicfile.Update(m.batchesPath(), func(f *batchesFile) error {
		f.prune(m.now())
		b := f.find(root, by.Name)
		if b == nil {
			if f.find(root, "") != nil {
				return errRefused("this batch was shown to somebody else, and only they approve it")
			}
			return fmt.Errorf("%w: %s", ErrNoBatch, clip(string(root)))
		}
		at := -1
		for i := range b.Items {
			if b.Items[i].Record == id {
				at = i
			}
		}
		if at < 0 {
			return fmt.Errorf("%w: the batch holds no record %s", register.ErrNotFound, clip(string(id)))
		}
		b.tick(now)
		b.Viewing, b.Since = at, now
		if b.Items[at].Opened == 0 {
			b.Items[at].Opened = now
		}
		c := *b
		c.Items = append([]BatchEntry(nil), b.Items...)
		out = &c
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	a, err := m.Ask(id)
	return out, a, err
}

// tick counts the time since the item being looked at was opened to it.
func (b *Batch) tick(now register.Time) {
	if b.Viewing >= 0 && b.Viewing < len(b.Items) && now > b.Since {
		b.Items[b.Viewing].Seconds += int64(now - b.Since)
	}
	b.Since = now
}

// SignBatch approves every decision of a batch by one assertion over its
// root, once the approver has opened every item the batch chose.
func (m *Approvals) SignBatch(by Person, root register.Digest, proof Proof) (*BatchOutcome, error) {
	if m.Audit == nil {
		return nil, fmt.Errorf("the approvals have no audit log to record a signature in, so nothing is signed")
	}
	pol, err := m.policy()
	if err != nil {
		return nil, err
	}
	if err := m.mayDecide(pol, by); err != nil {
		return nil, err
	}
	b, err := m.BatchOf(by, root)
	if errors.Is(err, ErrNoBatch) && m.shownTo(root) {
		return nil, errRefused("this batch was shown to somebody else, and only they approve it")
	}
	if err != nil {
		return nil, err
	}
	now := m.now()
	refuse := func(err error) (*BatchOutcome, error) {
		m.audited(by, audit.Denied, AuditRefused, map[string]string{"batch": string(root), "why": err.Error()})
		return nil, err
	}
	if n := b.Unopened(); n > 0 {
		return refuse(errRefused("%d of the decisions this batch chose for you to open %s not been opened, and the "+
			"batch is approved once they have", n, map[bool]string{true: "has", false: "have"}[n == 1]))
	}
	subject := b.Subject
	ev, err := m.evidenceOf(by, subject, ForBatch, root, proof, now)
	if err != nil {
		return refuse(err)
	}
	b.tick(register.TimeOf(now))

	// Each decision as it stands has to be the one shown: a change since
	// is a surface the root does not hold.
	asks := make([]*Ask, len(b.Items))
	for i, it := range b.Items {
		a, err := m.Ask(it.Record)
		if err != nil {
			return refuse(fmt.Errorf("%s %s: %w", it.Kind, it.Record, err))
		}
		if a.Hash != it.Surface || a.Proposal.Object != it.Object {
			return refuse(refusal{cause: ErrOtherSurface, msg: fmt.Sprintf("%s %s has changed since the batch was shown, "+
				"so the root you signed does not hold it as it stands; show the batch again", it.Kind, it.Record)})
		}
		if _, err := m.canSign(pol, by, subject, a, now); err != nil {
			return refuse(err)
		}
		asks[i] = a
	}
	d, err := keep(m.Root, ev)
	if err != nil {
		return nil, err
	}
	rec := register.ApprovalBatch{Root: root, Approver: subject, At: register.TimeOf(now), Assertion: d,
		Method: ev.Method, Seconds: int64(register.TimeOf(now) - b.Shown)}
	for _, it := range b.Items {
		rec.Items = append(rec.Items, register.BatchItem{Record: it.Record, Kind: string(it.Kind), Surface: it.Surface,
			Sampled: it.Sampled, Opened: it.Opened != 0, Seconds: it.Seconds})
	}
	rc, err := m.Register.Put(m.recorder(by, subject, register.KindApprovalBatch), "a batch of "+fmt.Sprint(len(rec.Items))+
		" decisions approved by one assertion", rec)
	if err != nil && !errors.Is(err, register.ErrUnrecorded) {
		return nil, err
	}
	out := &BatchOutcome{Root: root, Evidence: d, Receipt: rc}
	for _, a := range asks {
		s, err := m.canSign(pol, by, subject, a, now)
		if err != nil {
			return out, err
		}
		s.Evidence, s.Batch = d, root
		o, err := m.signed(pol, by, subject, a, s, now)
		if err != nil && !errors.Is(err, register.ErrUnrecorded) {
			return out, err
		}
		out.Items = append(out.Items, o)
	}
	_ = atomicfile.Update(m.batchesPath(), func(f *batchesFile) error {
		f.drop(root, b.By)
		return nil
	})
	return out, nil
}

// shownTo reports whether a batch with this root waits for anybody at all,
// so that somebody else's is refused as somebody else's rather than as
// nothing.
func (m *Approvals) shownTo(root register.Digest) bool {
	found := false
	_ = atomicfile.Update(m.batchesPath(), func(f *batchesFile) error {
		f.prune(m.now())
		found = f.find(root, "") != nil
		return atomicfile.ErrUnchanged
	})
	return found
}

// recorder is a person writing one of this module's own records, a batch
// or a review: what lets them is having passed the separation policy's
// checks for what it records, so the gate is not asked the register's own
// permission to write the kind.
func (m *Approvals) recorder(by Person, subject register.ID, kind register.Kind) register.Actor {
	spec, _ := register.SpecOf(string(kind))
	return register.Actor{Name: by.Name, Subject: subject, Kind: by.Kind, Verified: by.Verified,
		May: func(act auth.Action, resource string) error {
			if act == auth.ActEditDraft && resource == spec.Resource() {
				return nil
			}
			return m.ask2(by, act, resource)
		}}
}

// find is the batch with this root shown to this person, or, with nobody
// named, shown to anybody.
func (f *batchesFile) find(root register.Digest, by string) *Batch {
	for i := range f.Batches {
		if f.Batches[i].Root == root && (by == "" || auth.SamePerson(f.Batches[i].By, by)) {
			return &f.Batches[i]
		}
	}
	return nil
}

// drop takes away the batch with this root shown to this person, and
// leaves anybody else's.
func (f *batchesFile) drop(root register.Digest, by string) {
	kept := f.Batches[:0]
	for _, b := range f.Batches {
		if b.Root != root || !auth.SamePerson(b.By, by) {
			kept = append(kept, b)
		}
	}
	f.Batches = kept
}

func (f *batchesFile) prune(now time.Time) {
	kept := f.Batches[:0]
	for _, b := range f.Batches {
		if register.TimeOf(now) < b.Until {
			kept = append(kept, b)
		}
	}
	f.Batches = kept
}
