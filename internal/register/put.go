// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/store"
)

// The one way a record is written.
//
// Every write to the register goes through Put, in one order: the policy
// gate, the kind's invariants, the approval where the kind is a decision,
// one commit for the batch, an audit entry and a receipt. There is no second
// path. The generic record surfaces refuse the register's collections by
// name, nothing else in the program moves the register's ref, and a test
// walks the source to keep both true.
//
// One path is what the record's integrity is. A check made in four places is
// made in three of them after the next change, and for evidence the place
// that forgot is the place that will be used.

var (
	// ErrRefused is the access policy refusing a write. It is a decision,
	// not a failure: nothing broke, and trying again changes nothing.
	ErrRefused = errors.New("refused by the access policy")
	// ErrModel is a model trying to write the record. What a model
	// produces is a proposal, and a person decides it.
	ErrModel = errors.New("a model does not write the record; it proposes, and a person decides")
	// ErrImmutable is a change to a record of a kind that is never changed.
	ErrImmutable = errors.New("a record of this kind is never changed once written")
	// ErrUnrecorded is a write that landed whose audit entry could not be
	// written. The receipt is still returned, and says what was written.
	ErrUnrecorded = errors.New("the write is in the register and its audit entry could not be written")
)

// AuditAction is the name every write to the register is recorded under,
// on every surface.
const AuditAction = "register.put"

// Written is one record a write put in the register.
type Written struct {
	Kind Kind `json:"kind"`
	ID   ID   `json:"id"`
	// Object is the stored record's own hash.
	Object string `json:"object"`
	// New says the record did not exist before this write.
	New bool `json:"new,omitempty"`
}

// Receipt is what a write hands back: the commit it made, what it wrote and
// what it found already there. Its digest is in the audit entry for the
// write, so the two can be shown to be about the same thing.
type Receipt struct {
	// Ref is the ref the write was to: the register, or its proposals.
	Ref string `json:"ref"`
	// Commit is the commit the batch made, and Parent the one before it.
	// Commit is empty when every record was already there unchanged, and
	// then nothing was written at all.
	Commit string `json:"commit,omitempty"`
	Parent string `json:"parent,omitempty"`
	By     string `json:"by"`
	At     Time   `json:"at"`
	Why    string `json:"why"`
	// Written is the records that are new or changed, in the order of
	// their identifiers; Unchanged counts the rest.
	Written   []Written `json:"written"`
	Unchanged int       `json:"unchanged"`
	// Approved is the hash of what was approved, for each record written
	// that carries an approval: the surface the approvers were shown and
	// their passkeys signed. It is in the receipt, and in the audit entry,
	// so the hash on the page, the receipt and the log can be laid side by
	// side.
	Approved []Digest `json:"approved,omitempty"`
	// Digest is SHA-256 over everything above, as JSON.
	Digest Digest `json:"digest"`
}

func (rc *Receipt) seal() {
	rc.Digest = ""
	b, _ := json.Marshal(rc)
	sum := sha256.Sum256(b)
	rc.Digest = Digest("sha256:" + hex.EncodeToString(sum[:]))
}

// Put writes a batch of records to the register, as one commit.
//
// why says what the write is, in a line a person can read in the history:
// "entra users, run of 24 Nov 2026 10:00". It is written by code. It is not
// a place for a person's free text, which goes in a record's Text fields.
//
// A record that is already there with the same fields is skipped, and a
// batch of nothing but those makes no commit, no audit entry and a receipt
// that says so. That is what lets an import run every hour: the record
// changes when a fact does.
//
// Only a person or a service writes. A model is refused, and so is an actor
// that does not say what it is: the rule that a model only proposes cannot
// rest on the model, or a surface that forgot to ask, saying it is one.
func (r *Register) Put(by Actor, why string, recs ...Record) (Receipt, error) {
	switch by.Kind {
	case audit.KindHuman, audit.KindService:
	case audit.KindAI:
		r.audited(by, Ref, audit.Denied, map[string]string{"reason": "a model may only propose"})
		return Receipt{}, fmt.Errorf("%w (register.Propose)", ErrModel)
	default:
		r.audited(by, Ref, audit.Denied, map[string]string{"reason": "neither a person nor a service"})
		return Receipt{}, fmt.Errorf("%w: who is writing is neither a person nor a service, and is taken for a model "+
			"(register.Propose)", ErrModel)
	}
	return r.write(Ref, by, why, recs, nil)
}

// item is one record of a batch, ready to be stored.
type item struct {
	spec   *Spec
	id     ID
	rec    Record
	fields json.RawMessage
}

// prepare runs the gate and the invariants over a batch, and returns it in
// the order of its identifiers with duplicates folded.
func (r *Register) prepare(ref string, by Actor, why string, recs []Record) ([]item, error) {
	if r.Audit == nil {
		return nil, fmt.Errorf("the register has no audit log to record a write in, so it does not write")
	}
	if strings.TrimSpace(by.Name) == "" {
		return nil, fmt.Errorf("%w: a write names who is writing", ErrInvalid)
	}
	if err := validLabel(why, "why"); err != nil || why == "" {
		return nil, fmt.Errorf("%w: a write says what it is, in one plain line", ErrInvalid)
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("%w: a write holds at least one record", ErrInvalid)
	}

	// The policy gate, once for each kind in the batch, before anything
	// about the records is said: somebody who may not write a kind is not
	// told what is wrong with their record of it.
	asked := map[Kind]bool{}
	for _, rec := range recs {
		if rec == nil {
			return nil, fmt.Errorf("%w: a batch holds an empty record", ErrInvalid)
		}
		spec, err := specFor(rec.Kind())
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		if asked[spec.Kind] {
			continue
		}
		asked[spec.Kind] = true
		if err := r.gate(by, auth.ActEditDraft, spec.Resource()); err != nil {
			r.audited(by, ref, audit.Denied, map[string]string{"reason": "authorisation", "kind": spec.Collection})
			return nil, err
		}
	}

	byID := map[ID]int{}
	var items []item
	for _, rec := range recs {
		spec := kinds[rec.Kind()]
		if err := validate(awaitingApproval(ref, rec)); err != nil {
			return nil, err
		}
		id, err := IDOf(rec)
		if err != nil {
			return nil, err
		}
		if a, ok := rec.(interface{ attested() bool }); ok && a.attested() && by.Kind != audit.KindHuman {
			return nil, fmt.Errorf("%w: a statement about a control is a person's to make", ErrModel)
		}
		if err := r.approved(ref, spec, rec, id); err != nil {
			return nil, err
		}
		fields, err := canonicalFields(rec)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, strings.ToLower(string(spec.Kind)), err)
		}
		if at, dup := byID[id]; dup {
			if !bytes.Equal(items[at].fields, fields) {
				return nil, fmt.Errorf("%w: the batch describes the %s %s twice, differently", ErrInvalid,
					strings.ToLower(string(spec.Kind)), id)
			}
			continue
		}
		byID[id] = len(items)
		items = append(items, item{spec: spec, id: id, rec: rec, fields: fields})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].id != items[j].id {
			return items[i].id < items[j].id
		}
		return items[i].spec.Kind < items[j].spec.Kind
	})
	return items, nil
}

// gate asks the access policy, and answers a refusal as one.
func (r *Register) gate(by Actor, act auth.Action, resource string) error {
	if by.May == nil {
		return fmt.Errorf("%w: this surface did not say how to ask it", ErrRefused)
	}
	if err := by.May(act, resource); err != nil {
		return fmt.Errorf("%w: %v", ErrRefused, err)
	}
	return nil
}

// approved holds a record that is a decision to its approval. On the
// proposals ref a decision waits for its approval, so none is asked there.
func (r *Register) approved(ref string, spec *Spec, rec Record, id ID) error {
	a := approvalOf(rec)
	if a == nil {
		if spec.Signed && ref == Ref {
			return fmt.Errorf("%w: %s: it is a decision, and carries the approval that made it", ErrInvalid,
				strings.ToLower(string(spec.Kind)))
		}
		return nil
	}
	if r.Approvals != nil && ref == Ref {
		if err := r.Approvals(rec, id, a); err != nil {
			return fmt.Errorf("%w: %s: its approval does not hold: %v", ErrInvalid, strings.ToLower(string(spec.Kind)), err)
		}
	}
	return nil
}

// write is Put and Propose: prepare the batch, then compare, commit and
// record it with every ref of the store held.
func (r *Register) write(ref string, by Actor, why string, recs []Record, prop *proposed) (Receipt, error) {
	items, err := r.prepare(ref, by, why, recs)
	if err != nil {
		return Receipt{}, err
	}
	if r.Ready != nil {
		if err := r.Ready(); err != nil {
			return Receipt{}, fmt.Errorf("nothing was written, because the audit log cannot record it: %w", err)
		}
	}
	now := r.now()
	rc := Receipt{Ref: ref, By: by.Name, At: TimeOf(now), Why: why, Written: []Written{}}

	err = r.Store.WithRefLock(func() error {
		tree, head, err := r.treeAt(ref)
		if err != nil {
			return err
		}
		rd := newReader(r.Store)
		var changes []store.Change
		for _, it := range items {
			path := collection.Path(it.spec.Collection, string(it.id))
			st := stored{ID: string(it.id), Fields: it.fields, Created: now.Unix(), Updated: now.Unix(), Proposed: prop}
			oid, exists, err := rd.lookup(tree, path)
			if err != nil {
				return err
			}
			if exists {
				var was stored
				if err := r.Store.GetBlob(oid, &was); err != nil {
					return err
				}
				if bytes.Equal(was.Fields, it.fields) {
					rc.Unchanged++
					continue
				}
				if it.spec.Immutable && ref == Ref {
					return fmt.Errorf("%w: the %s %s", ErrImmutable, strings.ToLower(string(it.spec.Kind)), it.id)
				}
				st.Created = was.Created
			}
			payload, err := json.Marshal(st)
			if err != nil {
				return err
			}
			// The object's name is worked out here and the object is
			// written with the tree below, once.
			blob := store.ObjectID(store.KindBlob, payload)
			changes = append(changes, store.Change{Path: path, Value: st})
			rc.Written = append(rc.Written, Written{Kind: it.spec.Kind, ID: it.id, Object: blob, New: !exists})
			if a := approvalOf(it.rec); a != nil && ref == Ref {
				rc.Approved = append(rc.Approved, a.Surface)
			}
		}
		if len(changes) == 0 {
			return nil
		}
		next, err := r.Store.PutNested(tree, changes)
		if err != nil {
			return err
		}
		c := store.Commit{Tree: next, Message: why, Author: string(by.Subject), At: now.Unix(),
			Meta: map[string]string{"register": ref, "by": string(by.Kind), "written": strconv.Itoa(len(changes))}}
		if head != "" {
			c.Parents = []string{head}
		}
		commit, err := r.Store.PutCommit(c)
		if err != nil {
			return err
		}
		if err := r.Store.SetRef(ref, commit); err != nil {
			return err
		}
		rc.Commit, rc.Parent = commit, head
		return nil
	})
	if err != nil {
		return Receipt{}, err
	}
	rc.seal()
	if rc.Commit == "" {
		return rc, nil
	}
	detail := map[string]string{
		"commit": rc.Commit, "written": strconv.Itoa(len(rc.Written)), "unchanged": strconv.Itoa(rc.Unchanged),
		"kinds": kindsOf(rc.Written), "receipt": string(rc.Digest), "why": why,
	}
	if len(rc.Approved) > 0 {
		var surfaces []string
		for _, d := range rc.Approved {
			surfaces = append(surfaces, string(d))
		}
		detail["approved"] = strings.Join(surfaces, ",")
	}
	if err := r.audited(by, ref, audit.Success, detail); err != nil {
		return rc, fmt.Errorf("%w: %v", ErrUnrecorded, err)
	}
	return rc, nil
}

// audited writes the audit entry for a write, or for a refusal of one.
func (r *Register) audited(by Actor, ref string, outcome audit.Outcome, detail map[string]string) error {
	if r.Audit == nil {
		return nil
	}
	action := AuditAction
	if ref == ProposalsRef {
		action = ProposeAction
	}
	kind, verified := by.Kind, by.Verified
	if !kind.Valid() {
		kind = audit.KindUnknown
	}
	// The log takes an actor of unknown kind as nobody proved, which is
	// what an actor that would not say what it is amounts to.
	if kind == audit.KindUnknown {
		verified = false
	}
	return r.Audit(audit.Record{Action: action, Resource: Area, Outcome: outcome, Principal: by.Name,
		Kind: kind, Model: by.Model, Verified: verified, Detail: detail})
}

// kindsOf is the collections a write touched, in order, for the audit entry.
func kindsOf(written []Written) string {
	seen := map[string]bool{}
	for _, w := range written {
		seen[kinds[w.Kind].Collection] = true
	}
	return strings.Join(sortedKeys(seen), ",")
}

// approvalOf is the approval a record carries, under whichever of its
// fields holds one: the first that is an approval and is set. Found by the
// field's type, so a kind added later needs no entry in any list.
func approvalOf(rec Record) *Approval {
	v := reflect.Indirect(reflect.ValueOf(rec))
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return nil
	}
	for i := 0; i < v.NumField(); i++ {
		if a, ok := v.Field(i).Interface().(*Approval); ok && a != nil {
			return a
		}
	}
	return nil
}
