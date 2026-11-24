// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
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

// Proposals: what a model or a crew would write, kept apart until a person
// decides.
//
// A proposal is a whole record, held to the same field rules as any other,
// on a ref of its own. Nothing that draws a figure reads that ref. The
// index, the coverage counted from it, and every read in this package read
// the register, so a proposal cannot become a number on a screen by being
// well formed: it becomes one when a person accepts it and Put writes it.
//
// That is the rule "a model never writes a figure, a status, a date or a
// name on a security surface", kept by where the bytes are and not by a
// check somebody has to remember.

const (
	// ProposeAction and DecideAction are the names a proposal, and a
	// person's decision about one, are recorded under.
	ProposeAction = "register.propose"
	DecideAction  = "register.decide"
)

// proposed is who proposed a record and why, as the proposals ref holds it.
// A person is named by their pseudonym and an agent by its own name, which
// is not a person's.
type proposed struct {
	Agent   string     `json:"agent,omitempty"`
	Subject ID         `json:"subject,omitempty"`
	Kind    audit.Kind `json:"kind"`
	Why     string     `json:"why"`
	At      int64      `json:"at"`
}

// Proposal is a record waiting for a person to decide.
type Proposal struct {
	Entry
	// Agent is the agent that proposed it, or Subject the person who did.
	Agent   string     `json:"agent,omitempty"`
	Subject ID         `json:"subject,omitempty"`
	By      audit.Kind `json:"by"`
	// Why is what the proposer said the record is for, and At when.
	Why string `json:"why"`
	At  Time   `json:"at"`
}

// Propose puts records on the proposals ref, where they wait. A model may
// call it; it is the only write a model has.
//
// The records are held to their kinds' field rules, so a person is never
// asked to decide something malformed. A decision's approval is not asked
// for here: it is given by the person who accepts.
func (r *Register) Propose(by Actor, why string, recs ...Record) (Receipt, error) {
	p := &proposed{Kind: by.Kind, Why: why, At: r.now().Unix()}
	switch {
	case by.Kind == audit.KindHuman && by.Subject.Valid():
		p.Subject = by.Subject
	case by.Kind == audit.KindHuman:
		return Receipt{}, fmt.Errorf("%w: a person who proposes is named by their pseudonym, and this session has none", ErrInvalid)
	case !reSlug.MatchString(by.Name):
		return Receipt{}, fmt.Errorf("%w: an agent that proposes has a machine name of its own", ErrInvalid)
	default:
		p.Agent = by.Name
	}
	return r.write(ProposalsRef, by, why, recs, p)
}

// Proposals is every record waiting for a decision, oldest first.
func (r *Register) Proposals() ([]Proposal, error) {
	tree, _, err := r.treeAt(ProposalsRef)
	if err != nil || tree == "" {
		return nil, err
	}
	entries, err := r.Store.GetNested(tree)
	if err != nil {
		return nil, err
	}
	var out []Proposal
	for path, oid := range entries {
		name, _, ok := collection.IsCollectionPath(path)
		spec := collections[name]
		if !ok || spec == nil {
			continue
		}
		e, st, err := r.entryAt(spec, oid)
		if err != nil {
			return nil, err
		}
		p := Proposal{Entry: e}
		if st.Proposed != nil {
			p.Agent, p.Subject, p.By = st.Proposed.Agent, st.Proposed.Subject, st.Proposed.Kind
			p.Why, p.At = st.Proposed.Why, Time(st.Proposed.At)
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].At != out[j].At {
			return out[i].At < out[j].At
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// proposal finds one waiting record.
func (r *Register) proposal(id ID) (Proposal, error) {
	all, err := r.Proposals()
	if err != nil {
		return Proposal{}, err
	}
	for _, p := range all {
		if p.ID == id {
			return p, nil
		}
	}
	return Proposal{}, fmt.Errorf("%w: nothing with the identifier %s is waiting", ErrNotFound, clipped(string(id)))
}

// decider holds whoever decides a proposal to the rules: a person, who may
// approve records of the kind, and who did not propose it.
func (r *Register) decider(by Actor, p Proposal) error {
	if by.Kind != audit.KindHuman {
		return fmt.Errorf("%w: a proposal is decided by a person", ErrModel)
	}
	if err := r.gate(by, auth.ActApprove, kinds[p.Kind].Resource()); err != nil {
		r.audit2(by, audit.Denied, map[string]string{"reason": "authorisation", "kind": kinds[p.Kind].Collection})
		return err
	}
	if p.Subject != "" && p.Subject == by.Subject || p.Agent != "" && auth.SamePerson(p.Agent, by.Name) {
		return fmt.Errorf("%w: whoever proposed a record is not the one who decides it", ErrRefused)
	}
	return nil
}

// Accept writes a waiting record to the register, as the person accepting
// it, and takes it off the proposals ref. approval is the accepter's
// approval of a record that is a decision; it replaces whatever the
// proposal carried, because a proposer cannot approve its own proposal.
func (r *Register) Accept(by Actor, id ID, approval *Approval) (Receipt, error) {
	p, err := r.proposal(id)
	if err != nil {
		return Receipt{}, err
	}
	if err := r.decider(by, p); err != nil {
		return Receipt{}, err
	}
	rec := withApproval(p.Record, approval)
	// Accepting is what writes the record, so the permission to approve
	// records of this kind is the permission asked, and it was asked above.
	accepter, resource := by, kinds[p.Kind].Resource()
	accepter.May = func(act auth.Action, res string) error {
		if act == auth.ActEditDraft && res == resource {
			return nil
		}
		return by.May(act, res)
	}
	rc, err := r.Put(accepter, "accepted: "+p.Why, rec)
	if err != nil {
		return rc, err
	}
	if err := r.drop(id, p.Kind, "accepted"); err != nil {
		return rc, err
	}
	return rc, r.audit2(by, audit.Success, map[string]string{"decision": "accepted", "id": string(id),
		"kind": kinds[p.Kind].Collection, "commit": rc.Commit})
}

// Reject takes a waiting record off the proposals ref and writes nothing to
// the register.
func (r *Register) Reject(by Actor, id ID) error {
	p, err := r.proposal(id)
	if err != nil {
		return err
	}
	if err := r.decider(by, p); err != nil {
		return err
	}
	if err := r.drop(id, p.Kind, "rejected"); err != nil {
		return err
	}
	return r.audit2(by, audit.Success, map[string]string{"decision": "rejected", "id": string(id),
		"kind": kinds[p.Kind].Collection})
}

// drop removes one record from the proposals ref, as a commit.
func (r *Register) drop(id ID, kind Kind, why string) error {
	return r.Store.WithRefLock(func() error {
		tree, head, err := r.treeAt(ProposalsRef)
		if err != nil || tree == "" {
			return err
		}
		next, err := r.Store.PutNested(tree, []store.Change{{
			Path: collection.Path(kinds[kind].Collection, string(id)), Delete: true}})
		if err != nil {
			return err
		}
		commit, err := r.Store.PutCommit(store.Commit{Tree: next, Parents: []string{head},
			Message: why + ": " + string(id), At: r.now().Unix(),
			Meta: map[string]string{"register": ProposalsRef, "written": strconv.Itoa(1)}})
		if err != nil {
			return err
		}
		return r.Store.SetRef(ProposalsRef, commit)
	})
}

// audit2 records a decision about a proposal.
func (r *Register) audit2(by Actor, outcome audit.Outcome, detail map[string]string) error {
	if r.Audit == nil {
		return nil
	}
	return r.Audit(audit.Record{Action: DecideAction, Resource: Area, Outcome: outcome, Principal: by.Name,
		Kind: by.Kind, Model: by.Model, Verified: by.Verified, Detail: detail})
}

// withApproval is a record with its approval replaced: set to the
// accepter's, or cleared when they gave none.
func withApproval(rec Record, a *Approval) Record {
	v := reflect.ValueOf(rec)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return rec
	}
	out := reflect.New(v.Type()).Elem()
	out.Set(v)
	for i := 0; i < out.NumField(); i++ {
		if out.Field(i).Type() == reflect.TypeOf((*Approval)(nil)) {
			out.Field(i).Set(reflect.ValueOf(a))
			break
		}
	}
	got, _ := out.Interface().(Record)
	return got
}

// Label is the few words that name a record to a person: its reference and
// its title where it has them, else its machine name, else nothing. It
// reads only labels and slugs, which a person or code wrote; it never reads
// a digest, an identifier or a value.
func Label(rec Record) string {
	v := reflect.Indirect(reflect.ValueOf(rec))
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return ""
	}
	var parts []string
	for _, name := range []string{"Ref", "Name", "Title", "Fact"} {
		f := v.FieldByName(name)
		if f.IsValid() && f.Kind() == reflect.String && f.String() != "" {
			parts = append(parts, f.String())
		}
		if len(parts) == 2 {
			break
		}
	}
	return strings.Join(parts, " · ")
}
