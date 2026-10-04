// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package shield

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// The playbooks in force, and the changes waiting for a second person.
//
// A playbook acts without asking anybody, so changing one changes what
// Quilzo does on its own: turning one on, widening what it blocks, making
// it act sooner. Such a change is proposed by one administrator and takes
// effect when another approves it. The proposal carries the whole playbook
// as it will be, so what is approved is exactly what runs; a later edit is
// a new proposal.
//
// An install with one administrator cannot have a second, and is not left
// unable to change anything: the screen says the change was made alone and
// the audit log keeps it. The command line on the machine applies a change
// directly, because whoever runs it can already edit every file here; it
// is recorded the same way.

// Book is what is kept: the playbooks that differ from the ones Quilzo
// ships, and the proposals.
type Book struct {
	Playbooks []Playbook `json:"playbooks,omitempty"`
	Pending   []Proposal `json:"pending,omitempty"`
	Decided   []Proposal `json:"decided,omitempty"`
}

// Proposal is one change to one playbook.
type Proposal struct {
	ID       string    `json:"id"`
	Playbook Playbook  `json:"playbook"`
	Remove   bool      `json:"remove,omitempty"`
	Why      string    `json:"why"`
	By       string    `json:"by"`
	At       time.Time `json:"at"`
	// Outcome is approved, declined, withdrawn, or applied on the machine.
	Outcome   string    `json:"outcome,omitempty"`
	DecidedBy string    `json:"decided_by,omitempty"`
	Decided   time.Time `json:"decided,omitzero"`
	// Alone marks an approval by the proposer, on an install with one
	// administrator.
	Alone bool `json:"alone,omitempty"`
}

const (
	maxPending  = 50
	maxDecided  = 200
	maxPlaybook = 100
)

// BookPath is where the playbooks are kept.
func BookPath(root string) string { return filepath.Join(root, "shield-playbooks.json") }

// LoadBook reads the book; none is an empty one.
func LoadBook(root string) (*Book, error) {
	b, err := os.ReadFile(BookPath(root))
	if errors.Is(err, os.ErrNotExist) {
		return &Book{}, nil
	}
	if err != nil {
		return nil, err
	}
	bk := &Book{}
	if err := json.Unmarshal(b, bk); err != nil {
		return nil, fmt.Errorf("shield-playbooks.json: %w", err)
	}
	return bk, nil
}

func changeBook(root string, fn func(*Book) error) error {
	unlock, err := lock(BookPath(root) + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	bk, err := LoadBook(root)
	if err != nil {
		return err
	}
	if err := fn(bk); err != nil {
		return err
	}
	if len(bk.Decided) > maxDecided {
		bk.Decided = bk.Decided[len(bk.Decided)-maxDecided:]
	}
	b, err := json.MarshalIndent(bk, "", " ")
	if err != nil {
		return err
	}
	return atomicfile.Write(BookPath(root), b, 0o600)
}

func builtin(name string) (Playbook, bool) {
	for _, pb := range Builtins() {
		if pb.Name == name {
			return pb, true
		}
	}
	return Playbook{}, false
}

// InForce are the playbooks that run: Quilzo's own, as changed here, then
// the ones added here, by name. One kept here that no longer validates is
// left out rather than run as something it does not say; Problems names it.
func (bk *Book) InForce() []Playbook {
	kept := map[string]Playbook{}
	for _, pb := range bk.Playbooks {
		if pb.Validate() == nil {
			kept[pb.Name] = pb
		}
	}
	var out []Playbook
	for _, pb := range Builtins() {
		if k, ok := kept[pb.Name]; ok {
			k.Builtin = true
			pb = k
			delete(kept, pb.Name)
		}
		out = append(out, pb)
	}
	var added []Playbook
	for _, pb := range kept {
		pb.Builtin = false
		added = append(added, pb)
	}
	sort.Slice(added, func(i, j int) bool { return added[i].Name < added[j].Name })
	return append(out, added...)
}

// Problems are the kept playbooks that are not run, and why.
func (bk *Book) Problems() []string {
	var out []string
	for _, pb := range bk.Playbooks {
		if err := pb.Validate(); err != nil {
			out = append(out, fmt.Sprintf("%s: %v", pb.Name, err))
		}
	}
	return out
}

func (bk *Book) current(name string) (Playbook, bool) {
	for _, pb := range bk.InForce() {
		if pb.Name == name {
			return pb, true
		}
	}
	return Playbook{}, false
}

func (bk *Book) apply(p Proposal) {
	var keep []Playbook
	for _, pb := range bk.Playbooks {
		if pb.Name != p.Playbook.Name {
			keep = append(keep, pb)
		}
	}
	if !p.Remove {
		pb := p.Playbook
		// A shipped playbook set back to exactly what ships is kept as
		// nothing, so a later release's improvements to it apply.
		if b, ok := builtin(pb.Name); !ok || !reflect.DeepEqual(b, withBuiltin(pb, true)) {
			keep = append(keep, pb)
		}
	}
	bk.Playbooks = keep
}

func withBuiltin(pb Playbook, b bool) Playbook { pb.Builtin = b; return pb }

// Propose asks for a change to a playbook: the playbook as it will be, or
// its removal.
func Propose(root string, pb Playbook, remove bool, why, by string, now time.Time) (Proposal, error) {
	if why == "" || len(why) > 300 {
		return Proposal{}, errors.New("say why, in at most 300 characters")
	}
	_, shipped := builtin(pb.Name)
	pb.Builtin = shipped
	if remove {
		if shipped {
			return Proposal{}, errors.New("a playbook Quilzo ships is turned off, not removed")
		}
	} else if err := pb.Validate(); err != nil {
		return Proposal{}, err
	}
	p := Proposal{ID: newID(), Playbook: pb, Remove: remove, Why: why, By: by, At: now}
	err := changeBook(root, func(bk *Book) error {
		cur, exists := bk.current(pb.Name)
		if remove && !exists {
			return fmt.Errorf("there is no playbook %s", pb.Name)
		}
		if !remove && exists && reflect.DeepEqual(cur, pb) {
			return errors.New("that is the playbook as it already is")
		}
		if !remove && !exists && len(bk.InForce()) >= maxPlaybook+len(Builtins()) {
			return fmt.Errorf("%d playbooks is the limit", maxPlaybook)
		}
		for _, q := range bk.Pending {
			if q.Playbook.Name == pb.Name {
				return fmt.Errorf("a change to %s is already waiting (%s); approve, decline or withdraw it first", pb.Name, q.ID)
			}
		}
		if len(bk.Pending) >= maxPending {
			return fmt.Errorf("%d changes are waiting already", maxPending)
		}
		bk.Pending = append(bk.Pending, p)
		return nil
	})
	return p, err
}

// Decide approves or declines a waiting change. The person who proposed it
// may not approve it, unless they are the only administrator there is.
func Decide(root, id, by string, approve, onlyAdmin bool, now time.Time) (Proposal, error) {
	var out Proposal
	err := changeBook(root, func(bk *Book) error {
		for i, p := range bk.Pending {
			if p.ID != id {
				continue
			}
			if approve && p.By == by && !onlyAdmin {
				return errors.New("a change is approved by somebody other than the person who proposed it")
			}
			p.DecidedBy, p.Decided = by, now
			p.Outcome = "declined"
			if approve {
				p.Outcome, p.Alone = "approved", p.By == by
				bk.apply(p)
			}
			bk.Pending = append(bk.Pending[:i], bk.Pending[i+1:]...)
			bk.Decided = append(bk.Decided, p)
			out = p
			return nil
		}
		return fmt.Errorf("no change %s is waiting", id)
	})
	return out, err
}

// Withdraw takes back a waiting change; only its proposer may.
func Withdraw(root, id, by string, now time.Time) (Proposal, error) {
	var out Proposal
	err := changeBook(root, func(bk *Book) error {
		for i, p := range bk.Pending {
			if p.ID != id {
				continue
			}
			if p.By != by {
				return errors.New("a change is withdrawn by the person who proposed it")
			}
			p.Outcome, p.DecidedBy, p.Decided = "withdrawn", by, now
			bk.Pending = append(bk.Pending[:i], bk.Pending[i+1:]...)
			bk.Decided = append(bk.Decided, p)
			out = p
			return nil
		}
		return fmt.Errorf("no change %s is waiting", id)
	})
	return out, err
}

// SetOnMachine applies a change directly, from the command line on the
// machine, and keeps it in the history like any other.
func SetOnMachine(root string, pb Playbook, remove bool, why, by string, now time.Time) (Proposal, error) {
	_, shipped := builtin(pb.Name)
	pb.Builtin = shipped
	if remove && shipped {
		return Proposal{}, errors.New("a playbook Quilzo ships is turned off, not removed")
	}
	if !remove {
		if err := pb.Validate(); err != nil {
			return Proposal{}, err
		}
	}
	p := Proposal{ID: newID(), Playbook: pb, Remove: remove, Why: why, By: by, At: now,
		Outcome: "applied on the machine", DecidedBy: by, Decided: now}
	err := changeBook(root, func(bk *Book) error {
		if _, exists := bk.current(pb.Name); remove && !exists {
			return fmt.Errorf("there is no playbook %s", pb.Name)
		}
		// A change made here replaces one waiting for the same playbook,
		// which would otherwise be approved over it later.
		var keep []Proposal
		for _, q := range bk.Pending {
			if q.Playbook.Name == pb.Name {
				q.Outcome, q.DecidedBy, q.Decided = "replaced on the machine", by, now
				bk.Decided = append(bk.Decided, q)
				continue
			}
			keep = append(keep, q)
		}
		bk.Pending = keep
		bk.apply(p)
		bk.Decided = append(bk.Decided, p)
		return nil
	})
	return p, err
}

// Library is the playbooks in force as a server reads them on each
// signal: from the file at most once a second, and again only when it
// changed. One that cannot be read leaves what was last read in force, or
// Quilzo's own if nothing was.
type Library struct {
	Root string

	mu      sync.Mutex
	list    []Playbook
	read    os.FileInfo
	checked time.Time
}

// Refresh makes the next Get read the file, for a process that just
// changed it.
func (l *Library) Refresh() {
	l.mu.Lock()
	l.checked, l.read = time.Time{}, nil
	l.mu.Unlock()
}

// Get is the playbooks in force.
func (l *Library) Get() []Playbook {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.list != nil && now.Sub(l.checked) < time.Second {
		return l.list
	}
	l.checked = now
	fi, err := os.Stat(BookPath(l.Root))
	if err != nil {
		l.list, l.read = Builtins(), nil
		return l.list
	}
	if l.list != nil && !changed(fi, l.read) {
		return l.list
	}
	bk, err := LoadBook(l.Root)
	if err != nil {
		if l.list == nil {
			l.list = Builtins()
		}
		return l.list
	}
	l.list, l.read = bk.InForce(), fi
	return l.list
}
