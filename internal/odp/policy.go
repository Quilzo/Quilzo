// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package odp

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/config"
)

// Declared is one parameter value the organisation has adopted.
type Declared struct {
	Param string `json:"param"`
	Value string `json:"value"`
	// Reason is why, as the proposal gave it.
	Reason string `json:"reason,omitempty"`
	// By proposed it and ApprovedBy approved it; Alone says the deployment
	// had one administrator and they did both.
	By         string    `json:"by"`
	ApprovedBy string    `json:"approved_by"`
	Alone      bool      `json:"alone,omitempty"`
	At         time.Time `json:"at"`
}

// Change is one parameter in a proposal. An empty Value takes the
// declaration away.
type Change struct {
	Param string `json:"param"`
	Value string `json:"value"`
}

// Proposal is a change waiting for a second administrator.
type Proposal struct {
	ID      string    `json:"id"`
	Changes []Change  `json:"changes"`
	Reason  string    `json:"reason"`
	By      string    `json:"by"`
	At      time.Time `json:"at"`
	Expires time.Time `json:"expires"`
	// Source names where it came from when it was imported.
	Source string `json:"source,omitempty"`
}

// Policy is what is stored.
type Policy struct {
	Declared  []Declared `json:"declared,omitempty"`
	Proposals []Proposal `json:"proposals,omitempty"`
}

// ProposalLife is how long a proposal waits for its approval. A week is
// long enough for a second administrator to be back from a day off and
// short enough that an approval is of a change somebody still means.
const ProposalLife = 7 * 24 * time.Hour

// MaxPending bounds the proposals waiting at once.
const MaxPending = 50

// Load reads a stored policy. Absent is empty. Present and unreadable is an
// error, and the caller treats it as a policy in force that cannot be read:
// every setting it could bind refuses changes until it is repaired.
func Load(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Policy{}, nil
	}
	if err != nil {
		return nil, err
	}
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("the organisation's policy is not readable: %w", err)
	}
	return &p, nil
}

// Save writes the policy.
func Save(path string, p *Policy) error {
	sort.Slice(p.Declared, func(i, j int) bool { return p.Declared[i].Param < p.Declared[j].Param })
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(path, append(b, '\n'), 0o600)
}

// Update reads, changes and writes the policy under a lock, so two
// administrators deciding at once cannot lose one decision. Nothing is
// written when change fails.
func Update(path string, change func(*Policy) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	unlock, err := atomicfile.Lock(path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	p, err := Load(path)
	if err != nil {
		return err
	}
	if err := change(p); err != nil {
		return err
	}
	return Save(path, p)
}

// Raised is one setting brought up to the policy.
type Raised struct {
	Key, From, To, Param string
}

// Raise brings every setting below the policy up to it, in cfg, recording
// the policy as the reason. The caller saves cfg when anything was raised.
func Raise(p *Policy, cfg *config.Config, by string) ([]Raised, error) {
	var out []Raised
	for _, d := range p.Declared {
		for key, value := range Enforce(cfg, d) {
			reason := fmt.Sprintf("the organisation's policy declares %s as %q (proposed by %s, approved by %s)",
				d.Param, d.Value, d.By, d.ApprovedBy)
			from := cfg.Raw(key)
			if err := cfg.Put(key, value, reason, by); err != nil {
				return out, err
			}
			out = append(out, Raised{Key: key, From: from, To: value, Param: d.Param})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// Find is a declaration by parameter.
func (p *Policy) Find(param string) (Declared, bool) {
	for _, d := range p.Declared {
		if d.Param == param {
			return d, true
		}
	}
	return Declared{}, false
}

// Pending is the proposals still waiting, oldest first.
func (p *Policy) Pending(now time.Time) []Proposal {
	var out []Proposal
	for _, pr := range p.Proposals {
		if now.Before(pr.Expires) {
			out = append(out, pr)
		}
	}
	return out
}

// Prune drops proposals nobody approved in time.
func (p *Policy) Prune(now time.Time) (gone []Proposal) {
	kept := p.Proposals[:0]
	for _, pr := range p.Proposals {
		if now.Before(pr.Expires) {
			kept = append(kept, pr)
		} else {
			gone = append(gone, pr)
		}
	}
	p.Proposals = kept
	return gone
}

// Propose records a change for a second administrator. Every value is
// checked here, so a proposal is of something this program can keep.
func (p *Policy) Propose(changes []Change, reason, by, source string, now time.Time) (Proposal, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return Proposal{}, errors.New("a policy change needs a reason, which the second administrator reads and the audit log keeps")
	}
	if len(reason) > 500 {
		return Proposal{}, errors.New("the reason is at most 500 characters")
	}
	if len(changes) == 0 {
		return Proposal{}, errors.New("nothing to change")
	}
	seen := map[string]bool{}
	for i, c := range changes {
		param, ok := Lookup(c.Param)
		if !ok {
			return Proposal{}, fmt.Errorf("%q is not a parameter this program answers for; it can take %s",
				c.Param, strings.Join(IDs(), ", "))
		}
		if seen[param.ID] {
			return Proposal{}, fmt.Errorf("%s is changed twice in one proposal", param.ID)
		}
		seen[param.ID] = true
		changes[i].Param = param.ID
		changes[i].Value = strings.TrimSpace(c.Value)
		if changes[i].Value == "" {
			if _, has := p.Find(param.ID); !has {
				return Proposal{}, fmt.Errorf("%s is not declared, so there is nothing to take away", param.ID)
			}
			continue
		}
		if err := param.Check(changes[i].Value); err != nil {
			return Proposal{}, err
		}
	}
	p.Prune(now)
	if len(p.Proposals) >= MaxPending {
		return Proposal{}, fmt.Errorf("%d proposals are already waiting; decide some first", MaxPending)
	}
	id, err := newID()
	if err != nil {
		return Proposal{}, err
	}
	pr := Proposal{ID: id, Changes: changes, Reason: reason, By: by, At: now.UTC(),
		Expires: now.Add(ProposalLife).UTC(), Source: source}
	p.Proposals = append(p.Proposals, pr)
	return pr, nil
}

// ErrSameAdministrator refuses an approval by the person who proposed it.
var ErrSameAdministrator = errors.New("a policy change is approved by a different administrator from the one who proposed it")

// Decide approves or declines a proposal. alone says the deployment has a
// single administrator, who may then approve their own proposal; the
// declarations it makes say so for as long as they stand.
func (p *Policy) Decide(id, by string, approve, alone bool, now time.Time) (Proposal, error) {
	p.Prune(now)
	for i, pr := range p.Proposals {
		if pr.ID != id {
			continue
		}
		if approve && pr.By == by && !alone {
			return Proposal{}, ErrSameAdministrator
		}
		p.Proposals = append(p.Proposals[:i], p.Proposals[i+1:]...)
		if !approve {
			return pr, nil
		}
		for _, c := range pr.Changes {
			p.remove(c.Param)
			if c.Value == "" {
				continue
			}
			p.Declared = append(p.Declared, Declared{Param: c.Param, Value: c.Value, Reason: pr.Reason,
				By: pr.By, ApprovedBy: by, Alone: alone && pr.By == by, At: now.UTC()})
		}
		return pr, nil
	}
	return Proposal{}, fmt.Errorf("no proposal %s is waiting (approved, declined, withdrawn, or older than a week)", id)
}

// Withdraw takes back a proposal; only the person who made it may.
func (p *Policy) Withdraw(id, by string) (Proposal, error) {
	for i, pr := range p.Proposals {
		if pr.ID == id {
			if pr.By != by {
				return Proposal{}, errors.New("only the administrator who proposed it may withdraw it; another may decline it")
			}
			p.Proposals = append(p.Proposals[:i], p.Proposals[i+1:]...)
			return pr, nil
		}
	}
	return Proposal{}, fmt.Errorf("no proposal %s is waiting", id)
}

func (p *Policy) remove(param string) {
	kept := p.Declared[:0]
	for _, d := range p.Declared {
		if d.Param != param {
			kept = append(kept, d)
		}
	}
	p.Declared = kept
}

func newID() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
