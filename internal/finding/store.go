// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package finding

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// The register, kept between runs.
//
// A register only in memory is a queue that exists for the length of one
// command. `quilzo triage` built one from the events it was handed, printed
// the top twenty and threw it away, so there was nothing for a screen to show,
// nothing for an agent to read and nothing for a decision to apply to — the
// decisions were written to the audit log about findings that no longer
// existed anywhere.
//
// What is kept is what the scanners said: identity, severity, evidence,
// counts. What people decided stays in the audit log, where it is signed and
// chained, and is applied over this when it is read. Two copies of a decision
// is two things that can disagree, and the copy in the chain is the one that
// can be proved; the register has no field a person's decision writes to.

// Ledger is the register on disk, with where each producer has got to.
type Ledger struct {
	Findings []Finding `json:"findings"`
	// Cursors are, per producer, the arrival time it has processed up to. A
	// detection run over the event store starts from its cursor, so running
	// it twice does not count the same event twice — which would inflate
	// Seen, and Seen is part of the weight.
	Cursors map[string]time.Time `json:"cursors,omitempty"`
}

// MaxFindings bounds the register.
//
// Well above anything a team works, and low enough that a rule matching
// every event cannot fill a disk through the register. A producer that hits
// it is told so, rather than the oldest findings quietly falling off.
const MaxFindings = 50_000

// Load reads a register. A missing file is an empty register, not an error:
// a site that has never recorded a finding has nothing to load.
func Load(path string) (*Register, map[string]time.Time, error) {
	reg := NewRegister()
	cursors := map[string]time.Time{}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return reg, cursors, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var l Ledger
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, nil, fmt.Errorf(
			"%s is not a finding register: %w. It is refused rather than "+
				"treated as empty, because an empty register is the report "+
				"that nothing is wrong", path, err)
	}
	for _, f := range l.Findings {
		f := f
		key := Key(f.Kind, f.Source, f.Entity)
		if f.ID == "" {
			f.ID = key
		}
		reg.byKey[key] = &f
	}
	for k, v := range l.Cursors {
		cursors[k] = v
	}
	return reg, cursors, nil
}

// Save writes a register atomically, readable only by its owner.
//
// Findings are about weaknesses in this estate, which is exactly the list an
// attacker would most like to read.
func Save(path string, reg *Register, cursors map[string]time.Time) error {
	if reg.Len() > MaxFindings {
		return fmt.Errorf(
			"the register holds %d findings, over the %d limit. Something is "+
				"producing a finding per event rather than per problem; the "+
				"register was not written so the cause can be found",
			reg.Len(), MaxFindings)
	}
	l := Ledger{Cursors: cursors}
	for _, f := range reg.byKey {
		l.Findings = append(l.Findings, *f)
	}
	// Stable on disk, so two saves of the same register are the same bytes
	// and a diff of the file shows what changed.
	sort.Slice(l.Findings, func(i, j int) bool {
		return l.Findings[i].ID < l.Findings[j].ID
	})
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(path, b, 0o600)
}

// Get returns one finding by id.
func (r *Register) Get(id string) (Finding, bool) {
	for _, f := range r.byKey {
		if f.ID == id {
			return *f, true
		}
	}
	return Finding{}, false
}

// View is the register as people see it: what the scanners said, with every
// decision applied, ranked.
func View(reg *Register, decisions []Decision, now time.Time) []Finding {
	all := make([]Finding, 0, reg.Len())
	for _, f := range reg.byKey {
		all = append(all, Apply(*f, decisions))
	}
	return Rank(all, now)
}

// Lock takes the register for one writer.
//
// Producers write the register and nothing else does — a person's decision
// goes to the audit log — so the race is two producers: a scheduled detection
// run overlapping the one somebody started by hand. Without this the second
// save discards the first run's findings and its cursor, and the next run
// counts those events again.
//
// A lock file created exclusively, not an advisory lock, so it works the same
// on every platform this builds for. One older than StaleLock is from a run
// that died and is taken over, because a crash should not stop detection
// until somebody notices a file.
func Lock(path string) (unlock func(), err error) {
	lock := path + ".lock"
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%d\n", os.Getpid())
			f.Close()
			return func() { _ = os.Remove(lock) }, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		fi, serr := os.Stat(lock)
		if serr != nil || time.Since(fi.ModTime()) < StaleLock {
			return nil, fmt.Errorf(
				"another run is writing the finding register (%s exists). "+
					"Wait for it, or remove the file if no run is going", lock)
		}
		_ = os.Remove(lock)
	}
	return nil, fmt.Errorf("could not take %s", lock)
}

// StaleLock is how old a lock has to be before it is assumed abandoned.
const StaleLock = 15 * time.Minute
