// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package programme

import (
	"errors"
	"sort"
	"time"

	"github.com/quilzo/quilzo/internal/register"
)

// The scheduler: approved tests, run when they are due.
//
// A test a person approved is run by the scheduler from then on, and by
// nobody's say-so: a test is due when its last run is at least its period
// old, or it has never run. The scheduler reads the register's own ref, so
// a draft that waits on the proposals ref is never run, however it is
// written. The admin server runs it on its timer (internal/upkeep), and
// `quilzo control run --due` runs it for a deployment with a timer of its
// own.

// DefaultEvery is how often a test is run when it does not say: once a
// day.
const DefaultEvery = 24 * time.Hour

// Due is the approved tests due a run at the register's head, in the order
// of their identifiers.
func (p *Programme) Due() ([]register.ID, error) {
	v, err := p.Reg.At("")
	if err != nil {
		return nil, err
	}
	last := map[register.ID]register.Time{}
	if err := v.Each(register.KindTestRun, func(e register.Entry, _ map[string]any) error {
		r := e.Record.(register.TestRun)
		if r.Ran > last[r.Test] {
			last[r.Test] = r.Ran
		}
		return nil
	}); err != nil {
		return nil, err
	}
	now := p.now()
	var due []register.ID
	err = v.Each(register.KindControlTest, func(e register.Entry, _ map[string]any) error {
		t := e.Record.(register.ControlTest)
		// The register refuses a test without an approval, and a test whose
		// approval lapsed is a decision nobody holds: neither runs.
		if t.Approval == nil || t.Approval.Lapsed(register.TimeOf(now)) {
			return nil
		}
		every := DefaultEvery
		if t.Every > 0 {
			every = time.Duration(t.Every) * time.Second
		}
		ran, ever := last[e.ID]
		if !ever || !now.Before(ran.At().Add(every)) {
			due = append(due, e.ID)
		}
		return nil
	})
	sort.Slice(due, func(i, j int) bool { return due[i] < due[j] })
	return due, err
}

// RunDue runs every test that is due, each as its own commit, as by, and
// says how many it ran. A test that cannot be run does not stop the others;
// the errors are joined.
func (p *Programme) RunDue(by register.Actor) (int, error) {
	due, err := p.Due()
	if err != nil {
		return 0, err
	}
	var errs []error
	n := 0
	for _, id := range due {
		if _, _, err := p.RunTest(by, id); err != nil {
			errs = append(errs, err)
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}
