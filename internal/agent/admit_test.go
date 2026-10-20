// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// An action the host cannot record is not performed, and the run ends
// there: every action after it would be refused for the same reason.
func TestAnActionTheHostCannotRecordIsNotPerformed(t *testing.T) {
	read := Action{Op: "read_page", Input: map[string]any{"page": "about"}}
	p := &scripted{plan: []Action{read, read, read}}
	d := &doer{}
	admitted := 0
	r := Runner{Decide: p.decide, Perform: d.perform, Admit: func(Action) error {
		if admitted++; admitted > 1 {
			return errors.New("the audit log cannot take a record")
		}
		return nil
	}}
	tr, err := r.Run(context.Background(), NewSession(drafter(), nil), "tidy")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.did) != 1 {
		t.Fatalf("performed %v", d.did)
	}
	if len(tr.Steps) != 2 || tr.Steps[1].Allowed || !strings.Contains(tr.Steps[1].Why, "audit log") ||
		!strings.Contains(tr.Stopped, "audit log") || tr.Complete {
		t.Fatalf("the refused step or the stop is not on record: %+v", tr)
	}
	if p.asked != 2 {
		t.Errorf("the model was asked %d times after the run had to stop", p.asked)
	}
}
