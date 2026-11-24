// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

// Coverage is how the controls stand, counted from the index: of N controls,
// how many are passing, how many failing, and how many have no evidence at
// all. It is a count of each, never a score: there is no percentage here and
// no number between nought and a hundred, because a single figure for "how
// secure are we" is the one a board remembers and the one that means least.
type Coverage struct {
	// Controls is N: every control in the register.
	Controls int `json:"controls"`
	// Passing and Failing count the controls whose newest evidence passed
	// or failed, and NoEvidence those with none.
	Passing    int `json:"passing"`
	Failing    int `json:"failing"`
	NoEvidence int `json:"no_evidence"`
	// NeverFailed counts the passing controls that have never once failed.
	// It is flagged, not praised: a test that has never failed may be a
	// test that cannot.
	NeverFailed int `json:"never_failed"`
	// Latest is the moment of the newest evidence counted.
	Latest Time `json:"latest,omitempty"`
}

// Coverage counts how the controls stand. It reads the Control and Evidence
// rows of the index and nothing else: not Extracted, which is never
// evidence, and not the proposals ref, which the index does not hold.
//
// It is one pass over the evidence rows, with a small table keyed by
// control. Over a thousand controls and a hundred and fifty thousand rows
// that is a few milliseconds, which is the bound this index was designed to.
func (ix *Index) Coverage() Coverage {
	type standing struct {
		at          int64
		state       uint8
		seen, fails bool
	}
	controls := ix.Rows(KindControl)
	by := make(map[[16]byte]*standing, len(controls))
	table := make([]standing, len(controls))
	for i := range controls {
		by[controls[i].ID] = &table[i]
	}
	pass, fail := ordinal(Pass), ordinal(Fail)
	var cov Coverage
	for _, e := range ix.Rows(KindEvidence) {
		s := by[e.About]
		if s == nil {
			continue // evidence about a control that is not in the register
		}
		if e.State == fail {
			s.fails = true
		}
		// The newest evidence decides; of two at one moment, a failure
		// does, so the order the rows happen to be in decides nothing.
		if !s.seen || e.At > s.at || e.At == s.at && e.State == fail {
			s.at, s.state, s.seen = e.At, e.State, true
		}
		if Time(e.At) > cov.Latest {
			cov.Latest = Time(e.At)
		}
	}
	cov.Controls = len(controls)
	for i := range table {
		switch s := &table[i]; {
		case !s.seen:
			cov.NoEvidence++
		case s.state == pass:
			cov.Passing++
			if !s.fails {
				cov.NeverFailed++
			}
		default:
			cov.Failing++
		}
	}
	return cov
}
