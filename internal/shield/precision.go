// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package shield

import (
	"fmt"
	"math"
	"os"
	"sort"
	"time"
)

// MinVerdicts is how many judged protections a playbook needs before its
// precision is quoted, as for detection rules (detect.MinVerdicts).
const MinVerdicts = 10

// Record is what one playbook has turned out to be worth.
type Record struct {
	Playbook string `json:"playbook"`
	// Applied is how many protections it put in force that are still
	// remembered; Right and Mistakes are the ones a person judged.
	Applied  int `json:"applied"`
	Right    int `json:"right"`
	Mistakes int `json:"mistakes"`
	// LiftedEarly is how many a person ended before their time without
	// saying why: not a verdict, but worth seeing beside one.
	LiftedEarly int `json:"lifted_early"`
}

// Precision is the share of judged protections that were right, with a 95%
// Wilson interval, and whether there are enough verdicts to say it.
func (r Record) Precision() (rate, low, high float64, enough bool) {
	n := r.Right + r.Mistakes
	if n == 0 {
		return 0, 0, 1, false
	}
	low, high = wilson(r.Right, n)
	return float64(r.Right) / float64(n), low, high, n >= MinVerdicts
}

// Records counts each playbook's protections and verdicts, from what is
// in force and the ended history.
func Records(st *State) []Record {
	by := map[string]*Record{}
	for _, list := range [][]Protection{st.Protections, st.Ended} {
		for _, p := range list {
			if p.Playbook == "" {
				continue
			}
			r := by[p.Playbook]
			if r == nil {
				r = &Record{Playbook: p.Playbook}
				by[p.Playbook] = r
			}
			r.Applied++
			switch p.Verdict {
			case Right:
				r.Right++
			case Mistake:
				r.Mistakes++
			default:
				if !p.Lifted.IsZero() && p.ReplacedBy == "" {
					r.LiftedEarly++
				}
			}
		}
	}
	out := make([]Record, 0, len(by))
	for _, r := range by {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Playbook < out[j].Playbook })
	return out
}

// wilson is the 95% Wilson score interval for k successes in n: an
// interval that is honest at 0% and 100%, where a small sample most needs
// one (the same as internal/detect's).
func wilson(k, n int) (low, high float64) {
	if n == 0 {
		return 0, 1
	}
	const z = 1.959964
	p := float64(k) / float64(n)
	nn := float64(n)
	denom := 1 + z*z/nn
	centre := p + z*z/(2*nn)
	margin := z * math.Sqrt(p*(1-p)/nn+z*z/(4*nn*nn))
	return math.Max(0, (centre-margin)/denom), math.Min(1, (centre+margin)/denom)
}

// Repair sets an unreadable record aside, so the shield starts again
// empty: what it held is kept beside it for a person to read. A readable
// record is left alone.
func Repair(root string, now time.Time) (string, error) {
	if _, err := Load(root); err == nil {
		return "", fmt.Errorf("%s reads; there is nothing to repair", Path(root))
	}
	aside := Path(root) + ".unreadable-" + now.UTC().Format("20060102T150405Z")
	if err := os.Rename(Path(root), aside); err != nil {
		return "", err
	}
	return aside, nil
}
