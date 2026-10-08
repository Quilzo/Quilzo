// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package shield

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
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

// Repaired is what a repair kept and what it could not.
type Repaired struct {
	Aside string `json:"aside"`
	// Kept are the parts of the record still read whole: trusted networks,
	// vouched sources, planted decoys, a hold.
	Kept []string `json:"kept,omitempty"`
	// Lost are the parts that could not be read; protections are always
	// among them, because one read in part is not one to enforce.
	Lost []string `json:"lost,omitempty"`
}

// Repair sets an unreadable record aside and starts again with what of it
// can still be read whole: the networks never to block, the administrators
// vouched for, the decoys planted and a hold, which are what keep the
// office in, the people who run this in, and a leak findable. Protections
// in force are not kept: a record read in part is not one to enforce, and
// the person repairing it applies again what still matters. A readable
// record is left alone.
func Repair(root string, now time.Time) (Repaired, error) {
	if _, err := Load(root); err == nil {
		return Repaired{}, fmt.Errorf("%s reads; there is nothing to repair", Path(root))
	}
	raw, err := os.ReadFile(Path(root))
	if err != nil {
		return Repaired{}, err
	}
	out := Repaired{Aside: Path(root) + ".unreadable-" + now.UTC().Format("20060102T150405Z")}
	fresh := &State{}
	var parts map[string]json.RawMessage
	if json.Unmarshal(raw, &parts) == nil {
		salvage := func(key, what string, into any) {
			if b, ok := parts[key]; ok {
				if json.Unmarshal(b, into) == nil {
					out.Kept = append(out.Kept, what)
				} else {
					out.Lost = append(out.Lost, what)
				}
			}
		}
		salvage("trusted", "trusted networks", &fresh.Trusted)
		salvage("vouched", "vouched sources", &fresh.Vouched)
		salvage("decoys", "planted decoys", &fresh.Decoys)
		salvage("watching", "the hold on every playbook", &fresh.Watching)
	} else {
		out.Lost = append(out.Lost, "trusted networks, vouched sources and planted decoys, if there were any")
	}
	out.Lost = append(out.Lost, "the protections that were in force")
	if err := os.Rename(Path(root), out.Aside); err != nil {
		return Repaired{}, err
	}
	b, err := json.MarshalIndent(fresh, "", " ")
	if err != nil {
		return out, err
	}
	return out, atomicfile.Write(Path(root), b, 0o600)
}

// RepairBook sets an unreadable playbook file aside, so Quilzo's own
// playbooks run as they ship and a change can be made again. A readable
// one is left alone.
func RepairBook(root string, now time.Time) (string, error) {
	if _, err := LoadBook(root); err == nil {
		return "", fmt.Errorf("%s reads; there is nothing to repair", BookPath(root))
	}
	aside := BookPath(root) + ".unreadable-" + now.UTC().Format("20060102T150405Z")
	return aside, os.Rename(BookPath(root), aside)
}
