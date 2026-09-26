// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package source

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
)

// Batch is what happened when a page of records was mapped.
//
// The counts are the point, and they are the same accounting idea as
// internal/flow's: everything that came in left through exactly one exit,
// and a run that cannot say where the records went is the failure rather
// than a run with a caveat.
type Batch struct {
	Source  string            `json:"source"`
	At      time.Time         `json:"at"`
	Records int               `json:"records"`
	Mapped  int               `json:"mapped"`
	Events  []telemetry.Event `json:"-"`
	// Missed counts records that failed, and ByPath which requirement
	// failed them. The second is what turns "the connector is broken"
	// into "they renamed userId".
	Missed int            `json:"missed"`
	ByPath map[string]int `json:"by_path,omitempty"`
}

// Map runs a page of records through a source.
func Map(s Source, docs []any, at time.Time) Batch {
	b := Batch{Source: s.Issuer + "/" + s.Stream, At: at.UTC(),
		Records: len(docs), ByPath: map[string]int{}}
	for _, d := range docs {
		e, missed := s.Map(d)
		if len(missed) == 0 {
			e.Received = at.UTC()
			b.Mapped++
			b.Events = append(b.Events, e)
			continue
		}
		b.Missed++
		for _, m := range missed {
			b.ByPath[m.Path]++
		}
	}
	return b
}

// Balances reports whether every record was accounted for.
func (b Batch) Balances() bool { return b.Mapped+b.Missed == b.Records }

// Share is the fraction of records that failed to map.
func (b Batch) Share() float64 {
	if b.Records == 0 {
		return 0
	}
	return float64(b.Missed) / float64(b.Records)
}

// Changed is the threshold above which a source is treated as having
// changed shape rather than as having sent some odd records.
//
// One in twenty. Real logs contain occasional records that do not fit —
// a truncated write, a record type nobody documented — and treating one of
// those as an outage is how a real alert gets muted. A twentieth of a page
// failing on the same path is not that.
const Changed = 0.05

// Worst is the requirement that failed the most records.
func (b Batch) Worst() (string, int) {
	paths := make([]string, 0, len(b.ByPath))
	for p := range b.ByPath {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	best, at := "", 0
	for _, p := range paths {
		if b.ByPath[p] > at {
			best, at = p, b.ByPath[p]
		}
	}
	return best, at
}

// Drifted reports whether this source appears to have changed shape, and
// says which field.
//
// The whole point of the package. A source that changed and was absorbed
// produces events with empty fields and detections that quietly stop
// firing; a source that changed and was reported produces this sentence.
func (b Batch) Drifted() (string, bool) {
	if b.Records == 0 || b.Share() <= Changed {
		return "", false
	}
	path, n := b.Worst()
	if path == "" {
		return "", false
	}
	return fmt.Sprintf(
		"%d of %d record(s) from %s are missing %q. That is %.0f%% of the "+
			"page failing on one field, which is a source that has changed "+
			"shape rather than a few odd records — and the alternative to "+
			"saying so is events with an empty %s in them and every "+
			"detection written against it quietly not firing",
		n, b.Records, b.Source, path, b.Share()*100, leaf(path)), true
}

// Why describes a batch.
func (b Batch) Why() string {
	switch {
	case b.Records == 0:
		return "nothing arrived"
	case b.Missed == 0:
		return fmt.Sprintf("%d record(s) mapped", b.Mapped)
	}
	if why, drifted := b.Drifted(); drifted {
		return why
	}
	path, n := b.Worst()
	return fmt.Sprintf(
		"%d of %d mapped; %d failed, most often on %q (%d)",
		b.Mapped, b.Records, b.Missed, path, n)
}

// Health is a source's state across several batches.
type Health struct {
	Source  string  `json:"source"`
	Records int     `json:"records"`
	Mapped  int     `json:"mapped"`
	Missed  int     `json:"missed"`
	Share   float64 `json:"share"`
	Drifted bool    `json:"drifted,omitempty"`
	Why     string  `json:"why,omitempty"`
	// Quiet is true when the source has sent nothing across every batch,
	// which is not the same as a source that is sending records that fail.
	Quiet bool `json:"quiet,omitempty"`
}

// Across summarises several batches of one source.
//
// Batches rather than a single page, because one page failing on a field is
// noise and every page failing on the same field is a schema change, and a
// check that could not tell them apart would be muted within a week.
func Across(batches []Batch) Health {
	h := Health{}
	byPath := map[string]int{}
	for _, b := range batches {
		h.Source = b.Source
		h.Records += b.Records
		h.Mapped += b.Mapped
		h.Missed += b.Missed
		for p, n := range b.ByPath {
			byPath[p] += n
		}
	}
	if h.Records == 0 {
		h.Quiet = true
		h.Why = fmt.Sprintf(
			"%s has sent nothing. That is a quiet source or a connector "+
				"that has stopped, and from here they are the same thing "+
				"— internal/feed makes the same point about a database "+
				"nobody is updating", h.Source)
		return h
	}
	h.Share = float64(h.Missed) / float64(h.Records)

	// Drift is a property of every page, not of the total. One bad page
	// among several good ones drags an aggregate over any threshold while
	// meaning the opposite of a schema change — the source was fine before
	// it and fine after. So the test is how many batches that saw records
	// are themselves drifting, and a minority is noise.
	saw, bad := 0, 0
	for _, b := range batches {
		if b.Records == 0 {
			continue
		}
		saw++
		if _, drifted := b.Drifted(); drifted {
			bad++
		}
	}
	if saw == 0 || bad*2 <= saw {
		h.Why = fmt.Sprintf("%d of %d record(s) mapped", h.Mapped,
			h.Records)
		if bad > 0 {
			h.Why += fmt.Sprintf("; %d of %d page(s) failed heavily, "+
				"which is a bad page rather than a changed source", bad,
				saw)
		}
		return h
	}
	paths := make([]string, 0, len(byPath))
	for p := range byPath {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	worst, at := "", 0
	for _, p := range paths {
		if byPath[p] > at {
			worst, at = p, byPath[p]
		}
	}
	h.Drifted = true
	h.Why = fmt.Sprintf(
		"%s is failing %.0f%% of records, %d of them on %q. A source that "+
			"has changed shape and been absorbed produces events with an "+
			"empty %s and detections that stop firing with no error "+
			"anywhere", h.Source, h.Share*100, at, worst, leaf(worst))
	return h
}

// Check runs a source against a sample of real records and reports what it
// would do with them, without producing any events.
//
// The thing to run before turning a source on, and again after a vendor
// announces anything. It is internal/proving's argument in a different
// place: a mapping tested only against the record it was written from has
// been shown to work on that record.
func Check(s Source, sample []any) (Batch, error) {
	if err := s.Validate(); err != nil {
		return Batch{}, err
	}
	if len(sample) == 0 {
		return Batch{}, fmt.Errorf(
			"there is nothing to check %s/%s against. A mapping validated "+
				"against no records has been shown to be well-formed and "+
				"nothing else", s.Issuer, s.Stream)
	}
	b := Map(s, sample, time.Now().UTC())
	b.Events = nil
	return b, nil
}

// Issuer reports the namespace a source writes identifiers under, and
// whether it agrees with the connector manifest it is fetched by.
//
// Checked rather than assumed. The manifest names the issuer and so does
// the mapping, and the two disagreeing is a class of bug with no symptom:
// every event is well-formed, every field is populated, and the join to a
// person silently matches nothing.
func (s Source) AgreesWith(manifestName string) error {
	if strings.EqualFold(s.Issuer, manifestName) {
		return nil
	}
	return fmt.Errorf(
		"%s/%s writes identifiers under %q and is fetched by a connector "+
			"called %q. Every event will be well-formed, every field will "+
			"be populated, and the join to a person will match nothing",
		s.Issuer, s.Stream, s.Issuer, manifestName)
}
