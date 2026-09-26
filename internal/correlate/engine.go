// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package correlate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
)

// Seen is one event that matched one of the correlated rules.
type Seen struct {
	Rule  string
	Event telemetry.Event
}

// Hit is a correlation that fired.
type Hit struct {
	Rule string `json:"rule"`
	// Group is the field values this fired for, in group-by order.
	Group map[string]string `json:"group,omitempty"`
	// Window is the span the events fell in.
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// Count is what satisfied the condition: events, or distinct values.
	Count int `json:"count"`
	// Rules are the distinct detections involved, in the order they fired.
	Rules    []string           `json:"rules,omitempty"`
	Severity telemetry.Severity `json:"severity,omitempty"`
	// Sample is a few of the events, so somebody can see what this is.
	Sample []telemetry.Event `json:"-"`
}

// MaxSample caps what a hit carries back.
const MaxSample = 5

// Why describes a hit for somebody reading an alert.
func (h Hit) Why() string {
	var who string
	if len(h.Group) > 0 {
		var parts []string
		for _, k := range sorted(keys(h.Group)) {
			parts = append(parts, k+"="+h.Group[k])
		}
		who = " for " + strings.Join(parts, ", ")
	}
	return fmt.Sprintf("%s%s: %d within %s, between %s and %s", h.Rule,
		who, h.Count, plainly(h.To.Sub(h.From)),
		h.From.Format(time.RFC3339), h.To.Format(time.RFC3339))
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// MaxGroups caps how many distinct groups one correlation tracks at once.
//
// A correlation grouped by a field an attacker controls — a username in a
// spray, a source port — grows a bucket per value. Unbounded, that is a
// detection rule being used to exhaust the machine running it, so the
// engine refuses to open a new group past this and reports it rather than
// growing quietly. The refusal is the safe failure: a correlation that
// stopped tracking new groups has lost coverage and says so, where one that
// consumed all the memory has lost everything.
const MaxGroups = 100_000

// Engine evaluates one correlation over a stream.
//
// Events go in with their event time. Nothing comes out until the watermark
// passes a window's end, which is what makes the same input produce the
// same output on a replay as it did live.
type Engine struct {
	rule Rule

	// buckets are keyed by group then by window start.
	buckets map[string]map[int64]*bucket
	dropped int
	late    int
	groups  int
}

type bucket struct {
	events []Seen
}

// New builds an engine for a correlation.
func New(r Rule) (*Engine, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &Engine{rule: r, buckets: map[string]map[int64]*bucket{}}, nil
}

// Rule is the correlation this evaluates.
func (e *Engine) Rule() Rule { return e.rule }

// Dropped is how many events were refused because the group cap was
// reached, and Late how many arrived after their window had already closed.
func (e *Engine) Dropped() int { return e.dropped }
func (e *Engine) Late() int    { return e.late }

// Watches reports whether this correlation is over a given rule.
func (e *Engine) Watches(rule string) bool {
	for _, r := range e.rule.Rules {
		if strings.EqualFold(r, rule) {
			return true
		}
	}
	return false
}

// group is the key an event falls under.
func (e *Engine) group(ev telemetry.Event) (string, map[string]string, bool) {
	if len(e.rule.GroupBy) == 0 {
		return "", nil, true
	}
	f := ev.Fields()
	vals := map[string]string{}
	var parts []string
	for _, g := range e.rule.GroupBy {
		v, ok := f[g]
		if !ok || strings.TrimSpace(v) == "" {
			// An event missing a grouping field cannot be placed. Dropped
			// rather than pooled under an empty key, which would make one
			// bucket that every unrelated event falls into.
			return "", nil, false
		}
		vals[g] = v
		parts = append(parts, g+"\x00"+v)
	}
	return strings.Join(parts, "\x01"), vals, true
}

// window is the start of the window an event time falls in.
//
// Fixed windows aligned to the epoch rather than sliding ones. A sliding
// window has to be recomputed on every arrival and cannot be closed by a
// watermark at all, because there is always another window still open. The
// cost is that two events fifteen minutes apart can land in different
// buckets, which is why the engine also evaluates the pair of adjacent
// windows for the temporal types below.
func (e *Engine) window(t time.Time) int64 {
	span := int64(e.rule.Timespan)
	return (t.UnixNano() / span) * span
}

// Observe takes one event that matched one of the correlated rules.
func (e *Engine) Observe(s Seen, watermark time.Time) error {
	if !e.Watches(s.Rule) {
		return fmt.Errorf("%q is not one of the rules %q correlates",
			s.Rule, e.rule.Title)
	}
	when := s.Event.Time
	if when.IsZero() {
		when = s.Event.Received
	}
	if when.IsZero() {
		return fmt.Errorf("this event has no time, so no window holds it")
	}
	key, _, ok := e.group(s.Event)
	if !ok {
		e.dropped++
		return nil
	}
	start := e.window(when)
	if !watermark.IsZero() &&
		watermark.UnixNano() >= start+int64(e.rule.Timespan) {
		// Its window has already been closed and reported. Counted rather
		// than silently accepted into a window nobody will look at again:
		// a rising late count is the signal that the watermark is too
		// aggressive for a source.
		e.late++
		return nil
	}

	byWindow, seen := e.buckets[key]
	if !seen {
		if e.groups >= MaxGroups {
			e.dropped++
			return nil
		}
		byWindow = map[int64]*bucket{}
		e.buckets[key] = byWindow
		e.groups++
	}
	b, ok := byWindow[start]
	if !ok {
		b = &bucket{}
		byWindow[start] = b
	}
	b.events = append(b.events, s)
	return nil
}

// Close evaluates and releases every window the watermark has passed.
//
// Everything older than the watermark has been delivered, so a window
// ending before it is complete and can be decided. Anything still open is
// left alone.
func (e *Engine) Close(watermark time.Time) []Hit {
	var out []Hit
	span := int64(e.rule.Timespan)
	for key, byWindow := range e.buckets {
		starts := make([]int64, 0, len(byWindow))
		for s := range byWindow {
			starts = append(starts, s)
		}
		sort.Slice(starts, func(i, j int) bool { return starts[i] < starts[j] })
		for _, start := range starts {
			if watermark.UnixNano() < start+span {
				continue // still open
			}
			b := byWindow[start]
			if h, ok := e.evaluate(key, start, b); ok {
				out = append(out, h)
			}
			delete(byWindow, start)
		}
		if len(byWindow) == 0 {
			delete(e.buckets, key)
			e.groups--
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].From.Equal(out[j].From) {
			return out[i].From.Before(out[j].From)
		}
		return out[i].Why() < out[j].Why()
	})
	return out
}

// Flush closes every window regardless of the watermark.
//
// For the end of a replay, where there is no more input and leaving the
// last window open would silently lose the tail. Never for a live stream:
// closing a window early is exactly the bug the watermark exists to avoid.
func (e *Engine) Flush() []Hit {
	return e.Close(time.Unix(1<<62/int64(time.Second), 0))
}

func (e *Engine) evaluate(key string, start int64, b *bucket) (Hit, bool) {
	if len(b.events) == 0 {
		return Hit{}, false
	}
	from := time.Unix(0, start).UTC()
	h := Hit{
		Rule: e.rule.Title, From: from,
		To:       from.Add(e.rule.Timespan),
		Severity: e.rule.Severity,
		Group:    groupOf(key),
	}
	ordered := append([]Seen(nil), b.events...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return at(ordered[i].Event).Before(at(ordered[j].Event))
	})
	for _, s := range ordered {
		if len(h.Sample) < MaxSample {
			h.Sample = append(h.Sample, s.Event)
		}
	}

	switch e.rule.Type {
	case EventCount:
		h.Count = len(ordered)
		if !e.rule.Test.Holds(h.Count) {
			return Hit{}, false
		}
	case ValueCount:
		seen := map[string]bool{}
		for _, s := range ordered {
			if v, ok := s.Event.Fields()[e.rule.Field]; ok && v != "" {
				seen[v] = true
			}
		}
		h.Count = len(seen)
		if !e.rule.Test.Holds(h.Count) {
			return Hit{}, false
		}
	case Temporal:
		want := map[string]bool{}
		for _, r := range e.rule.Rules {
			want[strings.ToLower(r)] = false
		}
		for _, s := range ordered {
			want[strings.ToLower(s.Rule)] = true
		}
		for _, got := range want {
			if !got {
				return Hit{}, false
			}
		}
		h.Count = len(want)
		h.Rules = firedOrder(ordered)
	case TemporalOrdered:
		order := firedOrder(ordered)
		if !follows(order, e.rule.Rules) {
			return Hit{}, false
		}
		h.Count = len(e.rule.Rules)
		h.Rules = order
	}
	return h, true
}

// firedOrder is the distinct rules in the order they first fired.
func firedOrder(in []Seen) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		k := strings.ToLower(s.Rule)
		if !seen[k] {
			seen[k] = true
			out = append(out, s.Rule)
		}
	}
	return out
}

// follows reports whether every rule in want appears in order within got.
//
// A subsequence rather than an exact match: other things happening in
// between is normal, and requiring an exact sequence would mean the
// detection stops working the moment anything else on the machine matches
// one of the rules.
func follows(got, want []string) bool {
	i := 0
	for _, g := range got {
		if i < len(want) && strings.EqualFold(g, want[i]) {
			i++
		}
	}
	return i == len(want)
}

func groupOf(key string) map[string]string {
	if key == "" {
		return nil
	}
	out := map[string]string{}
	for _, pair := range strings.Split(key, "\x01") {
		k, v, ok := strings.Cut(pair, "\x00")
		if ok {
			out[k] = v
		}
	}
	return out
}

func at(e telemetry.Event) time.Time {
	if !e.Time.IsZero() {
		return e.Time
	}
	return e.Received
}

// Watermark is how far behind now a stream is believed to be complete.
//
// The caller's to supply: internal/spool measures observed lateness per
// source and that is the right input. This exists so a caller with no
// measurement has an explicit, visible default rather than accidentally
// using the clock — which is the bug the package comment is about.
func Watermark(now time.Time, lateness time.Duration) time.Time {
	return now.Add(-lateness)
}

// Safe is a lateness that assumes nothing about the source.
//
// Five minutes, because cloud provider exports commonly batch on that
// interval, so a window closed sooner than this misses whole batches. Too
// long for a fast source and the right sort of wrong: closing late delays a
// detection, closing early loses one.
const Safe = 5 * time.Minute
