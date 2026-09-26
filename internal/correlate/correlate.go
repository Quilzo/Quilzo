// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package correlate is Sigma's correlation rules: the detections that are
// about several events rather than one.
//
// Sigma version 2 defines four, and they are the four questions a single
// event cannot answer. How many times did this happen (event_count). How
// many different things did it happen to (value_count). Did these separate
// things all happen close together (temporal). Did they happen in this
// order (temporal_ordered).
//
// # Windows close on a watermark, not on a clock
//
// This is the part every implementation gets wrong and nobody notices for
// months, because the symptom is a detection that quietly misses things.
//
// A correlation over fifteen minutes has to decide when fifteen minutes is
// up. The obvious answer is to look at the clock, and it is wrong: events
// arrive late. A proxy buffers, an agent reconnects, a cloud provider's
// export lands in five-minute batches. An event that happened at 10:02 and
// arrived at 10:20 belongs in the 10:00 window, and a window closed at
// 10:15 by the clock never saw it. The rule does not fire, nothing reports
// an error, and the only evidence is an absence.
//
// It also makes the detection non-reproducible. Replaying yesterday's
// events through a clock-closed window gives different answers from the
// live run, so a rule cannot be tested — which is exactly what
// internal/proving needs to do before anything is promoted.
//
// So a window here closes when the watermark passes its end, and the
// watermark is a statement about arrival: everything older than this has
// been delivered. internal/telemetry keeps Time and Received apart for this
// reason and internal/spool measures observed lateness to produce the
// number. A replay that supplies the same watermarks gets the same answers
// as the live run, which is the property that makes a correlation testable
// at all.
//
// # Counting without grouping is almost always a mistake
//
// "Ten failed logons in fifteen minutes" across an entire estate fires
// continuously and means nothing. Grouped by user it is an account being
// attacked; grouped by source address it is a scanner. Sigma permits the
// ungrouped form and this implements it, because refusing a construct the
// standard defines would make portable rules unportable — but it says so,
// because the arithmetic in internal/detect is about precisely what a
// detection that fires on the whole population does to an analyst.
package correlate

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/sigma"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Type is which of the four correlations this is.
type Type string

const (
	// EventCount: how many times a rule fired in a window.
	EventCount Type = "event_count"
	// ValueCount: how many distinct values of a field appeared.
	ValueCount Type = "value_count"
	// Temporal: several different rules all fired in a window.
	Temporal Type = "temporal"
	// TemporalOrdered: the same, in the order the rules are listed.
	//
	// The one most backends do not implement, and the one that separates
	// "these things happened" from "this sequence happened" — which is the
	// difference between a coincidence and a technique.
	TemporalOrdered Type = "temporal_ordered"
)

// Types is every correlation type.
var Types = []Type{EventCount, ValueCount, Temporal, TemporalOrdered}

// Known reports whether a type is one of the four.
func (t Type) Known() bool {
	for _, c := range Types {
		if c == t {
			return true
		}
	}
	return false
}

// Counts reports whether a type is about a number of things.
func (t Type) Counts() bool {
	return t == EventCount || t == ValueCount
}

// Ordered reports whether the order of the rules matters.
func (t Type) Ordered() bool { return t == TemporalOrdered }

// Test is a comparison against a count.
type Test struct {
	Op string `json:"op"`
	N  int    `json:"n"`
}

// Ops are the comparisons Sigma defines for a correlation condition.
var Ops = []string{"gte", "gt", "lte", "lt", "eq"}

// Holds reports whether a count satisfies the test.
func (t Test) Holds(n int) bool {
	switch t.Op {
	case "gte":
		return n >= t.N
	case "gt":
		return n > t.N
	case "lte":
		return n <= t.N
	case "lt":
		return n < t.N
	case "eq":
		return n == t.N
	}
	return false
}

// Falling reports whether this is a test for absence.
//
// lte and lt fire when something stopped happening, which is a different
// kind of detection and a different failure: a rule looking for fewer than
// five heartbeats an hour fires for every group that has no events at all,
// including every group that has never existed. Worth telling apart.
func (t Test) Falling() bool { return t.Op == "lte" || t.Op == "lt" }

// Rule is one correlation.
type Rule struct {
	Title string `json:"title"`
	ID    string `json:"id,omitempty"`
	Type  Type   `json:"type"`
	// Rules names the detections this is over, by their Sigma name or id.
	Rules []string `json:"rules"`
	// GroupBy are the fields that partition the counting.
	GroupBy []string `json:"group_by,omitempty"`
	// Field is the one whose distinct values are counted, for value_count.
	Field    string        `json:"field,omitempty"`
	Timespan time.Duration `json:"timespan"`
	Test     Test          `json:"condition"`

	Severity telemetry.Severity `json:"severity,omitempty"`
	// Generate says the referenced rules should also alert on their own.
	// Off by default, which is Sigma's default and the right one: a
	// correlation usually exists because the individual events are not
	// worth waking anybody.
	Generate bool `json:"generate,omitempty"`
}

// MaxTimespan caps a correlation window.
//
// A day. Beyond that the thing being asked is not "did these happen
// together", it is "have these ever both happened", which is a search
// rather than a detection — and a window that long holds a day of events in
// memory per group, which is how a correlation engine becomes the incident.
const MaxTimespan = 24 * time.Hour

// Validate refuses a correlation that cannot be evaluated.
func (r Rule) Validate() error {
	if strings.TrimSpace(r.Title) == "" {
		return fmt.Errorf("a correlation needs a title")
	}
	if !r.Type.Known() {
		return fmt.Errorf("%q is not a correlation type; Sigma defines %s",
			r.Type, strings.Join(typeNames(), ", "))
	}
	if len(r.Rules) == 0 {
		return fmt.Errorf("%q correlates nothing; name the rules it is "+
			"over", r.Title)
	}
	if r.Timespan <= 0 {
		return fmt.Errorf("%q has no timespan, so there is no window to "+
			"count in", r.Title)
	}
	if r.Timespan > MaxTimespan {
		return fmt.Errorf(
			"%q has a timespan of %s and the cap is %s. Beyond that the "+
				"question is not whether these happened together, it is "+
				"whether they have ever both happened — which is a search, "+
				"and a window that long holds a day of events per group",
			r.Title, plainly(r.Timespan), plainly(MaxTimespan))
	}
	switch r.Type {
	case ValueCount:
		if strings.TrimSpace(r.Field) == "" {
			return fmt.Errorf(
				"%q counts distinct values and does not say of what",
				r.Title)
		}
		if len(r.GroupBy) == 0 {
			return fmt.Errorf(
				"%q counts distinct values of %s across everything, which "+
					"is one number for the whole estate. Group it by "+
					"something", r.Title, r.Field)
		}
	case Temporal, TemporalOrdered:
		if len(r.Rules) < 2 {
			return fmt.Errorf(
				"%q is a %s over one rule, which is that rule", r.Title,
				r.Type)
		}
		if len(r.GroupBy) == 0 {
			return fmt.Errorf(
				"%q asks whether these happened together and does not say "+
					"together to what. Without a group-by, two unrelated "+
					"events on two unrelated machines satisfy it", r.Title)
		}
	}
	if r.Type.Counts() {
		ok := false
		for _, o := range Ops {
			if r.Test.Op == o {
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("%q has no condition; use one of %s",
				r.Title, strings.Join(Ops, ", "))
		}
		if r.Test.N < 0 {
			return fmt.Errorf("%q compares against %d", r.Title, r.Test.N)
		}
	}
	for _, f := range append(append([]string{}, r.GroupBy...), r.Field) {
		if f != "" && strings.TrimSpace(f) != f {
			return fmt.Errorf("%q names a field with spaces around it: %q",
				r.Title, f)
		}
	}
	return nil
}

// Broad reports whether this counts across the whole population, with the
// reason.
//
// Not refused. Sigma permits it and refusing a construct the standard
// defines would make portable rules unportable. Reported, because a
// detection that fires on the whole estate is the case internal/detect's
// arithmetic is about.
func (r Rule) Broad() (string, bool) {
	if r.Type.Counts() && len(r.GroupBy) == 0 {
		return fmt.Sprintf(
			"%q counts across everything rather than per user, host or "+
				"address. Ten of something in fifteen minutes is constant "+
				"for an estate and meaningful for an account", r.Title), true
	}
	if r.Test.Falling() {
		return fmt.Sprintf(
			"%q fires when a count falls, which also fires for every group "+
				"that has no events at all — including every group that "+
				"has never existed. Make sure something upstream bounds "+
				"the groups", r.Title), true
	}
	return "", false
}

func typeNames() []string {
	out := make([]string, 0, len(Types))
	for _, t := range Types {
		out = append(out, string(t))
	}
	return out
}

// Read parses correlation rules from Sigma YAML.
func Read(in []byte) ([]Rule, error) {
	docs, err := sigma.Parse(in)
	if err != nil {
		return nil, err
	}
	var out []Rule
	for i, d := range docs {
		c, ok := d["correlation"].(map[string]any)
		if !ok {
			continue // an ordinary detection rule, not a correlation
		}
		r, err := fromDoc(d, c)
		if err != nil {
			return nil, fmt.Errorf("document %d: %w", i+1, err)
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("there are no correlation rules in this file")
	}
	return out, nil
}

func fromDoc(d, c map[string]any) (Rule, error) {
	r := Rule{
		Title: str(d["title"]), ID: str(d["id"]),
		Type:    Type(strings.ToLower(strings.TrimSpace(str(c["type"])))),
		Rules:   strs(c["rules"]),
		GroupBy: strs(c["group-by"]),
		Field:   str(c["field"]),
	}
	if lvl := str(d["level"]); lvl != "" {
		r.Severity = level(lvl)
	}
	if g := strings.ToLower(str(c["generate"])); g == "true" {
		r.Generate = true
	}
	if ts := str(c["timespan"]); ts != "" {
		d, err := Timespan(ts)
		if err != nil {
			return r, err
		}
		r.Timespan = d
	}
	if cond, ok := c["condition"].(map[string]any); ok {
		for _, op := range Ops {
			v := str(cond[op])
			if v == "" {
				continue
			}
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return r, fmt.Errorf("%q is not a number", v)
			}
			r.Test = Test{Op: op, N: n}
			break
		}
		if f := str(cond["field"]); f != "" && r.Field == "" {
			r.Field = f
		}
	}
	return r, r.Validate()
}

// Timespan parses Sigma's duration: a number and one of s, m, h, d.
//
// Its own parser rather than Go's, because Go accepts "1h30m" and Sigma
// does not, and accepting more than the standard means writing a rule here
// that no other backend will take.
func Timespan(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return 0, fmt.Errorf("%q is not a timespan", s)
	}
	unit := s[len(s)-1]
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n <= 0 {
		return 0, fmt.Errorf(
			"%q is not a timespan; Sigma writes a positive number and one "+
				"of s, m, h or d", s)
	}
	switch unit {
	case 's':
		return time.Duration(n) * time.Second, nil
	case 'm':
		return time.Duration(n) * time.Minute, nil
	case 'h':
		return time.Duration(n) * time.Hour, nil
	case 'd':
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return 0, fmt.Errorf(
		"%q ends in %q; Sigma's units are s, m, h and d, and accepting "+
			"more than that means writing a rule no other backend takes",
		s, string(unit))
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func strs(v any) []string {
	switch t := v.(type) {
	case string:
		if strings.TrimSpace(t) == "" {
			return nil
		}
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func level(s string) telemetry.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return telemetry.SeverityCritical
	case "high":
		return telemetry.SeverityHigh
	case "medium":
		return telemetry.SeverityMedium
	}
	return telemetry.SeverityLow
}

func plainly(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d second(s)", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d minute(s)", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hour(s)", int(d.Hours()))
	}
	return fmt.Sprintf("%d day(s)", int(d.Hours()/24))
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
