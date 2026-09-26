// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package source turns one platform's log records into events, and says
// loudly when it cannot.
//
// internal/connector already fetches from an arbitrary tool: one hostname,
// declared endpoints, pagination, rate limits and a credential it never
// prints. This is the half after that — what a fetched record means.
//
// # The failure this exists for
//
// Every SIEM ships two hundred integrations and the integrations are the
// weakest part of the product, for one reason: when a source changes shape,
// the mapping does not break. It keeps working and produces events with
// empty fields. A sign-in event with no user in it is still an event; it
// still counts, still appears on a dashboard, still fails to match the
// detection that was written against the field that is now empty. Nothing
// errors. The detection simply stops firing, and the first evidence is an
// incident nobody was alerted to.
//
// So a mapping here declares which paths it requires, and a record missing
// one produces a Miss rather than an event with a hole in it. A run reports
// its miss rate by path, because a source where two in five records fail on
// the same field has changed and somebody should be told today rather than
// at the post-mortem.
//
// # Identity is the other thing that silently breaks
//
// The same person is a user principal name in Entra, an email in Workspace,
// an IAM ARN in CloudTrail and an alternate id in Okta. internal/workforce
// joins them, and it can only do that if every event says which namespace
// its identifier belongs to. So a source's issuer is the connector
// manifest's name, carried into every telemetry.ID it produces, and it is
// not a free string per mapping — one connector writing "azure" where
// another writes "entra" breaks every join in the estate and produces no
// error anywhere.
//
// # Lateness is a property of the source, not a constant
//
// internal/correlate closes windows on a watermark and needs a number for
// how far behind a source runs. That number belongs here, with the source
// that has it: a cloud audit trail delivering in five-minute batches and an
// agent streaming in real time cannot share one.
package source

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/connector"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Source is how one platform's records become events.
type Source struct {
	// Issuer is the connector manifest's name, and the namespace every
	// identifier from this source belongs to.
	Issuer string `json:"issuer"`
	// Tool is what a person calls it, and Stream which of its logs this is
	// — one tool commonly has several with different shapes.
	Tool   string `json:"tool"`
	Stream string `json:"stream"`

	// Class is the OCSF class these records are.
	Class telemetry.Class `json:"class"`
	// Activity is the default OCSF activity, and From names a path whose
	// value selects one from Activities instead.
	Activity   uint8            `json:"activity"`
	From       string           `json:"from,omitempty"`
	Activities map[string]uint8 `json:"activities,omitempty"`

	// Time is the path to the source's own timestamp, and Layout how it
	// writes it. Both required: a record with no time cannot be windowed,
	// and guessing a layout is how a whole day lands in 2001.
	Time   string `json:"time"`
	Layout string `json:"layout,omitempty"`

	// Actor, Target and Device are paths to identifiers.
	Actor  string `json:"actor,omitempty"`
	Target string `json:"target,omitempty"`
	Device string `json:"device,omitempty"`

	Message string `json:"message,omitempty"`
	// Outcome is a path whose value says whether the action succeeded.
	//
	// Three conventions exist in the wild and a mapping says which it is
	// rather than guessing, because guessing wrong inverts every
	// disposition in the stream and nothing errors.
	//
	//   - Failed lists the values that mean it did not work. Okta writes
	//     FAILURE and DENY.
	//   - Succeeded lists the values that mean it did, and anything else
	//     failed. Entra writes a zero error code on success and one of
	//     several hundred numbers otherwise.
	//   - Neither: presence is failure. CloudTrail writes errorCode only
	//     when there was an error.
	Outcome   string   `json:"outcome,omitempty"`
	Failed    []string `json:"failed,omitempty"`
	Succeeded []string `json:"succeeded,omitempty"`

	// Observables are the pivotable values, by kind.
	Observables map[telemetry.ObservableKind]string `json:"observables,omitempty"`

	// Require are paths that must be present. A record missing one is a
	// miss rather than an event with a hole in it.
	Require []string `json:"require"`
	// Keep are extra paths carried into Raw, where a detection written
	// against the source's own field names can read them.
	Keep []string `json:"keep,omitempty"`

	// Lateness is how far behind this source runs, for the correlation
	// watermark. Required, because a default here would be a number
	// somebody else's source made up.
	Lateness time.Duration `json:"lateness"`
}

// Layouts for the sources that write a number where everybody else writes
// a formatted time.
//
// Named rather than special-cased inside the parser, because a mapping that
// says nothing about its format and silently produces 1970 is the same
// class of bug as one that says nothing about its fields.
const (
	// LayoutEpochSecond is seconds since the epoch. Slack writes this.
	LayoutEpochSecond = "epoch-s"
	// LayoutEpochMilli is milliseconds. GitHub writes this.
	LayoutEpochMilli = "epoch-ms"
)

// MaxLateness caps a source's declared delay.
//
// An hour. A source running further behind than that is not late, it is a
// batch import, and treating it as a stream means every correlation window
// waits an hour to close.
const MaxLateness = time.Hour

// Validate refuses a mapping that cannot produce a usable event.
func (s Source) Validate() error {
	for _, f := range []struct{ name, v string }{
		{"issuer", s.Issuer}, {"tool", s.Tool}, {"stream", s.Stream},
	} {
		if strings.TrimSpace(f.v) == "" {
			return fmt.Errorf("a source needs a %s", f.name)
		}
	}
	if s.Issuer != strings.ToLower(s.Issuer) {
		return fmt.Errorf(
			"the issuer %q is not lowercase. It is the namespace every "+
				"identifier from this source joins on, and two spellings "+
				"of it break every join in the estate with no error "+
				"anywhere", s.Issuer)
	}
	if !s.Class.Valid() {
		return fmt.Errorf(
			"%s/%s has no valid OCSF class. The value is category*1000 + "+
				"index, so a multiple of a thousand names a category and "+
				"not a class in it", s.Issuer, s.Stream)
	}
	if strings.TrimSpace(s.Time) == "" {
		return fmt.Errorf(
			"%s/%s does not say where the record's time is. A record with "+
				"no time cannot be windowed, correlated or aged",
			s.Issuer, s.Stream)
	}
	if strings.TrimSpace(s.Layout) == "" {
		return fmt.Errorf(
			"%s/%s does not say how the source writes its time. Guessing "+
				"a layout is how a whole day of events lands in 2001",
			s.Issuer, s.Stream)
	}
	if len(s.Failed) > 0 && len(s.Succeeded) > 0 {
		return fmt.Errorf(
			"%s/%s lists both the values that mean failure and the ones "+
				"that mean success. One of them is the rule and the other "+
				"is whatever is left, and a mapping that says both has not "+
				"decided which", s.Issuer, s.Stream)
	}
	if s.From != "" && len(s.Activities) == 0 {
		return fmt.Errorf(
			"%s/%s selects its activity from %q and lists none",
			s.Issuer, s.Stream, s.From)
	}
	if s.Lateness <= 0 {
		return fmt.Errorf(
			"%s/%s does not say how far behind it runs. internal/correlate "+
				"closes windows on that number, and a default here would "+
				"be one somebody else's source made up", s.Issuer, s.Stream)
	}
	if s.Lateness > MaxLateness {
		return fmt.Errorf(
			"%s/%s declares %s of lateness and the cap is %s. Further "+
				"behind than that is a batch import rather than a stream, "+
				"and treating it as one makes every correlation window "+
				"wait that long to close", s.Issuer, s.Stream,
			plainly(s.Lateness), plainly(MaxLateness))
	}
	if len(s.Require) == 0 {
		return fmt.Errorf(
			"%s/%s requires no paths, so a record of any shape maps to an "+
				"event. That is the failure this package exists for: when "+
				"the source changes, the mapping keeps working and "+
				"produces events with empty fields", s.Issuer, s.Stream)
	}
	wanted := map[string]bool{s.Time: true}
	for _, p := range []string{s.Actor, s.Target, s.Device, s.Message,
		s.Outcome, s.From} {
		if p != "" {
			wanted[p] = true
		}
	}
	for _, p := range s.Observables {
		wanted[p] = true
	}
	// A path carried into Raw is read: a detection written against the
	// source's own field name matches on it, so requiring one is not
	// requiring something nothing uses.
	for _, p := range s.Keep {
		wanted[p] = true
	}
	for _, r := range s.Require {
		if !wanted[r] {
			return fmt.Errorf(
				"%s/%s requires %q and never reads it. A required path "+
					"nothing uses fails records for no reason",
				s.Issuer, s.Stream, r)
		}
	}
	if !wanted[s.Time] || !contains(s.Require, s.Time) {
		return fmt.Errorf(
			"%s/%s does not require its own time path. Every other field "+
				"can be absent and leave a usable event; that one cannot",
			s.Issuer, s.Stream)
	}
	return nil
}

func contains(in []string, want string) bool {
	for _, s := range in {
		if s == want {
			return true
		}
	}
	return false
}

// Miss is a record that could not be mapped, and exactly why.
type Miss struct {
	Path string `json:"path"`
	Why  string `json:"why"`
}

// Map turns one fetched record into an event.
//
// Returns the misses rather than an event with holes. A caller that wants
// the record anyway has it; what it does not have is a way to get a
// half-populated event without noticing.
func (s Source) Map(doc any) (telemetry.Event, []Miss) {
	var missed []Miss
	for _, p := range s.Require {
		if !connector.Has(doc, p) {
			missed = append(missed, Miss{Path: p,
				Why: "absent from the record"})
		}
	}
	raw := connector.At(doc, s.Time)
	when, err := s.when(raw)
	if err != nil {
		missed = append(missed, Miss{Path: s.Time, Why: err.Error()})
	}
	if len(missed) > 0 {
		return telemetry.Event{}, missed
	}

	e := telemetry.Event{
		Source: s.Issuer + "/" + s.Stream,
		Time:   when, Class: s.Class,
		Activity: s.activity(doc),
		Severity: telemetry.SeverityLow,
		Message:  connector.At(doc, s.Message),
		Raw:      map[string]string{},
	}
	e.Disposition = s.disposition(doc)
	if e.Disposition == telemetry.DispositionFailed ||
		e.Disposition == telemetry.DispositionBlocked {
		// A refused action is worth more attention than a completed one
		// by default. Not a judgement about the record, a starting point
		// a detection can override.
		e.Severity = telemetry.SeverityMedium
	}

	for _, f := range []struct {
		path string
		into *telemetry.ID
	}{
		{s.Actor, &e.Actor}, {s.Target, &e.Target}, {s.Device, &e.Device},
	} {
		if f.path == "" {
			continue
		}
		if v := connector.At(doc, f.path); v != "" {
			*f.into = telemetry.ID{Issuer: s.Issuer, Value: v}
		}
	}

	kinds := make([]telemetry.ObservableKind, 0, len(s.Observables))
	for k := range s.Observables {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(a, b int) bool { return kinds[a] < kinds[b] })
	for _, k := range kinds {
		if v := connector.At(doc, s.Observables[k]); v != "" {
			e.Observables = append(e.Observables,
				telemetry.Observable{Kind: k, Value: v})
		}
	}

	for _, p := range s.Keep {
		if v := connector.At(doc, p); v != "" {
			e.Raw[leaf(p)] = v
		}
	}
	return e, nil
}

// when parses the source's timestamp in the layout it declared.
func (s Source) when(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, fmt.Errorf("the time field is empty")
	}
	switch s.Layout {
	case LayoutEpochSecond, LayoutEpochMilli:
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf(
				"%q is not a number, and this source writes its time as "+
					"one", raw)
		}
		if s.Layout == LayoutEpochMilli {
			return time.UnixMilli(n).UTC(), nil
		}
		return time.Unix(n, 0).UTC(), nil
	}
	t, err := time.Parse(s.Layout, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf(
			"%q does not parse as %q. A source that has changed its time "+
				"format silently moves every event, which is worse than "+
				"failing", raw, s.Layout)
	}
	return t.UTC(), nil
}

func (s Source) activity(doc any) uint8 {
	if s.From == "" {
		return s.Activity
	}
	if a, ok := s.Activities[connector.At(doc, s.From)]; ok {
		return a
	}
	return s.Activity
}

func (s Source) disposition(doc any) telemetry.Disposition {
	if s.Outcome == "" {
		return telemetry.DispositionAllowed
	}
	got := strings.TrimSpace(connector.At(doc, s.Outcome))
	switch {
	case len(s.Failed) > 0:
		if got == "" {
			return telemetry.DispositionUnknown
		}
		for _, f := range s.Failed {
			if strings.EqualFold(strings.TrimSpace(f), got) {
				return telemetry.DispositionFailed
			}
		}
		return telemetry.DispositionAllowed
	case len(s.Succeeded) > 0:
		if got == "" {
			return telemetry.DispositionUnknown
		}
		for _, ok := range s.Succeeded {
			if strings.EqualFold(strings.TrimSpace(ok), got) {
				return telemetry.DispositionAllowed
			}
		}
		return telemetry.DispositionFailed
	default:
		// Presence is failure. An absent field is the ordinary case and
		// means the action worked.
		if got == "" {
			return telemetry.DispositionAllowed
		}
		return telemetry.DispositionFailed
	}
}

// leaf is the last segment of a path, used as the Raw key.
func leaf(p string) string {
	if i := strings.LastIndexAny(p, "."); i >= 0 && i+1 < len(p) {
		return p[i+1:]
	}
	return p
}

func plainly(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d second(s)", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d minute(s)", int(d.Minutes()))
	}
	return fmt.Sprintf("%d hour(s)", int(d.Hours()))
}
